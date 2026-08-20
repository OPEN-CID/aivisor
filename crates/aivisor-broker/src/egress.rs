//! The host-side egress proxy: the only path out of a sandbox.
//!
//! A sandbox runs in its own network namespace with no route to anywhere
//! (`CLONE_NEWNET`), and the BPF network hooks deny by default on top of
//! that. Everything a sandbox is allowed to reach, it reaches through this
//! proxy, which is where host and method allowlists are applied and where
//! credentials are attached — so that a compromised agent can *use* a
//! credential without ever being able to *read* one.
//!
//! # What is enforced, and where
//!
//! For plaintext HTTP the proxy sees the whole request, so it enforces the
//! host allowlist, the method allowlist, the request-size limit, credential
//! injection, and byte budgets.
//!
//! For HTTPS the client issues `CONNECT host:port` and everything after is
//! an opaque TLS stream. The proxy enforces the **host allowlist** and the
//! **byte budget** on that tunnel, and nothing else: it cannot see methods,
//! paths, or headers, and it cannot inject a credential into the tunnel.
//! This is a real limitation, not a temporary one — seeing inside would
//! require terminating TLS with a CA the sandbox trusts, which means the
//! broker could then read every secret the agent sends to any origin.
//! Blueprint §9.1 describes that terminating design; it is deliberately not
//! what this implements, and any claim that HTTPS method allowlists or
//! HTTPS credential injection work today would be false.
//!
//! # Deliberate simplifications
//!
//! One request per connection, `Connection: close` in both directions. No
//! keep-alive, no pipelining, no HTTP/2. A sandbox agent's request rate does
//! not justify the state machine, and each connection getting an
//! independent, freshly authorised trip through the policy is easier to
//! reason about than a persistent one that was authorised once.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use aivisor_core::Error;

use crate::proxy::Broker;

/// Cap on the request line plus headers. A client that sends more is
/// refused rather than buffered: without a bound, a sandbox could pin
/// arbitrary host memory by opening connections and dribbling headers.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// How long to wait on a stalled peer before giving up on a connection.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Cloud metadata endpoints, blocked unconditionally regardless of policy.
///
/// These are the classic SSRF targets: reaching one from inside a sandbox
/// yields the host's own cloud credentials. The BPF layer blocks them too
/// (`net.bpf.c`); doing it here as well means the block survives even if
/// the proxy is somehow reached from a context the BPF hooks do not cover.
const METADATA_IPS: &[&str] = &[
    "169.254.169.254", // AWS / GCP / Azure IMDS
    "168.63.129.16",   // Azure WireServer
    "fd00:ec2::254",   // AWS IMDS over IPv6
];

/// Headers that describe a single hop and must not be forwarded onward.
/// `proxy-authorization` is on this list because it carries the sandbox's
/// session token, which is meaningless to the origin and must never leak.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-authorization",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// One `broker_route` entry from policy.
#[derive(Debug, Clone)]
pub struct Route {
    /// Exact hostnames, or `*.example.com` to match any subdomain (but not
    /// the bare apex, matching the usual reading of a wildcard).
    pub hosts: Vec<String>,
    /// Uppercase HTTP methods. Empty means no method is permitted, which is
    /// deny-by-default rather than allow-all — an empty allowlist that
    /// meant "everything" would turn a policy mistake into full access.
    pub methods: Vec<String>,
}

impl Route {
    fn matches_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.hosts.iter().any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            match pattern.strip_prefix("*.") {
                // The label boundary check is the whole point: a plain
                // `ends_with` would let `notexample.com` match
                // `*.example.com`, so an attacker-registrable domain would
                // satisfy a policy written for someone else's.
                Some(suffix) => {
                    host.len() > suffix.len()
                        && host.ends_with(suffix)
                        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                }
                None => host == pattern,
            }
        })
    }

    fn allows_method(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }
}

/// Supplies the credentials the proxy attaches to outbound requests.
///
/// The whole point of the indirection: the secret never enters the sandbox,
/// so an agent that is fully compromised still cannot exfiltrate it. It can
/// only cause requests to be made on its behalf, which the host allowlist
/// bounds.
pub trait SecretProvider: Send + Sync {
    /// Header name and value to attach for `host`, if any.
    fn header_for(&self, host: &str) -> Option<(String, String)>;
}

/// A fixed host-to-header map, for callers that load credentials once at
/// startup.
#[derive(Default)]
pub struct StaticSecrets {
    by_host: HashMap<String, (String, String)>,
}

impl StaticSecrets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, host: &str, header: &str, value: &str) {
        self.by_host.insert(
            host.to_ascii_lowercase(),
            (header.to_string(), value.to_string()),
        );
    }
}

impl SecretProvider for StaticSecrets {
    fn header_for(&self, host: &str) -> Option<(String, String)> {
        self.by_host.get(&host.to_ascii_lowercase()).cloned()
    }
}

/// Egress configuration for one broker instance.
pub struct EgressPolicy {
    pub routes: Vec<Route>,
    /// Largest request body the proxy will relay, in bytes.
    pub max_request_bytes: u64,
    pub secrets: Arc<dyn SecretProvider>,
}

impl EgressPolicy {
    /// The route covering `host`, if policy has one.
    fn route_for(&self, host: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches_host(host))
    }

    /// Whether any route covers `host`. Note this says nothing about
    /// methods — a permitted host with a disallowed method is still
    /// refused.
    pub fn permits_host(&self, host: &str) -> bool {
        self.route_for(host).is_some()
    }
}

/// Why a request was refused. Kept separate from `Error` so the connection
/// handler can map each case to the right HTTP status without string
/// matching.
#[derive(Debug)]
enum Refusal {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    TooLarge(String),
    Upstream(String),
}

impl Refusal {
    fn status(&self) -> (u16, &'static str) {
        match self {
            Refusal::BadRequest(_) => (400, "Bad Request"),
            Refusal::Unauthorized(_) => (407, "Proxy Authentication Required"),
            Refusal::Forbidden(_) => (403, "Forbidden"),
            Refusal::TooLarge(_) => (413, "Payload Too Large"),
            Refusal::Upstream(_) => (502, "Bad Gateway"),
        }
    }

    fn detail(&self) -> &str {
        match self {
            Refusal::BadRequest(m)
            | Refusal::Unauthorized(m)
            | Refusal::Forbidden(m)
            | Refusal::TooLarge(m)
            | Refusal::Upstream(m) => m,
        }
    }
}

/// A parsed request line plus headers.
struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read the request line and headers, bounded by [`MAX_HEADER_BYTES`].
fn read_request(reader: &mut BufReader<TcpStream>) -> Result<Request, Refusal> {
    let mut consumed = 0usize;
    let mut line = String::new();

    let read_line = |reader: &mut BufReader<TcpStream>,
                     line: &mut String,
                     consumed: &mut usize|
     -> Result<(), Refusal> {
        line.clear();
        let n = reader
            .read_line(line)
            .map_err(|e| Refusal::BadRequest(format!("read: {e}")))?;
        if n == 0 {
            return Err(Refusal::BadRequest("connection closed mid-request".into()));
        }
        *consumed += n;
        if *consumed > MAX_HEADER_BYTES {
            return Err(Refusal::TooLarge(format!(
                "request head exceeded {MAX_HEADER_BYTES} bytes"
            )));
        }
        Ok(())
    };

    read_line(reader, &mut line, &mut consumed)?;
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Err(Refusal::BadRequest("malformed request line".into()));
    };
    let (method, target) = (method.to_string(), target.to_string());

    let mut headers = Vec::new();
    loop {
        read_line(reader, &mut line, &mut consumed)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(Refusal::BadRequest(format!(
                "malformed header: {trimmed:?}"
            )));
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    Ok(Request {
        method,
        target,
        headers,
    })
}

/// Split `host:port` into its parts, applying `default_port` when absent.
fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), Refusal> {
    // IPv6 literals are bracketed: [::1]:443
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(Refusal::BadRequest(format!(
                "malformed IPv6 authority: {authority:?}"
            )));
        };
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| Refusal::BadRequest(format!("bad port in {authority:?}")))?,
            None => default_port,
        };
        return Ok((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| Refusal::BadRequest(format!("bad port in {authority:?}")))?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

/// Resolve `host` and pick one address to use, then keep using exactly that
/// address.
///
/// This is the DNS pinning step. Resolving once and connecting to the
/// resolved *address* closes the rebinding window: if the proxy checked the
/// name against policy and then handed the name to `connect`, a hostile DNS
/// server could answer differently the second time and send an allowlisted
/// name to an address policy would never have permitted.
///
/// Metadata addresses are rejected here rather than by name, since the
/// dangerous part is the address a name resolves to, not the name itself.
fn resolve_pinned(host: &str, port: u16) -> Result<SocketAddr, Refusal> {
    let blocked: Vec<IpAddr> = METADATA_IPS.iter().filter_map(|s| s.parse().ok()).collect();

    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| Refusal::Upstream(format!("resolve {host}: {e}")))?
        .collect();

    // Refuse if *any* answer is a metadata address, not merely the one that
    // would have been picked. A name that resolves to both a harmless
    // address and a metadata address is a rebinding attempt, and selecting
    // the harmless one would let the caller simply retry until ordering
    // favoured it.
    if let Some(bad) = addrs.iter().find(|a| blocked.contains(&a.ip())) {
        return Err(Refusal::Forbidden(format!(
            "{host} resolves to cloud metadata address {} — always blocked",
            bad.ip()
        )));
    }

    addrs
        .into_iter()
        .next()
        .ok_or_else(|| Refusal::Upstream(format!("{host} resolved to no addresses")))
}

/// The running proxy.
pub struct EgressProxy {
    broker: Arc<Broker>,
    policy: Arc<EgressPolicy>,
}

impl EgressProxy {
    pub fn new(broker: Arc<Broker>, policy: EgressPolicy) -> Self {
        Self {
            broker,
            policy: Arc::new(policy),
        }
    }

    /// Bind and serve until the listener fails. One thread per connection.
    pub fn serve(&self, listen_addr: &str) -> Result<(), Error> {
        let listener = TcpListener::bind(listen_addr)
            .map_err(|e| Error::LaunchFailed(format!("broker bind {listen_addr}: {e}")))?;
        self.serve_on(listener)
    }

    /// Serve on an already-bound listener. Useful when the caller needs the
    /// assigned port (bind to `:0`, read `local_addr`, then serve).
    pub fn serve_on(&self, listener: TcpListener) -> Result<(), Error> {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            let broker = Arc::clone(&self.broker);
            let policy = Arc::clone(&self.policy);
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                handle_connection(stream, &broker, &policy);
            });
        }
        Ok(())
    }
}

fn handle_connection(stream: TcpStream, broker: &Arc<Broker>, policy: &EgressPolicy) {
    let Ok(mut client_out) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);

    match serve_request(&mut reader, &mut client_out, broker, policy) {
        Ok(()) => {}
        Err(refusal) => {
            let (code, reason) = refusal.status();
            // The detail goes to the sandbox, so it must describe the
            // policy decision without disclosing anything about the host:
            // no resolved addresses, no credential names, no other routes.
            let body = format!("aivisor-broker: {}\n", refusal.detail());
            let _ = write!(
                client_out,
                "HTTP/1.1 {code} {reason}\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: text/plain\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
        }
    }
}

fn serve_request(
    reader: &mut BufReader<TcpStream>,
    client_out: &mut TcpStream,
    broker: &Arc<Broker>,
    policy: &EgressPolicy,
) -> Result<(), Refusal> {
    let request = read_request(reader)?;

    // Authenticate before anything else is inspected. An unauthenticated
    // caller learns only that it needs a token — not whether the host it
    // asked for is on any allowlist.
    let token = request
        .header("proxy-authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or_else(|| {
            Refusal::Unauthorized("missing Proxy-Authorization: Bearer <session token>".into())
        })?
        .to_string();

    if broker.remaining_budget(&token).is_none() {
        return Err(Refusal::Unauthorized("unknown session token".into()));
    }

    if request.method.eq_ignore_ascii_case("CONNECT") {
        return serve_connect(&request, reader, client_out, broker, policy, &token);
    }
    serve_plain(&request, reader, client_out, broker, policy, &token)
}

/// Absolute-form HTTP: the proxy sees and enforces everything.
fn serve_plain(
    request: &Request,
    reader: &mut BufReader<TcpStream>,
    client_out: &mut TcpStream,
    broker: &Broker,
    policy: &EgressPolicy,
    token: &str,
) -> Result<(), Refusal> {
    let rest = request.target.strip_prefix("http://").ok_or_else(|| {
        Refusal::BadRequest(format!(
            "expected an absolute http:// target, got {:?} — this is a forward proxy, \
                 not an origin server",
            request.target
        ))
    })?;

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority, 80)?;

    let route = policy
        .route_for(&host)
        .ok_or_else(|| Refusal::Forbidden(format!("no egress route permits host {host:?}")))?;
    if !route.allows_method(&request.method) {
        return Err(Refusal::Forbidden(format!(
            "method {} is not permitted for {host}",
            request.method
        )));
    }

    // Chunked request bodies are refused rather than relayed: honouring the
    // size limit means knowing the length up front, and a de-chunking relay
    // that got it wrong would silently bypass that limit.
    if let Some(te) = request.header("transfer-encoding") {
        return Err(Refusal::BadRequest(format!(
            "Transfer-Encoding: {te} is not supported; send a Content-Length body"
        )));
    }

    let body_len: u64 = match request.header("content-length") {
        Some(v) => v
            .parse()
            .map_err(|_| Refusal::BadRequest("bad Content-Length".into()))?,
        None => 0,
    };
    if body_len > policy.max_request_bytes {
        return Err(Refusal::TooLarge(format!(
            "request body of {body_len} bytes exceeds the {} byte limit",
            policy.max_request_bytes
        )));
    }

    let addr = resolve_pinned(&host, port)?;
    let mut upstream = TcpStream::connect(addr)
        .map_err(|e| Refusal::Upstream(format!("connect to {host}: {e}")))?;
    let _ = upstream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(IO_TIMEOUT));

    let mut head = format!("{} {} HTTP/1.1\r\n", request.method, path);
    for (name, value) in &request.headers {
        if HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            continue;
        }
        // The origin decides on Host; a client-supplied Host that disagreed
        // with the authority we authorised would let policy be checked
        // against one name and the request be served by another.
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Host: {authority}\r\n"));

    // The credential is attached here, on the host side, and never travels
    // into the sandbox in either direction.
    if let Some((name, value)) = policy.secrets.header_for(&host) {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");

    charge(broker, token, head.len() as u64)?;
    upstream
        .write_all(head.as_bytes())
        .map_err(|e| Refusal::Upstream(format!("write head: {e}")))?;

    if body_len > 0 {
        let mut body = vec![0u8; body_len as usize];
        reader
            .read_exact(&mut body)
            .map_err(|e| Refusal::BadRequest(format!("read body: {e}")))?;
        charge(broker, token, body_len)?;
        upstream
            .write_all(&body)
            .map_err(|e| Refusal::Upstream(format!("write body: {e}")))?;
    }

    relay(&mut upstream, client_out, broker, token);
    Ok(())
}

/// `CONNECT host:port` — host allowlist and byte budget only. See the
/// module docs for why nothing inside the tunnel can be enforced.
fn serve_connect(
    request: &Request,
    reader: &mut BufReader<TcpStream>,
    client_out: &mut TcpStream,
    broker: &Arc<Broker>,
    policy: &EgressPolicy,
    token: &str,
) -> Result<(), Refusal> {
    let (host, port) = split_authority(&request.target, 443)?;

    if policy.route_for(&host).is_none() {
        return Err(Refusal::Forbidden(format!(
            "no egress route permits host {host:?}"
        )));
    }

    let addr = resolve_pinned(&host, port)?;
    let upstream = TcpStream::connect(addr)
        .map_err(|e| Refusal::Upstream(format!("connect to {host}: {e}")))?;
    let _ = upstream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(IO_TIMEOUT));

    client_out
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| Refusal::Upstream(format!("write CONNECT response: {e}")))?;

    // Pump both directions until either side closes, charging the budget as
    // bytes move. A tunnel that outran its budget is cut, which is the only
    // control still available once the payload is opaque.
    let mut client_in = reader
        .get_ref()
        .try_clone()
        .map_err(|e| Refusal::Upstream(format!("clone client stream: {e}")))?;
    let mut upstream_out = upstream
        .try_clone()
        .map_err(|e| Refusal::Upstream(format!("clone upstream: {e}")))?;
    let mut upstream_in = upstream;
    let mut client_write = client_out
        .try_clone()
        .map_err(|e| Refusal::Upstream(format!("clone client out: {e}")))?;

    let broker_up = Arc::clone(broker);
    let token_up = token.to_string();
    let up = std::thread::spawn(move || {
        pump(&mut client_in, &mut upstream_out, &broker_up, &token_up);
    });
    pump(&mut upstream_in, &mut client_write, broker, token);
    let _ = up.join();

    Ok(())
}

/// Copy until EOF, charging the session budget and stopping the moment it
/// is exhausted.
fn pump(from: &mut TcpStream, to: &mut TcpStream, broker: &Broker, token: &str) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if broker.record_bytes(token, n as u64).is_err() {
            break;
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

fn relay(from: &mut TcpStream, to: &mut TcpStream, broker: &Broker, token: &str) {
    pump(from, to, broker, token);
}

fn charge(broker: &Broker, token: &str, n: u64) -> Result<(), Refusal> {
    broker
        .record_bytes(token, n)
        .map_err(|e| Refusal::Forbidden(format!("egress budget: {e}")))
}
