//! End-to-end tests for the egress proxy against a real origin server.
//!
//! Every case drives an actual TCP connection through the proxy to a real
//! listener, rather than calling the policy predicates directly — the
//! interesting failures in a proxy are in the request path (which headers
//! get forwarded, what happens after a refusal, whether a limit is checked
//! before or after the bytes move), and a unit test of the allowlist
//! function would miss all of them.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aivisor_broker::{Broker, EgressPolicy, EgressProxy, Route, StaticSecrets};
use aivisor_core::SandboxId;

/// A minimal origin server. Records what it received so tests can assert on
/// headers the proxy was supposed to add or strip, then answers 200.
struct Origin {
    addr: String,
    received: Arc<std::sync::Mutex<Vec<String>>>,
}

fn start_origin() -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let addr = listener.local_addr().expect("origin addr").to_string();
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                let mut out = stream.try_clone().expect("clone");
                let mut reader = BufReader::new(stream);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line.trim_end().is_empty() {
                        break;
                    }
                    head.push_str(&line);
                }
                sink.lock().expect("lock").push(head);
                let body = "hello from origin";
                let _ = write!(
                    out,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });

    Origin { addr, received }
}

struct Harness {
    proxy_addr: String,
    broker: Arc<Broker>,
    origin: Origin,
}

/// Stand up an origin and a proxy whose policy allows `methods` to the
/// origin's own host, optionally injecting a credential.
fn harness(methods: &[&str], secret: Option<(&str, &str)>, max_request_bytes: u64) -> Harness {
    let origin = start_origin();
    let broker = Arc::new(Broker::new());

    let mut secrets = StaticSecrets::new();
    if let Some((header, value)) = secret {
        secrets.insert("127.0.0.1", header, value);
    }

    let policy = EgressPolicy {
        routes: vec![Route {
            hosts: vec!["127.0.0.1".into()],
            methods: methods.iter().map(|m| (*m).to_string()).collect(),
        }],
        max_request_bytes,
        secrets: Arc::new(secrets),
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr").to_string();
    let proxy = EgressProxy::new(Arc::clone(&broker), policy);
    std::thread::spawn(move || {
        let _ = proxy.serve_on(listener);
    });

    Harness {
        proxy_addr,
        broker,
        origin,
    }
}

/// Send one raw request through the proxy and return the whole response.
fn through_proxy(proxy_addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).expect("connect proxy");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

fn get_via_proxy(h: &Harness, token: &str, method: &str, host: &str) -> String {
    let request = format!(
        "{method} http://{host}/path HTTP/1.1\r\n\
         Host: {host}\r\n\
         Proxy-Authorization: Bearer {token}\r\n\
         \r\n"
    );
    through_proxy(&h.proxy_addr, &request)
}

fn session(h: &Harness) -> String {
    h.broker
        .issue_session(SandboxId::new())
        .expect("issue session")
}

#[test]
fn allowed_host_and_method_reach_the_origin() {
    let h = harness(&["GET"], None, 1024);
    let token = session(&h);

    let response = get_via_proxy(&h, &token, "GET", &h.origin.addr);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected the request to reach the origin, got: {response}"
    );
    assert!(response.contains("hello from origin"));
}

#[test]
fn a_host_no_route_covers_is_refused() {
    let h = harness(&["GET"], None, 1024);
    let token = session(&h);

    // A syntactically fine request to a host policy says nothing about.
    let response = get_via_proxy(&h, &token, "GET", "example.invalid");
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "an unlisted host must be refused, got: {response}"
    );
    assert!(
        h.origin.received.lock().unwrap().is_empty(),
        "the origin must never have been contacted"
    );
}

#[test]
fn a_method_outside_the_route_is_refused() {
    let h = harness(&["GET"], None, 1024);
    let token = session(&h);

    let response = get_via_proxy(&h, &token, "DELETE", &h.origin.addr);
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "DELETE is not in the route's method list, got: {response}"
    );
    assert!(h.origin.received.lock().unwrap().is_empty());
}

#[test]
fn an_empty_method_list_permits_nothing() {
    // Deny-by-default: an empty allowlist is not "allow everything".
    let h = harness(&[], None, 1024);
    let token = session(&h);

    let response = get_via_proxy(&h, &token, "GET", &h.origin.addr);
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "an empty method list must permit nothing, got: {response}"
    );
}

#[test]
fn requests_without_a_session_token_are_refused() {
    let h = harness(&["GET"], None, 1024);
    let host = h.origin.addr.clone();

    let response = through_proxy(
        &h.proxy_addr,
        &format!("GET http://{host}/path HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(
        response.starts_with("HTTP/1.1 407"),
        "an unauthenticated request must be refused, got: {response}"
    );
    assert!(h.origin.received.lock().unwrap().is_empty());
}

#[test]
fn an_unknown_session_token_is_refused() {
    let h = harness(&["GET"], None, 1024);
    let response = get_via_proxy(&h, "aiv-ses-not-a-real-token", "GET", &h.origin.addr);
    assert!(
        response.starts_with("HTTP/1.1 407"),
        "a forged token must be refused, got: {response}"
    );
}

#[test]
fn the_credential_is_added_on_the_way_out_and_the_token_is_stripped() {
    let h = harness(
        &["GET"],
        Some(("Authorization", "Bearer super-secret")),
        1024,
    );
    let token = session(&h);

    let response = get_via_proxy(&h, &token, "GET", &h.origin.addr);
    assert!(response.starts_with("HTTP/1.1 200 OK"));

    let seen = h.origin.received.lock().unwrap();
    let head = seen.first().expect("origin saw a request");

    assert!(
        head.contains("Authorization: Bearer super-secret"),
        "the credential should have been injected host-side: {head}"
    );
    // The sandbox's own session token is a hop-by-hop credential for the
    // proxy. Forwarding it would hand the origin something that identifies
    // the sandbox and can be replayed against the broker.
    assert!(
        !head.contains("Proxy-Authorization"),
        "the session token must not be forwarded to the origin: {head}"
    );
    assert!(
        !head.to_lowercase().contains(&token.to_lowercase()),
        "the session token must not appear anywhere in the upstream request: {head}"
    );
}

#[test]
fn a_body_over_the_limit_is_refused_before_it_is_relayed() {
    let h = harness(&["POST"], None, 16);
    let token = session(&h);
    let host = h.origin.addr.clone();

    let body = "x".repeat(64);
    let request = format!(
        "POST http://{host}/path HTTP/1.1\r\n\
         Host: {host}\r\n\
         Proxy-Authorization: Bearer {token}\r\n\
         Content-Length: {}\r\n\
         \r\n{body}",
        body.len()
    );
    let response = through_proxy(&h.proxy_addr, &request);

    assert!(
        response.starts_with("HTTP/1.1 413"),
        "an oversized body must be refused, got: {response}"
    );
    assert!(
        h.origin.received.lock().unwrap().is_empty(),
        "the limit must be enforced before anything is forwarded"
    );
}

#[test]
fn a_chunked_body_is_refused_rather_than_relayed_unmeasured() {
    let h = harness(&["POST"], None, 1024);
    let token = session(&h);
    let host = h.origin.addr.clone();

    let request = format!(
        "POST http://{host}/path HTTP/1.1\r\n\
         Host: {host}\r\n\
         Proxy-Authorization: Bearer {token}\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n"
    );
    let response = through_proxy(&h.proxy_addr, &request);
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "chunked bodies bypass the size limit, so they must be refused: {response}"
    );
}

#[test]
fn exhausting_the_byte_budget_stops_further_egress() {
    let h = harness(&["GET"], None, 1024);
    let token = session(&h);

    // Spend the whole budget, then try to use the session.
    let budget = h.broker.remaining_budget(&token).expect("budget");
    h.broker
        .record_bytes(&token, budget)
        .expect("consume the budget");
    assert_eq!(h.broker.remaining_budget(&token), Some(0));

    let response = get_via_proxy(&h, &token, "GET", &h.origin.addr);
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "a session with no budget left must not egress, got: {response}"
    );
}

#[test]
fn a_wildcard_route_matches_subdomains_but_not_the_apex() {
    let route = Route {
        hosts: vec!["*.example.com".into()],
        methods: vec!["GET".into()],
    };
    let policy = EgressPolicy {
        routes: vec![route],
        max_request_bytes: 1024,
        secrets: Arc::new(StaticSecrets::new()),
    };
    // Exercised through the public matcher via a request path in the other
    // tests; here the concern is only the pattern semantics.
    assert!(policy_allows(&policy, "api.example.com"));
    assert!(policy_allows(&policy, "deep.api.example.com"));
    assert!(
        !policy_allows(&policy, "example.com"),
        "a bare apex is not a subdomain and must not match *.example.com"
    );
    assert!(
        !policy_allows(&policy, "notexample.com"),
        "suffix matching must respect the dot boundary"
    );
    assert!(
        !policy_allows(&policy, "example.com.evil.test"),
        "the pattern must not match when it appears mid-name"
    );
}

/// Small shim so the wildcard test can ask the policy a question without
/// `route_for` being public.
fn policy_allows(policy: &EgressPolicy, host: &str) -> bool {
    policy.permits_host(host)
}

/// CONNECT is how HTTPS traverses the proxy. If the host allowlist were not
/// applied to it, an agent could tunnel anywhere and every other control in
/// this file would be decoration.
#[test]
fn connect_to_an_unlisted_host_is_refused() {
    let h = harness(&["GET"], None, 1024);
    let token = session(&h);

    let response = through_proxy(
        &h.proxy_addr,
        &format!(
            "CONNECT example.invalid:443 HTTP/1.1\r\n\
             Proxy-Authorization: Bearer {token}\r\n\r\n"
        ),
    );
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "CONNECT must honour the host allowlist, got: {response}"
    );
}

#[test]
fn connect_without_a_token_is_refused() {
    let h = harness(&["GET"], None, 1024);
    let host = h.origin.addr.clone();

    let response = through_proxy(&h.proxy_addr, &format!("CONNECT {host} HTTP/1.1\r\n\r\n"));
    assert!(
        response.starts_with("HTTP/1.1 407"),
        "CONNECT must require a session token, got: {response}"
    );
}

/// The allowed case, so the refusal above is known to be policy talking and
/// not CONNECT being broken outright. The tunnel carries a plain HTTP
/// request to the origin, which is enough to show bytes flow both ways.
#[test]
fn connect_to_an_allowed_host_tunnels_bytes() {
    let h = harness(&["GET"], None, 1024);
    let token = session(&h);
    let host = h.origin.addr.clone();

    let mut stream = TcpStream::connect(&h.proxy_addr).expect("connect proxy");
    write!(
        stream,
        "CONNECT {host} HTTP/1.1\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut status = String::new();
    reader.read_line(&mut status).expect("read status");
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected the tunnel to be established, got: {status}"
    );
    // Consume the blank line ending the CONNECT response.
    let mut blank = String::new();
    reader.read_line(&mut blank).expect("read blank");

    // Now speak to the origin through the tunnel.
    write!(stream, "GET /tunnelled HTTP/1.1\r\nHost: {host}\r\n\r\n").expect("write tunnelled");
    let mut body = String::new();
    reader.read_to_string(&mut body).expect("read tunnelled");
    assert!(
        body.contains("hello from origin"),
        "bytes should have flowed through the tunnel, got: {body}"
    );
}
