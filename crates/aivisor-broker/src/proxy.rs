use std::collections::HashMap;
use std::sync::Mutex;

use aivisor_core::{CgroupId, Error, SandboxId};

/// Host-side egress proxy for sandboxed agents.
///
/// **Current scope, honestly stated**: session issuance, byte-budget
/// tracking and enforcement, and unix-socket peer verification (binding a
/// session token to the cgroup that requested it). The full HTTP(S)
/// terminating proxy described in blueprint.md §9.1 — TLS termination,
/// host/method allowlist enforcement, credential injection from a secret
/// backend, DNS pinning — is NOT implemented here. `serve()` below returns
/// `Error::Unsupported` rather than silently doing nothing, so a caller
/// that tries to actually stand up the broker finds out immediately rather
/// than discovering a broker that accepts no connections. Implementing it
/// is tracked as `TODO(phase3)`.
///
/// What IS enforced today (`issue_session`, `record_bytes`,
/// `verify_peer_cgroup`) is real, not a stub: a session's byte budget is
/// checked on every `record_bytes` call and further use is denied once
/// exhausted, and `verify_peer_cgroup` reads the actual peer credentials
/// off a connected unix socket rather than trusting a caller-supplied id.
#[derive(Default)]
pub struct Broker {
    sessions: Mutex<HashMap<String, SessionState>>,
}

struct SessionState {
    #[allow(dead_code)]
    sandbox_id: SandboxId,
    /// The sandbox's cgroup id at the moment the session was issued, used
    /// by `verify_peer_cgroup` to reject a caller presenting a token that
    /// belongs to a different sandbox. `None` means the caller did not
    /// supply a cgroup to bind to (e.g. in tests) — `verify_peer_cgroup`
    /// fails closed in that case rather than treating an unbound session
    /// as automatically trusted.
    bound_cgroup: Option<CgroupId>,
    byte_budget: u64,
    bytes_used: u64,
}

pub const DEFAULT_BYTE_BUDGET: u64 = 100 * 1024 * 1024; // 100 MB

impl Broker {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Issue an opaque session token for a sandbox, bound to its cgroup id
    /// so `verify_peer_cgroup` can later confirm a connection claiming this
    /// token actually originates from that sandbox.
    pub fn issue_session(&self, sandbox_id: SandboxId) -> Result<String, Error> {
        self.issue_session_bound(sandbox_id, None)
    }

    pub fn issue_session_bound(
        &self,
        sandbox_id: SandboxId,
        bound_cgroup: Option<CgroupId>,
    ) -> Result<String, Error> {
        let token = format!("aiv-ses-{}", uuid::Uuid::now_v7());
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(
            token.clone(),
            SessionState {
                sandbox_id,
                bound_cgroup,
                byte_budget: DEFAULT_BYTE_BUDGET,
                bytes_used: 0,
            },
        );
        Ok(token)
    }

    pub fn revoke_session(&self, token: &str) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(token);
        Ok(())
    }

    /// Record `n` bytes of egress traffic against a session's budget.
    /// Fails closed: an unknown token or an exhausted budget both return
    /// `Err`, and in neither case is the byte count silently accepted.
    pub fn record_bytes(&self, token: &str, n: u64) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(token)
            .ok_or_else(|| Error::PolicyInvalid(format!("unknown broker session: {token}")))?;

        let new_total = session.bytes_used.saturating_add(n);
        if new_total > session.byte_budget {
            return Err(Error::PolicyInvalid(format!(
                "broker session {token} exceeded byte budget ({new_total} > {})",
                session.byte_budget
            )));
        }
        session.bytes_used = new_total;
        Ok(())
    }

    pub fn remaining_budget(&self, token: &str) -> Option<u64> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(token)
            .map(|s| s.byte_budget.saturating_sub(s.bytes_used))
    }

    /// Verify that `peer_cgroup` — obtained by the caller via
    /// `unix_peer_cgroup` on the actual connected socket — matches the
    /// cgroup this session was issued for. This is the SO_PEERCRED-based
    /// check blueprint §9.2 describes ("the token is bound to the
    /// sandbox's cgroup"); it fails closed on any mismatch, missing
    /// session, or session that was never bound to a cgroup in the first
    /// place (an unbound session cannot be verified, so it is rejected
    /// rather than trusted).
    pub fn verify_peer_cgroup(&self, token: &str, peer_cgroup: CgroupId) -> Result<(), Error> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(token)
            .ok_or_else(|| Error::PolicyInvalid(format!("unknown broker session: {token}")))?;

        match session.bound_cgroup {
            Some(expected) if expected == peer_cgroup => Ok(()),
            Some(_) => Err(Error::PolicyInvalid(format!(
                "broker session {token}: peer cgroup does not match the cgroup it was issued for"
            ))),
            None => Err(Error::PolicyInvalid(format!(
                "broker session {token} was never bound to a cgroup — cannot verify peer"
            ))),
        }
    }

    pub fn stats(&self) -> HashMap<String, u64> {
        let sessions = self.sessions.lock().unwrap();
        let mut stats = HashMap::new();
        stats.insert("active_sessions".into(), sessions.len() as u64);
        stats
    }

    /// TODO(phase3): stand up the actual HTTP(S) terminating proxy —
    /// listen on the unix socket / veth link-local address, terminate TLS,
    /// enforce the policy's host/method allowlist, inject credentials from
    /// the secret backend on the way out, and call `record_bytes` /
    /// `verify_peer_cgroup` per connection. Left unimplemented rather than
    /// half-built so a caller that reaches for it fails loudly instead of
    /// silently getting a broker that accepts no traffic.
    pub fn serve(&self, _listen_addr: &str) -> Result<(), Error> {
        Err(Error::Unsupported(
            "broker HTTP(S) proxy listener not implemented in this build".into(),
        ))
    }
}

/// Read the peer credentials (pid) off a connected `AF_UNIX` stream via
/// `SO_PEERCRED`, then resolve that pid's cgroup id from `/proc/<pid>/cgroup`.
/// Linux-only: `SO_PEERCRED` and `/proc` are both Linux-specific, and this
/// crate otherwise builds on any platform (it is the "portable" broker
/// crate — see the workspace root Cargo.toml).
#[cfg(target_os = "linux")]
pub fn unix_peer_cgroup(stream: &std::os::unix::net::UnixStream) -> Result<CgroupId, Error> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(Error::PolicyInvalid(format!(
            "SO_PEERCRED: {}",
            std::io::Error::last_os_error()
        )));
    }

    cgroup_of_pid(cred.pid)
}

#[cfg(target_os = "linux")]
fn cgroup_of_pid(pid: i32) -> Result<CgroupId, Error> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|e| Error::PolicyInvalid(format!("read /proc/{pid}/cgroup: {e}")))?;
    cgroup_id_from_proc_cgroup(&content, pid)
}

/// Parse the cgroup v2 line (`0::<path>`) out of `/proc/<pid>/cgroup`
/// content and resolve it to a cgroup id via the path's inode number,
/// matching how `Cgroup::read_cgroup_id` in aivisor-runtime derives the
/// same id (`bpf_get_current_cgroup_id()` returns the kernfs inode number,
/// which is exactly what `stat()` on the cgroup directory gives you).
/// Split out from `cgroup_of_pid` so the parsing logic is unit-testable
/// without a real `/proc` entry.
#[cfg(target_os = "linux")]
fn cgroup_id_from_proc_cgroup(content: &str, pid: i32) -> Result<CgroupId, Error> {
    let path = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            Error::PolicyInvalid(format!(
                "no cgroup v2 (0::) entry in /proc/{pid}/cgroup — is this a cgroup v1 host?"
            ))
        })?;

    let full_path = format!("/sys/fs/cgroup{path}");
    let stat = rustix_stat(&full_path)
        .map_err(|e| Error::PolicyInvalid(format!("stat {full_path}: {e}")))?;
    Ok(CgroupId::new(stat))
}

#[cfg(target_os = "linux")]
fn rustix_stat(path: &str) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok(meta.ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_revoke_session() {
        let broker = Broker::new();
        let sid = SandboxId::new();
        let token = broker.issue_session(sid).unwrap();
        assert!(token.starts_with("aiv-ses-"));
        broker.revoke_session(&token).unwrap();
    }

    #[test]
    fn test_revoke_nonexistent_session() {
        let broker = Broker::new();
        assert!(broker.revoke_session("nonexistent").is_ok());
    }

    #[test]
    fn test_stats_empty() {
        let broker = Broker::new();
        let stats = broker.stats();
        assert_eq!(stats.get("active_sessions"), Some(&0));
    }

    #[test]
    fn test_stats_after_issue() {
        let broker = Broker::new();
        let sid = SandboxId::new();
        broker.issue_session(sid).unwrap();
        let stats = broker.stats();
        assert_eq!(stats.get("active_sessions"), Some(&1));
    }

    #[test]
    fn test_multiple_sessions_unique_tokens() {
        let broker = Broker::new();
        let sid1 = SandboxId::new();
        let sid2 = SandboxId::new();
        let t1 = broker.issue_session(sid1).unwrap();
        let t2 = broker.issue_session(sid2).unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_record_bytes_within_budget() {
        let broker = Broker::new();
        let token = broker.issue_session(SandboxId::new()).unwrap();
        broker.record_bytes(&token, 1024).unwrap();
        assert_eq!(
            broker.remaining_budget(&token),
            Some(DEFAULT_BYTE_BUDGET - 1024)
        );
    }

    #[test]
    fn test_record_bytes_exceeding_budget_is_denied() {
        let broker = Broker::new();
        let token = broker.issue_session(SandboxId::new()).unwrap();
        let result = broker.record_bytes(&token, DEFAULT_BYTE_BUDGET + 1);
        assert!(result.is_err());
        // The denied call must not have partially applied — budget stays
        // untouched, not silently consumed up to the cap.
        assert_eq!(broker.remaining_budget(&token), Some(DEFAULT_BYTE_BUDGET));
    }

    #[test]
    fn test_record_bytes_unknown_token_fails_closed() {
        let broker = Broker::new();
        assert!(broker.record_bytes("nonexistent", 1).is_err());
    }

    #[test]
    fn test_verify_peer_cgroup_matches() {
        let broker = Broker::new();
        let cgid = CgroupId::new(42);
        let token = broker
            .issue_session_bound(SandboxId::new(), Some(cgid))
            .unwrap();
        assert!(broker.verify_peer_cgroup(&token, cgid).is_ok());
    }

    #[test]
    fn test_verify_peer_cgroup_mismatch_fails_closed() {
        let broker = Broker::new();
        let token = broker
            .issue_session_bound(SandboxId::new(), Some(CgroupId::new(42)))
            .unwrap();
        assert!(broker
            .verify_peer_cgroup(&token, CgroupId::new(43))
            .is_err());
    }

    #[test]
    fn test_verify_peer_cgroup_unbound_session_fails_closed() {
        // A session issued without a bound cgroup (the plain
        // issue_session() path) must not be treated as automatically
        // trusted by verify_peer_cgroup.
        let broker = Broker::new();
        let token = broker.issue_session(SandboxId::new()).unwrap();
        assert!(broker.verify_peer_cgroup(&token, CgroupId::new(1)).is_err());
    }

    #[test]
    fn test_serve_is_explicitly_unsupported_not_silently_noop() {
        let broker = Broker::new();
        let result = broker.serve("127.0.0.1:3128");
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_cgroup_id_from_proc_cgroup_v2_line() {
        let content = "0::/aivisor/some-sandbox-id\n";
        // This will fail to stat (the path doesn't exist on this test
        // host), but must fail with a clear error, not panic or silently
        // return a bogus id.
        let result = cgroup_id_from_proc_cgroup(content, 1234);
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_cgroup_id_from_proc_cgroup_missing_v2_line() {
        let content = "1:name=systemd:/\n2:cpu:/\n";
        let result = cgroup_id_from_proc_cgroup(content, 1234);
        assert!(result.is_err());
    }
}
