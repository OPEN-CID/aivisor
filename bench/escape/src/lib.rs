//! Shared by every `bench/escape/*` scenario binary: a small, honest
//! three-way outcome classifier. The bug this replaces (see git history /
//! the project review) was scenarios that printed the string "BLOCKED" in
//! *both* branches of an error match, so any failure at all — including
//! "the target file doesn't exist in this rootfs", which proves nothing
//! about whether a security control fired — counted as a pass.

use std::io;

#[derive(Debug)]
pub enum Outcome {
    /// The attempted operation was denied by a security control (a
    /// permission-class errno, or — for network scenarios — a route-level
    /// unreachability consistent with "no default route unless NetCap
    /// grants one").
    Blocked,
    /// The attempted operation succeeded. This is what the escape suite
    /// exists to catch.
    Escaped,
    /// Neither of the above: the scenario's precondition wasn't met (the
    /// target file/binary doesn't exist in this rootfs, the command
    /// couldn't even be spawned, etc). This is NOT a pass — it means the
    /// scenario didn't actually exercise the control it claims to test.
    Unverified(String),
}

impl Outcome {
    /// Print the harness-recognized `KIND: scenario (detail)` line and
    /// exit with a distinct code per outcome so a caller that only checks
    /// the exit code (not stdout) still gets the three-way distinction:
    /// 0 = BLOCKED, 1 = ESCAPED, 2 = UNVERIFIED.
    pub fn print_and_exit(self, scenario: &str) -> ! {
        match self {
            Outcome::Blocked => {
                println!("BLOCKED: {scenario}");
                std::process::exit(0);
            }
            Outcome::Escaped => {
                println!("ESCAPED: {scenario}");
                std::process::exit(1);
            }
            Outcome::Unverified(detail) => {
                println!("UNVERIFIED: {scenario} ({detail})");
                std::process::exit(2);
            }
        }
    }
}

/// EPERM or EACCES — the two errnos a Landlock/eBPF-LSM/capability denial
/// actually surfaces as. Checked via raw_os_error rather than relying
/// solely on `ErrorKind::PermissionDenied`, since not every code path that
/// produces one of these errnos is guaranteed to classify identically
/// across std versions/platforms.
pub fn is_permission_denied(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(1) | Some(13)) || e.kind() == io::ErrorKind::PermissionDenied
}

/// For network-reachability scenarios: a sandbox with no NetCap grant has
/// no default route at all (blueprint §9.1), so a denied connect can
/// legitimately surface as "unreachable" rather than "permission denied" —
/// both are valid evidence of deny-by-default, neither is a bypass.
pub fn is_denied_or_unreachable(e: &io::Error) -> bool {
    if is_permission_denied(e) {
        return true;
    }
    // ENETUNREACH = 101, EHOSTUNREACH = 113, ECONNREFUSED = 111 (Linux).
    matches!(e.raw_os_error(), Some(101) | Some(113) | Some(111))
        || matches!(
            e.kind(),
            io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::ConnectionRefused
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_denied_classification() {
        let e = io::Error::from_raw_os_error(13); // EACCES
        assert!(is_permission_denied(&e));
        let e = io::Error::from_raw_os_error(1); // EPERM
        assert!(is_permission_denied(&e));
        let e = io::Error::from_raw_os_error(2); // ENOENT
        assert!(!is_permission_denied(&e));
    }

    #[test]
    fn test_network_unreachable_counts_as_denied() {
        let e = io::Error::from_raw_os_error(101); // ENETUNREACH
        assert!(is_denied_or_unreachable(&e));
        let e = io::Error::from_raw_os_error(2); // ENOENT — not a network denial signal
        assert!(!is_denied_or_unreachable(&e));
    }
}
