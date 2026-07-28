//! Scenario: Exec a denied binary (/usr/bin/perl when only the sandbox's
//! own launched command is allowed).
//!
//! Expected: BLOCKED (execve fails with EACCES / EPERM — a spawn failure
//! for any OTHER reason, e.g. the binary simply doesn't exist in this
//! rootfs, does not prove exec control fired, so it is UNVERIFIED, not
//! BLOCKED).

use aivisor_escape_bench::Outcome;

fn main() {
    match std::process::Command::new("/usr/bin/perl")
        .arg("-e")
        .arg("print 1")
        .spawn()
    {
        Ok(mut child) => {
            let _ = child.kill();
            Outcome::Escaped.print_and_exit("exec /usr/bin/perl")
        }
        Err(e) if aivisor_escape_bench::is_permission_denied(&e) => {
            Outcome::Blocked.print_and_exit("exec /usr/bin/perl")
        }
        Err(e) => Outcome::Unverified(e.to_string()).print_and_exit("exec /usr/bin/perl"),
    }
}
