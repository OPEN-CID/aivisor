//! Scenario: Direct read of /etc/shadow (should be blocked by Landlock)
//!
//! Attempts: open("/etc/shadow", O_RDONLY)
//! Expected: BLOCKED (EPERM or EACCES)

use aivisor_escape_bench::Outcome;

fn main() {
    match std::fs::read_to_string("/etc/shadow") {
        Ok(_) => Outcome::Escaped.print_and_exit("read /etc/shadow"),
        Err(e) if aivisor_escape_bench::is_permission_denied(&e) => {
            Outcome::Blocked.print_and_exit("read /etc/shadow")
        }
        Err(e) => Outcome::Unverified(e.to_string()).print_and_exit("read /etc/shadow"),
    }
}
