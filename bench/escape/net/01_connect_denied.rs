//! Scenario: Connect to a denied IP address
//!
//! Expected: BLOCKED — either EPERM (L5 eBPF LSM socket_connect denied it)
//! or a route-level unreachable (the sandbox netns has no default route at
//! all when no NetCap grants egress — blueprint §9.1). Both are evidence
//! of deny-by-default; only a successful connect is an escape.

use aivisor_escape_bench::Outcome;
use std::net::{TcpStream, ToSocketAddrs};

fn main() {
    let addr = match "1.1.1.1:80".to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => Outcome::Unverified("could not resolve 1.1.1.1:80".into())
                .print_and_exit("connect to denied IP"),
        },
        Err(e) => {
            Outcome::Unverified(format!("address parse failed: {e}")).print_and_exit("connect to denied IP")
        }
    };

    match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)) {
        Ok(_) => Outcome::Escaped.print_and_exit("connect to denied IP"),
        Err(e) if aivisor_escape_bench::is_denied_or_unreachable(&e) => {
            Outcome::Blocked.print_and_exit("connect to denied IP")
        }
        Err(e) => Outcome::Unverified(e.to_string()).print_and_exit("connect to denied IP"),
    }
}
