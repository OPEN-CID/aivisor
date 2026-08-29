//! Runtime capability grants — the one sanctioned way a sandbox's privilege
//! set may widen after launch.
//!
//! blueprint.md §8.4 states invariant M: *a sandbox's effective privilege set
//! may only shrink over its lifetime, except through an explicit
//! `GrantCapability` call from the control plane, which is authenticated and
//! audited.* This module is the type behind that exception. It is pure data
//! — parsing and equality only, no syscalls — so the shape of a grant can be
//! validated and logged before anything is installed in a kernel map.
//!
//! The wire form is a single compact string, matching
//! `GrantCapabilityRequest.capability` in `proto/aivisor/v1/aivisor.proto`:
//!
//! ```text
//!   net:<cidr>:<port>[,<port>...]      net:203.0.113.7/32:53
//!   fs:<path>:<access>[,<access>...]   fs:/data:read,write
//!   exec:<path>                        exec:/usr/bin/git
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A single privilege that can be granted to, or revoked from, a running
/// sandbox.
///
/// What each variant can actually achieve at runtime differs, and the
/// difference is a property of the kernel rather than of this crate — see
/// the `grant_capability` documentation in `aivisor-runtime`'s
/// `SandboxManager` for which grants a live sandbox can accept and why
/// Landlock bounds the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Direct egress to a CIDR on a set of ports.
    Network { cidr: String, ports: Vec<u16> },
    /// Filesystem access rights on a path, using the same access verbs as a
    /// policy document (`read`, `write`, `execute`, `create`, `delete`,
    /// `truncate`).
    Filesystem { path: String, access: Vec<String> },
    /// Permission to execute one binary.
    Exec { path: String },
}

impl Capability {
    /// A short, stable label for audit records — the kind of grant without
    /// its parameters.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Network { .. } => "net",
            Self::Filesystem { .. } => "fs",
            Self::Exec { .. } => "exec",
        }
    }
}

/// Why a capability string could not be understood.
///
/// Parsing is strict, and deliberately so: a control plane that typos a
/// grant should get an error, not a capability that quietly means something
/// else. The failure mode being avoided is a malformed port list parsing as
/// a *shorter* list — granting less than intended is survivable, but the
/// same leniency applied to a CIDR could widen a grant instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityParseError(String);

impl fmt::Display for CapabilityParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CapabilityParseError {}

impl FromStr for Capability {
    type Err = CapabilityParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |m: String| CapabilityParseError(m);

        let (kind, rest) = s.split_once(':').ok_or_else(|| {
            err(format!(
                "capability {s:?} has no kind prefix — expected one of \
                 net:<cidr>:<ports>, fs:<path>:<access>, exec:<path>"
            ))
        })?;

        match kind {
            "net" => {
                // rsplit: an IPv6 literal would contain colons, and while
                // v1 only enforces IPv4 (see net.bpf.c), splitting from the
                // right keeps this parser from mangling the address of a
                // form it should reject with a clear message later.
                let (cidr, ports) = rest.rsplit_once(':').ok_or_else(|| {
                    err(format!(
                        "network capability {s:?} has no port list — expected \
                         net:<cidr>:<port>[,<port>...]"
                    ))
                })?;
                if cidr.is_empty() {
                    return Err(err(format!("network capability {s:?} has an empty CIDR")));
                }
                let ports = ports
                    .split(',')
                    .map(|p| {
                        p.trim().parse::<u16>().map_err(|_| {
                            err(format!("network capability {s:?}: {p:?} is not a port"))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if ports.is_empty() {
                    return Err(err(format!("network capability {s:?} lists no ports")));
                }
                Ok(Self::Network {
                    cidr: cidr.to_string(),
                    ports,
                })
            }
            "fs" => {
                let (path, access) = rest.rsplit_once(':').ok_or_else(|| {
                    err(format!(
                        "filesystem capability {s:?} has no access list — expected \
                         fs:<path>:<access>[,<access>...]"
                    ))
                })?;
                check_absolute(path, s).map_err(err)?;
                let access: Vec<String> = access
                    .split(',')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect();
                if access.is_empty() {
                    return Err(err(format!(
                        "filesystem capability {s:?} lists no access rights"
                    )));
                }
                Ok(Self::Filesystem {
                    path: path.to_string(),
                    access,
                })
            }
            "exec" => {
                check_absolute(rest, s).map_err(err)?;
                Ok(Self::Exec {
                    path: rest.to_string(),
                })
            }
            other => Err(err(format!(
                "unknown capability kind {other:?} in {s:?} — expected net, fs or exec"
            ))),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network { cidr, ports } => {
                let ports: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "net:{cidr}:{}", ports.join(","))
            }
            Self::Filesystem { path, access } => {
                write!(f, "fs:{path}:{}", access.join(","))
            }
            Self::Exec { path } => write!(f, "exec:{path}"),
        }
    }
}

/// Paths in a capability are paths *inside* the sandbox, and both Landlock
/// rules and BPF fs-rule hashes are anchored on exact absolute paths. A
/// relative path would hash to something no hook ever produces, so the
/// grant would install cleanly and enforce nothing.
fn check_absolute(path: &str, full: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!(
            "capability {full:?}: path {path:?} must be absolute — rules are anchored on \
             exact in-sandbox paths, so a relative path would match nothing"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_network_grant() {
        let cap: Capability = "net:203.0.113.7/32:53,80".parse().unwrap();
        assert_eq!(
            cap,
            Capability::Network {
                cidr: "203.0.113.7/32".into(),
                ports: vec![53, 80],
            }
        );
        assert_eq!(cap.kind(), "net");
    }

    #[test]
    fn parses_a_filesystem_grant() {
        let cap: Capability = "fs:/data:read,write".parse().unwrap();
        assert_eq!(
            cap,
            Capability::Filesystem {
                path: "/data".into(),
                access: vec!["read".into(), "write".into()],
            }
        );
    }

    #[test]
    fn parses_an_exec_grant() {
        let cap: Capability = "exec:/usr/bin/git".parse().unwrap();
        assert_eq!(
            cap,
            Capability::Exec {
                path: "/usr/bin/git".into()
            }
        );
    }

    #[test]
    fn every_form_round_trips_through_its_string() {
        for s in [
            "net:10.0.0.0/8:53",
            "fs:/workspace:read,write,create",
            "exec:/bin/sh",
        ] {
            let cap: Capability = s.parse().unwrap();
            assert_eq!(cap.to_string(), s);
        }
    }

    #[test]
    fn relative_paths_are_refused() {
        // A relative path hashes to something no hook produces, so the
        // grant would look installed and enforce nothing.
        assert!("fs:data:read".parse::<Capability>().is_err());
        assert!("exec:git".parse::<Capability>().is_err());
    }

    #[test]
    fn malformed_grants_are_errors_not_silently_narrower_ones() {
        for s in [
            "",
            "net",
            "net:10.0.0.0/8",        // no ports
            "net:10.0.0.0/8:",       // empty port list
            "net:10.0.0.0/8:http",   // not a number
            "net:10.0.0.0/8:70000",  // out of u16 range
            "net::53",               // empty cidr
            "fs:/data",              // no access list
            "fs:/data:",             // empty access list
            "capability:/data:read", // unknown kind
            "exec:",                 // empty path
        ] {
            assert!(
                s.parse::<Capability>().is_err(),
                "{s:?} should not have parsed"
            );
        }
    }
}
