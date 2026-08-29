use std::path::PathBuf;

use aivisor_core::{Capability, Error};

#[derive(Debug, Clone)]
pub struct Policy {
    pub api_version: String,
    pub kind: String,
    pub metadata_name: String,
    pub filesystem: Option<FsPolicy>,
    pub exec: Option<ExecPolicy>,
    pub network: Option<NetPolicy>,
    pub runtime: Option<RuntimeOpts>,
    pub audit: Option<AuditOpts>,
}

#[derive(Debug, Clone)]
pub struct FsPolicy {
    pub default: AccessDefault,
    pub rules: Vec<FsRule>,
}

#[derive(Debug, Clone)]
pub struct FsRule {
    pub path: String,
    pub access: Vec<String>,
    pub recursive: bool,
}

#[derive(Debug, Clone)]
pub struct ExecPolicy {
    pub default: AccessDefault,
    pub allow: Vec<ExecRule>,
}

#[derive(Debug, Clone)]
pub enum ExecRule {
    Path { path: String, pin: Option<String> },
    Prefix(PathBuf),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AccessDefault {
    Deny,
    Allow,
}

#[derive(Debug, Clone)]
pub struct NetPolicy {
    pub default: AccessDefault,
    pub egress: Vec<NetRule>,
    pub block_metadata: bool,
    pub dns_policy: Option<String>,
}

#[derive(Debug, Clone)]
pub enum NetRule {
    BrokerRoute {
        hosts: Vec<String>,
        methods: Vec<String>,
    },
    Direct {
        cidr: String,
        ports: Vec<u16>,
    },
}

#[derive(Debug, Clone)]
pub struct RuntimeOpts {
    pub seccomp_profile: Option<String>,
    pub landlock_abi_min: Option<u32>,
    pub timeout: Option<String>,
    pub max_idle: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditOpts {
    pub level: Option<String>,
    pub sink: Option<String>,
}

/// `Clone` because the plan is also the record of what Landlock was
/// restricted to at launch: `SandboxManager` keeps a copy per sandbox to
/// bound later capability grants (see [`LandlockPlan::permits`]).
#[derive(Debug, Clone)]
pub struct LandlockPlan {
    pub rules: Vec<LandlockRule>,
    pub abi: u32,
}

#[derive(Debug, Clone)]
pub struct LandlockRule {
    pub path: PathBuf,
    pub access_mask: u64,
}

#[derive(Debug)]
pub struct BpfPlan {
    pub fs_rules: Vec<BpfFsRule>,
    pub exec_rules: Vec<BpfExecRule>,
    pub net_rules: Vec<BpfNetRule>,
    /// True once at least one exec rule exists, so an empty `exec_rules`
    /// (deny-all-exec) can be told apart from "policy has no exec section
    /// at all" (which falls back to profile defaults upstream).
    pub exec_policy_present: bool,
    pub block_metadata: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct BpfFsRule {
    pub path_hash: u64,
    pub access_mask: u64,
}

#[derive(Debug, Clone)]
pub struct BpfExecRule {
    /// Absolute path; the loader resolves this to (dev, inode) at policy
    /// install time — inode numbers are not stable across the parse step.
    pub path: String,
    pub is_prefix: bool,
    pub hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct BpfNetRule {
    pub cidr: String,
    pub ports: Vec<u16>,
}

#[derive(Debug)]
pub struct SeccompPlan {
    pub profile: String,
}

/// Landlock filesystem access-right bits (LANDLOCK_ACCESS_FS_*), per
/// include/uapi/linux/landlock.h. These are not exposed by the `libc` crate
/// so they are the single source of truth for both the compiler (here) and
/// the ABI-gated `handled_access_fs` set built in aivisor-runtime::landlock.
/// The two MUST stay in sync — see `aivisor_runtime::landlock::landlock_handled_set`.
pub mod landlock_bits {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    /// ABI >= 2
    pub const REFER: u64 = 1 << 13;
    /// ABI >= 3
    pub const TRUNCATE: u64 = 1 << 14;
    /// ABI >= 5
    pub const IOCTL_DEV: u64 = 1 << 15;

    /// All FS access rights introduced at or before `abi`.
    pub fn known_at_abi(abi: u32) -> u64 {
        let mut mask = EXECUTE
            | WRITE_FILE
            | READ_FILE
            | READ_DIR
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_CHAR
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_BLOCK
            | MAKE_SYM;
        if abi >= 2 {
            mask |= REFER;
        }
        if abi >= 3 {
            mask |= TRUNCATE;
        }
        if abi >= 5 {
            mask |= IOCTL_DEV;
        }
        mask
    }
}

impl Policy {
    pub fn compile_landlock(&self, abi: u32) -> LandlockPlan {
        let known = landlock_bits::known_at_abi(abi);
        let mut rules = Vec::new();
        if let Some(ref fs) = self.filesystem {
            for rule in &fs.rules {
                // Mask off rights the running kernel doesn't know about
                // (Appendix A: requesting an unknown right is EINVAL, which
                // is a fail-open bug — never sandbox at all).
                let mask = Self::access_to_landlock_mask(&rule.access) & known;
                rules.push(LandlockRule {
                    path: PathBuf::from(&rule.path),
                    access_mask: mask,
                });
            }
        }
        // Exec rules also become Landlock EXECUTE (+READ_FILE, to load the
        // binary) grants. This matters because L5 (eBPF bprm_check_security,
        // the layer the blueprint designs exec hash-pinning around) is not
        // load-bearing in this build yet — Landlock is, so `spec.exec` must
        // not be silently dropped on the floor between the two.
        if let Some(ref exec) = self.exec {
            let exec_mask = (landlock_bits::EXECUTE | landlock_bits::READ_FILE) & known;
            for rule in &exec.allow {
                let path = match rule {
                    ExecRule::Path { path, .. } => path.clone(),
                    ExecRule::Prefix(p) => p.to_string_lossy().into_owned(),
                };
                rules.push(LandlockRule {
                    path: PathBuf::from(path),
                    access_mask: exec_mask,
                });
            }
        }
        LandlockPlan { rules, abi }
    }

    pub fn compile_bpf(&self) -> BpfPlan {
        let mut fs_rules = Vec::new();
        if let Some(ref fs) = self.filesystem {
            for rule in &fs.rules {
                fs_rules.push(BpfFsRule {
                    path_hash: hash_path(&rule.path),
                    access_mask: Self::access_to_landlock_mask(&rule.access),
                });
            }
        }

        let mut exec_rules = Vec::new();
        let exec_policy_present = self.exec.is_some();
        if let Some(ref exec) = self.exec {
            for rule in &exec.allow {
                match rule {
                    ExecRule::Path { path, pin } => {
                        exec_rules.push(BpfExecRule {
                            path: path.clone(),
                            is_prefix: false,
                            hash: pin.as_deref().and_then(parse_sha256_pin),
                        });
                    }
                    ExecRule::Prefix(prefix) => {
                        exec_rules.push(BpfExecRule {
                            path: prefix.to_string_lossy().into_owned(),
                            is_prefix: true,
                            hash: None,
                        });
                    }
                }
            }
        }

        let mut net_rules = Vec::new();
        let mut block_metadata = true;
        if let Some(ref net) = self.network {
            block_metadata = net.block_metadata;
            for rule in &net.egress {
                if let NetRule::Direct { cidr, ports } = rule {
                    net_rules.push(BpfNetRule {
                        cidr: cidr.clone(),
                        ports: ports.clone(),
                    });
                }
                // BrokerRoute traffic never reaches socket_connect() with the
                // real destination — it goes to the broker's local address —
                // so it compiles to broker allow-listing, not an L5 net rule.
            }
        }

        BpfPlan {
            fs_rules,
            exec_rules,
            net_rules,
            exec_policy_present,
            block_metadata,
        }
    }

    pub fn compile_seccomp(&self) -> SeccompPlan {
        let profile = self
            .runtime
            .as_ref()
            .and_then(|r| r.seccomp_profile.clone())
            .unwrap_or_else(|| "aivisor-default".into());
        SeccompPlan { profile }
    }

    /// Public because a runtime capability grant has to ask "does the
    /// Landlock ruleset installed at launch already permit this?" before it
    /// installs anything — see `LandlockPlan::permits`.
    pub fn access_to_landlock_mask(access: &[String]) -> u64 {
        use landlock_bits::*;
        let mut mask = 0u64;
        for a in access {
            match a.as_str() {
                "read" => mask |= READ_FILE | READ_DIR,
                "write" => mask |= WRITE_FILE,
                "execute" => mask |= EXECUTE,
                "create" => mask |= MAKE_REG | MAKE_DIR | MAKE_SYM | MAKE_FIFO | MAKE_SOCK,
                "delete" => mask |= REMOVE_FILE | REMOVE_DIR,
                "truncate" => mask |= TRUNCATE,
                _ => {}
            }
        }
        mask
    }
}

impl LandlockPlan {
    /// Whether the ruleset this plan describes already permits `required`
    /// on `path`.
    ///
    /// Landlock rules are added as `LANDLOCK_RULE_PATH_BENEATH` (see
    /// `aivisor_runtime::landlock::apply_landlock`), so a rule on a
    /// directory covers everything under it — hence the ancestor walk
    /// rather than an exact-path comparison.
    ///
    /// This is the ceiling test for a runtime capability grant. A Landlock
    /// ruleset composes by intersection and `restrict_self()` cannot be
    /// undone from outside the restricted process, so the set of rights
    /// L3 permits is fixed for a sandbox's whole life. A grant that L3
    /// would still deny must be refused rather than installed at L5,
    /// because installing it reports a widening the sandbox will never
    /// actually observe.
    pub fn permits(&self, path: &std::path::Path, required: u64) -> bool {
        if required == 0 {
            return true;
        }
        self.rules
            .iter()
            .any(|rule| path.starts_with(&rule.path) && rule.access_mask & required == required)
    }
}

impl Policy {
    /// A copy of this policy with `cap` added.
    ///
    /// Only the capabilities a running sandbox can actually be granted are
    /// accepted; see [`Policy::check_runtime_capability`] for why
    /// filesystem capabilities are not among them.
    pub fn with_capability_granted(&self, cap: &Capability) -> Result<Policy, Error> {
        Self::check_runtime_capability(cap)?;
        let mut next = self.clone();
        match cap {
            Capability::Network { cidr, ports } => {
                let net = next.network.get_or_insert_with(|| NetPolicy {
                    default: AccessDefault::Deny,
                    egress: Vec::new(),
                    block_metadata: true,
                    dns_policy: None,
                });
                // Merge into an existing rule for the same CIDR rather than
                // appending a second one. Two rules for one destination
                // compile to two writes of the same LPM key, so the second
                // would overwrite the first's port bitmap and silently undo
                // an earlier grant.
                match net
                    .egress
                    .iter_mut()
                    .find(|r| matches!(r, NetRule::Direct { cidr: c, .. } if c == cidr))
                {
                    Some(NetRule::Direct {
                        ports: existing, ..
                    }) => {
                        for p in ports {
                            if !existing.contains(p) {
                                existing.push(*p);
                            }
                        }
                        existing.sort_unstable();
                    }
                    _ => net.egress.push(NetRule::Direct {
                        cidr: cidr.clone(),
                        ports: ports.clone(),
                    }),
                }
            }
            Capability::Exec { path } => {
                let exec = next.exec.get_or_insert_with(|| ExecPolicy {
                    default: AccessDefault::Deny,
                    allow: Vec::new(),
                });
                let already = exec
                    .allow
                    .iter()
                    .any(|r| matches!(r, ExecRule::Path { path: p, .. } if p == path));
                if !already {
                    exec.allow.push(ExecRule::Path {
                        path: path.clone(),
                        // A runtime grant carries no `sha256:` pin. Adding
                        // one would be an install-time check against a file
                        // the granting side cannot see (it lives inside the
                        // sandbox's mount namespace), so claiming to pin it
                        // would be a claim this code cannot keep.
                        pin: None,
                    });
                }
            }
            Capability::Filesystem { .. } => unreachable!("refused by check_runtime_capability"),
        }
        Ok(next)
    }

    /// A copy of this policy with `cap` removed.
    ///
    /// Revocation is a narrowing, and narrowing is always sound at L5
    /// because both the exec and network hooks deny on no match — removing
    /// a rule is sufficient to deny. (This is *not* symmetric with granting,
    /// which is bounded by Landlock; see [`LandlockPlan::permits`].)
    pub fn with_capability_revoked(&self, cap: &Capability) -> Result<Policy, Error> {
        Self::check_runtime_capability(cap)?;
        let mut next = self.clone();
        match cap {
            Capability::Network { cidr, ports } => {
                if let Some(net) = next.network.as_mut() {
                    for rule in net.egress.iter_mut() {
                        if let NetRule::Direct {
                            cidr: c,
                            ports: existing,
                        } = rule
                        {
                            if c == cidr {
                                existing.retain(|p| !ports.contains(p));
                            }
                        }
                    }
                    // A Direct rule with no ports left would compile to an
                    // LPM entry with an all-zero bitmap: present in the map,
                    // matching nothing. Dropping it keeps the map free of
                    // entries that exist only to be rejected.
                    net.egress.retain(
                        |r| !matches!(r, NetRule::Direct { ports, .. } if ports.is_empty()),
                    );
                }
            }
            Capability::Exec { path } => {
                if let Some(exec) = next.exec.as_mut() {
                    exec.allow
                        .retain(|r| !matches!(r, ExecRule::Path { path: p, .. } if p == path));
                }
            }
            Capability::Filesystem { .. } => unreachable!("refused by check_runtime_capability"),
        }
        Ok(next)
    }

    /// Which capabilities may be changed on a *running* sandbox at all.
    ///
    /// Network and exec can: their L5 hooks (`lsm/socket_connect`,
    /// `cgroup/connect4|6`, `lsm/bprm_check_security`) deny on no match, so
    /// adding or removing a map entry changes the answer in both
    /// directions, and Landlock does not gate either one — the ruleset is
    /// built with `handled_access_net: 0`, and exec is additionally bounded
    /// by the EXECUTE ceiling the caller checks with
    /// [`LandlockPlan::permits`].
    ///
    /// Filesystem cannot, and refusing is the honest answer rather than a
    /// missing feature:
    ///
    /// * **Granting** more than Landlock already allows is impossible —
    ///   `restrict_self()` is irreversible and only the restricted process
    ///   can narrow itself further, so no daemon-side call can widen L3.
    ///   Granting *within* what Landlock allows changes nothing, because
    ///   `lsm/file_open` already allows any path it has no exact rule for
    ///   (see the scope note at the top of `fs.bpf.c` — L3 is the recursive
    ///   filesystem layer, L5 is an exact-path override on top of it).
    /// * **Revoking** would have to make L5 deny a path it currently
    ///   allows, but `fs_rules` has no deny-rule encoding: removing an
    ///   entry returns that path to "no exact match", which allows. The
    ///   operation would therefore widen access under a name that promises
    ///   the opposite.
    ///
    /// Both directions would report success and enforce nothing, which
    /// CLAUDE.md rule 4 makes a defect rather than a limitation.
    pub fn check_runtime_capability(cap: &Capability) -> Result<(), Error> {
        match cap {
            Capability::Network { .. } | Capability::Exec { .. } => Ok(()),
            Capability::Filesystem { path, .. } => Err(Error::Unsupported(format!(
                "filesystem capability {path:?} cannot be granted or revoked on a running \
                 sandbox. Landlock (L3) is the recursive filesystem layer and its ruleset is \
                 fixed at launch — restrict_self() is irreversible and only the confined \
                 process itself can narrow further — while the L5 file_open hook allows any \
                 path it has no exact rule for, so it cannot express a runtime deny either. \
                 Change the sandbox's policy and relaunch instead"
            ))),
        }
    }
}

/// FNV-1a 64-bit — stable across process restarts (unlike a keyed hasher),
/// which matters because the compiled hash is looked up from a BPF map
/// keyed by this same value inside the LSM hook.
fn hash_path(path: &str) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for b in path.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

fn parse_sha256_pin(pin: &str) -> Option<[u8; 32]> {
    let hex = pin.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> Policy {
        Policy {
            api_version: "aivisor/v1".into(),
            kind: "SandboxPolicy".into(),
            metadata_name: "test".into(),
            filesystem: None,
            exec: None,
            network: None,
            runtime: None,
            audit: None,
        }
    }

    #[test]
    fn test_compile_landlock_empty() {
        let policy = test_policy();
        let plan = policy.compile_landlock(1);
        assert!(plan.rules.is_empty());
        assert_eq!(plan.abi, 1);
    }

    #[test]
    fn test_compile_seccomp_default() {
        let policy = test_policy();
        let plan = policy.compile_seccomp();
        assert_eq!(plan.profile, "aivisor-default");
    }

    #[test]
    fn test_compile_bpf_empty_policy_has_no_rules() {
        let policy = test_policy();
        let plan = policy.compile_bpf();
        assert!(plan.fs_rules.is_empty());
        assert!(plan.exec_rules.is_empty());
        assert!(!plan.exec_policy_present);
    }

    #[test]
    fn test_compile_landlock_with_rules() {
        let policy = Policy {
            filesystem: Some(FsPolicy {
                default: AccessDefault::Deny,
                rules: vec![FsRule {
                    path: "/workspace".into(),
                    access: vec!["read".into(), "write".into()],
                    recursive: true,
                }],
            }),
            ..test_policy()
        };
        let plan = policy.compile_landlock(1);
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].path.to_str().unwrap(), "/workspace");
        assert_eq!(
            plan.rules[0].access_mask,
            landlock_bits::READ_FILE | landlock_bits::READ_DIR | landlock_bits::WRITE_FILE
        );
    }

    #[test]
    fn test_compile_seccomp_custom() {
        let policy = Policy {
            runtime: Some(RuntimeOpts {
                seccomp_profile: Some("strict".into()),
                landlock_abi_min: Some(3),
                timeout: None,
                max_idle: None,
            }),
            ..test_policy()
        };
        let plan = policy.compile_seccomp();
        assert_eq!(plan.profile, "strict");
    }

    #[test]
    fn test_access_mask_matches_kernel_bits_not_sequential_indices() {
        // Regression test for the bug where read/write/execute/create/
        // delete/truncate were mapped to sequential bit positions instead
        // of the real LANDLOCK_ACCESS_FS_* values, silently granting the
        // wrong right for every verb except "write".
        assert_eq!(
            Policy::access_to_landlock_mask(&["read".to_string()]),
            landlock_bits::READ_FILE | landlock_bits::READ_DIR
        );
        assert_eq!(
            Policy::access_to_landlock_mask(&["execute".to_string()]),
            landlock_bits::EXECUTE
        );
        assert_ne!(
            Policy::access_to_landlock_mask(&["read".to_string()]),
            landlock_bits::EXECUTE,
            "read must never grant execute"
        );
        assert_ne!(
            Policy::access_to_landlock_mask(&["execute".to_string()]),
            landlock_bits::READ_FILE,
            "execute must never grant read"
        );
    }

    #[test]
    fn test_landlock_mask_respects_abi_ceiling() {
        // truncate (ABI>=3) requested against an ABI-1 kernel must be masked
        // off, not passed through — an unknown right is EINVAL, which is a
        // fail-open ("did not sandbox at all") bug per Appendix A.
        let policy = Policy {
            filesystem: Some(FsPolicy {
                default: AccessDefault::Deny,
                rules: vec![FsRule {
                    path: "/workspace".into(),
                    access: vec!["truncate".into()],
                    recursive: false,
                }],
            }),
            ..test_policy()
        };
        let plan = policy.compile_landlock(1);
        assert_eq!(plan.rules[0].access_mask, 0);

        let plan_abi3 = policy.compile_landlock(3);
        assert_eq!(plan_abi3.rules[0].access_mask, landlock_bits::TRUNCATE);
    }

    #[test]
    fn test_compile_bpf_with_fs_and_exec_rules() {
        let policy = Policy {
            filesystem: Some(FsPolicy {
                default: AccessDefault::Deny,
                rules: vec![FsRule {
                    path: "/workspace".into(),
                    access: vec!["read".into(), "write".into()],
                    recursive: true,
                }],
            }),
            exec: Some(ExecPolicy {
                default: AccessDefault::Deny,
                allow: vec![
                    ExecRule::Path {
                        path: "/usr/bin/python3".into(),
                        pin: Some(
                            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                                .into(),
                        ),
                    },
                    ExecRule::Prefix("/usr/lib/python3.12/".into()),
                ],
            }),
            ..test_policy()
        };
        let plan = policy.compile_bpf();
        assert_eq!(plan.fs_rules.len(), 1);
        assert!(plan.exec_policy_present);
        assert_eq!(plan.exec_rules.len(), 2);
        assert_eq!(plan.exec_rules[0].path, "/usr/bin/python3");
        assert!(!plan.exec_rules[0].is_prefix);
        assert!(plan.exec_rules[0].hash.is_some());
        assert_eq!(plan.exec_rules[0].hash.unwrap()[0], 0xab);
        assert!(plan.exec_rules[1].is_prefix);
    }

    #[test]
    fn test_compile_bpf_net_direct_rules_only() {
        let policy = Policy {
            network: Some(NetPolicy {
                default: AccessDefault::Deny,
                egress: vec![
                    NetRule::Direct {
                        cidr: "10.42.0.0/16".into(),
                        ports: vec![5432],
                    },
                    NetRule::BrokerRoute {
                        hosts: vec!["pypi.org".into()],
                        methods: vec!["GET".into()],
                    },
                ],
                block_metadata: true,
                dns_policy: None,
            }),
            ..test_policy()
        };
        let plan = policy.compile_bpf();
        assert_eq!(plan.net_rules.len(), 1);
        assert_eq!(plan.net_rules[0].cidr, "10.42.0.0/16");
        assert_eq!(plan.net_rules[0].ports, vec![5432]);
        assert!(plan.block_metadata);
    }

    #[test]
    fn test_compile_landlock_includes_exec_allow_entries() {
        // Regression test: exec policy must reach Landlock, because L5
        // (eBPF bprm_check_security) is not the layer enforcing exec
        // control in this build — Landlock EXECUTE is.
        let policy = Policy {
            exec: Some(ExecPolicy {
                default: AccessDefault::Deny,
                allow: vec![
                    ExecRule::Path {
                        path: "/usr/bin/python3".into(),
                        pin: None,
                    },
                    ExecRule::Prefix("/usr/lib/python3.12/".into()),
                ],
            }),
            ..test_policy()
        };
        let plan = policy.compile_landlock(3);
        assert_eq!(plan.rules.len(), 2);
        assert!(plan
            .rules
            .iter()
            .any(|r| r.path.to_str() == Some("/usr/bin/python3")
                && r.access_mask & landlock_bits::EXECUTE != 0
                && r.access_mask & landlock_bits::READ_FILE != 0));
    }

    #[test]
    fn test_path_hash_stable_and_distinct() {
        assert_eq!(hash_path("/workspace"), hash_path("/workspace"));
        assert_ne!(hash_path("/workspace"), hash_path("/etc"));
    }

    #[test]
    fn test_parse_sha256_pin_valid_and_invalid() {
        let valid = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert!(parse_sha256_pin(valid).is_some());
        assert!(parse_sha256_pin("sha256:tooshort").is_none());
        assert!(parse_sha256_pin("md5:abcdef").is_none());
    }

    // ---- runtime capability grants (T3.6) ----

    fn net_cap(cidr: &str, ports: &[u16]) -> Capability {
        Capability::Network {
            cidr: cidr.into(),
            ports: ports.to_vec(),
        }
    }

    #[test]
    fn granting_a_network_capability_reaches_the_bpf_plan() {
        let policy = test_policy();
        let granted = policy
            .with_capability_granted(&net_cap("203.0.113.7/32", &[53]))
            .unwrap();
        let plan = granted.compile_bpf();
        assert_eq!(plan.net_rules.len(), 1);
        assert_eq!(plan.net_rules[0].cidr, "203.0.113.7/32");
        assert_eq!(plan.net_rules[0].ports, vec![53]);
        // The original is untouched — grants produce a new policy so a
        // failed install can leave the live one in place.
        assert!(policy.compile_bpf().net_rules.is_empty());
    }

    #[test]
    fn a_grant_defaults_to_deny_and_keeps_metadata_blocked() {
        // Materialising a NetPolicy for a document that had none must not
        // accidentally open the default or unblock the metadata endpoint.
        let granted = test_policy()
            .with_capability_granted(&net_cap("10.0.0.0/8", &[53]))
            .unwrap();
        let net = granted.network.as_ref().unwrap();
        assert_eq!(net.default, AccessDefault::Deny);
        assert!(net.block_metadata);
        assert!(granted.compile_bpf().block_metadata);
    }

    #[test]
    fn repeated_grants_for_one_cidr_merge_instead_of_shadowing() {
        // Two Direct rules for the same CIDR compile to two writes of the
        // same LPM key, so the second would overwrite the first's bitmap
        // and silently revoke the earlier grant.
        let policy = test_policy()
            .with_capability_granted(&net_cap("10.0.0.0/8", &[53]))
            .unwrap()
            .with_capability_granted(&net_cap("10.0.0.0/8", &[7]))
            .unwrap();
        let plan = policy.compile_bpf();
        assert_eq!(plan.net_rules.len(), 1);
        assert_eq!(plan.net_rules[0].ports, vec![7, 53]);
    }

    #[test]
    fn revoking_removes_only_the_named_ports() {
        let policy = test_policy()
            .with_capability_granted(&net_cap("10.0.0.0/8", &[7, 53]))
            .unwrap()
            .with_capability_revoked(&net_cap("10.0.0.0/8", &[53]))
            .unwrap();
        let plan = policy.compile_bpf();
        assert_eq!(plan.net_rules.len(), 1);
        assert_eq!(plan.net_rules[0].ports, vec![7]);
    }

    #[test]
    fn revoking_the_last_port_drops_the_rule_entirely() {
        // An all-zero port bitmap is an LPM entry that exists only to be
        // rejected; it should not be left in the map.
        let policy = test_policy()
            .with_capability_granted(&net_cap("10.0.0.0/8", &[53]))
            .unwrap()
            .with_capability_revoked(&net_cap("10.0.0.0/8", &[53]))
            .unwrap();
        assert!(policy.compile_bpf().net_rules.is_empty());
    }

    #[test]
    fn granting_an_exec_capability_is_idempotent() {
        let cap = Capability::Exec {
            path: "/usr/bin/git".into(),
        };
        let policy = test_policy()
            .with_capability_granted(&cap)
            .unwrap()
            .with_capability_granted(&cap)
            .unwrap();
        assert_eq!(policy.exec.as_ref().unwrap().allow.len(), 1);
        assert_eq!(policy.compile_bpf().exec_rules.len(), 1);

        let revoked = policy.with_capability_revoked(&cap).unwrap();
        assert!(revoked.exec.as_ref().unwrap().allow.is_empty());
    }

    #[test]
    fn a_runtime_exec_grant_never_claims_a_hash_pin() {
        // The granting side cannot see the binary (it lives in the
        // sandbox's mount namespace), so it must not assert integrity it
        // did not verify.
        let policy = test_policy()
            .with_capability_granted(&Capability::Exec {
                path: "/usr/bin/git".into(),
            })
            .unwrap();
        assert_eq!(policy.compile_bpf().exec_rules[0].hash, None);
    }

    #[test]
    fn filesystem_capabilities_are_refused_in_both_directions() {
        // Not a missing feature: neither direction can be made to mean what
        // its name says. See check_runtime_capability.
        let cap = Capability::Filesystem {
            path: "/data".into(),
            access: vec!["read".into()],
        };
        let granted = test_policy().with_capability_granted(&cap).unwrap_err();
        assert!(granted.to_string().contains("cannot be granted or revoked"));
        assert!(test_policy().with_capability_revoked(&cap).is_err());
    }

    #[test]
    fn landlock_ceiling_covers_paths_beneath_a_granted_directory() {
        let policy = Policy {
            filesystem: Some(FsPolicy {
                default: AccessDefault::Deny,
                rules: vec![FsRule {
                    path: "/usr".into(),
                    access: vec!["read".into(), "execute".into()],
                    recursive: true,
                }],
            }),
            ..test_policy()
        };
        let plan = policy.compile_landlock(3);
        let exec_read = landlock_bits::EXECUTE | landlock_bits::READ_FILE;

        // path_beneath: a rule on /usr covers /usr/bin/git.
        assert!(plan.permits(std::path::Path::new("/usr/bin/git"), exec_read));
        // Outside the tree: no rule, so no ceiling.
        assert!(!plan.permits(std::path::Path::new("/opt/tool"), exec_read));
        // Inside the tree but asking for a right the rule does not carry.
        assert!(!plan.permits(
            std::path::Path::new("/usr/bin/git"),
            landlock_bits::WRITE_FILE
        ));
    }
}
