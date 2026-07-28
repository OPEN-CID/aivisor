use std::path::PathBuf;

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

#[derive(Debug)]
pub struct LandlockPlan {
    pub rules: Vec<LandlockRule>,
    pub abi: u32,
}

#[derive(Debug)]
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

    fn access_to_landlock_mask(access: &[String]) -> u64 {
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
}
