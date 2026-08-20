use serde::{Deserialize, Serialize};

/// A named reference to a policy document, resolved by the runtime against
/// whatever policy store it has (a file, a name registered on the daemon,
/// etc). The compiled policy representation — parsing, Landlock/BPF/seccomp
/// compilation — lives entirely in `aivisor-policy`; this crate only knows
/// the reference shape, consistent with `aivisor-core` owning types and IDs
/// but no policy logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRef {
    pub name: String,
    pub overrides: Option<serde_yaml::Value>,
}

/// The identity of an executable as the exec LSM hook sees it: the
/// `(dev, inode)` pair reachable from `bprm->file->f_inode`.
///
/// Both halves have to come from the right place, and neither is the
/// obvious one. Measured on Ubuntu 24.04 / kernel 6.8.0, for a single
/// binary in one sandbox, three sources disagree:
///
/// | source                                   | dev | inode |
/// |------------------------------------------|-----|-------|
/// | host `stat` of the upper-layer file      | 24  | 11794 |
/// | `stat(2)` inside the sandbox             | 49  | 11794 |
/// | the LSM hook (`f_inode->i_sb->s_dev`)    | 48  | 11794 |
///
/// * **inode** agrees everywhere, because the overlay is mounted `xino=off`
///   (see `Rootfs::mount_overlay`) and overlayfs then passes the underlying
///   inode number through unchanged.
/// * **dev** does not. The host sees the device of the filesystem holding
///   the layer. Inside the sandbox, `stat(2)` reports a *pseudo* device
///   overlayfs synthesises per layer (`ovl_get_pseudo_dev`) so files from
///   different layers look like they are on different devices — it is
///   deliberately not the overlay superblock's own `s_dev`, which is what
///   the hook reads.
///
/// So `dev` here is the **kernel `dev_t` of the mount the file lives on**,
/// which the child reads out of `/proc/self/mountinfo` — the one interface
/// that reports a mount's real `MAJ:MIN`. It is already in kernel
/// encoding (`major << 20 | minor`) and must not be run through a
/// userspace `st_dev` conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecIdentity {
    /// Kernel `dev_t` of the mount holding the file, from `mountinfo`.
    pub dev: u64,
    /// Inode number as reported by `stat(2)` inside the sandbox.
    pub inode: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_ref_serde_roundtrip() {
        let r = PolicyRef {
            name: "coding-agent-default".into(),
            overrides: None,
        };
        let yaml = serde_yaml::to_string(&r).unwrap();
        let parsed: PolicyRef = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.name, "coding-agent-default");
    }
}
