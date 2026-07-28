use std::os::unix::io::AsRawFd;
use std::path::Path;

use aivisor_core::Error;
use aivisor_policy::{landlock_bits, LandlockPlan};

use crate::abi;

/// Probe the running kernel's Landlock ABI.
/// Returns the ABI version (1-6) or an error if Landlock is unavailable or
/// the minimum ABI requirement is not met.
pub fn probe_landlock_abi(min_abi: u32) -> Result<u32, Error> {
    let ret = unsafe {
        abi::landlock_create_ruleset(std::ptr::null(), 0, abi::LANDLOCK_CREATE_RULESET_VERSION)
    };

    if ret < 0 {
        return Err(Error::KernelFeatureMissing {
            feature: "Landlock LSM",
            min_kernel: "5.13",
        });
    }

    let abi_version = ret as u32;
    if abi_version < min_abi {
        return Err(Error::KernelFeatureMissing {
            feature: "Landlock ABI (see min_abi in error context)",
            min_kernel: "5.13+",
        });
    }

    Ok(abi_version)
}

/// Apply a Landlock ruleset to the current process.
/// Must be called after pivot_root, no_new_privs, and before seccomp.
/// Opens path fds INSIDE the final mount namespace.
pub fn apply_landlock(plan: &LandlockPlan) -> Result<(), Error> {
    let handled = landlock_bits::known_at_abi(plan.abi);

    let ruleset_attr = abi::LandlockRulesetAttr {
        handled_access_fs: handled,
        // Network scoping (ABI>=4) is intentionally left unhandled here —
        // egress is enforced at L5 (eBPF LSM), not duplicated in Landlock.
        handled_access_net: 0,
    };

    let ruleset_fd = unsafe {
        abi::landlock_create_ruleset(
            &ruleset_attr,
            std::mem::size_of::<abi::LandlockRulesetAttr>(),
            0,
        )
    };

    if ruleset_fd < 0 {
        return Err(Error::LaunchFailed(format!(
            "landlock_create_ruleset: {}",
            std::io::Error::last_os_error()
        )));
    }
    let ruleset_fd = ruleset_fd as i32;

    for rule in &plan.rules {
        // Mask to what this ruleset actually handles — requesting a right
        // outside `handled_access_fs` is rejected with EINVAL by the
        // kernel (Appendix A: an unknown/unhandled right is a fail-open
        // bug, so the compiler in aivisor-policy already masks by ABI, but
        // we mask again here defensively in case a caller builds a plan by
        // hand).
        let access_mask = rule.access_mask & handled;
        if access_mask == 0 {
            continue;
        }

        let target_fd = open_dir_fd(&rule.path)?;
        let path_beneath = abi::LandlockPathBeneathAttr {
            allowed_access: access_mask,
            parent_fd: target_fd.as_raw_fd(),
        };

        let ret = unsafe {
            abi::landlock_add_rule(
                ruleset_fd,
                abi::LANDLOCK_RULE_PATH_BENEATH,
                &path_beneath,
                0,
            )
        };

        if ret < 0 {
            return Err(Error::LaunchFailed(format!(
                "landlock_add_rule for {}: {}",
                rule.path.display(),
                std::io::Error::last_os_error()
            )));
        }
    }

    let ret = unsafe { abi::landlock_restrict_self(ruleset_fd, 0) };

    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "landlock_restrict_self: {}",
            std::io::Error::last_os_error()
        )));
    }

    unsafe {
        libc::close(ruleset_fd);
    }

    Ok(())
}

fn open_dir_fd(path: &Path) -> Result<std::os::unix::io::OwnedFd, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_PATH)
        .open(path)
        .map_err(|e| Error::MountSetup(format!("open path for Landlock: {e}")))?;
    Ok(std::os::unix::io::OwnedFd::from(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handled_set_basic() {
        let set = landlock_bits::known_at_abi(1);
        assert!(set > 0);
        assert!(set & landlock_bits::EXECUTE != 0);
        assert!(set & landlock_bits::READ_FILE != 0);
    }

    #[test]
    fn test_handled_set_abi2() {
        let set1 = landlock_bits::known_at_abi(1);
        let set2 = landlock_bits::known_at_abi(2);
        assert!(set2 > set1); // REFER added
    }
}
