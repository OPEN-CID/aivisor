use std::io;

use aivisor_core::Error;

use crate::abi;

/// Drop all capabilities: bounding, ambient, effective, permitted, inheritable.
/// Must be called in the child after pivot_root and no_new_privs,
/// before Landlock, and before dropping to an unprivileged uid.
///
/// The child is root in its user namespace, so it holds a full set
/// of namespace-scoped capabilities. Dropping the bounding set
/// prevents regaining them.
pub fn drop_all_capabilities() -> Result<(), Error> {
    clear_ambient()?;
    drop_bounding_set()?;
    clear_all_sets()?;

    Ok(())
}

pub fn set_no_new_privs() -> Result<(), Error> {
    let ret = unsafe { abi::prctl(abi::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn clear_ambient() -> Result<(), Error> {
    let ret = unsafe {
        abi::prctl(
            abi::PR_CAP_AMBIENT,
            abi::PR_CAP_AMBIENT_CLEAR_ALL as u64,
            0,
            0,
            0,
        )
    };
    if ret < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
        return Err(Error::LaunchFailed(format!(
            "PR_CAP_AMBIENT_CLEAR_ALL: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn drop_bounding_set() -> Result<(), Error> {
    for cap in 0..=abi::CAP_PROBE_CEILING {
        let ret = unsafe { abi::prctl(abi::PR_CAPBSET_DROP, cap as u64, 0, 0, 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // EINVAL: this capability number is unknown to the running
            // kernel (we probe past the real ceiling on purpose). Any
            // other errno is a real failure and must deny.
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(Error::LaunchFailed(format!(
                    "PR_CAPBSET_DROP({cap}): {err}"
                )));
            }
        }
    }
    Ok(())
}

fn clear_all_sets() -> Result<(), Error> {
    let mut header = abi::CapUserHeader {
        version: abi::LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };

    // VERSION_3 splits the 64-bit capability space into two 32-bit slots.
    let data = [abi::CapUserData::default(), abi::CapUserData::default()];

    let ret = unsafe { abi::capset(&mut header, data.as_ptr()) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "capset: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Drop from root-in-userns to an unprivileged uid/gid inside the sandbox.
/// Must be called after `drop_all_capabilities` and Landlock/seccomp
/// installation (blueprint §6.2 step 14) — setresuid itself needs no
/// capability, but doing it before the bounding set is empty would let the
/// process regain capabilities other tools give to `uid 0` implicitly.
pub fn drop_to_unprivileged(uid: u32, gid: u32) -> Result<(), Error> {
    let ret = unsafe { libc::setresgid(gid, gid, gid) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "setresgid: {}",
            io::Error::last_os_error()
        )));
    }

    let ret = unsafe { libc::setresuid(uid, uid, uid) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "setresuid: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_probe_ceiling_covers_known_caps() {
        // CAP_CHECKPOINT_RESTORE = 40 (kernel 5.9). The probe ceiling must
        // stay above every capability number the kernel currently defines.
        const { assert!(abi::CAP_PROBE_CEILING >= 40) };
    }

    #[test]
    fn test_cap_user_header_version_is_v3() {
        assert_eq!(abi::LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
    }
}
