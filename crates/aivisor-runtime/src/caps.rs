use std::io;

use aivisor_core::Error;

use crate::abi;

/// Blueprint §6.2 step 11: drop the capability bounding set to empty, and
/// clear ambient and inheritable — but deliberately NOT effective/permitted
/// yet. `drop_to_unprivileged` (step 14) still needs CAP_SETUID/CAP_SETGID
/// in the EFFECTIVE set to change to the sandbox's unprivileged uid/gid;
/// clearing effective/permitted here, before that call, made setresuid/
/// setresgid fail closed with EPERM — verified empirically on a real
/// kernel (Ubuntu 24.04, 6.8.0): this was a real, previously-unexercised
/// bug (every earlier test run in this codebase's history died at the
/// overlay mount step, long before ever reaching this far in the launch
/// sequence). The bounding set is dropped here regardless — it does not
/// affect currently-held effective/permitted capabilities, only which
/// capabilities can ever be (re)acquired later — so nothing gained back
/// after this point could survive irrespective of ordering. Inheritable is
/// cleared here rather than deferred because it only affects what would
/// pass through a hypothetical execve of a file-capability-bearing binary,
/// not what setresuid/setresgid themselves need — see
/// `finish_dropping_capabilities`, called after the uid/gid change, for
/// where effective/permitted are actually zeroed.
pub fn drop_bounding_set_and_ambient() -> Result<(), Error> {
    clear_ambient()?;
    drop_bounding_set()?;
    clear_inheritable()?;

    Ok(())
}

/// Zero the effective and permitted sets (and inheritable, redundantly —
/// already cleared by `drop_bounding_set_and_ambient`). Must run AFTER
/// `drop_to_unprivileged`, which needs CAP_SETUID/CAP_SETGID still present
/// in the effective set to change uid/gid at all. The kernel already
/// clears effective capabilities as an implicit side effect of changing
/// away from a privileged uid (`cap_task_fix_setuid`), but this codebase's
/// fail-closed rule means not relying on that alone: an explicit capset
/// here is what actually guarantees the sandboxed process ends up with
/// zero capabilities, regardless of securebits or kernel-version-specific
/// implicit-clearing behavior this process hasn't verified either way.
pub fn finish_dropping_capabilities() -> Result<(), Error> {
    clear_all_sets()
}

/// Refresh this process's credentials to be namespace-relative root,
/// immediately after the parent has written uid_map/gid_map. Must run
/// before any mount or file-creation operation whose target filesystem's
/// owning user namespace is THIS process's own new namespace (e.g. the
/// `/dev` and `/tmp` tmpfs instances this process mounts itself in
/// `child_setup`) — until this call, the process's credential is still
/// the kuid it was forked with (the real host uid of the parent daemon,
/// commonly host root), which has no entry in this sandbox's own
/// uid_map (mapped range is `[uid_base, uid_base+UID_RANGE_SIZE)`, which
/// does not include the parent's real host uid). Any operation that needs
/// to stamp this process's fsuid onto a new inode within this namespace
/// then has no representable uid to write and fails closed with
/// `EOVERFLOW` — verified empirically on a real kernel (Ubuntu 24.04,
/// 6.8.0) with a minimal clone3+uid_map reproduction that isolated this
/// from every other variable (overlay mounting, mount options, uid
/// magnitude/range size all ruled out one at a time; only "does the
/// process's credential predate this uid_map" mattered).
/// `setresuid(0,0,0)`/`setresgid(0,0,0)`, called from inside the new
/// namespace, re-resolves "0" against THIS namespace's own uid_map (0 ->
/// uid_base), producing a credential that correctly resolves within this
/// namespace and everything mounted in it from here on.
pub fn become_namespace_root() -> Result<(), Error> {
    let ret = unsafe { libc::setresgid(0, 0, 0) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "setresgid(0,0,0): {}",
            io::Error::last_os_error()
        )));
    }

    let ret = unsafe { libc::setresuid(0, 0, 0) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "setresuid(0,0,0): {}",
            io::Error::last_os_error()
        )));
    }

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

/// Zero only the inheritable set, leaving effective/permitted exactly as
/// they are. Unlike `clear_all_sets`, this reads the CURRENT effective/
/// permitted values first (capset(2) always sets all three sets in one
/// call — there is no "just inheritable" syscall), so setresuid/setresgid
/// later still has the CAP_SETUID/CAP_SETGID it needs.
fn clear_inheritable() -> Result<(), Error> {
    let mut header = abi::CapUserHeader {
        version: abi::LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [abi::CapUserData::default(), abi::CapUserData::default()];

    let ret = unsafe { abi::capget(&mut header, data.as_mut_ptr()) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "capget: {}",
            io::Error::last_os_error()
        )));
    }

    // capget(2) can reset the header's version field on certain error/
    // compat paths; VERSION_3 is re-asserted explicitly for the capset(2)
    // call below rather than trusting whatever capget left behind.
    header.version = abi::LINUX_CAPABILITY_VERSION_3;
    for slot in &mut data {
        slot.inheritable = 0;
    }

    let ret = unsafe { abi::capset(&mut header, data.as_ptr()) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "capset (clear inheritable): {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Drop from root-in-userns to an unprivileged uid/gid inside the sandbox.
/// Must be called after `drop_bounding_set_and_ambient` and Landlock/
/// seccomp installation (blueprint §6.2 step 14), and before
/// `finish_dropping_capabilities`: at this point the process still holds
/// CAP_SETUID/CAP_SETGID in its effective set (only the bounding set and
/// ambient/inheritable were cleared earlier), which setresuid/setresgid
/// need to change to a genuinely different uid/gid — verified empirically
/// on a real kernel (Ubuntu 24.04, 6.8.0) that clearing effective/
/// permitted any earlier makes both calls fail closed with EPERM.
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
