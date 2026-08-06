//! Raw kernel ABI constants and structs not exposed by the `libc` crate for
//! this target/version (verified empty by grepping the vendored source: no
//! `PR_SET_NO_NEW_PRIVS`, `PR_CAPBSET_DROP`, `PR_CAP_AMBIENT*`, `capset`,
//! `landlock_ruleset_attr`, or `landlock_path_beneath_attr` anywhere under
//! `unix::linux_like::linux` for the gnu target — only the android/fuchsia/
//! l4re variants carry them). Rather than depend on a libc convenience
//! wrapper that may or may not exist for a given crate version, every
//! syscall in this module goes through `libc::syscall(SYS_*, ...)`, which
//! *is* verified present and stable per-architecture. Values below are
//! taken directly from the kernel UAPI headers they document and are frozen
//! kernel ABI, not libc-crate-version-dependent.

#![allow(dead_code)]

use libc::{c_int, c_long, c_uint};

// ---- prctl(2) options — include/uapi/linux/prctl.h ----
pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
pub const PR_CAPBSET_READ: c_int = 23;
pub const PR_CAPBSET_DROP: c_int = 24;
pub const PR_CAP_AMBIENT: c_int = 47;
pub const PR_CAP_AMBIENT_CLEAR_ALL: c_uint = 4;

/// Highest capability bit to probe when dropping the bounding set. The real
/// ceiling (`/proc/sys/kernel/cap_last_cap`) grows over kernel versions;
/// scanning past it is safe because `PR_CAPBSET_DROP` on an unknown
/// capability number returns `EINVAL`, which callers must tolerate rather
/// than treat as failure. 63 is comfortably above CAP_CHECKPOINT_RESTORE
/// (40, added 5.9) with headroom for future additions.
pub const CAP_PROBE_CEILING: c_int = 63;

// ---- capset(2) — include/uapi/linux/capability.h ----
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
pub struct CapUserHeader {
    pub version: u32,
    pub pid: c_int,
}

/// One `__user_cap_data_struct` slot. capset(2) with VERSION_3 takes an
/// array of 2: caps 0-31 in slot 0, caps 32-63 in slot 1.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

/// capset(2) has no libc wrapper here; SYS_capset is a verified per-arch
/// constant.
///
/// # Safety
/// `header` and `data` must be valid for the duration of the call and
/// `data` must point to 2 `CapUserData` entries for VERSION_3.
pub unsafe fn capset(header: *mut CapUserHeader, data: *const CapUserData) -> c_long {
    libc::syscall(libc::SYS_capset, header, data)
}

/// # Safety
/// `option` must be a valid `PR_*` prctl(2) operation and `arg2`..`arg5`
/// must be whatever that operation expects (some are ignored, some are
/// pointers the kernel will read or write through).
pub unsafe fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_long {
    libc::syscall(libc::SYS_prctl, option, arg2, arg3, arg4, arg5)
}

// ---- landlock(2) — include/uapi/linux/landlock.h ----
// Flag to landlock_create_ruleset() that requests the ABI version instead
// of creating a ruleset (attr=NULL, size=0 required alongside this flag).
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
pub const LANDLOCK_RULE_PATH_BENEATH: c_int = 1;

/// `struct landlock_ruleset_attr` — packed, no field padding by kernel
/// contract. Only the ABI-1 `handled_access_fs` field is populated; network
/// scoping (ABI>=4 `handled_access_net`) is left at 0 because network
/// egress is enforced at L5 (eBPF LSM) in this codebase, not duplicated
/// here — see docs/threat-model.md.
#[repr(C, packed)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
}

/// `struct landlock_path_beneath_attr` — packed. `parent_fd` is `__s32`,
/// NOT `u64`; getting this wrong silently corrupts the syscall argument
/// (the previous version of this code declared it as u64, which reads 4
/// bytes of adjacent stack garbage as part of the fd on the wire).
#[repr(C, packed)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: c_int,
}

/// # Safety
/// `attr` must be either null (only valid together with the
/// `LANDLOCK_CREATE_RULESET_VERSION` flag) or point to a valid, initialized
/// `LandlockRulesetAttr` of exactly `size` bytes.
pub unsafe fn landlock_create_ruleset(
    attr: *const LandlockRulesetAttr,
    size: usize,
    flags: u32,
) -> c_long {
    libc::syscall(libc::SYS_landlock_create_ruleset, attr, size, flags)
}

/// # Safety
/// `ruleset_fd` must be a valid fd returned by `landlock_create_ruleset`
/// and `rule_attr` must point to a valid, initialized
/// `LandlockPathBeneathAttr` matching `rule_type`.
pub unsafe fn landlock_add_rule(
    ruleset_fd: c_int,
    rule_type: c_int,
    rule_attr: *const LandlockPathBeneathAttr,
    flags: u32,
) -> c_long {
    libc::syscall(
        libc::SYS_landlock_add_rule,
        ruleset_fd,
        rule_type,
        rule_attr,
        flags,
    )
}

/// # Safety
/// `ruleset_fd` must be a valid fd returned by `landlock_create_ruleset`.
/// On success the calling thread is irreversibly confined by the ruleset
/// for the rest of its lifetime.
pub unsafe fn landlock_restrict_self(ruleset_fd: c_int, flags: u32) -> c_long {
    libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, flags)
}

// ---- clone3(2) — include/uapi/linux/sched.h ----
pub const CLONE_NEWTIME: u64 = 0x0000_0080;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const CLONE_PIDFD: u64 = 0x0000_1000;
pub const CLONE_INTO_CGROUP: u64 = 0x0000_0002_0000_0000;

/// `struct clone_args`, CLONE_ARGS_SIZE_VER2 (88 bytes) — the version that
/// added the trailing `cgroup` field (kernel 5.7+, `CLONE_INTO_CGROUP`).
/// All fields are `__aligned_u64`; an 11x-`u64` Rust struct is naturally
/// 88 bytes with no padding, matching the kernel layout exactly.
#[repr(C)]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// Raw `clone3(2)`. With `stack`/`stack_size` left at 0 this behaves like
/// `fork()`: returns twice, 0 in the child and the child pid in the parent.
///
/// # Safety
/// After this returns 0 (in the child) of a multi-threaded parent,
/// only async-signal-safe operations are well-defined until `execve()` —
/// the child has exactly one thread (the calling one) and any lock held by
/// another parent thread at the moment of the call is held forever. The
/// child path in this crate performs heap allocations (`CString`, path
/// formatting) before `execve()`, which is a known, accepted risk shared by
/// most Rust container runtimes; it is not fully async-signal-safe. Treat
/// hangs in the child path (rather than crashes) as the symptom.
pub unsafe fn clone3(args: &mut CloneArgs) -> c_long {
    libc::syscall(
        libc::SYS_clone3,
        args as *mut CloneArgs,
        std::mem::size_of::<CloneArgs>(),
    )
}

// ---- mount(2) / umount2(2) ----
pub const MNT_DETACH: c_int = 2;

/// # Safety
/// `source`, `target`, and `fstype` (when non-null) must be valid,
/// NUL-terminated C strings, and `data` (when non-null) must be valid for
/// whatever `fstype`'s mount option parser expects to read from it.
pub unsafe fn mount(
    source: *const libc::c_char,
    target: *const libc::c_char,
    fstype: *const libc::c_char,
    flags: libc::c_ulong,
    data: *const libc::c_void,
) -> c_long {
    libc::syscall(libc::SYS_mount, source, target, fstype, flags, data)
}

/// # Safety
/// `target` must be a valid, NUL-terminated C string.
pub unsafe fn umount2(target: *const libc::c_char, flags: c_int) -> c_long {
    libc::syscall(libc::SYS_umount2, target, flags)
}

/// # Safety
/// `new_root` and `put_old` must be valid, NUL-terminated C strings naming
/// paths that satisfy pivot_root(2)'s constraints (both must be mount
/// points, `put_old` must be beneath `new_root`, etc.) — the kernel
/// validates these, but a bad path here still changes the process's root
/// out from under any code that assumed the previous layout.
pub unsafe fn pivot_root(new_root: *const libc::c_char, put_old: *const libc::c_char) -> c_long {
    libc::syscall(libc::SYS_pivot_root, new_root, put_old)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone_args_size_matches_ver2() {
        // CLONE_ARGS_SIZE_VER2 per include/uapi/linux/sched.h.
        assert_eq!(std::mem::size_of::<CloneArgs>(), 88);
    }

    #[test]
    fn test_landlock_path_beneath_attr_is_packed_12_bytes() {
        // u64 + i32, packed: 12 bytes, not 16 (which an unpacked repr(C)
        // would produce by padding parent_fd out to 8-byte alignment).
        assert_eq!(std::mem::size_of::<LandlockPathBeneathAttr>(), 12);
    }

    #[test]
    fn test_landlock_ruleset_attr_16_bytes() {
        assert_eq!(std::mem::size_of::<LandlockRulesetAttr>(), 16);
    }
}
