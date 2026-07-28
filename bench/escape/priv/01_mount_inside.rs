//! Scenario: Attempt to mount inside the sandbox, directly via the raw
//! syscall (not by shelling out to a `mount` binary, which may simply not
//! exist in this rootfs and would make the result UNVERIFIED rather than
//! meaningful either way).
//!
//! Expected: BLOCKED (EPERM) — the sandbox's capability bounding set is
//! emptied (caps::drop_all_capabilities) before execve, so mount(2) fails
//! for lack of CAP_SYS_ADMIN in the process's own user namespace
//! regardless of whether Landlock or L5 additionally cover it.

use aivisor_escape_bench::Outcome;
use std::ffi::CString;

fn main() {
    let target = CString::new("/tmp").unwrap();
    let fstype = CString::new("tmpfs").unwrap();

    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount,
            std::ptr::null::<libc::c_char>(),
            target.as_ptr(),
            fstype.as_ptr(),
            0u64,
            std::ptr::null::<libc::c_void>(),
        )
    };

    if ret == 0 {
        Outcome::Escaped.print_and_exit("mount tmpfs on /tmp");
    }

    let e = std::io::Error::last_os_error();
    if aivisor_escape_bench::is_permission_denied(&e) {
        Outcome::Blocked.print_and_exit("mount tmpfs on /tmp");
    }
    Outcome::Unverified(e.to_string()).print_and_exit("mount tmpfs on /tmp");
}
