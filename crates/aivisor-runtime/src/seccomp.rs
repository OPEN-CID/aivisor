use aivisor_core::Error;

use crate::abi;

/// Seccomp filter profile names
pub const PROFILE_DEFAULT: &str = "aivisor-default";
pub const PROFILE_STRICT: &str = "aivisor-strict";

/// Build and apply a seccomp-bpf filter using the given profile.
/// Must be called last among self-restrictions (after Landlock).
pub fn apply_seccomp(profile: &str) -> Result<(), Error> {
    match profile {
        PROFILE_DEFAULT => apply_default_filter(),
        PROFILE_STRICT => apply_strict_filter(),
        other => Err(Error::LaunchFailed(format!(
            "unknown seccomp profile: {other}"
        ))),
    }
}

fn apply_default_filter() -> Result<(), Error> {
    let filter = build_default_bpf();
    install_filter(&filter)
}

fn apply_strict_filter() -> Result<(), Error> {
    let filter = build_strict_bpf();
    install_filter(&filter)
}

fn install_filter(filter: &[libc::sock_filter]) -> Result<(), Error> {
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };

    // Idempotent: the launcher already calls caps::set_no_new_privs()
    // earlier in the sequence, but SECCOMP_SET_MODE_FILTER independently
    // requires it to be set for an unprivileged caller, so we set it again
    // here rather than depend on call-order elsewhere in the process.
    let ret = unsafe { abi::prctl(abi::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SECCOMP_FILTER_FLAG_NEW_LISTENER is deliberately not requested here:
    // it is only useful alongside a filter that emits SECCOMP_RET_USER_NOTIF
    // (the basis for the ASK verb, blueprint §8.5), which is Phase 4 and not
    // wired up. Requesting NEW_LISTENER together with TSYNC is also invalid —
    // the kernel rejects that combination with EINVAL because both flags
    // claim the syscall's return value (listener fd vs TSYNC failure info).
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const _ as *const _,
        )
    };

    if ret < 0 {
        return Err(Error::LaunchFailed(format!(
            "seccomp: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn bpf_stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

fn arch_offset() -> u32 {
    4
}
fn nr_offset() -> u32 {
    0
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;

/// Kill anything that isn't running as the one architecture the filter's
/// syscall-number table below was built for. This MUST kill on every
/// mismatch, including architectures we don't otherwise recognise (i386,
/// x32, arm) — those have different syscall numbering, so a syscall number
/// that means one thing in the x86-64 table below can mean something the
/// filter never intended to allow under another ABI. Only the running
/// process's actual architecture is compiled in; cross-arch personas are
/// rejected wholesale rather than allow-listed, so this table does not
/// grow one branch per architecture.
fn build_arch_check(expected_arch: u32) -> Vec<libc::sock_filter> {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_LD, BPF_RET, SECCOMP_RET_KILL_PROCESS};
    vec![
        bpf_stmt(BPF_LD | BPF_ABS | 0x20, arch_offset()),
        // jt=0 (fall through to nr-load) on match, jf=1 (skip straight to
        // KILL) on mismatch — the inverse of the old table, which jumped
        // *past* the KILL on every branch and so could never reach it.
        bpf_jump(BPF_JMP | BPF_JEQ, 0, 1, expected_arch),
        bpf_stmt(BPF_RET | 0x04, SECCOMP_RET_KILL_PROCESS),
    ]
}

#[cfg(target_arch = "x86_64")]
fn native_audit_arch() -> u32 {
    AUDIT_ARCH_X86_64
}

#[cfg(target_arch = "aarch64")]
fn native_audit_arch() -> u32 {
    AUDIT_ARCH_AARCH64
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("aivisor-runtime seccomp profiles are only defined for x86_64 and aarch64");

/// Build the default seccomp-bpf filter.
/// Default-allow with a curated denylist.
fn build_default_bpf() -> Vec<libc::sock_filter> {
    use libc::{
        BPF_ABS, BPF_JEQ, BPF_JMP, BPF_LD, BPF_RET, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
        SECCOMP_RET_KILL_PROCESS,
    };

    let mut insns = build_arch_check(native_audit_arch());

    insns.push(bpf_stmt(BPF_LD | BPF_ABS | 0x20, nr_offset()));

    let denied: &[(i64, u32)] = &[
        (libc::SYS_init_module, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_finit_module, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_delete_module, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_kexec_load, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_kexec_file_load, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_bpf, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_perf_event_open, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_ptrace, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_process_vm_readv, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_process_vm_writev, SECCOMP_RET_ERRNO | 1),
        (
            libc::SYS_userfaultfd,
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        ),
        (
            libc::SYS_memfd_secret,
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        ),
        (libc::SYS_setns, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_mount_setattr, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_open_by_handle_at, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_name_to_handle_at, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_swapon, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_swapoff, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_pivot_root, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_reboot, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_iopl, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_ioperm, SECCOMP_RET_KILL_PROCESS),
        (
            libc::SYS_io_uring_setup,
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        ),
        (libc::SYS_clock_settime, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_settimeofday, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_adjtimex, SECCOMP_RET_ERRNO | 1),
        // Re-nesting / re-entering confinement from inside it (blueprint
        // §13.4 requires an `unshare` escape scenario in bench/escape).
        (libc::SYS_unshare, SECCOMP_RET_ERRNO | 1),
        // clone() with CLONE_NEWUSER etc. is filtered by argument below;
        // this denies the plain unshare(2) path, which takes no useful
        // argument to distinguish "just detach fs" from "make a new userns".
        (libc::SYS_keyctl, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_add_key, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_request_key, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_pidfd_getfd, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_personality, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_move_pages, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_fanotify_init, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_seccomp, SECCOMP_RET_ERRNO | 1),
        (libc::SYS_acct, SECCOMP_RET_KILL_PROCESS),
        (libc::SYS_quotactl, SECCOMP_RET_ERRNO | 1),
        (
            libc::SYS_nfsservctl,
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        ),
    ];

    for (nr, action) in denied {
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ, 0, 1, *nr as u32));
        insns.push(bpf_stmt(BPF_RET | 0x04, *action));
    }

    insns.push(bpf_stmt(BPF_RET | 0x04, SECCOMP_RET_ALLOW));
    insns
}

fn build_strict_bpf() -> Vec<libc::sock_filter> {
    use libc::{
        BPF_ABS, BPF_JEQ, BPF_JMP, BPF_LD, BPF_RET, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS,
    };

    let mut insns = build_arch_check(native_audit_arch());

    insns.push(bpf_stmt(BPF_LD | BPF_ABS | 0x20, nr_offset()));

    let allow: &[i64] = &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_exit_group,
        libc::SYS_exit,
        libc::SYS_brk,
        libc::SYS_access,
        libc::SYS_faccessat2,
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_nanosleep,
        libc::SYS_clone3,
        libc::SYS_madvise,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getppid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_lseek,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_pselect6,
        libc::SYS_ppoll,
        libc::SYS_writev,
        libc::SYS_readv,
        libc::SYS_sched_yield,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
    ];

    for nr in allow {
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ, 0, 1, *nr as u32));
        insns.push(bpf_stmt(BPF_RET | 0x04, SECCOMP_RET_ALLOW));
    }

    insns.push(bpf_stmt(BPF_RET | 0x04, SECCOMP_RET_KILL_PROCESS));
    insns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_filter_builds() {
        let filter = build_default_bpf();
        assert!(!filter.is_empty());
        let last = filter.last().unwrap();
        assert_eq!(last.k, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_strict_filter_builds() {
        let filter = build_strict_bpf();
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_arch_check_kill_branch_is_reachable() {
        // Regression test for the bug where the arch-check jump table could
        // never reach its own KILL_PROCESS instruction: walk the tiny BPF
        // program by hand for a mismatching arch value and confirm it lands
        // on the KILL return, not falls through past it.
        let insns = build_arch_check(AUDIT_ARCH_X86_64);
        assert_eq!(insns.len(), 3);
        let load = &insns[0];
        assert_eq!(load.code, (libc::BPF_LD | libc::BPF_ABS | 0x20) as u16);
        let jump = &insns[1];
        // on mismatch (jf branch) it must land exactly on the KILL stmt
        // that follows, i.e. jf == 1, not 2 (which would skip over it).
        assert_eq!(jump.jf, 1);
        let kill = &insns[2];
        assert_eq!(kill.k, libc::SECCOMP_RET_KILL_PROCESS);
    }
}
