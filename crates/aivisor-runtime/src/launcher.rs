use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use aivisor_core::{Error, SandboxSpec};
use aivisor_policy::LandlockPlan;
use serde::{Deserialize, Serialize};

use crate::abi;
use crate::caps;
use crate::landlock;
use crate::probe::KernelCaps;
use crate::rootfs::{path_cstring, Rootfs};
use crate::seccomp;

#[derive(Debug, Serialize, Deserialize)]
pub enum ChildMsg {
    Ready,
    Error(String),
    Exited(i32),
}

/// Every sandbox's user/group namespace maps a contiguous block of this
/// many host ids, `0..UID_RANGE_SIZE` in-namespace, so that dropping to an
/// unprivileged in-namespace uid (see SANDBOX_UID below) is a real
/// namespace-scoped id and not just an alias for root. Mapping a single id
/// (the previous behaviour) left no unprivileged uid to drop to at all.
const UID_RANGE_SIZE: u32 = 65536;
/// In-namespace unprivileged uid/gid the sandbox process drops to before
/// execve (blueprint §6.2 step 14). Arbitrary but fixed and non-zero.
const SANDBOX_UID: u32 = 1000;
const SANDBOX_GID: u32 = 1000;

#[derive(Debug)]
pub struct Supervisor {
    pub pid: nix::unistd::Pid,
    pub pidfd: OwnedFd,
}

impl Supervisor {
    /// Block until the sandboxed process exits, using pidfd exclusively —
    /// never a bare `waitpid(-1, ...)`, which would reap unrelated children
    /// of the daemon process (other sandboxes' supervisors included) and
    /// misattribute their exit codes to this one.
    pub fn wait(&self) -> Result<i32, Error> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let ret = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pidfd.as_raw_fd() as libc::id_t,
                    &mut info as *mut _,
                    libc::WEXITED,
                )
            };
            if ret == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(Error::LaunchFailed(format!("waitid: {err}")));
        }

        // SAFETY: populated by a successful WEXITED waitid() above.
        // si_status is inside a union (per-signal payload) so reading it
        // needs the accessor method; si_code is a plain top-level field.
        let si_status = unsafe { info.si_status() };
        let si_code = info.si_code;
        let code = match si_code {
            libc::CLD_EXITED => si_status,
            libc::CLD_KILLED | libc::CLD_DUMPED => 128 + si_status,
            _ => si_status,
        };
        Ok(code)
    }

    pub fn signal(&self, sig: nix::sys::signal::Signal) -> Result<(), Error> {
        let pidfd = self.pidfd.as_raw_fd();
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                sig as i32,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if ret < 0 {
            return Err(Error::LaunchFailed(format!(
                "pidfd_send_signal: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

/// Fully-resolved confinement to apply in the child before execve. Built by
/// the caller (SandboxManager), which is where SandboxSpec + policy +
/// probed Landlock ABI all come together.
pub struct LaunchPolicy {
    pub landlock: LandlockPlan,
    pub seccomp_profile: String,
}

pub struct Launcher {
    pub caps: KernelCaps,
    next_uid_base: Arc<AtomicU32>,
}

impl Launcher {
    pub fn new(caps: KernelCaps) -> Self {
        Self {
            caps,
            next_uid_base: Arc::new(AtomicU32::new(100_000)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        &self,
        spec: &SandboxSpec,
        cg_fd: RawFd,
        rootfs: &Rootfs,
        policy: &LaunchPolicy,
        cmd: &str,
        args: &[String],
    ) -> Result<Supervisor, Error> {
        let (parent_end, child_end) =
            UnixStream::pair().map_err(|e| Error::LaunchFailed(format!("sync socketpair: {e}")))?;

        // Reserve a fresh uid/gid range for this sandbox's user namespace.
        let uid_base = self
            .next_uid_base
            .fetch_add(UID_RANGE_SIZE, Ordering::SeqCst);

        let mut clone_args = abi::CloneArgs {
            flags: abi::CLONE_NEWUSER
                | abi::CLONE_NEWPID
                | abi::CLONE_NEWNS
                | abi::CLONE_NEWNET
                | abi::CLONE_NEWIPC
                | abi::CLONE_NEWUTS
                | abi::CLONE_NEWCGROUP
                | abi::CLONE_NEWTIME
                | abi::CLONE_PIDFD,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };

        let use_clone_into_cgroup = self.caps.clone_into_cgroup;
        if use_clone_into_cgroup {
            clone_args.flags |= abi::CLONE_INTO_CGROUP;
            clone_args.cgroup = cg_fd as u64;
        }

        let mut pidfd_slot: i32 = -1;
        clone_args.pidfd = &mut pidfd_slot as *mut i32 as u64;

        // Prepared before the call so the child branch (which runs with
        // exactly one thread and a COW copy of this stack frame) only has
        // to read an already-built local, not allocate more than
        // necessary.
        let rootfs_merged = path_cstring(&rootfs.merged)?;

        let ret = unsafe { abi::clone3(&mut clone_args) };
        if ret < 0 {
            return Err(Error::LaunchFailed(format!(
                "clone3: {}",
                std::io::Error::last_os_error()
            )));
        }

        if ret == 0 {
            // ---- CHILD ----
            drop(parent_end);
            let mut child_end = child_end;

            let result = Self::child_setup(
                &mut child_end,
                rootfs,
                &rootfs_merged,
                &spec
                    .env
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
                cmd,
                args,
                policy,
                uid_base,
            );

            let msg = match result {
                Ok(never) => match never {},
                Err(e) => ChildMsg::Error(e),
            };
            let _ = send_msg(&mut child_end, &msg);
            unsafe { libc::_exit(127) };
        }

        // ---- PARENT ----
        drop(child_end);
        let mut parent_end = parent_end;
        let pid = nix::unistd::Pid::from_raw(ret as i32);

        let pidfd = if pidfd_slot >= 0 {
            unsafe { OwnedFd::from_raw_fd(pidfd_slot) }
        } else {
            // Kernel too old to honour CLONE_PIDFD despite advertising
            // clone3 — fall back to pidfd_open (small TOCTOU window on pid
            // reuse, unavoidable without CLONE_PIDFD). No pidfd exists yet
            // for this one failure path, so a bare-pid kill is the only
            // option here — every other failure path below has a pidfd
            // and uses it instead, per CLAUDE.md's pidfd-only rule.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
            if fd < 0 {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                return Err(Error::LaunchFailed("pidfd_open failed".into()));
            }
            unsafe { OwnedFd::from_raw_fd(fd as RawFd) }
        };

        if let Err(e) = Self::write_userns_maps(pid, uid_base) {
            kill_via_pidfd(pidfd.as_raw_fd());
            return Err(e);
        }

        if !use_clone_into_cgroup {
            // Fallback for kernels with clone3 but not CLONE_INTO_CGROUP
            // (5.3 <= kernel < 5.7): join the cgroup from the parent BEFORE
            // releasing the child, so there is no window where the child
            // runs outside its eBPF LSM policy (blueprint §6.2).
            if let Err(e) = Self::join_cgroup_from_parent(cg_fd, pid) {
                kill_via_pidfd(pidfd.as_raw_fd());
                return Err(e);
            }
        }

        parent_end
            .write_all(&[1u8])
            .map_err(|e| Error::LaunchFailed(format!("sync send: {e}")))?;

        let msg: ChildMsg = recv_msg(&mut parent_end)?;
        match msg {
            ChildMsg::Ready => {}
            ChildMsg::Error(e) => {
                kill_via_pidfd(pidfd.as_raw_fd());
                return Err(Error::LaunchFailed(format!("child error: {e}")));
            }
            ChildMsg::Exited(code) => {
                return Err(Error::LaunchFailed(format!("child exited early: {code}")));
            }
        }

        Ok(Supervisor { pid, pidfd })
    }

    /// Runs entirely in the child. Returns `Err(message)` on any failure;
    /// on success it `execve()`s and never returns (`!` return type keeps
    /// callers from accidentally treating "setup finished" as a normal
    /// value with more work to do afterward).
    #[allow(clippy::too_many_arguments)]
    fn child_setup(
        sync: &mut UnixStream,
        rootfs: &Rootfs,
        rootfs_merged_c: &CString,
        env: &[(String, String)],
        cmd: &str,
        args: &[String],
        policy: &LaunchPolicy,
        uid_base: u32,
    ) -> Result<std::convert::Infallible, String> {
        // Block until the parent has written uid_map/gid_map/setgroups
        // (and, on the CLONE_INTO_CGROUP fallback path, joined the cgroup).
        let mut buf = [0u8; 1];
        sync.read_exact(&mut buf)
            .map_err(|e| format!("sync read: {e}"))?;

        // Step 9: no_new_privs first — before any of the mount work below,
        // matching blueprint §6.2 (it does not block mount/pivot_root,
        // which still run with full namespaced capabilities at this point).
        caps::set_no_new_privs().map_err(|e| e.to_string())?;

        // Step 10: mount setup + pivot_root. Every mount below is built
        // under `rootfs.merged` (the new root's tree) WHILE STILL IN THE
        // HOST MOUNT NAMESPACE, then the whole tree is pivoted into in one
        // move. This is deliberate: the /dev node binds need host source
        // paths (/dev/null etc.), which are only reachable before
        // pivot_root discards the old root — doing device setup after
        // pivoting would bind the sandbox's own empty placeholder files
        // onto themselves instead of the real host devices.
        remount_root_private()?;
        rootfs.mount_overlay().map_err(|e| e.to_string())?;
        mount_proc(&rootfs.merged)?;
        mount_sys(&rootfs.merged)?;
        mount_tmp(&rootfs.merged)?;
        mount_dev(&rootfs.merged)?;
        // /workspace lives on the overlay's writable upper layer — created
        // here (pre-pivot, but the same underlying directory either way)
        // so the default policy's `/workspace` Landlock rule has something
        // to open a path fd on.
        std::fs::create_dir_all(rootfs.merged.join("workspace"))
            .map_err(|e| format!("mkdir workspace: {e}"))?;
        pivot_into(rootfs_merged_c)?;

        // Step 11: drop capabilities.
        caps::drop_all_capabilities().map_err(|e| e.to_string())?;

        // Step 12: Landlock (opens path fds inside the final mount ns).
        landlock::apply_landlock(&policy.landlock).map_err(|e| e.to_string())?;

        // Step 13: seccomp — last of the self-restrictions, since it may
        // block syscalls (landlock_*, mount, pivot_root) used above it.
        seccomp::apply_seccomp(&policy.seccomp_profile).map_err(|e| e.to_string())?;

        // Step 14: drop to the unprivileged in-namespace uid/gid.
        caps::drop_to_unprivileged(SANDBOX_UID, SANDBOX_GID).map_err(|e| e.to_string())?;
        let _ = uid_base; // documents provenance of SANDBOX_UID's host mapping

        // Report readiness LAST, immediately before execve — sending it any
        // earlier (as this code once did, right after pivot_root) tells the
        // control plane the sandbox is confined while capabilities/Landlock/
        // seccomp/uid-drop are still pending.
        send_msg(sync, &ChildMsg::Ready).map_err(|e| format!("send ready: {e}"))?;

        let cmd_c = CString::new(cmd).map_err(|e| format!("CString cmd: {e}"))?;
        let mut exec_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
        exec_args.push(cmd_c.clone());
        for a in args {
            exec_args.push(CString::new(a.as_bytes()).map_err(|e| format!("CString arg: {e}"))?);
        }
        let mut exec_argv: Vec<*const libc::c_char> =
            exec_args.iter().map(|c| c.as_ptr()).collect();
        exec_argv.push(std::ptr::null());

        let mut envp_c: Vec<CString> = Vec::with_capacity(env.len());
        for (k, v) in env {
            envp_c.push(CString::new(format!("{k}={v}")).map_err(|e| format!("CString env: {e}"))?);
        }
        let mut envp: Vec<*const libc::c_char> = envp_c.iter().map(|c| c.as_ptr()).collect();
        envp.push(std::ptr::null());

        unsafe {
            libc::execve(cmd_c.as_ptr(), exec_argv.as_ptr(), envp.as_ptr());
        }

        Err(format!(
            "execve({cmd}) failed: {}",
            std::io::Error::last_os_error()
        ))
    }

    fn write_userns_maps(pid: nix::unistd::Pid, uid_base: u32) -> Result<(), Error> {
        let pid_str = pid.to_string();

        std::fs::write(format!("/proc/{pid_str}/setgroups"), "deny")
            .map_err(|e| Error::NamespaceSetup(format!("setgroups: {e}")))?;

        // Map the whole in-namespace range to a private host uid block, so
        // uid 0 (root-in-namespace, used transiently for mount/pivot_root)
        // and SANDBOX_UID (dropped to before execve) both resolve to real,
        // distinct, unprivileged-on-the-host ids.
        std::fs::write(
            format!("/proc/{pid_str}/uid_map"),
            format!("0 {uid_base} {UID_RANGE_SIZE}\n"),
        )
        .map_err(|e| Error::NamespaceSetup(format!("uid_map: {e}")))?;

        std::fs::write(
            format!("/proc/{pid_str}/gid_map"),
            format!("0 {uid_base} {UID_RANGE_SIZE}\n"),
        )
        .map_err(|e| Error::NamespaceSetup(format!("gid_map: {e}")))?;

        Ok(())
    }

    fn join_cgroup_from_parent(cg_fd: RawFd, pid: nix::unistd::Pid) -> Result<(), Error> {
        let name = CString::new("cgroup.procs").unwrap();
        let fd = unsafe { libc::openat(cg_fd, name.as_ptr(), libc::O_WRONLY) };
        if fd < 0 {
            return Err(Error::CgroupSetup(format!(
                "openat cgroup.procs: {}",
                std::io::Error::last_os_error()
            )));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let pid_str = pid.as_raw().to_string();
        let ret =
            unsafe { libc::write(fd.as_raw_fd(), pid_str.as_ptr() as *const _, pid_str.len()) };
        if ret < 0 {
            return Err(Error::CgroupSetup(format!(
                "write cgroup.procs: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

fn kill_via_pidfd(pidfd: RawFd) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}

fn send_msg(sock: &mut UnixStream, msg: &ChildMsg) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(std::io::Error::other)?;
    let len = (bytes.len() as u32).to_le_bytes();
    sock.write_all(&len)?;
    sock.write_all(&bytes)
}

fn recv_msg(sock: &mut UnixStream) -> Result<ChildMsg, Error> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf)
        .map_err(|e| Error::LaunchFailed(format!("child recv (len): {e}")))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1 << 20 {
        return Err(Error::LaunchFailed("child message too large".into()));
    }
    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf)
        .map_err(|e| Error::LaunchFailed(format!("child recv (body): {e}")))?;
    serde_json::from_slice(&buf).map_err(|e| Error::LaunchFailed(format!("child msg parse: {e}")))
}

fn remount_root_private() -> Result<(), String> {
    let root = CString::new("/").unwrap();
    let ret = unsafe {
        abi::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "remount / private: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn pivot_into(new_root_c: &CString) -> Result<(), String> {
    // The documented no-temp-directory pivot_root idiom (pivot_root(2)):
    //   chdir(new_root); pivot_root(".", "."); umount2(".", MNT_DETACH);
    // Order matters here specifically: chdir MUST happen before
    // pivot_root, so that the "." used afterward for pivot_root and then
    // umount2 resolves through the mount stack at new_root and lands on
    // the old root once it is stacked there — using absolute paths instead
    // of this exact chdir-then-"." sequence is not the documented-safe
    // form and was deliberately not used here.
    let ret = unsafe { libc::chdir(new_root_c.as_ptr()) };
    if ret != 0 {
        return Err(format!(
            "chdir(new_root): {}",
            std::io::Error::last_os_error()
        ));
    }

    let dot = CString::new(".").unwrap();
    let ret = unsafe { abi::pivot_root(dot.as_ptr(), dot.as_ptr()) };
    if ret != 0 {
        return Err(format!("pivot_root: {}", std::io::Error::last_os_error()));
    }

    // The old root is now mounted at "." (stacked on top of the new root,
    // which cwd still tracks). Lazily unmount it so the host filesystem is
    // no longer reachable from anywhere in this mount namespace — leaving
    // it mounted (the previous bug: `remove_dir("/.oldroot")` on a live
    // mountpoint just fails with EBUSY and is silently discarded) is a
    // full filesystem escape.
    let ret = unsafe { abi::umount2(dot.as_ptr(), abi::MNT_DETACH) };
    if ret != 0 {
        return Err(format!(
            "umount2(old root, MNT_DETACH): {}",
            std::io::Error::last_os_error()
        ));
    }

    let root = CString::new("/").unwrap();
    let ret = unsafe { libc::chdir(root.as_ptr()) };
    if ret != 0 {
        return Err(format!("chdir(/): {}", std::io::Error::last_os_error()));
    }

    Ok(())
}

fn mount_proc(merged: &std::path::Path) -> Result<(), String> {
    let target_path = merged.join("proc");
    std::fs::create_dir_all(&target_path).map_err(|e| format!("mkdir proc: {e}"))?;
    let target = path_cstring(&target_path).map_err(|e| e.to_string())?;
    let fstype = CString::new("proc").unwrap();
    // hidepid=2: only a process's own /proc/<pid> is visible to it;
    // subset=pid: hide non-pid procfs files entirely (sysctls, etc).
    let data = CString::new("hidepid=2,subset=pid").unwrap();
    let ret = unsafe {
        abi::mount(
            fstype.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(format!("mount proc: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn mount_sys(merged: &std::path::Path) -> Result<(), String> {
    let target_path = merged.join("sys");
    std::fs::create_dir_all(&target_path).map_err(|e| format!("mkdir sys: {e}"))?;
    let target = path_cstring(&target_path).map_err(|e| e.to_string())?;
    let fstype = CString::new("sysfs").unwrap();
    let ret = unsafe {
        abi::mount(
            fstype.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            (libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!("mount sys: {}", std::io::Error::last_os_error()));
    }
    // {merged}/sys/fs/cgroup is deliberately never mounted here: the agent
    // must not see, let alone edit, its own cgroup limits (blueprint §7).
    Ok(())
}

fn mount_tmp(merged: &std::path::Path) -> Result<(), String> {
    let target_path = merged.join("tmp");
    std::fs::create_dir_all(&target_path).map_err(|e| format!("mkdir tmp: {e}"))?;
    let target = path_cstring(&target_path).map_err(|e| e.to_string())?;
    let fstype = CString::new("tmpfs").unwrap();
    let data = CString::new("size=536870912,mode=1777").unwrap();
    let ret = unsafe {
        abi::mount(
            fstype.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(format!("mount tmp: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn mount_dev(merged: &std::path::Path) -> Result<(), String> {
    let dev_path = merged.join("dev");
    std::fs::create_dir_all(&dev_path).map_err(|e| format!("mkdir dev: {e}"))?;
    let target = path_cstring(&dev_path).map_err(|e| e.to_string())?;
    let fstype = CString::new("tmpfs").unwrap();
    let data = CString::new("size=67108864,mode=755").unwrap();
    let ret = unsafe {
        abi::mount(
            fstype.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount dev (tmpfs): {}",
            std::io::Error::last_os_error()
        ));
    }

    // Minimal device node subset (blueprint §7): null, zero, full, random,
    // urandom, tty — bind-mounted from the HOST's real nodes (still
    // reachable here, since we are pre-pivot_root) onto placeholder files
    // under the new root's /dev, one at a time, each fail-closed.
    for name in ["null", "zero", "full", "random", "urandom", "tty"] {
        let node_path = dev_path.join(name);
        std::fs::write(&node_path, []).map_err(|e| format!("touch dev/{name}: {e}"))?;
        bind_host_dev(name, &node_path)?;
    }

    // devpts, for ptmx/pty allocation (blueprint lists ptmx explicitly).
    let pts_path = dev_path.join("pts");
    std::fs::create_dir_all(&pts_path).map_err(|e| format!("mkdir dev/pts: {e}"))?;
    let pts_target = path_cstring(&pts_path).map_err(|e| e.to_string())?;
    let pts_fstype = CString::new("devpts").unwrap();
    let pts_data = CString::new("newinstance,ptmxmode=0666,mode=620").unwrap();
    let ret = unsafe {
        abi::mount(
            pts_fstype.as_ptr(),
            pts_target.as_ptr(),
            pts_fstype.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong,
            pts_data.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount dev/pts: {}",
            std::io::Error::last_os_error()
        ));
    }

    let ptmx_path = dev_path.join("ptmx");
    std::fs::write(&ptmx_path, []).map_err(|e| format!("touch dev/ptmx: {e}"))?;
    let ptmx_src = path_cstring(&pts_path.join("ptmx")).map_err(|e| e.to_string())?;
    let ptmx_dst = path_cstring(&ptmx_path).map_err(|e| e.to_string())?;
    let ret = unsafe {
        abi::mount(
            ptmx_src.as_ptr(),
            ptmx_dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "bind dev/ptmx: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn bind_host_dev(name: &str, dest: &std::path::Path) -> Result<(), String> {
    // Source is the host's real device node, read while still in the host
    // mount namespace (before pivot_root). Doing this bind after pivoting
    // would resolve "/dev/<name>" against the sandbox's own empty
    // placeholder instead of the real device.
    let src =
        path_cstring(std::path::Path::new(&format!("/dev/{name}"))).map_err(|e| e.to_string())?;
    let dst = path_cstring(dest).map_err(|e| e.to_string())?;
    let ret = unsafe {
        abi::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_RDONLY) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "bind dev/{name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_launcher_new() {
        let caps = KernelCaps {
            kernel: (6, 1),
            cgroup_v2: true,
            clone3: true,
            clone_into_cgroup: true,
            cgroup_kill: true,
            overlayfs: true,
            overlayfs_in_userns: true,
            unprivileged_userns: true,
            controllers: vec!["cpu".into(), "memory".into()],
        };
        let launcher = Launcher::new(caps);
        assert!(launcher.next_uid_base.load(Ordering::SeqCst) >= 100000);
    }

    #[test]
    fn test_uid_ranges_do_not_overlap_across_sandboxes() {
        let caps = KernelCaps {
            kernel: (6, 1),
            cgroup_v2: true,
            clone3: true,
            clone_into_cgroup: true,
            cgroup_kill: true,
            overlayfs: true,
            overlayfs_in_userns: true,
            unprivileged_userns: true,
            controllers: vec![],
        };
        let launcher = Launcher::new(caps);
        let a = launcher
            .next_uid_base
            .fetch_add(UID_RANGE_SIZE, Ordering::SeqCst);
        let b = launcher
            .next_uid_base
            .fetch_add(UID_RANGE_SIZE, Ordering::SeqCst);
        assert!(b >= a + UID_RANGE_SIZE);
    }
}
