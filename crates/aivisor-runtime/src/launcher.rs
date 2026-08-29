use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use aivisor_core::{Error, ExecIdentity, SandboxSpec};
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
    /// Fully confined and about to `execve`.
    ///
    /// `exec_ids` carries the identity of every binary the policy allows
    /// this launch to execute, observed from inside the sandbox's own
    /// mount namespace. Only the child can see these: the overlay is
    /// mounted in its namespace, and the device the exec hook matches on
    /// belongs to that mount (see [`aivisor_core::ExecIdentity`]).
    ///
    /// The child blocks after sending this until the parent acknowledges.
    /// That pause is what lets the parent install policy and switch BPF
    /// enforcement on at the one moment when the sandbox has finished
    /// building its mount namespace but has not yet run anything
    /// untrusted.
    Ready {
        exec_ids: Vec<ExecIdentity>,
    },
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

/// Exit status the child uses when it never reached the program at all —
/// any failure in `child_setup`, including a refused `execve`. Callers
/// distinguish it from a program that genuinely exited 127 by the presence
/// of a `ChildMsg::Error` on the sync socket (see `late_child_error`).
pub const CHILD_SETUP_FAILED_EXIT: i32 = 127;

#[derive(Debug)]
pub struct Supervisor {
    pub pid: nix::unistd::Pid,
    pub pidfd: OwnedFd,
    /// Kept open past the handshake purely for diagnostics.
    ///
    /// Everything the child does after the parent releases it — the
    /// `execve` itself, most obviously — can still fail, and at that point
    /// nobody is reading this socket any more. The child reports the reason
    /// and exits 127, so without this the caller sees a bare exit code 127
    /// and no explanation. A refused `execve` is precisely that case, which
    /// makes it the most common failure the sandbox can produce.
    sync: Option<UnixStream>,
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

        // 127 is what the child exits with when it never reached the
        // program. Distinguish that from a program that genuinely exited
        // 127 by looking for a reason on the sync socket: only the child's
        // own failure path writes one.
        if code == CHILD_SETUP_FAILED_EXIT {
            if let Some(reason) = self.late_child_error() {
                return Err(Error::LaunchFailed(reason));
            }
        }

        Ok(code)
    }

    /// Read a `ChildMsg::Error` the child left behind after it was
    /// released, if there is one. Never blocks: the child has already been
    /// reaped by the time this runs, so anything it sent is buffered and
    /// readable now, and anything else means it sent nothing.
    fn late_child_error(&self) -> Option<String> {
        let sock = self.sync.as_ref()?;
        sock.set_nonblocking(true).ok()?;
        let mut sock = sock.try_clone().ok()?;
        match recv_msg(&mut sock) {
            Ok(ChildMsg::Error(e)) => Some(e),
            _ => None,
        }
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
    /// Exact in-sandbox paths the policy allows to be executed. The child
    /// resolves these to `(dev, inode)` after `pivot_root` and reports them
    /// in [`ChildMsg::Ready`] — see `collect_exec_identities`.
    pub exec_paths: Vec<String>,
    /// In-sandbox directories whose immediate executable entries are
    /// allowed. Expanded by the child, the same way.
    pub exec_prefixes: Vec<String>,
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
        install_policy: &dyn Fn(&[ExecIdentity]) -> Result<(), Error>,
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

        // upper/work are chowned to this sandbox's own uid_base HERE, in
        // the parent (real, unmapped root — chown to an arbitrary host
        // uid is only unambiguous from outside any user namespace), before
        // clone3(). The child mounts the overlay itself, inside its own
        // namespace, once it has become namespace-relative root (see
        // caps::become_namespace_root) — at that point its credential
        // resolves to exactly this host uid, matching what upper/work are
        // now owned by. Chowning any later would race the child, which
        // needs upper/work already correctly owned the moment it mounts.
        rootfs.chown_upper_and_work(uid_base, uid_base)?;

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
            unsafe { libc::_exit(CHILD_SETUP_FAILED_EXIT) };
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
        let exec_ids = match msg {
            ChildMsg::Ready { exec_ids } => exec_ids,
            ChildMsg::Error(e) => {
                kill_via_pidfd(pidfd.as_raw_fd());
                return Err(Error::LaunchFailed(format!("child error: {e}")));
            }
            ChildMsg::Exited(code) => {
                return Err(Error::LaunchFailed(format!("child exited early: {code}")));
            }
        };

        // The child is fully confined but has not yet execve'd; it is
        // blocked waiting for the acknowledgement below. This is the point
        // at which policy is installed and enforcement switched on: any
        // earlier and the child's own mount setup would be denied by
        // lsm/sb_mount, any later and untrusted code would already be
        // running.
        //
        // A failure here kills the sandbox rather than releasing it — the
        // alternative is a child that runs with enforcement still off.
        if let Err(e) = install_policy(&exec_ids) {
            kill_via_pidfd(pidfd.as_raw_fd());
            return Err(e);
        }

        if let Err(e) = parent_end.write_all(&[1u8]) {
            kill_via_pidfd(pidfd.as_raw_fd());
            return Err(Error::LaunchFailed(format!("release child: {e}")));
        }

        Ok(Supervisor {
            pid,
            pidfd,
            sync: Some(parent_end),
        })
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

        // Refresh credentials to namespace-relative root NOW, before
        // anything below mounts or creates files: this process's
        // credential otherwise still predates the uid_map just written
        // above (see caps::become_namespace_root's doc comment) and every
        // filesystem this process itself mounts from here on (dev, tmp)
        // would fail file creation with EOVERFLOW.
        caps::become_namespace_root().map_err(|e| e.to_string())?;

        // Step 9: no_new_privs first — before any of the mount work below,
        // matching blueprint §6.2 (it does not block mount/pivot_root,
        // which still run with full namespaced capabilities at this point).
        caps::set_no_new_privs().map_err(|e| e.to_string())?;

        // Step 10: mount setup + pivot_root. Every mount below is built
        // under `rootfs.merged` (the new root's tree), then the whole tree
        // is pivoted into in one move. This is deliberate: the /dev node
        // binds need host source paths (/dev/null etc.), which are only
        // reachable before pivot_root discards the old root — doing device
        // setup after pivoting would bind the sandbox's own empty
        // placeholder files onto themselves instead of the real host
        // devices.
        remount_root_private()?;
        // Mounted here, not by the parent: pivot_root (below) refuses a
        // mount created outside this process's own user namespace
        // ("locked", in kernel terms — verified empirically on a real
        // kernel, Ubuntu 24.08, 6.8.0: pivot_root into a mount the parent
        // made before clone3() fails EINVAL regardless of propagation
        // settings, even though the child inherits an independent copy of
        // it). Mounting it here instead works because, by this point,
        // become_namespace_root() has already given this process a
        // credential that resolves correctly within its own namespace —
        // upper/work (chowned by the parent to this same uid, before
        // clone3()) are then already owned by exactly the uid this mount
        // is performed as. See Rootfs::mount_overlay's doc comment.
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

        // Collect exec identities here: after pivot_root, so paths resolve
        // against the sandbox's own root and /proc/self/mountinfo describes
        // the final mount tree, and before Landlock and seccomp, which may
        // deny the stat and /proc reads this needs.
        let exec_ids = collect_exec_identities(&policy.exec_paths, &policy.exec_prefixes)?;

        // Step 11: drop the capability bounding set + ambient/inheritable.
        // Deliberately NOT effective/permitted yet — step 14 below still
        // needs CAP_SETUID/CAP_SETGID to change uid/gid at all. See
        // caps::drop_bounding_set_and_ambient's doc comment.
        caps::drop_bounding_set_and_ambient().map_err(|e| e.to_string())?;

        // Step 12: Landlock (opens path fds inside the final mount ns).
        landlock::apply_landlock(&policy.landlock).map_err(|e| e.to_string())?;

        // Step 13: seccomp — last of the self-restrictions, since it may
        // block syscalls (landlock_*, mount, pivot_root) used above it.
        seccomp::apply_seccomp(&policy.seccomp_profile).map_err(|e| e.to_string())?;

        // Step 14: drop to the unprivileged in-namespace uid/gid, then
        // finish dropping capabilities now that the uid/gid change no
        // longer needs them.
        caps::drop_to_unprivileged(SANDBOX_UID, SANDBOX_GID).map_err(|e| e.to_string())?;
        caps::finish_dropping_capabilities().map_err(|e| e.to_string())?;
        let _ = uid_base; // documents provenance of SANDBOX_UID's host mapping

        // Report readiness LAST, immediately before execve — sending it any
        // earlier (as this code once did, right after pivot_root) tells the
        // control plane the sandbox is confined while capabilities/Landlock/
        // seccomp/uid-drop are still pending.
        send_msg(sync, &ChildMsg::Ready { exec_ids }).map_err(|e| format!("send ready: {e}"))?;

        // Block until the parent has installed policy and switched
        // enforcement on. Without this wait the child could win the race
        // and execve while enforcement was still off, which is the one
        // window in the whole launch where untrusted code could run
        // unconfined.
        let mut go = [0u8; 1];
        sync.read_exact(&mut go)
            .map_err(|e| format!("wait for policy install: {e}"))?;

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

/// The mount table as `(mount point, kernel dev_t)`, most specific first.
///
/// `/proc/self/mountinfo` is the only interface that reports a mount's real
/// `MAJ:MIN`. `stat(2)` will not do: on an overlay it returns a synthesised
/// per-layer pseudo device instead of the superblock's own, which is what
/// the exec hook compares against. See [`ExecIdentity`].
///
/// Fields are, per `Documentation/filesystems/proc.rst`:
/// `id parent MAJ:MIN root mount-point options...`
fn read_mount_devices() -> Result<Vec<(String, u64)>, String> {
    let raw = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| format!("read /proc/self/mountinfo: {e}"))?;
    Ok(parse_mount_devices(&raw))
}

/// Pure parse half of [`read_mount_devices`], split out so the same table
/// can be built from another task's `/proc/<pid>/mountinfo` (see
/// [`resolve_exec_identities_via_pid`]) and so the field handling is
/// testable without a mount namespace.
fn parse_mount_devices(raw: &str) -> Vec<(String, u64)> {
    let mut mounts = Vec::new();
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_id), Some(_parent), Some(dev), Some(_root), Some(point)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let Some((major, minor)) = dev.split_once(':') else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (major.parse::<u64>(), minor.parse::<u64>()) else {
            continue;
        };
        // Kernel dev_t encoding, which is what struct super_block::s_dev
        // holds and therefore what the BPF side compares against. This is
        // NOT glibc's st_dev layout.
        mounts.push((point.to_string(), (major << 20) | minor));
    }

    // Longest mount point first, so the lookup below finds the most
    // specific mount covering a path (e.g. /tmp before /).
    mounts.sort_by_key(|(point, _)| std::cmp::Reverse(point.len()));
    mounts
}

/// Resolve executables to [`ExecIdentity`] from **outside** the sandbox, by
/// borrowing the view of a task that is already inside it.
///
/// This is the runtime-grant counterpart to [`collect_exec_identities`]:
/// that one runs in the child at launch, this one runs in the daemon
/// against a sandbox that is already up, which is the only way a
/// `GrantCapability` call can produce an exec rule the hook will match.
///
/// Both halves of the identity have to come from the sandbox's namespace,
/// and they come from different places (see [`ExecIdentity`] for the
/// measured table of why):
///
/// * **inode** — `stat` through `/proc/<pid>/root/<path>`, which resolves
///   inside that task's mount namespace and root. `xino=off` on the overlay
///   means the number passes through unchanged.
/// * **dev** — the sandbox's own `/proc/<pid>/mountinfo`, never `st_dev`.
///   `stat(2)` on an overlay reports a synthesised per-layer pseudo device,
///   not the superblock `s_dev` the exec hook compares against.
///
/// `pid` must be a live task inside the target sandbox. A pid that has
/// exited yields a plain "no such file" error from `/proc` rather than a
/// wrong answer, because `/proc/<pid>` disappears with the task — this
/// cannot silently resolve against the host's own root.
pub(crate) fn resolve_exec_identities_via_pid(
    pid: u32,
    paths: &[String],
    prefixes: &[String],
) -> Result<Vec<ExecIdentity>, String> {
    use std::os::unix::fs::MetadataExt;

    if paths.is_empty() && prefixes.is_empty() {
        return Ok(Vec::new());
    }

    let mountinfo = format!("/proc/{pid}/mountinfo");
    let raw = std::fs::read_to_string(&mountinfo)
        .map_err(|e| format!("read {mountinfo}: {e} — is the sandbox still running?"))?;
    let mounts = parse_mount_devices(&raw);

    // Paths are joined onto /proc/<pid>/root, which is a magic symlink the
    // kernel resolves in the target's namespace. `path` is absolute and
    // sandbox-relative, so the leading slash is stripped before joining
    // rather than replacing the whole prefix.
    let in_sandbox = |path: &str| format!("/proc/{pid}/root{path}");

    let mut out = Vec::new();
    for path in paths {
        let host_view = in_sandbox(path);
        let meta = std::fs::metadata(&host_view)
            .map_err(|e| format!("stat {path:?} inside sandbox (via {host_view}): {e}"))?;
        out.push(ExecIdentity {
            // device_for_path matches against the *sandbox's* mount points,
            // so it takes the sandbox-relative path, not the /proc view.
            dev: device_for_path(&mounts, path)?,
            inode: meta.ino(),
        });
    }

    for prefix in prefixes {
        let dev = device_for_path(&mounts, prefix)?;
        let host_view = in_sandbox(prefix);
        let entries = std::fs::read_dir(&host_view)
            .map_err(|e| format!("read exec prefix {prefix:?} inside sandbox: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read exec prefix {prefix:?}: {e}"))?;
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_file() && meta.mode() & 0o111 != 0 {
                out.push(ExecIdentity {
                    dev,
                    inode: meta.ino(),
                });
            }
        }
    }

    Ok(out)
}

/// Kernel `dev_t` of the mount that `path` resolves on.
fn device_for_path(mounts: &[(String, u64)], path: &str) -> Result<u64, String> {
    mounts
        .iter()
        .find(|(point, _)| {
            path == point
                || path.starts_with(point)
                    && (point == "/" || path.as_bytes().get(point.len()) == Some(&b'/'))
        })
        .map(|(_, dev)| *dev)
        .ok_or_else(|| format!("no mount covers {path:?}"))
}

/// Identify every allowlisted executable from inside the sandbox, so the
/// parent can build exec rules the kernel will actually match.
///
/// Runs in the child, after `pivot_root`, so paths and the mount table are
/// both the sandbox's own.
///
/// A listed path that does not exist is an error rather than a skip: a
/// typo'd or missing binary would otherwise silently produce a shorter
/// allowlist than the policy asked for, surfacing much later as an
/// unexplained exec denial.
fn collect_exec_identities(
    paths: &[String],
    prefixes: &[String],
) -> Result<Vec<ExecIdentity>, String> {
    use std::os::unix::fs::MetadataExt;

    if paths.is_empty() && prefixes.is_empty() {
        return Ok(Vec::new());
    }

    let mounts = read_mount_devices()?;
    let mut out = Vec::new();

    for path in paths {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("stat allowlisted executable {path:?} inside sandbox: {e}"))?;
        out.push(ExecIdentity {
            dev: device_for_path(&mounts, path)?,
            inode: meta.ino(),
        });
    }

    for prefix in prefixes {
        let dev = device_for_path(&mounts, prefix)?;
        let entries = std::fs::read_dir(prefix)
            .map_err(|e| format!("read exec prefix {prefix:?} inside sandbox: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read exec prefix {prefix:?}: {e}"))?;
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            // Only regular files with an execute bit can ever reach the
            // exec hook; anything else would just consume a rule slot.
            if meta.is_file() && meta.mode() & 0o111 != 0 {
                out.push(ExecIdentity {
                    dev,
                    inode: meta.ino(),
                });
            }
        }
    }

    Ok(out)
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
