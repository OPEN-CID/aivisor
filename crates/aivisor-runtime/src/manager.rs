use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use aivisor_bpf::{attach_cgroup_hooks, BpfManager, CgroupProgAttachment, ExecSource};
use aivisor_core::{CgroupId, Error, ExecIdentity, SandboxId, SandboxSpec, SandboxState};
use aivisor_policy::{
    AccessDefault, ExecRule as PolicyExecRule, FsPolicy, FsRule, NetPolicy, Policy,
};
use nix::sys::signal::Signal;
use std::sync::Arc;

use crate::cgroup::Cgroup;
use crate::landlock::probe_landlock_abi;
use crate::launcher::{LaunchPolicy, Launcher, Supervisor};
use crate::probe::probe_all;
use crate::rootfs::Rootfs;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const TEMPLATES_DIR: &str = "/var/lib/aivisor/templates";

pub struct SandboxHandle {
    pub id: SandboxId,
    pub state: SandboxState,
    pub spec: SandboxSpec,
    pub cgroup: Option<Cgroup>,
    pub supervisor: Option<Supervisor>,
    pub rootfs: Option<Rootfs>,
    /// cgroup/connect4|6 programs attached to this sandbox's cgroup.
    /// Detached when dropped, during `destroy`.
    bpf_attachments: Vec<CgroupProgAttachment>,
}

#[derive(serde::Serialize)]
pub struct SandboxSummary {
    pub id: SandboxId,
    pub state: SandboxState,
    pub template: String,
}

struct Inner {
    registry: HashMap<String, SandboxHandle>,
    policy_store: HashMap<String, Policy>,
}

pub struct SandboxManager {
    inner: Mutex<Inner>,
    launcher: Launcher,
    /// Probed once at construction (Appendix A: probe by attempt, cache the
    /// result — never re-probe per sandbox). `SandboxManager::new()` fails
    /// closed if Landlock is unavailable at all; there is deliberately no
    /// implicit "run unconfined" fallback here. A future `--insecure-
    /// no-landlock` opt-out (roadmap.md Phase 2 DoD) would thread an
    /// override into this probe call, not bypass it after the fact.
    landlock_abi: u32,
    /// Shared, process-wide BPF enforcement (see `crate::bpf`). Acquired in
    /// `new()`, so a host without working BPF LSM fails at construction
    /// rather than silently launching sandboxes with layer 5 missing.
    bpf: Arc<BpfManager>,
}

impl SandboxManager {
    /// A poisoned mutex means some other thread panicked while mutating the
    /// registry — the `Inner` it left behind is still the best information
    /// this process has (there's no external source to recover from), so
    /// recovering the guard beats letting every subsequent call panic too.
    /// `.unwrap()` on `lock()` would panic identically on poison anyway;
    /// this just makes that an explicit, named decision instead of a bare
    /// unwrap.
    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn new() -> Result<Self, Error> {
        let caps = probe_all();
        crate::probe::check_hard_requirements(&caps).map_err(|_msg| {
            Error::KernelFeatureMissing {
                feature: "hardware requirements",
                min_kernel: "6.1",
            }
        })?;

        let landlock_abi = probe_landlock_abi(1)?;
        let bpf = crate::bpf::enforcement()?;

        let launcher = Launcher::new(caps);

        Self::adopt_or_clean_orphan_cgroups();

        Ok(Self {
            inner: Mutex::new(Inner {
                registry: HashMap::new(),
                policy_store: HashMap::new(),
            }),
            launcher,
            landlock_abi,
            bpf,
        })
    }

    /// Register a named policy so `SandboxSpec.policy = Some(PolicyRef {
    /// name, .. })` can resolve to it. There is no persistent policy store
    /// yet (that is a `aivisord` / Phase 4 concern per roadmap.md) — this
    /// is the in-memory registry for the current process's lifetime, which
    /// is what `aivisor-cli`'s `--policy` flag (see aivisor-cli) populates.
    pub fn register_policy(&self, name: String, policy: Policy) {
        let mut inner = self.lock_inner();
        inner.policy_store.insert(name, policy);
    }

    /// On startup, never delete a cgroup directory that still has live
    /// processes in it — a previous version of this code unconditionally
    /// `rmdir`'d anything whose name looked like a sandbox UUID, which
    /// destroys other sandboxes' state on every daemon restart. Only
    /// confirmed-empty leftovers (crashed prior runs) are cleaned up.
    /// Full crash recovery (reattaching to a still-running sandbox after a
    /// daemon restart) needs a persistent sandbox registry and is Phase 4
    /// scope; this is the conservative, non-destructive interim behavior.
    ///
    /// Empty `cgroup.procs` alone is NOT enough to call something an
    /// orphan: a sandbox mid-launch (`Cgroup::create` has made the
    /// directory, but `Launcher::spawn`'s clone3(CLONE_INTO_CGROUP) or the
    /// `join_cgroup_from_parent` fallback hasn't put a process in it yet)
    /// is legitimately, transiently empty too — and this function can run
    /// concurrently with that launch, from a DIFFERENT `SandboxManager` in
    /// the same process (every test in this codebase constructs its own).
    /// Verified empirically on a real kernel (Ubuntu 24.04, 6.8.0):
    /// running privileged tests together intermittently killed a sibling
    /// test's in-progress sandbox with "No such file or directory" from
    /// clone3/cgroup.procs, because this sweep deleted its cgroup out from
    /// under it between creation and first use. A cgroup genuinely
    /// orphaned by a crashed PRIOR process is old — it was created before
    /// this process even started — so skipping anything younger than
    /// `ORPHAN_GRACE_PERIOD` distinguishes "abandoned by a dead daemon"
    /// from "another live manager is still launching into it" without
    /// needing the persistent registry Phase 4 crash recovery would add.
    fn adopt_or_clean_orphan_cgroups() {
        const ORPHAN_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);

        let cgroup_root = PathBuf::from(CGROUP_ROOT).join("aivisor");
        let Ok(entries) = std::fs::read_dir(&cgroup_root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let id_str = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if id_str.len() != 36 || !id_str.contains('-') {
                continue;
            }

            let age = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.elapsed().ok());
            if !matches!(age, Some(age) if age >= ORPHAN_GRACE_PERIOD) {
                // Too young to plausibly be a crash orphan (or age
                // couldn't be determined at all) — leave it; a live
                // launch may still be using it.
                continue;
            }

            let procs = std::fs::read_to_string(path.join("cgroup.procs")).unwrap_or_default();
            if procs.trim().is_empty() {
                let _ = std::fs::remove_dir(&path);
            }
            // Non-empty: leave it. It belongs to a sandbox this process
            // doesn't know about yet; destroying it would kill a live
            // sandbox out from under its tenant.
        }
    }

    pub fn create(&self, spec: SandboxSpec) -> Result<SandboxId, Error> {
        let id = spec.id;
        let cgroup_root = PathBuf::from(CGROUP_ROOT);

        let cgroup = Cgroup::create(&cgroup_root, &id)?;
        cgroup.apply(&spec.limits)?;

        // Register a deny-all BPF context now, while the cgroup is still
        // empty. Every later step can only relax this, and no process can
        // exist in the cgroup before it — which is what "register before
        // the child is unblocked" (blueprint §6.2) reduces to here.
        self.bpf.register_sandbox(cgroup.id)?;

        // From here on, any failure must undo the registration, or the
        // entry leaks and the cgroup id — which the kernel reuses — could
        // later be re-registered and rejected as a duplicate.
        let setup = (|| -> Result<(Rootfs, Vec<CgroupProgAttachment>), Error> {
            let template_dir = PathBuf::from(TEMPLATES_DIR).join(&spec.template);
            let rootfs = Rootfs::prepare(&template_dir, &spec.workspace, &id.to_string())?;
            // connect4/connect6 are cgroup-scoped rather than global, so
            // unlike the LSM programs they attach per sandbox.
            let attachments = attach_cgroup_hooks(cgroup.fd.as_raw_fd())?;
            Ok((rootfs, attachments))
        })();

        let (rootfs, bpf_attachments) = match setup {
            Ok(v) => v,
            Err(e) => {
                let _ = self.bpf.deregister_sandbox(&cgroup.id);
                return Err(e);
            }
        };

        let mut inner = self.lock_inner();

        inner.registry.insert(
            id.to_string(),
            SandboxHandle {
                id,
                state: SandboxState::Ready,
                spec,
                cgroup: Some(cgroup),
                supervisor: None,
                rootfs: Some(rootfs),
                bpf_attachments,
            },
        );

        Ok(id)
    }

    pub fn exec(&self, id: &SandboxId, cmd: &str, args: &[String]) -> Result<i32, Error> {
        if !cmd.starts_with('/') {
            // See launcher::LaunchPolicy — Landlock rules and BPF exec
            // rules are anchored on exact in-sandbox paths, and raw
            // execve() (used instead of execvp) does no PATH search. A
            // bare command name would silently resolve against whatever
            // the process's cwd happens to be rather than doing the shell-
            // like lookup a caller might expect from `aivisor run -- python3`.
            return Err(Error::LaunchFailed(format!(
                "cmd must be an absolute path inside the sandbox, got {cmd:?} — \
                 aivisor does not perform PATH lookup"
            )));
        }

        // Snapshot everything needed to launch, then release the lock
        // before the (multi-millisecond) clone3+mount+Landlock+seccomp
        // work and the blocking wait() for the child to exit — holding a
        // single global mutex across that would serialize every sandbox in
        // the process against every other one, including unrelated
        // create/list/destroy calls.
        let (spec, cg_fd_owner, rootfs, resolved_policy, cgid) = {
            let mut inner = self.lock_inner();

            let policy = self.resolve_policy_locked(&inner, id)?;

            let handle = inner
                .registry
                .get_mut(&id.to_string())
                .ok_or(Error::LaunchFailed("sandbox not found".into()))?;

            // One payload at a time. This is not just bookkeeping: the
            // launch below returns the sandbox to the non-enforcing setup
            // state so the new child can build its mount namespace, and
            // doing that while an earlier payload is still running would
            // drop that payload out of enforcement.
            if handle.state == SandboxState::Running {
                return Err(Error::LaunchFailed(format!(
                    "sandbox {id} is already running a command; aivisor runs one payload \
                     per sandbox at a time"
                )));
            }

            handle.state = SandboxState::Running;

            let cgroup = handle
                .cgroup
                .as_ref()
                .ok_or(Error::LaunchFailed("no cgroup".into()))?;
            let rootfs = handle
                .rootfs
                .as_ref()
                .ok_or(Error::LaunchFailed("no rootfs".into()))?
                .clone();

            // Duplicate the cgroup dir fd so the clone3 call (which happens
            // outside the lock) has a stable fd independent of `handle`'s
            // lifetime under the lock.
            let dup_fd = unsafe { libc::fcntl(cgroup.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if dup_fd < 0 {
                return Err(Error::LaunchFailed(format!(
                    "dup cgroup fd: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let cg_fd_owner: OwnedFd = unsafe { OwnedFd::from_raw_fd(dup_fd) };

            (handle.spec.clone(), cg_fd_owner, rootfs, policy, cgroup.id)
        };

        let launch_policy = self.build_launch_policy(&resolved_policy, cmd)?;
        let bpf_plan = resolved_policy.compile_bpf();

        // The incoming child builds its own mount namespace from inside
        // this cgroup, and `lsm/sb_mount` denies mounts by a sandbox that
        // is enforcing. Safe here because the `Running` guard above
        // guarantees no payload is live in this sandbox.
        self.bpf.begin_setup(cgid)?;

        // Called by the launcher once the child is confined and has
        // reported the exec identities it can see, but before it is
        // released to execve. Until this runs the sandbox still holds the
        // deny-all context installed at `create`.
        // Installed at the launcher's handshake, from identities the child
        // observed inside its own mount namespace — see ExecIdentity for
        // why they cannot be derived here.
        let install_policy = |exec_ids: &[ExecIdentity]| -> Result<(), Error> {
            self.bpf
                .update_policy(cgid, &bpf_plan, ExecSource::Resolved(exec_ids))
        };

        let cg_fd = cg_fd_owner.as_raw_fd();
        let spawn_result = self.launcher.spawn(
            &spec,
            cg_fd,
            &rootfs,
            &launch_policy,
            cmd,
            args,
            &install_policy,
        );
        drop(cg_fd_owner);

        let supervisor = match spawn_result {
            Ok(s) => s,
            Err(e) => {
                let mut inner = self.lock_inner();
                if let Some(handle) = inner.registry.get_mut(&id.to_string()) {
                    handle.state = SandboxState::Ready;
                }
                return Err(e);
            }
        };

        let exit_code = supervisor.wait();

        let mut inner = self.lock_inner();
        if let Some(handle) = inner.registry.get_mut(&id.to_string()) {
            handle.state = SandboxState::Ready;
        }

        exit_code
    }

    /// Resolve `spec.policy` (a `PolicyRef` by name) against the in-memory
    /// store, falling back to the built-in least-privilege default when no
    /// policy was specified at all. An explicit reference to a name that
    /// isn't registered is an error, not a silent fallback — treating a
    /// typo'd policy name as "use the default" would be a fail-open bug.
    fn resolve_policy_locked(&self, inner: &Inner, id: &SandboxId) -> Result<Policy, Error> {
        let handle = inner
            .registry
            .get(&id.to_string())
            .ok_or(Error::LaunchFailed("sandbox not found".into()))?;

        match &handle.spec.policy {
            None => Ok(default_policy()),
            Some(policy_ref) => inner
                .policy_store
                .get(&policy_ref.name)
                .cloned()
                .ok_or_else(|| {
                    Error::PolicyInvalid(format!(
                        "sandbox references policy {:?}, which is not registered",
                        policy_ref.name
                    ))
                }),
        }
    }

    fn build_launch_policy(&self, policy: &Policy, cmd: &str) -> Result<LaunchPolicy, Error> {
        let mut landlock_plan = policy.compile_landlock(self.landlock_abi);

        // Which binaries the child should report identities for. This
        // mirrors the Landlock decision immediately below: with no explicit
        // exec policy the only executable allowed is the one being run, so
        // that is the only identity to install. Leaving this empty would
        // give the sandbox an empty exec allowlist, and the exec hook
        // denies on no match — the command would be refused by layer 5
        // even though Landlock permitted it.
        let mut exec_paths = Vec::new();
        let mut exec_prefixes = Vec::new();
        match &policy.exec {
            None => exec_paths.push(cmd.to_string()),
            Some(exec) => {
                for rule in &exec.allow {
                    match rule {
                        PolicyExecRule::Path { path, .. } => exec_paths.push(path.clone()),
                        PolicyExecRule::Prefix(prefix) => {
                            exec_prefixes.push(prefix.to_string_lossy().into_owned())
                        }
                    }
                }
            }
        }

        if policy.exec.is_none() {
            // No explicit exec policy: least-privilege dynamic default —
            // grant EXECUTE+READ_FILE on exactly the binary this call is
            // about to run, nothing else. `cmd` is a path as seen INSIDE
            // the sandbox (Landlock rule fds are opened by the child after
            // pivot_root), so it must not be resolved against the host.
            let known = aivisor_policy::landlock_bits::known_at_abi(self.landlock_abi);
            landlock_plan.rules.push(aivisor_policy::LandlockRule {
                path: PathBuf::from(cmd),
                access_mask: (aivisor_policy::landlock_bits::EXECUTE
                    | aivisor_policy::landlock_bits::READ_FILE)
                    & known,
            });
        }

        let seccomp_plan = policy.compile_seccomp();

        Ok(LaunchPolicy {
            landlock: landlock_plan,
            seccomp_profile: seccomp_plan.profile,
            exec_paths,
            exec_prefixes,
        })
    }

    pub fn pause(&self, id: &SandboxId) -> Result<(), Error> {
        let mut inner = self.lock_inner();
        let handle = inner
            .registry
            .get_mut(&id.to_string())
            .ok_or(Error::AlreadyTerminated)?;

        if let Some(ref cg) = handle.cgroup {
            cg.freeze()?;
        }
        handle.state = SandboxState::Paused;
        Ok(())
    }

    pub fn resume(&self, id: &SandboxId) -> Result<(), Error> {
        let mut inner = self.lock_inner();
        let handle = inner
            .registry
            .get_mut(&id.to_string())
            .ok_or(Error::AlreadyTerminated)?;

        if let Some(ref cg) = handle.cgroup {
            cg.thaw()?;
        }
        handle.state = SandboxState::Running;
        Ok(())
    }

    /// Teardown, reverse of acquisition order (blueprint §6.1): freeze/kill
    /// the process tree, wait for the cgroup to empty, unmount the
    /// workspace, then remove the cgroup directory. Idempotent: destroying
    /// an already-gone or never-launched sandbox is not an error.
    ///
    /// The BPF context is removed LAST, after the cgroup is confirmed empty
    /// (roadmap Phase 3 failure mode #3: "deleting map entries before
    /// cgroup empty"). Any process still alive in the cgroup keeps its
    /// enforcement until the moment there are none left; dropping the
    /// context earlier would make every surviving task look like a host
    /// process to the LSM hooks — `if (!ctx) return 0;` — and leave it
    /// briefly unconfined.
    pub fn destroy(&self, id: &SandboxId) -> Result<(), Error> {
        let removed = {
            let mut inner = self.lock_inner();
            inner.registry.remove(&id.to_string())
        };

        let Some(mut handle) = removed else {
            return Ok(());
        };

        if let Some(ref supervisor) = handle.supervisor {
            let _ = supervisor.signal(Signal::SIGKILL);
        }

        let cgid: Option<CgroupId> = handle.cgroup.as_ref().map(|c| c.id);

        if let Some(cg) = handle.cgroup.take() {
            // Cgroup::destroy() already does kill_all + wait_for_empty +
            // rmdir, in that order, and surfaces real errors instead of
            // being swallowed — a caller that ignores this Err would not
            // know a sandbox failed to fully tear down.
            //
            // On failure the BPF context is deliberately left in place:
            // the cgroup could not be confirmed empty, so something may
            // still be running in it and must stay confined.
            cg.destroy()?;
        }

        // The cgroup is gone, so these have nothing left to be attached to;
        // dropping them detaches explicitly rather than relying on the
        // cgroup's removal to do it.
        handle.bpf_attachments.clear();

        if let Some(rootfs) = handle.rootfs.take() {
            // Best-effort: the overlay mount itself lived inside the
            // sandbox's own mount namespace and is already gone once the
            // last process in it exited (cgroup.kill + wait above
            // guarantees that). This just reclaims the host-side
            // upper/work/merged directories.
            if let Some(sandbox_dir) = rootfs.upper.parent() {
                let _ = std::fs::remove_dir_all(sandbox_dir);
            }
        }

        // Last, as documented above.
        if let Some(cgid) = cgid {
            self.bpf.deregister_sandbox(&cgid)?;
        }

        Ok(())
    }

    /// Host-visible path to a sandbox's `/workspace` (the overlay's
    /// writable upper layer) — lets a caller stage files into the sandbox
    /// before calling `exec`, without needing to know `Rootfs`'s internal
    /// layout. Used by `bench/escape`'s harness to place a compiled
    /// scenario binary somewhere the sandbox can execute it from.
    pub fn workspace_upper_dir(&self, id: &SandboxId) -> Result<PathBuf, Error> {
        let inner = self.lock_inner();
        let handle = inner
            .registry
            .get(&id.to_string())
            .ok_or(Error::LaunchFailed("sandbox not found".into()))?;
        let rootfs = handle
            .rootfs
            .as_ref()
            .ok_or(Error::LaunchFailed("no rootfs".into()))?;
        Ok(rootfs.upper.join("workspace"))
    }

    pub fn list(&self) -> Vec<SandboxSummary> {
        let inner = self.lock_inner();
        inner
            .registry
            .values()
            .map(|h| SandboxSummary {
                id: h.id,
                state: h.state,
                template: h.spec.template.clone(),
            })
            .collect()
    }
}

/// Built-in least-privilege default applied when a sandbox has no explicit
/// policy: workspace read-write, base image read+execute, deny everything
/// else (blueprint §8.2's `coding-agent-default` example, minus the exec
/// allowlist — which `build_launch_policy` fills in dynamically per `exec`
/// call instead of hardcoding a fixed binary set here).
///
/// Honest limitation: `/usr`, `/lib`, `/lib64` etc. must actually exist in
/// the template's rootfs for Landlock rule installation to succeed — there
/// is no OCI image pull/build pipeline wired up yet (see `images/base/`),
/// so a template missing these paths makes `apply_landlock` fail closed at
/// launch with a clear error, not silently under-confine.
fn default_policy() -> Policy {
    Policy {
        api_version: "aivisor/v1".into(),
        kind: "SandboxPolicy".into(),
        metadata_name: "aivisor-runtime-default".into(),
        filesystem: Some(FsPolicy {
            default: AccessDefault::Deny,
            rules: vec![
                FsRule {
                    path: "/workspace".into(),
                    access: vec![
                        "read".into(),
                        "write".into(),
                        "create".into(),
                        "delete".into(),
                        "truncate".into(),
                    ],
                    recursive: true,
                },
                FsRule {
                    path: "/usr".into(),
                    access: vec!["read".into(), "execute".into()],
                    recursive: true,
                },
                FsRule {
                    path: "/lib".into(),
                    access: vec!["read".into(), "execute".into()],
                    recursive: true,
                },
                FsRule {
                    path: "/lib64".into(),
                    access: vec!["read".into(), "execute".into()],
                    recursive: true,
                },
                FsRule {
                    path: "/etc/ssl/certs".into(),
                    access: vec!["read".into()],
                    recursive: true,
                },
                FsRule {
                    path: "/tmp".into(),
                    access: vec![
                        "read".into(),
                        "write".into(),
                        "create".into(),
                        "delete".into(),
                    ],
                    recursive: true,
                },
            ],
        }),
        exec: None,
        network: Some(NetPolicy {
            default: AccessDefault::Deny,
            egress: vec![],
            block_metadata: true,
            dns_policy: None,
        }),
        runtime: None,
        audit: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_is_deny_by_default_everywhere() {
        let policy = default_policy();
        assert_eq!(
            policy.filesystem.as_ref().unwrap().default,
            AccessDefault::Deny
        );
        assert_eq!(
            policy.network.as_ref().unwrap().default,
            AccessDefault::Deny
        );
        assert!(policy.network.as_ref().unwrap().block_metadata);
        assert!(
            policy.exec.is_none(),
            "exec left None so the dynamic per-call rule applies"
        );
    }

    #[cfg(feature = "privileged-tests")]
    #[test]
    fn test_manager_create_list_destroy() {
        use std::collections::BTreeMap;
        use std::time::Duration;

        let manager = SandboxManager::new().unwrap();

        let spec = SandboxSpec {
            id: SandboxId::new(),
            template: "base".into(),
            limits: aivisor_core::ResourceLimits::default(),
            workspace: aivisor_core::WorkspaceSpec::Tmpfs { size: 268435456 },
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(60)),
            policy: None,
        };

        let id = manager.create(spec).unwrap();
        let list = manager.list();
        assert_eq!(list.len(), 1);

        manager.destroy(&id).unwrap();
        let list = manager.list();
        assert_eq!(list.len(), 0);
    }

    #[cfg(feature = "privileged-tests")]
    #[test]
    fn test_destroy_idempotent() {
        let manager = SandboxManager::new().unwrap();
        let id = SandboxId::new();
        let result = manager.destroy(&id);
        assert!(result.is_ok());
    }
}
