//! Userspace side of the BPF map contract.
//!
//! Every per-sandbox decision the LSM programs make is driven from these
//! maps: `sandboxes` (one `struct sandbox_ctx` per cgroup id) plus the rule
//! maps it points into. The programs themselves are global and stateless —
//! loaded once at daemon start (see `loader.rs`), never per sandbox.
//!
//! Ordering is the security-critical part, and it is forced by the BPF
//! side's deny-by-default shape:
//!
//! * [`BpfManager::register_sandbox`] MUST complete before any process can
//!   exist in the sandbox's cgroup. It installs a `sandbox_ctx` with
//!   zero-length rule ranges, so the moment enforcement is switched on the
//!   sandbox denies everything the hooks gate. A task running before that
//!   entry exists is not a sandbox as far as the BPF programs are concerned
//!   (`if (!ctx) return 0;` — the guard that keeps them off host processes)
//!   and is therefore entirely unenforced.
//! * [`BpfManager::update_policy`] installs the rules and switches
//!   `FLAG_ENFORCING` on. It MUST run before the sandbox executes anything
//!   untrusted, and cannot run earlier than the child's own mount setup —
//!   see `register_sandbox` for why those two constraints do not conflict.
//! * [`BpfManager::deregister_sandbox`] MUST run **last** at teardown, after
//!   the cgroup is confirmed empty.
//!
//! Both orderings are the caller's responsibility; this module cannot
//! observe whether the child is running, so it cannot enforce them itself.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use aivisor_core::{CgroupId, Error};
use aivisor_policy::{BpfExecRule, BpfNetRule, BpfPlan};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::loader::PIN_DIR;

/// Upper bound on how many rules one sandbox's range may span.
///
/// This is not a policy preference — it is the trip count of the `#pragma
/// unroll` loops in `fs.bpf.c` and `exec.bpf.c` (`MAX_RULES_PER_SANDBOX` in
/// `common.h`). A sandbox whose range is longer than this would have its
/// tail silently never examined, so a policy that exceeds it is rejected
/// here rather than installed and under-enforced.
pub const MAX_RULES_PER_SANDBOX: u32 = 64;

/// `max_entries` of each rule map, mirrored from `common.h`. Allocation is
/// refused past these, since a map write beyond capacity fails at the
/// kernel and would otherwise leave a half-installed policy.
const FS_RULES_CAPACITY: u32 = 65536;
const EXEC_RULES_CAPACITY: u32 = 8192;

/// Number of leading key bits an LPM `net_rules` lookup matches before it
/// reaches the address — the full cgroup id. Mirrors `NET_KEY_CGID_BITS`.
const NET_KEY_CGID_BITS: u32 = 64;

/// Allocates contiguous index ranges inside one rule map.
///
/// Ranges are reclaimed on release and coalesced with their neighbours. The
/// previous implementation only ever bumped a counter forward, so a daemon
/// churning sandboxes exhausted the map's index space and every policy
/// install past that point failed — a liveness bug that presents as a hard
/// launch failure once the counter passes `max_entries`.
///
/// Kept free of any kernel interaction so the allocation logic is testable
/// without privileges; [`BpfManager`] owns the map writes.
#[derive(Debug)]
struct RuleAllocator {
    what: &'static str,
    /// Free ranges as `(base, len)`, sorted by base and always coalesced.
    free: Vec<(u32, u32)>,
}

impl RuleAllocator {
    fn new(what: &'static str, capacity: u32) -> Self {
        Self {
            what,
            free: vec![(0, capacity)],
        }
    }

    /// First-fit allocation of `count` contiguous indices.
    ///
    /// `count == 0` is the deny-all case: it reserves nothing and returns
    /// base 0, which is sound because the BPF side reads `[base, base+count)`
    /// and an empty range can never contain a matching index regardless of
    /// where it nominally starts.
    fn alloc(&mut self, count: u32) -> Result<u32, Error> {
        if count == 0 {
            return Ok(0);
        }
        let pos = self
            .free
            .iter()
            .position(|&(_, len)| len >= count)
            .ok_or_else(|| {
                Error::PolicyInvalid(format!(
                    "{} map has no free range of {count} entries (fragmented or full)",
                    self.what
                ))
            })?;
        let (base, len) = self.free[pos];
        if len == count {
            self.free.remove(pos);
        } else {
            self.free[pos] = (base + count, len - count);
        }
        Ok(base)
    }

    /// Return a range to the pool, merging it with adjacent free ranges so
    /// repeated create/destroy cycles cannot fragment the map into
    /// unusable slivers.
    fn release(&mut self, base: u32, count: u32) {
        if count == 0 {
            return;
        }
        let pos = self.free.partition_point(|&(b, _)| b < base);
        self.free.insert(pos, (base, count));

        let mut i = 0;
        while i + 1 < self.free.len() {
            let (b, l) = self.free[i];
            let (nb, nl) = self.free[i + 1];
            if b + l == nb {
                self.free[i] = (b, l + nl);
                self.free.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }
}

/// The four maps this manager writes, opened from the pins `loader.rs`
/// created. Opening by pin path rather than holding the loader's `Object`
/// keeps policy installation independent of who loaded the programs.
struct BpfMaps {
    sandboxes: MapHandle,
    fs_rules: MapHandle,
    exec_rules: MapHandle,
    net_rules: MapHandle,
}

impl BpfMaps {
    fn open_pinned() -> Result<Self, Error> {
        let open = |name: &str| -> Result<MapHandle, Error> {
            let path = PathBuf::from(PIN_DIR).join(name);
            MapHandle::from_pinned_path(&path).map_err(|e| {
                Error::LaunchFailed(format!(
                    "open pinned BPF map {}: {e} — are the programs loaded? \
                     (BpfLoader::load_and_attach pins them)",
                    path.display()
                ))
            })
        };
        Ok(Self {
            sandboxes: open("sandboxes")?,
            fs_rules: open("fs_rules")?,
            exec_rules: open("exec_rules")?,
            net_rules: open("net_rules")?,
        })
    }
}

/// Userspace manager for BPF map entries.
pub struct BpfManager {
    maps: BpfMaps,
    inner: Mutex<BpfManagerInner>,
}

struct BpfManagerInner {
    registered: HashMap<u64, SandboxBpfState>,
    policy_gen: u32,
    fs_alloc: RuleAllocator,
    exec_alloc: RuleAllocator,
}

/// What userspace must remember about a sandbox to be able to take its
/// policy back down again. The kernel-side truth lives in the maps; this is
/// the bookkeeping needed to reclaim it.
struct SandboxBpfState {
    fs_rules_base: u32,
    fs_rules_count: u32,
    exec_rules_base: u32,
    exec_rules_count: u32,
    /// `net_rules` is an LPM trie keyed by (cgid, address), not an index
    /// range, so its entries are tracked by key to be deleted individually.
    net_keys: Vec<NetKey>,
}

impl BpfManager {
    /// Open the pinned maps. Fails if the programs have not been loaded —
    /// there is deliberately no in-memory fallback mode: a manager that
    /// accepted policy and wrote it nowhere would report success while
    /// enforcing nothing.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            maps: BpfMaps::open_pinned()?,
            inner: Mutex::new(BpfManagerInner {
                registered: HashMap::new(),
                policy_gen: 0,
                fs_alloc: RuleAllocator::new("fs_rules", FS_RULES_CAPACITY),
                exec_alloc: RuleAllocator::new("exec_rules", EXEC_RULES_CAPACITY),
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BpfManagerInner> {
        // Poisoning would mean a previous holder panicked mid-update,
        // leaving map state and bookkeeping possibly out of step. Recover
        // the guard rather than panic: callers are teardown paths that
        // still need to run, and every operation below re-reads the map.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a sandbox with an empty, not-yet-enforcing context, before
    /// any process can exist in its cgroup.
    ///
    /// Every rule range is empty — so the moment `FLAG_ENFORCING` is set,
    /// the sandbox denies everything the hooks gate — but the flag itself
    /// starts **clear**, and that is deliberate.
    ///
    /// The child sets up its own confinement from inside the cgroup: it
    /// remounts `/` private, mounts the overlay, `/proc`, `/sys`, `/tmp`
    /// and `/dev`, then pivots. Those are its own syscalls, made from a
    /// task the hooks already see as this sandbox, and `lsm/sb_mount`
    /// denies every mount a sandbox attempts. Enforcing from registration
    /// therefore makes the sandbox deny its own construction, which is
    /// exactly what it did before this was split: launches failed at
    /// "remount / private: Operation not permitted".
    ///
    /// Enforcement is switched on by [`Self::update_policy`], which the
    /// launcher calls while the child is blocked, confined, and not yet
    /// `execve`d. Nothing untrusted has run at any point before that: the
    /// only code executing in the cgroup until then is the launcher's own
    /// child-setup path, and the child physically cannot reach `execve`
    /// until the parent releases it. See [`Self::begin_setup`] for
    /// relaunches.
    ///
    /// Registering an already-registered cgroup id is an error: it would
    /// orphan the previous entry's rule ranges (leaking map space) and
    /// silently re-point a running sandbox at a fresh empty context.
    pub fn register_sandbox(&self, cgid: CgroupId) -> Result<(), Error> {
        let mut inner = self.lock();
        if inner.registered.contains_key(&cgid.as_raw()) {
            return Err(Error::PolicyInvalid(format!(
                "cgroup id {} is already registered in the BPF sandbox map",
                cgid.as_raw()
            )));
        }

        let ctx = SandboxCtx::registered_for_setup();
        self.maps
            .sandboxes
            .update(&cgid.as_raw().to_ne_bytes(), &ctx.to_bytes(), MapFlags::ANY)
            .map_err(|e| {
                Error::LaunchFailed(format!(
                    "register cgroup {} in BPF sandboxes map: {e}",
                    cgid.as_raw()
                ))
            })?;

        inner.registered.insert(
            cgid.as_raw(),
            SandboxBpfState {
                fs_rules_base: 0,
                fs_rules_count: 0,
                exec_rules_base: 0,
                exec_rules_count: 0,
                net_keys: Vec::new(),
            },
        );
        Ok(())
    }

    /// Return a registered sandbox to the not-yet-enforcing setup state,
    /// for a second (or later) launch into the same sandbox.
    ///
    /// Each launch builds a fresh mount namespace and so repeats the mount
    /// sequence that `lsm/sb_mount` denies; without this, only a sandbox's
    /// first launch would ever succeed.
    ///
    /// This widens the sandbox, so the caller must guarantee no payload is
    /// running in it — `SandboxManager` enforces that by refusing to launch
    /// into a sandbox that is already `Running`. Calling it while untrusted
    /// code is live would drop that code out of enforcement.
    pub fn begin_setup(&self, cgid: CgroupId) -> Result<(), Error> {
        let inner = self.lock();
        if !inner.registered.contains_key(&cgid.as_raw()) {
            return Err(Error::PolicyInvalid(format!(
                "cgroup id {} is not registered",
                cgid.as_raw()
            )));
        }
        let mut ctx = self.read_ctx(cgid)?;
        ctx.flags &= !SandboxCtx::FLAG_ENFORCING;
        self.maps
            .sandboxes
            .update(&cgid.as_raw().to_ne_bytes(), &ctx.to_bytes(), MapFlags::ANY)
            .map_err(|e| {
                Error::LaunchFailed(format!("reset {} to setup state: {e}", cgid.as_raw()))
            })
    }

    /// Install a compiled policy for an already-registered sandbox, and
    /// switch enforcement on.
    ///
    /// The swap is ordered so that no window exists in which the sandbox is
    /// less restricted than either the old or the new policy:
    ///
    /// 1. Resolve and validate everything that can fail (path → inode,
    ///    hash pins, CIDR parsing, rule counts) before touching a map.
    /// 2. Write the new rules into freshly allocated indices the running
    ///    `sandbox_ctx` does not point at yet.
    /// 3. Swap `sandbox_ctx` to the new ranges in a single map update.
    /// 4. Only then release the old ranges.
    ///
    /// Step 3 is a whole-value update of one hash entry. `sandboxes` is
    /// declared `BPF_F_NO_PREALLOC` precisely so this is atomic against a
    /// concurrent reader: a no-prealloc hash update installs a new element
    /// and swaps it under the bucket lock, and an in-flight program keeps
    /// its RCU-protected pointer to the old element for the rest of its
    /// run. It therefore observes the old ranges or the new ones, never a
    /// torn mix of the two — which, with prealloc's in-place value copy,
    /// would let a reader pair a new base with an old count and walk off
    /// the end of the intended range.
    pub fn update_policy(
        &self,
        cgid: CgroupId,
        plan: &BpfPlan,
        exec: ExecSource<'_>,
    ) -> Result<(), Error> {
        let fs_count = u32::try_from(plan.fs_rules.len()).unwrap_or(u32::MAX);
        check_rule_count("filesystem", fs_count)?;

        // Resolve exec rules to (dev, inode) up front: a prefix rule
        // expands to one entry per executable in the directory, so the
        // final count is not knowable from the plan alone.
        let exec_entries = match exec {
            ExecSource::HostPaths => resolve_exec_rules(&plan.exec_rules)?,
            // `id.dev` is already a kernel dev_t (read from mountinfo, not
            // from st_dev), so it must NOT go through to_kernel_dev.
            ExecSource::Resolved(ids) => ids
                .iter()
                .map(|id| ExecRule {
                    dev: id.dev,
                    inode: id.inode,
                    hash: [0u8; 32],
                })
                .collect(),
        };
        let exec_count = u32::try_from(exec_entries.len()).unwrap_or(u32::MAX);
        check_rule_count("exec", exec_count)?;

        let net_entries = resolve_net_rules(cgid, &plan.net_rules)?;

        let mut inner = self.lock();
        if !inner.registered.contains_key(&cgid.as_raw()) {
            // Silently succeeding here (the previous behaviour) meant a
            // policy could be "installed" for a sandbox that was never
            // registered: no map entry, no enforcement, no error.
            return Err(Error::PolicyInvalid(format!(
                "cgroup id {} is not registered — register_sandbox must run first",
                cgid.as_raw()
            )));
        }

        let fs_base = inner.fs_alloc.alloc(fs_count)?;
        let exec_base = match inner.exec_alloc.alloc(exec_count) {
            Ok(b) => b,
            Err(e) => {
                inner.fs_alloc.release(fs_base, fs_count);
                return Err(e);
            }
        };

        // From here on, unwind any partial map writes on failure — a
        // half-installed ruleset that the ctx never points at is dead
        // space, but one the ctx does point at is a wrong policy.
        let result = (|| -> Result<(), Error> {
            for (i, rule) in plan.fs_rules.iter().enumerate() {
                let idx = fs_base + i as u32;
                let value = FsRule {
                    path_hash: rule.path_hash,
                    access_mask: rule.access_mask,
                }
                .to_bytes();
                self.maps
                    .fs_rules
                    .update(&idx.to_ne_bytes(), &value, MapFlags::ANY)
                    .map_err(|e| Error::LaunchFailed(format!("write fs_rules[{idx}]: {e}")))?;
            }
            for (i, entry) in exec_entries.iter().enumerate() {
                let idx = exec_base + i as u32;
                self.maps
                    .exec_rules
                    .update(&idx.to_ne_bytes(), &entry.to_bytes(), MapFlags::ANY)
                    .map_err(|e| Error::LaunchFailed(format!("write exec_rules[{idx}]: {e}")))?;
            }
            for (key, ports) in &net_entries {
                self.maps
                    .net_rules
                    .update(&key.to_bytes(), &ports.to_ne_bytes(), MapFlags::ANY)
                    .map_err(|e| Error::LaunchFailed(format!("write net_rules {key:?}: {e}")))?;
            }
            Ok(())
        })();

        if let Err(e) = result {
            for (key, _) in &net_entries {
                let _ = self.maps.net_rules.delete(&key.to_bytes());
            }
            self.delete_rule_range(&self.maps.fs_rules, fs_base, fs_count);
            self.delete_rule_range(&self.maps.exec_rules, exec_base, exec_count);
            inner.fs_alloc.release(fs_base, fs_count);
            inner.exec_alloc.release(exec_base, exec_count);
            return Err(e);
        }

        inner.policy_gen = inner.policy_gen.wrapping_add(1);
        let policy_gen = inner.policy_gen;

        // Preserve the live flags (FLAG_DIRTY may have been set by the
        // kernel side since registration) instead of resetting them.
        let existing = self.read_ctx(cgid)?;
        let ctx = SandboxCtx {
            sandbox_seq: existing.sandbox_seq,
            flags: existing.flags | SandboxCtx::FLAG_ENFORCING,
            policy_gen,
            fs_rules_base: fs_base,
            fs_rules_count: fs_count,
            exec_rules_base: exec_base,
            exec_rules_count: exec_count,
            // Net matching is by key, not index range; these are carried
            // for observability only (see `NetKey`).
            net_rules_base: 0,
            net_rules_count: u32::try_from(net_entries.len()).unwrap_or(u32::MAX),
            turn_id: existing.turn_id,
        };
        self.maps
            .sandboxes
            .update(&cgid.as_raw().to_ne_bytes(), &ctx.to_bytes(), MapFlags::ANY)
            .map_err(|e| {
                Error::LaunchFailed(format!("swap sandbox_ctx for {}: {e}", cgid.as_raw()))
            })?;

        let old = inner
            .registered
            .insert(
                cgid.as_raw(),
                SandboxBpfState {
                    fs_rules_base: fs_base,
                    fs_rules_count: fs_count,
                    exec_rules_base: exec_base,
                    exec_rules_count: exec_count,
                    net_keys: net_entries.iter().map(|(k, _)| *k).collect(),
                },
            )
            .ok_or_else(|| {
                Error::PolicyInvalid(format!("cgroup id {} vanished mid-update", cgid.as_raw()))
            })?;

        // Old ranges are unreachable now that the ctx points elsewhere.
        self.delete_rule_range(&self.maps.fs_rules, old.fs_rules_base, old.fs_rules_count);
        self.delete_rule_range(
            &self.maps.exec_rules,
            old.exec_rules_base,
            old.exec_rules_count,
        );
        for key in &old.net_keys {
            if !net_entries.iter().any(|(k, _)| k == key) {
                let _ = self.maps.net_rules.delete(&key.to_bytes());
            }
        }
        inner
            .fs_alloc
            .release(old.fs_rules_base, old.fs_rules_count);
        inner
            .exec_alloc
            .release(old.exec_rules_base, old.exec_rules_count);

        Ok(())
    }

    /// Remove a sandbox from the maps. Call at teardown, after the cgroup
    /// is confirmed empty.
    ///
    /// Rules are deleted before the `sandbox_ctx` entry, not after. Should
    /// any process somehow still be alive in the cgroup, dropping the rules
    /// first leaves it with a context whose lookups all miss — exec and
    /// network deny, which is the safe direction. Deleting the context
    /// first would instead make it a non-sandbox to every hook
    /// (`if (!ctx) return 0;`), i.e. briefly unenforced.
    ///
    /// Idempotent: deregistering an unknown cgroup id is not an error, so
    /// teardown can run after a partial launch.
    pub fn deregister_sandbox(&self, cgid: &CgroupId) -> Result<(), Error> {
        let mut inner = self.lock();
        let Some(state) = inner.registered.remove(&cgid.as_raw()) else {
            return Ok(());
        };

        self.delete_rule_range(
            &self.maps.fs_rules,
            state.fs_rules_base,
            state.fs_rules_count,
        );
        self.delete_rule_range(
            &self.maps.exec_rules,
            state.exec_rules_base,
            state.exec_rules_count,
        );
        for key in &state.net_keys {
            let _ = self.maps.net_rules.delete(&key.to_bytes());
        }

        inner
            .fs_alloc
            .release(state.fs_rules_base, state.fs_rules_count);
        inner
            .exec_alloc
            .release(state.exec_rules_base, state.exec_rules_count);

        self.maps
            .sandboxes
            .delete(&cgid.as_raw().to_ne_bytes())
            .map_err(|e| {
                Error::LaunchFailed(format!(
                    "delete cgroup {} from BPF sandboxes map: {e}",
                    cgid.as_raw()
                ))
            })
    }

    /// Read a sandbox's live context out of the map.
    pub fn read_ctx(&self, cgid: CgroupId) -> Result<SandboxCtx, Error> {
        let raw = self
            .maps
            .sandboxes
            .lookup(&cgid.as_raw().to_ne_bytes(), MapFlags::ANY)
            .map_err(|e| Error::LaunchFailed(format!("lookup sandbox_ctx {}: {e}", cgid.as_raw())))?
            .ok_or_else(|| {
                Error::PolicyInvalid(format!("no sandbox_ctx for cgroup id {}", cgid.as_raw()))
            })?;
        SandboxCtx::from_bytes(&raw).ok_or_else(|| {
            Error::LaunchFailed(format!(
                "sandbox_ctx for cgroup {} is {} bytes, expected {} — Rust/C struct mismatch",
                cgid.as_raw(),
                raw.len(),
                SandboxCtx::SIZE
            ))
        })
    }

    /// Whether the kernel side has flagged any state-changing operation
    /// this turn.
    ///
    /// Returns an error rather than a bool when the context cannot be read:
    /// the caller (checkpoint policy) must treat an unreadable sandbox as
    /// dirty, and a bare `false` would silently skip a needed snapshot.
    pub fn is_turn_dirty(&self, cgid: &CgroupId) -> Result<bool, Error> {
        Ok(self.read_ctx(*cgid)?.flags & SandboxCtx::FLAG_DIRTY != 0)
    }

    /// Best-effort removal of an index range from a rule map.
    ///
    /// Delete failures are swallowed deliberately: this only runs on paths
    /// where the range is already unreachable from any `sandbox_ctx`, so a
    /// stale entry is wasted space rather than a policy effect, and the
    /// index is not returned to the allocator until the caller says so.
    fn delete_rule_range(&self, map: &MapHandle, base: u32, count: u32) {
        for i in 0..count {
            let idx = base + i;
            let _ = map.delete(&idx.to_ne_bytes());
        }
    }
}

/// Where the `(dev, inode)` pairs behind a policy's exec allowlist come
/// from.
///
/// The distinction is load-bearing. An `aivisor` sandbox roots on an
/// overlayfs mounted inside the child's own mount namespace, and the device
/// number that filesystem reports exists only in that namespace — so exec
/// rules for a real sandbox can only be built from identities the child
/// observed and reported back (see [`aivisor_core::ExecIdentity`]).
/// Resolving the same paths on the host yields the right inode and the
/// wrong device, which matches nothing and denies every exec.
pub enum ExecSource<'a> {
    /// Stat the plan's exec paths on the host filesystem. Correct only
    /// when the process being confined executes binaries the host sees at
    /// those same paths, with no intervening overlay — which today means
    /// tests and direct-rootfs callers, not `SandboxManager`.
    HostPaths,
    /// Identities already resolved by the caller, in the kernel's own
    /// encoding. `SandboxManager` supplies these from inside the sandbox's
    /// mount namespace — see [`aivisor_core::ExecIdentity`].
    Resolved(&'a [aivisor_core::ExecIdentity]),
}

fn check_rule_count(what: &str, count: u32) -> Result<(), Error> {
    if count > MAX_RULES_PER_SANDBOX {
        return Err(Error::PolicyInvalid(format!(
            "policy has {count} {what} rules, over the {MAX_RULES_PER_SANDBOX} a sandbox's \
             range may span — the BPF hook's unrolled loop would never examine the rest, \
             so the excess would be silently unenforced"
        )));
    }
    Ok(())
}

/// Resolve compiled exec rules to the `(dev, inode)` pairs the BPF hook
/// matches on.
///
/// A prefix rule is expanded to one entry per executable regular file
/// directly inside the directory. That snapshot is taken now, at install
/// time: a binary added to the directory afterwards is not covered, and
/// neither are nested subdirectories. Both are deliberate — the hook
/// matches kernel objects, not paths, and there is nothing to match until
/// an inode exists. Landlock's EXECUTE right remains the path-tree-shaped
/// layer (blueprint §5.3).
fn resolve_exec_rules(rules: &[BpfExecRule]) -> Result<Vec<ExecRule>, Error> {
    use std::os::unix::fs::MetadataExt;

    let mut out = Vec::new();
    for rule in rules {
        if rule.is_prefix {
            let entries = std::fs::read_dir(&rule.path).map_err(|e| {
                Error::PolicyInvalid(format!(
                    "exec prefix rule {:?} cannot be read: {e} — a prefix that does not \
                     resolve would allow nothing, which is more likely a policy typo than \
                     an intentional deny-all",
                    rule.path
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    Error::PolicyInvalid(format!("read exec prefix {:?}: {e}", rule.path))
                })?;
                let meta = match entry.metadata() {
                    Ok(m) if m.is_file() && m.mode() & 0o111 != 0 => m,
                    // Non-executables and unreadable entries are not
                    // candidates for exec in the first place.
                    _ => continue,
                };
                out.push(ExecRule {
                    dev: to_kernel_dev(meta.dev()),
                    inode: meta.ino(),
                    hash: [0u8; 32],
                });
            }
        } else {
            let meta = std::fs::metadata(&rule.path).map_err(|e| {
                Error::PolicyInvalid(format!("exec rule {:?} cannot be stat'd: {e}", rule.path))
            })?;
            if let Some(expected) = rule.hash {
                verify_sha256_pin(&rule.path, &expected)?;
            }
            out.push(ExecRule {
                dev: to_kernel_dev(meta.dev()),
                inode: meta.ino(),
                hash: rule.hash.unwrap_or([0u8; 32]),
            });
        }
    }
    Ok(out)
}

/// Check a `sha256:` pin against the file's current contents.
///
/// Honest limitation: this is an **install-time** integrity check, not a
/// per-exec one. The BPF hook matches `(dev, inode)` and cannot hash a file
/// from an LSM context, so a binary replaced in place — same inode, new
/// contents — after policy installation still executes. Pinning therefore
/// detects a tampered or wrong-version binary at launch; it is not a
/// runtime integrity guarantee, and the hash carried into the map is
/// retained for audit rather than consulted by any hook.
fn verify_sha256_pin(path: &str, expected: &[u8; 32]) -> Result<(), Error> {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path)
        .map_err(|e| Error::PolicyInvalid(format!("read {path} to verify sha256 pin: {e}")))?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual != expected {
        return Err(Error::PolicyInvalid(format!(
            "sha256 pin mismatch for {path}: policy pins {}, file is {}",
            hex(expected),
            hex(&actual)
        )));
    }
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convert a userspace `st_dev` to the kernel's `dev_t` encoding.
///
/// These are not the same number. `struct super_block::s_dev`, which the
/// exec hook reads, is the kernel's 32-bit `MKDEV(major, minor)` =
/// `major << 20 | minor`. glibc's `st_dev` is a 64-bit value with major and
/// minor split across different bit ranges entirely. Comparing the two
/// directly never matches, which would make every exec rule dead and every
/// exec deny — fail-closed, but a total false negative.
fn to_kernel_dev(st_dev: u64) -> u64 {
    let major = nix::sys::stat::major(st_dev);
    let minor = nix::sys::stat::minor(st_dev);
    ((major << 20) | minor) as u64
}

/// Compile the plan's CIDR + port list into LPM trie entries scoped to this
/// sandbox's cgroup id.
fn resolve_net_rules(cgid: CgroupId, rules: &[BpfNetRule]) -> Result<Vec<(NetKey, u64)>, Error> {
    let mut out = Vec::new();
    for rule in rules {
        let (addr, prefix) = parse_cidr(&rule.cidr)?;
        let mut ports: u64 = 0;
        for &port in &rule.ports {
            if port >= 64 {
                // The BPF side denies any port >= 64 because the bitmap
                // cannot express it. Accepting the rule here would present
                // as an allowlist entry that never takes effect.
                return Err(Error::Unsupported(format!(
                    "network rule {} lists port {port}: the v1 port bitmap only encodes \
                     ports 0-63, and the kernel side denies anything above that",
                    rule.cidr
                )));
            }
            ports |= 1u64 << port;
        }
        out.push((
            NetKey {
                prefixlen: NET_KEY_CGID_BITS + prefix,
                cgid: cgid.as_raw(),
                addr,
            },
            ports,
        ));
    }
    Ok(out)
}

/// Parse `a.b.c.d/N` into a network-byte-order address and prefix length.
fn parse_cidr(cidr: &str) -> Result<(u32, u32), Error> {
    let (addr_part, prefix_part) = match cidr.split_once('/') {
        Some((a, p)) => (a, p),
        None => (cidr, "32"),
    };
    let addr: std::net::Ipv4Addr = addr_part.parse().map_err(|_| {
        Error::PolicyInvalid(format!(
            "network rule {cidr:?}: {addr_part:?} is not an IPv4 address (IPv6 is denied \
             outright in v1 — see net.bpf.c)"
        ))
    })?;
    let prefix: u32 = prefix_part
        .parse()
        .map_err(|_| Error::PolicyInvalid(format!("network rule {cidr:?}: bad prefix length")))?;
    if prefix > 32 {
        return Err(Error::PolicyInvalid(format!(
            "network rule {cidr:?}: prefix length {prefix} exceeds 32"
        )));
    }
    // The trie matches address bits MSB-first, which for an IPv4 CIDR is
    // network byte order.
    Ok((u32::from(addr).to_be(), prefix))
}

/// The C-side `struct sandbox_ctx`.
///
/// MUST match `struct sandbox_ctx` in `aivisor-bpf/src/bpf/common.h`
/// field-for-field — this crosses the Rust/BPF boundary as raw bytes with
/// no serialization layer, so a mismatch silently corrupts whichever field
/// the two definitions disagree about. The layout is padding-free, which is
/// what makes the byte-for-byte encoding below exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SandboxCtx {
    pub sandbox_seq: u64,
    pub flags: u32,
    pub policy_gen: u32,
    pub fs_rules_base: u32,
    pub fs_rules_count: u32,
    pub exec_rules_base: u32,
    pub exec_rules_count: u32,
    pub net_rules_base: u32,
    pub net_rules_count: u32,
    pub turn_id: u64,
}

impl SandboxCtx {
    pub const FLAG_ENFORCING: u32 = 1;
    pub const FLAG_DIRTY: u32 = 2;
    pub const FLAG_KILL_PENDING: u32 = 4;

    pub const SIZE: usize = 48;

    /// The context a sandbox is registered with: empty rule ranges, and
    /// enforcement not yet switched on so the child can build its own
    /// mount namespace. See [`BpfManager::register_sandbox`].
    pub fn registered_for_setup() -> Self {
        Self {
            flags: 0,
            ..Self::deny_all()
        }
    }

    /// Empty rule ranges with enforcement on: denies everything the hooks
    /// gate, by construction rather than by convention.
    pub fn deny_all() -> Self {
        Self {
            sandbox_seq: 0,
            flags: Self::FLAG_ENFORCING,
            policy_gen: 0,
            fs_rules_base: 0,
            fs_rules_count: 0,
            exec_rules_base: 0,
            exec_rules_count: 0,
            net_rules_base: 0,
            net_rules_count: 0,
            turn_id: 0,
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0..8].copy_from_slice(&self.sandbox_seq.to_ne_bytes());
        b[8..12].copy_from_slice(&self.flags.to_ne_bytes());
        b[12..16].copy_from_slice(&self.policy_gen.to_ne_bytes());
        b[16..20].copy_from_slice(&self.fs_rules_base.to_ne_bytes());
        b[20..24].copy_from_slice(&self.fs_rules_count.to_ne_bytes());
        b[24..28].copy_from_slice(&self.exec_rules_base.to_ne_bytes());
        b[28..32].copy_from_slice(&self.exec_rules_count.to_ne_bytes());
        b[32..36].copy_from_slice(&self.net_rules_base.to_ne_bytes());
        b[36..40].copy_from_slice(&self.net_rules_count.to_ne_bytes());
        b[40..48].copy_from_slice(&self.turn_id.to_ne_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::SIZE {
            return None;
        }
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_ne_bytes([
                b[o],
                b[o + 1],
                b[o + 2],
                b[o + 3],
                b[o + 4],
                b[o + 5],
                b[o + 6],
                b[o + 7],
            ])
        };
        Some(Self {
            sandbox_seq: u64_at(0),
            flags: u32_at(8),
            policy_gen: u32_at(12),
            fs_rules_base: u32_at(16),
            fs_rules_count: u32_at(20),
            exec_rules_base: u32_at(24),
            exec_rules_count: u32_at(28),
            net_rules_base: u32_at(32),
            net_rules_count: u32_at(36),
            turn_id: u64_at(40),
        })
    }
}

/// Mirrors `struct fs_rule` in `common.h`.
struct FsRule {
    path_hash: u64,
    access_mask: u64,
}

impl FsRule {
    fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.path_hash.to_ne_bytes());
        b[8..16].copy_from_slice(&self.access_mask.to_ne_bytes());
        b
    }
}

/// Mirrors `struct exec_rule` in `common.h`.
struct ExecRule {
    dev: u64,
    inode: u64,
    hash: [u8; 32],
}

impl ExecRule {
    fn to_bytes(&self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0..8].copy_from_slice(&self.dev.to_ne_bytes());
        b[8..16].copy_from_slice(&self.inode.to_ne_bytes());
        b[16..48].copy_from_slice(&self.hash);
        b
    }
}

/// Mirrors the packed `struct net_key` in `common.h`: 4-byte prefix length,
/// then the matched data (cgroup id, then address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetKey {
    prefixlen: u32,
    cgid: u64,
    addr: u32,
}

impl NetKey {
    fn to_bytes(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.prefixlen.to_ne_bytes());
        b[4..12].copy_from_slice(&self.cgid.to_ne_bytes());
        b[12..16].copy_from_slice(&self.addr.to_ne_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_ctx_roundtrips_through_its_wire_bytes() {
        let ctx = SandboxCtx {
            sandbox_seq: 7,
            flags: SandboxCtx::FLAG_ENFORCING | SandboxCtx::FLAG_DIRTY,
            policy_gen: 3,
            fs_rules_base: 10,
            fs_rules_count: 2,
            exec_rules_base: 20,
            exec_rules_count: 4,
            net_rules_base: 0,
            net_rules_count: 1,
            turn_id: 99,
        };
        let bytes = ctx.to_bytes();
        assert_eq!(bytes.len(), SandboxCtx::SIZE);
        assert_eq!(SandboxCtx::from_bytes(&bytes), Some(ctx));
    }

    #[test]
    fn sandbox_ctx_size_matches_the_c_layout() {
        // 8 + 4*8 + 8, no padding. If this ever disagrees with
        // common.h the maps are silently mis-parsed.
        assert_eq!(std::mem::size_of::<SandboxCtx>(), SandboxCtx::SIZE);
    }

    #[test]
    fn deny_all_placeholder_has_empty_rule_ranges() {
        let ctx = SandboxCtx::deny_all();
        assert!(ctx.flags & SandboxCtx::FLAG_ENFORCING != 0);
        // An empty range can never contain a matching rule index, which is
        // what makes this deny-all by construction rather than by the
        // convention that index 0 happens to be unpopulated.
        assert_eq!(ctx.fs_rules_count, 0);
        assert_eq!(ctx.exec_rules_count, 0);
        assert_eq!(ctx.net_rules_count, 0);
    }

    #[test]
    fn allocator_hands_out_non_overlapping_ranges() {
        let mut alloc = RuleAllocator::new("test", 100);
        let a = alloc.alloc(10).unwrap();
        let b = alloc.alloc(5).unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 10);
    }

    #[test]
    fn allocator_reclaims_and_coalesces_released_ranges() {
        let mut alloc = RuleAllocator::new("test", 100);
        let a = alloc.alloc(10).unwrap();
        let b = alloc.alloc(10).unwrap();
        alloc.release(a, 10);
        alloc.release(b, 10);
        // Both halves must have merged back into one 20-wide hole,
        // otherwise a churning daemon fragments the map into slivers.
        assert_eq!(alloc.free, vec![(0, 100)]);
        assert_eq!(alloc.alloc(20).unwrap(), 0);
    }

    #[test]
    fn allocator_reuses_freed_space_instead_of_exhausting_the_map() {
        let mut alloc = RuleAllocator::new("test", 16);
        // Churn far past capacity: the old bump-pointer allocator failed
        // on the second cycle here.
        for _ in 0..1000 {
            let base = alloc.alloc(16).unwrap();
            alloc.release(base, 16);
        }
        assert_eq!(alloc.alloc(16).unwrap(), 0);
    }

    #[test]
    fn allocator_refuses_when_no_contiguous_range_is_left() {
        let mut alloc = RuleAllocator::new("test", 10);
        alloc.alloc(6).unwrap();
        assert!(alloc.alloc(6).is_err());
    }

    #[test]
    fn zero_length_allocation_reserves_nothing() {
        let mut alloc = RuleAllocator::new("test", 10);
        assert_eq!(alloc.alloc(0).unwrap(), 0);
        assert_eq!(alloc.free, vec![(0, 10)]);
    }

    #[test]
    fn rule_counts_over_the_unrolled_loop_bound_are_refused() {
        assert!(check_rule_count("filesystem", MAX_RULES_PER_SANDBOX).is_ok());
        let err = check_rule_count("filesystem", MAX_RULES_PER_SANDBOX + 1).unwrap_err();
        assert!(err.to_string().contains("silently unenforced"));
    }

    #[test]
    fn net_key_is_scoped_to_one_cgroup() {
        let a = resolve_net_rules(
            CgroupId::new(1),
            &[BpfNetRule {
                cidr: "10.0.0.1/32".into(),
                ports: vec![443],
            }],
        );
        // Port 443 is outside the v1 bitmap and must be refused rather
        // than installed as a rule that can never match.
        assert!(a.is_err());

        let a = resolve_net_rules(
            CgroupId::new(1),
            &[BpfNetRule {
                cidr: "10.0.0.1/32".into(),
                ports: vec![53],
            }],
        )
        .unwrap();
        let b = resolve_net_rules(
            CgroupId::new(2),
            &[BpfNetRule {
                cidr: "10.0.0.1/32".into(),
                ports: vec![53],
            }],
        )
        .unwrap();
        // Same destination, different sandbox: the keys must differ, or
        // one sandbox's allowlist entry would satisfy the other's lookup.
        assert_ne!(a[0].0, b[0].0);
        assert_eq!(a[0].0.prefixlen, NET_KEY_CGID_BITS + 32);
    }

    #[test]
    fn cidr_parses_to_network_byte_order() {
        let (addr, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(prefix, 8);
        assert_eq!(
            addr,
            u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0)).to_be()
        );
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("not-an-ip/8").is_err());
        assert!(parse_cidr("::1/128").is_err());
    }

    #[test]
    fn kernel_dev_encoding_differs_from_userspace_st_dev() {
        // major 253, minor 1 as glibc encodes it.
        let st_dev = nix::sys::stat::makedev(253, 1);
        assert_eq!(to_kernel_dev(st_dev), (253u64 << 20) | 1);
    }
}
