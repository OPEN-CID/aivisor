use std::collections::HashMap;
use std::sync::Mutex;

use aivisor_core::{CgroupId, Error};
use aivisor_policy::BpfPlan;

/// Userspace manager for BPF map entries.
/// Programs are global (loaded once by the daemon).
/// Per-sandbox state lives entirely in maps.
///
/// Honest limitation: this manager tracks rule-index bookkeeping correctly
/// (see `SandboxCtx`/rule range allocation below) but does not yet write
/// through to real BPF map file descriptors — that requires the loader
/// (`aivisor_bpf::loader`) to actually load and pin the compiled `.bpf.o`
/// objects via libbpf-rs, which is TODO(phase3) (see loader.rs). Until
/// then this is an in-memory simulation of the map contract, useful for
/// testing the allocation/index logic in isolation from a running kernel.
pub struct BpfManager {
    inner: Mutex<BpfManagerInner>,
}

struct BpfManagerInner {
    registered: HashMap<u64, SandboxBpfState>,
    policy_gen: u64,
    /// Simulates the fs_rules / exec_rules / net_rules maps' next free
    /// index — real map population (task: loader.rs) will replace this
    /// with the actual libbpf-rs map write + index bookkeeping, but the
    /// base/count contract callers see here already matches what the BPF
    /// programs expect (see common.h's `sandbox_ctx`).
    next_fs_rule_idx: u32,
    next_exec_rule_idx: u32,
    next_net_rule_idx: u32,
}

struct SandboxBpfState {
    #[allow(dead_code)]
    cgid: CgroupId,
    policy_gen: u64,
    fs_rules_base: u32,
    fs_rules_count: u32,
    exec_rules_base: u32,
    exec_rules_count: u32,
    net_rules_base: u32,
    net_rules_count: u32,
}

impl BpfManager {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            inner: Mutex::new(BpfManagerInner {
                registered: HashMap::new(),
                policy_gen: 0,
                next_fs_rule_idx: 0,
                next_exec_rule_idx: 0,
                next_net_rule_idx: 0,
            }),
        })
    }

    /// Register a sandbox: insert a deny-all placeholder BEFORE the child is unblocked.
    /// At this point the sandbox_ctx has FLAG_ENFORCING set but a zero-length rule
    /// range (base==0, count==0), meaning every check inside will deny — an empty
    /// range can never contain a matching rule index.
    pub fn register_sandbox(&self, cgid: CgroupId) -> Result<(), Error> {
        let mut inner = self.inner.lock().unwrap();
        inner.registered.insert(
            cgid.as_raw(),
            SandboxBpfState {
                cgid,
                policy_gen: inner.policy_gen,
                fs_rules_base: 0,
                fs_rules_count: 0,
                exec_rules_base: 0,
                exec_rules_count: 0,
                net_rules_base: 0,
                net_rules_count: 0,
            },
        );
        Ok(())
    }

    /// Update policy: allocate fresh rule-map index ranges for this
    /// sandbox's fs/exec/net rules, then atomically swap `sandbox_ctx`'s
    /// base/count fields to point at them. A concurrent BPF-side check
    /// sees either the old range or the new one, never a partial mix,
    /// because it reads `sandbox_ctx` once and the ranges themselves are
    /// only ever appended to, never mutated in place.
    pub fn update_policy(&self, cgid: CgroupId, plan: &BpfPlan) -> Result<(), Error> {
        let mut inner = self.inner.lock().unwrap();
        inner.policy_gen += 1;
        let policy_gen = inner.policy_gen;

        let fs_base = inner.next_fs_rule_idx;
        inner.next_fs_rule_idx += plan.fs_rules.len() as u32;
        let exec_base = inner.next_exec_rule_idx;
        inner.next_exec_rule_idx += plan.exec_rules.len() as u32;
        let net_base = inner.next_net_rule_idx;
        inner.next_net_rule_idx += plan.net_rules.len() as u32;

        if let Some(state) = inner.registered.get_mut(&cgid.as_raw()) {
            state.policy_gen = policy_gen;
            state.fs_rules_base = fs_base;
            state.fs_rules_count = plan.fs_rules.len() as u32;
            state.exec_rules_base = exec_base;
            state.exec_rules_count = plan.exec_rules.len() as u32;
            state.net_rules_base = net_base;
            state.net_rules_count = plan.net_rules.len() as u32;
        }

        Ok(())
    }

    /// Deregister a sandbox: delete map entries LAST, after the cgroup is confirmed empty.
    /// Must be called at teardown after cgroup.kill and wait.
    pub fn deregister_sandbox(&self, cgid: &CgroupId) -> Result<(), Error> {
        let mut inner = self.inner.lock().unwrap();
        inner.registered.remove(&cgid.as_raw());
        Ok(())
    }

    /// Subscriber interface for audit events.
    /// Returns events from the BPF ring buffer.
    pub fn subscribe_events(&self) -> Result<EventSubscription, Error> {
        Ok(EventSubscription {
            pending: Vec::new(),
        })
    }

    /// Turn dirty: check if the current turn is dirty.
    /// In a real implementation this reads the BPF map's dirty flag.
    pub fn is_turn_dirty(&self, cgid: &CgroupId) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.registered.contains_key(&cgid.as_raw())
    }
}

pub struct EventSubscription {
    pending: Vec<Vec<u8>>,
}

impl EventSubscription {
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.pending)
    }
}

/// The c-side sandbox context struct.
/// MUST match `struct sandbox_ctx` in aivisor-bpf/src/bpf/common.h
/// field-for-field — this is read/written directly across the Rust/BPF FFI
/// boundary with no serialization layer, so a mismatch here silently
/// corrupts whichever field the two definitions disagree about.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_deregister() {
        let mgr = BpfManager::new().unwrap();
        let cgid = CgroupId::new(42);
        mgr.register_sandbox(cgid).unwrap();
        assert!(mgr.is_turn_dirty(&cgid));
        mgr.deregister_sandbox(&cgid).unwrap();
    }

    #[test]
    fn test_deny_all_placeholder_has_empty_rule_ranges() {
        let ctx = SandboxCtx::deny_all();
        assert!(ctx.flags & SandboxCtx::FLAG_ENFORCING != 0);
        // An empty range (count == 0) can never contain a matching rule
        // index, which is what makes this placeholder deny-all — the
        // previous single-index shape's "0 == deny-all" was only true by
        // convention (index 0 happening to be unpopulated), not by
        // construction.
        assert_eq!(ctx.fs_rules_count, 0);
        assert_eq!(ctx.exec_rules_count, 0);
        assert_eq!(ctx.net_rules_count, 0);
    }

    #[test]
    fn test_update_policy_allocates_non_overlapping_ranges() {
        let mgr = BpfManager::new().unwrap();
        let cgid_a = CgroupId::new(1);
        let cgid_b = CgroupId::new(2);
        mgr.register_sandbox(cgid_a).unwrap();
        mgr.register_sandbox(cgid_b).unwrap();

        let plan_a = BpfPlan {
            fs_rules: vec![
                aivisor_policy::BpfFsRule { path_hash: 1, access_mask: 1 },
                aivisor_policy::BpfFsRule { path_hash: 2, access_mask: 1 },
            ],
            exec_rules: vec![],
            net_rules: vec![],
            exec_policy_present: false,
            block_metadata: true,
        };
        let plan_b = BpfPlan {
            fs_rules: vec![aivisor_policy::BpfFsRule { path_hash: 3, access_mask: 1 }],
            exec_rules: vec![],
            net_rules: vec![],
            exec_policy_present: false,
            block_metadata: true,
        };

        mgr.update_policy(cgid_a, &plan_a).unwrap();
        mgr.update_policy(cgid_b, &plan_b).unwrap();

        let inner = mgr.inner.lock().unwrap();
        let state_a = &inner.registered[&cgid_a.as_raw()];
        let state_b = &inner.registered[&cgid_b.as_raw()];
        assert_eq!(state_a.fs_rules_base, 0);
        assert_eq!(state_a.fs_rules_count, 2);
        // b's range must not overlap a's.
        assert_eq!(state_b.fs_rules_base, 2);
        assert_eq!(state_b.fs_rules_count, 1);
    }
}
