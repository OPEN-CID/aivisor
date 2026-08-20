//! Privileged integration test for the BPF map contract (T3.1).
//!
//! Everything here runs against the real kernel: the programs are loaded
//! (which is also the only way to know the verifier accepts them), the maps
//! are the pinned ones the programs actually read, and the assertions are
//! about bytes the kernel stored rather than about userspace bookkeeping.
//!
//! Safety of running this on a live machine: every sandbox id used below is
//! synthetic and far outside the range the kernel assigns to real cgroups,
//! so no process on the host can ever match one of these map entries. That
//! matters because the entries are deny-all — registering a cgroup id that
//! did belong to a running cgroup would start denying its syscalls for the
//! lifetime of the test.
//!
//! This is deliberately one `#[test]`, not several. `libbpf_rs::Object` is
//! `!Send`, so a loaded program set cannot live in a shared static, and a
//! per-test load would give each test its own [`BpfManager`] — each with
//! its own rule-index allocator handing out overlapping ranges in the same
//! shared map, plus a redundant second attachment of every LSM hook. One
//! load, one manager, phases in order.

#![cfg(feature = "privileged-tests")]

use aivisor_bpf::{BpfLoader, BpfManager, ExecSource, SandboxCtx, MAX_RULES_PER_SANDBOX};
use aivisor_core::CgroupId;
use aivisor_policy::{BpfExecRule, BpfFsRule, BpfNetRule, BpfPlan};

/// Synthetic cgroup ids. Real cgroup ids are kernfs inode numbers, which
/// count up from small values; the top of the u64 range is unreachable.
const SANDBOX_A: u64 = 0xFFFF_FFF0_0000_0001;
const SANDBOX_B: u64 = 0xFFFF_FFF0_0000_0002;
const SANDBOX_C: u64 = 0xFFFF_FFF0_0000_0003;

fn plan(fs: Vec<BpfFsRule>, exec: Vec<BpfExecRule>, net: Vec<BpfNetRule>) -> BpfPlan {
    BpfPlan {
        exec_policy_present: !exec.is_empty(),
        fs_rules: fs,
        exec_rules: exec,
        net_rules: net,
        block_metadata: true,
    }
}

fn fs_rules(n: u32) -> Vec<BpfFsRule> {
    (0..n)
        .map(|i| BpfFsRule {
            path_hash: u64::from(i) + 0x1000,
            access_mask: 4,
        })
        .collect()
}

#[test]
fn bpf_map_contract() {
    let programs = BpfLoader::load_and_attach().expect("load and attach BPF programs");
    let m = BpfManager::new().expect("open pinned maps");

    all_objects_share_one_set_of_maps(&programs);
    registration_installs_deny_all(&m);
    policy_install_writes_through(&m);
    oversized_policy_is_refused(&m);
    unrepresentable_port_is_refused(&m);
    lifecycles_do_not_exhaust_the_rule_maps(&m);
    host_processes_are_untouched(&m);
}

/// If this fails, nothing else in this file is meaningful: userspace would
/// be writing policy into a map that four of the five program sets never
/// read, and those four would enforce nothing.
fn all_objects_share_one_set_of_maps(programs: &aivisor_bpf::LoadedPrograms) {
    for map in ["sandboxes", "fs_rules", "exec_rules", "net_rules", "events"] {
        let ids = programs.map_ids(map).expect("map ids");
        assert!(
            !ids.is_empty(),
            "no loaded object declares a map called {map}"
        );
        assert!(
            ids.windows(2).all(|w| w[0] == w[1]),
            "map {map} was not shared across objects: kernel ids {ids:?} — each differing \
             id is a program enforcing against its own permanently empty copy"
        );
    }
}

fn registration_installs_deny_all(m: &BpfManager) {
    let a = CgroupId::new(SANDBOX_A);
    m.register_sandbox(a).expect("register a");

    let ctx = m.read_ctx(a).expect("read ctx a");
    // Registration does not enforce yet — the child still has to build its
    // own mount namespace, which lsm/sb_mount would deny. Enforcement is
    // switched on by update_policy, before the child can execve. What
    // registration guarantees is that the rule ranges are empty, so
    // enforcement means deny-all the instant it is enabled.
    assert_eq!(
        ctx.flags & SandboxCtx::FLAG_ENFORCING,
        0,
        "registration must leave the sandbox in the non-enforcing setup state"
    );
    assert_eq!(
        (
            ctx.fs_rules_count,
            ctx.exec_rules_count,
            ctx.net_rules_count
        ),
        (0, 0, 0),
        "a freshly registered sandbox must have empty rule ranges (deny-all)"
    );

    // Double registration is refused rather than silently re-pointing an
    // already-running sandbox at a fresh deny-all context.
    assert!(m.register_sandbox(a).is_err());

    m.deregister_sandbox(&a).expect("deregister a");
    assert!(
        m.read_ctx(a).is_err(),
        "the sandbox_ctx must be gone after deregistration"
    );
    // Idempotent, so teardown after a partial launch does not fail.
    m.deregister_sandbox(&a)
        .expect("second deregister is a no-op");
}

fn policy_install_writes_through(m: &BpfManager) {
    let a = CgroupId::new(SANDBOX_A);
    let b = CgroupId::new(SANDBOX_B);

    // Installing policy for a sandbox that was never registered must fail
    // loudly. Silently succeeding would mean "policy installed" with no map
    // entry and no enforcement anywhere.
    assert!(m.update_policy(b, &plan(vec![], vec![], vec![]), ExecSource::HostPaths).is_err());

    m.register_sandbox(a).expect("register a");
    m.register_sandbox(b).expect("register b");

    let p = plan(
        fs_rules(2),
        vec![BpfExecRule {
            path: "/bin/true".into(),
            is_prefix: false,
            hash: None,
        }],
        vec![BpfNetRule {
            cidr: "10.1.2.3/32".into(),
            ports: vec![53],
        }],
    );
    m.update_policy(a, &p, ExecSource::HostPaths).expect("install policy on a");

    let ctx_a = m.read_ctx(a).expect("read ctx a after install");
    assert_eq!(ctx_a.fs_rules_count, 2);
    assert_eq!(ctx_a.exec_rules_count, 1);
    assert_eq!(ctx_a.net_rules_count, 1);
    assert!(
        ctx_a.policy_gen > 0,
        "policy generation must advance on install"
    );
    assert!(
        ctx_a.flags & SandboxCtx::FLAG_ENFORCING != 0,
        "installing policy must switch enforcement on"
    );

    // A second sandbox must get a disjoint rule range.
    m.update_policy(b, &p, ExecSource::HostPaths).expect("install policy on b");
    let ctx_b = m.read_ctx(b).expect("read ctx b");
    let a_range = ctx_a.fs_rules_base..ctx_a.fs_rules_base + ctx_a.fs_rules_count;
    let b_range = ctx_b.fs_rules_base..ctx_b.fs_rules_base + ctx_b.fs_rules_count;
    assert!(
        a_range.end <= b_range.start || b_range.end <= a_range.start,
        "rule ranges overlap: {a_range:?} vs {b_range:?} — one sandbox would enforce the \
         other's rules"
    );

    // Reinstalling must advance the generation.
    let gen_before = m.read_ctx(a).unwrap().policy_gen;
    m.update_policy(a, &p, ExecSource::HostPaths).expect("reinstall policy on a");
    assert!(
        m.read_ctx(a).unwrap().policy_gen > gen_before,
        "reinstall must advance the policy generation"
    );

    m.deregister_sandbox(&a).expect("deregister a");
    m.deregister_sandbox(&b).expect("deregister b");
}

/// A policy longer than the hook's unrolled loop must be refused, not
/// installed with a silently unenforced tail.
fn oversized_policy_is_refused(m: &BpfManager) {
    let cgid = CgroupId::new(SANDBOX_C);
    m.register_sandbox(cgid).expect("register");

    let too_many = plan(fs_rules(MAX_RULES_PER_SANDBOX + 1), vec![], vec![]);
    let err = m.update_policy(cgid, &too_many, ExecSource::HostPaths).unwrap_err().to_string();
    assert!(
        err.contains("silently unenforced"),
        "unexpected error: {err}"
    );

    // A rejected install must leave the live context untouched.
    let ctx = m.read_ctx(cgid).expect("ctx survives a rejected install");
    assert_eq!(ctx.fs_rules_count, 0);

    m.deregister_sandbox(&cgid).unwrap();
}

/// Ports outside the v1 bitmap must be rejected at install time rather than
/// accepted as an allowlist entry the kernel side can only ever deny.
fn unrepresentable_port_is_refused(m: &BpfManager) {
    let cgid = CgroupId::new(SANDBOX_C);
    m.register_sandbox(cgid).expect("register");

    let p = plan(
        vec![],
        vec![],
        vec![BpfNetRule {
            cidr: "10.0.0.1/32".into(),
            ports: vec![443],
        }],
    );
    assert!(m.update_policy(cgid, &p, ExecSource::HostPaths).is_err());

    m.deregister_sandbox(&cgid).unwrap();
}

/// The rule maps must not leak index space across create/destroy cycles.
/// With the old bump-pointer allocator this exhausted `fs_rules` and every
/// later policy install failed outright.
fn lifecycles_do_not_exhaust_the_rule_maps(m: &BpfManager) {
    let cgid = CgroupId::new(SANDBOX_C);
    let p = plan(fs_rules(MAX_RULES_PER_SANDBOX), vec![], vec![]);

    // 65536 / 64 = 1024 cycles is where the map would run dry without
    // reclamation, so go well past it.
    for i in 0..2000 {
        m.register_sandbox(cgid)
            .unwrap_or_else(|e| panic!("register on cycle {i}: {e}"));
        m.update_policy(cgid, &p, ExecSource::HostPaths)
            .unwrap_or_else(|e| panic!("install on cycle {i}: {e}"));
        m.deregister_sandbox(&cgid)
            .unwrap_or_else(|e| panic!("deregister on cycle {i}: {e}"));
    }
}

/// Host processes must be completely unaffected while the programs are
/// attached. The whole design rests on the `if (!ctx) return 0;` guard, so
/// it is checked rather than assumed.
fn host_processes_are_untouched(m: &BpfManager) {
    // Hold a registered deny-all sandbox open, so any leakage of
    // enforcement onto non-sandbox processes is maximally visible.
    let cgid = CgroupId::new(SANDBOX_C);
    m.register_sandbox(cgid).expect("register");

    let contents = std::fs::read("/etc/hostname").expect("host file open must still work");
    assert!(!contents.is_empty());

    let status = std::process::Command::new("/bin/true")
        .status()
        .expect("host exec must still work");
    assert!(status.success(), "host exec was denied");

    // A loopback connect exercises the socket hooks. Nothing need be
    // listening: the hook runs before the stack refuses, so ECONNREFUSED
    // means the hook let it through.
    if let Err(e) = std::net::TcpStream::connect("127.0.0.1:9") {
        assert_ne!(
            e.kind(),
            std::io::ErrorKind::PermissionDenied,
            "host connect was denied by an aivisor hook"
        );
    }

    m.deregister_sandbox(&cgid).unwrap();
}
