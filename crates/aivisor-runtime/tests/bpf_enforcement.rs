//! End-to-end BPF LSM enforcement against real sandboxes (T3.2).
//!
//! These tests exist to prove layer 5 specifically, not confinement in
//! general. Landlock (layer 3) would deny most of the same things, so a
//! bare "the sandbox could not run it" result proves nothing about the BPF
//! programs. Every case below is therefore constructed so that **Landlock
//! permits the operation** — the binaries live under a directory the policy
//! grants EXECUTE on — and only the exec allowlist in the BPF map separates
//! the allowed case from the denied one.
//!
//! Exit-code convention: a child whose confinement setup fails (including a
//! refused `execve`) exits 127 without running anything, so 127 means
//! "never started" and any other code came from the program itself.

#![cfg(feature = "privileged-tests")]

use std::collections::BTreeMap;
use std::time::Duration;

use aivisor_core::{PolicyRef, ResourceLimits, SandboxId, SandboxSpec, WorkspaceSpec};
use aivisor_policy::{AccessDefault, ExecPolicy, ExecRule, FsPolicy, FsRule, NetPolicy, Policy};
use aivisor_runtime::SandboxManager;

use aivisor_runtime::launcher::CHILD_SETUP_FAILED_EXIT as CHILD_SETUP_FAILED;

const BUSYBOX: &str = "/var/lib/aivisor/templates/base/bin/busybox";

/// Build a policy that grants Landlock read+execute across `/workspace`
/// but allows only `exec_allow` through the BPF exec hook.
fn policy_allowing_exec(exec_allow: &[&str]) -> Policy {
    Policy {
        api_version: "aivisor/v1".into(),
        kind: "SandboxPolicy".into(),
        metadata_name: "bpf-enforcement-test".into(),
        filesystem: Some(FsPolicy {
            default: AccessDefault::Deny,
            rules: vec![
                FsRule {
                    path: "/workspace".into(),
                    access: vec![
                        "read".into(),
                        "write".into(),
                        "create".into(),
                        "execute".into(),
                    ],
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
            ],
        }),
        exec: Some(ExecPolicy {
            default: AccessDefault::Deny,
            allow: exec_allow
                .iter()
                .map(|p| ExecRule::Path {
                    path: (*p).to_string(),
                    pin: None,
                })
                .collect(),
        }),
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

fn spec_with_policy(name: &str) -> SandboxSpec {
    SandboxSpec {
        id: SandboxId::new(),
        template: "base".into(),
        limits: ResourceLimits::default(),
        workspace: WorkspaceSpec::Tmpfs { size: 268_435_456 },
        env: BTreeMap::new(),
        timeout: Some(Duration::from_secs(60)),
        policy: Some(PolicyRef {
            name: name.to_string(),
            overrides: None,
        }),
    }
}

/// Stage two *separate copies* of busybox into the sandbox workspace.
///
/// Copies, not symlinks, and this matters: every applet in the base image
/// is a symlink to the one busybox binary, so they all share a single
/// inode. The exec hook matches `(dev, inode)`, so it cannot tell
/// `/bin/sh` from `/bin/cat` in that image — allowing one allows them all.
/// Two independent copies are what gives the test two distinct inodes to
/// distinguish, and the limitation itself is documented on the exec hook.
fn stage_binaries(manager: &SandboxManager, id: &SandboxId) -> (String, String) {
    let dir = manager.workspace_upper_dir(id).expect("workspace dir");
    std::fs::create_dir_all(&dir).expect("create workspace dir");

    // Named for the busybox applets they will dispatch to, since busybox
    // selects behaviour from argv[0].
    let allowed = dir.join("sh");
    let denied = dir.join("true");
    std::fs::copy(BUSYBOX, &allowed).expect("copy busybox -> sh");
    std::fs::copy(BUSYBOX, &denied).expect("copy busybox -> true");

    ("/workspace/sh".to_string(), "/workspace/true".to_string())
}

#[test]
fn exec_allowlist_is_enforced_in_kernel() {
    let manager = SandboxManager::new().expect("manager");

    // Only /workspace/sh is allowed to exec. /workspace/true is a
    // different inode in the same Landlock-permitted directory.
    manager.register_policy("only-sh".into(), policy_allowing_exec(&["/workspace/sh"]));

    let id = manager.create(spec_with_policy("only-sh")).expect("create");
    let (allowed, denied) = stage_binaries(&manager, &id);

    // The allowlisted binary runs. If the exec identities were resolved on
    // the host instead of inside the sandbox, the (dev, inode) pair would
    // not match the overlay's and this would be denied — so this assertion
    // is what proves the in-sandbox identity plumbing works at all.
    let code = manager
        .exec(&id, &allowed, &["-c".into(), "exit 42".into()])
        .expect("exec allowed binary");
    assert_eq!(
        code, 42,
        "the allowlisted binary should have run and exited 42, got {code} \
         (127 means it never started)"
    );

    // The non-allowlisted binary is refused, even though Landlock grants
    // EXECUTE on the directory holding it. The refusal surfaces as the
    // child's own report of the failed execve, not a bare exit code.
    let err = manager
        .exec(&id, &denied, &[])
        .expect_err("a binary outside the exec allowlist must be refused")
        .to_string();
    assert!(
        err.contains("execve") && err.contains("Operation not permitted"),
        "expected an EPERM from the exec hook, got: {err}"
    );

    manager.destroy(&id).expect("destroy");
}

/// The same binary that was refused above must run once policy allows it —
/// otherwise the previous test would also pass if exec were simply broken.
#[test]
fn the_denied_binary_runs_when_policy_allows_it() {
    let manager = SandboxManager::new().expect("manager");
    manager.register_policy(
        "both".into(),
        policy_allowing_exec(&["/workspace/sh", "/workspace/true"]),
    );

    let id = manager.create(spec_with_policy("both")).expect("create");
    let (_allowed, denied) = stage_binaries(&manager, &id);

    let code = manager.exec(&id, &denied, &[]).expect("exec now-allowed");
    assert_ne!(
        code, CHILD_SETUP_FAILED,
        "the binary is on the allowlist now and should have started"
    );
    // busybox dispatches on argv[0]; as `true` it exits 0.
    assert_eq!(code, 0, "busybox `true` applet should exit 0");

    manager.destroy(&id).expect("destroy");
}

/// Teardown must remove the sandbox from the BPF maps, and only after the
/// cgroup is empty. A leaked entry would make the next sandbox that
/// happens to reuse the cgroup id fail to register.
#[test]
fn teardown_releases_the_bpf_context() {
    let manager = SandboxManager::new().expect("manager");
    manager.register_policy("only-sh".into(), policy_allowing_exec(&["/workspace/sh"]));

    for _ in 0..3 {
        let id = manager.create(spec_with_policy("only-sh")).expect("create");
        manager.destroy(&id).expect("destroy");
    }
}
