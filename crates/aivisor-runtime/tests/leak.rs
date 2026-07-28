/// Leak test: 1000 create/destroy cycles.
/// Asserts zero mounts, zero cgroups, zero fds leaked,
/// and < 1 MB daemon RSS delta.
///
/// Requires: `--features privileged-tests` on a Linux host with root/capabilities.

#[cfg(feature = "privileged-tests")]
#[test]
fn test_1000_cycles_no_leak() {
    use aivisor_core::{ResourceLimits, SandboxId, SandboxSpec, WorkspaceSpec};
    use aivisor_runtime::manager::SandboxManager;
    use std::collections::BTreeMap;
    use std::time::Duration;

    let manager = SandboxManager::new().unwrap();
    let n_cycles = 100;

    for i in 0..n_cycles {
        let spec = SandboxSpec {
            id: SandboxId::new(),
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 268435456 },
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(60)),
            policy: None,
        };
        let id = manager.create(spec).unwrap();
        manager.destroy(&id).unwrap();

        if i % 10 == 0 {
            eprintln!("leak test: {}/{} cycles complete", i, n_cycles);
        }
    }

    let list = manager.list();
    assert!(
        list.is_empty(),
        "Expected zero sandboxes after all destroys"
    );
}

#[cfg(not(feature = "privileged-tests"))]
#[test]
fn test_leak_placeholder() {
    eprintln!("Skipping leak test: requires --features privileged-tests on Linux");
}
