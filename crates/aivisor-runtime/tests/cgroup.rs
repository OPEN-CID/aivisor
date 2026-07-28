/// cgroup enforcement tests.
/// Requires: `--features privileged-tests` on Linux.

#[cfg(feature = "privileged-tests")]
#[test]
fn test_cgroup_create_destroy() {
    use aivisor_core::{ResourceLimits, SandboxId};
    use aivisor_runtime::cgroup::Cgroup;
    use std::path::Path;

    let root = Path::new("/sys/fs/cgroup");
    let id = SandboxId::new();

    let cg = Cgroup::create(root, &id).unwrap();
    let limits = ResourceLimits::default();
    cg.apply(&limits).unwrap();

    let stats = cg.stats().unwrap();
    eprintln!("Cgroup stats: {:?}", stats);

    cg.destroy().unwrap();
}

#[cfg(not(feature = "privileged-tests"))]
#[test]
fn test_cgroup_placeholder() {
    eprintln!("Skipping cgroup test: requires --features privileged-tests on Linux");
}
