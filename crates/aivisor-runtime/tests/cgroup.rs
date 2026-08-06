//! cgroup enforcement tests.
//!
//! Requires: `--features privileged-tests` on a Linux host with cgroup v2
//! mounted at /sys/fs/cgroup and write access to it. Without the feature this
//! file compiles to nothing — deliberately, rather than to a test that prints
//! "skipping" and reports green, which would make an un-run gate look like a
//! passing one in the CI summary.

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
    eprintln!("Cgroup stats: {stats:?}");

    cg.destroy().unwrap();

    // destroy() must actually remove the cgroup directory, not just drop the
    // handle — a leaked cgroup directory keeps its controllers charged and
    // eventually exhausts the parent's cgroup.max.descendants.
    assert!(
        !root.join("aivisor").join(id.to_string()).exists(),
        "cgroup directory still present after destroy()"
    );
}
