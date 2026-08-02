//! Leak test: 1000 sandbox create/destroy cycles must reclaim everything.
//!
//! blueprint.md §"Phase 1 exit criteria" (table row 1) and roadmap.md's phase-1
//! acceptance list both state the same bar: *"1000 cycles leak zero
//! mounts/cgroups/fds"*. This file measures each of those four quantities
//! before and after the churn loop and asserts the delta, rather than asserting
//! only that `manager.list()` came back empty — an empty in-memory map proves
//! the manager forgot about the sandboxes, not that the kernel objects behind
//! them were released, which is exactly the leak this test exists to catch.
//!
//! Requires: `--features privileged-tests` on a Linux host with root/
//! capabilities. Without the feature this file compiles to nothing —
//! deliberately, rather than to a test that prints "skipping" and reports
//! green, which would make an un-run gate look like a passing one.

#[cfg(feature = "privileged-tests")]
mod leak_tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::time::Duration;

    use aivisor_core::{ResourceLimits, SandboxId, SandboxSpec, WorkspaceSpec};
    use aivisor_runtime::manager::SandboxManager;

    /// The count blueprint.md's phase-1 exit criteria names. Kept as a
    /// constant so the test name, the doc comment and the loop cannot drift
    /// apart the way they previously had (the test was named
    /// `test_1000_cycles_no_leak` while actually running 100).
    const N_CYCLES: usize = 1000;

    /// Open file descriptors held by this process. A sandbox that leaks a
    /// cgroup dirfd, a pidfd, or a mount fd shows up here.
    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .count()
    }

    /// Mount entries in this process's mount namespace. Reclaim must unmount
    /// every overlay/tmpfs the sandbox created.
    fn mount_count() -> usize {
        std::fs::read_to_string("/proc/self/mountinfo")
            .expect("read /proc/self/mountinfo")
            .lines()
            .count()
    }

    /// Sandbox cgroup directories left under the aivisor cgroup root. Absent
    /// root directory counts as zero: nothing has been created yet.
    fn cgroup_count() -> usize {
        let root = Path::new("/sys/fs/cgroup/aivisor");
        match std::fs::read_dir(root) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .count(),
            Err(_) => 0,
        }
    }

    /// Resident set size in bytes, from field 2 (resident pages) of
    /// /proc/self/statm.
    fn rss_bytes() -> u64 {
        let statm = std::fs::read_to_string("/proc/self/statm").expect("read /proc/self/statm");
        let pages: u64 = statm
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("resident pages field in /proc/self/statm");
        // SAFETY: sysconf(_SC_PAGESIZE) takes no pointers and cannot fail for
        // this name; it is the documented way to read the page size.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        pages * page_size
    }

    fn spec() -> SandboxSpec {
        SandboxSpec {
            id: SandboxId::new(),
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 268_435_456 },
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(60)),
            policy: None,
        }
    }

    #[test]
    fn test_1000_cycles_no_leak() {
        let manager = SandboxManager::new().expect("SandboxManager::new");

        // One warm-up cycle before the baseline: the first create/destroy
        // pair legitimately allocates one-off state (the /sys/fs/cgroup/aivisor
        // root, lazily-initialised allocator arenas, the template lookup
        // cache). Counting that against the leak budget would make the test
        // fail for a non-leak.
        let warmup = manager.create(spec()).expect("warm-up create");
        manager.destroy(&warmup).expect("warm-up destroy");

        let fds_before = open_fds();
        let mounts_before = mount_count();
        let cgroups_before = cgroup_count();
        let rss_before = rss_bytes();

        for i in 0..N_CYCLES {
            let id = manager.create(spec()).expect("create");
            manager.destroy(&id).expect("destroy");

            if i % 100 == 0 {
                eprintln!("leak test: {i}/{N_CYCLES} cycles complete");
            }
        }

        let fds_after = open_fds();
        let mounts_after = mount_count();
        let cgroups_after = cgroup_count();
        let rss_after = rss_bytes();

        assert!(
            manager.list().is_empty(),
            "manager still tracks sandboxes after all destroys"
        );
        assert_eq!(
            fds_after,
            fds_before,
            "leaked {} file descriptor(s) over {N_CYCLES} cycles",
            fds_after as i64 - fds_before as i64
        );
        assert_eq!(
            mounts_after,
            mounts_before,
            "leaked {} mount(s) over {N_CYCLES} cycles",
            mounts_after as i64 - mounts_before as i64
        );
        assert_eq!(
            cgroups_after,
            cgroups_before,
            "leaked {} cgroup(s) over {N_CYCLES} cycles",
            cgroups_after as i64 - cgroups_before as i64
        );

        // RSS is the one budgeted (rather than zero-delta) quantity: the
        // allocator is free to hold on to freed arenas, so a strict equality
        // here would be a flake, not a leak detector. 1 MiB over 1000 cycles
        // is ~1 KiB per cycle — far below what a per-sandbox structure that
        // is never freed would cost.
        let rss_delta = rss_after.saturating_sub(rss_before);
        assert!(
            rss_delta < 1024 * 1024,
            "RSS grew {rss_delta} bytes over {N_CYCLES} cycles (budget: 1 MiB)"
        );
    }
}
