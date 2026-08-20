//! Privileged test that the network LSM hooks actually deny egress.
//!
//! The base sandbox image is busybox-only and has no network applets, so
//! there is nothing inside a real sandbox that can attempt a connection.
//! Instead this drives the hooks directly: a child process is placed into a
//! registered, enforcing cgroup and then tries to connect. That is exactly
//! the condition the hooks key on (`bpf_get_current_cgroup_id()`), so it
//! exercises the real decision path rather than a stand-in for it.
//!
//! A child, not the test process itself: everything in an enforcing cgroup
//! is subject to the whole hook set, and `lsm/bpf` denies the `bpf(2)` calls
//! this harness needs to clean up afterwards.
//!
//! Deny and allow are both asserted. A test that only checked the denial
//! would pass just as well if connections were failing for some unrelated
//! reason.

#![cfg(feature = "privileged-tests")]

use std::io::Write;
use std::path::{Path, PathBuf};

use aivisor_bpf::{BpfLoader, BpfManager, ExecSource};
use aivisor_core::CgroupId;
use aivisor_policy::{BpfNetRule, BpfPlan};

/// Nothing listens here, so an allowed connection fails with
/// ECONNREFUSED — which is the point: the hook let it reach the stack.
/// Port 9 (discard) is below 64, the range the v1 port bitmap can express.
const TARGET: &str = "127.0.0.1:9";
const TARGET_CIDR: &str = "127.0.0.1/32";
const TARGET_PORT: u16 = 9;

const EXIT_ALLOWED: i32 = 0;
const EXIT_DENIED: i32 = 1;
const EXIT_OTHER: i32 = 2;

fn net_plan(rules: Vec<BpfNetRule>) -> BpfPlan {
    BpfPlan {
        fs_rules: vec![],
        exec_rules: vec![],
        net_rules: rules,
        exec_policy_present: false,
        block_metadata: true,
    }
}

/// A scratch cgroup, removed on drop.
struct TestCgroup {
    path: PathBuf,
    id: CgroupId,
}

impl TestCgroup {
    fn create() -> Self {
        let path = PathBuf::from(format!(
            "/sys/fs/cgroup/aivisor-nettest-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir(&path);
        std::fs::create_dir(&path).expect("create test cgroup");
        // A cgroup's id is its kernfs inode number — the same value
        // bpf_get_current_cgroup_id() returns.
        let meta = std::fs::metadata(&path).expect("stat cgroup");
        let id = CgroupId::new(std::os::unix::fs::MetadataExt::ino(&meta));
        Self { path, id }
    }
}

impl Drop for TestCgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Run a connection attempt inside `cgroup`, in a child process, and return
/// its exit code.
fn connect_from_cgroup(cgroup: &Path) -> i32 {
    // SAFETY: the child does no allocation-sensitive work beyond a file
    // write and a connect, and leaves via _exit without unwinding or
    // running atexit handlers inherited from the test harness.
    match unsafe { nix::unistd::fork() }.expect("fork") {
        nix::unistd::ForkResult::Child => {
            let code = (|| -> i32 {
                let procs = cgroup.join("cgroup.procs");
                let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&procs) else {
                    return EXIT_OTHER;
                };
                if write!(f, "{}", std::process::id()).is_err() {
                    return EXIT_OTHER;
                }
                drop(f);

                match std::net::TcpStream::connect(TARGET) {
                    Ok(_) => EXIT_ALLOWED,
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => EXIT_DENIED,
                    // Refused means the hook allowed it through and the
                    // stack answered — nothing is listening on port 9.
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => EXIT_ALLOWED,
                    Err(_) => EXIT_OTHER,
                }
            })();
            unsafe { libc::_exit(code) };
        }
        nix::unistd::ForkResult::Parent { child } => {
            match nix::sys::wait::waitpid(child, None).expect("waitpid") {
                nix::sys::wait::WaitStatus::Exited(_, code) => code,
                other => panic!("child did not exit normally: {other:?}"),
            }
        }
    }
}

#[test]
fn egress_is_denied_by_default_and_allowed_by_policy() {
    let _programs = BpfLoader::load_and_attach().expect("load and attach BPF programs");
    let m = BpfManager::new().expect("open pinned maps");

    let cgroup = TestCgroup::create();
    m.register_sandbox(cgroup.id).expect("register");

    // ---- deny by default ----
    //
    // An enforcing sandbox with no network rules at all. Every field of the
    // decision is empty, so the only correct answer is EPERM.
    m.update_policy(cgroup.id, &net_plan(vec![]), ExecSource::Resolved(&[]))
        .expect("install deny-all policy");

    let code = connect_from_cgroup(&cgroup.path);
    assert_eq!(
        code, EXIT_DENIED,
        "a sandbox with no egress rules must be denied by the network hook \
         (exit {code}: {EXIT_ALLOWED}=allowed, {EXIT_DENIED}=EPERM, {EXIT_OTHER}=other)"
    );

    // ---- allowed by policy ----
    //
    // The same destination, now covered by a rule. If this also came back
    // denied, the assertion above would prove nothing about policy.
    m.update_policy(
        cgroup.id,
        &net_plan(vec![BpfNetRule {
            cidr: TARGET_CIDR.into(),
            ports: vec![TARGET_PORT],
        }]),
        ExecSource::Resolved(&[]),
    )
    .expect("install allow policy");

    let code = connect_from_cgroup(&cgroup.path);
    assert_eq!(
        code, EXIT_ALLOWED,
        "a destination the policy allows must reach the network stack \
         (exit {code}: {EXIT_ALLOWED}=allowed, {EXIT_DENIED}=EPERM, {EXIT_OTHER}=other)"
    );

    // ---- one sandbox's rule must not satisfy another's lookup ----
    //
    // The net_rules LPM key carries the cgroup id in its matched prefix
    // precisely so this cannot happen. Before that, net_rules was a single
    // global allowlist and this second cgroup would have been allowed
    // through on the rule installed above.
    let other = TestCgroup::create2();
    m.register_sandbox(other.id).expect("register other");
    m.update_policy(other.id, &net_plan(vec![]), ExecSource::Resolved(&[]))
        .expect("install deny-all on other");

    let code = connect_from_cgroup(&other.path);
    assert_eq!(
        code, EXIT_DENIED,
        "a second sandbox with no rules of its own must still be denied, even though \
         another sandbox allows this exact destination (exit {code})"
    );

    m.deregister_sandbox(&other.id).expect("deregister other");
    m.deregister_sandbox(&cgroup.id).expect("deregister");
}

impl TestCgroup {
    /// A second scratch cgroup, distinct from [`TestCgroup::create`].
    fn create2() -> Self {
        let path = PathBuf::from(format!(
            "/sys/fs/cgroup/aivisor-nettest2-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir(&path);
        std::fs::create_dir(&path).expect("create second test cgroup");
        let meta = std::fs::metadata(&path).expect("stat cgroup");
        let id = CgroupId::new(std::os::unix::fs::MetadataExt::ino(&meta));
        Self { path, id }
    }
}
