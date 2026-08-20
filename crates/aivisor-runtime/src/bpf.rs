//! Process-wide handle to the loaded BPF LSM enforcement layer.
//!
//! The programs are global and stateless — one load per process, with all
//! per-sandbox state in maps (roadmap Phase 3 failure mode #4: "per-sandbox
//! program loading"). This module owns that single load.
//!
//! Why a singleton rather than one per [`crate::SandboxManager`]: every
//! manager would otherwise attach its own copy of every LSM hook, and each
//! would get a [`BpfManager`] with its own rule-index allocator handing out
//! *overlapping* index ranges in the same shared kernel maps — so one
//! sandbox would enforce another's rules. Several tests in this workspace
//! construct a manager each, so this is a real configuration, not a
//! hypothetical one.

use std::sync::{Arc, OnceLock};

use aivisor_bpf::{BpfLoader, BpfManager};
use aivisor_core::Error;

static ENFORCEMENT: OnceLock<Result<Arc<BpfManager>, String>> = OnceLock::new();

/// Load and attach the BPF programs (once), returning the shared manager.
///
/// Fails closed: any error here means no in-kernel enforcement is
/// available, and callers are expected to refuse to launch rather than
/// continue unprotected.
pub fn enforcement() -> Result<Arc<BpfManager>, Error> {
    ENFORCEMENT
        .get_or_init(|| {
            let programs = BpfLoader::load_and_attach().map_err(|e| e.to_string())?;

            // Deliberately leaked, and this is the intended lifetime rather
            // than an oversight. The LSM links must stay attached for as
            // long as this process can launch sandboxes, and
            // `libbpf_rs::Object` is `!Send`, so the loaded set cannot be
            // parked in this `static`. Forgetting it keeps the link fds
            // open until the process exits, at which point the kernel
            // detaches them. Everything needed afterwards — maps and the
            // per-sandbox cgroup programs — is reachable through the pins
            // under /sys/fs/bpf/aivisor.
            std::mem::forget(programs);

            BpfManager::new().map(Arc::new).map_err(|e| e.to_string())
        })
        .clone()
        .map_err(|e| {
            Error::LaunchFailed(format!(
                "BPF LSM enforcement unavailable: {e} — the sandbox would run without \
                 in-kernel policy, so the launch is refused"
            ))
        })
}
