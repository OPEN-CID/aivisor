use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aivisor_core::Error;
use aivisor_runtime::manager::SandboxManager;

use crate::warmpool::WarmPool;

/// The aivisord gRPC daemon.
/// Owns the sandbox manager, BPF maps, warm pool, and audit pipeline.
pub struct Daemon {
    #[allow(dead_code)] // consumed once the gRPC service (TODO(phase4)) is wired to it
    manager: Arc<SandboxManager>,
    #[allow(dead_code)]
    warm_pool: Arc<WarmPool>,
}

const WARM_POOL_TEMPLATE: &str = "base";
const WARM_POOL_TARGET_DEPTH: usize = 4;
const WARM_POOL_REFILL_INTERVAL: Duration = Duration::from_secs(5);

impl Daemon {
    pub fn new() -> Result<Self, Error> {
        let manager = Arc::new(SandboxManager::new()?);

        // Crash recovery: re-attach to pinned BPF programs
        // TODO(phase4): re-attach to pinned BPF progs at /sys/fs/bpf/aivisor/

        let warm_pool = Arc::new(WarmPool::new(
            Arc::clone(&manager),
            WARM_POOL_TEMPLATE,
            WARM_POOL_TARGET_DEPTH,
        ));

        Ok(Self { manager, warm_pool })
    }

    /// Run the gRPC server.
    pub async fn run(&self, socket_path: &str) -> Result<(), Error> {
        let _ = Path::new(socket_path).parent().map(std::fs::create_dir_all);

        let _refill_handle = self.warm_pool.spawn_refill_task(WARM_POOL_REFILL_INTERVAL);

        // TODO(phase4): start tonic gRPC server with SandboxService
        //   serving on unix socket at socket_path with peer-cred authz,
        //   plus optional mTLS TCP. It should call self.warm_pool.acquire()
        //   on CreateSandbox and fall back to self.manager.create() on a
        //   pool miss (never block the RPC path waiting on a refill).

        tracing::info!("Daemon ready (gRPC stubbed, warm pool refilling in background)");

        // Block forever
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }
}
