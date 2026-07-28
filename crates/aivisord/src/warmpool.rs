use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aivisor_core::{Error, SandboxId};
use aivisor_runtime::manager::SandboxManager;

/// A sandbox popped from the warm pool. Deliberately not `Clone`/`Copy`:
/// owning one is the only way to get its id back out (`into_id`, which
/// consumes it), so the type system rules out acquiring the same pooled
/// sandbox twice — there is no code path that produces two live
/// `WarmSandbox` values for the same underlying sandbox.
pub struct WarmSandbox(SandboxId);

impl WarmSandbox {
    pub fn id(&self) -> SandboxId {
        self.0
    }

    pub fn into_id(self) -> SandboxId {
        self.0
    }
}

/// Warm pool for fast sandbox acquire.
///
/// Honest scope: pre-pays `SandboxManager::create()` (cgroup + rootfs
/// directory provisioning) ahead of demand, which is what the current
/// `aivisor-runtime` architecture actually front-loads at create() time —
/// namespace/mount/Landlock/seccomp setup happens later, per-`exec()` call
/// (see `SandboxManager::exec`), not at create time. Blueprint §6.3's full
/// design (namespaces created, overlay mounted, supervisor parked in a
/// blocking read, atomic deny-all-to-real policy swap on acquire) needs a
/// persistent-supervisor launcher model that does not exist yet — that is
/// Phase 4 (roadmap.md T4.2). What's implemented here is real, not
/// simulated: `acquire()` returns an id that has an actual cgroup and
/// rootfs directory already created, not a freshly-fabricated, unprovisioned
/// spec (the previous version's bug).
pub struct WarmPool {
    manager: Arc<SandboxManager>,
    template: String,
    inner: Mutex<WarmPoolInner>,
}

struct WarmPoolInner {
    target_depth: usize,
    max_age: Duration,
    entries: Vec<PoolEntry>,
    cold_fallback_count: u64,
}

struct PoolEntry {
    id: SandboxId,
    created: Instant,
}

impl WarmPool {
    pub fn new(manager: Arc<SandboxManager>, template: &str, target_depth: usize) -> Self {
        Self {
            manager,
            template: template.into(),
            inner: Mutex::new(WarmPoolInner {
                target_depth,
                max_age: Duration::from_secs(300), // 5 min
                entries: Vec::new(),
                cold_fallback_count: 0,
            }),
        }
    }

    /// Top the pool up to its target depth by provisioning fresh sandboxes.
    /// Synchronous — callers on aivisord's async runtime should run this
    /// via `spawn_blocking` (cgroup/filesystem setup does blocking I/O),
    /// which is exactly what `spawn_refill_task` below does.
    pub fn refill(&self) -> Result<usize, Error> {
        let needed = {
            let inner = self.inner.lock().unwrap();
            inner.target_depth.saturating_sub(inner.entries.len())
        };

        let mut provisioned = 0;
        for _ in 0..needed {
            let spec = aivisor_core::SandboxSpec {
                id: SandboxId::new(),
                template: self.template.clone(),
                limits: aivisor_core::ResourceLimits::default(),
                workspace: aivisor_core::WorkspaceSpec::Tmpfs { size: 268_435_456 },
                env: Default::default(),
                timeout: Some(Duration::from_secs(1800)),
                policy: None,
            };
            let id = self.manager.create(spec)?;
            let mut inner = self.inner.lock().unwrap();
            inner.entries.push(PoolEntry {
                id,
                created: Instant::now(),
            });
            provisioned += 1;
        }
        Ok(provisioned)
    }

    /// Acquire a pre-provisioned sandbox, or `None` if the pool is empty —
    /// callers MUST fall back to a cold `manager.create()` on `None` rather
    /// than block waiting for a refill (blueprint §6.3: pool refill happens
    /// asynchronously off the request path; the request path never waits
    /// on it). A pooled sandbox is single-use: once acquired it is never
    /// returned to `entries` — reusing it would leak workspace/process
    /// state across whatever trust boundary the next acquirer is on.
    pub fn acquire(&self) -> Option<WarmSandbox> {
        let mut inner = self.inner.lock().unwrap();

        let now = Instant::now();
        let max_age = inner.max_age;
        let before = inner.entries.len();
        inner
            .entries
            .retain(|e| now.duration_since(e.created) < max_age);
        let expired = before - inner.entries.len();
        if expired > 0 {
            tracing::warn!(expired, "warm pool: dropped entries older than max_age");
        }

        match inner.entries.pop() {
            Some(entry) => Some(WarmSandbox(entry.id)),
            None => {
                inner.cold_fallback_count += 1;
                None
            }
        }
    }

    pub fn cold_fallback_count(&self) -> u64 {
        self.inner.lock().unwrap().cold_fallback_count
    }

    pub fn depth(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Spawn a background task that periodically tops the pool back up to
    /// its target depth. `interval` should be short relative to how fast
    /// the pool drains under load; refill work itself runs on a blocking
    /// thread (`spawn_blocking`) since cgroup/filesystem setup is
    /// synchronous I/O, not async.
    pub fn spawn_refill_task(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let pool = Arc::clone(&pool);
                let result = tokio::task::spawn_blocking(move || pool.refill()).await;
                match result {
                    Ok(Ok(n)) if n > 0 => tracing::info!(provisioned = n, "warm pool refilled"),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::warn!(error = %e, "warm pool refill failed"),
                    Err(e) => tracing::warn!(error = %e, "warm pool refill task panicked"),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warm_sandbox_is_not_clone() {
        // Compile-time check: WarmSandbox must not implement Clone/Copy,
        // or the single-use guarantee acquire() relies on is void. There's
        // no direct "assert type is not Clone" in stable Rust, so this
        // test exists as the documented invariant — if someone adds
        // `#[derive(Clone)]` to WarmSandbox, the comment on `acquire()`
        // claiming single-use-via-ownership becomes false, which is the
        // thing to catch in review, not something this test can assert
        // directly.
        let id = SandboxId::new();
        let ws = WarmSandbox(id);
        assert_eq!(ws.into_id(), id);
    }

    // Pool behavior against a real SandboxManager needs root/cgroup v2
    // (SandboxManager::new() probes hard kernel requirements), so it is
    // exercised by aivisord's own privileged integration tests once those
    // exist, not here.
}
