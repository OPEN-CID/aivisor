use std::collections::HashMap;
use std::sync::Mutex;

use aivisor_core::SandboxId;

/// Turn-aware dirty detection.
/// Consumes the dirty bit set by BPF programs and exposes it
/// to the snapshot manager for smart checkpointing.
#[derive(Default)]
pub struct TurnTracker {
    inner: Mutex<HashMap<String, TurnState>>,
}

#[allow(dead_code)]
struct TurnState {
    current_turn_id: String,
    dirty: bool,
    baseline_pids: u64,
}

impl TurnTracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Begin a new turn: clear dirty flag, record PID baseline.
    pub fn begin(&self, sandbox_id: &SandboxId, turn_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.insert(
            sandbox_id.to_string(),
            TurnState {
                current_turn_id: turn_id.into(),
                dirty: false,
                baseline_pids: 0,
            },
        );
    }

    /// End a turn: return whether it was dirty.
    /// Fail-closed: unknown sandbox returns `true` (assume dirty) so
    /// a checkpoint is not skipped due to missing tracking data.
    pub fn end(&self, sandbox_id: &SandboxId) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if let Some(state) = inner.get_mut(&sandbox_id.to_string()) {
            state.dirty
        } else {
            true // fail-closed: unknown → assume dirty
        }
    }

    /// Mark current turn as dirty (called by BPF inspector).
    pub fn mark_dirty(&self, sandbox_id: &SandboxId) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(state) = inner.get_mut(&sandbox_id.to_string()) {
            state.dirty = true;
        }
    }

    /// Check if the current turn is dirty.
    /// Fail-closed: unknown sandbox returns `true` so a checkpoint is not skipped.
    pub fn is_dirty(&self, sandbox_id: &SandboxId) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .get(&sandbox_id.to_string())
            .map(|s| s.dirty)
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_turn_dirty_detection() {
        let tracker = TurnTracker::new();
        let sid = SandboxId::new();

        tracker.begin(&sid, "turn-1");
        assert!(!tracker.is_dirty(&sid));

        tracker.mark_dirty(&sid);
        assert!(tracker.is_dirty(&sid));
        assert!(tracker.end(&sid));
    }

    #[test]
    fn test_clean_turn() {
        let tracker = TurnTracker::new();
        let sid = SandboxId::new();

        tracker.begin(&sid, "turn-1");
        assert!(!tracker.end(&sid)); // clean turn
    }

    #[test]
    fn test_fail_closed_unknown_sandbox() {
        let tracker = TurnTracker::new();
        let sid = SandboxId::new();
        // end() for an unknown sandbox returns true (dirty) per fail-closed
        assert!(tracker.end(&sid));
        assert!(tracker.is_dirty(&sid));
    }

    #[test]
    fn test_mark_dirty_unknown_sandbox_no_panic() {
        let tracker = TurnTracker::new();
        let sid = SandboxId::new();
        // mark_dirty on an unknown sandbox should not panic
        tracker.mark_dirty(&sid);
    }

    #[test]
    fn test_multiple_sandboxes_independent() {
        let tracker = TurnTracker::new();
        let sid_a = SandboxId::new();
        let sid_b = SandboxId::new();

        tracker.begin(&sid_a, "turn-1");
        tracker.begin(&sid_b, "turn-1");

        tracker.mark_dirty(&sid_a);

        assert!(tracker.is_dirty(&sid_a));
        assert!(!tracker.is_dirty(&sid_b));

        assert!(tracker.end(&sid_a));
        assert!(!tracker.end(&sid_b));
    }

    #[test]
    fn test_turn_id_independent_of_sandbox_id() {
        let tracker = TurnTracker::new();
        let sid = SandboxId::new();

        tracker.begin(&sid, "turn-alpha");
        tracker.mark_dirty(&sid);
        assert!(tracker.is_dirty(&sid));

        tracker.begin(&sid, "turn-beta");
        // New turn should reset dirty flag
        assert!(!tracker.is_dirty(&sid));
    }

    #[test]
    fn test_concurrent_begin_end() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(TurnTracker::new());
        let mut handles = Vec::new();

        for i in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                let sid = SandboxId::new();
                tracker.begin(&sid, &format!("turn-{i}"));
                tracker.mark_dirty(&sid);
                assert!(tracker.end(&sid));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_is_dirty_after_end() {
        let tracker = TurnTracker::new();
        let sid = SandboxId::new();

        tracker.begin(&sid, "turn-1");
        tracker.mark_dirty(&sid);
        tracker.end(&sid);
        // After end, the turn state is still in the map until a new begin
        assert!(tracker.is_dirty(&sid));
    }
}
