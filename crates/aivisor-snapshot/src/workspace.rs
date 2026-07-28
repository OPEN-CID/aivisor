use std::path::Path;

use aivisor_core::Error;

/// Content-addressed workspace snapshot.
/// Archives the overlay upper layer with dedup and chunking.
/// Snapshots are shared across sandboxes from the same template.
pub struct WorkspaceSnapshot;

impl WorkspaceSnapshot {
    /// Snapshot the overlay upper layer.
    /// Freezes with cgroup.freeze for consistency, archives, thaws.
    pub fn create(_upper_dir: &Path) -> Result<SnapshotRef, Error> {
        // TODO(phase4): implement FastCDC chunking + content-addressed storage
        Ok(SnapshotRef {
            id: "snap-placeholder".into(),
        })
    }

    /// Restore a snapshot into a fresh upper layer.
    pub fn restore(_snap: &SnapshotRef, _target: &Path) -> Result<(), Error> {
        // TODO(phase4): materialize manifest into fresh upper dir
        Ok(())
    }
}

pub struct SnapshotRef {
    pub id: String,
}
