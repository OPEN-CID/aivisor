use std::path::Path;

use aivisor_core::Error;

/// Content-addressed workspace snapshot: archives the overlay upper layer
/// with chunking and dedup so snapshots are shared across sandboxes from the
/// same template.
///
/// **Not implemented in this build.** Both `create` and `restore` return
/// `Error::Unsupported`, the same way [`crate::criu::CriuHandle`] and
/// `aivisor_broker::Broker::serve` do for their own phase-4/phase-3 gaps.
///
/// They previously returned `Ok(...)` — `create` handing back a fixed
/// `"snap-placeholder"` id and `restore` reporting success without writing
/// anything. That is the worst possible shape for an unimplemented control:
/// a caller would checkpoint a workspace, be told it succeeded, restore it
/// later, be told *that* succeeded, and get an empty directory. Silent data
/// loss reported as success. Failing closed means a caller that reaches for
/// snapshotting finds out immediately, at the call site, that this build
/// cannot do it.
///
/// Implementing it (FastCDC chunking, content-addressed store, manifest
/// materialisation into a fresh upper dir) is tracked as `TODO(phase4)`.
pub struct WorkspaceSnapshot;

impl WorkspaceSnapshot {
    /// Snapshot the overlay upper layer.
    ///
    /// Once implemented: freezes the sandbox with `cgroup.freeze` so the
    /// upper layer is quiescent, archives it, and thaws. Until then this
    /// fails closed rather than returning a snapshot reference that points
    /// at nothing.
    pub fn create(_upper_dir: &Path) -> Result<SnapshotRef, Error> {
        Err(Error::Unsupported(
            "workspace snapshot creation not implemented in this build".into(),
        ))
    }

    /// Restore a snapshot into a fresh upper layer.
    ///
    /// Fails closed: a restore that silently wrote nothing would leave the
    /// caller running against an empty workspace while believing it had been
    /// repopulated.
    pub fn restore(_snap: &SnapshotRef, _target: &Path) -> Result<(), Error> {
        Err(Error::Unsupported(
            "workspace snapshot restore not implemented in this build".into(),
        ))
    }
}

pub struct SnapshotRef {
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_is_explicitly_unsupported_not_silently_ok() {
        let result = WorkspaceSnapshot::create(Path::new("/tmp/does-not-matter"));
        assert!(
            matches!(result, Err(Error::Unsupported(_))),
            "create() must fail closed, not hand back a placeholder snapshot ref"
        );
    }

    #[test]
    fn test_restore_is_explicitly_unsupported_not_silently_ok() {
        let snap = SnapshotRef {
            id: "whatever".into(),
        };
        let result = WorkspaceSnapshot::restore(&snap, Path::new("/tmp/does-not-matter"));
        assert!(
            matches!(result, Err(Error::Unsupported(_))),
            "restore() must fail closed, not report success without writing anything"
        );
    }
}
