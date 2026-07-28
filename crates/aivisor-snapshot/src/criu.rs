use aivisor_core::Error;

/// Supported CRIU checkpoint/restore envelope.
/// v1 supports: same kernel minor, no GPU, sockets closed at checkpoint.
/// Everything outside this returns `Unsupported`.
pub struct CriuHandle;

impl CriuHandle {
    pub fn new() -> Result<Self, Error> {
        Ok(Self)
    }

    /// Checkpoint a sandbox process tree.
    /// Requires CAP_CHECKPOINT_RESTORE in the host namespace.
    pub fn checkpoint(&self, _pid: i32, _image_dir: &str) -> Result<(), Error> {
        Err(Error::Unsupported("CRIU checkpoint in Phase 4".into()))
    }

    /// Restore from checkpoint images.
    pub fn restore(&self, _image_dir: &str) -> Result<i32, Error> {
        Err(Error::Unsupported("CRIU restore in Phase 4".into()))
    }

    /// Check if CRIU is available on this host.
    pub fn check_available() -> Result<bool, Error> {
        Ok(false) // Phase 4
    }
}
