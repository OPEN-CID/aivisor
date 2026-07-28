use aivisor_core::{Error, SandboxId};

/// SPIFFE SVID manager.
/// The private key lives in the broker, never in the sandbox.
/// The sandbox receives only an opaque session token.
pub struct SvidManager;

impl SvidManager {
    pub fn new() -> Result<Self, Error> {
        Ok(Self)
    }

    /// Request an SVID for a sandbox identity.
    pub fn request_svid(&self, sandbox_id: &SandboxId) -> Result<String, Error> {
        Ok(format!("spiffe://aivisor/agent/{}", sandbox_id))
    }
}
