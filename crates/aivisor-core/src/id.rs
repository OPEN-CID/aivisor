use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(Uuid);

impl SandboxId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SandboxId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SandboxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CgroupId(pub u64);

impl CgroupId {
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for CgroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_id_unique() {
        let a = SandboxId::new();
        let b = SandboxId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn test_sandbox_id_serde_roundtrip() {
        let id = SandboxId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: SandboxId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_sandbox_id_from_bytes_roundtrip() {
        let original = SandboxId::new();
        let uuid = original.as_uuid();
        let bytes = uuid.as_bytes();
        let restored = SandboxId::from_bytes(*bytes);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_sandbox_id_default_is_new() {
        let a = SandboxId::default();
        let b = SandboxId::new();
        // Both should be valid UUIDv7, just different
        assert_ne!(a.to_string(), b.to_string());
    }

    #[test]
    fn test_cgroup_id_new() {
        let cg = CgroupId::new(42);
        assert_eq!(cg.as_raw(), 42);
    }

    #[test]
    fn test_cgroup_id_display() {
        let cg = CgroupId::new(12345);
        assert_eq!(cg.to_string(), "12345");
    }

    #[test]
    fn test_cgroup_id_equality() {
        let a = CgroupId::new(1);
        let b = CgroupId::new(1);
        let c = CgroupId::new(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
