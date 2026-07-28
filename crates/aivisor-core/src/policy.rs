use serde::{Deserialize, Serialize};

/// A named reference to a policy document, resolved by the runtime against
/// whatever policy store it has (a file, a name registered on the daemon,
/// etc). The compiled policy representation — parsing, Landlock/BPF/seccomp
/// compilation — lives entirely in `aivisor-policy`; this crate only knows
/// the reference shape, consistent with `aivisor-core` owning types and IDs
/// but no policy logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRef {
    pub name: String,
    pub overrides: Option<serde_yaml::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_ref_serde_roundtrip() {
        let r = PolicyRef {
            name: "coding-agent-default".into(),
            overrides: None,
        };
        let yaml = serde_yaml::to_string(&r).unwrap();
        let parsed: PolicyRef = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.name, "coding-agent-default");
    }
}
