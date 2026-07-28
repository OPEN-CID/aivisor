use crate::id::SandboxId;
use crate::policy::PolicyRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuQuota {
    pub quota_us: u64,
    pub period_us: u64,
}

impl CpuQuota {
    pub fn from_cpus(cpus: f64) -> Self {
        let period_us = 100_000;
        let quota_us = (cpus * period_us as f64) as u64;
        Self {
            quota_us,
            period_us,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoLimit {
    pub major: u32,
    pub minor: u32,
    pub rbps: u64,
    pub wbps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_max: Option<CpuQuota>,
    pub memory_high: Option<u64>,
    pub memory_max: Option<u64>,
    pub pids_max: Option<u64>,
    pub io_max: Vec<IoLimit>,
    pub swap_max: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_max: None,
            memory_high: None,
            memory_max: None,
            pids_max: None,
            io_max: Vec::new(),
            swap_max: Some(0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkspaceSpec {
    Tmpfs { size: u64 },
    Dir { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub id: SandboxId,
    pub template: String,
    pub limits: ResourceLimits,
    pub workspace: WorkspaceSpec,
    pub env: BTreeMap<String, String>,
    pub timeout: Option<Duration>,
    #[serde(default)]
    pub policy: Option<PolicyRef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_quota_from_cpus() {
        let q = CpuQuota::from_cpus(2.0);
        assert_eq!(q.period_us, 100_000);
        assert_eq!(q.quota_us, 200_000);

        let q = CpuQuota::from_cpus(0.5);
        assert_eq!(q.quota_us, 50_000);
    }

    #[test]
    fn test_cpu_quota_zero() {
        let q = CpuQuota::from_cpus(0.0);
        assert_eq!(q.quota_us, 0);
    }

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert!(limits.cpu_max.is_none());
        assert_eq!(limits.swap_max, Some(0));
        assert!(limits.io_max.is_empty());
    }

    #[test]
    fn test_resource_limits_with_values() {
        let limits = ResourceLimits {
            cpu_max: Some(CpuQuota::from_cpus(2.0)),
            memory_high: Some(536_870_912),  // 512Mi
            memory_max: Some(1_073_741_824), // 1Gi
            pids_max: Some(512),
            io_max: vec![IoLimit {
                major: 8,
                minor: 0,
                rbps: 104_857_600,
                wbps: 52_428_800,
            }],
            swap_max: Some(0),
        };
        assert!(limits.cpu_max.is_some());
        assert_eq!(limits.pids_max, Some(512));
    }

    #[test]
    fn test_sandbox_spec_serde_roundtrip() {
        let spec = SandboxSpec {
            id: SandboxId::new(),
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 1073741824 },
            env: BTreeMap::new(),
            timeout: Some(Duration::from_secs(1800)),
            policy: None,
        };

        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: SandboxSpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.template, "base");
    }

    #[test]
    fn test_sandbox_spec_dir_workspace() {
        let spec = SandboxSpec {
            id: SandboxId::new(),
            template: "custom".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Dir {
                path: "/data/sandboxes/abc".into(),
            },
            env: BTreeMap::new(),
            timeout: None,
            policy: None,
        };

        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: SandboxSpec = serde_yaml::from_str(&yaml).unwrap();
        match parsed.workspace {
            WorkspaceSpec::Dir { path } => assert_eq!(path, "/data/sandboxes/abc"),
            _ => panic!("expected Dir variant"),
        }
    }

    #[test]
    fn test_sandbox_spec_with_env() {
        let mut env = BTreeMap::new();
        env.insert("FOO".into(), "bar".into());
        env.insert("BAZ".into(), "qux".into());

        let spec = SandboxSpec {
            id: SandboxId::new(),
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 1048576 },
            env,
            timeout: Some(Duration::from_secs(60)),
            policy: None,
        };

        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: SandboxSpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.env.get("FOO").unwrap(), "bar");
        assert_eq!(parsed.env.get("BAZ").unwrap(), "qux");
    }

    #[test]
    fn test_sandbox_spec_policy_ref() {
        let spec = SandboxSpec {
            id: SandboxId::new(),
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 1048576 },
            env: BTreeMap::new(),
            timeout: None,
            policy: Some(crate::policy::PolicyRef {
                name: "my-policy".into(),
                overrides: None,
            }),
        };

        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: SandboxSpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.policy.unwrap().name, "my-policy");
    }

    #[test]
    fn test_sandbox_spec_default_policy_is_none() {
        let spec = SandboxSpec {
            id: SandboxId::new(),
            template: "base".into(),
            limits: ResourceLimits::default(),
            workspace: WorkspaceSpec::Tmpfs { size: 1048576 },
            env: BTreeMap::new(),
            timeout: None,
            policy: None,
        };
        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: SandboxSpec = serde_yaml::from_str(&yaml).unwrap();
        assert!(parsed.policy.is_none());
    }
}
