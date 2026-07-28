use std::path::Path;

use crate::compile::Policy;
use aivisor_core::Error;

pub fn parse_policy(path: &Path) -> Result<Policy, Error> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::PolicyInvalid(format!("read policy file: {e}")))?;
    parse_policy_str(&content)
}

pub fn parse_policy_str(yaml: &str) -> Result<Policy, Error> {
    let raw: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|e| Error::PolicyInvalid(format!("YAML parse: {e}")))?;

    let api_version = raw["apiVersion"]
        .as_str()
        .unwrap_or("aivisor/v1")
        .to_string();

    if api_version != "aivisor/v1" {
        return Err(Error::PolicyInvalid(format!(
            "unsupported apiVersion: {api_version}"
        )));
    }

    let kind = raw["kind"].as_str().unwrap_or("SandboxPolicy").to_string();

    if kind != "SandboxPolicy" {
        return Err(Error::PolicyInvalid(format!("unsupported kind: {kind}")));
    }

    let metadata_name = raw["metadata"]["name"]
        .as_str()
        .unwrap_or("default")
        .to_string();

    let spec = &raw["spec"];

    let filesystem = parse_fs_policy(spec)?;
    let exec = parse_exec_policy(spec)?;
    let network = parse_net_policy(spec)?;
    let runtime = parse_runtime_opts(spec);
    let audit = parse_audit_opts(spec);

    Ok(Policy {
        api_version,
        kind,
        metadata_name,
        filesystem,
        exec,
        network,
        runtime,
        audit,
    })
}

fn parse_fs_policy(spec: &serde_yaml::Value) -> Result<Option<crate::compile::FsPolicy>, Error> {
    let fs = match spec.get("filesystem") {
        Some(v) => v,
        None => return Ok(None),
    };

    let i_know = spec["runtime"]["iKnowWhatImDoing"]
        .as_bool()
        .unwrap_or(false);

    let default = match fs["default"].as_str() {
        Some("allow") if i_know => crate::compile::AccessDefault::Allow,
        Some("allow") => {
            return Err(Error::PolicyInvalid(
                "default: allow on filesystem requires spec.runtime.iKnowWhatImDoing: true".into(),
            ));
        }
        _ => crate::compile::AccessDefault::Deny,
    };

    let mut rules = Vec::new();
    if let Some(rules_list) = fs["rules"].as_sequence() {
        for rule in rules_list {
            let path = rule["path"]
                .as_str()
                .ok_or_else(|| Error::PolicyInvalid("filesystem rule missing path".into()))?
                .to_string();

            if !path.starts_with('/') {
                return Err(Error::PolicyInvalid(format!(
                    "filesystem path must be absolute: {path}"
                )));
            }
            if path.contains("..") {
                return Err(Error::PolicyInvalid(format!(
                    "filesystem path must not contain '..': {path}"
                )));
            }

            let access: Vec<String> = rule["access"]
                .as_sequence()
                .map(|s| {
                    s.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            if access.contains(&"execute".to_string()) {
                let allow_ws = rule["allowWorkspaceExec"].as_bool().unwrap_or(false);
                if path == "/workspace" && !allow_ws {
                    return Err(Error::PolicyInvalid(
                        "execute on /workspace requires allowWorkspaceExec: true".into(),
                    ));
                }
            }

            let write_access = ["write", "create", "delete", "truncate"];
            let system_paths = ["/", "/usr", "/etc", "/proc", "/sys", "/dev"];
            if system_paths.contains(&path.as_str())
                && access.iter().any(|a| write_access.contains(&a.as_str()))
            {
                return Err(Error::PolicyInvalid(format!(
                    "cannot grant write access to system path: {path}"
                )));
            }

            let recursive = rule["recursive"].as_bool().unwrap_or(false);

            rules.push(crate::compile::FsRule {
                path,
                access,
                recursive,
            });
        }
    }

    Ok(Some(crate::compile::FsPolicy { default, rules }))
}

fn parse_exec_policy(
    spec: &serde_yaml::Value,
) -> Result<Option<crate::compile::ExecPolicy>, Error> {
    let exec = match spec.get("exec") {
        Some(v) => v,
        None => return Ok(None),
    };

    let i_know = spec["runtime"]["iKnowWhatImDoing"]
        .as_bool()
        .unwrap_or(false);

    let default = match exec["default"].as_str() {
        Some("allow") if i_know => crate::compile::AccessDefault::Allow,
        Some("allow") => {
            return Err(Error::PolicyInvalid(
                "default: allow on exec requires spec.runtime.iKnowWhatImDoing: true".into(),
            ));
        }
        _ => crate::compile::AccessDefault::Deny,
    };

    let mut allow = Vec::new();
    if let Some(allow_list) = exec["allow"].as_sequence() {
        for entry in allow_list {
            if let Some(path) = entry["path"].as_str() {
                if !path.starts_with('/') {
                    return Err(Error::PolicyInvalid(format!(
                        "exec rule path must be absolute: {path}"
                    )));
                }
                if path.contains("..") {
                    return Err(Error::PolicyInvalid(format!(
                        "exec rule path must not contain '..': {path}"
                    )));
                }
                let pin = entry["pin"].as_str().map(String::from);
                allow.push(crate::compile::ExecRule::Path {
                    path: path.to_string(),
                    pin,
                });
            } else if let Some(prefix) = entry["prefix"].as_str() {
                if !prefix.starts_with('/') {
                    return Err(Error::PolicyInvalid(format!(
                        "exec rule prefix must be absolute: {prefix}"
                    )));
                }
                if prefix.contains("..") {
                    return Err(Error::PolicyInvalid(format!(
                        "exec rule prefix must not contain '..': {prefix}"
                    )));
                }
                allow.push(crate::compile::ExecRule::Prefix(std::path::PathBuf::from(
                    prefix,
                )));
            }
        }
    }

    Ok(Some(crate::compile::ExecPolicy { default, allow }))
}

fn parse_net_policy(spec: &serde_yaml::Value) -> Result<Option<crate::compile::NetPolicy>, Error> {
    let net = match spec.get("network") {
        Some(v) => v,
        None => return Ok(None),
    };

    let default = match net["default"].as_str() {
        Some("allow") => {
            return Err(Error::PolicyInvalid(
                "network default: allow is not supported in Phase 2; use default: deny".into(),
            ));
        }
        _ => crate::compile::AccessDefault::Deny,
    };

    let mut egress = Vec::new();
    if let Some(egress_list) = net["egress"].as_sequence() {
        for entry in egress_list {
            if entry.get("via").is_some() {
                let hosts: Vec<String> = entry["hosts"]
                    .as_sequence()
                    .map(|s| {
                        s.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let methods: Vec<String> = entry["methods"]
                    .as_sequence()
                    .map(|s| {
                        s.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                egress.push(crate::compile::NetRule::BrokerRoute { hosts, methods });
            } else if entry.get("direct").is_some() {
                let cidr = entry["cidr"].as_str().unwrap_or("").to_string();
                let ports: Vec<u16> = entry["ports"]
                    .as_sequence()
                    .map(|s| {
                        s.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u16))
                            .collect()
                    })
                    .unwrap_or_default();
                egress.push(crate::compile::NetRule::Direct { cidr, ports });
            }
        }
    }

    let block_metadata = net["blockMetadata"].as_bool().unwrap_or(true);
    let dns_policy = net["dnsPolicy"].as_str().map(String::from);

    Ok(Some(crate::compile::NetPolicy {
        default,
        egress,
        block_metadata,
        dns_policy,
    }))
}

fn parse_runtime_opts(spec: &serde_yaml::Value) -> Option<crate::compile::RuntimeOpts> {
    let rt = spec.get("runtime")?;
    Some(crate::compile::RuntimeOpts {
        seccomp_profile: rt["seccompProfile"].as_str().map(String::from),
        landlock_abi_min: rt["landlockAbiMin"].as_u64().map(|n| n as u32),
        timeout: rt["timeout"].as_str().map(String::from),
        max_idle: rt["maxIdle"].as_str().map(String::from),
    })
}

fn parse_audit_opts(spec: &serde_yaml::Value) -> Option<crate::compile::AuditOpts> {
    let audit = spec.get("audit")?;
    Some(crate::compile::AuditOpts {
        level: audit["level"].as_str().map(String::from),
        sink: audit["sink"].as_str().map(String::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{ExecRule, NetRule};

    fn minimal_yaml() -> &'static str {
        r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: test-policy
spec:
  filesystem:
    default: deny
    rules:
      - path: /workspace
        access: [read, write, create, delete]
        recursive: true
  exec:
    default: deny
    allow:
      - path: /usr/bin/python3
"#
    }

    #[test]
    fn test_parse_minimal_policy() {
        let policy = parse_policy_str(minimal_yaml()).unwrap();
        assert_eq!(policy.metadata_name, "test-policy");
        assert!(policy.filesystem.is_some());
        assert!(policy.exec.is_some());
        assert!(policy.network.is_none());
    }

    #[test]
    fn test_parse_full_policy() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: full-policy
spec:
  filesystem:
    default: deny
    rules:
      - path: /workspace
        access: [read, write, create, delete, truncate]
      - path: /usr
        access: [read, execute]
      - path: /tmp
        access: [read, write, create, delete]
      - path: /etc/ssl/certs
        access: [read]
  exec:
    default: deny
    allow:
      - path: /usr/bin/python3
        pin: sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
      - path: /usr/bin/bash
      - prefix: /usr/lib/python3.12/
  network:
    default: deny
    egress:
      - via: broker
        hosts: [pypi.org, github.com]
        methods: [GET]
      - direct:
        cidr: 10.42.0.0/16
        ports: [5432]
    blockMetadata: true
    dnsPolicy: broker-pinned
  runtime:
    seccompProfile: aivisor-default
    landlockAbiMin: 3
    timeout: 30m
    maxIdle: 10m
  audit:
    level: allow+deny
    sink: otlp
"#;
        let policy = parse_policy_str(yaml).unwrap();
        assert_eq!(policy.metadata_name, "full-policy");

        // Filesystem
        let fs = policy.filesystem.unwrap();
        assert_eq!(fs.rules.len(), 4);
        assert!(fs.rules.iter().any(|r| r.path == "/workspace"));

        // Exec
        let exec = policy.exec.unwrap();
        assert_eq!(exec.allow.len(), 3);
        assert!(
            matches!(&exec.allow[0], ExecRule::Path { path, .. } if path == "/usr/bin/python3")
        );

        // Network
        let net = policy.network.unwrap();
        assert!(net.block_metadata);
        assert_eq!(net.dns_policy.as_deref(), Some("broker-pinned"));
        assert_eq!(net.egress.len(), 2);
        assert!(
            matches!(&net.egress[0], NetRule::BrokerRoute { hosts, .. } if hosts.contains(&"pypi.org".into()))
        );

        // Runtime
        let rt = policy.runtime.unwrap();
        assert_eq!(rt.seccomp_profile.as_deref(), Some("aivisor-default"));
        assert_eq!(rt.landlock_abi_min, Some(3));

        // Audit
        let audit = policy.audit.unwrap();
        assert_eq!(audit.level.as_deref(), Some("allow+deny"));
    }

    #[test]
    fn test_reject_fs_default_allow_without_flag() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  filesystem:
    default: allow
"#;
        let err = parse_policy_str(yaml).unwrap_err();
        assert!(err.to_string().contains("iKnowWhatImDoing"));
    }

    #[test]
    fn test_reject_exec_default_allow_without_flag() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  exec:
    default: allow
"#;
        let err = parse_policy_str(yaml).unwrap_err();
        assert!(err.to_string().contains("iKnowWhatImDoing"));
    }

    #[test]
    fn test_accept_default_allow_with_flag() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: permissive
spec:
  runtime:
    iKnowWhatImDoing: true
  filesystem:
    default: allow
  exec:
    default: allow
"#;
        let policy = parse_policy_str(yaml).unwrap();
        assert_eq!(
            policy.filesystem.unwrap().default,
            crate::compile::AccessDefault::Allow
        );
        assert_eq!(
            policy.exec.unwrap().default,
            crate::compile::AccessDefault::Allow
        );
    }

    #[test]
    fn test_reject_relative_path() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  filesystem:
    rules:
      - path: relative/path
        access: [read]
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_path_traversal() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  filesystem:
    rules:
      - path: /workspace/../../etc
        access: [read]
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_system_path_write() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  filesystem:
    rules:
      - path: /etc
        access: [write]
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_accept_system_path_read() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: ok
spec:
  filesystem:
    rules:
      - path: /etc/ssl/certs
        access: [read]
"#;
        assert!(parse_policy_str(yaml).is_ok());
    }

    #[test]
    fn test_reject_exec_relative_path() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  exec:
    allow:
      - path: relative/bin
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_exec_path_traversal() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  exec:
    allow:
      - path: /usr/bin/../../etc
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_net_default_allow() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  network:
    default: allow
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_workspace_exec_without_flag() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: bad
spec:
  filesystem:
    rules:
      - path: /workspace
        access: [execute]
"#;
        let err = parse_policy_str(yaml).unwrap_err();
        assert!(err.to_string().contains("allowWorkspaceExec"));
    }

    #[test]
    fn test_accept_workspace_exec_with_flag() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: ws-exec
spec:
  filesystem:
    rules:
      - path: /workspace
        access: [execute]
        allowWorkspaceExec: true
"#;
        let policy = parse_policy_str(yaml).unwrap();
        let fs = policy.filesystem.unwrap();
        let ws_rule = fs.rules.iter().find(|r| r.path == "/workspace").unwrap();
        assert!(ws_rule.access.contains(&"execute".to_string()));
    }

    #[test]
    fn test_reject_bad_api_version() {
        let yaml = r#"
apiVersion: aivisor/v2
kind: SandboxPolicy
metadata:
  name: bad
spec: {}
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_bad_kind() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: OtherPolicy
metadata:
  name: bad
spec: {}
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_parse_empty_policy_sections() {
        let yaml = r#"
apiVersion: aivisor/v1
kind: SandboxPolicy
metadata:
  name: empty
spec: {}
"#;
        let policy = parse_policy_str(yaml).unwrap();
        assert!(policy.filesystem.is_none());
        assert!(policy.exec.is_none());
        assert!(policy.network.is_none());
        assert!(policy.runtime.is_none());
        assert!(policy.audit.is_none());
    }
}
