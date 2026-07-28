---
layout: default
title: Deployment Guide
---

# AIVisor Deployment Guide

## Prerequisites

### Kernel Requirements

| Feature | Minimum | Required |
|---------|---------|----------|
| Kernel version | 6.1 LTS | Yes (6.6+ recommended) |
| cgroup v2 unified | 4.5 (practical 5.2) | Yes |
| Landlock LSM | 5.13 | Yes (Phase 2) |
| BPF LSM | 5.7 | Yes (Phase 3) |
| overlayfs | 3.18 | Yes |
| overlayfs in userns | 5.11 | Recommended |

### Kernel Configuration

```
CONFIG_BPF_LSM=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_OVERLAY_FS=y
```

### Boot Parameters

```
lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,bpf
```

### sysctl Settings

```ini
kernel.unprivileged_userns_clone=0    # Let aivisord create userns
vm.unprivileged_userfaultfd=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=3
```

## Installation

### Standalone (recommended for development)

```bash
cargo build --release
sudo ./target/release/aivisor doctor
sudo ./target/release/aivisor run -- /bin/echo "hello world"
```

### Kubernetes (production)

```bash
helm install aivisor k8s/helm/aivisor/
```

See `k8s/` for CRD definitions and Helm values.

## Host Hardening

1. Run on a dedicated node pool with the kernel requirements above.
2. Enable automatic security patching with a defined SLA.
3. Disable unprivileged user namespaces; `aivisord` creates them.
4. Use nested mode (microVM + AIVisor) for untrusted multi-tenancy.

## Nested Mode (Recommended for Multi-Tenancy)

Run AIVisor inside a Firecracker or Kata microVM:

- One microVM per tenant
- Many AIVisor sandboxes per microVM

This adds the hardware isolation boundary between tenants while keeping
AIVisor's density and observability within a tenant.

## Monitoring

AIVisor exposes:
- Prometheus metrics on `/metrics`
- OTLP traces for requests
- Structured JSONL audit events

Key metrics to alert on:
- `aivisor_pool_hit_rate` — low hit rate means cold creates are frequent
- `aivisor_denials_total` — sudden spike may indicate an attack
- `aivisor_audit_dropped_total` — dropped audit events
- `aivisor_sandbox_memory_pressure` — agents under memory pressure

## Further reading

- [Quickstart](quickstart.md) — get started in 5 minutes
- [Threat Model](threat-model.md) — understand the security boundary
- [Architecture](architecture.md) — system design overview
