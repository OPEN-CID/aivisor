---
layout: default
title: Threat Model
---

# AIVisor Threat Model

## What AIVisor Protects Against

AIVisor composes Linux kernel security primitives — namespaces, cgroup v2,
Landlock LSM, seccomp-bpf, and eBPF LSM — into a defense-in-depth sandbox
for AI agents. The isolation boundary is the host kernel.

**Implementation status of the layers below** (see README.md for the fuller table): namespaces,
cgroups, Landlock, seccomp, and capability dropping are wired into every sandbox launch. The eBPF
LSM programs (L5) are written and loadable but not yet registered per-sandbox in the live creation
path, so rows below that depend on L5 specifically (metadata-endpoint blocking, exec hash pinning,
in-kernel audit) describe the design, not yet an enforced-by-default property of a running
sandbox. The egress broker's TLS termination and credential injection are not implemented at all.
None of this has been verified on a running kernel — see README.md's verification-status note.

### Adversary Model

- **The agent is fully untrusted and actively hostile.**
- The model driving the agent may be prompt-injected by content it fetches.
- The agent will enumerate its environment, read every readable file, probe
  every reachable address, and try published kernel exploits.

### Assets Protected

- Host kernel integrity
- Other sandboxes' data and processes
- Host credentials and cloud IAM
- The control plane and audit log
- Other tenants' network reachability

## What AIVisor Explicitly Does NOT Protect Against

These are design limitations, not gaps:

1. **Kernel 0-day.** One host kernel, one boundary. A privilege-escalation
   bug in any reachable kernel subsystem defeats all five layers.

2. **CPU microarchitectural side channels** (Spectre-class) between co-located
   sandboxes.

3. **Semantic abuse of granted capability.** If policy grants `python3` and
   `github.com`, an agent that publishes your source to a gist is doing
   something you allowed.

4. **A malicious control plane or host.** AIVisor protects the host from the
   agent, not the agent from the host.

## Recommended Deployment for Hostile Multi-Tenancy

For untrusted multi-tenant SaaS: **one microVM (Firecracker/Kata) per tenant,
many AIVisor sandboxes per microVM.** This gives you the hardware boundary
between tenants and AIVisor's speed, density, and observability within a
tenant.

## Attack Tree

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Read host files | L1 mount ns + L3 Landlock + L5 `file_open` | Kernel path-resolution bug |
| Write outside workspace | Same, plus noexec,nosuid,nodev | Same |
| Exec unapproved binary | L3 `FS_EXECUTE` + L5 `bprm_check_security` + hash pin | Interpreter abuse |
| Escalate via setuid | no_new_privs + empty bounding set | — |
| Load BPF / kernel module | seccomp deny + L5 KILL verb | — |
| Escape via userns exploit | Optional: disable unprivileged userns on host | Primary residual risk |
| Reach cloud metadata | L5 unconditional block + no default route | Misconfigured grant |
| Exfiltrate via allowed host | Broker method/size limits + audit | Detection, not prevention |
| Steal credentials | Broker holds them; sandbox has none | Broker compromise |
| DoS the host | cgroup limits + PSI monitoring | Slab exhaustion |
| Tamper with audit | Ring buffer write-only; events signed/sequenced | Consumer compromise |
| Side-channel co-tenant | Not mitigated in v1 | Use microVM nesting |

## Further reading

- [Deployment Guide](deployment.md) — host hardening and production setup
- [Architecture](architecture.md) — defence layers and launch sequence
- [Quickstart](quickstart.md) — get started in 5 minutes
