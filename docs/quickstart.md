---
layout: default
title: Quickstart
---

# AIVisor Quickstart

## Prerequisites

- Linux kernel ≥ 6.1 with cgroup v2 unified
- Rust toolchain (1.82+)
- Root or `CAP_SYS_ADMIN` + `CAP_SYS_RESOURCE`

## Check your kernel

```bash
aivisor doctor
```

This probes every required kernel feature and reports what is missing with
actionable remediation. You need all hard requirements green before running
a sandbox.

## Run your first sandbox

```bash
# Clone and build
git clone https://github.com/your-org/aivisor
cd aivisor
cargo build --release

# Run a command inside a sandbox
sudo ./target/release/aivisor run -- /bin/echo "hello world"
```

## Common commands

```bash
# Check kernel capabilities
aivisor doctor

# Run with resource limits (cmd must be an absolute path INSIDE the
# sandbox — aivisor execve()s it directly, with no PATH lookup, so
# `-- python3 ...` fails; use `-- /usr/bin/python3 ...`)
aivisor run --cpu 2 --memory 2Gi --pids 512 --timeout 30m -- /bin/bash

# Run with an explicit policy document (blueprint.md §8.2 schema).
# Omitted entirely, the runtime's built-in least-privilege default
# applies — there is no unconfined mode.
aivisor run --policy ./my-policy.yaml -- /usr/bin/python3 script.py

# Run and get JSON timing report
aivisor run --json -- /bin/echo "hello"

# List running sandboxes — only ones created by THIS process; aivisor-cli
# does not yet share state across separate invocations (see aivisord for
# the daemon model that will fix this).
aivisor ps

# Execute in an existing sandbox — same process-local limitation as `ps`.
aivisor exec <sandbox-id> -- /bin/ls

# Inspect a sandbox
aivisor inspect <sandbox-id>

# Destroy a sandbox
aivisor destroy <sandbox-id>
```

**Base image requirement.** `aivisor run --template base` expects a rootfs at
`/var/lib/aivisor/templates/base`. There is no OCI pull/build pipeline wired up yet
(`images/base/build.sh` is a stub) — provision this directory yourself before `run` will work.

## What happens when you run a sandbox

1. Kernel capabilities are verified
2. A cgroup v2 leaf is created under `/sys/fs/cgroup/aivisor/<id>/`
3. Resource limits are applied (cpu, memory, pids)
4. A child process is created via `clone3` with all 8 namespaces
5. The root filesystem is mounted via overlayfs
6. The process is `pivot_root`'d into the sandbox
7. The command executes as PID 1 inside the sandbox
8. On exit, all resources are reclaimed

## Next steps

- [Deployment Guide](deployment.md) — production setup and host hardening
- [Threat Model](threat-model.md) — understand the security boundary
- [Architecture](architecture.md) — deep dive into the design
