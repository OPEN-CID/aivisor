# AIVisor — eBPF-driven sandbox runtime for AI agents

AIVisor is a lightweight, eBPF-driven sandbox runtime for autonomous AI
agents. It composes existing Linux security primitives — namespaces, cgroup
v2, Landlock LSM, eBPF LSM, seccomp — into a per-agent execution context
that starts in single-digit milliseconds, enforces policy inside the kernel,
and streams a complete audit trail.

**Status:** Pre-release, under active development. Nothing here has been verified on a running
Linux kernel yet — see the honesty note below before relying on any of it.

## Architecture

Five enforcement layers applied at sandbox creation. "Wired" means the layer is applied to every
sandbox launch by `aivisor-runtime`; "implemented, not yet load-bearing" means the code exists and
is believed correct but is not yet in the live sandbox creation path.

| # | Layer | Enforces | Status |
|---|-------|----------|--------|
| L1 | Namespaces | Process/FS/net/IPC visibility isolation | Wired |
| L2 | cgroup v2 | CPU, memory, PIDs, IO — with backpressure | Wired |
| L3 | Landlock LSM | Filesystem paths, exec | Wired (FS + exec; no TCP bind/connect scoping) |
| L4 | seccomp-bpf | Syscall surface reduction | Wired |
| L5 | eBPF LSM | Kernel-object-level allow/deny + audit | Programs written and loadable; not yet registered per-sandbox by `SandboxManager` |

**Not yet implemented at all:** the HTTP(S) egress-terminating broker (session issuance and byte
budgets are real; TLS termination, host allowlisting, and credential injection are not — see
`aivisor-broker`'s own doc comment), CRIU snapshot/restore, the gRPC API, and OCI base image
pull/build (`images/base/build.sh` is a stub, so a sandbox needs a manually-provisioned rootfs
under `/var/lib/aivisor/templates/<name>` to run at all).

**Verification status, stated plainly:** this codebase has been built and reviewed for logical
and API correctness against kernel documentation and vendored crate sources, but this
development environment cannot compile or run the Linux-only crates (`aivisor-runtime`,
`aivisor-bpf`, `aivisord`, `aivisor-cli`, `bench/escape`) at all. `cargo build --workspace`,
`cargo clippy`, and the privileged test suite have **not** been run against this code on a real
kernel. Treat every claim in this document as "should be correct, unverified" until someone runs
the checklist in `CLAUDE.md` § "Before declaring a task done" on Linux and pastes the output.

## Quick Start

```bash
# Check kernel compatibility
cargo build --release
sudo ./target/release/aivisor doctor

# Run a command in an isolated sandbox
sudo ./target/release/aivisor run -- /bin/echo "hello world"

# With resource limits
sudo ./target/release/aivisor run --cpu 2 --memory 2Gi --pids 512 \
    -- python3 -c "print(2+2)"
```

## Full Documentation

See the **[documentation site](docs/index.md)** for:

- [Quickstart](docs/quickstart.md) — install and first sandbox
- [Deployment Guide](docs/deployment.md) — production setup and host hardening
- [Threat Model](docs/threat-model.md) — security boundary and limitations
- [Architecture](docs/architecture.md) — system design overview
- [API Reference](docs/api/README.md) — gRPC and SDK docs

## What AIVisor Is Not

- **Not a microVM.** AIVisor runs on the host kernel. See `docs/threat-model.md`
  for what this means for isolation.
- **Not a behavioural sandbox.** Exec control constrains *which binary*, not
  *what logic*.
- **Not a replacement for hardware isolation** in hostile multi-tenancy.
  Use nested mode (microVM + AIVisor) for that.

## Performance Targets

Targets (not measurements — see blueprint.md §13 for the full table and the CI gates each one
maps to):

| Metric | Target (p50) |
|--------|-------------|
| Warm-pool acquire → Ready | < 1 ms |
| Cold create → Ready (shell) | < 10 ms |
| Cold create → first Python bytecode | < 40 ms |
| Idle sandbox RSS (excl. agent) | < 8 MB |
| `open()` overhead vs bare host | < 3 % |

**No number above has been measured.** `bench/lifecycle/bench.sh` is currently a stub that prints
`(benchmark stubbed)` rather than a real timing. Per blueprint.md §0 and §13: no performance claim
belongs in this README, in docs, or in a talk unless `bench/` actually produced it on a named
kernel and CPU, with the raw output committed alongside it. Until that happens, the table above is
a target, not a result.

## Repository Layout

```
crates/aivisor-core/       Shared types, errors, IDs, policy model
crates/aivisor-runtime/    Namespaces, cgroups, mounts, Landlock, seccomp, launcher
crates/aivisor-bpf/        eBPF C programs + Rust loader
crates/aivisor-policy/     Policy parse → Landlock + BPF + seccomp plans
crates/aivisor-broker/     Egress proxy + secret injection + SPIFFE
crates/aivisor-snapshot/   Overlay archive + CRIU + turn-aware checkpointing
crates/aivisord/           gRPC daemon, warm pool, audit pipeline
crates/aivisor-cli/        `aivisor` CLI
proto/                     gRPC protocol definition
sdk/python/                Python SDK
sdk/typescript/            TypeScript SDK
k8s/                       Kubernetes CRDs + controller + Helm chart
docs/                      Threat model, deployment guide, RFCs
bench/                     Micro, lifecycle, workload, escape, density benchmarks
```

## License

MIT. (Moving to Apache-2.0 before v1.0.)
