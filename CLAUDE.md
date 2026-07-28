# AIVisor — conventions for coding agents

Read `blueprint.md` before writing code. It is authoritative; this file only covers mechanics.

## What this is

A privileged Linux sandbox runtime for AI agents, built from namespaces, cgroup v2, Landlock,
seccomp, and eBPF LSM. This is security-critical systems code. `roadmap.md` Part II (phase
breakdowns, tasks, common failure modes, handoff markers) and Part III (the AI-assisted
implementation workflow: model allocation, session loop, non-negotiables) are the current source
for phase-by-phase working rules. Earlier drafts of this project also referenced a `prompts/`
directory of ready-to-paste session prompts and standalone `phase1.md`…`phase4.md` build specs;
neither exists in this repo — `roadmap.md` is what actually carries that content today. Don't
assume either path exists without checking.

## The four rules that matter most

1. **Fail closed.** Every error in a security control denies. No `warn!` and continue. Ever.
2. **Unmatched denies.** Deny-by-default on filesystem, exec, and network.
3. **Measure, don't estimate.** No performance number anywhere without a `bench/` run that
   recorded the kernel version and CPU.
4. **Document limitations next to the control.** Overselling a security property is a defect.

## Platform

Linux only, kernel ≥ 6.1, cgroup v2 unified. There is no Windows or macOS build; do not add
`#[cfg]` paths for them. Development from a non-Linux host requires a Linux VM. Integration
tests require privileges and are gated behind `--features privileged-tests`.

## Layout

```
crates/aivisor-core      types, errors, IDs, policy model — no syscalls
crates/aivisor-runtime   namespaces, cgroups, mounts, landlock, seccomp, launcher
crates/aivisor-bpf       eBPF C programs + Rust loader
crates/aivisor-policy    policy parse → landlock plan + bpf plan + seccomp plan
crates/aivisor-broker    egress proxy, secret injection, SPIFFE
crates/aivisor-snapshot  overlay archive, CRIU, turn-aware checkpointing
crates/aivisord          gRPC daemon, warm pool, audit pipeline
crates/aivisor-cli       `aivisor` binary
proto/  sdk/  k8s/  bench/  docs/
```

Integration tests live under each crate's own `tests/` directory (e.g. `crates/aivisor-runtime/tests/`),
which is where Cargo actually discovers them — not a top-level `tests/`. `bench/escape/` is its own
workspace member with the categorized escape scenarios plus the harness that runs them.

## Style

- Rust edition 2021+, `cargo fmt`, `cargo clippy -- -D warnings` must be clean.
- Typed errors (`thiserror`) in libraries; `anyhow` only in binaries.
- No `unwrap()` / `expect()` outside tests.
- `pidfd` for all process signalling — never bare PIDs.
- Every acquired resource has one owner and a teardown; teardown is reverse acquisition order.
- Comments explain *why*. Security-relevant public items document their limitations.

## Commits

```
{phase}: {TASK_ID} — <what changed>

<why, 2-4 lines. Name the failure mode prevented, if a security control.>
```

Do not commit or push unless asked.

## Before declaring a task done

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace
sudo -E cargo test --workspace --features privileged-tests
```

Paste real output. "All tests pass" without output will be checked and rejected at the gate.

## Phase boundaries

Do not implement across phases. If you need something from a later phase, leave the
`TODO(phaseN)` marker specified in `roadmap.md`'s handoff-markers section for the current phase,
at the exact call site, and move on.
