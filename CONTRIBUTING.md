# Contributing to AIVisor

## Code of Conduct

All contributors must adhere to the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Getting Started

1. Read `blueprint.md` in full.
2. Read the phase doc for what you're implementing.
3. AIVisor is **security-critical systems code**. Every line matters.

## Development Environment

- Linux host with kernel ≥ 6.1, cgroup v2, BPF LSM, Landlock.
- Rust 1.82+ with `cargo fmt` and `clippy`.
- For integration tests: root privileges (`sudo -E cargo test --features privileged-tests`).

## Pull Request Process

1. Every PR must pass:
   - `cargo build --workspace`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo fmt --check`
   - `cargo test --workspace`
   - `sudo -E cargo test --workspace --features privileged-tests`
2. Adversarial tests for any security control.
3. Commit messages explain *why*, referencing the task ID.
4. No `unwrap()`/`expect()` outside test code.
5. No `TODO` except `TODO(phaseN)` handoff markers.
6. A reviewer who finds a fail-open error path rejects the PR.

## Security

See `SECURITY.md` for disclosure policy.
