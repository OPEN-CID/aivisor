---
layout: default
title: Architecture
---

# AIVisor Architecture

> **Full authoritative specification:** [`blueprint.md`](../blueprint.md)
> This document provides a high-level summary.

## Defence in Depth

AIVisor composes five layers of Linux kernel security primitives:

| Layer | Mechanism | Enforces | Phase |
|---|---|---|---|
| L1 | Namespaces + cgroups v2 | Process isolation, resource caps | 1 |
| L2 | Overlayfs + pivot_root | Filesystem isolation | 1 |
| L3 | Landlock LSM | FS access rights (read/write/exec) | 2 |
| L4 | seccomp-bpf | Syscall surface reduction | 2 |
| L5 | eBPF LSM | Path, exec, net, audit, dirty-turn | 3 |

Each layer catches what the previous one misses. If one fails to load, the
others still stand.

## Launch Sequence

The exact ordering matters. All steps below are wired in `aivisor-runtime::launcher` today except
step 13 (L5 registration — the BPF programs exist and load, but `SandboxManager` does not yet
register a launching sandbox's cgroup in the `sandboxes` map before releasing the child):

```
 1. Parent verifies kernel capabilities
 2. Parent creates cgroup leaf, applies limits
 3. Parent builds a clone3 CloneArgs: all CLONE_NEW* flags + CLONE_PIDFD,
    and CLONE_INTO_CGROUP + the cgroup fd when the kernel supports it
    (5.7+; older kernels join the cgroup from the parent instead, before
    releasing the child — never after)
 4. Parent opens a UnixStream pair for the sync/result channel
 5. Parent calls clone3 (stack left at 0/0 → fork()-like: returns twice)
 6. Child blocks on a 1-byte sync-channel read (cannot proceed without
    uid/gid maps, and — on the CLONE_INTO_CGROUP fallback path — cgroup
    membership)
 7. Parent writes /proc/<pid>/setgroups, uid_map, gid_map (and, on the
    fallback path, the child's pid into cgroup.procs)
 8. Parent sends the go byte
 9. Child: prctl(NO_NEW_PRIVS)
10. Child: mount setup (proc/sys/tmp/dev/workspace, built under the new
    root's tree) + pivot_root + old-root unmount (MNT_DETACH)
11. Child: drop capabilities (bounding set, ambient, all sets)
12. Child: apply Landlock ruleset, restrict_self()
13. Child: register cgroup in BPF maps (deny-all → real)  ← NOT YET WIRED
14. Child: install seccomp-bpf filter
15. Child: setresuid/setresgid to the unprivileged in-namespace user
16. Child sends Ready (last, immediately before execve — not earlier)
17. Child: execve(agent entrypoint)
18. Parent receives Ready, returns a Supervisor handle (pidfd-based wait
    and signal only, never a bare pid)
```

## Repository Layout

```
crates/
  aivisor-core      Types, errors, IDs, policy model — no syscalls
  aivisor-runtime   Namespaces, cgroups, mounts, landlock, seccomp, launcher
  aivisor-bpf       eBPF C programs + Rust loader
  aivisor-policy    Policy parse → landlock + bpf + seccomp plan
  aivisor-broker    Egress proxy, secret injection, SPIFFE
  aivisor-snapshot  Overlay archive, CRIU, turn-aware checkpointing
  aivisord          gRPC daemon, warm pool, audit pipeline
  aivisor-cli       `aivisor` binary

proto/              gRPC protobuf definitions
sdk/                Python and TypeScript SDKs
k8s/                Kubernetes CRDs, controller, Helm chart
bench/              Performance benchmarks
tests/              Integration tests (privileged)
docs/               Documentation
```

## Key Design Decisions

- **Probe by attempt, not version.** Kernel features are probed by attempting
  the operation — never parsed from `uname`. Distro kernels backport aggressively.
- **pidfd for all signalling.** Never bare PIDs. PID-reuse bugs in teardown paths
  would signal unrelated host processes.
- **Generation-swapped policy updates.** BPF rules are never mutated in place.
  New rules at a fresh index, then atomic `sandbox_ctx` swap.
- **Teardown is reverse of acquisition.** Every resource has one owner and is
  reclaimed in reverse order. Crash recovery enumerates orphan cgroups on start.
- **Deny-by-default everywhere.** Unmatched paths, syscalls, and network
  destinations are denied. Opt-in only.

## Limitations

See the [Threat Model](threat-model.md) for a complete list. Key limitations:

1. Kernel 0-day defeats all five layers
2. CPU side channels between co-located sandboxes are not mitigated
3. Semantic abuse of granted capabilities cannot be prevented
4. Hardware isolation (microVM nesting) recommended for hostile multi-tenancy
