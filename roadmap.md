# AIVisor Roadmap

**Single source of truth for strategy, implementation phases, and AI-assisted development workflow.**

---

## Part I — Strategic Overview

### 1. Why this exists

AIVisor is an eBPF-driven Linux sandbox runtime for autonomous AI agents. It combines cgroup
v2, namespaces, Landlock, seccomp-bpf, and eBPF LSM into five defence layers (L1–L5) that
progressively narrow what a compromised agent can do.

The core insight: **no single mechanism is sufficient.** Namespaces isolate process trees but
do not constrain root-in-namespace. Landlock prevents file-system escapes but cannot do
per-binary exec control. eBPF LSM can do fine-grained per-cgroup decisions but runs globally
and risks host interference. The layers are designed so that each catches what the previous one
misses — and if one fails to load, the others still stand.

### 2. Competitive landscape (as of July 2026)

| Product | Isolation | Density | Observability | Checkpoint | Egress | GPU |
|---|---|---|---|---|---|---|
| **Firecracker** | KVM microVM | Low | Opaque | VM snapshot | Guest config | No |
| **gVisor** | Userspace kernel | Medium | Syscall-level | No | Via sentry | No |
| **nsjail** | Namespaces | High | Minimal | No | Host-routed | No |
| **Kata** | HW-backed VM | Low | Opaque | VM snapshot | Guest config | Passthrough |
| **Docker** | Namespaces | High | Minimal | commit | Host-routed | Yes |
| **AIVisor** | Namespaces + eBPF LSM | High (target) | Full audit (target) | Turn-aware (target) | Broker-enforced (target) | Phase 4 |

Cold-start numbers were dropped from this table: they were unsourced (no benchmark, no
methodology, no kernel/CPU) and blueprint.md §0/§13 both prohibit carrying a performance figure
into any derived document without a `bench/` run backing it. "Target" above marks properties this
design aims for, not something `bench/` has measured for AIVisor specifically — see README.md's
verification-status note. Restore this table with real numbers once `bench/workload/` produces a
same-machine, same-kernel comparison.

### 3. Design principles (from blueprint.md)

1. **Fail closed** — every error in a security control denies. No `warn!` and continue.
2. **Unmatched denies** — deny-by-default on filesystem, exec, and network.
3. **Layered defence** — each layer catches what the previous misses. Order matters.
4. **Measure, don't estimate** — every performance number requires a `bench/` run.
5. **Document limitations** — overselling a security property is a defect.

### 4. Five defence layers

| Layer | Mechanism | Enforces | Applied at |
|---|---|---|---|
| L1 | Namespaces + cgroups v2 | Process isolation, resource caps | Clone |
| L2 | Overlayfs + pivot_root | Filesystem isolation | Post-clone mount |
| L3 | Landlock | FS access rights (read/write/exec) | After pivot_root |
| L4 | seccomp-bpf | Syscall surface reduction | After Landlock |
| L5 | eBPF LSM (BPF hook) | Path, exec, net, audit, dirty-turn | Daemon start |

### 5. Kernel requirements

Minimum: Linux 6.1, cgroup v2 unified, Landlock ABI 3. BPF LSM required for Phase 3+.

---

## Part II — Implementation Phases

### Phase 1 — Fast-Boot Runtime

**Goal:** `aivisor run -- <cmd>` launches an isolated, resource-capped, overlay-backed sandbox
and tears it down completely.

**Estimated:** 6 weeks · Kernel ≥ 6.1, cgroup v2, root or CAP_SYS_ADMIN+CAP_SYS_RESOURCE

**Definition of done:**
- `aivisor run --template base -- /bin/echo hello` prints `hello`, exits 0
- Command runs as PID 1 in all 8 namespaces, cannot see host processes
- Writes to `/workspace` persist across `exec` calls, vanish on destroy
- Writes to base image do not affect host or other sandboxes
- Memory limit enforced (OOM kills inside sandbox only)
- CPU limit enforced (busy loop with `cpu.max = 50000 100000` ≈ 0.5 CPU)
- PID limit enforced (fork bomb contained)
- `aivisor destroy` reclaims everything; 1000 cycles leak zero mounts/cgroups/fds
- Cold create→Ready p50 < 10 ms, p99 < 25 ms; destroy p50 < 5 ms
- Wedged sandbox destroyed within 2 s
- `cargo test` + `cargo clippy` pass; integration tests on privileged CI runner

**Deliverables:**
```
crates/aivisor-core/          # shared types — no syscalls
crates/aivisor-runtime/       # kernel plumbing
crates/aivisor-cli/           # `aivisor` binary
tests/                        # integration tests (privileged)
bench/lifecycle/              # create/destroy benchmarks
images/base/                  # minimal rootfs build script
```

**Tasks:**
- T1.1 Workspace scaffolding — Cargo workspace, CI
- T1.2 `aivisor-core`: SandboxId, SandboxSpec, ResourceLimits, Error — pure data, no syscalls
- T1.3 Kernel capability probe — `aivisor doctor`, probe by operation not version string
- T1.4 cgroup v2 manager — create/apply/freeze/thaw/kill/destroy, subtree_control delegation
- T1.5 Namespace launcher — clone3 with all 8 namespaces, sync socket, uid/gid mapping, pidfd
- T1.6 Rootfs and overlay — overlay mount, pivot_root, tmpfs/devpts/proc/sysfs mounts
- T1.7 Sandbox manager — create/exec/pause/resume/destroy, teardown order, crash recovery
- T1.8 CLI — doctor/run/ps/exec/pause/resume/destroy/inspect, --json timings
- T1.9 Base image — minimal rootfs (busybox/distroless + python3), < 150 MB, no Docker dep
- T1.10 Benchmarks — lifecycle create/destroy at concurrency 1/10/100/1000

**Teardown order (reverse of acquisition):** cgroup.kill → wait populated=0 → close pidfd →
unmount → remove tmpfs → rmdir cgroup → return uid range → deregister.

**Handoff markers for Phase 2** (leave in `launcher.rs`):
```
// TODO(phase2): prctl(PR_SET_NO_NEW_PRIVS, 1)
// TODO(phase2): drop capability bounding set + clear ambient/inheritable
// TODO(phase2): apply Landlock ruleset, then restrict_self()
// TODO(phase2): install seccomp-bpf filter; send user-notify fd to parent via SCM_RIGHTS
```

---

### Phase 2 — Confinement (Landlock + seccomp + capabilities)

**Goal:** sandbox becomes hostile-code-safe on filesystem and exec. A root-in-userns process
cannot read/write outside declared paths or exec non-allowlisted binaries.

**Estimated:** 6 weeks · Adds Landlock ABI negotiation, seccomp-bpf, capability dropping.

**Definition of done:**
- `tests/hostile.rs` cannot escape via any listed vector
- `no_new_privs` set; setuid binaries gain nothing
- Capability bounding set empty; `capsh --print` shows no caps
- Landlock ABI probed; narrows rights on lower ABI with WARN; refuses if absent unless
  `--insecure-no-landlock`
- seccomp blocks dangerous syscalls; verified per-syscall test
- Policy YAML from blueprint §8.2 parses, compiles, and is enforced
- Confinement inherited across `bash → python → subprocess` (depth 3)
- `bench/escape/fs/` and `bench/escape/exec/`: 0 successful escapes
- Overhead vs Phase 1: < 5 % on open/stat/execve

**Deliverables:**
```
crates/aivisor-policy/        # policy parse + compile
crates/aivisor-runtime/       # extended: landlock.rs, seccomp.rs, caps.rs
bench/escape/                 # escape scenario suite
tests/hostile.rs              # adversarial test binary
```

**Key tasks:**
- T2.1 Policy model and parser — FsPolicy, ExecPolicy, NetPolicy (parsed only, enforced in P3),
  validation rules (deny-by-default, absolute paths, no write to `/`/`/proc`/`/sys`/`/dev`)
- T2.2 Landlock integration — ABI negotiation (1–6), handle ALL access rights for ABI then grant
  selectively, rules built after pivot_root, `restrict_self()` after capability drop
- T2.3 Capability and privilege drop — no_new_privs → clear ambient → drop bounding set →
  capset clear → setresgid/setgroups/setresuid in order
- T2.4 seccomp-bpf profile — default-deny-list (`aivisor-default`) + strict allowlist profile,
  arch validation (deny i386 on x86-64), action choice (KILL_PROCESS vs ERRNO)
- T2.5 Wire into launcher — fill TODO(phase2) markers, ConfinementReport in sync message
- T2.6 Escape benchmark suite — 23+ scenarios across FS/exec/priv categories, harness asserts
  `ESCAPED`/`BLOCKED`, XFAIL(phase3) for known gaps

**Common failure modes:**
1. Fail-open on Landlock error
2. Selective `handle_access` (must handle ALL, grant selectively)
3. Building ruleset in wrong mount namespace
4. Installing seccomp before Landlock
5. Forgetting `no_new_privs`
6. Only checking syscall numbers (must validate arch)
7. Treating exec allowlisting as behavioural control
8. Testing only happy path

**Handoff markers for Phase 3:**
```rust
// TODO(phase3): register cgroup_id in BPF sandbox map BEFORE child unblocked, deny-all
// TODO(phase3): deregister from BPF maps LAST during teardown
```

---

### Phase 3 — eBPF Policy Engine, Network, Audit

**Goal:** in-kernel cgroup-keyed policy enforcement (L5) atop Phase 2, deny-by-default egress
with host-side broker, full audit stream.

**Estimated:** 9 weeks · Hardest phase. Requires CONFIG_BPF_LSM=y, BTF, kernel ≥ 6.1.

**Definition of done:**
- 10 LSM hooks attached and enforcing
- No host interference (< 1 % throughput delta with 100 sandboxes)
- Fail-closed inside (unmatched ⇒ deny)
- Egress deny-by-default; `bench/escape/net/` scores 0
- Broker terminates HTTP(S), enforces host/method/size, injects credentials (never readable
  inside sandbox)
- Audit < 1 % loss at 100k events/s burst, `dropped_count` reported
- `GrantCapability`/`RevokeCapability` propagates < 1 ms p50, < 5 ms p99
- Turn-dirty detection: read-only turn clean, write turn dirty
- Microbenchmark overhead: open() < 3 %, connect() < 5 % vs Phase 2
- Verifier-clean on 6.1, 6.6, 6.12, latest

**Deliverables:**
```
crates/aivisor-bpf/           # eBPF C programs + Rust loader
  src/bpf/*.bpf.c             # one file per concern (fs, exec, net, priv, task)
  src/maps.rs                 # map definitions
  src/loader.rs               # load, attach, pin, lifecycle
crates/aivisor-broker/        # egress proxy + secret injection + SPIFFE
crates/aivisor-policy/        # extended: compile_bpf()
crates/aivisord/              # skeleton: audit pipeline + map ownership
bench/escape/net/             # network escape suite
```

**Key tasks:**
- T3.1 Map contract — `sandboxes` map keyed by cgroup id, generation-swapped policy updates,
  registration ordering (deny-all BEFORE child unblocked)
- T3.2 LSM programs — fs (file_open, path_*), exec (bprm_check_security), net (socket_connect,
  socket_bind, cgroup/connect4/6, cgroup_skb/egress), priv (sb_mount, ptrace, bpf), task
- T3.3 Network policy and broker — loopback-only default, veth+broker mode, TLS termination,
  credential injection, DNS pinning, metadata endpoint blocking, egress budgets
- T3.4 Audit pipeline — BPF RINGBUF → consumer thread → bounded channel → sinks (JSON,
  OTLP, stdout), never block the kernel
- T3.5 Turn-dirty detection — BPF sets DIRTY flag on write/task/socket events, EndTurn
  reads flag + PID count baseline delta
- T3.6 GrantCapability/RevokeCapability — generation-swapped runtime policy changes,
  Landlock widening restrictions documented

**Common failure modes:**
1. Forgetting `if (!ctx) return 0;` → host-wide LSM
2. Fail-open inside → unmatched path allows
3. Deleting map entries before cgroup empty
4. Per-sandbox program loading (programs are global, state in maps)
5. Blocking ring-buffer consumer on slow sink
6. IPv4-only network rules (bypass over IPv6)
7. Trusting HTTP_PROXY (enforce in-kernel)
8. Assuming bpf_d_path() available everywhere
9. Believing eBPF replaces Landlock

---

### Phase 4 — Platform: Daemon, API, Warm Pools, Snapshots, SDKs, Kubernetes

**Goal:** turn runtime into product. gRPC daemon, sub-ms warm acquire, turn-aware checkpoint,
Python/TypeScript SDKs, K8s CRDs, complete hardening.

**Estimated:** 10 weeks.

**Definition of done:**
- `aivisord` serves full SandboxService over unix socket + mTLS TCP
- Warm-pool acquire→Ready p50 < 1 ms, p99 < 3 ms
- Pooled sandboxes are single-use (enforced in type system)
- Workspace snapshot of 100 MB upper layer < 150 ms; byte-identical restore
- CRIU checkpoint/restore with documented supported envelope
- Restore-twice produces independent sandboxes with fresh IDs and SPIFFE identities
- Turn-aware checkpointing reduces I/O by clean-turn fraction
- Python and TypeScript SDKs with 10-line quickstarts
- K8s: `AIVisorSandbox` CR → running sandbox → delete → reclaimed
- All hard gates in blueprint §13 green on reference machine

**Deliverables:**
```
crates/aivisord/              # gRPC, warm pool, scheduler, audit, recovery
crates/aivisor-snapshot/      # overlay archive + CRIU + turn-aware policy
proto/aivisor/v1/             # full IDL
sdk/python/ sdk/typescript/   # SDKs
k8s/                          # Go controller, CRDs, Helm chart
bench/                        # micro, lifecycle, workload, escape, density
docs/                         # rfcs, deployment guide, threat model
```

**Key tasks:**
- T4.1 gRPC daemon — tonic, unix socket + mTLS, idempotency keys, exec bidirectional stream,
  StreamEvents filtering, graceful shutdown
- T4.2 Warm pool — pre-paid cgroup+ns+mount+deny-all BPF entry, atomic policy swap on acquire,
  single-use enforced, background refill, age-out, fallback to cold create
- T4.3 Snapshot manager — workspace archive (content-addressed chunks) + CRIU wrapper,
  supported envelope enforcement, turn-aware policy consuming TurnTracker
- T4.4 SDKs — Python (sync+async, context manager, turn/snapshot/events) + TypeScript
  (promise-based, AsyncIterable) + framework adapters
- T4.5 Kubernetes — Go controller, AIVisorSandbox/SandboxTemplate/WarmPool CRDs, DaemonSet
  with node readiness gate, Helm chart
- T4.6 Complete benchmark suite — workload comparison (pip/pytest/git), density scaling,
  regression gates
- T4.7 Hardening and documentation — SECURITY.md, threat model, deployment guide, security
  review, fuzzing, reproducible builds, relicensing

**Common failure modes:**
1. Reusing pooled sandboxes (cross-tenant leak)
2. Blocking on empty pool instead of cold create fallback
3. Cloning identity on restore (two agents, one SVID)
4. Silent partial CRIU restore
5. Killing sandboxes on daemon restart
6. Publishing benchmarks without machine/kernel
7. Leading docs with performance instead of threat model
8. Shipping v1.0 without external security review

---

## Part III — AI-Assisted Implementation Workflow

### Overview

The phase docs above are designed for an AI model implementing task-by-task. Use the prompts
below to drive sessions.

### Prompt files

| File | Use |
|---|---|
| `00-system.md` | System prompt — prepend to every session |
| `01-phase-kickoff.md` | Starts a phase: verify starting state, produce task plan |
| `02-task-loop.md` | One task per invocation: the workhorse prompt |
| `03-bpf-specialist.md` | Phase 3 eBPF tasks only — extra guardrails for verifier work |
| `04-test-author.md` | Writes adversarial tests — run with a strong model, fresh context |
| `05-gate-review.md` | Phase exit gate review — strong model, adversarial |
| `06-debug.md` | Debugging diagnostics when something fails inexplicably |

### Recommended model allocation

| Work | Model tier | Why |
|---|---|---|
| Scaffolding, types, CLI, SDKs, docs | Cheap | Mechanical, well-specified |
| cgroups, mounts, launcher (P1) | Mid | Fiddly but deterministic; tests catch errors |
| Landlock + seccomp (P2) | Mid, strong review | Fail-open bugs are silent |
| eBPF LSM (P3) | Strong | Verifier fights, host-interference risk |
| Broker + secrets (P3) | Strong | Security-critical, hard to test |
| Escape test suites | Strong | The tests are the deliverable |
| Snapshots (P4) | Mid, strong review | Correctness envelope matters |
| Gate reviews | Strong, fresh context | Must not be the model that wrote the code |

**Do not** let the model that wrote a security control also write its adversarial test.

### Implementation loop

```
for phase in 1..4:
    01-phase-kickoff  → task plan committed
    for task in plan:
        02-task-loop  → implement + unit tests + commit
        (03-bpf-specialist for Phase 3 BPF tasks)
    04-test-author    → adversarial tests, strong model, fresh context
    05-gate-review    → strong model, fresh context, adversarial
    if review fails: back to 02 with the findings
```

### Non-negotiables across every session

1. **Fail closed.** Any error in a security control denies. No `warn!` and continue.
2. **The escape suite is the product.** Implementation exists to pass it.
3. **No unverified performance claims.** A number without kernel+CPU is not a number.
4. **Honest limitations.** blueprint.md §11.4 is load-bearing documentation.
5. **Never widen privilege at runtime** except through audited `GrantCapability`.

---

## Part IV — Beyond Phase 4

Ordered by expected value:

1. **Nested mode** — one microVM per tenant, N sandboxes inside. Ship Firecracker/Kata
   composition as a supported topology.
2. **`ASK` verb** — seccomp user-notify escalation to userspace/human for decisions that
   cannot be pre-declared.
3. **Policy learning** — observe fleet behaviour, propose least-privilege policies,
   human-approve.
4. **GPU sandboxes** — device cgroup + DeviceCap + CRIU implications.
5. **`sched_ext`** — agent-cgroup-derived scheduling, once kernel API stabilises.
6. **Confidential computing** — SEV-SNP / TDX to protect agent from host.

---

## Appendix A — Kernel compatibility matrix

| Kernel | cgroup v2 | clone3 | CLONE_INTO_CGROUP | cgroup.kill | Landlock ABI | overlayfs in userns | BPF LSM |
|---|---|---|---|---|---|---|---|
| 6.1 | ✓ | ✓ | ✓ | ✓ | 3 | ✓ | ✓ |
| 6.6 | ✓ | ✓ | ✓ | ✓ | 3 | ✓ | ✓ |
| 6.12 | ✓ | ✓ | ✓ | ✓ | 6 | ✓ | ✓ |

All features are probed by attempting the operation, never parsed from `uname`.

## Appendix B — Reference resources

- `blueprint.md` — full architecture document (authoritative)
- `crates/aivisor-core/src/` — shared types, errors, IDs, policy model
- `crates/aivisor-runtime/src/` — namespaces, cgroups, mounts, landlock, seccomp, launcher
- `crates/aivisor-bpf/src/` — eBPF C programs + Rust loader
- `crates/aivisor-policy/src/` — policy parse → landlock + bpf + seccomp plans
- `crates/aivisor-broker/src/` — egress proxy, secret injection, SPIFFE
- `crates/aivisor-snapshot/src/` — overlay archive, CRIU, turn-aware checkpointing
- `crates/aivisord/src/` — gRPC daemon, warm pool, audit pipeline
- `crates/aivisor-cli/src/` — `aivisor` binary
- `tests/` — integration tests (privileged)
- `bench/` — performance benchmarks across suites
- `docs/` — threat model, deployment guide, RFCs
