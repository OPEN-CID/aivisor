/* AIVisor BPF common header — shared types and maps.
 *
 * The mandatory preamble pattern for every LSM program:
 *
 *   __u64 cgid = bpf_get_current_cgroup_id();
 *   struct sandbox_ctx *ctx = bpf_map_lookup_elem(&sandboxes, &cgid);
 *   if (!ctx) return 0;            // NOT a sandbox — do not touch the host
 *   if (!(ctx->flags & FLAG_ENFORCING)) return 0;  // audit-only mode
 *
 * After that, every unmatched path returns -EPERM.
 *
 * To set a flag bit (e.g. FLAG_DIRTY) on an existing entry, mutate through
 * the pointer `bpf_map_lookup_elem` returns (`ctx->flags |= FLAG_DIRTY;`)
 * rather than calling `bpf_map_update_elem` with a differently-typed local —
 * the verifier allows in-place writes through a HASH map value pointer, and
 * this is the only form that cannot corrupt the other fields of the struct
 * (sandbox_seq, policy_gen, rule indices, turn_id) by overwriting the whole
 * map slot with a partial value of the wrong size/type.
 */

#ifndef __AIVISOR_BPF_COMMON_H
#define __AIVISOR_BPF_COMMON_H

/* AF_* and EPERM are preprocessor macros in the kernel's own headers
 * (include/linux/socket.h, include/uapi/asm-generic/errno-base.h), not BTF
 * enums — vmlinux.h is generated from BTF and does NOT carry preprocessor
 * macros, so these are not available just by including it. Values below
 * are long-stable parts of the Linux ABI (unchanged since the original
 * socket API) and are safe to hardcode rather than depend on a kernel
 * header path that may not be available in the BPF build environment.
 */
#define EPERM 1
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

#define FLAG_ENFORCING   1
#define FLAG_DIRTY       2
#define FLAG_KILL_PENDING 4

#define MAX_PATH_DEPTH   16
#define MAX_RULES        1024
/* Upper bound for bpf_loop() iteration over a sandbox's own rule range.
 * Rule *storage* (fs_rules/exec_rules/net_rules maps) can hold MAX_RULES
 * entries total across all sandboxes; MAX_RULES_PER_SANDBOX bounds how many
 * of those any single sandbox's ruleset may span, which is what the
 * verifier needs a static bound on for the bpf_loop() callback below.
 */
#define MAX_RULES_PER_SANDBOX 64

/* Per-sandbox context — exactly one entry keyed by cgroup id.
 *
 * Rule ranges are [base, base+count) into the corresponding rule map,
 * assigned contiguously by the policy compiler/loader (aivisor-bpf's
 * BpfManager) when a sandbox's policy is installed. A single `_idx` field
 * (the previous shape) could only ever reference one rule, which made any
 * policy with more than one filesystem/exec/network rule silently only
 * enforce its first entry.
 *
 * MUST match `SandboxCtx` in aivisor-bpf/src/maps.rs field-for-field.
 */
struct sandbox_ctx {
    __u64  sandbox_seq;
    __u32  flags;
    __u32  policy_gen;
    __u32  fs_rules_base;
    __u32  fs_rules_count;
    __u32  exec_rules_base;
    __u32  exec_rules_count;
    __u32  net_rules_base;
    __u32  net_rules_count;
    __u64  turn_id;
};

/* Filesystem rule entry: exact full-path hash + access mask.
 *
 * Scope note: this is intentionally NOT a directory-prefix/recursive
 * matcher. Recursive path-tree access control is Landlock's job (L3) —
 * blueprint.md §5.3/§8.3: "If Landlock alone would be sufficient for a
 * rule, it goes in Landlock; eBPF is for what Landlock cannot express."
 * This hook exists for exact-path defense-in-depth and audit, matched by
 * hashing the fully-resolved path exactly as fs_path_hash() below builds
 * it, which MUST use the same algorithm as `hash_path()` in
 * aivisor-policy/src/compile.rs (FNV-1a 64) for any rule to ever match.
 */
struct fs_rule {
    __u64 path_hash;
    __u64 access_mask;
};

/* Exec rule entry: (dev, inode) of allowed binary. Exact match — no path
 * reconstruction needed or attempted here, unlike fs_rule.
 */
struct exec_rule {
    __u64 dev;
    __u64 inode;
    __u8  hash[32];  /* SHA-256 pin, all-zero if not pinned */
};

/* Network rule entry: LPM trie key + port bitmap (bit N set = port N
 * allowed, for N in 0..64; ports >= 64 are not expressible in v1 — see
 * net.bpf.c for the fail-closed behaviour on such a port).
 */
struct net_key {
    __u32 prefixlen;
    __u32 addr;       /* IPv4 only in v1 — see net.bpf.c for the IPv6 note */
};

/* BPF maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);              /* cgroup id */
    __type(value, struct sandbox_ctx);
} sandboxes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);              /* rule index */
    __type(value, struct fs_rule);
} fs_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct exec_rule);
} exec_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct net_key);
    __type(value, __u64);            /* port bitmap */
} net_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);  /* 8 MB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} scratch SEC(".maps");

/* Audit/decision event, mirrored on the userspace side by
 * aivisord's Event (proto/aivisor/v1/aivisor.proto) — kind/decision use the
 * same small integer encodings so the consumer doesn't need a translation
 * table.
 */
#define EVT_KIND_FILE_OPEN  0
#define EVT_KIND_EXEC       1
#define EVT_KIND_CONNECT    2
#define EVT_KIND_MOUNT      3
#define EVT_KIND_POLICY_DENY 4
#define EVT_KIND_LIFECYCLE  6

#define EVT_DECISION_ALLOW  0
#define EVT_DECISION_DENY   1
#define EVT_DECISION_NOTIFY 2
#define EVT_DECISION_KILL   3

struct aivisor_event {
    __u64 cgid;
    __u64 ts_ns;
    __u32 pid;
    __u32 kind;
    __u32 decision;
    __u32 errno_val;
};

static __always_inline void emit_event(__u64 cgid, __u32 kind, __u32 decision, __u32 errno_val)
{
    struct aivisor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return; /* ring full — audit loss is tracked by the consumer's
                  * dropped_count, not by blocking or failing the syscall
                  * (blueprint §12: StreamEvents must drop with an explicit
                  * count rather than blocking the kernel ring consumer). */
    e->cgid = cgid;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->kind = kind;
    e->decision = decision;
    e->errno_val = errno_val;
    bpf_ringbuf_submit(e, 0);
}

/* Request the whole sandbox be torn down (blueprint §8.5 KILL verb). An LSM
 * hook cannot itself invoke `cgroup.kill` synchronously against its own
 * cgroup — that is a write to a cgroupfs control file, not something
 * reachable from BPF context. What it CAN do: block the immediate
 * operation (the caller still returns -EPERM) and set FLAG_KILL_PENDING +
 * emit a KILL-decision event; a privileged userspace consumer watching the
 * ringbuf (aivisord's audit pipeline) is responsible for actually calling
 * cgroup.kill on cgid in response. This mutates through the map pointer
 * in place — see the file header note on why that matters.
 */
static __always_inline void request_kill(struct sandbox_ctx *ctx, __u64 cgid, __u32 kind)
{
    ctx->flags |= FLAG_KILL_PENDING;
    emit_event(cgid, kind, EVT_DECISION_KILL, 0);
}

#endif /* __AIVISOR_BPF_COMMON_H */
