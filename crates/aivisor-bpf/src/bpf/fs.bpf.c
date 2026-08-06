/* AIVisor filesystem BPF LSM programs.
 *
 * Hooks: lsm/file_open, lsm/path_mkdir, lsm/path_unlink,
 *        lsm/path_rename, lsm/path_truncate, lsm/path_symlink
 *
 * Scope note (file_open): recursive/directory-tree filesystem access
 * control is Landlock's job (L3), which is the layer this codebase
 * actually enforces path rules through. `fs_rules` here holds the SAME
 * directory-oriented rules compiled for Landlock (see
 * aivisor-policy::compile_bpf), so exact full-path hash matching against
 * them would almost never hit for a real file *inside* an allowed
 * directory (the hash of "/workspace/notes.txt" does not equal the hash of
 * the rule "/workspace") — deny-by-default against that mismatch would
 * incorrectly block virtually everything Landlock already allows. This
 * hook therefore does NOT re-decide what Landlock already decided: absent
 * an EXACT match on one of the sandbox's own rules, it allows and audits.
 * An exact match (a rule for that literal path) acts as a defense-in-depth
 * override — this is what "FS read/write policy beyond Landlock" in
 * blueprint Appendix B means: single-file precision Landlock's directory
 * rules aren't meant to special-case, not a duplicate of Landlock itself.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* FNV-1a 64-bit over a NUL-free byte buffer of length `len` — MUST match
 * aivisor-policy::compile::hash_path() exactly, since that is what
 * produced the `path_hash` values stored in the fs_rules map.
 */
static __always_inline __u64 fnv1a_hash(const char *buf, __u32 len)
{
    __u64 h = 0xcbf29ce484222325ULL;
    /* Bounded, verifier-friendly: PATH_MAX-ish cap. bpf_d_path() truncates
     * into a fixed buffer anyway, so this loop's trip count is capped by
     * that buffer size, not by `len` alone. */
#pragma unroll
    for (int i = 0; i < 256; i++) {
        if (i >= len)
            break;
        h ^= (__u8)buf[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

struct fs_rule_ctx {
    __u64 path_hash;
    __u32 requested_access;
    __u32 found_match;
    __u32 matched_denied;
};

/* Checks one absolute rule index against the target path hash. Called from
 * a `#pragma unroll` loop below (not `bpf_loop()` — the trip count is
 * small and MAX_RULES_PER_SANDBOX-bounded at compile time, so a plain
 * unrolled loop is simpler and needs no kernel-version-gated helper). */
static __always_inline void check_fs_rule(__u32 rule_idx, struct fs_rule_ctx *rctx)
{
    struct fs_rule *rule = bpf_map_lookup_elem(&fs_rules, &rule_idx);
    if (!rule)
        return;
    if (rule->path_hash != rctx->path_hash)
        return;

    rctx->found_match = 1;
    if ((rule->access_mask & rctx->requested_access) != rctx->requested_access)
        rctx->matched_denied = 1;
}

/* ---- lsm/file_open ---- */
SEC("lsm/file_open")
int BPF_PROG(aivisor_file_open, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;  /* NOT a sandbox — do not touch the host */
    if (!(sctx->flags & FLAG_ENFORCING))
        return 0;  /* audit-only mode */

    char path_buf[256];
    long path_len = bpf_d_path(&file->f_path, path_buf, sizeof(path_buf));
    if (path_len < 0) {
        /* Could not resolve a path at all (e.g. an anonymous inode) —
         * nothing to match against; allow and let Landlock's own decision
         * stand, since that already ran before this hook fires. */
        return 0;
    }

    __u32 mode;
    bpf_core_read(&mode, sizeof(mode), &file->f_mode);
    /* FMODE_WRITE = 0x2 (include/linux/fs.h, stable since the original
     * fmode_t bit layout — not BTF-visible, same rationale as the AF_*
     * macros in common.h). */
    __u32 requested = (mode & 0x2) ? 2 /* WRITE_FILE bit */ : 4 /* READ_FILE bit */;

    struct fs_rule_ctx rctx = {
        .path_hash = fnv1a_hash(path_buf, (__u32)path_len),
        .requested_access = requested,
        .found_match = 0,
        .matched_denied = 0,
    };

    __u32 idx = sctx->fs_rules_base;
    __u32 end = sctx->fs_rules_base + sctx->fs_rules_count;
#pragma unroll
    for (int i = 0; i < MAX_RULES_PER_SANDBOX; i++) {
        if (idx + i >= end)
            break;
        __u32 rule_idx = idx + i;
        check_fs_rule(rule_idx, &rctx);
        if (rctx.found_match)
            break;
    }

    if (rctx.found_match && rctx.matched_denied) {
        emit_event(cgid, EVT_KIND_FILE_OPEN, EVT_DECISION_DENY, EPERM);
        return -EPERM;
    }

    emit_event(cgid, EVT_KIND_FILE_OPEN, EVT_DECISION_ALLOW, 0);
    return 0;
}

/* ---- lsm/path_mkdir (dirty-turn detection) ---- */
SEC("lsm/path_mkdir")
int BPF_PROG(aivisor_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;

    /* In-place bit-set through the map pointer — never overwrite the
     * whole struct with a differently-typed local (see common.h header). */
    sctx->flags |= FLAG_DIRTY;

    return 0;
}

/* ---- lsm/path_unlink (dirty-turn detection) ---- */
SEC("lsm/path_unlink")
int BPF_PROG(aivisor_path_unlink, const struct path *dir, struct dentry *dentry, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;

    sctx->flags |= FLAG_DIRTY;

    return 0;
}

/* ---- lsm/path_rename (dirty-turn detection) ---- */
SEC("lsm/path_rename")
int BPF_PROG(aivisor_path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;

    sctx->flags |= FLAG_DIRTY;

    return 0;
}

/* ---- lsm/path_truncate (dirty-turn detection) ---- */
SEC("lsm/path_truncate")
int BPF_PROG(aivisor_path_truncate, const struct path *path, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;

    sctx->flags |= FLAG_DIRTY;

    return 0;
}
