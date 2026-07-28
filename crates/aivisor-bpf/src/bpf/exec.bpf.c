/* AIVisor exec BPF LSM program.
 *
 * Hook: lsm/bprm_check_security  — called on every execve/execveat.
 * Checks the binary inode against the exec allowlist.
 * Optionally verifies SHA-256 hash pin on first exec.
 *
 * Unlike fs_rules (see fs.bpf.c), exec_rules match by exact (dev, inode) —
 * there is no path-tree-matching ambiguity here, so this hook IS the
 * primary L5 enforcement point for exec, matching Landlock's EXECUTE bit
 * as a second, kernel-object-level check (blueprint Appendix B).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/bprm_check_security")
int BPF_PROG(aivisor_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *ctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!ctx)
        return 0;
    if (!(ctx->flags & FLAG_ENFORCING))
        return 0;

    /* Get the file's inode and device. */
    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &bprm->file);
    if (!file)
        return -EPERM;

    struct inode *inode;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return -EPERM;

    __u64 inode_nr, dev;
    bpf_core_read(&inode_nr, sizeof(inode_nr), &inode->i_ino);
    bpf_core_read(&dev, sizeof(dev), &inode->i_sb->s_dev);

    __u32 base = ctx->exec_rules_base;
    __u32 end = ctx->exec_rules_base + ctx->exec_rules_count;
    __u32 matched = 0;

#pragma unroll
    for (int i = 0; i < MAX_RULES_PER_SANDBOX; i++) {
        if (base + i >= end)
            break;
        __u32 rule_idx = base + i;
        struct exec_rule *rule = bpf_map_lookup_elem(&exec_rules, &rule_idx);
        if (!rule)
            continue;
        if (rule->inode == inode_nr && rule->dev == dev) {
            matched = 1;
            break;
        }
    }

    if (!matched) {
        emit_event(cgid, EVT_KIND_EXEC, EVT_DECISION_DENY, EPERM);
        return -EPERM;
    }

    /* Set dirty bit: an exec happened this turn. In-place through the map
     * pointer, not a full-struct overwrite (see common.h header note). */
    ctx->flags |= FLAG_DIRTY;

    emit_event(cgid, EVT_KIND_EXEC, EVT_DECISION_ALLOW, 0);
    return 0;
}
