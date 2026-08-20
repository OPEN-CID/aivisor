/* AIVisor exec BPF LSM program.
 *
 * Hook: lsm/bprm_check_security  — called on every execve/execveat.
 * Checks the binary inode against the exec allowlist.
 *
 * `exec_rule.hash` is NOT consulted here, and this hook makes no integrity
 * claim about the bytes being executed. Hashing a file is not something an
 * LSM hook can do — there is no helper to read a whole file from BPF
 * context. A `sha256:` pin in policy is verified once, in userspace, when
 * the rule is resolved to (dev, inode) at install time
 * (aivisor-bpf::maps::verify_sha256_pin); the hash travels into the map for
 * audit only. A binary rewritten in place after installation keeps its
 * inode and still executes.
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
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;
    if (!(sctx->flags & FLAG_ENFORCING))
        return 0;

    /* Get the file's inode and device. */
    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &bprm->file);
    if (!file)
        return -EPERM;

    /* What this hook can see, on an overlay rootfs, is the REAL file.
     *
     * `bprm->file` for an execve through overlayfs is the underlying
     * upper- or lower-layer file, not the overlay entry: both
     * `f_inode->i_sb` and `f_path.mnt->mnt_sb` resolve to the underlying
     * filesystem. Measured on Ubuntu 24.04 / 6.8.0 with a binary staged in
     * the upper layer: this hook observes (dev 48, ino 11340) via either
     * route, while the sandbox's own `stat(2)` on the same path reports
     * (dev 49, ino 11340) — 49 being the overlay mount, 48 the tmpfs
     * holding the upper layer. The inode agrees; the device does not.
     *
     * So exec rules must be built from the layer files as the HOST sees
     * them (aivisor-runtime resolves upper-then-lower, mirroring overlay
     * lookup), never from a stat taken inside the sandbox. See
     * `SandboxManager::resolve_exec_identities`.
     *
     * Each hop is its own probe read: `file` came out of a probe read and
     * is an untrusted scalar to the verifier, so an address expression
     * walking through it compiles to a direct load that the verifier
     * rejects with "invalid mem access 'scalar'".
     */
    struct inode *inode;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return -EPERM;

    struct super_block *sb;
    bpf_core_read(&sb, sizeof(sb), &inode->i_sb);
    if (!sb)
        return -EPERM;

    __u64 inode_nr;
    bpf_core_read(&inode_nr, sizeof(inode_nr), &inode->i_ino);

    /* s_dev is a dev_t, i.e. 32 bits. Reading 8 bytes here would pull in
     * whatever follows it in struct super_block as the high half, so the
     * value could never equal the (dev, inode) pair userspace installed
     * and every exec would be denied. */
    __u32 dev32;
    bpf_core_read(&dev32, sizeof(dev32), &sb->s_dev);
    __u64 dev = dev32;

    __u32 base = sctx->exec_rules_base;
    __u32 end = sctx->exec_rules_base + sctx->exec_rules_count;
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
    sctx->flags |= FLAG_DIRTY;

    emit_event(cgid, EVT_KIND_EXEC, EVT_DECISION_ALLOW, 0);
    return 0;
}
