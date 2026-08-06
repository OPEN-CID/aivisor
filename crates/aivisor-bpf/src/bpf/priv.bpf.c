/* AIVisor privilege-escalation BPF LSM programs.
 *
 * Hooks: lsm/sb_mount, lsm/ptrace_access_check, lsm/bpf,
 *        lsm/kernel_load_data, lsm/kernel_module_request
 *
 * bpf / kernel_load_data / kernel_module_request use the KILL verb
 * (blueprint §8.5, Appendix B) for unambiguous attack signals. An LSM hook
 * cannot itself invoke `cgroup.kill` — see request_kill() in common.h —
 * so KILL here means: block the immediate call AND flag the sandbox for
 * teardown by the userspace audit consumer. sb_mount and
 * ptrace_access_check stay BLOCK-only per Appendix B; they're routine
 * denials (Landlock/namespace/exec-scope violations any confined process
 * will hit sometimes), not by-construction attack signals the way loading
 * a kernel module from inside a sandbox is.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/sb_mount")
int BPF_PROG(aivisor_sb_mount, const struct path *path, const char *dev_name,
             unsigned long flags, void *data, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;
    if (!(sctx->flags & FLAG_ENFORCING))
        return 0;

    /* Deny all mounts from sandbox tasks. Landlock already covers this,
     * but belt-and-braces at L5. */
    emit_event(cgid, EVT_KIND_MOUNT, EVT_DECISION_DENY, EPERM);
    return -EPERM;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(aivisor_ptrace_access_check, struct task_struct *child, unsigned int mode, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;
    if (!(sctx->flags & FLAG_ENFORCING))
        return 0;

    /* Deny cross-process inspection. */
    emit_event(cgid, EVT_KIND_POLICY_DENY, EVT_DECISION_DENY, EPERM);
    return -EPERM;
}

SEC("lsm/bpf")
int BPF_PROG(aivisor_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;
    if (!(sctx->flags & FLAG_ENFORCING))
        return 0;

    /* KILL: BPF from inside a sandbox is an unambiguous attack. */
    request_kill(sctx, cgid, EVT_KIND_POLICY_DENY);
    return -EPERM;
}

SEC("lsm/kernel_load_data")
int BPF_PROG(aivisor_kernel_load_data, enum kernel_load_data_id id, bool contents, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;
    if (!(sctx->flags & FLAG_ENFORCING))
        return 0;

    request_kill(sctx, cgid, EVT_KIND_POLICY_DENY);
    return -EPERM;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(aivisor_kernel_module_request, const char *fmt, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;
    if (!(sctx->flags & FLAG_ENFORCING))
        return 0;

    request_kill(sctx, cgid, EVT_KIND_POLICY_DENY);
    return -EPERM;
}
