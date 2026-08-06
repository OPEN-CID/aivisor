/* AIVisor task lifecycle BPF LSM programs.
 *
 * Hooks: lsm/task_alloc — called when a new task is created.
 *        lsm/task_free  — called when a task exits.
 *
 * Used for PID accounting and propagating sandbox context.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/task_alloc")
int BPF_PROG(aivisor_task_alloc, struct task_struct *task, unsigned long clone_flags, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 0;

    /* Mark turn dirty when a new process survives (fork). In-place through
     * the map pointer — never overwrite the whole struct with a
     * differently-typed local (see common.h header note: the previous
     * form here wrote a bare __u32 into a map slot typed struct
     * sandbox_ctx, corrupting every other field — sandbox_seq,
     * policy_gen, all three rule ranges, turn_id — with whatever else
     * happened to be on the stack). */
    sctx->flags |= FLAG_DIRTY;

    return 0;
}
