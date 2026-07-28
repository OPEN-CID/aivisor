/* AIVisor network BPF LSM + cgroup-BPF programs.
 *
 * Hooks: lsm/socket_connect, lsm/socket_bind,
 *        cgroup/connect4, cgroup/connect6
 *
 * Deny-by-default egress. Metadata endpoints are blocked unconditionally
 * (169.254.169.254, fd00:ec2::254, 168.63.129.16).
 *
 * Why both lsm/socket_connect AND cgroup/connect4|6: lsm/socket_connect
 * fires for connect() on a stream/dgram socket generally, but a UDP
 * sendto() on an unconnected socket never calls the kernel's
 * security_socket_connect() at all — it goes through a different path.
 * cgroup/connect4|6 (BPF_CGROUP_INET4_CONNECT / INET6_CONNECT) close that
 * gap: they fire for the connect-like address resolution both connect()
 * and connectionless send paths go through when a socket belongs to the
 * attached cgroup. Belt-and-braces by design (blueprint §9.1 / roadmap.md
 * Phase 3 failure mode #7: "trusting HTTP_PROXY (enforce in-kernel)").
 *
 * IPv6 honest limitation: `struct net_key.addr` is a `__u32` (IPv4-only in
 * v1 — see common.h). Matching specific IPv6 destinations against policy
 * would need the map extended to a 128-bit key, and encoding the exact
 * per-word byte layout of `bpf_sock_addr.user_ip6` correctly is not
 * something this change can verify without a real kernel + verifier run.
 * Rather than ship an address comparison that might silently never match
 * (looks like enforcement, provides none), IPv6 is denied unconditionally
 * here. That is a real restriction (no IPv6 egress at all, not "IPv6
 * egress with policy"), not a bypass — it satisfies blueprint §13's
 * required "IPv6 bypass of an IPv4 allowlist" escape scenario by
 * construction. Fully expressing IPv6 net policy is TODO(phase3).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Cloud metadata endpoints — blocked unconditionally. */
#define META_169_254_169_254 0xfea9fea9  /* 169.254.169.254 in network byte order */
#define META_168_63_129_16   0x10813fa8  /* 168.63.129.16 */

static __always_inline int check_ipv4_dst(__u64 cgid, struct sandbox_ctx *ctx, __u32 dst_be, __u16 port)
{
    if (dst_be == META_169_254_169_254 || dst_be == META_168_63_129_16) {
        emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
        return 0; /* deny */
    }

    struct net_key key = { .prefixlen = 32, .addr = dst_be };
    __u64 *ports = bpf_map_lookup_elem(&net_rules, &key);
    if (!ports) {
        emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
        return 0; /* no rule for this destination at all: deny by default */
    }

    /* Port bitmap only expresses ports 0-63 (one bit each) in v1. A port
     * outside that range has no way to be represented as "allowed", so it
     * fails closed rather than being silently treated as allowed. */
    if (port >= 64 || !((*ports >> port) & 1ULL)) {
        emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
        return 0;
    }

    emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_ALLOW, 0);
    return 1; /* allow */
}

SEC("lsm/socket_connect")
int BPF_PROG(aivisor_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *ctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!ctx)
        return 0;
    if (!(ctx->flags & FLAG_ENFORCING))
        return 0;

    if (!address)
        return -EPERM;

    __u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        __u32 sin_addr;
        __u16 sin_port;
        bpf_probe_read_kernel(&sin_addr, sizeof(sin_addr), &addr4->sin_addr);
        bpf_probe_read_kernel(&sin_port, sizeof(sin_port), &addr4->sin_port);

        int allowed = check_ipv4_dst(cgid, ctx, sin_addr, bpf_ntohs(sin_port));
        return allowed ? 0 : -EPERM;
    }
    else if (family == AF_INET6) {
        /* See file header: IPv6 destination matching is not implemented,
         * denied unconditionally rather than risk a silently-broken check. */
        emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
        return -EPERM;
    }
    else if (family == AF_UNIX) {
        /* AF_UNIX: IPC namespace handles scoping. */
        return 0;
    }
    else {
        /* AF_PACKET, AF_NETLINK, AF_XDP, etc. — all denied. */
        emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
        return -EPERM;
    }
}

SEC("lsm/socket_bind")
int BPF_PROG(aivisor_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *ctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!ctx)
        return 0;
    if (!(ctx->flags & FLAG_ENFORCING))
        return 0;

    if (!address)
        return -EPERM;

    __u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    /* "Only allow loopback binds" (this hook's actual purpose: prevent a
     * sandbox from standing up an unexpected listener reachable from
     * outside its own netns/loopback). */
    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        __u32 sin_addr;
        bpf_probe_read_kernel(&sin_addr, sizeof(sin_addr), &addr4->sin_addr);
        /* 127.0.0.1 in network byte order == 0x0100007f. Any 127.0.0.0/8
         * address would ideally be matched via a prefix check; the single
         * canonical loopback address is matched exactly here as the common
         * case, consistent with the rest of v1's exact-match style. */
        if (sin_addr == 0x0100007f) {
            emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_ALLOW, 0);
            return 0;
        }
        emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
        return -EPERM;
    }
    else if (family == AF_UNIX) {
        /* AF_UNIX binds (a listen socket path) are scoped by the mount/IPC
         * namespace and Landlock's filesystem rules already; not a network
         * exposure concern the way AF_INET/AF_INET6 binds are. */
        return 0;
    }

    emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
    return -EPERM;
}

/* cgroup/connect4 and cgroup/connect6 are attached per-sandbox-cgroup at
 * sandbox creation (unlike the lsm/* programs above, which load once,
 * globally, at daemon start) — see aivisor-bpf::loader. Return 1 to allow,
 * 0 to deny (the kernel synthesizes EPERM for the caller on a 0 return).
 */
SEC("cgroup/connect4")
int aivisor_cgroup_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 1; /* not an aivisor-managed cgroup — do not interfere */
    if (!(sctx->flags & FLAG_ENFORCING))
        return 1;

    __u16 port = bpf_ntohs((__u16)ctx->user_port);
    return check_ipv4_dst(cgid, sctx, ctx->user_ip4, port);
}

SEC("cgroup/connect6")
int aivisor_cgroup_connect6(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    struct sandbox_ctx *sctx = bpf_map_lookup_elem(&sandboxes, &cgid);
    if (!sctx)
        return 1;
    if (!(sctx->flags & FLAG_ENFORCING))
        return 1;

    /* See file header: IPv6 is denied unconditionally in v1. */
    emit_event(cgid, EVT_KIND_CONNECT, EVT_DECISION_DENY, EPERM);
    return 0;
}
