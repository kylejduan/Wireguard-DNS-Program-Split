// SPDX-License-Identifier: GPL-3.0-or-later
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
#define AF_PACKET 17
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_MARK 36

#define WGPS_BPF 1
#include "policy.bpf.h"

SEC("lsm_cgroup/socket_post_create")
int BPF_PROG(classify, struct socket *sock, int family, int type, int protocol, int kern)
{
    (void)ctx;
    /* Cgroup LSM: 1 grants, 0 denies. Another granting attachment can weaken
     * denial, so the loader rejects existing effective/subtree LSM attachments. */
    if (kern || (family != AF_INET && family != AF_INET6 && family != AF_PACKET))
        return 1;
    int selection = policy_select();
    if (selection != INCLUDED)
        return result(selection, selection == DIRECT || selection == UNSUPPORTED_CONTEXT);
    __u32 zero = 0;
    struct policy_config *cfg = bpf_map_lookup_elem(&policy_cfg, &zero);
    if (!cfg) return result(BLOCKED, 0);
    if (family != AF_INET || (type != SOCK_STREAM && type != SOCK_DGRAM) ||
        (protocol != 0 && protocol != 6 && protocol != 17))
        return result(UNSUPPORTED_SOCKET, 0);
    if (!cfg->ready) return result(BLOCKED, 0);
    /* Direct CO-RE access retains the verifier's socket pointer type. */
    struct sock *sk = sock->sk;
    if (!sk) return result(SOCKOPT_ERROR, 0);
    __u32 mark = 0;
    if (bpf_getsockopt(sk, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)))
        return result(SOCKOPT_ERROR, 0);
    mark = (mark & ~cfg->mask) | cfg->mark;
    if (bpf_setsockopt(sk, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)))
        return result(SOCKOPT_ERROR, 0);
    return result(INCLUDED, 1);
}

#include "resolver_guard.bpf.c"

char LICENSE[] SEC("license") = "GPL";
