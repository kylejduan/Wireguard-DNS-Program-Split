// SPDX-License-Identifier: GPL-2.0
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* ABI v1 is mirrored in bpf-loader.cpp; map sizes are verified before updates. */
#define PATH_BYTES 4096
#define AF_INET 2
#define AF_INET6 10
#define AF_PACKET 17
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_MARK 36

struct path_key { char pathname[PATH_BYTES]; };
struct path_scratch { struct path_key key; char resolved[PATH_BYTES]; };
struct configuration {
    __u32 abi, ready, mask, mark;
    __u64 root_dev, root_ino;
    __u32 netns, userns;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct path_key);
    __type(value, __u32);
} paths SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct configuration);
} policy_cfg SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_scratch);
} scratch SEC(".maps");
enum reason {
    DIRECT, INCLUDED, BLOCKED, UNSUPPORTED_CONTEXT, EXE_ERROR,
    PATH_ERROR, UNLINKED_IMAGE, UNSUPPORTED_SOCKET, SOCKOPT_ERROR, REASONS
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, REASONS);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;
extern int bpf_path_d_path(const struct path *path, char *buf, size_t size) __ksym;

static __always_inline int result(__u32 reason, int allow)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &reason);
    if (count) __sync_fetch_and_add(count, 1);
    return allow;
}

static __always_inline bool linked_file(struct file *file)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    const struct dentry_operations *ops = BPF_CORE_READ(dentry, d_op);
    /* Check actual identity, never strip a textual " (deleted)" suffix. */
    return inode && BPF_CORE_READ(inode, i_nlink) &&
           BPF_CORE_READ(dentry, d_hash.pprev) &&
           (!ops || !BPF_CORE_READ(ops, d_dname));
}

SEC("lsm_cgroup/socket_post_create")
int BPF_PROG(classify, struct socket *sock, int family, int type, int protocol, int kern)
{
    (void)ctx;
    /* Cgroup LSM: 1 grants, 0 denies. Another granting attachment can weaken
     * denial, so the loader rejects existing effective/subtree LSM attachments. */
    if (kern || (family != AF_INET && family != AF_INET6 && family != AF_PACKET))
        return 1;
    __u32 zero = 0;
    struct configuration *cfg = bpf_map_lookup_elem(&policy_cfg, &zero);
    if (!cfg || cfg->abi != 1) return result(BLOCKED, 0);
    struct task_struct *task = bpf_get_current_task_btf();
    struct inode *root = BPF_CORE_READ(task, fs, root.dentry, d_inode);
    if (BPF_CORE_READ(root, i_ino) != cfg->root_ino ||
        BPF_CORE_READ(root, i_sb, s_dev) != cfg->root_dev ||
        BPF_CORE_READ(task, nsproxy, net_ns, ns.inum) != cfg->netns ||
        BPF_CORE_READ(task, cred, user_ns, ns.inum) != cfg->userns)
        return result(UNSUPPORTED_CONTEXT, 1);
    struct file *exe = bpf_get_task_exe_file(task);
    if (!exe) return result(EXE_ERROR, 0);
    if (!linked_file(exe)) {
        bpf_put_file(exe);
        return result(UNLINKED_IMAGE, 0);
    }
    struct path_scratch *work = bpf_map_lookup_elem(&scratch, &zero);
    if (!work) {
        bpf_put_file(exe);
        return result(PATH_ERROR, 0);
    }
    /* No cross-socket cache: every creation resolves the current path. */
    /* clang's BPF backend does not lower a 4096-byte builtin memset. */
#pragma clang loop unroll(full)
    for (int i = 0; i < PATH_BYTES / 8; i++)
        ((volatile __u64 *)&work->key)[i] = 0;
    int len = bpf_path_d_path(&exe->f_path, work->resolved, sizeof(work->resolved));
    bool linked = linked_file(exe);
    bpf_put_file(exe);
    if (!linked) return result(UNLINKED_IMAGE, 0);
    if (len <= 1 || len > PATH_BYTES || work->resolved[0] != '/')
        return result(PATH_ERROR, 0);
    /* d_path initially writes at the end, then memmoves: its tail is NOT zero.
     * Copy only the terminated string into the zero-padded hash key. */
    if (bpf_probe_read_kernel_str(work->key.pathname, PATH_BYTES, work->resolved) != len)
        return result(PATH_ERROR, 0);
    __u32 *selected = bpf_map_lookup_elem(&paths, &work->key);
    if (!selected) return result(DIRECT, 1);
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

char LICENSE[] SEC("license") = "GPL";
