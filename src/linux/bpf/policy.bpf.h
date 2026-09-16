// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef WGPS_POLICY_BPF_H
#define WGPS_POLICY_BPF_H
#ifndef WGPS_BPF
#include <linux/types.h>
#endif
#define POLICY_ABI 3
#define PATH_BYTES 4096
#define SHORT_PATH_BYTES 256
struct policy_path { char pathname[PATH_BYTES]; };
struct policy_short_path { char pathname[SHORT_PATH_BYTES]; };
struct path_scratch { struct policy_path key; char resolved[PATH_BYTES]; };
struct policy_config {
    __u32 version, ready, mask, mark;
    __u64 root_dev, root_ino;
    __u32 netns, userns;
};

/* Namespace, filesystem and sockfs identities are deliberately separate. */
struct object_id { __u64 dev, ino; };
struct guard_slot { struct object_id parent; char name[64]; };
struct endpoint_name { __u32 netns, length; char name[108]; };
enum object_role { ROLE_SOCKET=1, ROLE_CACHE=2, ROLE_CACHE_DIR=4,
                   ROLE_NSCD_PARENT=8, ROLE_USER_ROOT=16, ROLE_RUNTIME=32,
                   ROLE_SYSTEMD=64 };
enum stream_role { STREAM_SAFE=1, STREAM_PROTECTED=2 };
struct role_version { __u64 topology, configuration; };
struct stream_label { struct role_version version; __u32 role; __u32 reserved; };
#ifdef WGPS_BPF
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct policy_path);
    __type(value, __u32);
} paths SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct policy_short_path);
    __type(value, __u32);
} paths_short SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_config);
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
extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;

static __always_inline int result(__u32 reason, int allow)
{
    __u64 *count = bpf_map_lookup_elem(&stats, &reason);
    if (count) __sync_fetch_and_add(count, 1);
    return allow;
}

/* memfd and other anonymous images synthesize their names; they are refused
 * rather than guessed, unlike a regular file that a replacement unlinked. */
static __always_inline bool synthetic_file(struct file *file)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const struct dentry_operations *ops = BPF_CORE_READ(dentry, d_op);
    return ops && BPF_CORE_READ(ops, d_dname);
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

/* Caller holds preemption disabled throughout the shared per-CPU buffer use.
 * Only path/probe/map operations run here; file release stays outside to avoid
 * release-side callbacks. These helpers do not invoke our task-context hooks. */
static __always_inline int resolve_policy(struct file *exe)
{
    __u32 zero = 0;
    struct path_scratch *work = bpf_map_lookup_elem(&scratch, &zero);
    if (!work) return PATH_ERROR;
    /* No cross-socket cache: every creation resolves the current path. */
    int len = bpf_path_d_path(&exe->f_path, work->resolved, sizeof(work->resolved));
    bool linked = linked_file(exe);
    if (len <= 1 || len > PATH_BYTES || work->resolved[0] != '/')
        return PATH_ERROR;
    if (!linked) {
        if (synthetic_file(exe)) return UNLINKED_IMAGE;
        /* The identity check above, not this text, established that the image
         * is unlinked. d_path appends " (deleted)"; strip it so the enrolled
         * key can be looked up. Only an enrolled path whose image was replaced
         * is refused: an unlisted process whose binary a package upgrade
         * replaced stays unlisted instead of losing socket creation. */
        if (len < 12) return PATH_ERROR;
        __u32 cut = len - 11;
        /* Keep the bound check on the register the access uses: the compiler
         * would otherwise fold it into the earlier len check and the verifier
         * loses the bound across the 32-bit spill. */
        asm volatile("" : "+r"(cut));
        if (cut > PATH_BYTES - 11) return PATH_ERROR;
        char *tail = work->resolved + cut;
        if (tail[0] != ' ' || tail[1] != '(' || tail[2] != 'd' || tail[3] != 'e' ||
            tail[4] != 'l' || tail[5] != 'e' || tail[6] != 't' || tail[7] != 'e' ||
            tail[8] != 'd' || tail[9] != ')' || tail[10] != 0)
            return PATH_ERROR;
        tail[0] = 0;
        len = cut + 1;
    }
    /* d_path initially writes at the end, then memmoves: its tail is NOT zero.
     * Resolve the full path first, then zero/copy only the selected exact key.
     * len includes NUL: a 255-byte filesystem path fits the short tier. */
    __u32 *selected;
    if (len <= SHORT_PATH_BYTES) {
#pragma clang loop unroll(full)
        for (int i = 0; i < SHORT_PATH_BYTES / 8; i++)
            ((volatile __u64 *)&work->key)[i] = 0;
        if (bpf_probe_read_kernel_str(work->key.pathname, SHORT_PATH_BYTES, work->resolved) != len)
            return PATH_ERROR;
        selected = bpf_map_lookup_elem(&paths_short, &work->key);
    } else {
        /* clang's BPF backend does not lower a 4096-byte builtin memset. */
#pragma clang loop unroll(full)
        for (int i = 0; i < PATH_BYTES / 8; i++)
            ((volatile __u64 *)&work->key)[i] = 0;
        if (bpf_probe_read_kernel_str(work->key.pathname, PATH_BYTES, work->resolved) != len)
            return PATH_ERROR;
        selected = bpf_map_lookup_elem(&paths, &work->key);
    }
    if (!selected) return DIRECT;
    return linked ? INCLUDED : UNLINKED_IMAGE;
}

static __always_inline int policy_select(void)
{
    __u32 zero = 0;
    struct policy_config *cfg = bpf_map_lookup_elem(&policy_cfg, &zero);
    if (!cfg || cfg->version != POLICY_ABI) return BLOCKED;
    struct task_struct *task = bpf_get_current_task_btf();
    struct inode *root = BPF_CORE_READ(task, fs, root.dentry, d_inode);
    /* A private user namespace does not change executable identity: with the
     * host root and network namespace the path resolves and is classified
     * normally. The recorded userns identity is diagnostic only. */
    if (BPF_CORE_READ(root, i_ino) != cfg->root_ino ||
        BPF_CORE_READ(root, i_sb, s_dev) != cfg->root_dev ||
        BPF_CORE_READ(task, nsproxy, net_ns, ns.inum) != cfg->netns)
        return UNSUPPORTED_CONTEXT;
    struct file *exe = bpf_get_task_exe_file(task);
    if (!exe) return EXE_ERROR;
    /* BPF LSM execution pins the CPU but permits task preemption. Another
     * task's classifier or resolver guard could otherwise overwrite scratch
     * between resolution and lookup, silently treating an included path as
     * direct. No sleeping helpers or nested LSM operations run in this region. */
    bpf_preempt_disable();
    int selection = resolve_policy(exe);
    bpf_preempt_enable();
    bpf_put_file(exe);
    return selection;
}
#endif
#endif
