// SPDX-License-Identifier: GPL-3.0-or-later
/* Included by classifier.bpf.c: one object, one executable policy. */
#define AF_UNIX 1
#define SOCK_SEQPACKET 5
#define EACCES 13
#define MAY_READ 4
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
    __type(key, struct guard_slot); __type(value, __u32);
} guard_slots SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32);
    __type(key, struct object_id); __type(value, __u32);
} guard_dirs SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
    __type(key, struct endpoint_name); __type(value, __u32);
} endpoint_names SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); __type(value, __u32);
} object_roles SEC(".maps");
/* Bounded cache of inodes proved to have no resolver role, keyed by inode
 * identity and stamped with the guard configuration epoch. Ordinary file opens
 * and reads then skip pathname matching; object_role states why a hit is exact. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536);
    __type(key, struct negative_key); __type(value, __u64);
} negative_roles SEC(".maps");
/* Roles a rename into a slot holds for an inode, keyed like negative_roles,
 * only while that rename runs: guard_rename adds the entry before the move and
 * guard_renamed removes it, for both participants of an exchange, whether the
 * rename succeeded or failed. Nothing about the destination is committed. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, struct negative_key); __type(value, __u32);
} held_roles SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); __type(value, struct stream_label);
} stream_roles SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64);
} role_generation SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64);
} guard_config SEC(".maps");
enum guard_counter { GUARD_LOOKUPS, GUARD_DENIES, GUARD_OBJECTS, GUARD_UNKNOWN,
                     GUARD_COUNTERS };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, GUARD_COUNTERS);
    __type(key, __u32); __type(value, __u64);
} guard_stats SEC(".maps");

static __always_inline void guard_count(__u32 reason)
{
    __u64 *value=bpf_map_lookup_elem(&guard_stats,&reason);
    if (value) __sync_fetch_and_add(value,1);
}
static __always_inline int guard_selected(void)
{
    guard_count(GUARD_LOOKUPS);
    int selection=policy_select();
    if (selection==DIRECT || selection==UNSUPPORTED_CONTEXT) return 0;
    guard_count(GUARD_DENIES);
    return -EACCES;
}
/* Direct typed reads: these run on every uncached file operation, and a
 * BPF_CORE_READ chain costs one probe helper call per member. */
static __always_inline struct object_id inode_id(struct inode *inode)
{
    return (struct object_id){inode->i_sb->s_dev,inode->i_ino};
}
static __always_inline __u32 inode_role(struct inode *inode)
{
    struct object_id id=inode_id(inode);
    __u32 *role=bpf_map_lookup_elem(&guard_dirs,&id);
    return role ? *role : 0;
}
static __always_inline __u32 directory_role(struct dentry *dentry)
{
    return inode_role(dentry->d_inode);
}
/* Branch-free: one comparison per literal keeps verifier state bounded. */
#define NAME_IS(buffer, literal) ({ unsigned char difference=0; \
    _Pragma("clang loop unroll(full)") \
    for (unsigned int byte=0;byte<sizeof(literal);byte++) \
        difference|=(unsigned char)((buffer)[byte]^(literal)[byte]); difference==0; })
/* The built-in socket names a directory's name makes resolver endpoints. */
enum parent_label { PARENT_SOCKET=1<<8, PARENT_BUS_SOCKET=1<<9, PARENT_RESOLVE=1<<10,
                    PARENT_USER_BUS=1<<11 };
/* Which built-in socket names a directory called NAME, inside a directory with
 * role ANCESTOR, makes resolver endpoints. */
static __always_inline __u32 parent_names(const unsigned char *name_ptr,__u32 ancestor,struct inode *directory)
{
    char name[20]={};
    long length=bpf_probe_read_kernel_str(name,sizeof(name),name_ptr);
    __u32 bits=0;
    if ((ancestor&ROLE_RUNTIME) && (NAME_IS(name,"nscd") || NAME_IS(name,"avahi-daemon"))) bits|=PARENT_SOCKET;
    if ((ancestor&ROLE_RUNTIME) && NAME_IS(name,"dbus")) bits|=PARENT_BUS_SOCKET;
    if ((ancestor&ROLE_SYSTEMD) && NAME_IS(name,"resolve")) bits|=PARENT_RESOLVE;
    if (ancestor&ROLE_USER_ROOT) {
        bool valid=length>1 && length<12;
        __u64 number=0;
#pragma clang loop unroll(full)
        for (int i=0;i<10;i++) {
            if (i<length-1) {
                if (name[i]<'0' || name[i]>'9') valid=false;
                number=number*10+(name[i]-'0');
            }
        }
        if (valid && number<=0xffffffff && number==directory->i_uid.val) bits|=PARENT_USER_BUS;
    }
    return bits;
}
/* Whether a socket called NAME is a resolver endpoint below a directory whose
 * parent_label bits are BITS. */
static __always_inline bool socket_child(const char *name,__u32 bits)
{
    return (NAME_IS(name,"socket") && (bits&PARENT_SOCKET)) ||
           (NAME_IS(name,"system_bus_socket") && (bits&PARENT_BUS_SOCKET)) ||
           (NAME_IS(name,"io.systemd.Resolve") && (bits&PARENT_RESOLVE)) ||
           (NAME_IS(name,"bus") && (bits&PARENT_USER_BUS));
}
/* *cacheable reports that the role depends only on the slot map, the inode's
 * own name and its parent's identity: the name was read completely and none of
 * the built-in rules that inspect parent names, owners or ancestors applied. */
static __always_inline int dentry_role(struct dentry *dentry,bool *cacheable)
{
    *cacheable=false;
    if (!dentry) return 0;
    struct dentry *parent=dentry->d_parent;
    struct guard_slot key={.parent=inode_id(parent->d_inode)};
    const unsigned char *name_ptr=dentry->d_name.name;
    long copied=bpf_probe_read_kernel_str(key.name,sizeof(key.name),name_ptr);
    if (copied<1) return 0;
    if (copied==sizeof(key.name)) {
        /* Exactly 63 bytes fills the slot legitimately; a longer name was
         * truncated and must not match an enrolled 63-byte prefix. */
        char extra=0;
        if (bpf_probe_read_kernel(&extra,1,name_ptr+sizeof(key.name)-1)) return 0;
        if (extra) {
            *cacheable=true; /* Longer than any slot or rule name. */
            return 0;
        }
    }
    __u32 *slot=bpf_map_lookup_elem(&guard_slots,&key);
    __u32 role=slot ? *slot : 0;
    bool cache_name=(key.name[0]=='h' && key.name[1]=='o' && key.name[2]=='s' &&
                    key.name[3]=='t' && key.name[4]=='s' && !key.name[5]) ||
                   (key.name[0]=='d' && key.name[1]=='b' && key.name[2] &&
                    key.name[7] && !key.name[8]);
    if (cache_name && (directory_role(parent)&ROLE_CACHE_DIR)) role|=ROLE_CACHE;
    if (cache_name && !(role&ROLE_CACHE)) {
        char name[6]={};
        long length=bpf_probe_read_kernel_str(name,sizeof(name),parent->d_name.name);
        if (length==5 && name[0]=='n' && name[1]=='s' && name[2]=='c' && name[3]=='d' &&
            (directory_role(parent->d_parent)&ROLE_NSCD_PARENT))
            role|=ROLE_CACHE;
    }
    /* Audited standard child slots survive daemon runtime-directory creation
     * and replacement without a userspace polling/enrollment window. */
    bool socket_name=NAME_IS(key.name,"socket") || NAME_IS(key.name,"system_bus_socket") ||
                     NAME_IS(key.name,"io.systemd.Resolve");
    bool bus_name=NAME_IS(key.name,"bus");
    if ((socket_name || bus_name) &&
        socket_child(key.name,parent_names(parent->d_name.name,directory_role(parent->d_parent),parent->d_inode)))
        role|=ROLE_SOCKET;
    /* systemd may mount each newly created UID runtime directory as tmpfs.
     * Its root has no parent ancestry inside that filesystem. Protect the exact
     * root-level bus slot, including before rename, without a mount watcher.
     * This deliberately also blocks selected custom tmpfs-root bus endpoints. */
    if (bus_name && parent==parent->d_parent && parent->d_inode->i_sb->s_magic==0x01021994)
        role|=ROLE_SOCKET;
    *cacheable=!cache_name && !socket_name && !bus_name;
    return role;
}
static __always_inline struct negative_key inode_key(struct inode *inode)
{
    struct negative_key key={};
    key.inode=(__u64)inode; key.ino=inode->i_ino;
    key.dev=inode->i_sb->s_dev; key.generation=inode->i_generation;
    return key;
}
static __always_inline __u32 held_role(struct inode *inode)
{
    struct negative_key key=inode_key(inode);
    __u32 *held=bpf_map_lookup_elem(&held_roles,&key);
    return held ? *held : 0;
}
static __always_inline int label_inode(struct inode *inode,__u32 role)
{
    if (inode && role) {
        __u32 *label=bpf_inode_storage_get(&object_roles,inode,&role,BPF_LOCAL_STORAGE_GET_F_CREATE);
        /* A concurrent creation wins with EEXIST; use the storage it created. */
        if (!label) label=bpf_inode_storage_get(&object_roles,inode,0,0);
        if (!label) return -1;
        *label|=role;
    }
    return role;
}
/* Rename is rare and already inlines two role computations; the uncached form
 * keeps its verifier state bounded. */
static __always_inline int object_role_uncached(struct dentry *dentry,struct inode *inode)
{
    if (!inode || !dentry) return 0;
    __u32 *known=bpf_inode_storage_get(&object_roles,inode,0,0);
    bool unused=false;
    return known && *known ? *known : label_inode(inode,dentry_role(dentry,&unused));
}
static __always_inline int object_role(struct dentry *dentry,struct inode *inode)
{
    if (!inode || !dentry) return 0;
    __u32 *known=bpf_inode_storage_get(&object_roles,inode,0,0);
    if (known && *known) return *known;
    __u32 held=held_role(inode);
    if (held) return held;
    /* A cached "no role" is exact. It is kept only for an inode with a single
     * link, so it has exactly one name and parent, and only when that name is
     * not one the built-in parent, owner or ancestor rules inspect, so the role
     * came from the slot map alone. The name or parent changes only by rename;
     * a rename into a slot holds the destination roles above, consulted before
     * this cache, and advances role_generation before and after, which is part
     * of the stamp. A second link fails the single-link check, and guard
     * enrollment changes the epoch (an odd epoch is an update in progress). */
    __u32 zero=0;
    __u64 *config=bpf_map_lookup_elem(&guard_config,&zero);
    __u64 *generation=bpf_map_lookup_elem(&role_generation,&zero);
    if (!config || !generation) return -1;
    __u64 epoch=*config+*generation;
    bool stable=!(*config&1) && (*config&GUARD_SETTLED) && inode->i_nlink==1;
    struct negative_key key=inode_key(inode);
    if (stable) {
        __u64 *cached=bpf_map_lookup_elem(&negative_roles,&key);
        if (cached && *cached==epoch) return 0;
    }
    bool cacheable=false;
    int role=label_inode(inode,dentry_role(dentry,&cacheable));
    if (!role && cacheable && stable) bpf_map_update_elem(&negative_roles,&key,&epoch,BPF_ANY);
    return role;
}
static __always_inline int address_role(struct unix_sock *unix,struct unix_address *address);
static __always_inline int unix_role(struct unix_sock *unix)
{
    struct dentry *dentry=unix->path.dentry;
    int role=dentry ? object_role(dentry,dentry->d_inode) : 0;
    if (role) return role;
    /* The peer owns this immutable bind address. This also covers a later
     * unlink/rename of a listener bound using an audited absolute address. */
    return address_role(unix,BPF_CORE_READ(unix,addr));
}
static __always_inline int address_role(struct unix_sock *unix,struct unix_address *address)
{
    if (!address) return 0;
    struct endpoint_name key={};
    key.netns=BPF_CORE_READ(&unix->sk,__sk_common.skc_net.net,ns.inum);
    int length=BPF_CORE_READ(address,len)-2;
    if (length<1 || length>108) return 0;
    char first=0;
    bpf_probe_read_kernel(&first,1,address->name[0].sun_path);
    if (first) {
        long n=bpf_probe_read_kernel_str(key.name,sizeof(key.name),address->name[0].sun_path);
        if (n<1 || n>108) return 0;
        key.length=n;
    } else {
        key.length=length;
        if (bpf_probe_read_kernel(key.name,length,address->name[0].sun_path)) return 0;
    }
    __u32 *found=bpf_map_lookup_elem(&endpoint_names,&key);
    return found ? *found : 0;
}
static __always_inline int peer_role(struct sock *peer)
{
    if (!peer) return 0;
    struct unix_sock *unix=bpf_skc_to_unix_sock(peer);
    return unix ? unix_role(unix) : 0;
}
static __always_inline bool role_version(struct role_version *version)
{
    __u32 zero=0;
    __u64 *generation=bpf_map_lookup_elem(&role_generation,&zero);
    __u64 *configuration=bpf_map_lookup_elem(&guard_config,&zero);
    if (!generation || !configuration) return false;
    version->topology=*generation; version->configuration=*configuration;
    return true;
}
static __always_inline __u64 stream_stamp(struct role_version version)
{
    return (version.topology+version.configuration)<<1;
}
/* Concurrent relabels of one socket each publish with a single 64-bit store,
 * so a reader sees one complete decision: never a SAFE role paired with a
 * stamp another thread resolved after an invalidation. */
/* Never current: a stamp no generation sum reaches. */
#define STREAM_STALE (~1ULL)
static __always_inline struct stream_label *stream_storage(struct sock *sock)
{
    struct stream_label initial={};
    *(volatile __u64 *)&initial.word=STREAM_STALE; /* A store, not a .rodata copy. */
    struct stream_label *stored=bpf_sk_storage_get(&stream_roles,sock,&initial,BPF_SK_STORAGE_GET_F_CREATE);
    return stored ? stored : bpf_sk_storage_get(&stream_roles,sock,0,0); /* Lost a creation race. */
}
static __always_inline int set_stream_role(struct sock *sock,__u32 role,struct role_version version)
{
    if (!sock) return -EACCES;
    if (!(version.configuration&GUARD_SETTLED)) return 0; /* Not settled: decided per call. */
    struct stream_label *stored=stream_storage(sock);
    if (!stored) return -EACCES;
    *(volatile __u64 *)&stored->word=stream_stamp(version)|(role==STREAM_SAFE);
    return 0;
}
static __always_inline bool stream_label_read(struct sock *sock,__u64 *word)
{
    struct stream_label *stored=bpf_sk_storage_get(&stream_roles,sock,0,0);
    if (!stored) return false;
    *word=*(volatile __u64 *)&stored->word;
    return true;
}
/* Label the old object synchronously before its slot name can disappear: its
 * current role is committed, which closes bind-through-alias plus
 * rename-before-first-client without peer watching. A destination role is only
 * held for the duration of the rename (held_roles), never committed. An
 * exchange runs this hook in both directions, one per participant. */
SEC("lsm/inode_rename")
int BPF_PROG(guard_rename,struct inode *old_dir,struct dentry *old_dentry,
             struct inode *new_dir,struct dentry *new_dentry,int ret)
{
    (void)ctx; (void)old_dir; (void)new_dir;
    if (ret) return ret;
    struct inode *inode=old_dentry->d_inode;
    if (object_role_uncached(old_dentry,inode)<0) return -EACCES;
    bool unused=false;
    __u32 target=dentry_role(new_dentry,&unused)&(ROLE_SOCKET|ROLE_CACHE);
    if (!target || !inode) return 0;
    __u32 zero=0;
    __u64 *generation=bpf_map_lookup_elem(&role_generation,&zero);
    __u64 *config=bpf_map_lookup_elem(&guard_config,&zero);
    if (!generation || !config) return -EACCES;
    /* A rename entered before guard_renamed attached gets no completion call;
     * until the loader proved none remains, nothing is held (or cached). */
    if (!(*config&GUARD_SETTLED)) return 0;
    /* Advancing first makes earlier "no role" cache entries for it stale. */
    __sync_fetch_and_add(generation,1);
    struct negative_key key=inode_key(inode);
    return bpf_map_update_elem(&held_roles,&key,&target,BPF_ANY) ? -EACCES : 0;
}
SEC("lsm/unix_stream_connect")
int BPF_PROG(guard_connect,struct sock *sock,struct sock *other,struct sock *newsk,int ret)
{
    (void)ctx;
    if (ret) return ret;
    /* Snapshot BEFORE resolving the peer: a concurrent role change must leave
     * this label stale, never bless an old SAFE decision with a newer epoch. */
    struct role_version version={};
    if (!role_version(&version)) return -EACCES;
    int role=peer_role(other);
    if (role<0) return -EACCES;
    __u32 tag=((role&ROLE_SOCKET) || (version.configuration&1)) ? STREAM_PROTECTED : STREAM_SAFE;
    if (set_stream_role(sock,tag,version) || set_stream_role(newsk,tag,version)) return -EACCES;
    if (tag==STREAM_SAFE) return 0;
    guard_count(GUARD_OBJECTS);
    return guard_selected();
}
SEC("lsm/unix_may_send")
int BPF_PROG(guard_datagram,struct socket *sock,struct socket *other,int ret)
{
    (void)ctx; (void)sock;
    if (ret) return ret;
    int role=peer_role(other->sk);
    if (role<0) return -EACCES;
    if (!(role&ROLE_SOCKET)) return 0;
    guard_count(GUARD_OBJECTS);
    return guard_selected();
}
static __always_inline int stream_guard(struct socket *sock);
static __always_inline int file_guard(struct file *file,bool check_stream)
{
    if (!file) return 0;
    struct inode *inode=file->f_inode;
    /* Typed CO-RE reads avoid a probe helper on each ordinary file operation.
     * Regular files cannot be sockets; dispatch once, retaining splice checks
     * for socket files on permission/descriptor-receive hooks. Pipes, devices
     * and other nonregular files are never resolver objects. */
    if (!inode) return 0;
    __u32 kind=inode->i_mode&0170000;
    if (kind!=0100000)
        return check_stream && kind==0140000 ? stream_guard(bpf_sock_from_file(file)) : 0;
    int role=object_role(file->f_path.dentry,inode);
    if (role<0) return -EACCES;
    if (!(role&ROLE_CACHE)) return 0;
    guard_count(GUARD_OBJECTS);
    return guard_selected();
}
static __always_inline int stream_guard(struct socket *sock)
{
    if (!sock) return 0;
    struct sock *sk=sock->sk;
    if (!sk) return 0;
    if (sk->__sk_common.skc_family!=AF_UNIX) return 0; /* No executable lookup on any IP payload path. */
    __u16 type=sk->sk_type;
    if (type!=SOCK_STREAM && type!=SOCK_SEQPACKET) return 0;
    struct role_version version={};
    if (!role_version(&version)) return guard_selected();
    __u64 word=0;
    if (!stream_label_read(sk,&word) || (word&~1ULL)!=stream_stamp(version)) {
        /* Pre-guard stream, or a rename/bind/configuration generation moved:
         * label it now from the audited identity of its own bind address (an
         * accepted child carries the listener's) or of its peer, exactly as at
         * connect time. A generation change therefore costs one resolution per
         * socket, never one per message, and an included process keeps its
         * unrelated streams instead of losing them until they are recreated. */
        guard_count(GUARD_UNKNOWN);
        struct unix_sock *self=bpf_skc_to_unix_sock(sk);
        if (!self) return guard_selected();
        /* A stream's peer is published once, by connect or socketpair, after
         * guard_connect labelled it. SAFE is cached only for a resolved,
         * published peer: an unconnected socket is decided per call, so a
         * relabel racing a connect cannot replace the connect's label. */
        struct sock *peer=self->peer;
        int found=unix_role(self);
        if (!found) found=peer_role(peer);
        if (found<0) return -EACCES;
        __u32 tag=((found&ROLE_SOCKET) || (version.configuration&1)) ? STREAM_PROTECTED : STREAM_SAFE;
        if (tag==STREAM_SAFE && !peer) return 0;
        if (set_stream_role(sk,tag,version)) return -EACCES;
        if (tag==STREAM_SAFE) return 0;
        guard_count(GUARD_OBJECTS);
        return guard_selected();
    }
    if (!(version.configuration&1) && (word&1)) return 0;
    return guard_selected();
}
SEC("lsm/socket_socketpair")
int BPF_PROG(guard_pair,struct socket *one,struct socket *two,int ret)
{
    (void)ctx;
    if (ret) return ret;
    struct role_version version={};
    if (!role_version(&version)) return -EACCES;
    return set_stream_role(one->sk,STREAM_SAFE,version) || set_stream_role(two->sk,STREAM_SAFE,version) ? -EACCES : 0;
}
/* Kept so a guard loaded before guard_bound existed keeps its exact link set;
 * stream labels are invalidated by guard_bound once a bind is visible. */
SEC("lsm/socket_bind")
int BPF_PROG(guard_bind,struct socket *sock,struct sockaddr *address,int length,int ret)
{ (void)ctx; (void)sock; (void)address; (void)length; return ret; }
SEC("lsm/file_open")
int BPF_PROG(guard_open,struct file *file,int ret)
{ (void)ctx; return ret ? ret : file_guard(file,false); }
SEC("lsm/mmap_file")
int BPF_PROG(guard_mmap,struct file *file,unsigned long reqprot,unsigned long prot,unsigned long flags,int ret)
{ (void)ctx; (void)reqprot; (void)prot; (void)flags; return ret ? ret : file_guard(file,false); }
SEC("lsm/file_permission")
int BPF_PROG(guard_read,struct file *file,int mask,int ret)
{
    (void)ctx;
    if (ret || !(mask&MAY_READ)) return ret;
    /* splice(socket, pipe) performs file permission checks but does not call
     * socket_recvmsg. Apply the same stream role gate before exposing bytes. */
    return file_guard(file,true);
}
SEC("lsm/file_receive")
int BPF_PROG(guard_receive,struct file *file,int ret)
{
    (void)ctx;
    if (ret) return ret;
    return file_guard(file,true);
}
SEC("lsm/socket_sendmsg")
int BPF_PROG(guard_send,struct socket *sock,struct msghdr *msg,int size,int ret)
{ (void)ctx; (void)msg; (void)size; return ret ? ret : stream_guard(sock); }
SEC("lsm/socket_recvmsg")
int BPF_PROG(guard_recv,struct socket *sock,struct msghdr *msg,int size,int flags,int ret)
{ (void)ctx; (void)msg; (void)size; (void)flags; return ret ? ret : stream_guard(sock); }
/* Stream labels: a SAFE label stamped with generation g is stored only by a
 * relabel that read g first and then resolved both endpoints. Every operation
 * that can make an endpoint's resolved identity protected advances the
 * generation after its effect is visible (these fexit programs run before the
 * system call returns), so such a label is stale for any later operation.
 * Nothing caches a provisional decision, so an operation that leaves no
 * protected identity also leaves the next relabel free to store SAFE. */
static __always_inline void invalidate_streams(void)
{
    __u32 zero=0;
    __u64 *generation=bpf_map_lookup_elem(&role_generation,&zero);
    if (generation) __sync_fetch_and_add(generation,1);
}
/* A pathname bind may name a protected slot or standard endpoint; an abstract
 * one only if it is enrolled. Autobind and other abstract names change no
 * resolved identity, so they do not invalidate every stream. */
SEC("fexit/unix_bind")
int BPF_PROG(guard_bound,struct socket *sock,struct sockaddr *address,int length,int ret)
{
    (void)ctx; (void)address; (void)length;
    if (ret || !sock) return 0;
    struct sock *sk=sock->sk;
    if (!sk) return 0;
    __u16 type=sk->sk_type;
    if (type!=SOCK_STREAM && type!=SOCK_SEQPACKET) return 0;
    struct unix_sock *unix=bpf_skc_to_unix_sock(sk);
    if (!unix) return 0;
    struct unix_address *bound=BPF_CORE_READ(unix,addr);
    if (!bound) return 0;
    char first=0;
    bpf_probe_read_kernel(&first,1,bound->name[0].sun_path);
    if (first || address_role(unix,bound)) invalidate_streams();
    return 0;
}
/* Retire what guard_rename held for one participant; true if it held a role. */
static __always_inline bool release_held(struct inode *inode)
{
    if (!inode) return false;
    struct negative_key key=inode_key(inode);
    return !bpf_map_delete_elem(&held_roles,&key);
}
/* Moving a socket can move it into or out of a slot; moving a directory inside
 * a runtime, systemd or user-root directory can change its name rules; a rename
 * into a slot held its destination roles (guard_rename), which this releases
 * for both exchange participants, after success or failure. */
SEC("fexit/vfs_rename")
int BPF_PROG(guard_renamed,struct renamedata *rename,int ret)
{
    (void)ctx;
    /* Typed loads keep BTF pointers, which dentry_role dereferences directly. */
    struct dentry *moved=rename->old_dentry, *other=rename->new_dentry;
    if (!moved || !other) return 0;
    struct inode *first=moved->d_inode, *second=other->d_inode;
    bool held=release_held(first);
    held|=release_held(second);
    /* A relabel may have cached the held role; resolve again either way. */
    if (held) { invalidate_streams(); return 0; }
    if (ret) return 0;
    __u32 kind=first ? first->i_mode&0170000 : 0;
    __u32 exchanged=second ? second->i_mode&0170000 : 0;
    if (kind==0140000 || exchanged==0140000) { invalidate_streams(); return 0; }
    if (kind!=0040000 && exchanged!=0040000) return 0;
    struct dentry *from=rename->old_parent, *to=rename->new_parent;
    if (!from || !to || !from->d_inode || !to->d_inode) return 0;
    if ((inode_role(from->d_inode)|inode_role(to->d_inode))&(ROLE_RUNTIME|ROLE_SYSTEMD|ROLE_USER_ROOT))
        invalidate_streams();
    return 0;
}
/* The user-root rule compares a runtime directory's numeric name with its
 * owner; a changed owner can change the role of the bus socket inside it. */
SEC("lsm/inode_post_setattr")
int BPF_PROG(guard_attr,struct mnt_idmap *idmap,struct dentry *dentry,int valid)
{
    (void)ctx; (void)idmap;
    if (!(valid&2) || !dentry) return 0; /* ATTR_UID */
    struct inode *inode=dentry->d_inode;
    if (!inode || (inode->i_mode&0170000)!=0040000) return 0;
    if (directory_role(dentry->d_parent)&ROLE_USER_ROOT) invalidate_streams();
    return 0;
}
/* Loaded with the object but never linked or pinned: one raw sample per task
 * (see drain.h, which decides) so the loader can prove that no task still runs
 * inside a unix_bind or vfs_rename it entered before guard_bound and
 * guard_renamed attached.
 *
 * Sampling order: switch count, on_cpu, walk, on_cpu, switch count. __schedule
 * counts a switch-out (nvcsw or nivcsw) before finish_task clears the
 * outgoing task's on_cpu, so a task that ran during the walk and stopped again
 * shows on_cpu set at one read or a changed switch count; x86 keeps both the
 * scheduler's stores and these loads in order. */
enum drain_flag { TASK_EXITED=1, TASK_SELF=2, TASK_ON_CPU=4, TASK_WALK_ERROR=8 };
struct drain_record { __u32 tid, flags; __u64 start, switches_before, switches_after, bytes; };
SEC("iter/task")
int drain_tasks(struct bpf_iter__task *ctx)
{
    struct seq_file *seq=ctx->meta->seq;
    struct task_struct *task=ctx->task;
    if (!task) return 0;
    struct drain_record record={};
    record.tid=task->pid; record.start=task->start_time;
    if (task->exit_state) record.flags|=TASK_EXITED;
    if (task==bpf_get_current_task_btf()) record.flags|=TASK_SELF; /* Running this scan. */
    __u32 zero=0;
    struct path_scratch *buffer=bpf_map_lookup_elem(&scratch,&zero);
    if (record.flags || !buffer) {
        record.flags|=buffer ? 0 : TASK_WALK_ERROR;
        bpf_seq_write(seq,&record,sizeof(record));
        return 0;
    }
    /* The classifier shares this per-CPU buffer with preemption disabled. */
    bpf_preempt_disable();
    record.switches_before=*(volatile unsigned long *)&task->nvcsw+*(volatile unsigned long *)&task->nivcsw;
    if (*(volatile int *)&task->on_cpu) record.flags|=TASK_ON_CPU;
    long size=bpf_get_task_stack(task,buffer,sizeof(*buffer),0);
    if (*(volatile int *)&task->on_cpu) record.flags|=TASK_ON_CPU;
    record.switches_after=*(volatile unsigned long *)&task->nvcsw+*(volatile unsigned long *)&task->nivcsw;
    if (size>0 && size<=(long)sizeof(*buffer)) record.bytes=size;
    else record.flags|=TASK_WALK_ERROR;
    bpf_seq_write(seq,&record,sizeof(record));
    if (size>0 && size<=(long)sizeof(*buffer)) bpf_seq_write(seq,buffer,size);
    bpf_preempt_enable();
    return 0;
}
