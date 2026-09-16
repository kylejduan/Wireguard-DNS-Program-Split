// SPDX-License-Identifier: GPL-3.0-or-later
/* Included by classifier.bpf.c: one object, one executable policy. */
#define AF_UNIX 1
#define SOCK_SEQPACKET 5
#define EACCES 13
#define MAY_READ 4
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 128);
    __type(key, struct guard_slot); __type(value, __u32);
} guard_slots SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32);
    __type(key, struct object_id); __type(value, __u32);
} guard_dirs SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 128);
    __type(key, struct endpoint_name); __type(value, __u32);
} endpoint_names SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); __type(value, __u32);
} object_roles SEC(".maps");
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
static __always_inline struct object_id inode_id(struct inode *inode)
{
    return (struct object_id){BPF_CORE_READ(inode,i_sb,s_dev),BPF_CORE_READ(inode,i_ino)};
}
static __always_inline __u32 directory_role(struct dentry *dentry)
{
    struct inode *inode=BPF_CORE_READ(dentry,d_inode);
    struct object_id id=inode_id(inode);
    __u32 *role=bpf_map_lookup_elem(&guard_dirs,&id);
    return role ? *role : 0;
}
static __always_inline int dentry_role(struct dentry *dentry)
{
    if (!dentry) return 0;
    struct dentry *parent=BPF_CORE_READ(dentry,d_parent);
    struct guard_slot key={.parent=inode_id(BPF_CORE_READ(parent,d_inode))};
    const unsigned char *name_ptr=BPF_CORE_READ(dentry,d_name.name);
    long copied=bpf_probe_read_kernel_str(key.name,sizeof(key.name),name_ptr);
    if (copied<1) return 0;
    if (copied==sizeof(key.name)) {
        /* Exactly 63 bytes fills the slot legitimately; a longer name was
         * truncated and must not match an enrolled 63-byte prefix. */
        char extra=0;
        if (bpf_probe_read_kernel(&extra,1,name_ptr+sizeof(key.name)-1) || extra) return 0;
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
        long length=bpf_probe_read_kernel_str(name,sizeof(name),BPF_CORE_READ(parent,d_name.name));
        if (length==5 && name[0]=='n' && name[1]=='s' && name[2]=='c' && name[3]=='d' &&
            (directory_role(BPF_CORE_READ(parent,d_parent))&ROLE_NSCD_PARENT))
            role|=ROLE_CACHE;
    }
    /* Audited standard child slots survive daemon runtime-directory creation
     * and replacement without a userspace polling/enrollment window. */
#define NAME_IS(buffer, literal) ({ bool same=true; \
    _Pragma("clang loop unroll(full)") \
    for (unsigned int byte=0;byte<sizeof(literal);byte++) \
        if ((buffer)[byte]!=(literal)[byte]) same=false; same; })
    if (NAME_IS(key.name,"socket") || NAME_IS(key.name,"system_bus_socket") ||
        NAME_IS(key.name,"io.systemd.Resolve")) {
        char name[20]={};
        bpf_probe_read_kernel_str(name,sizeof(name),BPF_CORE_READ(parent,d_name.name));
        __u32 ancestor=directory_role(BPF_CORE_READ(parent,d_parent));
        if (((ancestor&ROLE_RUNTIME) &&
             ((NAME_IS(key.name,"socket") && (NAME_IS(name,"nscd") || NAME_IS(name,"avahi-daemon"))) ||
              (NAME_IS(key.name,"system_bus_socket") && NAME_IS(name,"dbus")))) ||
            ((ancestor&ROLE_SYSTEMD) && NAME_IS(name,"resolve") && NAME_IS(key.name,"io.systemd.Resolve")))
            role|=ROLE_SOCKET;
    }
    if (key.name[0]=='b' && key.name[1]=='u' && key.name[2]=='s' && !key.name[3] &&
        (directory_role(BPF_CORE_READ(parent,d_parent))&ROLE_USER_ROOT)) {
        char uid[12]={};
        long length=bpf_probe_read_kernel_str(uid,sizeof(uid),BPF_CORE_READ(parent,d_name.name));
        bool valid=length>1 && length<12;
        __u64 number=0;
#pragma clang loop unroll(full)
        for (int i=0;i<10;i++) {
            if (i<length-1) {
                if (uid[i]<'0' || uid[i]>'9') valid=false;
                number=number*10+(uid[i]-'0');
            }
        }
        if (valid && number<=0xffffffff &&
            number==BPF_CORE_READ(parent,d_inode,i_uid.val)) role|=ROLE_SOCKET;
    }
    /* systemd may mount each newly created UID runtime directory as tmpfs.
     * Its root has no parent ancestry inside that filesystem. Protect the exact
     * root-level bus slot, including before rename, without a mount watcher.
     * This deliberately also blocks selected custom tmpfs-root bus endpoints. */
    if (NAME_IS(key.name,"bus") && parent==BPF_CORE_READ(parent,d_parent) &&
        BPF_CORE_READ(parent,d_inode,i_sb,s_magic)==0x01021994)
        role|=ROLE_SOCKET;
    return role;
}
static __always_inline int label_inode(struct inode *inode,__u32 role)
{
    if (inode && role) {
        __u32 *label=bpf_inode_storage_get(&object_roles,inode,&role,BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!label) return -1;
        *label|=role;
    }
    return role;
}
static __always_inline int object_role(struct dentry *dentry,struct inode *inode)
{
    if (!inode || !dentry) return 0;
    __u32 *known=bpf_inode_storage_get(&object_roles,inode,0,0);
    return known ? *known : label_inode(inode,dentry_role(dentry));
}
static __always_inline int unix_role(struct unix_sock *unix)
{
    struct dentry *dentry=unix->path.dentry;
    int role=dentry ? object_role(dentry,dentry->d_inode) : 0;
    if (role) return role;
    /* The peer owns this immutable bind address. This also covers a later
     * unlink/rename of a listener bound using an audited absolute address. */
    struct unix_address *address=BPF_CORE_READ(unix,addr);
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
static __always_inline int set_stream_role(struct sock *sock,__u32 role,struct role_version version)
{
    if (!sock) return -EACCES;
    struct stream_label label={.version=version,.role=role};
    struct stream_label *stored=bpf_sk_storage_get(&stream_roles,sock,&label,BPF_SK_STORAGE_GET_F_CREATE);
    if (!stored) return -EACCES;
    *stored=label;
    return 0;
}
/* Label the old object synchronously before its slot name can disappear. This
 * closes bind-through-alias + rename-before-first-client without peer watching. */
SEC("lsm/inode_rename")
int BPF_PROG(guard_rename,struct inode *old_dir,struct dentry *old_dentry,
             struct inode *new_dir,struct dentry *new_dentry,int ret)
{
    (void)ctx; (void)old_dir; (void)new_dir;
    if (ret) return ret;
    int old_role=object_role(old_dentry,old_dentry->d_inode);
    int target_role=dentry_role(new_dentry);
    if (old_role<0 || label_inode(old_dentry->d_inode,target_role)<0) return -EACCES;
    if ((old_role|target_role)&ROLE_SOCKET) {
        __u32 zero=0;
        __u64 *generation=bpf_map_lookup_elem(&role_generation,&zero);
        if (!generation) return -EACCES;
        __sync_fetch_and_add(generation,1);
    }
    return 0;
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
     * for nonregular files on permission/descriptor-receive hooks. */
    if (!inode || (inode->i_mode&0170000)!=0100000)
        return check_stream ? stream_guard(bpf_sock_from_file(file)) : 0;
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
    __u16 type=BPF_CORE_READ(sk,sk_type);
    if (type!=SOCK_STREAM && type!=SOCK_SEQPACKET) return 0;
    struct role_version version={};
    if (!role_version(&version)) return guard_selected();
    struct stream_label *role=bpf_sk_storage_get(&stream_roles,sk,0,0);
    if (!role || role->version.topology!=version.topology ||
        role->version.configuration!=version.configuration) {
        /* Pre-guard stream, or a rename/bind/configuration generation moved:
         * label it now from the audited identity of its own bind address (an
         * accepted child carries the listener's) or of its peer, exactly as at
         * connect time. A generation change therefore costs one resolution per
         * socket, never one per message, and an included process keeps its
         * unrelated streams instead of losing them until they are recreated. */
        guard_count(GUARD_UNKNOWN);
        struct unix_sock *self=bpf_skc_to_unix_sock(sk);
        if (!self) return guard_selected();
        int found=unix_role(self);
        if (!found) found=peer_role(self->peer);
        if (found<0) return -EACCES;
        __u32 tag=((found&ROLE_SOCKET) || (version.configuration&1)) ? STREAM_PROTECTED : STREAM_SAFE;
        if (set_stream_role(sk,tag,version)) return -EACCES;
        if (tag==STREAM_SAFE) return 0;
        guard_count(GUARD_OBJECTS);
        return guard_selected();
    }
    if (!(version.configuration&1) && role->role==STREAM_SAFE) return 0;
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
SEC("lsm/socket_bind")
int BPF_PROG(guard_bind,struct socket *sock,struct sockaddr *address,int length,int ret)
{
    (void)ctx; (void)address; (void)length;
    if (ret) return ret;
    struct sock *sk=sock->sk;
    if (!sk || sk->__sk_common.skc_family!=AF_UNIX) return 0;
    __u16 type=BPF_CORE_READ(sk,sk_type);
    if (type!=SOCK_STREAM && type!=SOCK_SEQPACKET) return 0;
    struct stream_label *role=bpf_sk_storage_get(&stream_roles,sk,0,0);
    if (!role || role->role!=STREAM_SAFE) return 0;
    /* A named socketpair/connected stream is no longer provably unrelated.
     * Ordinary fresh listener binds have no SAFE tag and do not invalidate. */
    __u32 zero=0;
    __u64 *generation=bpf_map_lookup_elem(&role_generation,&zero);
    if (!generation) return -EACCES;
    __sync_fetch_and_add(generation,1);
    return 0;
}
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
