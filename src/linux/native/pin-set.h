// SPDX-License-Identifier: GPL-3.0-or-later
// Included by bpf-loader.cpp inside its private namespace: the exact pin set.
/* added marks pins the earlier (128-entry guard map) generation lacks. */
struct MapSpec { const char *name; uint32_t key, value, type, entries; bool added=false; };
const std::array<MapSpec,15> maps{{
    {"paths",sizeof(PathKey),4,BPF_MAP_TYPE_HASH,1024},
    {"paths_short",sizeof(policy_short_path),4,BPF_MAP_TYPE_HASH,1024},
    {"policy_cfg",4,sizeof(Configuration),BPF_MAP_TYPE_ARRAY,1},
    {"scratch",4,sizeof(path_scratch),BPF_MAP_TYPE_PERCPU_ARRAY,1},
    {"stats",4,8,BPF_MAP_TYPE_PERCPU_ARRAY,9},
    {"guard_slots",sizeof(guard_slot),4,BPF_MAP_TYPE_HASH,1024},
    {"guard_dirs",sizeof(object_id),4,BPF_MAP_TYPE_HASH,32},
    {"endpoint_names",sizeof(endpoint_name),4,BPF_MAP_TYPE_HASH,1024},
    {"object_roles",4,4,BPF_MAP_TYPE_INODE_STORAGE,0},
    {"stream_roles",4,sizeof(stream_label),BPF_MAP_TYPE_SK_STORAGE,0},
    {"role_generation",4,8,BPF_MAP_TYPE_ARRAY,1},
    {"guard_config",4,8,BPF_MAP_TYPE_ARRAY,1},
    {"guard_stats",4,8,BPF_MAP_TYPE_PERCPU_ARRAY,4},
    {"negative_roles",sizeof(negative_key),8,BPF_MAP_TYPE_LRU_HASH,65536},
    {"held_roles",sizeof(negative_key),4,BPF_MAP_TYPE_HASH,4096,true}}};
enum LinkKind { LINK_CGROUP, LINK_LSM, LINK_FEXIT };
struct LinkSpec { const char *pin, *program, *hook; LinkKind kind; bool added; };
/* Pin order is attach order; removal is its reverse. Programs that invalidate
 * cached stream labels and "no role" entries precede every program that caches
 * them, so no interrupted load leaves a cache without its invalidators. */
const std::array<LinkSpec,15> links{{
    {"link","classify","socket_post_create",LINK_CGROUP,false},
    {"link_bound","guard_bound","unix_bind",LINK_FEXIT,true},
    {"link_renamed","guard_renamed","vfs_rename",LINK_FEXIT,true},
    {"link_attr","guard_attr","inode_post_setattr",LINK_LSM,true},
    {"link_rename","guard_rename","inode_rename",LINK_LSM,false},
    {"link_connect","guard_connect","unix_stream_connect",LINK_LSM,false},
    {"link_pair","guard_pair","socket_socketpair",LINK_LSM,false},
    {"link_send","guard_send","socket_sendmsg",LINK_LSM,false},
    {"link_recv","guard_recv","socket_recvmsg",LINK_LSM,false},
    {"link_read","guard_read","file_permission",LINK_LSM,false},
    {"link_receive","guard_receive","file_receive",LINK_LSM,false},
    {"link_open","guard_open","file_open",LINK_LSM,false},
    {"link_mmap","guard_mmap","mmap_file",LINK_LSM,false},
    {"link_datagram","guard_datagram","unix_may_send",LINK_LSM,false},
    {"link_bind","guard_bind","socket_bind",LINK_LSM,false}}};
