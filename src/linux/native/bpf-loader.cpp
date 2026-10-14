// SPDX-License-Identifier: GPL-3.0-or-later
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <csignal>
#include <sstream>
#include <thread>
#include "../bpf/policy.bpf.h"

namespace {
namespace fs = std::filesystem;
#include "json-string.h"
constexpr uint32_t abi = POLICY_ABI;
using PathKey = policy_path;
using Configuration = policy_config;
static_assert(sizeof(Configuration) == 40);
#include "pin-set.h"
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) {
        if (fd < 0) throw std::runtime_error(std::strerror(errno));
    }
    ~Fd() { close(value); }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
};
[[noreturn]] void fail(const std::string &text) { throw std::runtime_error(text); }
void check(bool okay, const std::string &text) {
    if (!okay) fail(text + ": " + std::strerror(errno));
}
struct stat stat_path(const fs::path &path) {
    struct stat result{};
    check(stat(path.c_str(), &result) == 0, "stat " + path.string());
    return result;
}
std::string read_text(const char *path) {
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), {});
}
void require_host() {
    for (const auto &part : {"root", "ns/net", "ns/user", "ns/pid"}) {
        auto current = stat_path(fs::path("/proc/self") / part);
        auto init = stat_path(fs::path("/proc/1") / part);
        if (current.st_ino != init.st_ino || current.st_dev != init.st_dev)
            fail("unsupported enrollment context: requires host root, network, user and PID namespace");
    }
}
void require_mutation_host() {
    if (geteuid()!=0) fail("mutations require root on a supported native host");
    struct utsname name{};
    check(uname(&name)==0,"uname");
    std::string release=name.release;
    if ((release.rfind("7.0.",0)!=0 && release.rfind("7.0-",0)!=0) || release.find("microsoft")!=std::string::npos)
        fail("mutations require supported native Ubuntu 26.04 / kernel 7.0");
    std::istringstream lines(read_text("/etc/os-release"));
    std::string line,id,version;
    while (std::getline(lines,line)) {
        auto equal=line.find('='); if (equal==std::string::npos) continue;
        auto value=line.substr(equal+1);
        if (value.size()>=2 && value.front()=='"' && value.back()=='"') value=value.substr(1,value.size()-2);
        if (line.substr(0,equal)=="ID") id=value;
        if (line.substr(0,equal)=="VERSION_ID") version=value;
    }
    if (id!="ubuntu" || version!="26.04") fail("mutations require supported native Ubuntu 26.04 / kernel 7.0");
    /* Kernel 7 UAPI IDs distinguish initial namespaces even when /proc has
     * been remounted inside a PID namespace and its local PID 1 looks normal. */
    for (const auto &item:std::array<std::pair<const char *,uint64_t>,3>{{
            {"net",NET_NS_INIT_ID},{"user",USER_NS_INIT_ID},{"pid",PID_NS_INIT_ID}}}) {
        Fd fd(open((std::string("/proc/self/ns/")+item.first).c_str(),O_RDONLY|O_CLOEXEC));
        uint64_t id=0;
        check(ioctl(fd.value,NS_GET_ID,&id)==0,"read initial namespace identity");
        if (id!=item.second) fail("unsupported enrollment context: requires initial host network, user and PID namespaces");
    }
    require_host();
    std::istringstream enabled(read_text("/sys/kernel/security/lsm")); bool bpf=false;
    while (std::getline(enabled,line,',')) if (line=="bpf" || line=="bpf\n") bpf=true;
    if (!bpf) fail("mutations require effective BPF LSM");
}
uint32_t number(const std::string &input) {
    size_t end = 0;
    unsigned long result = std::stoul(input, &end, 0);
    if (end != input.size() || result > UINT32_MAX) fail("invalid u32: " + input);
    return static_cast<uint32_t>(result);
}
PathKey path_key(const std::string &input, bool adding) {
    if (!fs::path(input).is_absolute()) fail("executable path must be absolute");
    /* Resolve the original spelling: symlink/.. traversal is filesystem semantics,
     * not lexical normalization. Deletion names the stored policy key exactly and
     * must keep working after the old file becomes a symlink or disappears. */
    fs::path path = adding ? fs::canonical(input) : fs::path(input);
    if (!adding && (path.lexically_normal().string() != input || input == "/" || input.back() == '/'))
        fail("stored policy requires the exact canonical key, without . or .. components or a trailing slash");
    auto text = path.string();
    if (text.size() >= sizeof(PathKey)) fail("executable path exceeds ABI pathname capacity");
    if (adding) {
        /* Inspect the type before opening for read: a FIFO or device at the path
         * must not block or be opened; only a regular executable is read. */
        Fd probe(open(path.c_str(), O_PATH | O_CLOEXEC));
        struct stat st{};
        check(fstat(probe.value, &st) == 0, "fstat executable");
        if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111))
            fail("unsupported enrollment: requires a native executable ELF file; scripts need their interpreter path");
        Fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY));
        Elf64_Ehdr header{};
        if (read(fd.value, &header, sizeof(header)) != sizeof(header) ||
            std::memcmp(header.e_ident, ELFMAG, SELFMAG) ||
            header.e_ident[EI_CLASS] != ELFCLASS64 ||
            header.e_ident[EI_DATA] != ELFDATA2LSB ||
            (header.e_type != ET_EXEC && header.e_type != ET_DYN))
            fail("unsupported enrollment: requires a native executable ELF file; scripts need their interpreter path");
#if defined(__x86_64__)
        if (header.e_machine != EM_X86_64) fail("non-native ELF architecture");
#elif defined(__aarch64__)
        if (header.e_machine != EM_AARCH64) fail("non-native ELF architecture");
#else
#error Unsupported native architecture
#endif
    }
    PathKey key{};
    std::memcpy(key.pathname, text.c_str(), text.size() + 1);
    return key;
}
std::vector<PathKey> read_policy_stdin(std::istream &input) {
    std::vector<PathKey> keys;
    std::set<std::string> unique;
    std::string current;
    size_t total = 0;
    char byte;
    while (input.get(byte)) {
        if (++total > 1024 * sizeof(PathKey)) fail("policy stdin exceeds capacity");
        if (byte) {
            if (current.size() >= sizeof(PathKey)-1) fail("policy stdin key exceeds capacity");
            current += byte;
        } else {
            if (keys.size() >= 1024 || current.empty() || current.back()=='/' ||
                !unique.insert(current).second) fail("invalid policy stdin record/count");
            keys.push_back(path_key(current, false));
            current.clear();
        }
    }
    if (!input.eof() || !current.empty()) fail("policy stdin read failed or final NUL missing");
    return keys;
}
const MapSpec &path_map_spec(const PathKey &key) {
    return maps[std::strlen(key.pathname)<SHORT_PATH_BYTES ? 1 : 0];
}
void initialize_paths(bpf_object *object, const std::vector<PathKey> &keys) {
    uint32_t selected=1;
    if (keys.size()>1024) fail("policy exceeds combined path capacity");
    for (const auto &key:keys) {
        int fd=bpf_object__find_map_fd_by_name(object,path_map_spec(key).name);
        check(bpf_map_update_elem(fd,&key,&selected,BPF_NOEXIST)==0,"initialize path");
    }
}
/* Earlier builds pinned 128-entry guard_slots and endpoint_names maps; the
 * layout and programs are otherwise identical. Accepting that capacity lets a
 * newer loader manage a guard lifetime loaded before an upgrade without
 * unloading it. Every new load creates the current capacity. */
bool legacy_capacity(const std::string &name, uint32_t entries) {
    return entries == 128 && (name == "guard_slots" || name == "endpoint_names");
}
int map_fd(const fs::path &dir, const char *name, uint32_t key_size,
           uint32_t value_size, uint32_t type, uint32_t entries) {
    int fd = bpf_obj_get((dir / name).c_str());
    if (fd < 0) fail("open pinned map " + std::string(name) + ": " + std::strerror(errno));
    bpf_map_info info{};
    uint32_t length = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &length) || info.key_size != key_size ||
        info.value_size != value_size || info.type != type ||
        (info.max_entries != entries && !legacy_capacity(name, info.max_entries)) ||
        std::string(info.name) != name) {
        close(fd);
        fail("pinned map ABI mismatch: " + std::string(name));
    }
    return fd;
}
Configuration configuration(const fs::path &dir) {
    Fd fd(map_fd(dir, "policy_cfg", 4, sizeof(Configuration), BPF_MAP_TYPE_ARRAY, 1));
    uint32_t zero = 0;
    Configuration cfg{};
    check(bpf_map_lookup_elem(fd.value, &zero, &cfg) == 0, "read config");
    if (cfg.version != abi) fail("unsupported pinned ABI");
    return cfg;
}
// Kernel function type IDs are immutable for this process's boot. Keep only
// these integers; release the large parsed BTF after resolving them.
const std::array<int, links.size()> &hook_types() {
    static const auto ids=[] {
        std::unique_ptr<btf,decltype(&btf__free)> types(btf__load_vmlinux_btf(),btf__free);
        if (!types) fail("kernel BTF unavailable");
        std::array<int, links.size()> result{};
        for (size_t i=0;i<links.size();++i) {
            auto hook=(links[i].kind==LINK_FEXIT ? std::string() : std::string("bpf_lsm_"))+links[i].hook;
            result[i]=btf__find_by_name_kind(types.get(),hook.c_str(),BTF_KIND_FUNC);
            if (result[i]<=0) fail("kernel hook type unavailable");
        }
        return result;
    }();
    return ids;
}
/* What an interrupted load left pinned: the classifier program IDs it attached
 * and how many links (a prefix of the pin order) and maps it pinned. */
struct Generation { std::set<uint32_t> classifiers; size_t links=0; bool maps=false; };
/* Verify a pin directory against this loader's exact map and link set. A
 * partial directory is an interrupted load: maps are pinned before links and
 * both in array order, so it may lack only trailing pins, and its cgroup link
 * must belong to CGROUP_ID. Anything else is not this loader's and is refused. */
Generation inspect_generation(const fs::path &dir, bool partial = false, uint64_t cgroup_id = 0) {
    std::set<std::string> expected;
    for (const auto &spec:maps) expected.insert(spec.name);
    for (const auto &spec:links) expected.insert(spec.pin);
    for (const auto &entry:fs::directory_iterator(dir))
        if (!expected.count(entry.path().filename())) fail("unknown pin-directory entry");
    if (!partial) (void)configuration(dir);
    Generation result;
    std::set<uint32_t> owned, used;
    size_t pinned=0, legacy_maps=0, missing_added=0;
    for (const auto &spec:maps) {
        if ((partial || spec.added) && !fs::exists(dir/spec.name)) { missing_added+=spec.added; continue; }
        Fd fd(map_fd(dir,spec.name,spec.key,spec.value,spec.type,spec.entries));
        bpf_map_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read owned map");
        owned.insert(info.id); ++pinned;
        legacy_maps+=info.max_entries!=spec.entries; // Only the two guard maps may differ.
    }
    result.maps=pinned==maps.size();
    const auto &targets=hook_types();
    /* The earlier build is told apart by its 128-entry guard maps, which no
     * current load creates, never by missing pins: only it may lack the added
     * links, and then all of them. Every other directory needs every link. */
    if (legacy_maps && legacy_maps!=2) fail("pinned guard map capacities disagree");
    bool legacy=!partial && legacy_maps==2 && missing_added;
    for (const auto &spec:links) if (legacy && spec.added && fs::exists(dir/spec.pin)) legacy=false;
    if (!partial && missing_added && !legacy) fail("pinned map set is incomplete");
    for (size_t i=0;i<links.size();++i) {
        const auto &spec=links[i];
        if ((partial || (legacy && spec.added)) && !fs::exists(dir/spec.pin)) continue;
        if (partial && (result.links!=i || !result.maps)) fail("interrupted pin directory is not a prefix of the pin order");
        Fd link(bpf_obj_get((dir/spec.pin).c_str()));
        bpf_link_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(link.value,&info,&size)==0,"read owned link");
        int target=targets[i];
        if (spec.kind==LINK_CGROUP ? (info.type!=BPF_LINK_TYPE_CGROUP || info.cgroup.attach_type!=BPF_LSM_CGROUP ||
                                      (partial && info.cgroup.cgroup_id!=cgroup_id)) :
            (info.type!=BPF_LINK_TYPE_TRACING ||
             info.tracing.attach_type!=(spec.kind==LINK_FEXIT ? BPF_TRACE_FEXIT : BPF_LSM_MAC) ||
             info.tracing.target_btf_id!=static_cast<uint32_t>(target))) fail("link attachment identity mismatch");
        Fd prog(bpf_prog_get_fd_by_id(info.prog_id));
        bpf_prog_info program{}; size=sizeof(program);
        check(bpf_obj_get_info_by_fd(prog.value,&program,&size)==0,"read program");
        if (program.type!=(spec.kind==LINK_FEXIT ? BPF_PROG_TYPE_TRACING : BPF_PROG_TYPE_LSM) ||
            std::string(program.name)!=spec.program ||
            program.attach_btf_id!=static_cast<uint32_t>(target)) fail("program hook identity mismatch");
        std::vector<uint32_t> ids(program.nr_map_ids);
        program={}; program.nr_map_ids=ids.size(); program.map_ids=reinterpret_cast<uint64_t>(ids.data());
        check(bpf_obj_get_info_by_fd(prog.value,&program,&size)==0,"read program maps");
        for (auto id:ids) {
            if (!owned.count(id)) fail("linked program references an unowned map");
            used.insert(id);
        }
        if (spec.kind==LINK_CGROUP) result.classifiers.insert(info.prog_id);
        ++result.links;
    }
    if (!partial && owned!=used) fail("pinned map is not used by the owned link set");
    return result;
}
void verify_owner(const fs::path &dir) { (void)inspect_generation(dir); }
/* Walk the cgroup tree with plain readdir so that a cgroup removed during the
 * walk (systemd scopes churn constantly, most of all during early boot) is
 * skipped rather than aborting the load. Every other error remains fatal. */
void reject_competitors(const fs::path &group, const std::set<uint32_t> &interrupted) {
    int raw = open(group.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (raw < 0 && errno == ENOENT) return;
    Fd fd(raw);
    uint32_t count = 0;
    int rc = bpf_prog_query(fd.value, BPF_LSM_CGROUP, BPF_F_QUERY_EFFECTIVE,
                            nullptr, nullptr, &count);
    if (rc && errno != ENOSPC) fail("cannot query effective cgroup LSM attachments: " + std::string(strerror(errno)));
    if (count) {
        /* Only the verified classifiers of an interrupted load of this pin
         * directory are tolerated; they stay attached only until replaced. */
        std::vector<uint32_t> ids(count + 1);
        uint32_t listed = ids.size();
        if (interrupted.empty() || bpf_prog_query(fd.value, BPF_LSM_CGROUP, BPF_F_QUERY_EFFECTIVE,
                                                  nullptr, ids.data(), &listed) || listed > count)
            fail("competing cgroup LSM attachments can override denial: " + group.string());
        for (uint32_t i = 0; i < listed; i++)
            if (!interrupted.count(ids[i])) fail("competing cgroup LSM attachments can override denial: " + group.string());
    }
    DIR *listing = opendir(group.c_str());
    if (!listing) {
        if (errno == ENOENT) return;
        check(false, "list cgroup " + group.string());
    }
    std::vector<std::string> children;
    while (dirent *entry = readdir(listing)) {
        std::string name = entry->d_name;
        if (name == "." || name == ".." || (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN)) continue;
        struct stat st{};
        if (entry->d_type == DT_UNKNOWN && (fstatat(dirfd(listing), name.c_str(), &st, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(st.st_mode)))
            continue;
        children.push_back(name);
    }
    closedir(listing);
    for (const auto &child : children) reject_competitors(group / child, interrupted);
}
/* The kernel compares superblock device numbers (i_sb->s_dev). stat() reports
 * them for most filesystems, but btrfs reports a per-subvolume anonymous device
 * instead; the mount table lists the superblock's own number for every mount,
 * so take it from the longest mount point containing the path. */
uint64_t kernel_device(const fs::path &path, const struct stat &st) {
    std::istringstream table(read_text("/proc/self/mountinfo"));
    std::string line, best_point, best_device;
    while (std::getline(table, line)) {
        std::istringstream fields(line);
        std::string id, parent, device, root, point;
        if (!(fields >> id >> parent >> device >> root >> point)) continue;
        std::string decoded;
        for (size_t i = 0; i < point.size(); i++) {
            if (point[i] == '\\' && i + 3 < point.size() && std::isdigit(point[i+1]))
                decoded += static_cast<char>(std::stoi(point.substr(i + 1, 3), nullptr, 8)), i += 3;
            else decoded += point[i];
        }
        bool covers = decoded == "/" || path == decoded ||
                      path.string().compare(0, decoded.size() + 1, decoded + "/") == 0;
        if (covers && decoded.size() >= best_point.size()) { best_point = decoded; best_device = device; }
    }
    auto colon = best_device.find(':');
    if (best_point.empty() || colon == std::string::npos) return (static_cast<uint64_t>(major(st.st_dev))<<20)|minor(st.st_dev);
    return (static_cast<uint64_t>(number(best_device.substr(0, colon)))<<20)|number(best_device.substr(colon + 1));
}
object_id identity(const fs::path &path, const struct stat &st) {
    return {kernel_device(path, st), st.st_ino};
}
struct GuardMaps { int slots, dirs, names, roles; };
void merge_role(int fd,const void *key,uint32_t role) {
    uint32_t previous=0;
    if (bpf_map_lookup_elem(fd,key,&previous) && errno!=ENOENT) fail("guard map read failed");
    role|=previous;
    check(bpf_map_update_elem(fd,key,&role,BPF_ANY)==0,"enroll guard object");
}
void guard_slot_add(GuardMaps fd,uint32_t netns,const std::string &kind,const std::string &input) {
    uint32_t role=kind=="socket" || kind=="abstract" ? ROLE_SOCKET : ROLE_CACHE;
    if (kind=="abstract") {
        if (input.empty() || input[0]!='@' || input.size()>108) fail("abstract name must be @NAME, at most 108 bytes");
        endpoint_name name{}; name.netns=netns; name.length=input.size();
        memcpy(name.name+1,input.data()+1,input.size()-1);
        merge_role(fd.names,&name,ROLE_SOCKET); return;
    }
    if (!fs::path(input).is_absolute()) fail("guard slot requires absolute path");
    fs::path path=fs::weakly_canonical(input);
    if (kind=="cache-dir" || kind=="user-bus-dir" || kind=="nscd-parent") {
        auto st=stat_path(path);
        if (!S_ISDIR(st.st_mode)) fail("guard directory is not a directory");
        role=kind=="cache-dir" ? ROLE_CACHE_DIR : kind=="user-bus-dir" ? ROLE_USER_ROOT : ROLE_NSCD_PARENT;
        auto key=identity(path,st); merge_role(fd.dirs,&key,role); return;
    }
    if (kind!="socket" && kind!="cache") fail("guard kind must be socket, abstract, cache, cache-dir or user-bus-dir");
    if (role==ROLE_SOCKET) {
        for (const auto &spelling:{input,path.string()}) {
            endpoint_name name{}; name.netns=netns; name.length=spelling.size()+1;
            if (name.length>sizeof(name.name)) fail("Unix endpoint exceeds sockaddr capacity");
            memcpy(name.name,spelling.c_str(),name.length); merge_role(fd.names,&name,role);
        }
    }
    if (fs::exists(path.parent_path())) {
        auto st=stat_path(path.parent_path());
        guard_slot slot{}; slot.parent=identity(path.parent_path(),st);
        auto name=path.filename().string();
        if (name.size()>=sizeof(slot.name)) fail("guard basename exceeds slot capacity");
        memcpy(slot.name,name.c_str(),name.size()+1); merge_role(fd.slots,&slot,role);
    } else if (kind=="cache") fail("custom cache parent must exist; default nscd ancestors are enrolled separately");
    if (fs::exists(path)) {
        Fd file(open(path.c_str(),O_PATH|O_CLOEXEC));
        auto st=stat_path(path);
        if ((role==ROLE_SOCKET && !S_ISSOCK(st.st_mode)) || (role==ROLE_CACHE && !S_ISREG(st.st_mode)))
            fail("guard object has wrong file type");
        merge_role(fd.roles,&file.value,role);
    }
}
GuardMaps guard_maps(bpf_object *object) {
    return {bpf_object__find_map_fd_by_name(object,"guard_slots"),
        bpf_object__find_map_fd_by_name(object,"guard_dirs"),
        bpf_object__find_map_fd_by_name(object,"endpoint_names"),
        bpf_object__find_map_fd_by_name(object,"object_roles")};
}
/* A user's runtime directory is user-writable. Never resolve symlinks there,
 * enroll only the exact expected spelling, and never fail on user content:
 * an unprivileged user must not be able to block guard loading or redirect
 * a socket role by placing a symlink or an unrelated object at "bus". The
 * BPF guard additionally recognizes "bus" under the user-root directory and
 * at a tmpfs root, so this enrollment only adds the immutable bind address. */
void guard_user_bus(GuardMaps fd,uint32_t netns,const fs::path &directory) {
    fs::path path=directory/"bus";
    auto spelling=path.string();
    endpoint_name name{}; name.netns=netns; name.length=spelling.size()+1;
    if (name.length>sizeof(name.name)) return;
    memcpy(name.name,spelling.c_str(),name.length); merge_role(fd.names,&name,ROLE_SOCKET);
    struct stat parent{};
    if (lstat(directory.c_str(),&parent) || !S_ISDIR(parent.st_mode)) return;
    guard_slot slot{}; slot.parent=identity(directory,parent);
    memcpy(slot.name,"bus",4); merge_role(fd.slots,&slot,ROLE_SOCKET);
    struct stat st{};
    if (lstat(path.c_str(),&st) || !S_ISSOCK(st.st_mode)) return;
    int raw=open(path.c_str(),O_PATH|O_NOFOLLOW|O_CLOEXEC);
    if (raw<0) return;
    Fd file(raw);
    merge_role(fd.roles,&file.value,ROLE_SOCKET);
}
void seed_guards(bpf_object *object,uint32_t netns) {
    auto fd=guard_maps(object);
    for (const char *path:{"/run/systemd/resolve/io.systemd.Resolve","/run/nscd/socket",
            "/var/run/nscd/socket","/run/avahi-daemon/socket","/var/run/avahi-daemon/socket",
            "/run/dbus/system_bus_socket","/var/run/dbus/system_bus_socket"})
        guard_slot_add(fd,netns,"socket",path);
    for (const char *path:{"/run","/var/cache","/var/lib"})
        guard_slot_add(fd,netns,"nscd-parent",path);
    auto runtime=identity("/run",stat_path("/run")); merge_role(fd.dirs,&runtime,ROLE_RUNTIME);
    auto systemd=identity("/run/systemd",stat_path("/run/systemd")); merge_role(fd.dirs,&systemd,ROLE_SYSTEMD);
    if (fs::exists("/run/user")) {
        guard_slot_add(fd,netns,"user-bus-dir","/run/user");
        for (const auto &entry:fs::directory_iterator("/run/user")) {
            auto name=entry.path().filename().string();
            if (name.empty() || name.size()>10 || name.find_first_not_of("0123456789")!=std::string::npos) continue;
            struct stat st{};
            /* A session ending mid-walk simply disappears; it is not an error. */
            if (lstat(entry.path().c_str(),&st) || !S_ISDIR(st.st_mode) || st.st_uid!=number(name)) continue;
            guard_user_bus(fd,netns,entry.path());
        }
    }
    for (const char *path:{"/run/nscd","/var/cache/nscd","/var/lib/nscd"}) {
        if (!fs::exists(path)) continue;
        guard_slot_add(fd,netns,"cache-dir",path);
        for (const auto &entry:fs::directory_iterator(path)) {
            auto name=entry.path().filename().string();
            std::error_code ec;
            if (entry.is_regular_file(ec) && (name=="hosts" || (name.size()==8 && name.substr(0,2)=="db")))
                guard_slot_add(fd,netns,"cache",entry.path());
        }
    }
}
void ready_preflight() {
    std::istringstream lines(read_text("/etc/nsswitch.conf"));
    std::string line, hosts;
    while (std::getline(lines,line)) {
        auto colon=line.find(':');
        if (colon==std::string::npos) continue;
        std::istringstream head(line.substr(0,colon)); std::string name; head>>name;
        if (name!="hosts") continue;
        std::istringstream words(line.substr(colon+1,line.find('#')-colon-1));
        std::string word; while (words>>word) { if (!hosts.empty()) hosts+=' '; hosts+=word; }
    }
    if (hosts!="files dns" && hosts!="files mdns4_minimal [NOTFOUND=return] dns")
        fail("unsupported hosts NSS configuration; ready accepts files dns or files mdns4_minimal [NOTFOUND=return] dns only");
}
/* Indices into the classifier stats map, in the BPF object's enum reason order
 * (the same order as the names printed by status). */
constexpr uint32_t REASON_DIRECT = 0, REASON_UNSUPPORTED_CONTEXT = 3;
uint64_t counter(const fs::path &dir, const char *name, uint32_t entries, uint32_t index) {
    Fd fd(map_fd(dir, name, 4, 8, BPF_MAP_TYPE_PERCPU_ARRAY, entries));
    int count = libbpf_num_possible_cpus();
    if (count < 1) fail("cannot discover possible CPUs");
    std::vector<uint64_t> values(count);
    check(bpf_map_lookup_elem(fd.value, &index, values.data()) == 0, "read counter");
    uint64_t sum = 0;
    for (auto value : values) sum += value;
    return sum;
}
/* Prove the recorded root/namespace identity matches what the hooks observe:
 * this unlisted process must classify as DIRECT. A mismatch would silently
 * make every task UNSUPPORTED_CONTEXT, which is allowed unmarked, so it must
 * fail the load rather than pass readiness. */
bool inside_cgroup(const fs::path &group) {
    std::istringstream table(read_text("/proc/self/mountinfo"));
    std::string line, mount;
    while (std::getline(table, line)) {
        auto separator = line.find(" - ");
        if (separator == std::string::npos) continue;
        std::istringstream tail(line.substr(separator + 3)), head(line);
        std::string type, id, parent, device, root, point;
        if ((tail >> type) && type == "cgroup2" && (head >> id >> parent >> device >> root >> point)) { mount = point; break; }
    }
    std::istringstream cgroups(read_text("/proc/self/cgroup"));
    std::string self;
    while (std::getline(cgroups, line))
        if (line.rfind("0::", 0) == 0) self = mount + line.substr(3);
    if (mount.empty() || self.empty()) return false;
    auto target = group.string();
    return self == target || self.compare(0, target.size() + 1, target + "/") == 0;
}
void verify_context(const fs::path &dir, const fs::path &group) {
    if (!inside_cgroup(group)) {
        /* A test attaches to a cgroup this process is not in; only a load onto
         * this process's own cgroup ancestry can observe its probe socket. */
        std::cerr << "classification context self-check skipped: loader is outside the target cgroup\n";
        return;
    }
    for (int attempt = 0; attempt < 5; attempt++) {
        uint64_t direct = counter(dir, "stats", 9, REASON_DIRECT), unsupported = counter(dir, "stats", 9, REASON_UNSUPPORTED_CONTEXT);
        Fd probe(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        uint64_t direct_after = counter(dir, "stats", 9, REASON_DIRECT), unsupported_after = counter(dir, "stats", 9, REASON_UNSUPPORTED_CONTEXT);
        if (direct_after > direct && unsupported_after == unsupported) return;
        if (direct_after == direct && unsupported_after > unsupported)
            fail("classification context mismatch: this host's root identity is not observed by the hooks");
        /* Another process created a socket in the same window; sample again. */
    }
    fail("classification context could not be verified against concurrent socket creation");
}
/* Remove a staging pin directory and everything this loader could have pinned
 * there; unpinning the last reference to a link detaches its program. Reverse
 * pin order keeps an interrupted removal a valid prefix for the next load.
 * Only a leftover foreign entry keeps the directory, which is then reported. */
void discard_staging(const fs::path &staging) {
    std::error_code ec;
    if (!fs::exists(staging, ec)) return;
    for (auto spec=links.rbegin(); spec!=links.rend(); ++spec) fs::remove(staging/spec->pin, ec);
    for (auto spec=maps.rbegin(); spec!=maps.rend(); ++spec) fs::remove(staging/spec->name, ec);
    if (!fs::remove(staging, ec)) fail("stale staging pin directory could not be removed: " + staging.string());
}
#ifdef WGPS_LOADER_TEST_HOOKS
/* Test builds only: a deterministic death or failure at a named load step. */
void interruption_point(const std::string &point) {
    const char *target = getenv("WGPS_TEST_KILL_AT");
    if (target && point == target) raise(SIGKILL);
    target = getenv("WGPS_TEST_FAIL_AT");
    if (target && point == target) fail("injected failure at " + point);
}
void scan_delay() { // A slow task scan: each read of the iterator takes this long.
    if (const char *delay = getenv("WGPS_TEST_SCAN_DELAY_MS")) usleep(1000 * std::stoul(delay));
}
#else
void interruption_point(const std::string &) {}
void scan_delay() {}
#endif
std::set<std::string> policy_entries(const fs::path &dir);
struct Interrupted { fs::path path; Generation generation; };
/* A load killed after pinning into staging leaves that generation attached,
 * blocking its selected executables. Give it the replacement's blocked
 * configuration: one killed before a valid configuration was written would
 * refuse every socket, including this loader's context probe, while a valid
 * one is already blocked and differs at most in marks that blocked state does
 * not apply. Its links stay attached until the replacement is published. */
void hold_interrupted(const Interrupted &stale, const Configuration &cfg) {
    if (!stale.generation.maps) return; // No links: it attaches nothing.
    Fd fd(map_fd(stale.path, "policy_cfg", 4, sizeof(Configuration), BPF_MAP_TYPE_ARRAY, 1));
    uint32_t zero = 0;
    check(bpf_map_update_elem(fd.value, &zero, &cfg, BPF_ANY) == 0, "hold interrupted generation blocked");
}
/* With both staging names held, free the one whose protection the other
 * already provides: no links at all, or a link prefix and policy that the other
 * covers. Otherwise both stay attached and the load is refused. */
size_t covered_generation(const std::vector<Interrupted> &stale) {
    for (size_t i=0;i<2;++i) {
        const auto &a=stale[i].generation, &b=stale[1-i].generation;
        if (!a.links) return i;
        if (a.links<=b.links && b.maps) {
            auto mine=policy_entries(stale[i].path), theirs=policy_entries(stale[1-i].path);
            if (std::includes(theirs.begin(),theirs.end(),mine.begin(),mine.end())) return i;
        }
    }
    fail("two interrupted guard loads with different policies remain attached; reboot or remove them");
}
/* Exact map and link identities, in the snapshot's "maps" and "links" form. */
std::string identities_json(const fs::path &dir) {
    std::ostringstream out;
    out<<"\"maps\":{";
    bool comma=false;
    for (const auto &spec:maps) {
        if (!fs::exists(dir/spec.name)) continue; // A verified legacy generation.
        Fd fd(bpf_obj_get((dir/spec.name).c_str())); bpf_map_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read map identity");
        if (comma) out<<',';
        comma=true; out<<json_string(spec.name)<<':'<<info.id;
    }
    out<<"},\"links\":{"; comma=false;
    for (const auto &spec:links) {
        if (!fs::exists(dir/spec.pin)) continue; // A verified legacy generation.
        Fd fd(bpf_obj_get((dir/spec.pin).c_str())); bpf_link_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read link identity");
        if (comma) out<<',';
        comma=true; out<<json_string(spec.pin)<<":{\"id\":"<<info.id<<",\"program_id\":"<<info.prog_id;
        if (spec.kind==LINK_CGROUP) out<<",\"cgroup_id\":"<<info.cgroup.cgroup_id;
        out<<'}';
    }
    out<<'}';
    return out.str();
}
/* Before publication, durably record the exact identities being published.
 * A caller whose load was killed after the rename can then prove the
 * published directory is this load's and complete it instead of refusing it. */
void write_birth_record(const fs::path &record, const fs::path &staging) {
    auto text="{"+identities_json(staging)+"}\n";
    Fd fd(open(record.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    check(fchmod(fd.value,0600)==0,"protect birth record");
    check(write(fd.value,text.data(),text.size())==static_cast<ssize_t>(text.size()) && fsync(fd.value)==0,"write birth record");
    Fd parent(open(record.parent_path().c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
    check(fsync(parent.value)==0,"persist birth record");
}
/* Complete a load killed after publication: the published generation protects,
 * so verified interrupted generations of the same cgroup are detached. */
void settle(const fs::path &dir, const fs::path &group) {
    auto group_id=stat_path(group).st_ino;
    Fd link(bpf_obj_get((dir/"link").c_str()));
    bpf_link_info info{}; uint32_t size=sizeof(info);
    check(bpf_obj_get_info_by_fd(link.value,&info,&size)==0,"read published classifier link");
    if (info.cgroup.cgroup_id!=group_id) fail("published classifier is attached to another cgroup");
    size_t removed=0;
    for (const char *suffix:{"_new","_next"}) {
        fs::path name=dir; name+=suffix;
        if (!fs::exists(name)) continue;
        (void)inspect_generation(name,true,group_id);
        discard_staging(name); ++removed;
    }
    std::cout<<"settled="<<removed<<'\n';
}
#include "pin-removal.h"
#include "drain.h"
void load(int argc, char **argv) {
    if (argc < 7) fail("load OBJECT PIN_DIR CGROUP MASK MARK [PATH...]");
    bool bulk = std::string(argv[1]) == "load-policy-stdin";
    if ((bulk && argc != 7 && argc != 8) || argc > 7+1024) fail("invalid policy arguments/count");
    /* load-policy-stdin takes an optional birth record path instead of paths. */
    fs::path record = bulk && argc == 8 ? fs::absolute(argv[7]) : fs::path();
    std::vector<PathKey> keys;
    if (bulk) keys = read_policy_stdin(std::cin);
    else for (int i=7; i<argc; i++) keys.push_back(path_key(argv[i],std::string(argv[1])=="load"));
    fs::path dir = fs::absolute(argv[3]), group = fs::canonical(argv[4]);
    struct statfs bpffs{}, cgfs{};
    check(statfs(dir.parent_path().c_str(), &bpffs) == 0 && bpffs.f_type == BPF_FS_MAGIC,
          "PIN_DIR parent must be bpffs");
    check(statfs(group.c_str(), &cgfs) == 0 && cgfs.f_type == CGROUP2_SUPER_MAGIC,
          "CGROUP must be cgroup v2");
    /* bpffs reserves names containing a dot, so the staging suffixes have none.
     * A load killed before publishing leaves its staging directory attached; a
     * second staging name lets the replacement attach before it is removed. */
    std::array<fs::path,2> names{dir, dir};
    names[0] += "_new"; names[1] += "_next";
    std::vector<Interrupted> stale;
    std::set<uint32_t> interrupted;
    for (const auto &name:names) {
        if (!fs::exists(name)) continue;
        stale.push_back({name, inspect_generation(name, true, stat_path(group).st_ino)});
        interrupted.insert(stale.back().generation.classifiers.begin(), stale.back().generation.classifiers.end());
    }
    reject_competitors(group, interrupted);
    auto root = stat_path("/");
    Configuration cfg{abi, 0, number(argv[5]), number(argv[6]),
        kernel_device("/", root),
        root.st_ino, static_cast<uint32_t>(stat_path("/proc/self/ns/net").st_ino),
        static_cast<uint32_t>(stat_path("/proc/self/ns/user").st_ino)};
    if (!cfg.mask || !cfg.mark || (cfg.mark & ~cfg.mask)) fail("MARK must be nonzero and contained in MASK");
    if (fs::exists(dir)) fail("pin directory already exists; existing pins are never adopted");
    for (const auto &item:stale) hold_interrupted(item, cfg);
    if (stale.size() == names.size()) {
        auto covered = covered_generation(stale);
        discard_staging(stale[covered].path);
        stale.erase(stale.begin() + covered);
    }
    fs::path staging = stale.empty() || stale[0].path != names[0] ? names[0] : names[1];
    /* libbpf owns the verifier log buffer: it retries with a larger buffer on
     * ENOSPC and prints the log on failure, so a chattier verifier cannot turn
     * a valid load into a spurious rejection. */
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open_file(argv[2], nullptr), bpf_object__close);
    if (!object) fail("open BPF object failed");
    std::set<std::string> expected_maps, expected_programs, found_maps, found_programs;
    for (const auto &spec:maps) expected_maps.insert(spec.name);
    for (const auto &spec:links) expected_programs.insert(spec.program);
    expected_programs.insert("drain_tasks"); // Loaded, never linked or pinned.
    bpf_map *map;
    bpf_object__for_each_map(map, object.get()) found_maps.insert(bpf_map__name(map));
    bpf_program *program;
    bpf_object__for_each_program(program, object.get()) found_programs.insert(bpf_program__name(program));
    if (found_maps != expected_maps || found_programs != expected_programs)
        fail("BPF object inventory does not match this loader's map and program set");
    int rc = bpf_object__load(object.get());
    if (rc) fail("BPF verifier/load rejected classifier: " + std::string(strerror(-rc)));
    int conf = bpf_object__find_map_fd_by_name(object.get(), "policy_cfg");
    uint32_t zero = 0;
    check(bpf_map_update_elem(conf, &zero, &cfg, BPF_ANY) == 0, "initialize blocked config");
    initialize_paths(object.get(),keys);
    seed_guards(object.get(),cfg.netns);
    /* Pin into a staging directory and publish it with one rename, so a load
     * killed midway (for example by the caller's timeout) never leaves a
     * half-populated directory under the owned name. */
    check(mkdir(staging.c_str(), 0700) == 0, "create exclusive staging pin directory");
    try {
        for (const auto &spec:maps)
            check(bpf_map__pin(bpf_object__find_map_by_name(object.get(),spec.name),(staging/spec.name).c_str())==0,"pin map");
        interruption_point("maps");
        Fd cg(open(group.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        for (const auto &spec:links) {
            auto *target=bpf_object__find_program_by_name(object.get(),spec.program);
            if (!target) fail("program missing from object: "+std::string(spec.program));
            std::unique_ptr<bpf_link,decltype(&bpf_link__destroy)> link(
                spec.kind==LINK_CGROUP ? bpf_program__attach_cgroup(target,cg.value) : spec.kind==LINK_FEXIT ?
                bpf_program__attach_trace(target) : bpf_program__attach_lsm(target),
                bpf_link__destroy);
            if (!link) fail("attach failed: "+std::string(spec.hook)+": "+strerror(errno));
            check(bpf_link__pin(link.get(),(staging/spec.pin).c_str())==0,"pin link");
            interruption_point(spec.pin);
        }
        verify_owner(staging);
        verify_context(staging, group);
        if (auto outcome = drain(object.get(), staging); outcome != Drain::Settled)
            std::cerr << "guard not settled yet (" << (outcome == Drain::Deadline ? "drain deadline reached" : "a task stays unproven")
                      << "): a unix_bind or vfs_rename call may predate it; deciding per call\n";
        interruption_point("verified");
        if (!record.empty()) write_birth_record(record, staging);
        check(rename(staging.c_str(), dir.c_str()) == 0, "publish pin directory");
    } catch (...) {
        /* Only this attempt is removed; an interrupted generation keeps
         * protecting until a later load publishes its replacement. */
        discard_staging(staging);
        throw;
    }
    interruption_point("published");
    /* The published generation now protects; detach what it replaced. */
    for (const auto &item:stale) discard_staging(item.path);
    std::cout << "abi=" << abi << " state=blocked links=pinned resolver_guards=active restart_audit=required\n";
}
void status(const fs::path &dir) {
    verify_owner(dir);
    auto cfg = configuration(dir);
    std::cout << "abi=" << cfg.version << " state=" << (cfg.ready ? "ready" : "blocked")
              << " mask=" << cfg.mask << " mark=" << cfg.mark << "\n";
    const std::array<const char *, 9> names{"direct", "included", "blocked", "unsupported_context",
        "exe_error", "path_error", "unlinked_image", "unsupported_socket", "sockopt_error"};
    Fd fd(map_fd(dir, "stats", 4, 8, BPF_MAP_TYPE_PERCPU_ARRAY, names.size()));
    int count = libbpf_num_possible_cpus();
    if (count < 1) fail("cannot discover possible CPUs");
    std::vector<uint64_t> values(count);
    for (uint32_t i = 0; i < names.size(); i++) {
        check(bpf_map_lookup_elem(fd.value, &i, values.data()) == 0, "read stats");
        uint64_t sum = 0;
        for (auto value : values) sum += value;
        std::cout << names[i] << '=' << sum << '\n';
    }
    Fd guards(map_fd(dir,"guard_stats",4,8,BPF_MAP_TYPE_PERCPU_ARRAY,4));
    const std::array<const char *,4> guard_names{"guard_path_lookups","guard_denies","guard_objects","guard_unknown_stream"};
    for (uint32_t i=0;i<guard_names.size();i++) {
        check(bpf_map_lookup_elem(guards.value,&i,values.data())==0,"read guard stats");
        uint64_t sum=0; for (auto value:values) sum+=value;
        std::cout<<guard_names[i]<<'='<<sum<<'\n';
    }
    std::cout<<"resolver_guards=active restart_audit=required unknown_pre_guard_streams=labelled_by_peer_on_first_use\n";
}
std::set<std::string> policy_entries(const fs::path &dir) {
    std::set<std::string> entries;
    for (const auto &spec:maps) {
        if (std::string(spec.name)!="paths" && std::string(spec.name)!="paths_short") continue;
        Fd fd(map_fd(dir,spec.name,spec.key,spec.value,spec.type,spec.entries));
        PathKey key{}, next{}; const PathKey *previous=nullptr;
        while (bpf_map_get_next_key(fd.value,previous,&next)==0) {
            const char *end=static_cast<const char *>(memchr(next.pathname,0,spec.key));
            if (!end) fail("unterminated policy key");
            size_t length=end-next.pathname;
            if ((length<SHORT_PATH_BYTES)!=(spec.key==SHORT_PATH_BYTES))
                fail("policy key in wrong path tier");
            if (!entries.insert(next.pathname).second || entries.size()>1024)
                fail("policy changed during readback or exceeds capacity");
            key=next; previous=&key;
        }
        if (errno!=ENOENT) fail("read policy keys");
    }
    return entries;
}
void change_path(const fs::path &dir, const PathKey &key, bool adding, const std::string &command) {
    const auto &spec=path_map_spec(key);
    Fd fd(map_fd(dir,spec.name,spec.key,spec.value,spec.type,spec.entries));
    uint32_t value=1;
    if (adding) {
        /* The caller holds the directory's exclusive ownership lock. Both maps
         * share one limit; re-adding an existing exact key remains idempotent. */
        uint32_t previous=0;
        if (bpf_map_lookup_elem(fd.value,&key,&previous)) {
            if (errno!=ENOENT) fail("read policy before add");
            if (policy_entries(dir).size()>=1024) fail("policy exceeds combined path capacity");
        }
    }
    check((adding ? bpf_map_update_elem(fd.value,&key,&value,BPF_ANY) :
           bpf_map_delete_elem(fd.value,&key))==0,command);
}
void policy_json(const fs::path &dir) {
    auto entries=policy_entries(dir);
    std::cout<<'['; bool comma=false;
    for (const auto &entry:entries) { if (comma) std::cout<<','; comma=true; std::cout<<json_string(entry); }
    std::cout<<']';
}
/* The earlier (128-entry) generation's programs never gate on settling. */
bool settled(const fs::path &dir) {
    Fd slots(bpf_obj_get((dir/"guard_slots").c_str()));
    bpf_map_info info{}; uint32_t size=sizeof(info);
    check(bpf_obj_get_info_by_fd(slots.value,&info,&size)==0,"read guard slot capacity");
    Fd config(map_fd(dir,"guard_config",4,8,BPF_MAP_TYPE_ARRAY,1));
    uint32_t zero=0; uint64_t epoch=0;
    check(bpf_map_lookup_elem(config.value,&zero,&epoch)==0,"read guard configuration");
    return info.max_entries==128 || (epoch&GUARD_SETTLED);
}
void snapshot_json(const fs::path &dir) {
    auto cfg=configuration(dir);
    std::cout<<"{\"abi\":"<<cfg.version<<",\"ready\":"<<(cfg.ready?"true":"false")
        <<",\"mask\":"<<cfg.mask<<",\"mark\":"<<cfg.mark<<",\"root_dev\":"<<cfg.root_dev
        <<",\"root_ino\":"<<cfg.root_ino<<",\"netns\":"<<cfg.netns<<",\"userns\":"<<cfg.userns
        <<",\"settled\":"<<(settled(dir)?"true":"false")<<','<<identities_json(dir);
    std::cout<<",\"paths\":";
    policy_json(dir); // Same shared ownership lock as configuration and IDs.
    std::cout<<"}\n";
}
void probe_dns(const fs::path &dir) {
    auto cfg=configuration(dir);
    if (!cfg.mask || !cfg.mark || (cfg.mark&~cfg.mask)) fail("invalid probe mark configuration");
    Fd socket(::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0));
    check(setsockopt(socket.value,SOL_SOCKET,SO_MARK,&cfg.mark,sizeof(cfg.mark))==0,"mark native DNS probe");
    uint32_t observed=0; socklen_t mark_size=sizeof(observed);
    check(getsockopt(socket.value,SOL_SOCKET,SO_MARK,&observed,&mark_size)==0 && observed==cfg.mark,"verify DNS probe mark");
    timeval timeout{2,0};
    check(setsockopt(socket.value,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0,"bound DNS probe wait");
    std::array<unsigned char,29> query{0,0,1,0,0,1,0,0,0,0,0,0,
        7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    check(getrandom(query.data(),2,GRND_NONBLOCK)==2,"initialize DNS probe transaction");
    sockaddr_in target{}; target.sin_family=AF_INET; target.sin_port=htons(53);
    check(inet_pton(AF_INET,"127.0.0.53",&target.sin_addr)==1,"initialize DNS probe destination");
    check(sendto(socket.value,query.data(),query.size(),0,reinterpret_cast<sockaddr *>(&target),sizeof(target))==static_cast<ssize_t>(query.size()),"send native DNS probe");
    std::array<unsigned char,4096> answer{}; sockaddr_in peer{}; socklen_t peer_size=sizeof(peer);
    ssize_t size=recvfrom(socket.value,answer.data(),answer.size(),0,reinterpret_cast<sockaddr *>(&peer),&peer_size);
    if (size<static_cast<ssize_t>(query.size()+12) || peer_size!=sizeof(peer) || peer.sin_family!=AF_INET ||
        peer.sin_addr.s_addr!=target.sin_addr.s_addr || peer.sin_port!=target.sin_port ||
        answer[0]!=query[0] || answer[1]!=query[1] || (answer[2]&0xfa)!=0x80 || (answer[3]&0xf) ||
        answer[4] || answer[5]!=1 || (!answer[6] && !answer[7]) ||
        memcmp(answer.data()+12,query.data()+12,query.size()-12))
        fail("native DNS probe timed out or returned an invalid original-peer answer");
    std::cout<<"{\"dns\":true}\n";
}
// Read-only request loop over inherited anonymous pipes. Reopen and verify
// every pin/map/link/program under a fresh lock on every operation. Nothing
// mutable (including configuration or policy) is retained between requests.
void observe(const fs::path &dir) {
    char request[32];
    while (std::cin.getline(request,sizeof(request))) {
        std::string operation=request;
        if (operation!="snapshot" && operation!="probe-dns") fail("unsupported observation");
        if (operation=="probe-dns") require_mutation_host();
        Fd lock(open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        check(flock(lock.value,operation=="snapshot"?LOCK_SH:LOCK_EX)==0,"lock observation");
        verify_owner(dir);
        if (operation=="snapshot") snapshot_json(dir);
        else probe_dns(dir);
        std::cout.flush();
        if (!std::cout) fail("observation pipe closed");
    }
    if (!std::cin.eof()) fail("invalid observation request");
}
void capabilities() {
    struct utsname name{};
    check(uname(&name) == 0, "uname");
    std::cout << "abi=" << abi << " kernel=" << name.release << " libbpf=" << libbpf_version_string()
              << "\nlsm=" << read_text("/sys/kernel/security/lsm") << '\n'
              << "coverage=host-root,host-netns,any-userns;private-mounts-with-host-root\n"
              << "unsupported-context=outside-classification;restart-required=yes;cache=none\n"
              << "attachment-and-helper-support=unverified-until-load\n";
    std::unique_ptr<btf, decltype(&btf__free)> types(btf__load_vmlinux_btf(), btf__free);
    if (!types) fail("kernel BTF unavailable");
    for (const char *symbol : {"bpf_get_task_exe_file", "bpf_put_file", "bpf_path_d_path",
                               "bpf_preempt_disable", "bpf_preempt_enable",
                              "bpf_lsm_socket_post_create"})
        std::cout << symbol << "_btf=" << btf__find_by_name_kind(types.get(), symbol, BTF_KIND_FUNC) << '\n';
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "capabilities") { capabilities(); return 0; }
        if (argc == 3 && std::string(argv[1]) == "observe") { observe(argv[2]); return 0; }
        if (argc == 3 && std::string(argv[1]) == "status") { status(argv[2]); return 0; }
        if (argc==3 && (std::string(argv[1])=="policy" || std::string(argv[1])=="snapshot")) {
            Fd lock(open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC));
            check(flock(lock.value,LOCK_SH)==0,"lock policy readback"); verify_owner(argv[2]);
            if (std::string(argv[1])=="policy") { policy_json(argv[2]); std::cout<<'\n'; }
            else snapshot_json(argv[2]);
            return 0;
        }
        if (argc < 3) fail("commands: capabilities | load | load-policy | load-policy-stdin | settle | path-add | path-add-policy | path-del | guard-slot | state | status | policy | snapshot | probe-dns | remove");
        require_mutation_host();
        std::string command = argv[1];
        if (command == "load" || command == "load-policy" || command == "load-policy-stdin") { load(argc, argv); return 0; }
        fs::path dir = argv[2];
        if (command=="discard" && argc==3) { discard(dir); return 0; }
        if (command=="drain-report" && argc==3) { // OBJECT: outermost frames of one scan.
            std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(bpf_object__open_file(argv[2], nullptr), bpf_object__close);
            if (!object) fail("open BPF object failed");
            bpf_program *program;
            bpf_object__for_each_program(program, object.get())
                bpf_program__set_autoload(program, std::string(bpf_program__name(program))=="drain_tasks");
            check(bpf_object__load(object.get())==0, "load task stack iterator");
            drain_report(object.get()); return 0;
        }
        Fd owner_lock(open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        check(flock(owner_lock.value,LOCK_EX)==0,"lock owned pin directory for mutation");
        verify_owner(dir);
        if (command=="probe-dns" && argc==3) { probe_dns(dir); return 0; }
        if ((command == "path-add" || command == "path-add-policy" || command == "path-del") && argc == 4) {
            bool adding = command != "path-del";
            auto key = path_key(argv[3], command == "path-add");
            change_path(dir,key,adding,command);
        } else if (command=="drain" && argc==4) {
            /* Retry settling a published guard: only the iterator is loaded. */
            std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
                bpf_object__open_file(argv[3], nullptr), bpf_object__close);
            if (!object) fail("open BPF object failed");
            bpf_program *program;
            bpf_object__for_each_program(program, object.get())
                bpf_program__set_autoload(program, std::string(bpf_program__name(program))=="drain_tasks");
            check(bpf_object__load(object.get())==0, "load task stack iterator");
            std::cout<<"settled="<<(drain(object.get(),dir)==Drain::Settled)<<'\n';
        } else if (command=="guard-slot" && argc==5) {
            auto cfg=configuration(dir);
            if (cfg.ready) fail("guard configuration changes require blocked state");
            Fd slots(bpf_obj_get((dir/"guard_slots").c_str())), dirs(bpf_obj_get((dir/"guard_dirs").c_str()));
            Fd names(bpf_obj_get((dir/"endpoint_names").c_str())), roles(bpf_obj_get((dir/"object_roles").c_str()));
            Fd generation(map_fd(dir,"guard_config",4,8,BPF_MAP_TYPE_ARRAY,1));
            uint32_t zero=0; uint64_t epoch=0;
            check(bpf_map_lookup_elem(generation.value,&zero,&epoch)==0,"read role generation");
            if ((epoch&1) || epoch>UINT64_MAX-2) fail("guard update incomplete/exhausted; reinstall guards");
            ++epoch;
            check(bpf_map_update_elem(generation.value,&zero,&epoch,BPF_ANY)==0,"begin guarded configuration update");
            auto finish=[&]() {
                ++epoch;
                check(bpf_map_update_elem(generation.value,&zero,&epoch,BPF_ANY)==0,"invalidate previous stream roles");
            };
            try { guard_slot_add({slots.value,dirs.value,names.value,roles.value},cfg.netns,argv[3],argv[4]); }
            catch (...) { finish(); throw; }
            finish();
        } else if (command == "state" && argc == 4) {
            auto cfg = configuration(dir);
            if (std::string(argv[3]) != "ready" && std::string(argv[3]) != "blocked") fail("state must be blocked or ready");
            cfg.ready = std::string(argv[3]) == "ready";
            if (cfg.ready) {
                Fd generation(map_fd(dir,"guard_config",4,8,BPF_MAP_TYPE_ARRAY,1));
                uint32_t zero=0; uint64_t epoch=0;
                check(bpf_map_lookup_elem(generation.value,&zero,&epoch)==0,"read guard configuration state");
                if (epoch&1) fail("guard update incomplete; reinstall guards before ready");
                ready_preflight();
            }
            Fd fd(map_fd(dir, "policy_cfg", 4, sizeof(Configuration), BPF_MAP_TYPE_ARRAY, 1));
            uint32_t zero = 0;
            check(bpf_map_update_elem(fd.value, &zero, &cfg, BPF_ANY) == 0, "update state");
        } else if (command == "settle" && argc == 4) {
            settle(dir, fs::canonical(argv[3]));
        } else if (command == "remove" && argc == 3) {
            remove_pins(dir);
        } else fail("invalid command or argument count");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "bpf-loader: " << error.what() << '\n';
        return 1;
    }
}
