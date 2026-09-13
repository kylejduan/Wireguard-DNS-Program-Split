// SPDX-License-Identifier: GPL-3.0-or-later
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sys/ioctl.h>
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
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include "../bpf/policy.bpf.h"

namespace {
namespace fs = std::filesystem;
constexpr uint32_t abi = POLICY_ABI;
using PathKey = policy_path;
using Configuration = policy_config;
static_assert(sizeof(Configuration) == 40);
struct MapSpec { const char *name; uint32_t key, value, type, entries; };
const std::array<MapSpec,12> maps{{
    {"paths",sizeof(PathKey),4,BPF_MAP_TYPE_HASH,1024},
    {"policy_cfg",4,sizeof(Configuration),BPF_MAP_TYPE_ARRAY,1},
    {"scratch",4,sizeof(path_scratch),BPF_MAP_TYPE_PERCPU_ARRAY,1},
    {"stats",4,8,BPF_MAP_TYPE_PERCPU_ARRAY,9},
    {"guard_slots",sizeof(guard_slot),4,BPF_MAP_TYPE_HASH,128},
    {"guard_dirs",sizeof(object_id),4,BPF_MAP_TYPE_HASH,32},
    {"endpoint_names",sizeof(endpoint_name),4,BPF_MAP_TYPE_HASH,128},
    {"object_roles",4,4,BPF_MAP_TYPE_INODE_STORAGE,0},
    {"stream_roles",4,sizeof(stream_label),BPF_MAP_TYPE_SK_STORAGE,0},
    {"role_generation",4,8,BPF_MAP_TYPE_ARRAY,1},
    {"guard_config",4,8,BPF_MAP_TYPE_ARRAY,1},
    {"guard_stats",4,8,BPF_MAP_TYPE_PERCPU_ARRAY,4}}};
struct LinkSpec { const char *pin, *program, *hook; bool cgroup; };
const std::array<LinkSpec,12> links{{
    {"link","classify","socket_post_create",true},
    {"link_connect","guard_connect","unix_stream_connect",false},
    {"link_datagram","guard_datagram","unix_may_send",false},
    {"link_pair","guard_pair","socket_socketpair",false},
    {"link_open","guard_open","file_open",false},
    {"link_mmap","guard_mmap","mmap_file",false},
    {"link_read","guard_read","file_permission",false},
    {"link_receive","guard_receive","file_receive",false},
    {"link_send","guard_send","socket_sendmsg",false},
    {"link_recv","guard_recv","socket_recvmsg",false},
    {"link_rename","guard_rename","inode_rename",false},
    {"link_bind","guard_bind","socket_bind",false}}};
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
    if (release.rfind("7.0.",0)!=0 || release.find("microsoft")!=std::string::npos)
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
    if (!adding && path.lexically_normal().string() != input)
        fail("stored policy requires the exact canonical key, without . or .. components");
    auto text = path.string();
    if (text.size() >= sizeof(PathKey)) fail("executable path exceeds ABI pathname capacity");
    if (adding) {
        Fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
        struct stat st{};
        check(fstat(fd.value, &st) == 0, "fstat executable");
        Elf64_Ehdr header{};
        if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111) ||
            read(fd.value, &header, sizeof(header)) != sizeof(header) ||
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
int map_fd(const fs::path &dir, const char *name, uint32_t key_size,
           uint32_t value_size, uint32_t type, uint32_t entries) {
    int fd = bpf_obj_get((dir / name).c_str());
    if (fd < 0) fail("open pinned map " + std::string(name) + ": " + std::strerror(errno));
    bpf_map_info info{};
    uint32_t length = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &length) || info.key_size != key_size ||
        info.value_size != value_size || info.type != type || info.max_entries != entries ||
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
void verify_owner(const fs::path &dir) {
    std::set<std::string> expected;
    for (const auto &spec:maps) expected.insert(spec.name);
    for (const auto &spec:links) expected.insert(spec.pin);
    for (const auto &entry:fs::directory_iterator(dir))
        if (!expected.count(entry.path().filename())) fail("unknown pin-directory entry");
    (void)configuration(dir);
    std::set<uint32_t> owned, used;
    for (const auto &spec:maps) {
        Fd fd(map_fd(dir,spec.name,spec.key,spec.value,spec.type,spec.entries));
        bpf_map_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read owned map");
        owned.insert(info.id);
    }
    std::unique_ptr<btf,decltype(&btf__free)> types(btf__load_vmlinux_btf(),btf__free);
    if (!types) fail("kernel BTF unavailable");
    for (const auto &spec:links) {
        Fd link(bpf_obj_get((dir/spec.pin).c_str()));
        bpf_link_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(link.value,&info,&size)==0,"read owned link");
        auto hook=std::string("bpf_lsm_")+spec.hook;
        int target=btf__find_by_name_kind(types.get(),hook.c_str(),BTF_KIND_FUNC);
        if (spec.cgroup ? (info.type!=BPF_LINK_TYPE_CGROUP || info.cgroup.attach_type!=BPF_LSM_CGROUP) :
            (info.type!=BPF_LINK_TYPE_TRACING || info.tracing.attach_type!=BPF_LSM_MAC ||
             info.tracing.target_btf_id!=static_cast<uint32_t>(target))) fail("link attachment identity mismatch");
        Fd prog(bpf_prog_get_fd_by_id(info.prog_id));
        bpf_prog_info program{}; size=sizeof(program);
        check(bpf_obj_get_info_by_fd(prog.value,&program,&size)==0,"read program");
        if (program.type!=BPF_PROG_TYPE_LSM || std::string(program.name)!=spec.program ||
            program.attach_btf_id!=static_cast<uint32_t>(target)) fail("program hook identity mismatch");
        std::vector<uint32_t> ids(program.nr_map_ids);
        program={}; program.nr_map_ids=ids.size(); program.map_ids=reinterpret_cast<uint64_t>(ids.data());
        check(bpf_obj_get_info_by_fd(prog.value,&program,&size)==0,"read program maps");
        for (auto id:ids) {
            if (!owned.count(id)) fail("linked program references an unowned map");
            used.insert(id);
        }
    }
    if (owned!=used) fail("pinned map is not used by the owned link set");
}
void reject_competitors(const fs::path &group) {
    Fd fd(open(group.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    uint32_t count = 0;
    int rc = bpf_prog_query(fd.value, BPF_LSM_CGROUP, BPF_F_QUERY_EFFECTIVE,
                            nullptr, nullptr, &count);
    if (rc && errno != ENOSPC) fail("cannot query effective cgroup LSM attachments: " + std::string(strerror(errno)));
    if (count) fail("competing cgroup LSM attachments can override denial: " + group.string());
}
object_id identity(const struct stat &st) {
    return {(static_cast<uint64_t>(major(st.st_dev))<<20)|minor(st.st_dev),st.st_ino};
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
        auto key=identity(st); merge_role(fd.dirs,&key,role); return;
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
        guard_slot slot{}; slot.parent=identity(st);
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
void seed_guards(bpf_object *object,uint32_t netns) {
    auto fd=guard_maps(object);
    for (const char *path:{"/run/systemd/resolve/io.systemd.Resolve","/run/nscd/socket",
            "/var/run/nscd/socket","/run/avahi-daemon/socket","/var/run/avahi-daemon/socket",
            "/run/dbus/system_bus_socket","/var/run/dbus/system_bus_socket"})
        guard_slot_add(fd,netns,"socket",path);
    for (const char *path:{"/run","/var/cache","/var/lib"})
        guard_slot_add(fd,netns,"nscd-parent",path);
    auto runtime=identity(stat_path("/run")); merge_role(fd.dirs,&runtime,ROLE_RUNTIME);
    auto systemd=identity(stat_path("/run/systemd")); merge_role(fd.dirs,&systemd,ROLE_SYSTEMD);
    if (fs::exists("/run/user")) {
        guard_slot_add(fd,netns,"user-bus-dir","/run/user");
        for (const auto &entry:fs::directory_iterator("/run/user")) {
            auto name=entry.path().filename().string();
            if (name.empty() || name.find_first_not_of("0123456789")!=std::string::npos) continue;
            if (entry.is_directory() && stat_path(entry.path()).st_uid==number(name))
                guard_slot_add(fd,netns,"socket",entry.path()/"bus");
        }
    }
    for (const char *path:{"/run/nscd","/var/cache/nscd","/var/lib/nscd"}) {
        if (!fs::exists(path)) continue;
        guard_slot_add(fd,netns,"cache-dir",path);
        for (const auto &entry:fs::directory_iterator(path)) {
            auto name=entry.path().filename().string();
            if (entry.is_regular_file() && (name=="hosts" || (name.size()==8 && name.substr(0,2)=="db")))
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
void load(int argc, char **argv) {
    if (argc < 7) fail("load OBJECT PIN_DIR CGROUP MASK MARK [PATH...]");
    bool bulk = std::string(argv[1]) == "load-policy-stdin";
    if ((bulk && argc != 7) || argc > 7+1024) fail("invalid policy arguments/count");
    std::vector<PathKey> keys;
    if (bulk) keys = read_policy_stdin(std::cin);
    else for (int i=7; i<argc; i++) keys.push_back(path_key(argv[i],std::string(argv[1])=="load"));
    fs::path dir = fs::absolute(argv[3]), group = fs::canonical(argv[4]);
    struct statfs bpffs{}, cgfs{};
    check(statfs(dir.parent_path().c_str(), &bpffs) == 0 && bpffs.f_type == BPF_FS_MAGIC,
          "PIN_DIR parent must be bpffs");
    check(statfs(group.c_str(), &cgfs) == 0 && cgfs.f_type == CGROUP2_SUPER_MAGIC,
          "CGROUP must be cgroup v2");
    reject_competitors(group);
    for (const auto &entry : fs::recursive_directory_iterator(group))
        if (entry.is_directory()) reject_competitors(entry.path());
    auto root = stat_path("/");
    Configuration cfg{abi, 0, number(argv[5]), number(argv[6]),
        (static_cast<uint64_t>(major(root.st_dev)) << 20) | minor(root.st_dev),
        root.st_ino, static_cast<uint32_t>(stat_path("/proc/self/ns/net").st_ino),
        static_cast<uint32_t>(stat_path("/proc/self/ns/user").st_ino)};
    if (!cfg.mask || !cfg.mark || (cfg.mark & ~cfg.mask)) fail("MARK must be nonzero and contained in MASK");
    std::vector<char> log(4 * 1024 * 1024);
    bpf_object_open_opts opts{};
    opts.sz = sizeof(opts);
    opts.kernel_log_buf = log.data();
    opts.kernel_log_size = log.size();
    opts.kernel_log_level = 1;
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(
        bpf_object__open_file(argv[2], &opts), bpf_object__close);
    if (!object) fail("open BPF object failed");
    int rc = bpf_object__load(object.get());
    std::cerr << log.data();
    if (rc) fail("BPF verifier/load rejected classifier: " + std::to_string(rc));
    int conf = bpf_object__find_map_fd_by_name(object.get(), "policy_cfg");
    int paths = bpf_object__find_map_fd_by_name(object.get(), "paths");
    uint32_t zero = 0, selected = 1;
    check(bpf_map_update_elem(conf, &zero, &cfg, BPF_ANY) == 0, "initialize blocked config");
    for (const auto &key : keys)
        check(bpf_map_update_elem(paths, &key, &selected, BPF_NOEXIST) == 0, "initialize path");
    seed_guards(object.get(),cfg.netns);
    check(mkdir(dir.c_str(), 0700) == 0, "create exclusive pin directory");
    std::vector<fs::path> pinned;
    try {
        for (const auto &spec:maps) {
            auto path=dir/spec.name;
            check(bpf_map__pin(bpf_object__find_map_by_name(object.get(),spec.name),path.c_str())==0,"pin map");
            pinned.push_back(path);
        }
        Fd cg(open(group.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        for (const auto &spec:links) {
            auto *program=bpf_object__find_program_by_name(object.get(),spec.program);
            std::unique_ptr<bpf_link,decltype(&bpf_link__destroy)> link(
                spec.cgroup ? bpf_program__attach_cgroup(program,cg.value) : bpf_program__attach_lsm(program),
                bpf_link__destroy);
            if (!link) fail("attach failed: "+std::string(spec.hook)+": "+strerror(errno));
            check(bpf_link__pin(link.get(),(dir/spec.pin).c_str())==0,"pin link");
            pinned.push_back(dir/spec.pin);
        }
        verify_owner(dir);
    } catch (...) {
        for (auto it = pinned.rbegin(); it != pinned.rend(); ++it) fs::remove(*it);
        fs::remove(dir);
        throw;
    }
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
    std::cout<<"resolver_guards=active restart_audit=required unknown_pre_guard_streams=denied_for_selected\n";
}
std::string json_string(const std::string &text) {
    std::string output="\"";
    for (size_t i=0;i<text.size();i++) {
        unsigned char ch=text[i];
        if (ch=='"' || ch=='\\') { output+='\\'; output+=ch; }
        else if (ch<32) { output+="\\u00"; output+="0123456789abcdef"[ch>>4]; output+="0123456789abcdef"[ch&15]; }
        else if (ch<128) output+=ch;
        else {
            size_t length=ch>=0xc2 && ch<=0xdf ? 2 : ch>=0xe0 && ch<=0xef ? 3 : ch>=0xf0 && ch<=0xf4 ? 4 : 0;
            bool valid=length && i+length<=text.size();
            for (size_t n=1;valid && n<length;n++) valid=(static_cast<unsigned char>(text[i+n])&0xc0)==0x80;
            if (valid) {
                unsigned char second=text[i+1];
                valid=!((ch==0xe0 && second<0xa0) || (ch==0xed && second>=0xa0) ||
                        (ch==0xf0 && second<0x90) || (ch==0xf4 && second>=0x90));
            }
            if (valid) { output.append(text,i,length); i+=length-1; }
            else { output+="\\udc"; output+="0123456789abcdef"[ch>>4]; output+="0123456789abcdef"[ch&15]; }
        }
    }
    return output+'"';
}
void policy_json(const fs::path &dir) {
    Fd fd(map_fd(dir,"paths",sizeof(PathKey),4,BPF_MAP_TYPE_HASH,1024));
    PathKey key{}, next{}; const PathKey *previous=nullptr;
    std::set<std::string> entries;
    while (bpf_map_get_next_key(fd.value,previous,&next)==0) {
        if (!memchr(next.pathname,0,sizeof(next.pathname))) fail("unterminated policy key");
        entries.insert(next.pathname); key=next; previous=&key;
        if (entries.size()>1024) fail("policy changed during readback");
    }
    if (errno!=ENOENT) fail("read policy keys");
    std::cout<<'['; bool comma=false;
    for (const auto &entry:entries) { if (comma) std::cout<<','; comma=true; std::cout<<json_string(entry); }
    std::cout<<"]\n";
}
void snapshot_json(const fs::path &dir) {
    auto cfg=configuration(dir);
    std::cout<<"{\"abi\":"<<cfg.version<<",\"ready\":"<<(cfg.ready?"true":"false")
        <<",\"mask\":"<<cfg.mask<<",\"mark\":"<<cfg.mark<<",\"root_dev\":"<<cfg.root_dev
        <<",\"root_ino\":"<<cfg.root_ino<<",\"netns\":"<<cfg.netns<<",\"userns\":"<<cfg.userns<<",\"maps\":{";
    bool comma=false;
    for (const auto &spec:maps) {
        Fd fd(bpf_obj_get((dir/spec.name).c_str())); bpf_map_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read map identity");
        if (comma) std::cout<<',';
        comma=true; std::cout<<json_string(spec.name)<<':'<<info.id;
    }
    std::cout<<"},\"links\":{"; comma=false;
    for (const auto &spec:links) {
        Fd fd(bpf_obj_get((dir/spec.pin).c_str())); bpf_link_info info{}; uint32_t size=sizeof(info);
        check(bpf_obj_get_info_by_fd(fd.value,&info,&size)==0,"read link identity");
        if (comma) std::cout<<',';
        comma=true; std::cout<<json_string(spec.pin)<<":{\"id\":"<<info.id<<",\"program_id\":"<<info.prog_id;
        if (spec.cgroup) std::cout<<",\"cgroup_id\":"<<info.cgroup.cgroup_id;
        std::cout<<'}';
    }
    std::cout<<"}}\n";
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
void capabilities() {
    struct utsname name{};
    check(uname(&name) == 0, "uname");
    std::cout << "abi=" << abi << " kernel=" << name.release << " libbpf=" << libbpf_version_string()
              << "\nlsm=" << read_text("/sys/kernel/security/lsm") << '\n'
              << "coverage=host-root,host-netns,host-userns;private-mounts-with-host-root\n"
              << "unsupported-context=outside-classification;restart-required=yes;cache=none\n"
              << "attachment-and-helper-support=unverified-until-load\n";
    std::unique_ptr<btf, decltype(&btf__free)> types(btf__load_vmlinux_btf(), btf__free);
    if (!types) fail("kernel BTF unavailable");
    for (const char *symbol : {"bpf_get_task_exe_file", "bpf_put_file", "bpf_path_d_path",
                              "bpf_lsm_socket_post_create"})
        std::cout << symbol << "_btf=" << btf__find_by_name_kind(types.get(), symbol, BTF_KIND_FUNC) << '\n';
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "capabilities") { capabilities(); return 0; }
        if (argc == 3 && std::string(argv[1]) == "status") { status(argv[2]); return 0; }
        if (argc==3 && (std::string(argv[1])=="policy" || std::string(argv[1])=="snapshot")) {
            Fd lock(open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC));
            check(flock(lock.value,LOCK_SH)==0,"lock policy readback"); verify_owner(argv[2]);
            if (std::string(argv[1])=="policy") policy_json(argv[2]); else snapshot_json(argv[2]);
            return 0;
        }
        if (argc < 3) fail("commands: capabilities | load | load-policy | load-policy-stdin | path-add | path-add-policy | path-del | guard-slot | state | status | policy | snapshot | probe-dns | remove");
        require_mutation_host();
        std::string command = argv[1];
        if (command == "load" || command == "load-policy" || command == "load-policy-stdin") { load(argc, argv); return 0; }
        fs::path dir = argv[2];
        Fd owner_lock(open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        check(flock(owner_lock.value,LOCK_EX)==0,"lock owned pin directory for mutation");
        verify_owner(dir);
        if (command=="probe-dns" && argc==3) { probe_dns(dir); return 0; }
        if ((command == "path-add" || command == "path-add-policy" || command == "path-del") && argc == 4) {
            bool adding = command != "path-del";
            auto key = path_key(argv[3], command == "path-add");
            Fd fd(map_fd(dir, "paths", sizeof(PathKey), 4, BPF_MAP_TYPE_HASH, 1024));
            uint32_t value = 1;
            check((adding ? bpf_map_update_elem(fd.value, &key, &value, BPF_ANY) :
                   bpf_map_delete_elem(fd.value, &key)) == 0, command);
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
        } else if (command == "remove" && argc == 3) {
            for (const auto &spec:links) check(unlink((dir/spec.pin).c_str())==0,"remove owned link");
            for (const auto &spec:maps) check(unlink((dir/spec.name).c_str())==0,"remove owned map");
            check(rmdir(dir.c_str()) == 0, "remove owned pin directory");
        } else fail("invalid command or argument count");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "bpf-loader: " << error.what() << '\n';
        return 1;
    }
}
