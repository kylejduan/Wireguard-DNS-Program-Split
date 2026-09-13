// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <linux/magic.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
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

namespace {
namespace fs = std::filesystem;
constexpr uint32_t abi = 1;
struct PathKey { char pathname[4096]{}; };
struct Configuration {
    uint32_t version, ready, mask, mark;
    uint64_t root_dev, root_ino;
    uint32_t netns, userns;
};
static_assert(sizeof(Configuration) == 40);
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
    for (const auto &part : {"root", "ns/net", "ns/user"}) {
        auto current = stat_path(fs::path("/proc/self") / part);
        auto init = stat_path(fs::path("/proc/1") / part);
        if (current.st_ino != init.st_ino || current.st_dev != init.st_dev)
            fail("unsupported enrollment context: requires host root, network and user namespace");
    }
}
void require_vm() {
    struct utsname name{};
    check(uname(&name) == 0, "uname");
    const char *opt = getenv("WG_CLASSIFIER_DISPOSABLE_VM");
    if (!opt || std::string(opt) != "1" || std::strstr(name.release, "microsoft") ||
        std::string(name.nodename) == "TV")
        fail("mutations require WG_CLASSIFIER_DISPOSABLE_VM=1 on the disposable native VM");
    require_host();
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
        fail("path-del requires the exact canonical policy key, without . or .. components");
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
    (void)configuration(dir);
    Fd link(bpf_obj_get((dir / "link").c_str()));
    bpf_link_info info{};
    uint32_t size = sizeof(info);
    check(bpf_obj_get_info_by_fd(link.value, &info, &size) == 0, "read link");
    if (info.type != BPF_LINK_TYPE_CGROUP || info.cgroup.attach_type != BPF_LSM_CGROUP)
        fail("pin is not a classifier cgroup LSM link");
    Fd prog(bpf_prog_get_fd_by_id(info.prog_id));
    bpf_prog_info program{};
    size = sizeof(program);
    check(bpf_obj_get_info_by_fd(prog.value, &program, &size) == 0, "read program");
    if (program.type != BPF_PROG_TYPE_LSM || std::string(program.name) != "classify")
        fail("pin is not the classifier program");
    std::vector<uint32_t> ids(program.nr_map_ids);
    program = {};
    program.nr_map_ids = ids.size();
    program.map_ids = reinterpret_cast<uint64_t>(ids.data());
    check(bpf_obj_get_info_by_fd(prog.value, &program, &size) == 0, "read program maps");
    for (const char *name : {"paths", "policy_cfg", "scratch", "stats"}) {
        Fd map(bpf_obj_get((dir / name).c_str()));
        bpf_map_info mi{};
        uint32_t ms = sizeof(mi);
        check(bpf_obj_get_info_by_fd(map.value, &mi, &ms) == 0, "read owned map");
        bool found = false;
        for (auto id : ids) if (id == mi.id) found = true;
        if (!found || std::string(mi.name) != name) fail("pin map does not belong to linked program");
    }
}
void reject_competitors(const fs::path &group) {
    Fd fd(open(group.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    uint32_t count = 0;
    int rc = bpf_prog_query(fd.value, BPF_LSM_CGROUP, BPF_F_QUERY_EFFECTIVE,
                            nullptr, nullptr, &count);
    if (rc && errno != ENOSPC) fail("cannot query effective cgroup LSM attachments: " + std::string(strerror(errno)));
    if (count) fail("competing cgroup LSM attachments can override denial: " + group.string());
}
void load(int argc, char **argv) {
    if (argc < 7) fail("load OBJECT PIN_DIR CGROUP MASK MARK [PATH...]");
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
    std::vector<PathKey> keys;
    for (int i = 7; i < argc; i++) keys.push_back(path_key(argv[i], true));
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
    check(mkdir(dir.c_str(), 0700) == 0, "create exclusive pin directory");
    std::vector<fs::path> pinned;
    try {
        for (const char *name : {"paths", "policy_cfg", "scratch", "stats"}) {
            auto path = dir / name;
            check(bpf_map__pin(bpf_object__find_map_by_name(object.get(), name), path.c_str()) == 0, "pin map");
            pinned.push_back(path);
        }
        Fd cg(open(group.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link(
            bpf_program__attach_cgroup(bpf_object__find_program_by_name(object.get(), "classify"), cg.value),
            bpf_link__destroy);
        if (!link) fail("attach cgroup LSM failed: " + std::string(strerror(errno)));
        check(bpf_link__pin(link.get(), (dir / "link").c_str()) == 0, "pin link");
        pinned.push_back(dir / "link");
    } catch (...) {
        for (auto it = pinned.rbegin(); it != pinned.rend(); ++it) fs::remove(*it);
        fs::remove(dir);
        throw;
    }
    std::cout << "abi=1 state=blocked link=pinned\n";
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
}
void capabilities() {
    struct utsname name{};
    check(uname(&name) == 0, "uname");
    std::cout << "abi=1 kernel=" << name.release << " libbpf=" << libbpf_version_string()
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
        if (argc < 3) fail("commands: capabilities | load | path-add | path-del | state | status | remove");
        require_vm();
        std::string command = argv[1];
        if (command == "load") { load(argc, argv); return 0; }
        fs::path dir = argv[2];
        verify_owner(dir);
        if ((command == "path-add" || command == "path-del") && argc == 4) {
            bool adding = command == "path-add";
            auto key = path_key(argv[3], adding);
            Fd fd(map_fd(dir, "paths", sizeof(PathKey), 4, BPF_MAP_TYPE_HASH, 1024));
            uint32_t value = 1;
            check((adding ? bpf_map_update_elem(fd.value, &key, &value, BPF_ANY) :
                   bpf_map_delete_elem(fd.value, &key)) == 0, command);
        } else if (command == "state" && argc == 4) {
            auto cfg = configuration(dir);
            if (std::string(argv[3]) != "ready" && std::string(argv[3]) != "blocked") fail("state must be blocked or ready");
            cfg.ready = std::string(argv[3]) == "ready";
            Fd fd(map_fd(dir, "policy_cfg", 4, sizeof(Configuration), BPF_MAP_TYPE_ARRAY, 1));
            uint32_t zero = 0;
            check(bpf_map_update_elem(fd.value, &zero, &cfg, BPF_ANY) == 0, "update state");
        } else if (command == "remove" && argc == 3) {
            for (const auto &entry : fs::directory_iterator(dir)) {
                auto name = entry.path().filename();
                if (name != "link" && name != "paths" && name != "policy_cfg" && name != "scratch" && name != "stats")
                    fail("refusing cleanup: unknown pin-directory entry");
            }
            for (const char *name : {"link", "paths", "policy_cfg", "scratch", "stats"})
                check(unlink((dir / name).c_str()) == 0, "remove owned pin");
            check(rmdir(dir.c_str()) == 0, "remove owned pin directory");
        } else fail("invalid command or argument count");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "bpf-loader: " << error.what() << '\n';
        return 1;
    }
}
