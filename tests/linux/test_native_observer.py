# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify immutable metadata reuse still rejects changed live BPF identities."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

HARNESS = r'''
#define main loader_main
#include LOADER_SOURCE
#undef main
static unsigned loads=0, frees=0;
static int fault=0;
extern "C" btf *__wrap_btf__load_vmlinux_btf() { ++loads; return reinterpret_cast<btf*>(1); }
extern "C" void __wrap_btf__free(btf *) { ++frees; }
extern "C" int __wrap_btf__find_by_name_kind(const btf *, const char *name, __u32) {
    for (size_t i=0;i<links.size();++i)
        if (std::string(name)==std::string("bpf_lsm_")+links[i].hook) return 1000+i;
    return -1;
}
extern "C" int __wrap_bpf_obj_get(const char *path) {
    auto name=fs::path(path).filename();
    for (size_t i=0;i<maps.size();++i) if (name==maps[i].name) return 10000+i;
    for (size_t i=0;i<links.size();++i) if (name==links[i].pin) return 20000+i;
    return -1;
}
extern "C" int __wrap_bpf_prog_get_fd_by_id(__u32 id) { return 30000+id; }
extern "C" int __wrap_bpf_map_lookup_elem(int, const void *, void *value) {
    auto &cfg=*static_cast<Configuration*>(value); cfg={}; cfg.version=abi; return 0;
}
extern "C" int __wrap_bpf_obj_get_info_by_fd(int fd, void *data, __u32 *) {
    if (fd<20000) {
        size_t i=fd-10000; const auto &spec=maps.at(i);
        auto &info=*static_cast<bpf_map_info*>(data); info={};
        info.type=spec.type; info.key_size=spec.key; info.value_size=spec.value;
        info.max_entries=spec.entries; info.id=100+i+(fault==1 && i==0 ? 5000:0);
        std::strcpy(info.name,spec.name);
    } else if (fd<30000) {
        size_t i=fd-20000; const auto &spec=links.at(i);
        auto &info=*static_cast<bpf_link_info*>(data); info={}; info.prog_id=i;
        if (spec.cgroup) { info.type=BPF_LINK_TYPE_CGROUP; info.cgroup.attach_type=BPF_LSM_CGROUP; }
        else { info.type=BPF_LINK_TYPE_TRACING; info.tracing.attach_type=BPF_LSM_MAC;
               info.tracing.target_btf_id=1000+i+(fault==2 ? 1:0); }
    } else {
        size_t i=fd-30000;
        auto &info=*static_cast<bpf_prog_info*>(data);
        if (info.map_ids) {
            auto ids=reinterpret_cast<uint32_t*>(info.map_ids);
            for (size_t j=0;j<maps.size();++j) ids[j]=100+j;
        } else {
            info={}; info.type=BPF_PROG_TYPE_LSM; info.attach_btf_id=1000+i;
            info.nr_map_ids=maps.size(); std::strcpy(info.name,links.at(i).program);
            if (fault==3) info.name[0]='X';
        }
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc!=2) return 2;
    verify_owner(argv[1]); verify_owner(argv[1]);
    if (loads!=1 || frees!=1) return 3;
    for (fault=1;fault<=3;++fault) {
        bool rejected=false;
        try { verify_owner(argv[1]); } catch (const std::exception &) { rejected=true; }
        if (!rejected) return 4;
    }
    fault=0; verify_owner(argv[1]);
    if (loads!=1 || frees!=1) return 5;
    std::cout<<"PASS: cached kernel types retain fresh map/link/program ownership checks\n";
}
'''


class NativeObserverTests(unittest.TestCase):
    def test_mutable_identity_changes_are_rejected_after_metadata_reuse(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temp:
            source, executable = Path(temp)/'observer.cpp', Path(temp)/'observer'
            source.write_text(HARNESS)
            wrappers = ('btf__load_vmlinux_btf', 'btf__free', 'btf__find_by_name_kind',
                        'bpf_obj_get', 'bpf_prog_get_fd_by_id', 'bpf_map_lookup_elem', 'bpf_obj_get_info_by_fd')
            flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libbpf'], text=True))
            subprocess.run(['c++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
                            f'-DLOADER_SOURCE="{repo / "src/linux/native/bpf-loader.cpp"}"',
                            str(source), '-o', str(executable),
                            *['-Wl,--wrap='+name for name in wrappers], *flags], check=True, capture_output=True)
            pins = Path(temp)/'pins'; pins.mkdir()
            result = subprocess.run([str(executable), str(pins)], check=True, capture_output=True, text=True)
            self.assertIn('PASS:', result.stdout)
