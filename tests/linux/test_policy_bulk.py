#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded filesystem-byte policy transport; privileged proof requires explicit VM mode."""
import argparse
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import uuid

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src/linux'))
from wg_program_split.preflight import ControllerError, NativeGuard


def keys():
    values = [f'/wgps-stored-{index}/' + '/'.join(['a' * 250] * 9) + '/image'
              for index in range(1024)]
    values[:4] = boundary_keys()
    values[4] = "/" + "/".join(["a" * 255] * 15) + "/" + "b" * 254
    values[-1] = '/wgps-raw-' + os.fsdecode(b'\xff') + '/image'
    return values


def boundary_keys():
    # Length is filesystem bytes, including multi-byte UTF-8 and invalid UTF-8.
    return ['/' + 's' * 254, '/' + 'l' * 255,
            '/' + 'é' * 127, '/' + os.fsdecode(b'\xff') * 255]


def packed(values):
    return b''.join(os.fsencode(value) + b'\0' for value in values)


def malformed():
    return {'empty-record': b'\0', 'unterminated': b'/one', 'relative': b'one\0',
            'duplicate': b'/one\0/one\0',
            'duplicate-long': packed([boundary_keys()[1]] * 2), 'dot': b'/one/./two\0',
            'parent': b'/one/../two\0', 'double-slash': b'//one\0',
            'root': b'/\0', 'trailing-slash': b'/one/\0',
            'long-key': b'/' + b'x' * 4095 + b'\0',
            'too-many': packed(f'/entry-{i}' for i in range(1025)),
            'oversized': b'x' * (1024 * 4096 + 1)}


def invoke(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), capture_output=True, timeout=30, **kwargs)


# Only emulate the BPF syscall boundary: production parsing, map ownership
# layout checks and policy enumeration all execute unchanged without attachment.
MAP_HARNESS = r'''
#define main hidden_loader_main
#include LOADER_SOURCE
#undef main
#include <map>
static std::array<std::map<std::string, uint32_t>, 2> fixture;
static size_t width(int fd) { return fd == 100000 ? 4096 : 256; }
static auto &contents(int fd) { return fixture.at(fd - 100000); }
extern "C" int __wrap_bpf_obj_get(const char *path) {
    auto name = fs::path(path).filename();
    if (name == "paths") return 100000;
    if (name == "paths_short") return 100001;
    errno = ENOENT; return -1;
}
extern "C" int __wrap_bpf_obj_get_info_by_fd(int fd, void *data, __u32 *) {
    auto &info = *static_cast<bpf_map_info *>(data); info = {};
    info.type = BPF_MAP_TYPE_HASH; info.key_size = width(fd);
    info.value_size = 4; info.max_entries = 1024;
    std::strcpy(info.name, fd == 100000 ? "paths" : "paths_short");
    return 0;
}
extern "C" int __wrap_bpf_map_get_next_key(int fd, const void *key, void *next) {
    auto &entries = contents(fd);
    auto found = key ? entries.find(std::string(static_cast<const char *>(key), width(fd))) : entries.end();
    auto item = found == entries.end() ? entries.begin() : std::next(found);
    if (item == entries.end()) { errno = ENOENT; return -1; }
    std::memcpy(next, item->first.data(), width(fd)); return 0;
}
extern "C" int __wrap_bpf_object__find_map_fd_by_name(const bpf_object *, const char *name) {
    return __wrap_bpf_obj_get(name);
}
extern "C" int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value) {
    auto &entries = contents(fd);
    auto found = entries.find(std::string(static_cast<const char *>(key), width(fd)));
    if (found == entries.end()) { errno = ENOENT; return -1; }
    *static_cast<uint32_t *>(value) = found->second; return 0;
}
extern "C" int __wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags) {
    auto &entries = contents(fd);
    std::string bytes(static_cast<const char *>(key), width(fd));
    if (entries.count(bytes) && flags == BPF_NOEXIST) { errno = EEXIST; return -1; }
    if (!entries.count(bytes) && entries.size() == 1024) { errno = E2BIG; return -1; }
    entries[bytes] = *static_cast<const uint32_t *>(value); return 0;
}
extern "C" int __wrap_bpf_map_delete_elem(int fd, const void *key) {
    if (contents(fd).erase(std::string(static_cast<const char *>(key), width(fd)))) return 0;
    errno = ENOENT; return -1;
}
int main(int argc, char **) {
    try {
        auto keys = read_policy_stdin(std::cin);
        if (argc > 1) {
            initialize_paths(nullptr, keys);
            auto expect_failure = [](auto operation) {
                try { operation(); } catch (const std::exception &) { return; }
                fail("capacity or missing-key operation was accepted");
            };
            if (keys.size() != 1024) fail("capacity fixture needs 1024 mixed entries");
            change_path("/test-pins", keys.front(), true, "duplicate");
            change_path("/test-pins", keys[1], true, "duplicate");
            auto short_key = path_key("/new-short", false);
            auto long_key = path_key("/new-long/" + std::string(255, 'z'), false);
            for (const auto &key : {short_key, long_key})
                expect_failure([&] { change_path("/test-pins", key, true, "overflow"); });
            for (const auto &key : {keys.front(), keys[1]}) {
                change_path("/test-pins", key, false, "delete exact key");
                expect_failure([&] { change_path("/test-pins", key, false, "missing key"); });
            }
            change_path("/test-pins", short_key, true, "refill short");
            change_path("/test-pins", long_key, true, "refill long");
        } else for (const auto &key : keys) {
            size_t length = std::strlen(key.pathname);
            size_t bytes = length < 256 ? 256 : 4096;
            contents(length < 256 ? 100001 : 100000).emplace(std::string(key.pathname, bytes), 1);
        }
        policy_json("/test-pins"); return 0;
    } catch (const std::exception &error) { std::cerr << error.what(); return 1; }
}
'''


def native_map_tests(temporary, flags, values):
    source = temporary / 'map-test.cpp'; source.write_text(MAP_HARNESS)
    executable = temporary / 'map-test'
    result = invoke(['c++', '-O2', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                     f'-DLOADER_SOURCE="{REPO / "src/linux/native/bpf-loader.cpp"}"',
                     source, '-o', executable, *flags,
                     '-Wl,--wrap=bpf_obj_get,--wrap=bpf_obj_get_info_by_fd,--wrap=bpf_map_get_next_key',
                     '-Wl,--wrap=bpf_map_lookup_elem,--wrap=bpf_map_update_elem,--wrap=bpf_map_delete_elem',
                     '-Wl,--wrap=bpf_object__find_map_fd_by_name'])
    assert result.returncode == 0, result.stderr.decode()
    for good in (boundary_keys(), values, []):
        result = invoke([executable], input=packed(good))
        assert result.returncode == 0, result.stderr.decode()
        assert sorted(json.loads(result.stdout)) == sorted(good), 'policy enumeration lost a path tier'
    result = invoke([executable, 'mutate'], input=packed(values))
    assert result.returncode == 0, result.stderr.decode()
    assert sorted(json.loads(result.stdout)) == sorted(values[2:] + ['/new-short', '/new-long/' + 'z' * 255])


def local_tests():
    values = keys(); payload = packed(values)
    assert len(payload) > 2 * 1024 * 1024
    # Establish the actual OS boundary, independently of any wrapper mock.
    try:
        result = invoke(['/bin/true', *values])
    except OSError as error:
        assert error.errno == errno.E2BIG
    else:
        assert result.returncode == 0  # Some hosts admit a larger ARG_MAX.
    native = NativeGuard('/usr/lib/wg-program-split', '/sys/fs/bpf/wgps-bulk-test')
    with patch('wg_program_split.preflight.verify_artifact'), \
            patch('wg_program_split.preflight.subprocess.run', return_value=SimpleNamespace(
                  returncode=0, stdout=b'loaded\n')) as execute:
        native.load(values, SimpleNamespace(mask=0xffff0000, mark=0x10000))
        argv = execute.call_args.args[0]
        assert argv[1] == 'load-policy-stdin' and len(argv) == 7
        assert execute.call_args.kwargs['input'] == payload
        assert execute.call_args.kwargs.get('text') is not True
        assert execute.call_args.kwargs['timeout'] == 30
        assert execute.call_args.kwargs['env'] == {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
    for bad in (['/x'] * 1025, ['/' + 'x' * 4095], ['/x\0/y']):
        with patch('wg_program_split.preflight.verify_artifact'), \
                patch('wg_program_split.preflight.subprocess.run') as execute:
            try:
                native.load(bad, SimpleNamespace(mask=0xffff0000, mark=0x10000))
            except ControllerError:
                pass
            else:
                raise AssertionError('wrapper accepted transport overflow or embedded NUL')
            execute.assert_not_called()
    build = REPO / 'build/linux'; build.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='policy-parser-', dir=build) as temporary:
        temporary = Path(temporary)
        source = temporary / 'parser.cpp'
        source.write_text('#define main hidden_loader_main\n#include "' +
                          str(REPO / 'src/linux/native/bpf-loader.cpp') +
                          '"\n#undef main\nint main() { try { auto keys=read_policy_stdin(std::cin);'
                          'std::cout<<"["; bool first=true; for(const auto &key:keys) {'
                          'if(!first) std::cout<<","; first=false; std::cout<<json_string(key.pathname);}'
                          'std::cout<<"]\\n"; return 0;} catch(const std::exception&) {return 1;} }\n')
        executable = temporary / 'parser'
        flags = invoke(['pkg-config', '--cflags', '--libs', 'libbpf']); assert flags.returncode == 0
        result = invoke(['c++', '-O2', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                         source, '-o', executable, *flags.stdout.decode().split()])
        assert result.returncode == 0, result.stderr.decode()
        for good in ([], values, ['/' + '/'.join(['a' * 255] * 15) + '/' + 'b' * 254]):
            result = invoke([executable], input=packed(good))
            assert result.returncode == 0 and json.loads(result.stdout) == good
        for name, data in malformed().items():
            assert invoke([executable], input=data).returncode != 0, name
        native_map_tests(temporary, flags.stdout.decode().split(), values)
    print('PASS native policy: mixed byte tiers, bulk initialization, readback, combined capacity, duplicate adds, exact deletes and malformed input')


def require_vm():
    if (os.geteuid() != 0 or os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') != '1' or
            socket.gethostname() == 'TV' or 'microsoft' in os.uname().release.lower() or
            not Path('/var/lib/wgps-vm-provisioned').is_file()):
        raise SystemExit('requires root in the explicit marked disposable native VM')


def vm_tests():
    require_vm()
    baseline = json.loads(invoke(['bpftool', '-j', 'link', 'show']).stdout)
    token = 'wgps-policy-' + uuid.uuid4().hex[:10]
    work, pins = Path('/run') / token, Path('/sys/fs/bpf') / token
    assert not os.path.lexists(work) and not os.path.lexists(pins)
    work.mkdir(mode=0o700)
    evidence = REPO / 'local/validation' / token; evidence.mkdir(parents=True, mode=0o700)
    values = keys(); payload = packed(values); active = False; files = {}
    try:
        for name in ('bpf-loader', 'classifier.bpf.o'):
            destination = work / name
            shutil.copyfile(REPO / 'build/linux' / name, destination)
            destination.chmod(0o755 if name == 'bpf-loader' else 0o644)
            info = destination.stat(); files[destination] = (info.st_dev, info.st_ino)
        loader = work / 'bpf-loader'
        argv = [loader, 'load-policy-stdin', work / 'classifier.bpf.o', pins,
                '/sys/fs/cgroup', '0xffff0000', '0x10000']
        for name, data in malformed().items():
            result = invoke(argv, input=data)
            assert result.returncode != 0 and not os.path.lexists(pins), name
            assert json.loads(invoke(['bpftool', '-j', 'link', 'show']).stdout) == baseline
        native = NativeGuard(work, pins)
        native.load(values, SimpleNamespace(mask=0xffff0000, mark=0x10000)); active = True
        observed = native.snapshot()
        assert sorted(observed['paths']) == sorted(values)
        assert observed['state'] == 'blocked' and len(observed['pins']['links']) == 12
        snapshot = json.loads(invoke([loader, 'snapshot', pins]).stdout)
        assert snapshot['abi'] == 4 and len(snapshot['maps']) == 14
        for name, width in (('paths_short', 256), ('paths', 4096)):
            info = json.loads(invoke(['bpftool', '-j', 'map', 'show', 'pinned', pins / name]).stdout)
            assert info['bytes_key'] == width and info['max_entries'] == 1024
            entries = json.loads(invoke(['bpftool', '-j', 'map', 'dump', 'pinned', pins / name]).stdout)
            expected = sum((len(os.fsencode(value)) < 256) == (width == 256) for value in values)
            assert len(entries) == expected
        extra = ['/new-short', '/new-long/' + 'z' * 255]
        for value in values[:2]:
            assert invoke([loader, 'path-add-policy', pins, value]).returncode == 0
        for value in extra:
            result = invoke([loader, 'path-add-policy', pins, value])
            assert result.returncode != 0 and b'combined path capacity' in result.stderr
        assert sorted(native.snapshot()['paths']) == sorted(values)
        for value in values[:2]:
            assert invoke([loader, 'path-del', pins, value]).returncode == 0
            assert invoke([loader, 'path-del', pins, value]).returncode != 0
        for value in extra:
            assert invoke([loader, 'path-add-policy', pins, value]).returncode == 0
        assert sorted(native.snapshot()['paths']) == sorted(values[2:] + extra)
        native.unload(); active = False
        # Empty stream and argv API remain supported.
        for command, data in (('load-policy-stdin', b''), ('load-policy', None)):
            result = invoke([loader, command, *argv[2:]], input=data)
            assert result.returncode == 0, result.stderr.decode()
            active = True
            assert native.snapshot()['paths'] == []
            native.unload(); active = False
        (evidence / 'results.json').write_text(json.dumps({'entries': len(values), 'stdin_bytes': len(payload),
            'malformed_rejections': list(malformed()), 'readback_exact': True, 'empty_and_argv': True,
            'abi': 4, 'path_key_widths': [256, 4096], 'combined_capacity': 1024,
            'duplicate_add_at_capacity': True, 'exact_delete_and_refill': True}, indent=2))
        print(f'PASS real native stdin load/readback: {len(values)} entries, {len(payload)} bytes; malformed inputs attach nothing')
    finally:
        if active:
            NativeGuard(work, pins).unload()
        assert not os.path.lexists(pins)
        assert json.loads(invoke(['bpftool', '-j', 'link', 'show']).stdout) == baseline
        assert set(work.iterdir()) == set(files), 'unexpected test artifact retained'
        for path, expected in files.items():
            info = path.lstat(); assert (info.st_dev, info.st_ino) == expected
            path.unlink()
        work.rmdir()
        print('Evidence:', evidence)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--native', action='store_true')
    modes.add_argument('--vm', action='store_true')
    args = parser.parse_args()
    local_tests() if args.native else vm_tests()
