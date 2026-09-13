#!/usr/bin/env python3
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
    values[-1] = '/wgps-raw-' + os.fsdecode(b'\xff') + '/image'
    return values


def packed(values):
    return b''.join(os.fsencode(value) + b'\0' for value in values)


def malformed():
    return {'empty-record': b'\0', 'unterminated': b'/one', 'relative': b'one\0',
            'duplicate': b'/one\0/one\0', 'dot': b'/one/./two\0',
            'parent': b'/one/../two\0', 'double-slash': b'//one\0',
            'root': b'/\0', 'trailing-slash': b'/one/\0',
            'long-key': b'/' + b'x' * 4095 + b'\0',
            'too-many': packed(f'/entry-{i}' for i in range(1025)),
            'oversized': b'x' * (1024 * 4096 + 1)}


def invoke(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), capture_output=True, timeout=30, **kwargs)


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
    print('PASS binary wrapper and native parser: large/raw-byte/maximum/empty policy; malformed input rejected')


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
        native.unload(); active = False
        # Empty stream and argv API remain supported.
        for command, data in (('load-policy-stdin', b''), ('load-policy', None)):
            result = invoke([loader, command, *argv[2:]], input=data)
            assert result.returncode == 0, result.stderr.decode()
            active = True
            assert native.snapshot()['paths'] == []
            native.unload(); active = False
        (evidence / 'results.json').write_text(json.dumps({'entries': len(values), 'stdin_bytes': len(payload),
            'malformed_rejections': list(malformed()), 'readback_exact': True, 'empty_and_argv': True}, indent=2))
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
