#!/usr/bin/env python3
"""Same-CPU scratch regression; no VM, attachment or scheduler changes on import.

--native checks the ordinary unmarked client. --vm uses a FIFO periodic client
and a continuously runnable normal client, then reverses their selection roles.
The old shared-scratch implementation should fail; do not call its failures a
benchmark outlier. Evidence is retained even when the regression fails.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[2]


def command(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True,
                          timeout=45, **kwargs)


def build():
    output = REPO / 'build/linux/probe_preemption'
    output.parent.mkdir(parents=True, exist_ok=True)
    result = command(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                      REPO / 'tests/linux/probe_preemption.c', '-o', output])
    assert result.returncode == 0, result.stderr
    return output


def native():
    binary = build()
    with tempfile.TemporaryDirectory(prefix='wgps-preempt-', dir=Path.home()) as directory:
        cache = Path(directory) / 'cache'; cache.write_bytes(b'x')
        result = command([binary, min(os.sched_getaffinity(0)), 0, 0,
                          time.monotonic_ns() + 100_000_000, 1, cache, 0])
        assert result.returncode == 0, (result.stdout, result.stderr)
        value = json.loads(result.stdout)
        assert value['sockets'] > 100
        print('PASS native preemption probe: unmarked sockets and ordinary file/Unix IPC')


def vm(obj, seconds):
    assert os.geteuid() == 0 and os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert Path('/var/lib/wgps-vm-provisioned').is_file()
    assert socket.gethostname() != 'TV' and 'microsoft' not in os.uname().release.lower()
    binary = build()
    work = REPO / 'local/validation' / ('wgps-preempt-' + uuid.uuid4().hex[:10])
    work.mkdir(parents=True, mode=0o700)
    pins = Path('/sys/fs/bpf') / work.name
    assert not pins.exists()
    loader = REPO / 'build/linux/bpf-loader'
    clients = [work / 'selected', work / 'unlisted']
    for client in clients: shutil.copy2(binary, client)
    cache = work / 'cache'; cache.write_bytes(b'x')
    cpu = min(os.sched_getaffinity(0))
    before = command(['bpftool', '-j', 'link', 'show'])
    assert before.returncode == 0, before.stderr
    (work / 'links-before.json').write_text(before.stdout)
    config = Path('/boot') / ('config-' + os.uname().release)
    if config.exists():
        (work / 'preempt-config.txt').write_text('\n'.join(
            line for line in config.read_text().splitlines() if 'PREEMPT' in line))
    dynamic = Path('/sys/kernel/debug/sched/preempt')
    if dynamic.exists(): (work / 'preempt-mode.txt').write_text(dynamic.read_text())
    children, observations = [], []
    loaded = False
    try:
        result = command([loader, 'load', obj, pins, '/sys/fs/cgroup',
                          '0x00ff0000', '0x00010000', clients[0]])
        (work / 'verifier.log').write_text(result.stderr)
        assert result.returncode == 0, f'load failed; see {work}/verifier.log'
        loaded = True
        for args in [('guard-slot', pins, 'cache', cache), ('state', pins, 'ready')]:
            result = command([loader, *args]); assert result.returncode == 0, result.stderr
        for paced_selected in (True, False):
            start = time.monotonic_ns() + 300_000_000
            for index, client in enumerate(clients):
                args = [str(client), str(cpu), str(int((index == 0) == paced_selected)),
                        str(0x10000 if index == 0 else 0), str(start), str(seconds), str(cache), '1']
                children.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            for index, child in enumerate(children):
                stdout, stderr = child.communicate(timeout=seconds + 10)
                (work / f'round-{int(paced_selected)}-{index}.json').write_text(stdout)
                (work / f'round-{int(paced_selected)}-{index}.stderr').write_text(stderr)
                value = json.loads(stdout) if stdout else {'fixture_error': stderr}
                observations.append({'selected': index == 0, 'returncode': child.returncode, **value})
            children.clear()
        result = command([loader, 'status', pins])
        (work / 'status.json').write_text(result.stdout)
        assert result.returncode == 0, result.stderr
    finally:
        for child in children:
            if child.poll() is None: child.kill()
            child.communicate(timeout=5)
        if loaded:
            result = command([loader, 'remove', pins])
            assert result.returncode == 0, f'owned pins retained: {pins}; {result.stderr}'
        after = command(['bpftool', '-j', 'link', 'show'])
        (work / 'links-after.json').write_text(after.stdout)
        assert after.returncode == 0 and json.loads(after.stdout) == json.loads(before.stdout)
    (work / 'results.json').write_text(json.dumps(observations, indent=2))
    print(json.dumps({'evidence': str(work), 'results': observations}))
    for value in observations:
        assert value['returncode'] == 0, value
        assert value['sockets'] > 100 and value['cpu'] == cpu, value
        assert value['voluntary' if value['paced'] else 'involuntary'] > 10, value
    print('PASS same-CPU forced-preemption marks, denial boundaries and file/Unix IPC')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--native', action='store_true')
    modes.add_argument('--vm', action='store_true')
    parser.add_argument('--object', type=Path, default=REPO / 'build/linux/classifier.bpf.o')
    parser.add_argument('--seconds', type=int, choices=range(1, 61), default=10)
    args = parser.parse_args()
    native() if args.native else vm(args.object.resolve(), args.seconds)
