#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Staged disposable-VM reboot proof. Never invokes reboot itself.

Host captures each JSON manifest_sha256 and passes it to the next stage:
  --vm init
  --vm prepare FIXTURE HASH
  [host requests reboot, waits for SSH and a new boot ID]
  --vm positive FIXTURE HASH
  --vm arm-negative FIXTURE HASH
  [host requests second reboot and waits for SSH]
  --vm negative FIXTURE HASH
  --vm cleanup FIXTURE HASH
A failed stage retains evidence; it never adopts unrecorded files for cleanup.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

from test_acceptance import (ARTIFACTS, CLI, CONFIG, ENV, PAYLOADS, PINS, STATE, UNITS,
                             directory_identity, execute, identity, pristine, require_vm,
                             snapshot, unit_state, wait_for)

REPO = Path(__file__).resolve().parents[2]


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def file_id(path):
    return list(identity(path))


def link_id(path):
    info = path.lstat()
    assert path.is_symlink() and info.st_uid == 0
    return [info.st_dev, info.st_ino, info.st_ctime_ns, os.readlink(path)]


def semantic_snapshot():
    value = snapshot()
    # IDs and PIDs are boot-local. Compare socket endpoints/process names and
    # attachment kinds against their newly observed cgroup path/program tag.
    for family in ('routes4', 'routes6'):
        for route in value[family]: route.pop('nhid', None)
    value['listeners'] = sorted(re.sub(r'pid=\d+', 'pid=*', row) for row in value['listeners'])
    programs = json.loads(execute('bpftool', '-j', 'prog', 'show').stdout)
    by_id = {entry['id']: entry for entry in programs}
    groups = {}
    for directory, _, _ in os.walk('/sys/fs/cgroup'):
        groups[Path(directory).stat().st_ino] = directory
    observed = []
    for entry in value['bpf']:
        program = by_id[entry['prog_id']]
        clean = {k: v for k, v in entry.items() if k not in ('id', 'prog_id', 'cgroup_id')}
        clean.update(program_type=program['type'], program_name=program.get('name'), program_tag=program['tag'])
        if 'cgroup_id' in entry: clean['cgroup_path'] = groups.get(entry['cgroup_id'], 'unresolved')
        assert clean.get('cgroup_path') != 'unresolved', 'cannot compare foreign attachment across boots'
        observed.append(clean)
    value['bpf'] = sorted(observed, key=lambda x: json.dumps(x, sort_keys=True))
    return value


class Stage:
    def __init__(self, root, expected=None):
        self.root, self.manifest = Path(root), Path(root) / 'manifest.json'
        assert re.fullmatch(r'/var/lib/wgps-boot-[0-9a-f]{12}', str(self.root))
        self.before = None
        self.archived = False
        if expected is not None and not self.root.exists():
            self.root = REPO / 'local/validation' / self.root.name
            self.manifest = self.root / 'manifest.json'
            self.archived = True
        if expected is not None:
            assert re.fullmatch('[0-9a-f]{64}', expected)
            self.before = file_id(self.manifest)
            assert self.before[3:5] == [0, 0o600]
            self.data = json.loads(self.manifest.read_text())
            cursor, digest = self.data, self.before[-1]
            for _ in range(64):
                if digest == expected: break
                digest = cursor.get('previous_sha256')
                assert digest and re.fullmatch('[0-9a-f]{64}', digest), 'host checkpoint is not an ancestor'
                checkpoint = self.root / ('.checkpoint-' + digest + '.json')
                assert file_id(checkpoint)[3:] == [0, 0o600, digest]
                cursor = json.loads(checkpoint.read_text())
            else: raise AssertionError('checkpoint chain exceeds bound')
            assert list(directory_identity(self.root)) == self.data['directory']
            assert self.data['root'] == str(root) and self.data['schema'] == 1
            assert not self.archived or self.data['phase'] == 'complete'
        else:
            self.root.mkdir(mode=0o700)
            self.data = {'schema': 1, 'root': str(self.root), 'nonce': self.root.name[-12:],
                         'directory': list(directory_identity(self.root)), 'phase': 'initialized',
                         'origin_boot': boot_id(), 'files': {}, 'links': {}, 'directories': {}, 'checks': [], 'checkpoints': []}

    def capture(self, path):
        self.data['files'][str(path)] = file_id(path)

    def verify(self):
        assert file_id(self.manifest) == self.before
        for name, expected in self.data['files'].items():
            if not os.path.lexists(name) and name in self.data.get('retiring_files', []): continue
            if not os.path.lexists(name) and name == self.data.get('dropin_source') and self.data['phase'] == 'negative-arming':
                renamed = file_id(Path(self.data['dropin']))
                assert renamed[:2] + renamed[3:] == expected[:2] + expected[3:]
                continue
            assert file_id(Path(name)) == expected, 'owned persistent file changed: ' + name
        for name, expected in self.data['links'].items():
            if not os.path.lexists(name) and self.data['phase'] in ('cleaning', 'complete'): continue
            assert link_id(Path(name)) == expected, 'owned enable link changed: ' + name
        for name, expected in self.data['directories'].items():
            if not os.path.lexists(name) and self.data['phase'] in ('cleaning', 'complete'): continue
            assert list(directory_identity(Path(name))) == expected, 'owned directory changed: ' + name
        assert list(directory_identity(self.root)) == self.data['directory']

    def publish(self):
        if self.before is not None:
            assert file_id(self.manifest) == self.before
            digest = self.before[-1]
            checkpoint = self.root / ('.checkpoint-' + digest + '.json')
            if not checkpoint.exists(): create(checkpoint, self.manifest.read_bytes())
            assert file_id(checkpoint)[3:] == [0, 0o600, digest]
            self.data['previous_sha256'] = digest
            self.data['checkpoints'] = list(dict.fromkeys([*self.data['checkpoints'], digest]))
            assert len(self.data['checkpoints']) < 64
        path = self.root / ('.manifest-' + uuid.uuid4().hex)
        create(path, json.dumps(self.data, sort_keys=True).encode())
        if self.before is None:
            os.link(path, self.manifest); path.unlink()
        else:
            assert file_id(self.manifest) == self.before
            os.replace(path, self.manifest)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        self.before = file_id(self.manifest)
        try:
            print(json.dumps({'fixture': self.data['root'], 'manifest_sha256': self.before[-1],
                              'phase': self.data['phase'], 'boot_id': boot_id(), 'checks': self.data['checks']}), flush=True)
        except BrokenPipeError:
            pass  # The next invocation verifies the durable previous-hash chain.

    def unit(self):
        return self.root.name + '.service'

    def control(self, *args):
        return execute('systemctl', *args, env=ENV, timeout=100)

    def native(self, command):
        return json.loads(execute(ARTIFACTS / 'bpf-loader', command, PINS, env=ENV).stdout)

    def require_phase(self, phase, *, reboot=False):
        self.verify()
        assert self.data['phase'] == phase
        prior = self.data.get('positive_boot', self.data['origin_boot'])
        assert (boot_id() != prior) if reboot else (boot_id() == prior)

    def verify_unit(self, unit, dropin=''):
        value = unit_state(unit)
        expected = '/etc/systemd/system/' + unit if unit == self.unit() else '/usr/lib/systemd/system/' + unit
        assert value['FragmentPath'] == expected and value['DropInPaths'] == dropin
        return value

    def verify_links(self):
        found = set()
        for root in ('/etc/systemd/system', '/run/systemd/system'):
            for unit in (*UNITS, self.unit()):
                for path in Path(root).rglob(unit):
                    if path.is_symlink(): found.add(str(path))
        expected = set(self.data['links'])
        assert found <= expected if self.data['phase'] in ('cleaning', 'complete') else found == expected, 'unrecorded service enable link'


def create(path, content, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(content); stream.flush(); os.fsync(fd)
    finally: os.close(fd)


def initialize():
    pristine()
    assert not list(Path('/var/lib').glob('wgps-boot-*')), 'previous staged boot fixture exists'
    baseline = semantic_snapshot()
    stage = Stage('/var/lib/wgps-boot-' + uuid.uuid4().hex[:12])
    stage.data['baseline'] = baseline
    stage.publish()


def prepare(stage):
    stage.require_phase('initialized'); pristine()
    baseline = stage.data['baseline']
    try:
        probe = stage.root / 'probe'
        execute('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', REPO / 'tests/linux/probe_boot.c', '-o', probe)
        stage.capture(probe)
        private = execute('wg', 'genkey').stdout.strip()
        peer_private = execute('wg', 'genkey').stdout
        public = execute('wg', 'pubkey', input=peer_private).stdout.strip()
        profile = ('[Interface]\nPrivateKey=' + private + '\nAddress=10.200.0.1/32\nDNS=10.200.0.2\n'
                   '[Peer]\nPublicKey=' + public + '\nAllowedIPs=0.0.0.0/0\nEndpoint=192.0.2.2:51822\n')
        create(stage.root / 'profile.conf', profile.encode()); stage.capture(stage.root / 'profile.conf')
        create(stage.root / 'settings.json', json.dumps({'schema_version': 1, 'included_executables': [str(probe)]}).encode())
        stage.capture(stage.root / 'settings.json')
        result = execute('/usr/bin/python3', '-I', REPO / 'build/linux/wg-program-split.pyz', 'install',
                         '--profile', stage.root / 'profile.conf', '--settings', stage.root / 'settings.json',
                         '--artifacts', REPO / 'build/linux', env=ENV, timeout=60)
        assert json.loads(result.stdout)['activated'] is False
        for path in (*PAYLOADS, CONFIG / 'installation.json', CONFIG / 'profile.conf', CONFIG / 'settings.json'):
            stage.capture(path)
        for path in (CONFIG, ARTIFACTS): stage.data['directories'][str(path)] = list(directory_identity(path))
        assert not PINS.exists() and not STATE.exists()
        path = Path('/etc/systemd/system') / stage.unit()
        text = ('[Unit]\nDescription=Disposable boot dependency proof\nRequires=' + UNITS[0] + '\nAfter=' + UNITS[0] +
                '\n[Service]\nType=oneshot\nExecStart=' + str(probe) + ' ' + str(stage.root / 'positive.json') +
                ' ' + stage.data['nonce'] + '\nRemainAfterExit=yes\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n')
        create(path, text.encode(), 0o644); stage.capture(path)
        directory = Path('/etc/systemd/system') / (UNITS[0] + '.d')
        directory.mkdir(mode=0o755)
        stage.data['directories'][str(directory)] = list(directory_identity(directory))
        staged = directory / (stage.root.name + '.conf.disabled')
        create(staged, b'[Service]\nExecStartPre=/usr/bin/false\n', 0o644); stage.capture(staged)
        stage.data.update(dropin_source=str(staged), dropin=str(staged.with_suffix('')), dropin_identity=file_id(staged))
        stage.control('daemon-reload')
        execute('systemd-analyze', 'verify', path, *[Path('/usr/lib/systemd/system') / unit for unit in UNITS])
        stage.control('enable', UNITS[0], stage.unit())
        for parent, unit in (('sysinit.target.wants', UNITS[0]), ('multi-user.target.wants', stage.unit())):
            path = Path('/etc/systemd/system') / parent / unit
            stage.data['links'][str(path)] = link_id(path)
        stage.verify_links()
        assert all(unit_state(unit)['ActiveState'] == 'inactive' for unit in (*UNITS, stage.unit()))
        assert semantic_snapshot() == baseline
        stage.data['phase'] = 'prepared'; stage.data['checks'].append('inactive install and guarded probe enabled for reboot')
    except Exception:
        stage.data['phase'] = 'prepare-failed'; stage.publish()
        raise
    stage.publish()


def positive(stage):
    stage.require_phase('prepared', reboot=True); stage.verify_links()
    wait_for(lambda: unit_state(stage.unit())['ActiveState'] in ('active', 'failed'), 'boot probe completion', timeout=100)
    assert stage.verify_unit(UNITS[0])['ActiveState'] == 'active'
    assert stage.verify_unit(UNITS[1])['ActiveState'] == 'inactive'
    assert stage.verify_unit(stage.unit())['ActiveState'] == 'active'
    path = stage.root / 'positive.json'
    result = json.loads(path.read_text())
    assert result == {'boot_id': boot_id(), 'nonce': stage.data['nonce'], 'socket_errno': errno.EPERM, 'mark': None}
    stage.capture(path)
    pins = stage.native('snapshot'); policy = stage.native('policy')
    assert pins['ready'] is False and len(pins['links']) == 12 and policy == [str(stage.root / 'probe')]
    journal = json.loads((STATE / 'controller.json').read_text())
    assert journal['boot_id'] == boot_id() and journal['state'] == 'blocked'
    assert journal['pins'] == {'maps': pins['maps'], 'links': pins['links']}
    assert not (STATE / 'receipt.json').exists()
    stage.data.update(phase='positive', positive_boot=boot_id(), positive_pins=pins)
    stage.data['checks'].append('fresh boot guard blocked first native socket before dependent service ran')
    stage.publish()


def arm_negative(stage):
    assert stage.data['phase'] in ('positive', 'negative-arming')
    stage.require_phase(stage.data['phase']); stage.verify_links()
    if stage.data['phase'] == 'positive':
        stage.data['phase'] = 'negative-arming'; stage.publish()
    source, path = Path(stage.data['dropin_source']), Path(stage.data['dropin'])
    if source.exists():
        assert not os.path.lexists(path)
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.renameat2(-100, os.fsencode(source), -100, os.fsencode(path), 1) == 0, ctypes.get_errno()
    expected, actual = stage.data['dropin_identity'], file_id(path)
    assert actual[:2] + actual[3:] == expected[:2] + expected[3:]
    stage.data['files'].pop(str(source), None); stage.capture(path); stage.publish()
    stage.control('daemon-reload')
    stage.verify_unit(UNITS[0], str(path))
    stage.data['phase'] = 'negative-armed'; stage.publish()


def negative(stage):
    stage.require_phase('negative-armed', reboot=True); stage.verify_links()
    wait_for(lambda: unit_state(UNITS[0])['ActiveState'] == 'failed', 'injected guard startup failure', timeout=100)
    wait_for(lambda: unit_state('multi-user.target')['ActiveState'] == 'active', 'boot target completion', timeout=100)
    stage.verify_unit(UNITS[0], stage.data['dropin'])
    probe = stage.verify_unit(stage.unit())
    assert probe['ActiveState'] == 'inactive' and probe['MainPID'] == '0'
    observed = execute('systemctl', 'show', stage.unit(), '-p', 'ExecMainStartTimestampMonotonic', '-p', 'ExecMainPID').stdout
    fields = dict(line.split('=', 1) for line in observed.splitlines())
    assert fields['ExecMainStartTimestampMonotonic'] == '0' and fields['ExecMainPID'] == '0'
    assert stage.verify_unit(UNITS[1])['ActiveState'] == 'inactive'
    assert not os.path.lexists(PINS)
    wait_for(lambda: semantic_snapshot() == stage.data['baseline'], 'boot host baseline convergence', timeout=60)
    assert STATE.exists() and not list(STATE.iterdir()), 'unexpected current-boot runtime state'
    stage.data['negative_runtime'] = list(directory_identity(STATE))
    stage.data.update(phase='negative', negative_boot=boot_id())
    stage.data['checks'].append('failed guard prevents dependent probe startup; no project pins or network changes')
    stage.publish()


def cleanup(stage):
    stage.verify(); stage.verify_links()
    if stage.archived:
        assert not Path(stage.data['root']).exists()
        pristine()
        print(json.dumps({'phase': 'complete', 'evidence': str(stage.root), 'checks': stage.data['checks']})); return
    assert stage.data['phase'] in ('negative', 'cleaning', 'complete') and stage.data['negative_boot'] == boot_id()
    assert not os.path.lexists(PINS)
    retained = {str(CONFIG / name) for name in ('profile.conf', 'settings.json')}
    if stage.data['phase'] == 'negative':
        assert not list(STATE.iterdir()) and list(directory_identity(STATE)) == stage.data['negative_runtime']
        stage.data.update(phase='cleaning', retiring_files=sorted(set(stage.data['files']) - retained))
        stage.publish()  # Only these exact recorded files may now disappear.
    def remove(path):
        if os.path.lexists(path):
            assert file_id(path) == stage.data['files'][str(path)]
            path.unlink()
    dropin = Path(stage.data['dropin']); remove(dropin)
    if dropin.parent.exists(): dropin.parent.rmdir()
    stage.control('daemon-reload')
    fixture_unit = Path('/etc/systemd/system') / stage.unit()
    if fixture_unit.exists():
        stage.verify_unit(stage.unit())
        stage.control('disable', '--now', stage.unit()); remove(fixture_unit)
    assert unit_state(stage.unit()).get('MainPID', '0') == '0'
    # A retry may follow a completed/partially published uninstall. No network
    # cleanup is inferred: this negative boot never loaded a guard or network.
    if all(path.exists() for path in (*PAYLOADS, CONFIG / 'installation.json')):
        for unit in UNITS: stage.verify_unit(unit)
        result = execute(CLI, 'disable', env=ENV, timeout=100)
        assert json.loads(result.stdout)['state'] == 'disabled' and not os.path.lexists(PINS)
        result = json.loads(execute(CLI, 'uninstall', env=ENV, timeout=100).stdout)
        assert not result['retained'] and not result.get('removal_deferred')
    assert all(unit_state(unit).get('MainPID', '0') == '0' for unit in UNITS)
    assert not os.path.lexists(PINS) and not (STATE / 'receipt.json').exists()
    for path in (*PAYLOADS, CONFIG / 'installation.json'): remove(path)
    for name, expected in stage.data['links'].items():
        path = Path(name)
        if os.path.lexists(path):
            assert link_id(path) == expected; path.unlink()
    if not stage.data.get('configuration_retention_verified'):
        for name in retained: assert file_id(Path(name)) == stage.data['files'][name]
        stage.data['configuration_retention_verified'] = True
        stage.data['retiring_files'] = sorted(stage.data['files'])
        stage.data['checks'].append('uninstall retained unchanged private profile/settings')
        stage.publish()  # Retained configuration retirement is now authorized.
    if STATE.exists():
        assert list(directory_identity(STATE)) == stage.data['negative_runtime']
        assert {path.name for path in STATE.iterdir()} <= {'.lock'}
        lock = STATE / '.lock'
        if lock.exists():
            held = file_id(lock)
            assert held[3:5] == [0, 0o600] and lock.read_bytes() == b''
            assert file_id(lock) == held; lock.unlink()
        STATE.rmdir()
    for directory in (CONFIG, ARTIFACTS):
        if directory.exists():
            assert list(directory_identity(directory)) == stage.data['directories'][str(directory)]
            for path in directory.iterdir(): remove(path)
            directory.rmdir()
    stage.control('daemon-reload')
    for unit in (*UNITS, stage.unit()): execute('systemctl', 'reset-failed', unit, okay=False)
    assert semantic_snapshot() == stage.data['baseline']
    pristine()
    if stage.data['phase'] != 'complete':
        stage.data['phase'] = 'complete'
        stage.data['checks'].append('owned installation and fixture retired; semantic host baseline restored')
        stage.publish()
    for name in stage.data['files']:
        path = Path(name)
        if path.parent == stage.root: remove(path)
    checkpoints = {stage.root / ('.checkpoint-' + digest + '.json') for digest in stage.data['checkpoints']}
    assert set(stage.root.iterdir()) == checkpoints | {stage.manifest}
    for path in checkpoints:
        assert file_id(path)[3:] == [0, 0o600, path.name[len('.checkpoint-'):-5]]
    evidence = REPO / 'local/validation' / stage.root.name
    evidence.parent.mkdir(parents=True, exist_ok=True)
    assert not os.path.lexists(evidence)
    # Keep only public checkpoint evidence. Directory rename preserves the exact
    # journal identity and permits retry if the final stdout response is lost.
    assert ctypes.CDLL(None, use_errno=True).renameat2(-100, os.fsencode(stage.root), -100, os.fsencode(evidence), 1) == 0
    print(json.dumps({'phase': 'complete', 'evidence': str(evidence), 'checks': stage.data['checks']}))


def local_test():
    with tempfile.TemporaryDirectory(prefix='wgps-boot-probe-', dir=Path.home()) as temporary:
        path = Path(temporary); executable = path / 'probe'
        execute('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', REPO / 'tests/linux/probe_boot.c', '-o', executable)
        output = path / 'result.json'
        result = execute(executable, output, '0123456789ab', okay=False)
        assert result.returncode == 1
        assert json.loads(output.read_text()) == {'boot_id': boot_id(), 'nonce': '0123456789ab', 'socket_errno': 0, 'mark': 0}
        before = file_id(output)
        assert execute(executable, output, '0123456789ab', okay=False).returncode == 2
        assert file_id(output) == before
    print('PASS native boot probe observes unmarked baseline and refuses replacing prior evidence')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--native', action='store_true'); mode.add_argument('--vm', action='store_true')
    parser.add_argument('stage', nargs='?', choices=('init', 'prepare', 'positive', 'arm-negative', 'negative', 'cleanup'))
    parser.add_argument('fixture', nargs='?'); parser.add_argument('manifest_sha256', nargs='?')
    args = parser.parse_args()
    if args.native:
        assert args.stage is None; local_test()
    else:
        require_vm()
        if args.stage == 'init':
            assert args.fixture is None and args.manifest_sha256 is None; initialize()
        else:
            assert args.stage and args.fixture and args.manifest_sha256
            stage = Stage(args.fixture, args.manifest_sha256)
            {'prepare': prepare, 'positive': positive, 'arm-negative': arm_negative, 'negative': negative, 'cleanup': cleanup}[args.stage](stage)
