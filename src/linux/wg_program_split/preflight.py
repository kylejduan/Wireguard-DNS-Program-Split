# SPDX-License-Identifier: GPL-3.0-or-later
"""Native-host checks, private input reads, and observed readiness probes."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from . import ownership as own


class ControllerError(RuntimeError):
    """Lifecycle failure with no private input or subprocess output in diagnostics."""


def command(*argv, input=None):
    try:
        result = subprocess.run(argv, input=input, text=input is None, capture_output=True, timeout=30,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        raise ControllerError('native operation could not complete') from None
    if result.returncode:
        raise ControllerError('native operation failed')
    try:
        return result.stdout if input is None else result.stdout.decode('utf-8')
    except UnicodeError:
        raise ControllerError('native operation returned invalid output') from None


def read_private(directory, name, maximum):
    before = own.file_identity(directory, name)
    if before.size > maximum:
        raise ControllerError('private input exceeds its size limit')
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=directory)
    try:
        chunks, total = [], 0
        while chunk := os.read(fd, min(65536, maximum + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ControllerError('private input exceeds its size limit')
        held = os.fstat(fd)
        if (held.st_dev, held.st_ino) != (before.device, before.inode):
            raise ControllerError('private input changed while opening')
    finally:
        os.close(fd)
    own.verify_file(directory, name, before)
    try:
        return b''.join(chunks).decode('utf-8'), before
    except UnicodeError:
        raise ControllerError('private input is not valid UTF-8') from None


def validate_nss(text):
    rows = [line.split('#', 1)[0].strip() for line in text.splitlines()]
    hosts = [line.split(':', 1)[1].strip() for line in rows if re.match(r'^hosts\s*:', line)]
    supported = ('files dns', 'files mdns4_minimal [NOTFOUND=return] dns')
    if len(hosts) != 1 or ' '.join(hosts[0].split()) not in supported:
        raise ControllerError('unsupported hosts NSS configuration')


def check_host():
    """Only the proved native Ubuntu/kernel envelope; loading proves exact hooks."""
    try:
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                       if '=' in line)
        if (os.geteuid() != 0 or release.get('ID', '').strip('"') != 'ubuntu' or
                release.get('VERSION_ID', '').strip('"') != '26.04' or
                not re.match(r'^7\.0(?:\.|-)', os.uname().release) or
                'microsoft' in os.uname().release.lower()):
            raise ControllerError('requires root on supported native Ubuntu 26.04/kernel 7.0')
        for option in ('--container', '--chroot'):
            result = subprocess.run(['/usr/bin/systemd-detect-virt', option], capture_output=True, timeout=5)
            if result.returncode != 1:
                raise ControllerError('container or changed-root enrollment is unsupported')
        for item in ('root', 'ns/net', 'ns/user', 'ns/pid'):
            current, init = os.stat('/proc/self/' + item), os.stat('/proc/1/' + item)
            if (current.st_dev, current.st_ino) != (init.st_dev, init.st_ino):
                raise ControllerError('requires the initial host root and namespaces')
        if 'bpf' not in Path('/sys/kernel/security/lsm').read_text().strip().split(','):
            raise ControllerError('BPF LSM is not active')
        if not Path('/sys/kernel/btf/vmlinux').is_file():
            raise ControllerError('kernel BTF is unavailable')
        if command('/usr/bin/stat', '-f', '-c', '%T', '/sys/fs/cgroup').strip() != 'cgroup2fs':
            raise ControllerError('unified cgroup v2 is required')
        nss = Path('/etc/nsswitch.conf').read_text()
        validate_nss(nss)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise ControllerError('host capability preflight failed') from None


def verify_artifact(path):
    path = Path(path)
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ControllerError('installed artifact has unsafe ancestry')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise ControllerError('installed artifact is not a trusted root-owned file')


class NativeGuard:
    def __init__(self, artifacts, pins):
        self.loader, self.object = Path(artifacts) / 'bpf-loader', Path(artifacts) / 'classifier.bpf.o'
        self.pins = Path(pins)

    def _run(self, *args, input=None):
        verify_artifact(self.loader)
        return command(str(self.loader), *map(str, args), input=input)

    def exists(self):
        return os.path.lexists(self.pins)

    def load(self, paths, allocation):
        verify_artifact(self.object)
        records = []
        for path in paths:
            try:
                value = os.fsencode(path)
            except (TypeError, UnicodeError):
                raise ControllerError('invalid policy filesystem encoding') from None
            if len(records) >= 1024 or not value or len(value) >= 4096 or b'\0' in value:
                raise ControllerError('policy exceeds native stdin capacity or contains NUL')
            records.append(value + b'\0')
        self._run('load-policy-stdin', self.object, self.pins, '/sys/fs/cgroup',
                  hex(allocation.mask), hex(allocation.mark), input=b''.join(records))

    def snapshot(self):
        try:
            data = json.loads(self._run('snapshot', self.pins))
            return {'abi': data['abi'], 'state': 'ready' if data['ready'] else 'blocked',
                    'mask': data['mask'], 'mark': data['mark'], 'paths': data['paths'],
                    'pins': {'maps': data['maps'], 'links': data['links']}}
        except (ValueError, KeyError, TypeError):
            raise ControllerError('native guard returned an invalid observation') from None

    def set_state(self, state):
        self._run('state', self.pins, state)

    def add(self, path):
        self._run('path-add-policy', self.pins, path)

    def remove(self, path):
        self._run('path-del', self.pins, path)

    def unload(self):
        self._run('remove', self.pins)

    def probe_dns(self, *, attempts=3):
        """One lost datagram is not an ownership failure; retry within the check."""
        for attempt in range(attempts):
            try:
                result = json.loads(self._run('probe-dns', self.pins))
                if not isinstance(result, dict) or set(result) != {'dns'} or result['dns'] is not True:
                    raise ValueError()
                return
            except (ValueError, TypeError, ControllerError):
                if attempt == attempts - 1:
                    raise ControllerError('native DNS readiness probe failed') from None


def process_snapshot():
    """Read PID/start-time identities, never inspect socket inventories or kill."""
    result = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            fields = (directory / 'stat').read_text().rsplit(') ', 1)[1].split()
            executable = os.readlink(directory / 'exe')
            again = (directory / 'stat').read_text().rsplit(') ', 1)[1].split()
            if fields[19] == again[19]:
                result.append({'pid': int(directory.name), 'ppid': int(fields[1]),
                               'starttime': int(fields[19]), 'exe': executable})
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise ControllerError('process restart audit is incomplete') from None
        except (OSError, ValueError, IndexError):
            continue  # Kernel tasks and exiting tasks need no userspace restart.
    return result


def restart_audit(paths, current, previous):
    live = {(p['pid'], p['starttime']): p for p in current}
    affected = {(p['pid'], p['starttime']) for p in previous} & live.keys()
    affected.update(key for key, p in live.items()
                    if p['exe'] in paths or p['exe'].removesuffix(' (deleted)') in paths)
    while True:
        parents = {pid for pid, _ in affected}
        updated = affected | {key for key, p in live.items() if p['ppid'] in parents}
        if updated == affected:
            return [live[key] for key in sorted(affected)]
        affected = updated


def readiness_probe(profile, allocation, guard):
    """Probe the marked loopback DNS path and an independently observed handshake."""
    # The management ELF supplies the socket: enrolling this Python interpreter
    # must not prevent the blocked controller from probing the real marked path.
    guard.probe_dns()
    handshakes = command('/usr/bin/wg', 'show', allocation.interface, 'latest-handshakes').splitlines()
    entries = [row.split() for row in handshakes]
    if len(entries) != 1 or len(entries[0]) != 2 or entries[0][0] != profile.public_key:
        raise ControllerError('WireGuard peer readiness observation failed')
    age = time.time() - int(entries[0][1])
    if not 0 <= age <= 180:
        raise ControllerError('WireGuard handshake is not recent')
    return {'dns': True, 'handshake_recent': True, 'handshake_age_seconds': int(age)}
