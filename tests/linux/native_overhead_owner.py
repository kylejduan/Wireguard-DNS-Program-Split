# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit native admission and identity-bound, persistent fixture ownership."""
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import time
import uuid

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
UNITS = ('wg-program-split-guard.service', 'wg-program-split.service')
SINGLETONS = ('/usr/bin/wg-program-split', '/usr/lib/wg-program-split', '/etc/wg-program-split',
              '/run/wg-program-split', '/sys/fs/bpf/wg_program_split', '/usr/local/bin/wg-program-split',
              '/usr/local/lib/wg-program-split')


def run(*args, okay=True, timeout=40, **kwargs):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True,
                            timeout=timeout, env=ENV, **kwargs)
    if okay and result.returncode:
        # Private keys may be on stdin. Neither inputs nor outputs enter errors.
        raise RuntimeError(f'{args[0]} {args[1] if len(args) > 1 else ""} failed: exit {result.returncode}')
    return result


def data(*args): return json.loads(run(*args).stdout)


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _hashed(path, keep):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('not a singly linked regular file')
        h, chunks = hashlib.sha256(), []
        while chunk := os.read(fd, 65536):
            h.update(chunk)
            if keep: chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_ino, before.st_ctime_ns, before.st_size) != (after.st_ino, after.st_ctime_ns, after.st_size):
            raise ValueError('file changed during read')
        return {'device': after.st_dev, 'inode': after.st_ino, 'ctime_ns': after.st_ctime_ns,
                'uid': after.st_uid, 'mode': stat.S_IMODE(after.st_mode), 'sha256': h.hexdigest()}, b''.join(chunks)
    finally: os.close(fd)


def file_identity(path): return _hashed(path, False)[0]


STAGING_HINT = ('copy the accepted bytes as root into a root-owned directory with no group/other write '
                '(for example install -d -m 0700 and install -m 0644/0755), point the manifest at the copy '
                'and keep the manifest sha256 values; the runner never edits or re-owns the source')


def _staged(path, expected, keep, owner_uid):
    """Root-controlled input: only root can replace or edit the file or any ancestor."""
    path = Path(path)
    if not path.is_absolute() or path != path.resolve():
        raise ValueError(f'{path}: staged input must be a resolved absolute path; {STAGING_HINT}')
    for parent in path.parents:
        value = parent.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, owner_uid) or value.st_mode & 0o022:
            raise ValueError(f'{parent}: staging directory is not root-controlled; {STAGING_HINT}')
    identity, content = _hashed(path, keep)
    if identity['uid'] not in (0, owner_uid) or identity['mode'] & 0o022:
        raise ValueError(f'{path}: staged file is not root-owned without group/other write; {STAGING_HINT}')
    if identity['sha256'] != expected: raise ValueError(f'{path}: sha256 differs from the manifest; retained')
    return identity, content


def staged_file(path, expected, *, owner_uid=0): return _staged(path, expected, False, owner_uid)[0]


def staged_bytes(path, expected, *, owner_uid=0):
    """Bytes read once through the same descriptor that proved the manifest hash."""
    return _staged(path, expected, True, owner_uid)[1]


def directory_identity(path):
    value = Path(path).lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
        raise ValueError('unsafe directory')
    return {'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid, 'mode': stat.S_IMODE(value.st_mode)}


def same_identity(expected, actual):
    if expected != actual: raise ValueError('ownership identity changed; retained')


@contextlib.contextmanager
def lock_manifest(path, *, owner_uid=0):
    path = Path(path)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner_uid or
            stat.S_IMODE(parent.st_mode) != 0o700 or path.parent != path.parent.resolve()):
        raise ValueError('manifest directory must be resolved, private and root owned')
    expected = file_identity(path)
    if expected['uid'] != owner_uid or expected['mode'] != 0o600:
        raise ValueError('manifest must be root-owned mode 0600')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        same_identity(expected, file_identity(path))
        if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (expected['device'], expected['inode']):
            raise ValueError('manifest replaced while locking')
        with os.fdopen(os.dup(fd)) as stream: document = json.load(stream)
        yield document, expected
        same_identity(expected, file_identity(path))
    finally: os.close(fd)


def host_identity():
    virtual = run('systemd-detect-virt', okay=False)
    return {'uid': os.geteuid(), 'hostname': socket.gethostname(), 'release': os.uname().release,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'machine_id': Path('/etc/machine-id').read_text().strip(),
            'virtualization': virtual.stdout.strip(), 'vm_marker': Path('/var/lib/wgps-vm-provisioned').is_file()}


def admit(manifest, host, requested_mode):
    if requested_mode != manifest['mode'] or host['uid'] != 0 or 'microsoft' in host['release'].lower():
        raise ValueError('mode, root or native-kernel admission failed')
    if any(manifest[k] != host[k] for k in ('boot_id', 'machine_id')):
        raise ValueError('boot or machine identity changed')
    if requested_mode == 'native-tv':
        if host['hostname'] != 'TV' or host['virtualization'] != 'none':
            raise ValueError('native evidence requires physical TV')
    elif requested_mode == 'vm-rehearsal':
        if host['hostname'] == 'TV' or host['virtualization'] in ('', 'none') or not host['vm_marker']:
            raise ValueError('rehearsal requires a marked non-TV virtual machine')
    else: raise ValueError('unknown evidence mode')


def names(run_id):
    token = uuid.UUID(run_id).hex[:10]
    return {'underlay': 'nu' + token, 'remote': 'nr' + token, 'namespace': 'nn' + token}


def validate_manifest(manifest):
    if manifest['schema'] != 1 or manifest['names'] != names(manifest['run_id']):
        raise ValueError('manifest schema or UUID-derived names invalid')
    root = Path(manifest['evidence'])
    if not root.is_absolute() or root != root.resolve() or root == Path('/tmp') or Path('/tmp') in root.parents:
        raise ValueError('evidence must be a resolved persistent absolute path')
    if root.exists(): raise ValueError('new run evidence directory already exists; use --recover')
    for parent in root.parents: directory_identity(parent)
    if not manifest.get('root_preflight_complete') or not manifest.get('protected_services_reviewed'):
        raise ValueError('root host/protection review attestation required')
    if str(root).startswith('/home/tv/') and manifest.get('native_account_verified') != 'tv@TV':
        raise ValueError('root must verify native tv@TV before writes below /home/tv')
    if manifest['builds']['baseline']['revision'] != 'b843960':
        raise ValueError('baseline must be the validated b843960 build')
    for arm in ('baseline', 'candidate'):
        build = manifest['builds'][arm]
        directory = Path(build['directory'])
        if directory != directory.resolve(): raise ValueError('build directory must be resolved')
        required = {'wg-program-split.pyz', 'bpf-loader', 'classifier.bpf.o', *UNITS}
        if set(build['sha256']) != required: raise ValueError('exact build artifact set required')
        for name, expected in build['sha256'].items(): staged_file(directory / name, expected)
    staged_file(manifest['probe'], manifest['probe_sha256'])
    if not manifest['management_ips']: raise ValueError('management/LAN/Tailscale route probes required')
    for address in manifest['management_ips']: ipaddress.ip_address(address)
    for key in ('host_port', 'peer_port', 'payload_port'):
        if type(manifest[key]) is not int or not 1024 <= manifest[key] <= 65535: raise ValueError('invalid owned port')
    subnet = ipaddress.IPv4Network(manifest['underlay'])
    if subnet.prefixlen != 30: raise ValueError('owned underlay must be /30')
    networks = [subnet, *(ipaddress.IPv4Network(manifest[k] + '/32') for k in ('host_tunnel', 'peer_tunnel'))]
    if any(a.overlaps(b) for i, a in enumerate(networks) for b in networks[i + 1:]):
        raise ValueError('fixture address spaces overlap')


def inventory():
    links = data('ip', '-j', '-d', 'link', 'show')
    addresses = data('ip', '-j', 'address', 'show')
    routes = [*data('ip', '-j', '-4', 'route', 'show', 'table', 'all'),
              *data('ip', '-j', '-6', 'route', 'show', 'table', 'all')]
    units = []
    for base in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
        units.extend(str(p) for p in Path(base).glob('**/*wg-program-split*'))
    for unit in UNITS:
        value = run('systemctl', 'show', unit, '-p', 'LoadState', '-p', 'FragmentPath', '-p', 'DropInPaths', '-p', 'MainPID', okay=False).stdout
        parsed = dict(row.split('=', 1) for row in value.splitlines() if '=' in row)
        if (parsed.get('LoadState') != 'not-found' or parsed.get('FragmentPath') or
                parsed.get('DropInPaths') or int(parsed.get('MainPID', '0'))): units.append(unit)
    ports = []
    for row in run('ss', '-H', '-lnu').stdout.splitlines():
        local = row.split()[3]
        if local.rsplit(':', 1)[-1].isdigit(): ports.append(int(local.rsplit(':', 1)[-1]))
    return {'paths': [p for p in SINGLETONS if os.path.lexists(p)], 'units': units,
            'namespaces': [p.name for p in Path('/run/netns').iterdir()] if Path('/run/netns').exists() else [],
            'links': [row['ifname'] for row in links], 'routes': routes,
            'addresses': [str(a['local']) + '/' + str(a['prefixlen']) for row in addresses for a in row['addr_info']],
            'udp_ports': ports, 'tables': [row['table']['name'] for row in data('nft', '-j', 'list', 'ruleset')['nftables'] if 'table' in row]}


def preflight(manifest, observed):
    if observed['paths'] or observed['units'] or 'wgps0' in observed['links'] or 'wg_program_split' in observed['tables']:
        raise ValueError('pre-existing singleton product ownership')
    if set(manifest['names'].values()) & set(observed['links'] + observed['namespaces']):
        raise ValueError('fixture name collision')
    if manifest['host_port'] in observed['udp_ports']: raise ValueError('WireGuard host port already occupied')
    requested = [ipaddress.ip_network(manifest['underlay']),
                 *(ipaddress.ip_network(manifest[k] + '/32') for k in ('host_tunnel', 'peer_tunnel'))]
    existing = [*observed['addresses'], *manifest['reserved_networks']]
    existing += [row['dst'] for row in observed['routes'] if row.get('dst') not in (None, 'default', '0.0.0.0/0', '::/0')]
    for address in existing:
        network = ipaddress.ip_network(address, strict=False)
        if any(network.version == test.version and network.overlaps(test) for test in requested):
            raise ValueError('fixture address overlaps host/provider inventory: ' + str(network))


def link_identity(name, namespace=None):
    prefix = ('ip', '-n', namespace) if namespace else ('ip',)
    rows = data(*prefix, '-j', '-d', 'link', 'show', 'dev', name)
    if len(rows) != 1: raise ValueError('ambiguous link identity')
    row = rows[0]
    return {key: row.get(key) for key in ('ifindex', 'ifname', 'ifalias', 'link_netnsid')}


def pid_identity(pid):
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    return {'pid': pid, 'starttime': int(fields[19])}


def namespace_identity(path):
    value = Path(path).stat()
    return {'device': value.st_dev, 'inode': value.st_ino}


class Journal:
    def __init__(self, path, run_id, *, resume=False):
        self.path, self.run_id, self.records, self.pending = Path(path), run_id, [], []
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        if resume:
            previous = file_identity(self.path)
            if previous['uid'] != os.geteuid() or previous['mode'] != 0o600: raise ValueError('unsafe journal ownership')
            for line in self.path.read_text().splitlines():
                event = json.loads(line)
                if event['run_id'] != run_id: raise ValueError('journal belongs to another run')
                if event['event'] == 'intent': self.pending.append(event)
                elif event['event'] == 'intent-resolved': self.pending = [r for r in self.pending if r['id'] != event['id']]
                elif event['event'] == 'acquire': self.records.append(event)
                elif event['event'] == 'checkpoint':
                    next(r for r in self.records if r['id'] == event['id']).update(event['fields'])
                elif event['event'] == 'release': self.records = [r for r in self.records if r['id'] != event['id']]
        else: flags |= os.O_CREAT | os.O_EXCL
        self.fd = os.open(self.path, flags, 0o600)
        self.identity = (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino)
        if resume and self.identity != (previous['device'], previous['inode']):
            os.close(self.fd); raise ValueError('journal replaced while opening')

    def write(self, event):
        value = self.path.lstat()
        if (value.st_dev, value.st_ino) != self.identity: raise ValueError('journal replaced')
        content = (json.dumps({'run_id': self.run_id, **event}, sort_keys=True) + '\n').encode()
        view = memoryview(content)
        while view:
            size = os.write(self.fd, view)
            if size <= 0: raise OSError('journal write failed')
            view = view[size:]
        os.fsync(self.fd)

    def begin(self, kind, name):
        event = {'event': 'intent', 'id': uuid.uuid4().hex, 'kind': kind, 'name': name}
        self.write(event); self.pending.append(event)
        return event

    def resolve_intent(self, event):
        self.write({'event': 'intent-resolved', 'id': event['id']})
        self.pending.remove(event)

    def acquire(self, kind, name, identity, **extra):
        event = {'event': 'acquire', 'id': uuid.uuid4().hex, 'kind': kind, 'name': name, 'identity': identity, **extra}
        self.write(event); self.records.append(event)
        for intent in list(self.pending):
            if (intent['kind'], intent['name']) == (kind, name): self.resolve_intent(intent)
        return event

    def checkpoint(self, record, **fields):
        self.write({'event': 'checkpoint', 'id': record['id'], 'fields': fields})
        record.update(fields)

    def release(self, record):
        self.write({'event': 'release', 'id': record['id']})
        self.records.remove(record)

    def create_file(self, path, content, mode=0o600):
        self.begin('file', str(path))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(os.dup(fd), 'wb') as stream: stream.write(content); stream.flush(); os.fsync(stream.fileno())
        finally: os.close(fd)
        self.acquire('file', str(path), file_identity(path))

    def cleanup(self):
        errors = ['unresolved acquisition intent: ' + r['kind'] + ' ' + r['name'] for r in self.pending]
        if self.pending: return errors  # Unknown births can depend on captured objects; retain the whole fixture.
        for record in list(reversed(self.records)):
            kind, name, expected = record['kind'], record['name'], record['identity']
            try:
                if kind == 'file':
                    same_identity(expected, file_identity(name)); Path(name).unlink()
                elif kind == 'directory':
                    same_identity(expected, directory_identity(name)); Path(name).rmdir()
                elif kind == 'route':
                    same_identity(expected, data('ip', '-j', '-4', 'route', 'show', name))
                    run('ip', 'route', 'delete', name, 'dev', record['dev'], 'metric', str(record['metric']))
                elif kind == 'link':
                    same_identity(expected, link_identity(name)); run('ip', 'link', 'delete', 'dev', name)
                elif kind == 'namespace':
                    same_identity(expected, namespace_identity('/run/netns/' + name))
                    if run('ip', 'netns', 'pids', name).stdout.strip(): raise ValueError('namespace still has processes')
                    run('ip', 'netns', 'delete', name)
                elif kind == 'pid':
                    try: same_identity(expected, pid_identity(int(name)))
                    except FileNotFoundError: self.release(record); continue
                    fd = os.pidfd_open(int(name))
                    try:
                        same_identity(expected, pid_identity(int(name)))
                        signal.pidfd_send_signal(fd, signal.SIGTERM)
                        import select
                        if not select.select([fd], [], [], 4)[0]:
                            signal.pidfd_send_signal(fd, signal.SIGKILL)
                            if not select.select([fd], [], [], 4)[0]: raise ValueError('owned process did not retire')
                    finally: os.close(fd)
                else: raise ValueError('requires product/runtime recovery: ' + kind)
                self.release(record)
            except Exception as error: errors.append(f'{kind} {name}: {type(error).__name__}: {error}')
        return errors

    def close(self): os.close(self.fd)
