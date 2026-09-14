"""Owned local topology and installed singleton lifecycle; no VM orchestration."""
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import subprocess
import time

import native_overhead_owner as own
import overhead_stats as stats

CLI = Path('/usr/bin/wg-program-split')
ARTIFACTS = Path('/usr/lib/wg-program-split')
CONFIG = Path('/etc/wg-program-split')
STATE = Path('/run/wg-program-split')
PINS = Path('/sys/fs/bpf/wg_program_split')
UNIT_DIR = Path('/usr/lib/systemd/system')
SHIM = b'#!/bin/sh\nexec /usr/bin/python3 -I /usr/lib/wg-program-split/wg-program-split.pyz "$@"\n'


def report(path, value): path.write_text(json.dumps(value, indent=2) + '\n')


def line(child, timeout=10):
    end, value = time.monotonic() + timeout, bytearray()
    while len(value) < 8192:
        if not select.select([child.stdout], [], [], max(0, end - time.monotonic()))[0]:
            raise TimeoutError('native peer/client readiness timed out')
        part = os.read(child.stdout.fileno(), 1)
        if not part: raise RuntimeError('native peer/client exited before readiness')
        if part == b'\n': return json.loads(value)
        value += part
    raise ValueError('oversized native readiness report')


def _children():
    """PIDs whose parent is this thread, or None when the kernel cannot list them."""
    try: return set(Path('/proc/thread-self/children').read_text().split())
    except OSError: return None


def child(journal, argv, errors):
    with errors.open('xb') as stream:
        intent = journal.begin('spawn', str(argv[0]))
        before = _children()
        try:
            process = subprocess.Popen(list(map(str, argv)), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=stream, env=own.ENV)
        except OSError:
            # Popen reaps a child whose exec failed before raising. Resolve only this
            # intent, and only when this thread provably gained no child (zombies included).
            after = _children()
            if before is not None and after is not None and after <= before: journal.resolve_intent(intent)
            raise
    receipt = journal.acquire('pid', str(process.pid), own.pid_identity(process.pid))
    process.ownership_receipt = receipt
    journal.resolve_intent(intent)
    return process


def retire(journal, process):
    receipt = process.ownership_receipt
    if process.poll() is None:
        own.same_identity(receipt['identity'], own.pid_identity(process.pid))
        process.terminate()
    try: process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        own.same_identity(receipt['identity'], own.pid_identity(process.pid))
        process.kill(); process.wait(timeout=4)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream and not stream.closed: stream.close()
    if receipt in journal.records: journal.release(receipt)


def resolver_identity():
    result = {}
    for name in ('/etc/resolv.conf', '/etc/nsswitch.conf'):
        path = Path(name); info = path.lstat(); target = path.stat()
        result[name] = {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
                        'link': os.readlink(path) if path.is_symlink() else None,
                        'target_device': target.st_dev, 'target_inode': target.st_ino, 'sha256': own.digest(path)}
    return result


def stable(value):
    if isinstance(value, list): return [stable(row) for row in value]
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in ('expires', 'packets', 'bytes', 'used', 'age')}
    return value


def resolver_links():
    """Per-link resolved routing configuration; an absent resolver is recorded, not fatal."""
    result = {}
    for command in ('dns', 'domain', 'default-route'):
        try:
            value = own.run('resolvectl', command, okay=False)
            result[command] = {'exit': value.returncode, 'stdout': value.stdout}
        except FileNotFoundError: result[command] = {'exit': None, 'stdout': 'resolvectl unavailable'}
    return result


def links():
    return [{'ifindex': row.get('ifindex'), 'ifname': row.get('ifname'), 'ifalias': row.get('ifalias'),
             'kind': row.get('linkinfo', {}).get('info_kind'), 'link_type': row.get('link_type'),
             'address': row.get('address'), 'mtu': row.get('mtu'), 'master': row.get('master')}
            for row in own.data('ip', '-j', '-d', 'link', 'show')]


def addresses():
    # Privacy addresses rotate by design; lifetimes are counters. Everything else is compared.
    return [{'ifname': row.get('ifname'), **{k: a.get(k) for k in ('family', 'local', 'prefixlen', 'scope')}}
            for row in own.data('ip', '-j', 'address', 'show') for a in row.get('addr_info', []) if not a.get('temporary')]


def snapshot(manifest):
    routes = {address: stable(own.data('ip', '-j', 'route', 'get', address)) for address in manifest['management_ips']}
    # All observations are public kernel metadata; no WireGuard key dump.
    # Keys are only ever added, so earlier raw snapshots keep their meaning.
    return {'resolver': resolver_identity(), 'management_routes': routes,
            'links': links(), 'addresses': addresses(), 'resolver_links': resolver_links(),
            'routes4': stable(own.data('ip', '-j', '-4', 'route', 'show', 'table', 'all')),
            'routes6': stable(own.data('ip', '-j', '-6', 'route', 'show', 'table', 'all')),
            'rules4': own.data('ip', '-j', '-4', 'rule', 'show'), 'rules6': own.data('ip', '-j', '-6', 'rule', 'show'),
            'bpf_links': own.data('bpftool', '-j', 'link', 'show'),
            'bpf_programs': own.data('bpftool', '-j', 'prog', 'show'),
            'nft': stable(own.data('nft', '-j', 'list', 'ruleset')),
            'listeners': own.run('ss', '-H', '-lntup').stdout,
            'active_services': own.run('systemctl', 'list-units', '--state=active', '--type=service', '--no-legend', '--plain').stdout,
            'protected_services': {unit: own.run('systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID', '-p', 'NRestarts', '-p', 'FragmentPath').stdout
                                   for unit in manifest['protected_services_reviewed']},
            'sysctls': {name: own.run('sysctl', '-n', name).stdout.strip() for name in
                        ('net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding', 'net.ipv4.conf.all.rp_filter',
                         'net.ipv4.conf.all.src_valid_mark', 'kernel.bpf_stats_enabled')}}


def _management_meaning(snapshot):
    """Ignore only an optional local-table label backed by this snapshot's FIB.

    Raw snapshots stay intact. A cached local IPv4 lookup through lo must have
    an exact host-scope local /32 in table local; all forwarding fields remain.
    """
    result = {}
    for address, rows in snapshot['management_routes'].items():
        try: host = str(ipaddress.IPv4Address(address))
        except ipaddress.AddressValueError: host = None
        proved = host is not None and any(
            route.get('type') == 'local' and route.get('table') in ('local', 255) and
            route.get('scope') == 'host' and route.get('dst') in (host, host + '/32') and route.get('dev')
            for route in snapshot['routes4'])
        result[address] = []
        for row in rows:
            value = dict(row)
            if (proved and row.get('type') == 'local' and row.get('dev') == 'lo' and
                    row.get('dst') == host and 'local' in row.get('cache', []) and
                    row.get('table', 'local') in ('local', 255)):
                value.pop('table', None)
            result[address].append(value)
    return result


def _brief(row): return json.dumps(row, sort_keys=True, separators=(',', ':'))[:200]


def verify_snapshot(first, last):
    """Both directions: originals must survive and nothing may be left behind.

    Keys absent from a legacy original snapshot are not compared.
    """
    errors = []
    for name in ('resolver', 'rules4', 'rules6', 'protected_services', 'sysctls'):
        if first[name] != last[name]: errors.append(name + ' changed')
    if _management_meaning(first) != _management_meaning(last): errors.append('management_routes changed')
    tables = {name: (first[name], last[name]) for name in ('routes4', 'routes6', 'bpf_links')}
    # Ignore dynamic counters and metainfo; foreign nft objects must survive unchanged.
    tables['nft'] = tuple([row for row in value['nftables'] if 'metainfo' not in row] for value in (first['nft'], last['nft']))
    for name in ('links', 'addresses'):
        if name in first: tables[name] = (first[name], last.get(name, []))
    for name, (before, after) in tables.items():
        errors += ['original ' + name + ' entry missing or changed: ' + _brief(row) for row in before if row not in after]
        errors += [name + ' entry added: ' + _brief(row) for row in after if row not in before]
    if 'resolver_links' in first and first['resolver_links'] != last.get('resolver_links'):
        errors.append('resolver per-link configuration changed')
    return errors


def route_proof(topology, mark=0):
    """Kernel route decisions for every fixture destination, before any client sends.

    Direct and WireGuard-endpoint traffic must use the owned veth; tunnel traffic,
    marked on product arms, must use wgps0; the namespace can only answer locally.
    """
    m, underlay = topology.m, topology.m['names']['underlay']
    outer = own.run('wg', 'show', 'wgps0', 'fwmark').stdout.strip()
    outer = 0 if outer in ('', 'off') else int(outer, 0)
    checks = [('direct', (), topology.peer, 0, underlay), ('endpoint', (), topology.peer, outer, underlay),
              ('tunnel', (), m['peer_tunnel'], mark, 'wgps0'),
              ('peer-direct', ('-n', topology.ns), topology.host, 0, m['names']['remote']),
              ('peer-tunnel', ('-n', topology.ns), m['host_tunnel'], 0, 'peerwg')]
    proof = []
    for label, prefix, address, value, expected in checks:
        rows = own.data('ip', *prefix, '-j', 'route', 'get', address, *(('mark', str(value)) if value else ()))
        proof.append({'check': label, 'address': address, 'mark': value, 'expected_dev': expected, 'route': rows})
        if len(rows) != 1 or rows[0].get('dev') != expected or rows[0].get('type', 'unicast') != 'unicast':
            raise ValueError(f'fixture {label} route to {address} leaves the owned link {expected}: {_brief(rows)}')
    topology.j.write({'event': 'route-proof', 'checks': proof})
    return proof


class Topology:
    def __init__(self, manifest, journal):
        self.m, self.j = manifest, journal
        self.evidence = Path(manifest['evidence'])
        self.private = Path('/etc/wireguard') / ('native-' + manifest['run_id'])
        self.ns = manifest['names']['namespace']
        self.host, self.peer = map(str, ipaddress.ip_network(manifest['underlay']).hosts())
        self.servers = []
        self.peer_ready = []  # Parsed ready lines in server order, including effective payload_rcvbuf.

    def create(self):
        m, j = self.m, self.j
        if os.path.lexists(self.private): raise ValueError('private fixture path occupied')
        own.directory_identity(self.private.parent)  # Fail before any intent if /etc/wireguard is absent or unsafe.
        j.begin('directory', str(self.private))
        self.private.mkdir(mode=0o700)
        j.acquire('directory', str(self.private), own.directory_identity(self.private))
        for side in ('host', 'peer'):
            key = own.run('wg', 'genkey').stdout
            j.create_file(self.private / (side + '.key'), key.encode())
            public = own.run('wg', 'pubkey', input=key).stdout.strip()
            j.create_file(self.private / (side + '.pub'), public.encode())
        j.begin('namespace', self.ns)
        own.run('ip', 'netns', 'add', self.ns)
        j.acquire('namespace', self.ns, own.namespace_identity('/run/netns/' + self.ns))
        marker = 'wgps-native:' + m['run_id']
        j.begin('link', m['names']['underlay'])
        own.run('ip', 'link', 'add', 'name', m['names']['underlay'], 'alias', marker, 'type', 'veth',
                'peer', 'name', m['names']['remote'])
        j.acquire('link', m['names']['underlay'], own.link_identity(m['names']['underlay']))
        own.run('ip', 'link', 'set', m['names']['remote'], 'netns', self.ns)
        # Moving the peer can add link_netnsid; update only after verifying birth.
        receipt = j.records[-1]
        observed = own.link_identity(m['names']['underlay'])
        if any(observed[k] != receipt['identity'][k] for k in ('ifindex', 'ifname', 'ifalias')):
            raise ValueError('veth birth changed while moving peer')
        j.begin('link', m['names']['underlay'])
        j.release(receipt); j.acquire('link', m['names']['underlay'], observed)
        own.run('ip', 'addr', 'add', self.host + '/30', 'dev', m['names']['underlay'])
        own.run('ip', 'link', 'set', m['names']['underlay'], 'mtu', '1500', 'up')
        own.run('ip', '-n', self.ns, 'addr', 'add', self.peer + '/30', 'dev', m['names']['remote'])
        own.run('ip', '-n', self.ns, 'link', 'set', m['names']['remote'], 'mtu', '1500', 'up')
        own.run('ip', '-n', self.ns, 'link', 'set', 'lo', 'up')
        own.run('ip', '-n', self.ns, 'link', 'add', 'peerwg', 'type', 'wireguard')
        own.run('ip', 'netns', 'exec', self.ns, 'wg', 'set', 'peerwg',
                'private-key', self.private / 'peer.key', 'listen-port', m['peer_port'],
                'peer', (self.private / 'host.pub').read_text(), 'allowed-ips', m['host_tunnel'] + '/32')
        own.run('ip', '-n', self.ns, 'addr', 'add', m['peer_tunnel'] + '/32', 'dev', 'peerwg')
        own.run('ip', '-n', self.ns, 'link', 'set', 'peerwg', 'mtu', '1420', 'up')
        own.run('ip', '-n', self.ns, 'route', 'add', m['host_tunnel'] + '/32', 'dev', 'peerwg')
        for label, address, source in (('vpn', m['peer_tunnel'], m['host_tunnel']), ('direct', self.peer, self.host)):
            process = child(j, ['ip', 'netns', 'exec', self.ns, self.evidence / 'bin/probe', 'peer',
                               address, 53, m['payload_port'], source], self.evidence / (label + '-peer.stderr'))
            self.servers.append(process)
            self.peer_ready.append(line(process))
            if not self.peer_ready[-1].get('ready'): raise ValueError('native peer not ready')
        j.write({'event': 'topology', 'namespace_links': own.data('ip', '-n', self.ns, '-j', '-d', 'link', 'show'),
                 'namespace_routes': own.data('ip', '-n', self.ns, '-j', 'route', 'show', 'table', 'all'),
                 'host_link_addresses': own.data('ip', '-j', 'addr', 'show', 'dev', m['names']['underlay'])})
        # Allow owned IPv6 DAD without changing any host IPv6 sysctl.
        time.sleep(2)
        for prefix, dev in ((('ip',), m['names']['underlay']), (('ip', '-n', self.ns), m['names']['remote'])):
            for row in own.data(*prefix, '-j', '-6', 'addr', 'show', 'dev', dev):
                if any(a.get('tentative') or a.get('dadfailed') for a in row['addr_info']):
                    raise ValueError('owned IPv6 address did not become ready')

    def profile(self):
        return ('[Interface]\nPrivateKey = ' + (self.private / 'host.key').read_text().strip() +
                '\nAddress = ' + self.m['host_tunnel'] + '/32\nDNS = ' + self.m['peer_tunnel'] +
                '\nMTU = 1420\n[Peer]\nPublicKey = ' + (self.private / 'peer.pub').read_text().strip() +
                '\nAllowedIPs = 0.0.0.0/0\nEndpoint = ' + self.peer + ':' + str(self.m['peer_port']) + '\n')

    def retire(self):
        errors = []
        for process in self.servers:
            try: retire(self.j, process)
            except Exception as error: errors.append(str(error))
        return errors


@contextlib.contextmanager
def plain(topology):
    m, j = topology.m, topology.j
    if 'wgps0' in [row['ifname'] for row in own.data('ip', '-j', 'link', 'show')]: raise ValueError('wgps0 occupied')
    marker = 'wgps-native:' + m['run_id']
    j.begin('link', 'wgps0')
    own.run('ip', 'link', 'add', 'name', 'wgps0', 'alias', marker, 'type', 'wireguard')
    receipt = j.acquire('link', 'wgps0', own.link_identity('wgps0'))
    route = None
    route_receipt = None
    try:
        own.run('wg', 'set', 'wgps0', 'private-key', topology.private / 'host.key', 'listen-port', m['host_port'],
                'peer', (topology.private / 'peer.pub').read_text(), 'allowed-ips', m['peer_tunnel'] + '/32',
                'endpoint', topology.peer + ':' + str(m['peer_port']))
        own.run('ip', 'addr', 'add', m['host_tunnel'] + '/32', 'dev', 'wgps0', 'noprefixroute')
        own.run('ip', 'link', 'set', 'wgps0', 'mtu', '1420', 'up')
        j.begin('route', m['peer_tunnel'] + '/32')
        own.run('ip', 'route', 'add', m['peer_tunnel'] + '/32', 'dev', 'wgps0', 'src', m['host_tunnel'], 'metric', '77')
        route = own.data('ip', '-j', '-4', 'route', 'show', m['peer_tunnel'] + '/32')
        route_receipt = j.acquire('route', m['peer_tunnel'] + '/32', route, dev='wgps0', metric=77)
        time.sleep(6)
        route_proof(topology)
        yield None
    finally:
        own.same_identity(receipt['identity'], own.link_identity('wgps0'))
        if route is not None:
            own.same_identity(route, own.data('ip', '-j', '-4', 'route', 'show', m['peer_tunnel'] + '/32'))
            own.run('ip', 'route', 'delete', m['peer_tunnel'] + '/32', 'dev', 'wgps0', 'metric', '77')
            j.release(route_receipt)
        own.run('ip', 'link', 'delete', 'wgps0'); j.release(receipt)


def service_instances():
    result = {}
    for unit in own.UNITS:
        row = dict(line.split('=', 1) for line in own.run('systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'SubState',
                   '-p', 'MainPID', '-p', 'NRestarts', '-p', 'ControlGroup', '-p', 'FragmentPath', '-p', 'DropInPaths').stdout.splitlines())
        if row['ActiveState'] != 'active' or row['DropInPaths'] or row['FragmentPath'] != '/usr/lib/systemd/system/' + unit:
            raise ValueError('owned service inactive or identity changed')
        if unit == own.UNITS[1]:
            if row['SubState'] != 'running' or int(row['MainPID']) <= 0: raise ValueError('controller is not running')
            row['process'] = own.pid_identity(int(row['MainPID']))
        group = Path('/sys/fs/cgroup') / row['ControlGroup'].lstrip('/') if row['ControlGroup'] else None
        row['cgroup_inode'] = group.stat().st_ino if group and group.exists() else None
        result[unit] = row
    return result


class Product:
    def __init__(self, topology, arm, directory):
        self.t, self.m, self.j, self.arm, self.directory = topology, topology.m, topology.j, arm, directory
        self.receipt = None
        self.state_receipt = None
        self.instance = None

    def cli(self, *args, timeout=100):
        if self.receipt is None: raise ValueError('no owned installation receipt')
        for path, expected in self.receipt['identity']['files'].items(): own.same_identity(expected, own.file_identity(path))
        return own.data(CLI, *args) if timeout == 40 else json.loads(own.run(CLI, *args, timeout=timeout).stdout)

    def enter(self):
        # Product is a singleton; fixture already exists but product resources must not.
        observed = own.inventory()
        if observed['paths'] or observed['units'] or 'wgps0' in observed['links'] or 'wg_program_split' in observed['tables']:
            raise ValueError('foreign singleton before install')
        build = self.m['builds'][self.arm]
        for name, expected in build['sha256'].items():
            if own.file_identity(Path(build['directory']) / name)['sha256'] != expected: raise ValueError('build changed')
        profile, settings = self.directory / 'profile.conf', self.directory / 'settings.json'
        self.j.create_file(profile, self.t.profile().encode())
        selected = [str(Path(self.m['evidence']) / 'bin' / name) for name in ('selected-ip', 'selected-dns')]
        self.j.create_file(settings, json.dumps({'schema_version': 1, 'included_executables': selected}).encode())
        self.j.begin('product', str(CLI))
        result = own.run('/usr/bin/python3', '-I', Path(build['directory']) / 'wg-program-split.pyz', 'install',
                         '--profile', profile, '--settings', settings, '--artifacts', build['directory'], okay=False, timeout=90)
        if result.returncode:
            raise RuntimeError('installer failed; uncertain installation retained without adoption')
        if (CONFIG / 'installation.json').exists():
            paths = [CLI, *(ARTIFACTS / name for name in ('wg-program-split.pyz', 'bpf-loader', 'classifier.bpf.o')),
                     *(UNIT_DIR / unit for unit in own.UNITS)]
            # One read per file yields both the receipt and the hash, bound to the locked
            # manifest document rather than to build bytes that could change meanwhile.
            expected = {str(path): own.file_identity(path) for path in paths}
            for path in paths:
                wanted = hashlib.sha256(SHIM).hexdigest() if path == CLI else build['sha256'][path.name]
                if expected[str(path)]['sha256'] != wanted: raise ValueError('installed payload differs from manifest sha256; retained')
            package = Path(build['directory']) / 'wg-program-split.pyz'
            package_identity = own.file_identity(package)
            if package_identity['sha256'] != build['sha256'][package.name]: raise ValueError('staged package changed; retained')
            self.receipt = self.j.acquire('product', str(CLI), {'files': expected,
                'package': {'path': str(package), 'identity': package_identity},
                'manifest': own.file_identity(CONFIG / 'installation.json'),
                'directories': {str(p): own.directory_identity(p) for p in (ARTIFACTS, CONFIG)},
                'config': {str(CONFIG / name): own.file_identity(CONFIG / name) for name in ('profile.conf', 'settings.json')}})
        if result.returncode or not self.receipt: raise RuntimeError('install failed; owned leftovers retained')
        activated = time.time()
        self.j.begin('product-state', str(STATE))
        try: self.cli('activate')
        finally:
            if STATE.exists():
                self.state_receipt = self.j.acquire('product-state', str(STATE),
                    {'directory': own.directory_identity(STATE), 'lock': own.file_identity(STATE / '.lock')})
        observations, end = [], time.monotonic() + 30
        self.instance = service_instances()
        time.sleep(6)
        while True:
            status = self.cli('status'); observations.append(status)
            if stats.fresh_readiness(status, activated): break
            if time.monotonic() > end: raise RuntimeError('daemon did not publish fresh readiness')
            time.sleep(.25)
        own.same_identity(self.instance, service_instances())
        for name in ('controller.json', 'receipt.json'):
            path = STATE / name
            before = own.file_identity(path); document = json.loads(path.read_text())
            own.same_identity(before, own.file_identity(path))
            report(self.directory / ('product-' + name), document)
        report(self.directory / 'startup.json', {'activated_at': activated, 'instances': self.instance, 'observations': observations})
        report(self.directory / 'route-proof.json', route_proof(self.t, self.mark()))
        return self

    def mark(self): return own.data(ARTIFACTS / 'bpf-loader', 'snapshot', PINS)['mark']

    def counters(self):
        return {key: int(value) for row in own.run(ARTIFACTS / 'bpf-loader', 'status', PINS).stdout.splitlines()
                if '=' in row for key, value in [row.split('=', 1)] if value.isdecimal()}

    def _verify_retired_runtime(self):
        if os.path.lexists(PINS): raise ValueError('product pins remain or reappeared')
        if any(row['ifname'] == 'wgps0' for row in own.data('ip', '-j', 'link', 'show')):
            raise ValueError('product interface remains or reappeared')
        if any(row.get('table', {}).get('name') == 'wg_program_split' for row in own.data('nft', '-j', 'list', 'ruleset')['nftables']):
            raise ValueError('product nft table remains or reappeared')
        for unit in own.UNITS:
            value = dict(line.split('=', 1) for line in own.run('systemctl', 'show', unit, '-p', 'ActiveState',
                         '-p', 'MainPID', '-p', 'FragmentPath', '-p', 'DropInPaths', okay=False).stdout.splitlines())
            if (value.get('ActiveState') not in ('inactive', 'failed') or int(value.get('MainPID', '0')) or
                    value.get('DropInPaths') or value.get('FragmentPath') not in ('', '/usr/lib/systemd/system/' + unit)):
                raise ValueError('retired unit changed or became active')

    def _capture_retired_state(self):
        if not STATE.exists(): return {}
        if self.state_receipt is None: raise ValueError('unexpected runtime state retained')
        fd = os.open(STATE / '.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            own.same_identity(self.state_receipt['identity']['lock'], own.file_identity(STATE / '.lock'))
            path = STATE / 'controller.json'; expected = own.file_identity(path); document = json.loads(path.read_text())
            if (document['state'] != 'disabled' or document['pins'] is not None or document['pending'] is not None or
                    document['boot_id'] != self.m['boot_id'] or
                    document['profile_digest'] != self.receipt['identity']['config'][str(CONFIG / 'profile.conf')]['sha256']):
                raise ValueError('retired controller journal not ours')
            own.same_identity(expected, own.file_identity(path))
            return {str(path): expected, str(STATE / '.lock'): own.file_identity(STATE / '.lock')}
        finally: os.close(fd)

    def _verify_survivors(self, *, allow_missing):
        identity = self.receipt['identity']
        directories = dict(identity['directories'])
        files = {**identity['files'], **identity['config']}
        files[str(CONFIG / 'installation.json')] = identity['manifest']
        cleanup = self.receipt.get('cleanup', {})
        files.update(cleanup.get('state_files', {}))
        if self.state_receipt:
            directories[str(STATE)] = self.state_receipt['identity']['directory']
            files[str(STATE / '.lock')] = self.state_receipt['identity']['lock']
        for path, expected in directories.items():
            if allow_missing and not os.path.lexists(path): continue
            own.same_identity(expected, own.directory_identity(path))
        for path, expected in files.items():
            if allow_missing and not os.path.lexists(path): continue
            own.same_identity(expected, own.file_identity(path))

    def _resume_package_removal(self):
        identity = self.receipt['identity']
        manifest = CONFIG / 'installation.json'
        if manifest.exists():
            # CLI may have been removed during the earlier uninstall. Resume the
            # production install.uninstall function after durable disabled proof.
            package = identity['package']
            own.same_identity(package['identity'], own.file_identity(package['path']))
            script = ('import sys,json;sys.path.insert(0,sys.argv[1]);'
                      'from wg_program_split.install import uninstall;print(json.dumps(uninstall()))')
            removed = json.loads(own.run('/usr/bin/python3', '-I', '-c', script, package['path']).stdout)
            if removed['retained'] or removed.get('removal_deferred'): raise ValueError('owned uninstall incomplete')
        if os.path.lexists(manifest) or any(os.path.lexists(p) for p in identity['files']):
            raise ValueError('package removal postcondition not established')
        own.run('systemctl', 'daemon-reload')

    def close(self):
        if not self.receipt: return
        initial = 'cleanup' not in self.receipt
        if initial:
            self._verify_survivors(allow_missing=False)
            if STATE.exists() and not self.state_receipt: raise ValueError('runtime state not acquired')
            result = self.cli('disable')
            if result['state'] != 'disabled': raise ValueError('owned product failed to disable')
            self._verify_retired_runtime()
            cleanup = {'phase': 'uninstall-requested', 'state_files': self._capture_retired_state()}
            self.j.checkpoint(self.receipt, cleanup=cleanup)
        cleanup = self.receipt['cleanup']
        self._verify_retired_runtime()
        self._verify_survivors(allow_missing=True)
        if cleanup['phase'] == 'uninstall-requested':
            if initial:
                removed = self.cli('uninstall')
                if removed['retained'] or removed.get('removal_deferred'): raise ValueError('owned uninstall incomplete')
            self._resume_package_removal()
            cleanup = {**cleanup, 'phase': 'uninstalled'}
            self.j.checkpoint(self.receipt, cleanup=cleanup)
        if cleanup['phase'] != 'uninstalled': raise ValueError('unknown cleanup phase')
        for directory, allowed in ((CONFIG, self.receipt['identity']['config']), (STATE, cleanup['state_files']), (ARTIFACTS, {})):
            if not os.path.lexists(directory): continue  # Durable removal phase permits already removed owned objects.
            expected = (self.state_receipt['identity']['directory'] if directory == STATE else
                        self.receipt['identity']['directories'][str(directory)])
            own.same_identity(expected, own.directory_identity(directory))
            if not {str(p) for p in directory.iterdir()} <= set(allowed): raise ValueError('unexpected private file retained')
            for path, expected_file in allowed.items():
                if not os.path.lexists(path): continue
                own.same_identity(expected_file, own.file_identity(path)); Path(path).unlink()
            directory.rmdir()
        if self.state_receipt: self.j.release(self.state_receipt); self.state_receipt = None
        self.j.release(self.receipt); self.receipt = None


@contextlib.contextmanager
def installed(topology, arm, directory):
    product = Product(topology, arm, directory)
    try: yield product.enter()
    finally: product.close()
