# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit owned Linux networking operations; controller owns BPF readiness."""
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .config import Profile
from .errors import NetworkError  # noqa: F401
from .inventory import (  # noqa: F401  (re-exported for callers and tests)
    _BUILTIN_TABLES, _IPTABLES_DUMPS, _OPAQUE_MARK_EXTENSIONS, _TABLE_DIRS, _TABLE_FILES,
    _TOOL_PATH, _call, _has_mark, _iptables_dumps, _json, _legacy_mask, _legacy_zones,
    _named_tables, _nft_usage, _opaque_marks, _require_mark_visibility, _split_mark,
    _table, _u32, _wireguard_state, run_command,
)
from .firewall import Firewall
from . import ownership as own


@dataclass(frozen=True)
class Allocation:
    mask: int
    mark: int
    outer_mark: int
    routing_table: int
    priority: int
    zone: int
    interface: str = 'wgps0'
    nft_table: str = 'wg_program_split'

    def __post_init__(self):
        numbers = (self.mask, self.mark, self.outer_mark, self.routing_table, self.priority, self.zone)
        if (any(type(n) is not int for n in numbers) or not 0 < self.mask <= 0xffffffff or
                self.mask.bit_count() != 2 or self.mark.bit_count() != 1 or self.outer_mark.bit_count() != 1 or
                self.mark == self.outer_mark or self.mark | self.outer_mark != self.mask or
                not 57000 <= self.routing_table <= 57999 or not 1 <= self.priority <= 1000 or
                not 1 <= self.zone <= 65535 or self.interface != 'wgps0' or self.nft_table != 'wg_program_split'):
            raise NetworkError('invalid internal network allocation')


@dataclass(frozen=True)
class Inventory:
    used_mask: int
    tables: frozenset
    priorities: frozenset
    zones: frozenset
    underlay: str
    mtu: int


def inspect(profile: Profile, *, runner=run_command, require_underlay=True) -> Inventory:
    """Reserve policy resources before networking; transport checks default on.

    require_underlay=False is for the early blocked guard only. Its Inventory
    has underlay='' and mtu=0, which do not establish transport readiness.
    """
    if type(require_underlay) is not bool:
        raise NetworkError('require_underlay must be a boolean')
    try:
        return _inspect(profile, runner=runner, require_underlay=require_underlay)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        raise NetworkError('network inventory contains unsupported values') from None


def _inspect(profile, *, runner, require_underlay):
    """Read-only preflight; refuse old full tunnels and ambiguous policy state."""
    links = _json(runner, 'ip', '-j', '-d', 'link', 'show')
    rules = _json(runner, 'ip', '-j', '-4', 'rule', 'show')
    rules6 = _json(runner, 'ip', '-j', '-6', 'rule', 'show')
    routes = _json(runner, 'ip', '-j', '-4', 'route', 'show', 'table', 'all')
    nft = _json(runner, 'nft', '-j', 'list', 'ruleset')
    if (any(not isinstance(v, list) for v in (links, rules, rules6, routes)) or
            not isinstance(nft, dict) or not isinstance(nft.get('nftables'), list)):
        raise NetworkError('incomplete network inventory')
    if (any(link.get('ifname') == 'wgps0' for link in links) or
            any(entry.get('table', {}).get('name') == 'wg_program_split' and
                entry['table'].get('family') == 'inet' for entry in nft['nftables'])):
        raise NetworkError('reserved network name already exists; ownership is not established')
    if not any(rule.get('priority') == 0 and _table(rule.get('table', 0)) == 255 for rule in rules):
        raise NetworkError('required host local routing rule is absent')
    if sum(rule.get('priority') == 0 for rule in rules) != 1:
        raise NetworkError('foreign routing at priority zero prevents an earlier owned policy')
    tunnel_names = {link.get('ifname') for link in links if
                    link.get('linkinfo', {}).get('info_kind') in
                    ('wireguard', 'tun', 'ipip', 'gre', 'sit', 'vti', 'ip6tnl', 'xfrm')}
    if any(route.get('dev') in tunnel_names and route.get('dst') in ('default', '0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1')
           for route in routes):
        raise NetworkError('foreign full-tunnel routing must be retired by its owner')
    used, zones = _nft_usage(nft)
    priorities, tables = set(), {_table(route.get('table', 254)) for route in routes}
    for rule in rules + rules6:
        if 'fwmark' in rule:
            _u32(rule['fwmark'])
            used |= _u32(rule.get('fwmask', 0xffffffff))
        if 'table' in rule:
            tables.add(_table(rule['table']))
    for rule in rules:
        priorities.add(_u32(rule.get('priority')))
    for line in _call(runner, 'wg', 'show', 'all', 'fwmark').splitlines():
        parts = line.split()
        if len(parts) != 2:
            raise NetworkError('unparseable WireGuard mark inventory')
        if parts[1] != 'off':
            used |= _u32(parts[1])
    dumps = _iptables_dumps(runner)
    _require_mark_visibility(nft['nftables'], dumps)
    for text in dumps.values():
        used |= _legacy_mask(text)
        zones |= _legacy_zones(text)
    for token in _call(runner, 'conntrack', '-L', '-o', 'extended').split():
        if 'zone' in token:
            if not re.fullmatch(r'zone(?:-orig|-reply)?=[0-9]{1,5}', token):
                raise NetworkError('unparseable conntrack zone inventory')
            number = int(token.split('=')[1])
            if number > 65535:
                raise NetworkError('invalid conntrack zone inventory')
            zones.add(number)
    underlay, mtu = _underlay(profile, links, runner) if require_underlay else ('', 0)
    return Inventory(used, frozenset(tables), frozenset(priorities), frozenset(zones), underlay, mtu)


def _underlay(profile, links, runner):
    tunnel_names = {link.get('ifname') for link in links if
                    link.get('linkinfo', {}).get('info_kind') in
                    ('wireguard', 'tun', 'ipip', 'gre', 'sit', 'vti', 'ip6tnl', 'xfrm')}
    endpoint = _json(runner, 'ip', '-j', '-4', 'route', 'get', profile.endpoint_host)
    public = _json(runner, 'ip', '-j', '-4', 'route', 'get', '1.1.1.1')
    if (any(not isinstance(result, list) or len(result) != 1 or not result[0].get('dev') or
            result[0]['dev'] in tunnel_names or result[0]['dev'] == 'lo' for result in (endpoint, public))
            or not public[0].get('gateway')):
        raise NetworkError('unlisted and VPN transport routes must use an ordinary router path')
    underlay = next((link for link in links if link.get('ifname') == endpoint[0]['dev']), None)
    if not underlay or type(underlay.get('mtu')) is not int:
        raise NetworkError('underlay MTU is unknown')
    mtus = [underlay['mtu'], endpoint[0].get('mtu', underlay['mtu'])]
    metrics = endpoint[0].get('metrics', [])
    if isinstance(metrics, dict):
        metrics = [metrics]
    for metric in metrics:
        if 'mtu' in metric:
            mtus.append(metric['mtu'])
    if any(type(mtu) is not int or mtu <= 80 for mtu in mtus):
        raise NetworkError('underlay path MTU is not a usable integer')
    mtu = min(mtus)
    if profile.mtu > mtu - 80:
        raise NetworkError('profile MTU exceeds the observed underlay MTU minus 80 bytes')
    return underlay['ifname'], mtu


def allocate(inventory: Inventory) -> Allocation:
    available = [1 << bit for bit in range(32) if not inventory.used_mask & (1 << bit)]
    if len(available) < 2:
        raise NetworkError('no two collision-free socket mark bits are available')
    mask = 0x03000000 if not inventory.used_mask & 0x03000000 else available[0] | available[1]
    first_foreign = min((p for p in inventory.priorities if p), default=1001)
    priority = next((p for p in range(1, min(1001, first_foreign)) if p not in inventory.priorities), None)
    table = next((t for t in range(57000, 58000) if t not in inventory.tables), None)
    zone = next((z for z in range(1, 65536) if z not in inventory.zones), None)
    if any(value is None for value in (priority, table, zone)):
        raise NetworkError('no free routing priority, table, or conntrack zone is available')
    mark = mask & -mask
    return Allocation(mask, mark, mask ^ mark, table, priority, zone)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _stable_nft(value):
    if isinstance(value, list):
        return [_stable_nft(v) for v in value]
    if isinstance(value, dict):
        # Anonymous/named counter runtime totals are not configuration identity.
        return {k: ({x: _stable_nft(y) for x, y in v.items() if x not in ('packets', 'bytes')}
                    if k == 'counter' and isinstance(v, dict) else _stable_nft(v))
                for k, v in value.items()}
    return value


@dataclass(frozen=True)
class Health:
    matching: tuple[str, ...]
    missing: tuple[str, ...]
    changed: tuple[str, ...]
    ready: bool = False


class Network:
    """Concrete network lifetime under a caller-held ownership.locked_state.

    The controller must prove the selected BPF guard is blocked before prepare,
    repair, disable, or rollback. The boolean is an API precondition, not kernel proof.
    A failed acquisition never triggers automatic network cleanup.
    """

    def __init__(self, profile, directory_fd, *, runner=run_command, boot_id=None,
                 wireguard_root='/etc/wireguard', owner_uid=0, allocation=None, receipt=None):
        self.profile, self.directory, self.runner = profile, directory_fd, runner
        self.boot_id = boot_id or own.current_boot_id()
        self.wireguard_root, self.owner_uid = Path(wireguard_root), owner_uid
        self.receipt, self.allocation, self.uncertain = receipt, allocation, False
        if receipt is not None:
            own.validate_receipt(receipt, boot_id=self.boot_id, attempt_id=receipt.attempt_id)
            allowed = {('route', 'fallback'), ('route', 'preferred'), ('rule', 'vpn'),
                       ('interface', 'wgps0'), ('nft_table', 'wg_program_split'), ('conntrack_zone', 'vpn'),
                       ('sysctl', 'route_localnet'), ('private_file', 'configuration'),
                       ('private_directory', 'configuration')}
            if any((r.kind, r.name) not in allowed for r in receipt.resources):
                raise NetworkError('receipt includes resources outside the network adapter scope')
            for resource in receipt.resources:
                if resource.kind in ('private_file', 'private_directory'):
                    expected = str(self.wireguard_root / ('wgps-' + receipt.attempt_id))
                    if (resource.identity.get('path') != expected or
                            (resource.kind == 'private_file' and
                             resource.identity.get('file', {}).get('name') != 'wg.conf')):
                        raise NetworkError('private configuration ownership is outside this attempt directory')
            fallback = next((r for r in receipt.resources if r.kind == 'route' and r.name == 'fallback'), None)
            if fallback is not None:
                recovered = Allocation(**fallback.identity['allocation'])
                if allocation is not None and allocation != recovered:
                    raise NetworkError('allocation does not match the recorded acquisition')
                self.allocation = recovered
            if receipt.resources and self.allocation is None:
                raise NetworkError('nonempty network receipt is missing its allocation evidence')

    def _run(self, *argv, input=None):
        return _call(self.runner, *argv, input=input)

    def _publish(self, updated):
        try:
            own.write_receipt(self.directory, updated, expected=self.receipt)
        except own.OwnershipError:
            self.uncertain = True
            try:
                loaded = own.read_receipt(self.directory)
                own.validate_receipt(loaded, boot_id=self.boot_id, attempt_id=updated.attempt_id)
                self.receipt = loaded
            except own.OwnershipError:
                pass
            raise NetworkError('receipt publication failed; acquisition or cleanup may be unrecorded') from None
        self.receipt = updated

    def _record(self, kind, name, identity):
        resources = tuple(r for r in self.receipt.resources if (r.kind, r.name) != (kind, name))
        self._publish(replace(self.receipt, resources=resources + (own.ResourceIdentity(kind, name, identity),)))

    def _forget(self, resource):
        self._publish(replace(self.receipt, resources=tuple(
            r for r in self.receipt.resources if (r.kind, r.name) != (resource.kind, resource.name))))

    def _snapshot(self):
        try:
            snapshot = {
                'links': _json(self.runner, 'ip', '-j', '-d', 'link', 'show'),
                'routes': _json(self.runner, 'ip', '-j', '-4', 'route', 'show', 'table', 'all'),
                'rules': _json(self.runner, 'ip', '-j', '-4', 'rule', 'show'),
                'rules6': _json(self.runner, 'ip', '-j', '-6', 'rule', 'show'),
                'nft': _json(self.runner, 'nft', '-j', 'list', 'ruleset')['nftables'],
            }
            if any(not isinstance(v, list) or any(not isinstance(x, dict) for x in v)
                   for v in snapshot.values()):
                raise ValueError
            return snapshot
        except (KeyError, TypeError, ValueError):
            raise NetworkError('incomplete live network inventory') from None

    def _nft_identity(self, entries):
        selected = []
        table = None
        for entry in entries:
            for kind, item in entry.items():
                if not isinstance(item, dict) or item.get('family') != 'inet':
                    continue
                if ((kind == 'table' and item.get('name') == self.allocation.nft_table) or
                        item.get('table') == self.allocation.nft_table):
                    selected.append(entry)
                    if kind == 'table':
                        if table is not None:
                            raise NetworkError('ambiguous owned nft table inventory')
                        table = item
        if table is None:
            return None
        return {'handle': table.get('handle'), 'comment': table.get('comment'),
                'sha256': _digest(_stable_nft(selected)),
                # Bind observed kernel content to the profile used at acquisition;
                # a new resolver or key must not inherit the old state's readiness.
                'profile_sha256': _digest(asdict(self.profile))}

    def _directory_identity(self, path):
        fd = own.open_private_dir(path, owner_uid=self.owner_uid)
        try:
            info = os.fstat(fd)
            return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
                    'owner_uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}
        finally:
            os.close(fd)

    def _observe(self, resource, snapshot):
        a, kind, name = self.allocation, resource.kind, resource.name
        if kind == 'route':
            metric = 32760 if name == 'fallback' else 10
            routes = [r for r in snapshot['routes'] if _table(r.get('table', 254)) == a.routing_table
                      and r.get('metric') == metric and r.get('dst') in ('default', '0.0.0.0/0')]
            if not routes:
                return None
            if len(routes) != 1:
                return {'ambiguous': True}
            result = {'state': routes[0]}
            if name == 'fallback':
                result['allocation'] = asdict(a)
            return result
        if kind == 'rule':
            rules = [r for r in snapshot['rules'] if r.get('priority') == a.priority]
            return None if not rules else {'state': rules[0]} if len(rules) == 1 else {'ambiguous': True}
        if kind == 'nft_table':
            return self._nft_identity(snapshot['nft'])
        if kind == 'conntrack_zone':
            table = self._nft_identity(snapshot['nft'])
            if table is None:
                return None
            return {'zone': a.zone, 'nft_handle': table['handle'], 'comment': table['comment']}
        if kind in ('interface', 'sysctl'):
            link = next((x for x in snapshot['links'] if x.get('ifname') == a.interface), None)
            if link is None:
                return None
            if kind == 'sysctl':
                return {'ifindex': link['ifindex'], 'value': self._run(
                    'sysctl', '-n', 'net.ipv4.conf.wgps0.route_localnet').strip()}
            result = {'ifindex': link['ifindex'], 'kind': link.get('linkinfo', {}).get('info_kind'),
                      'alias': link.get('ifalias', ''), 'mtu': link.get('mtu'),
                      'up': 'UP' in link.get('flags', [])}
            if (result['kind'] != 'wireguard' or resource.identity and any(
                    result[field] != resource.identity.get(field) for field in ('ifindex', 'alias'))):
                # Never request key-bearing output for a known replacement.
                return result
            addresses = _json(self.runner, 'ip', '-j', '-4', 'address', 'show', 'dev', a.interface)
            result['addresses'] = sorted(f"{x['local']}/{x['prefixlen']}" for dev in addresses
                                         for x in dev.get('addr_info', []) if x.get('family') == 'inet')
            result['prefix_route_flags'] = sorted(bool(x.get('noprefixroute', False)) for dev in addresses
                                                  for x in dev.get('addr_info', []) if x.get('family') == 'inet')
            result.update(_wireguard_state(self._run('wg', 'show', a.interface, 'dump')))
            return result
        if kind in ('private_file', 'private_directory'):
            path = Path(resource.identity['path'])
            # A missing leaf is distinguishable from a symlink/unsafe ancestor.
            parent = own.open_private_dir(path.parent, owner_uid=self.owner_uid)
            try:
                try:
                    os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return None
            finally:
                os.close(parent)
            directory = self._directory_identity(path)
            if kind == 'private_directory':
                return directory
            fd = own.open_private_dir(path, owner_uid=self.owner_uid)
            try:
                filename = resource.identity['file']['name']
                try:
                    os.stat(filename, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                return {**directory, 'file': asdict(own.file_identity(fd, filename))}
            finally:
                os.close(fd)
        raise NetworkError('receipt contains a resource outside the network adapter scope')

    def _capture(self, kind, name):
        identity = self._observe(own.ResourceIdentity(kind, name, {}), self._snapshot())
        if identity is None:
            raise NetworkError('newly acquired network resource is missing during readback')
        if kind == 'nft_table' and (type(identity['handle']) is not int or identity['handle'] <= 0 or
                                   identity['comment'] != 'wgps:' + self.receipt.attempt_id):
            raise NetworkError('new nft table lacks its required handle and attempt marker')
        self._record(kind, name, identity)
        return identity

    def _allocation_conflict(self, snapshot):
        a = self.allocation
        foreign_nft = [entry for entry in snapshot['nft'] if not any(
            isinstance(item, dict) and item.get('family') == 'inet' and
            ((kind == 'table' and item.get('name') == a.nft_table) or item.get('table') == a.nft_table)
            for kind, item in entry.items())]
        bits, zones = _nft_usage(foreign_nft)
        own_rules = {_canonical(r.identity['state']) for r in self.receipt.resources if r.kind == 'rule'}
        for rule in snapshot['rules']:
            if _canonical(rule) in own_rules:
                continue
            priority = _u32(rule.get('priority'))
            if 0 < priority <= a.priority or (priority == 0 and _table(rule.get('table', 0)) != 255):
                return True
            if 'fwmark' in rule:
                bits |= _u32(rule.get('fwmask', 0xffffffff))
        if sum(r.get('priority') == 0 and _table(r.get('table', 0)) == 255 for r in snapshot['rules']) != 1:
            return True
        for rule in snapshot['rules6']:
            if 'fwmark' in rule:
                bits |= _u32(rule.get('fwmask', 0xffffffff))
        for line in self._run('wg', 'show', 'all', 'fwmark').splitlines():
            parts = line.split()
            if len(parts) != 2:
                raise NetworkError('unparseable WireGuard mark inventory')
            if parts[0] != a.interface and parts[1] != 'off':
                bits |= _u32(parts[1])
        dumps = _iptables_dumps(self.runner)
        _require_mark_visibility(foreign_nft, dumps)
        for text in dumps.values():
            bits |= _legacy_mask(text)
            zones |= _legacy_zones(text)
        return bool(bits & a.mask or a.zone in zones)

    def _acquire(self, kind, name, *argv, input=None):
        # Exclusive command success plus readback establishes birth ownership.
        # A timeout/death between them must not turn into name-only adoption.
        self.uncertain = True
        self._run(*argv, input=input)
        result = self._capture(kind, name)
        self.uncertain = False
        return result

    def _route_argv(self, action, name):
        a = self.allocation
        destination = ('unreachable', 'default') if name == 'fallback' else ('default',)
        args = ('ip', '-4', 'route', action, *destination, 'table', str(a.routing_table),
                'metric', '32760' if name == 'fallback' else '10', 'proto', 'static')
        if name == 'preferred':
            args += ('dev', a.interface, 'src', self.profile.address.split('/')[0])
        return args

    def _rule_argv(self, action):
        a = self.allocation
        return ('ip', '-4', 'rule', action, 'priority', str(a.priority),
                'fwmark', f'{a.mark:#x}/{a.mask:#x}', 'table', str(a.routing_table))

    def _configure(self):
        a, p = self.allocation, self.profile
        path = self.wireguard_root / ('wgps-' + self.receipt.attempt_id)
        root = own.open_private_dir(self.wireguard_root, owner_uid=self.owner_uid)
        try:
            self.uncertain = True
            os.mkdir(path.name, 0o700, dir_fd=root)
            os.fsync(root)
            identity = self._directory_identity(path)
            self._record('private_directory', 'configuration', identity)
            self.uncertain = False
        finally:
            os.close(root)
        directory = own.open_private_dir(path, owner_uid=self.owner_uid)
        try:
            # Stock AppArmor permits wg config files here, unlike stdin/proc-FD
            # profiles. Keys are never command arguments, receipt data, or logs.
            body = f'[Interface]\nPrivateKey = {p.private_key}\nFwMark = {a.outer_mark:#x}\n'
            body += f'[Peer]\nPublicKey = {p.public_key}\n'
            if p.preshared_key:
                body += f'PresharedKey = {p.preshared_key}\n'
            body += f'AllowedIPs = 0.0.0.0/0\nEndpoint = {p.endpoint_host}:{p.endpoint_port}\n'
            body += f'PersistentKeepalive = {p.persistent_keepalive}\n'
            self.uncertain = True
            file = own.create_owned_file(directory, 'wg.conf', body.encode())
            self._record('private_file', 'configuration', {**identity, 'file': asdict(file)})
            self.uncertain = False
        finally:
            os.close(directory)
        self._run('wg', 'setconf', a.interface, str(path / 'wg.conf'))
        self._capture('interface', a.interface)
        for kind in ('private_file', 'private_directory'):
            self._remove(next(r for r in self.receipt.resources if r.kind == kind))

    def _install_interface(self):
        a = self.allocation
        self._acquire('interface', a.interface, 'ip', 'link', 'add', 'name', a.interface, 'type', 'wireguard')
        self._run('ip', 'link', 'set', 'dev', a.interface, 'alias', 'wgps:' + self.receipt.attempt_id,
                  'mtu', str(self.profile.mtu))
        self._capture('interface', a.interface)
        self._run('ip', '-4', 'address', 'add', self.profile.address, 'dev', a.interface, 'noprefixroute')
        self._capture('interface', a.interface)
        self._configure()
        self._run('sysctl', '-w', 'net.ipv4.conf.wgps0.route_localnet=1')
        self._capture('sysctl', 'route_localnet')
        self._run('ip', 'link', 'set', 'dev', a.interface, 'up')
        self._capture('interface', a.interface)

    def prepare(self, *, guard_blocked):
        if guard_blocked is not True:
            raise NetworkError('controller must establish a blocked selected-process guard first')
        if self.receipt is not None or self.uncertain:
            raise NetworkError('prepare requires a new acquisition attempt')
        inventory = inspect(self.profile, runner=self.runner)
        candidate = allocate(inventory)
        if self.allocation is not None and self.allocation != candidate:
            raise NetworkError('allocation changed since controller preflight')
        self.allocation = candidate
        fd = own.open_private_dir(self.wireguard_root, owner_uid=self.owner_uid)
        os.close(fd)
        self._publish(own.new_receipt(boot_id=self.boot_id))
        a = self.allocation
        self._acquire('route', 'fallback', *self._route_argv('add', 'fallback'))
        self._acquire('rule', 'vpn', *self._rule_argv('add'))
        firewall = Firewall(self.profile.address.split('/')[0], self.profile.resolver,
                            interface=a.interface, table=a.nft_table, mask=a.mask, mark=a.mark, zone=a.zone)
        marker = 'wgps:' + self.receipt.attempt_id
        script = firewall.render().replace(
            f'table inet {a.nft_table} {{', f'create table inet {a.nft_table} {{\n comment "{marker}";', 1)
        self._run('nft', '-c', '-f', '-', input=script)
        self._acquire('nft_table', a.nft_table, 'nft', '-f', '-', input=script)
        self._capture('conntrack_zone', 'vpn')
        self._install_interface()
        self._acquire('route', 'preferred', *self._route_argv('add', 'preferred'))
        health = self.health()
        if not health.ready:
            raise NetworkError('prepared network state did not survive final ownership verification')
        return self.receipt

    def health(self):
        try:
            return self._health()
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
            raise NetworkError('live network inventory contains unsupported values') from None

    def _health(self):
        if self.receipt is None or not self.receipt.resources:
            return Health((), (), ('unrecorded acquisition',) if self.uncertain else ())
        own.validate_receipt(self.receipt, boot_id=self.boot_id, attempt_id=self.receipt.attempt_id)
        snapshot = self._snapshot()
        matching, missing, changed = [], [], []
        for resource in self.receipt.resources:
            label = resource.kind + ':' + resource.name
            try:
                live = self._observe(resource, snapshot)
                if live is None:
                    missing.append(label)
                elif _canonical(live) == _canonical(resource.identity):
                    matching.append(label)
                else:
                    changed.append(label)
            except (own.OwnershipError, OSError):
                changed.append(label)
        if self.uncertain:
            changed.append('unrecorded acquisition')
        expected_routes = {_canonical(r.identity['state']) for r in self.receipt.resources if r.kind == 'route'}
        if any(_table(r.get('table', 254)) == self.allocation.routing_table and
               _canonical(r) not in expected_routes for r in snapshot['routes']):
            changed.append('routing_table:foreign')
        if self._allocation_conflict(snapshot):
            changed.append('allocation:foreign')
        a = self.allocation
        required = {'route:fallback', 'route:preferred', 'rule:vpn', 'interface:' + a.interface,
                    'nft_table:' + a.nft_table, 'conntrack_zone:vpn', 'sysctl:route_localnet'}
        private_pending = any(r.kind in ('private_file', 'private_directory') for r in self.receipt.resources)
        ready = self._configured_interface() and required.issubset(matching) and not missing and not changed and not private_pending
        return Health(tuple(matching), tuple(missing), tuple(changed), ready)

    def _configured_interface(self):
        a, p = self.allocation, self.profile
        interface = next((r.identity for r in self.receipt.resources if r.kind == 'interface'), {})
        expected = {'kind': 'wireguard', 'alias': 'wgps:' + self.receipt.attempt_id,
                    'mtu': p.mtu, 'up': True, 'addresses': [p.address], 'prefix_route_flags': [True],
                    'fwmark': a.outer_mark, 'peers': [[p.public_key]],
                    'endpoints': [[p.public_key, f'{p.endpoint_host}:{p.endpoint_port}']],
                    'allowed-ips': [[p.public_key, '0.0.0.0/0']],
                    'persistent-keepalive': [[p.public_key, str(p.persistent_keepalive) if p.persistent_keepalive else 'off']]}
        return all(_canonical(interface.get(k)) == _canonical(v) for k, v in expected.items())

    def repair_missing(self, *, guard_blocked):
        """Recreate a missing preferred route or deleted WG interface only.

        Caller holds the state lock and proves the BPF guard is blocked. Safety
        anchors and flow zone stay installed. Changed or ambiguous resources
        require inspection, including an interrupted unrecorded repair birth.
        """
        if (guard_blocked is not True or self.uncertain or self.receipt is None or
                not self.receipt.resources):
            raise NetworkError('repair requires a blocked guard and an unambiguous receipt')
        if _canonical(asdict(own.read_receipt(self.directory))) != _canonical(asdict(self.receipt)):
            raise NetworkError('receipt changed before repair')
        health = self.health()
        if health.ready:
            return self.receipt
        a = self.allocation
        anchors = {'route:fallback', 'rule:vpn', 'nft_table:' + a.nft_table, 'conntrack_zone:vpn'}
        replaceable = {'route:preferred', 'interface:' + a.interface, 'sysctl:route_localnet'}
        recorded = {r.kind + ':' + r.name for r in self.receipt.resources}
        missing = set(health.missing)
        if (health.changed or not anchors.issubset(health.matching) or
                recorded != anchors | replaceable or not self._configured_interface() or
                missing not in ({'route:preferred'}, replaceable)):
            raise NetworkError('repair requires intact safety anchors and only missing tunnel resources')
        _underlay(self.profile, self._snapshot()['links'], self.runner)
        # A same-attribute route can be recreated after disappearance. Fence its
        # old identity durably before birth so a crash cannot bless an orphan.
        self._publish(replace(self.receipt, resources=tuple(
            replace(r, identity={**r.identity, 'repair_pending': True})
            if r.kind + ':' + r.name in missing else r for r in self.receipt.resources)))
        # Recheck after the durable fence, before the first exclusive operation.
        current = self.health()
        if current.changed or set(current.missing) != missing:
            raise NetworkError('network changed while preparing repair; retain guard and inspect')
        if 'interface:' + a.interface in missing:
            self._install_interface()
        self._acquire('route', 'preferred', *self._route_argv('add', 'preferred'))
        if not self.health().ready:
            raise NetworkError('repaired network did not survive final ownership verification')
        return self.receipt

    def _flush_zone(self):
        a = self.allocation
        try:
            self._run('conntrack', '-D', '--zone', str(a.zone))
        except NetworkError:
            # conntrack may report failure when no matching entries exist.
            # A successful empty scoped readback is required, never assume.
            if self._run('conntrack', '-L', '--zone', str(a.zone), '-o', 'extended').strip():
                raise NetworkError('owned conntrack zone cleanup is incomplete') from None
        if self._run('conntrack', '-L', '--zone', str(a.zone), '-o', 'extended').strip():
            raise NetworkError('owned conntrack zone still contains flows after cleanup')

    def _sweep_private(self, attempt_id):
        """Remove a private configuration orphaned by a crash before its scoped removal."""
        name = 'wgps-' + attempt_id
        try:
            root = own.open_private_dir(self.wireguard_root, owner_uid=self.owner_uid)
            try:
                try:
                    os.stat(name, dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    return
                directory = own.open_private_dir(self.wireguard_root / name, owner_uid=self.owner_uid)
                try:
                    try:
                        os.unlink('wg.conf', dir_fd=directory)
                    except FileNotFoundError:
                        pass
                    os.fsync(directory)
                finally:
                    os.close(directory)
                os.rmdir(name, dir_fd=root)
                os.fsync(root)
            finally:
                os.close(root)
        except (own.OwnershipError, OSError):
            raise NetworkError('orphaned private configuration could not be verified and removed') from None

    def _remove(self, resource):
        live = self._observe(resource, self._snapshot())
        if live is None:
            if resource.kind == 'conntrack_zone':
                # The owned table is already gone (for example a foreign ruleset
                # flush); stale zone flows are still ours to remove by number.
                self._flush_zone()
            self._forget(resource)
            return
        own.verify_resource(self.receipt, resource.kind, resource.name, live,
                            boot_id=self.boot_id, attempt_id=self.receipt.attempt_id)
        a, kind = self.allocation, resource.kind
        if kind == 'private_file':
            fd = own.open_private_dir(resource.identity['path'], owner_uid=self.owner_uid)
            try:
                own.verify_file(fd, resource.identity['file']['name'], own.FileIdentity(**resource.identity['file']))
                os.unlink(resource.identity['file']['name'], dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)
        elif kind == 'private_directory':
            path = Path(resource.identity['path'])
            fd = own.open_private_dir(path.parent, owner_uid=self.owner_uid)
            try:
                os.rmdir(path.name, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)
        elif kind == 'route':
            self._run(*self._route_argv('delete', resource.name))
        elif kind == 'rule':
            self._run(*self._rule_argv('delete'))
        elif kind == 'interface':
            self._run('ip', 'link', 'delete', 'dev', a.interface)
        elif kind == 'nft_table':
            self._run('nft', 'delete', 'table', 'inet', a.nft_table)
        elif kind == 'conntrack_zone':
            self._flush_zone()
        elif kind == 'sysctl':
            # Per-interface setting dies with the verified owned interface.
            raise NetworkError('owned interface must be removed before forgetting its sysctl')
        else:
            raise NetworkError('resource is outside the network cleanup scope')
        if kind != 'conntrack_zone' and self._observe(resource, self._snapshot()) is not None:
            raise NetworkError('resource remains after its scoped deletion; retain ownership receipt')
        self._forget(resource)

    def disable(self, *, guard_blocked):
        if guard_blocked is not True or self.uncertain:
            raise NetworkError('cleanup requires a blocked guard and an unambiguous receipt')
        if self.receipt is None:
            return None
        if _canonical(asdict(own.read_receipt(self.directory))) != _canonical(asdict(self.receipt)):
            raise NetworkError('receipt changed before cleanup')
        if not self.receipt.resources:
            return self.receipt
        health = self.health()
        # A missing zone binding is only acceptable together with its whole owned
        # table (for example after a foreign ruleset flush): the flows are then
        # removed by zone number. A missing binding under a present table is an
        # ambiguous replacement and stays for inspection.
        table_missing = 'nft_table:' + self.allocation.nft_table in health.missing
        if health.changed or ('conntrack_zone:vpn' in health.missing and not table_missing):
            raise NetworkError('cleanup ownership is incomplete; retain guard and inspect live resources')
        # All identities are checked before the first deletion, then individually
        # again. Keep nft drop rules/zone binding until WG and its flows are gone.
        order = (('private_file', 'configuration'), ('private_directory', 'configuration'),
                 ('route', 'preferred'), ('interface', self.allocation.interface),
                 ('sysctl', 'route_localnet'), ('conntrack_zone', 'vpn'),
                 ('nft_table', self.allocation.nft_table), ('rule', 'vpn'), ('route', 'fallback'))
        for key in order:
            resource = next((r for r in self.receipt.resources if (r.kind, r.name) == key), None)
            if resource is not None:
                self._remove(resource)
        self._sweep_private(self.receipt.attempt_id)
        return self.receipt
