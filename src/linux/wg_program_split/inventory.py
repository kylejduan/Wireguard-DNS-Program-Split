# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded command execution and read-only parsing of routing, nftables,
iptables and WireGuard inventories."""
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from .errors import NetworkError


_TOOL_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
_IPTABLES_DUMPS = ('iptables-legacy-save', 'ip6tables-legacy-save', 'iptables-nft-save', 'ip6tables-nft-save')
_OPAQUE_MARK_EXTENSIONS = {'MARK', 'CONNMARK', 'CT', 'mark', 'connmark'}


def run_command(argv, *, input=None):
    """Run fixed argv with a trusted executable search path, no shell, no logs."""
    if not argv or argv[0] not in {'ip', 'wg', 'nft', 'conntrack', 'sysctl', *_IPTABLES_DUMPS}:
        raise NetworkError('unsupported network command')
    try:
        result = subprocess.run(tuple(argv), input=input, capture_output=True, text=True,
                                timeout=15, check=False,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.SubprocessError):
        raise NetworkError('network command failed or timed out; inspect effective state') from None
    if result.returncode or len(result.stdout) > 32 * 1024 * 1024:
        raise NetworkError('network command failed or returned excessive output')
    return result.stdout


def _call(runner, *argv, input=None):
    try:
        return runner(tuple(argv), input=input)
    except Exception:
        raise NetworkError('network command failed; effective state may require inspection') from None


def _json(runner, *argv):
    try:
        return json.loads(_call(runner, *argv))
    except (ValueError, TypeError):
        raise NetworkError('network inventory is not valid JSON') from None


def _u32(value):
    try:
        number = int(value, 0) if isinstance(value, str) else value
    except ValueError:
        raise NetworkError('unparseable network integer') from None
    if type(number) is not int or not 0 <= number <= 0xffffffff:
        raise NetworkError('unparseable network integer')
    return number


def _wireguard_state(raw):
    """Normalize an owned-interface dump to the existing nonsecret receipt fields."""
    rows = [line.split('\t') for line in raw.splitlines()]
    del raw
    malformed = not rows
    for index, row in enumerate(rows):
        malformed |= len(row) != (4 if index == 0 else 8)
        # Drop private key / PSK before any parsing, hashing or returned state.
        secret_column = 0 if index == 0 else 1
        del row[secret_column:secret_column + 1]
    if malformed:
        rows.clear()
        raise NetworkError('malformed owned WireGuard state')

    def integer(value, maximum):
        if not re.fullmatch(r'[0-9]{1,20}', value) or int(value) > maximum:
            raise NetworkError('malformed owned WireGuard state')
        return int(value)

    def key(value):
        if (not re.fullmatch(r'[A-Za-z0-9+/]{43}=', value) or
                base64.b64encode(base64.b64decode(value)).decode() != value):
            raise NetworkError('malformed owned WireGuard state')

    public, listen_port, mark = rows[0]
    if public != '(none)':
        key(public)
    integer(listen_port, 65535)
    if mark == 'off':
        fwmark = 0
    elif re.fullmatch(r'0x[0-9a-f]{1,8}', mark):
        fwmark = int(mark, 16)
    else:
        raise NetworkError('malformed owned WireGuard state')
    result = {'public_key_sha256': hashlib.sha256(public.encode()).hexdigest(),
              'fwmark': fwmark, 'peers': [], 'endpoints': [], 'allowed-ips': [],
              'persistent-keepalive': []}
    seen = set()
    for public, endpoint, allowed, handshake, received, sent, keepalive in rows[1:]:
        key(public)
        if public in seen or any(not x or re.search(r'\s', x) for x in (endpoint, allowed)):
            raise NetworkError('malformed owned WireGuard state')
        seen.add(public)
        for value in (handshake, received, sent):
            integer(value, 0xffffffffffffffff)
        if keepalive != 'off':
            integer(keepalive, 65535)
        allowed = allowed.split(',')
        if not all(allowed):
            raise NetworkError('malformed owned WireGuard state')
        result['peers'].append([public])
        result['endpoints'].append([public, endpoint])
        result['allowed-ips'].append([public, *allowed])
        result['persistent-keepalive'].append([public, keepalive])
    for field in ('peers', 'endpoints', 'allowed-ips', 'persistent-keepalive'):
        result[field].sort()
    return result


_BUILTIN_TABLES = {'local': 255, 'main': 254, 'default': 253, 'unspec': 0}
_TABLE_FILES = ('/etc/iproute2/rt_tables', '/usr/lib/iproute2/rt_tables', '/usr/share/iproute2/rt_tables')
_TABLE_DIRS = ('/etc/iproute2/rt_tables.d', '/usr/lib/iproute2/rt_tables.d')


def _named_tables():
    """Resolve administrator-named routing tables, which ip prints by name."""
    names = dict(_BUILTIN_TABLES)
    paths = [Path(p) for p in _TABLE_FILES]
    for directory in _TABLE_DIRS:
        try:
            paths.extend(sorted(Path(directory).glob('*.conf')))
        except OSError:
            continue
    for path in paths:
        try:
            text = path.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            fields = line.split('#', 1)[0].split()
            if len(fields) == 2 and re.fullmatch(r'0x[0-9a-fA-F]{1,8}|[0-9]{1,10}', fields[0]):
                try:
                    names.setdefault(fields[1], _u32(fields[0]))
                except NetworkError:
                    continue
    return names


def _table(value):
    if isinstance(value, str) and value in _BUILTIN_TABLES:
        return _BUILTIN_TABLES[value]
    if isinstance(value, str) and not re.fullmatch(r'0x[0-9a-fA-F]{1,8}|[0-9]{1,10}', value):
        named = _named_tables()
        if value in named:
            return named[value]
        raise NetworkError('unknown named routing table')
    return _u32(value)


def _has_mark(value):
    if isinstance(value, dict):
        return (isinstance(value.get('meta'), dict) and value['meta'].get('key') == 'mark' or
                any(_has_mark(v) for v in value.values()))
    return isinstance(value, list) and any(_has_mark(v) for v in value)


def _nft_usage(value):
    """Recognize constant masks/preserving writes; reject dynamic mark semantics."""
    mark = {'meta': {'key': 'mark'}}
    zone = {'ct': {'key': 'zone'}}
    used, zones = 0, set()
    if isinstance(value, list):
        for item in value:
            bits, found = _nft_usage(item)
            used |= bits
            zones |= found
        return used, zones
    if not isinstance(value, dict):
        return used, zones
    if 'xt' in value and isinstance(value['xt'], dict):
        # iptables-nft renders its extensions opaquely; their bits and zones
        # come from the textual iptables-nft-save dump instead (see _opaque_marks).
        return used, zones
    if 'mangle' in value and value['mangle'].get('key') == mark:
        output = value['mangle']['value']
        if type(output) is int:
            return 0xffffffff, zones
        try:
            preserved, added = output['|']
            original, mask = preserved['&']
            if original != mark:
                raise ValueError
            return ((~_u32(mask)) | _u32(added)) & 0xffffffff, zones
        except (KeyError, TypeError, ValueError):
            raise NetworkError('unsupported nftables mark assignment') from None
    if 'match' in value and _has_mark(value['match']):
        item = value['match']
        left = item.get('left')
        if left == mark:
            _u32(item.get('right'))
            return 0xffffffff, zones
        if isinstance(left, dict) and '&' in left and len(left['&']) == 2 and left['&'][0] == mark:
            _u32(item.get('right'))
            return _u32(left['&'][1]), zones
        raise NetworkError('unsupported nftables mark comparison')
    if 'mangle' in value and value['mangle'].get('key') == zone:
        number = _u32(value['mangle'].get('value'))
        if number > 65535:
            raise NetworkError('invalid conntrack zone')
        return used, {number}
    if 'match' in value and value['match'].get('left') == zone:
        return used, {_u32(value['match'].get('right'))}
    if ((isinstance(value.get('meta'), dict) and value['meta'].get('key') == 'mark') or
            (isinstance(value.get('ct'), dict) and value['ct'].get('key') == 'zone')):
        raise NetworkError('unrecognized nftables mark or zone expression')
    for item in value.values():
        bits, found = _nft_usage(item)
        used |= bits
        zones |= found
    return used, zones


def _opaque_marks(entries):
    """True when the ruleset carries iptables extensions whose marks nft -j hides."""
    if isinstance(entries, list):
        return any(_opaque_marks(item) for item in entries)
    if not isinstance(entries, dict):
        return False
    xt = entries.get('xt')
    if isinstance(xt, dict) and xt.get('name') in _OPAQUE_MARK_EXTENSIONS:
        return True
    return any(_opaque_marks(item) for item in entries.values())


def _iptables_dumps(runner):
    """Textual dumps from every installed iptables flavour; absent tools are skipped."""
    return {tool: _call(runner, tool) for tool in _IPTABLES_DUMPS
            if shutil.which(tool, path=_TOOL_PATH) is not None}


def _require_mark_visibility(nft_entries, dumps):
    if _opaque_marks(nft_entries) and not {'iptables-nft-save', 'ip6tables-nft-save'} <= set(dumps):
        raise NetworkError('iptables-nft mark or conntrack rules need iptables-nft-save to be inventoried')


def _split_mark(value):
    pieces = value.split('/')
    if len(pieces) > 2:
        raise ValueError
    return _u32(pieces[0]), _u32(pieces[1]) if len(pieces) == 2 else 0xffffffff


def _legacy_mask(text):
    """Packet-mark bits an iptables dump can read or write.

    MARK writes the packet mark; CONNMARK --restore-mark copies conntrack-mark
    bits into the packet mark within --nfmask (all bits by default); every other
    CONNMARK operation and the connmark match touch the conntrack mark only.
    """
    used = 0
    for line in text.splitlines():
        if not re.search(r'\b(?:MARK|CONNMARK|mark|connmark)\b', line):
            continue
        try:
            args = shlex.split(line)
            module = target = None
            recognized = False
            index = 0
            while index < len(args):
                token = args[index]
                if token in ('-m', '--match'):
                    module = args[index + 1]
                    index += 2
                    continue
                if token in ('-j', '--jump', '-g', '--goto'):
                    target = args[index + 1]
                    index += 2
                    continue
                if token == '--mark':
                    value, mask = _split_mark(args[index + 1])
                    if module == 'mark':
                        used |= value | mask
                    elif module != 'connmark':
                        raise ValueError
                    recognized = True
                elif token in ('--set-mark', '--set-xmark', '--and-mark', '--or-mark', '--xor-mark'):
                    value, mask = _split_mark(args[index + 1])
                    if target == 'MARK':
                        used |= ((~value) & 0xffffffff if token == '--and-mark' else
                                 value if token in ('--or-mark', '--xor-mark') else mask | value)
                    elif target != 'CONNMARK':
                        raise ValueError
                    recognized = True
                elif token == '--restore-mark':
                    if target != 'CONNMARK':
                        raise ValueError
                    used |= _u32(args[args.index('--nfmask') + 1]) if '--nfmask' in args else 0xffffffff
                    recognized = True
                elif token == '--save-mark':
                    if target != 'CONNMARK':
                        raise ValueError
                    recognized = True
                index += 1
            if not recognized:
                raise ValueError
        except (ValueError, IndexError):
            raise NetworkError('unsupported iptables mark state') from None
    return used


def _legacy_zones(text):
    zones = set()
    for line in text.splitlines():
        if '--zone' not in line:
            continue
        try:
            args = shlex.split(line)
            for index, option in enumerate(args):
                if option in ('--zone', '--zone-orig', '--zone-reply'):
                    zone = _u32(args[index + 1])
                    if zone > 65535:
                        raise ValueError
                    zones.add(zone)
                elif option.startswith('--zone'):
                    raise ValueError
        except (ValueError, IndexError):
            raise NetworkError('unsupported legacy conntrack zone state') from None
    return zones
