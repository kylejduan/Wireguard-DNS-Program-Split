# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded command execution and read-only parsing of routing, nftables,
iptables and WireGuard inventories."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import struct
import subprocess

from .errors import NetworkError
from .command import capture, stream


_TOOL_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
_IPTABLES_DUMPS = ('iptables-legacy-save', 'ip6tables-legacy-save', 'iptables-nft-save', 'ip6tables-nft-save')
_OPAQUE_MARK_EXTENSIONS = {'MARK', 'CONNMARK', 'CT', 'mark', 'connmark'}


def nft_generation():
    """This network namespace's nf_tables ruleset generation (NFT_MSG_GETGEN).

    Every committed nf_tables transaction advances it: nft and iptables-nft
    edits, flushes and deletions, in any table or family. The count restarts
    only if the nf_tables module is unloaded and loaded again, which gives its
    sysfs directory a new inode, so that inode is part of the result. Raises
    OSError or ValueError when it cannot be read.
    """
    try:
        module = os.stat('/sys/module/nf_tables').st_ino
    except FileNotFoundError:
        module = None  # Built in: never reloaded.
    netlink_netfilter, subsystem, getgen, newgen = 12, 10, 16, 15
    request = struct.pack('=IHHII', 20, subsystem << 8 | getgen, 1, 1, 0) + struct.pack('=BBH', 0, 0, 0)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, netlink_netfilter) as channel:
        channel.settimeout(2)
        channel.send(request)
        reply = channel.recv(65536)
    length, kind = struct.unpack_from('=IH', reply)
    if kind != subsystem << 8 | newgen or not 20 <= length <= len(reply):
        raise ValueError('no nf_tables generation reply')
    offset = 20
    while offset + 4 <= length:
        size, attribute = struct.unpack_from('=HH', reply, offset)
        if size < 4 or offset + size > length:
            break
        if attribute & 0x3fff == 1 and size == 8:  # NFTA_GEN_ID, big endian
            return module, struct.unpack_from('>I', reply, offset + 4)[0]
        offset += (size + 3) & ~3
    raise ValueError('nf_tables generation reply lacks its ID')


class RulesetListings:
    """nf_tables-backed listings reused while the ruleset generation is unchanged.

    A listing is kept only when the generation read before and after it is the
    same, so it is exactly the ruleset of that generation; a later equal
    generation means no transaction has committed since, and the identical
    text is returned without running the tool. Only counters and dynamic set
    contents change outside transactions, and no inventory decision reads
    them, with one exception: the kernel deletes an owner-bound table (flag
    "owner") when the netlink socket that owns it closes, without advancing
    the generation. So a listing is kept only once an nft listing of the same
    generation has shown no owner-bound table (one cannot appear without a new
    generation); while one exists, every listing runs the tool. Without a
    readable generation every listing runs.
    """
    NFT = ('nft', '-j', 'list', 'ruleset')
    COMMANDS = frozenset({NFT, ('iptables-nft-save',), ('ip6tables-nft-save',)})

    def __init__(self, generation=nft_generation):
        self.generation = generation
        self.entries = {}
        self.owner_free = None  # Generation whose nft listing had no owner-bound table.

    def __call__(self, argv, run):
        try:
            before = self.generation()
        except (OSError, ValueError):
            self.entries.clear()
            self.owner_free = None
            return run()
        cached = self.entries.get(argv)
        if cached is not None and cached[0] == before and self.owner_free == before:
            return cached[1]
        output = run()
        try:
            stable = self.generation() == before
        except (OSError, ValueError):
            stable = False
        if argv == self.NFT:
            self.owner_free = before if stable and not _owner_bound(output) else None
        # A listing taken while an owner-bound table may exist could still show
        # it after its silent deletion, so only owner-free listings are kept.
        if stable and self.owner_free == before:
            self.entries[argv] = (before, output)
        else:
            self.entries.pop(argv, None)
        return output


def _owner_bound(listing):
    """True unless LISTING is nft JSON whose tables carry no "owner" flag."""
    try:
        entries = json.loads(listing)['nftables']
        for entry in entries:
            table = entry.get('table') if isinstance(entry, dict) else None
            if isinstance(table, dict):
                flags = table.get('flags', [])
                if flags == 'owner' or (isinstance(flags, list) and 'owner' in flags):
                    return True
        return False
    except (ValueError, TypeError, KeyError, AttributeError):
        return True


_LISTINGS = RulesetListings()
# A legacy iptables dump prints exactly the tables named here; no file or no
# name means no legacy table exists and the dump would be empty.
_LEGACY_TABLES = {'iptables-legacy-save': '/proc/net/ip_tables_names',
                  'ip6tables-legacy-save': '/proc/net/ip6_tables_names'}


def _legacy_tables_absent(tool):
    try:
        with open(_LEGACY_TABLES[tool], 'rb') as names:
            return not names.read(4096).strip()
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _spawn(argv, input):
    try:
        return capture(tuple(argv), input=input.encode('utf-8') if input is not None else None, timeout=15)
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise NetworkError('network command failed, timed out or exceeded output limits; inspect effective state') from None


def run_command(argv, *, input=None):
    """Run fixed argv with a trusted executable search path, no shell, no logs."""
    if not argv or argv[0] not in {'ip', 'wg', 'nft', 'conntrack', 'sysctl', *_IPTABLES_DUMPS}:
        raise NetworkError('unsupported network command')
    argv = tuple(argv)
    if (len(argv) == 3 and argv[:2] == ('sysctl', '-n') and
            re.fullmatch(r'[a-z0-9_]+(?:\.[a-z0-9_]+)+', argv[2])):
        # A readback is the procfs file sysctl would print; no process is needed.
        try:
            with open('/proc/sys/' + argv[2].replace('.', '/'), 'rb') as file:
                return file.read(4096).decode('utf-8')
        except (OSError, UnicodeError):
            raise NetworkError('network command failed, timed out or exceeded output limits; inspect effective state') from None
    if input is None and argv in RulesetListings.COMMANDS:
        return _LISTINGS(argv, lambda: _spawn(argv, None))
    if input is None and argv[0] in _LEGACY_TABLES and len(argv) == 1 and _legacy_tables_absent(argv[0]):
        return ''
    return _spawn(argv, input)


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


class TableNames:
    """Routing table resolution for one network observation. The named-table
    configuration is read at most once, at the first nonbuiltin name, and a
    later observation starts afresh, so edits apply from the next check."""

    def __init__(self):
        self._named = None

    def __call__(self, value):
        if isinstance(value, str) and value in _BUILTIN_TABLES:
            return _BUILTIN_TABLES[value]
        if isinstance(value, str) and not re.fullmatch(r'0x[0-9a-fA-F]{1,8}|[0-9]{1,10}', value):
            if self._named is None:
                self._named = _named_tables()
            if value in self._named:
                return self._named[value]
            raise NetworkError('unknown named routing table')
        return _u32(value)


def _table(value, tables=None):
    return (TableNames() if tables is None else tables)(value)


def _has_mark(value):
    if isinstance(value, dict):
        return (isinstance(value.get('meta'), dict) and value['meta'].get('key') == 'mark' or
                any(_has_mark(v) for v in value.values()))
    return isinstance(value, list) and any(_has_mark(v) for v in value)


def _nft_usage(value):
    """Recognize constant masks/preserving writes; reject dynamic mark semantics.

    Accumulate once per inventory rather than allocating masks and sets for
    every JSON scalar. Every expression is still inspected, even after all
    mark bits are claimed: a later unsupported expression must fail closed.
    """
    mark = {'meta': {'key': 'mark'}}
    zone = {'ct': {'key': 'zone'}}
    used, zones = 0, set()
    pending = [value]
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
            continue
        if not isinstance(value, dict):
            continue
        if 'xt' in value and isinstance(value['xt'], dict):
            # Opaque iptables extensions are covered by the textual dumps.
            continue
        if 'mangle' in value and value['mangle'].get('key') == mark:
            output = value['mangle']['value']
            if type(output) is int:
                used |= 0xffffffff
                continue
            try:
                preserved, added = output['|']
                original, mask = preserved['&']
                if original != mark:
                    raise ValueError
                used |= ((~_u32(mask)) | _u32(added)) & 0xffffffff
            except (KeyError, TypeError, ValueError):
                raise NetworkError('unsupported nftables mark assignment') from None
            continue
        if 'match' in value and _has_mark(value['match']):
            item = value['match']
            left = item.get('left')
            if left == mark:
                _u32(item.get('right'))
                used |= 0xffffffff
            elif isinstance(left, dict) and '&' in left and len(left['&']) == 2 and left['&'][0] == mark:
                _u32(item.get('right'))
                used |= _u32(left['&'][1])
            else:
                raise NetworkError('unsupported nftables mark comparison')
            continue
        if 'mangle' in value and value['mangle'].get('key') == zone:
            number = _u32(value['mangle'].get('value'))
            if number > 65535:
                raise NetworkError('invalid conntrack zone')
            zones.add(number)
            continue
        if 'match' in value and value['match'].get('left') == zone:
            zones.add(_u32(value['match'].get('right')))
            continue
        if ((isinstance(value.get('meta'), dict) and value['meta'].get('key') == 'mark') or
                (isinstance(value.get('ct'), dict) and value['ct'].get('key') == 'zone')):
            raise NetworkError('unrecognized nftables mark or zone expression')
        pending.extend(value.values())
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


_CONNTRACK_LIST = ('conntrack', '-L', '-o', 'extended')
_ZONE_TOKEN = re.compile(rb'zone(?:-orig|-reply)?=([0-9]{1,5})')


class _ZoneScan:
    """Incremental flow-table parser: keeps only the bounded set of zone numbers
    (at most 65,535) and one partial line, discarding flow details as they stream."""
    LINE_MAXIMUM = 64 * 1024

    def __init__(self):
        self.zones, self.partial = set(), b''

    def feed(self, chunk):
        lines = (self.partial + chunk).split(b'\n')
        self.partial = lines.pop()
        if len(self.partial) > self.LINE_MAXIMUM:
            raise NetworkError('conntrack flow line exceeds its limit')
        for line in lines:
            self._line(line)

    def finish(self):
        self._line(self.partial)
        self.partial = b''
        return self.zones

    def _line(self, line):
        for token in line.split():
            if b'zone' in token:
                match = _ZONE_TOKEN.fullmatch(token)
                if not match:
                    raise NetworkError('unparseable conntrack zone inventory')
                number = int(match[1])
                if number > 65535:
                    raise NetworkError('invalid conntrack zone inventory')
                self.zones.add(number)


def conntrack_zones(runner, *, timeout=15):
    """Zones referenced by any live flow, from one listing under one deadline.

    The production runner streams the listing; a busy flow table is never held
    whole in memory. Substitute runners return the same listing as text.
    """
    scan = _ZoneScan()
    if runner is run_command:
        try:
            stream(_CONNTRACK_LIST, scan.feed, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            raise NetworkError('network command failed, timed out or exceeded output limits; inspect effective state') from None
    else:
        scan.feed(_call(runner, *_CONNTRACK_LIST).encode('utf-8', 'surrogateescape'))
    return scan.finish()
