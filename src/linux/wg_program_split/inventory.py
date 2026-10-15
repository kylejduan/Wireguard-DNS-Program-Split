# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded command execution and read-only parsing of routing, nftables,
iptables and WireGuard inventories."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess

from .errors import NetworkError
from .command import capture, stream


_TOOL_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
_IPTABLES_DUMPS = ('iptables-legacy-save', 'ip6tables-legacy-save', 'iptables-nft-save', 'ip6tables-nft-save')
_OPAQUE_MARK_EXTENSIONS = {'MARK', 'CONNMARK', 'CT', 'TPROXY', 'HMARK', 'IPMARK', 'SET', 'socket', 'mark', 'connmark'}
# Target extensions that never write the packet mark (skb->mark), checked
# against their kernel modules: verdicts, logging, NAT, conntrack templates,
# header and checksum mangling, priority (CLASSIFY), security marks (SECMARK,
# CONNSECMARK are skb->secmark), tracing and timers, and NFQUEUE/QUEUE, whose
# userspace verdict can set a mark: an administrator residual, see
# docs/linux.md. SET is listed but refused with --map-mark. MARK, CONNMARK and
# TPROXY are modelled separately; every other target is refused: IPMARK and
# HMARK write the mark, and TEE sends a clone of the packet (for included
# traffic, its plaintext) to another gateway.
_NON_MARK_TARGETS = frozenset({
    'ACCEPT', 'DROP', 'RETURN', 'QUEUE', 'REJECT', 'LOG', 'NFLOG', 'ULOG', 'MASQUERADE', 'SNAT', 'DNAT',
    'REDIRECT', 'NETMAP', 'DNPT', 'SNPT', 'CT', 'NOTRACK', 'TCPMSS', 'TCPOPTSTRIP', 'DSCP', 'TOS', 'ECN', 'TTL',
    'HL', 'CLASSIFY', 'CHECKSUM', 'SECMARK', 'CONNSECMARK', 'AUDIT', 'TRACE', 'SYNPROXY', 'IDLETIMER', 'LED',
    'RATEEST', 'NFQUEUE', 'SET'})


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


def _mark_write(output, mark):
    """Bits a `meta mark set` of the current mark and constants can change.

    mark | C sets C; mark ^ C flips C; mark & C clears the complement of C;
    (mark & M) | C and (mark & M) ^ C change the complement of M and C. Any
    other operand (another key, a map, a shift, a nested expression) raises.
    """
    if not isinstance(output, dict) or len(output) != 1:
        raise ValueError
    (operator, operands), = output.items()
    if operator not in ('|', '^', '&') or not isinstance(operands, list) or len(operands) != 2:
        raise ValueError
    left, constant = operands
    if type(constant) is not int:
        raise ValueError
    constant = _u32(constant)
    if left == mark:
        return (~constant) & 0xffffffff if operator == '&' else constant
    if operator == '&' or not isinstance(left, dict) or list(left) != ['&']:
        raise ValueError
    inner = left['&']
    if not isinstance(inner, list) or len(inner) != 2 or inner[0] != mark or type(inner[1]) is not int:
        raise ValueError
    return ((~_u32(inner[1])) | constant) & 0xffffffff


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
                used |= _mark_write(output, mark)
            except (KeyError, TypeError, ValueError, AttributeError, NetworkError):
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
        if 'mangle' in value and isinstance(value['mangle'], dict) and isinstance(value['mangle'].get('key'), dict) \
                and 'payload' in value['mangle']['key']:
            payload = value['mangle']['key']['payload']
            field = payload.get('field') if isinstance(payload, dict) else None
            if not isinstance(payload, dict) or 'base' in payload or field in ('saddr', 'daddr', 'sport', 'dport'):
                # A stateless address or port rewrite (or a raw payload write) can
                # move a packet past the owned DNS and routing guards unseen.
                what = (f"{payload.get('protocol')} {field}" if field else 'raw payload') if isinstance(payload, dict) else 'payload'
                raise NetworkError(f'foreign nftables rule rewrites {what} statelessly; refused as a conflict')
            continue  # Other header fields (DSCP, ECN, TTL) move nothing.
        for statement in ('dup', 'fwd'):
            if statement in value:
                # dup clones a packet to another address or device; fwd sends it
                # out another device (a netdev egress fwd on the tunnel device
                # would emit included plaintext). Either can leak included traffic.
                raise NetworkError(f'foreign nftables {statement} statement can copy or divert packets; '
                                   'refused as a conflict')
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
    if isinstance(xt, dict) and (xt.get('name') in _OPAQUE_MARK_EXTENSIONS or (
            xt.get('type') == 'target' and xt.get('name') not in _NON_MARK_TARGETS)):
        return True  # Read from the iptables-nft dump, which refuses unknown targets.
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


# Options each packet-mark-relevant target accepts, as iptables-save prints
# them; a target line with anything else cannot be modelled and is refused.
_MARK_TARGETS = {
    'MARK': {'--set-xmark', '--set-mark', '--and-mark', '--or-mark', '--xor-mark'},
    'CONNMARK': {'--set-xmark', '--set-mark', '--and-mark', '--or-mark', '--xor-mark', '--save-mark',
                 '--restore-mark', '--nfmask', '--ctmask', '--mask', '--left-shift-mark', '--right-shift-mark'},
    'TPROXY': {'--on-port', '--on-ip', '--tproxy-mark'},
}
_MARK_FLAGS = {'--save-mark', '--restore-mark'}
_MARK_OPERATIONS = ('--set-xmark', '--set-mark', '--and-mark', '--or-mark', '--xor-mark', '--save-mark', '--restore-mark')


def _target_bits(target, options):
    """Packet-mark bits one MARK, CONNMARK or TPROXY target can change."""
    if target == 'TPROXY':
        # skb->mark = (skb->mark & ~mask) ^ value
        if '--tproxy-mark' not in options:
            return 0
        value, mask = _split_mark(options['--tproxy-mark'])
        return value | mask
    operations = [name for name in _MARK_OPERATIONS if name in options]
    if len(operations) != 1:
        raise ValueError
    operation = operations[0]
    if target == 'MARK':
        # skb->mark = (skb->mark & ~mask) ^ value, every form included.
        if set(options) != {operation}:
            raise ValueError
        value, mask = _split_mark(options[operation])
        if operation == '--and-mark':
            return (~value) & 0xffffffff
        return value if operation in ('--or-mark', '--xor-mark') else mask | value
    if operation != '--restore-mark':
        return 0  # Every other CONNMARK operation writes the conntrack mark only.
    # skb->mark = (skb->mark & ~nfmask) ^ shift(ct->mark & ctmask): the XOR can
    # set any bit of the shifted ctmask, inside nfmask or not. Both masks
    # default to every bit; --mask sets both.
    if '--mask' in options and ('--nfmask' in options or '--ctmask' in options):
        raise ValueError
    default = options.get('--mask', '0xffffffff')
    nfmask, ctmask = _u32(options.get('--nfmask', default)), _u32(options.get('--ctmask', default))
    if '--left-shift-mark' in options and '--right-shift-mark' in options:
        raise ValueError
    for direction in ('--left-shift-mark', '--right-shift-mark'):
        if direction in options:
            bits = int(options[direction], 10)
            if not 0 <= bits <= 31:
                raise ValueError
            ctmask = (ctmask << bits if direction == '--left-shift-mark' else ctmask >> bits) & 0xffffffff
    return nfmask | ctmask


# Built-in verdicts take no options and write no mark.
_VERDICTS = {'ACCEPT', 'DROP', 'RETURN', 'QUEUE'}


def _iptables_records(text):
    """(token, quoted) lists of each record of an iptables-save dump.

    libxtables prints a value that needs quoting inside double quotes with
    `"`, `\\` and `'` escaped by a backslash; a quoted value (a comment, for
    example) may contain a real newline, so records end only at a newline
    outside quotes. A token with any quoted part is marked quoted: it is a
    value, never an option, module or jump keyword. Lines beginning with # are
    skipped whole. An unterminated quote raises ValueError.
    """
    record, token, quoted, escaped, started, comment, was_quoted = [], [], False, False, False, False, False
    for char in text + '\n':
        if comment:
            comment = char != '\n'
            continue
        if quoted:
            if escaped:
                token.append(char)
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
            else:
                token.append(char)
            continue
        if char == '#' and not record and not started:
            comment = True
            continue
        if char in ' \t\r\n':
            if started:
                record.append((''.join(token), was_quoted))
                token, started, was_quoted = [], False, False
            if char == '\n' and record:
                yield record
                record = []
            continue
        started = True
        if char == '"':
            quoted = was_quoted = True
        else:
            token.append(char)
    if quoted:
        raise ValueError('unterminated quoted iptables value')


# Built-in verdicts take no options and write no mark.
_VERDICTS = {'ACCEPT', 'DROP', 'RETURN', 'QUEUE'}
_JUMPS = ('-j', '--jump', '-g', '--goto')


def _rule(record, chains):
    """Split one rule into (match tokens, target or None, target tokens, quoted flags).

    Only an unquoted keyword is structural. The target is the rule's single
    unquoted -j or -g; a second one means an unquoted value could be either,
    so argument boundaries cannot be established and the rule is refused.
    Returns target None for a jump to a declared chain or a verdict.
    """
    tokens = [value for value, _ in record]
    quoted = [flag for _, flag in record]
    if tokens[0] not in ('-A', '-I') or len(tokens) < 2 or quoted[0] or quoted[1]:
        raise ValueError
    jumps = [index for index in range(2, len(tokens)) if tokens[index] in _JUMPS and not quoted[index]]
    if len(jumps) > 1:
        raise ValueError
    if not jumps:
        return tokens[2:], quoted[2:], None, []
    index = jumps[0]
    if index + 1 >= len(tokens) or quoted[index + 1]:
        raise ValueError
    name, rest = tokens[index + 1], list(zip(tokens[index + 2:], quoted[index + 2:]))
    if tokens[index] in ('-g', '--goto') or name in chains or name in _VERDICTS:
        if rest:
            raise ValueError  # A chain jump or verdict takes no options.
        name = None
    return tokens[2:index], quoted[2:index], name, rest


def _legacy_mask(text):
    """Packet-mark bits an iptables dump can read or write.

    Each rule is parsed by structure from unquoted keywords only: chain
    declarations and comments are skipped, a jump to a declared chain is not a
    target extension, and only the target extension's own options are read as
    target options. The mark match (printed as -m mark [!] --mark V/M) reads its
    value and mask. MARK writes, and TPROXY with --tproxy-mark writes, the bits
    of their mask and value. CONNMARK --restore-mark writes --nfmask and the
    (shifted) --ctmask; every other CONNMARK operation and the connmark match
    touch the conntrack mark only. Any other target must be on the allowlist of
    targets that never write the mark (_NON_MARK_TARGETS): IPMARK, HMARK and
    unknown targets are refused by name, as are SET --map-mark (its marks live
    in mutable ipset entries) and socket --restore-skmark, and so is
    any rule whose argument boundaries are ambiguous (an unquoted --mark away
    from its module, or more than one unquoted jump). Other targets' arguments
    are not interpreted and may repeat values.
    """
    used = 0
    chains = set()
    try:
        records = list(_iptables_records(text))
    except ValueError:
        raise NetworkError('unsupported iptables mark state') from None
    for record in records:
        first = record[0][0]
        if first.startswith('*') and not record[0][1]:
            chains = set()  # A new table; its chains are declared next.
            continue
        if first.startswith(':') and not record[0][1]:
            chains.add(first[1:])
            continue
        if [token for token, _ in record] == ['COMMIT']:
            continue
        try:
            matches, quoted, target, rest = _rule(record, chains)
            for index, token in enumerate(matches):
                if quoted[index]:
                    continue
                if token == '--mark':
                    # Printed as "-m mark --mark V" or "-m mark ! --mark V".
                    start = index - 3 if index >= 3 and matches[index - 1] == '!' else index - 2
                    if (start < 0 or matches[start] not in ('-m', '--match') or quoted[start] or
                            matches[start + 1] not in ('mark', 'connmark') or index + 1 >= len(matches)):
                        raise ValueError
                    value, mask = _split_mark(matches[index + 1])
                    if matches[start + 1] == 'mark':
                        used |= value | mask
                elif token == '--restore-skmark':
                    raise ValueError  # socket: the one match that writes the packet mark.
                elif token in _MARK_OPERATIONS or token in ('--nfmask', '--ctmask', '--tproxy-mark',
                                                            '--left-shift-mark', '--right-shift-mark'):
                    raise ValueError  # A mark target option outside its target.
            if target is not None and target not in _MARK_TARGETS and target not in _NON_MARK_TARGETS:
                # IPMARK, HMARK and any target not known to leave the mark alone.
                raise NetworkError(f'iptables target {target} may write the packet mark and is not '
                                   'modelled; refused as a conflict')
            if target in _MARK_TARGETS:
                options = {}
                index = 0
                while index < len(rest):
                    token, is_quoted = rest[index]
                    if is_quoted or token not in _MARK_TARGETS[target] or token in options:
                        raise ValueError
                    if token in _MARK_FLAGS:
                        options[token] = True
                        index += 1
                    else:
                        value, value_quoted = rest[index + 1]
                        if value_quoted:
                            raise ValueError
                        options[token] = value
                        index += 2
                used |= _target_bits(target, options)
            elif target == 'SET' and ('--map-mark', False) in rest:
                raise ValueError  # Only SET, of the other targets, writes the packet mark.
        except (ValueError, IndexError):
            raise NetworkError('unsupported iptables mark state') from None
    return used


def _legacy_zones(text):
    """Conntrack zones the CT target assigns in an iptables dump; only the CT
    target extension's own unquoted options are read."""
    zones, chains = set(), set()
    try:
        records = list(_iptables_records(text))
    except ValueError:
        raise NetworkError('unsupported legacy conntrack zone state') from None
    for record in records:
        first = record[0][0]
        if first.startswith('*') and not record[0][1]:
            chains = set()
            continue
        if first.startswith(':') and not record[0][1]:
            chains.add(first[1:])
            continue
        if [token for token, _ in record] == ['COMMIT']:
            continue
        try:
            _, _, target, rest = _rule(record, chains)
            if target != 'CT':
                continue
            index = 0
            while index < len(rest):
                option, is_quoted = rest[index]
                if not is_quoted and option in ('--zone', '--zone-orig', '--zone-reply'):
                    value, value_quoted = rest[index + 1]
                    zone = _u32(value)
                    if value_quoted or zone > 65535:
                        raise ValueError  # Also "mark": a zone taken from the packet mark.
                    zones.add(zone)
                    index += 2
                    continue
                if not is_quoted and option.startswith('--zone'):
                    raise ValueError
                index += 1
        except (ValueError, IndexError, NetworkError):
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
