"""Strict profile/policy parsing without executing configuration or executables."""
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct


class ConfigError(ValueError):
    """Invalid configuration; diagnostics never reproduce profile input."""


@dataclass(frozen=True)
class Profile:
    address: str
    resolver: str
    endpoint_host: str
    endpoint_port: int
    private_key: str = field(repr=False)
    public_key: str = field(repr=False)
    preshared_key: str | None = field(default=None, repr=False)
    mtu: int = 1420
    persistent_keepalive: int = 0


@dataclass(frozen=True)
class Settings:
    schema_version: int
    included_executables: tuple[str, ...]


def _key(value: str) -> str:
    try:
        decoded = b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise ConfigError('profile contains an invalid key') from None
    if len(decoded) != 32 or not any(decoded) or b64encode(decoded).decode() != value:
        raise ConfigError('profile contains an invalid key')
    return value


def _ipv4(value: str) -> str:
    try:
        addr = IPv4Address(value)
    except (ValueError, TypeError):
        raise ConfigError('profile requires literal unicast IPv4 addresses') from None
    if (addr.is_unspecified or addr.is_loopback or addr.is_multicast or
            addr.is_link_local or addr.is_reserved or int(addr) >> 24 == 0):
        raise ConfigError('profile contains an unsafe IPv4 address')
    return str(addr)


def _number(value: str, low: int, high: int) -> int:
    if not re.fullmatch(r'[0-9]{1,5}', value):
        raise ConfigError('profile contains an invalid numeric field')
    number = int(value)
    if not low <= number <= high:
        raise ConfigError('profile numeric field is out of range')
    return number


def parse_profile(text: str) -> Profile:
    """Accept one IPv4 Interface and full-tunnel Peer, with no wg-quick actions.

    MTU is restricted to 576..65535. Keepalive defaults to WireGuard's disabled
    value 0, rather than introducing periodic traffic absent from the profile.
    Input must fit the runtime reader's 65536-byte UTF-8 limit.
    """
    if not isinstance(text, str) or len(text) > 65536 or '\x00' in text:
        raise ConfigError('invalid profile input')
    try:
        encoded_size = len(text.encode('utf-8'))
    except UnicodeError:
        raise ConfigError('profile input must be valid UTF-8') from None
    if encoded_size > 65536:
        raise ConfigError('profile input exceeds the byte limit')
    allowed = {'Interface': {'PrivateKey', 'Address', 'DNS', 'MTU'},
               'Peer': {'PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive'}}
    sections: dict[str, dict[str, str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('['):
            if line not in ('[Interface]', '[Peer]'):
                raise ConfigError('profile contains an unsupported section')
            current = line[1:-1]
            if current in sections:
                raise ConfigError('profile contains a duplicate section')
            sections[current] = {}
            continue
        if current is None or '=' not in line:
            raise ConfigError('invalid profile syntax')
        name, value = (part.strip() for part in line.split('=', 1))
        if name not in allowed[current] or name in sections[current] or not value:
            raise ConfigError('profile contains an unknown, duplicate or empty field')
        sections[current][name] = value
    interface, peer = sections.get('Interface', {}), sections.get('Peer', {})
    if not {'PrivateKey', 'Address', 'DNS'} <= interface.keys() or not {
            'PublicKey', 'AllowedIPs', 'Endpoint'} <= peer.keys():
        raise ConfigError('profile is missing a required field')
    if peer['AllowedIPs'] != '0.0.0.0/0':
        raise ConfigError('profile must contain exactly the full IPv4 AllowedIPs route')
    try:
        if '/' not in interface['Address']:
            raise ValueError
        address = IPv4Interface(interface['Address'])
    except ValueError:
        raise ConfigError('profile requires one IPv4 address with a prefix') from None
    _ipv4(str(address.ip))
    if address.network.prefixlen < 31 and address.ip in (
            address.network.network_address, address.network.broadcast_address):
        raise ConfigError('profile interface address is not a usable host address')
    endpoint = peer['Endpoint'].split(':')
    if len(endpoint) != 2:
        raise ConfigError('profile requires a numeric IPv4 endpoint and port')
    return Profile(address=str(address), resolver=_ipv4(interface['DNS']),
                   endpoint_host=_ipv4(endpoint[0]), endpoint_port=_number(endpoint[1], 1, 65535),
                   private_key=_key(interface['PrivateKey']), public_key=_key(peer['PublicKey']),
                   preshared_key=_key(peer['PresharedKey']) if 'PresharedKey' in peer else None,
                   mtu=_number(interface.get('MTU', '1420'), 576, 65535),
                   persistent_keepalive=_number(peer.get('PersistentKeepalive', '0'), 0, 65535))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError('settings contain a duplicate field')
        result[key] = value
    return result


def _reject_constant(_value):
    raise ConfigError('settings contain an invalid JSON constant')


def _path_input(value: str) -> None:
    if not isinstance(value, str) or not value.startswith('/') or '\x00' in value:
        raise ConfigError('executable path must be absolute and fit the classifier ABI')
    try:
        length = len(os.fsencode(value))
    except UnicodeError:
        raise ConfigError('executable path has an invalid filesystem encoding') from None
    if length >= 4096:
        raise ConfigError('executable path must fit the classifier ABI')


def policy_path(path: str) -> str:
    """Validate the exact stored deletion key, without following or opening it."""
    _path_input(path)
    if path == '/' or path.startswith('//') or str(Path(path)) != path or any(
            p in ('.', '..') for p in path.split('/')[1:]):
        raise ConfigError('deletion requires an exact canonical policy key')
    return path


def canonical_executable(path: str) -> str:
    """Resolve original symlink/.. semantics, then inspect a native ELF header."""
    _path_input(path)
    try:
        canonical = str(Path(path).resolve(strict=True))
        policy_path(canonical)
        fd = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise ConfigError('enrollment requires an executable regular ELF file')
            header = os.read(fd, 64)
        finally:
            os.close(fd)
    except (OSError, RuntimeError, ValueError):
        raise ConfigError('cannot enroll executable path') from None
    machine = {'x86_64': 62, 'aarch64': 183}.get(platform.machine())
    if (machine is None or len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or
            struct.unpack_from('<H', header, 16)[0] not in (2, 3) or
            struct.unpack_from('<H', header, 18)[0] != machine):
        raise ConfigError('enrollment requires a native ELF64 little-endian executable; scripts use their interpreter')
    return canonical


def _parse_settings(text: str, resolve) -> Settings:
    # Enough room for 1024 ABI-sized paths even when JSON escapes every byte.
    if not isinstance(text, str) or len(text) > 32 * 1024 * 1024:
        raise ConfigError('invalid settings input')
    try:
        data = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ConfigError('invalid settings JSON') from None
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'included_executables'} or
            type(data['schema_version']) is not int or data['schema_version'] != 1 or
            not isinstance(data['included_executables'], list) or len(data['included_executables']) > 1024):
        raise ConfigError('unsupported settings schema')
    paths = tuple(resolve(path) for path in data['included_executables'])
    if len(set(paths)) != len(paths):
        raise ConfigError('settings contain duplicate canonical executable paths')
    return Settings(1, tuple(sorted(paths)))


def parse_settings(text: str) -> Settings:
    """Import/enroll paths by resolving and inspecting their current executables."""
    return _parse_settings(text, canonical_executable)


def parse_policy(text: str) -> Settings:
    """Load trusted stored keys for boot/recovery, without filesystem resolution.

    A missing/replaced image must not silently disappear from installed policy.
    The caller must validate the policy file's root ownership before calling.
    """
    return _parse_settings(text, policy_path)


def settings_json(settings: Settings) -> str:
    """Serialize stored policy keys without re-resolving replaced/deleted images."""
    if (not isinstance(settings, Settings) or type(settings.schema_version) is not int or
            settings.schema_version != 1 or not isinstance(settings.included_executables, tuple) or
            len(settings.included_executables) > 1024):
        raise ConfigError('unsupported settings schema')
    paths = tuple(policy_path(path) for path in settings.included_executables)
    if len(set(paths)) != len(paths):
        raise ConfigError('settings contain duplicate policy keys')
    return json.dumps({'schema_version': 1, 'included_executables': sorted(paths)},
                      sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
