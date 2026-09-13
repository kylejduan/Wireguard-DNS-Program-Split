"""Private state files, exclusive acquisition, and durable ownership receipts.

Receipts are evidence of an attempt, not proof of effective network ownership.
Callers must compare recorded and live identities before mutating live resources.
No network action or automatic recovery/deletion is performed here.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid


CONFIG_ROOT = Path('/etc/wg-program-split')
STATE_ROOT = Path('/run/wg-program-split')
# A later wg adapter must create exclusive transient key/config files here:
# the target AppArmor policy disallows the attempted stdin configuration path.
WIREGUARD_PRIVATE_ROOT = Path('/etc/wireguard')
_RECEIPT = 'receipt.json'
_LOCK = '.lock'
_MAX_RECEIPT = 1024 * 1024
_RESOURCE_KINDS = {'interface', 'route', 'rule', 'nft_table', 'conntrack_zone',
                   'bpf_link', 'bpf_map', 'process', 'sysctl',
                   'private_file', 'private_directory'}


class OwnershipError(RuntimeError):
    """Unproved ownership or failed state operation; no input contents echoed."""


@dataclass(frozen=True)
class FileIdentity:
    name: str
    device: int
    inode: int
    ctime_ns: int
    size: int
    sha256: str
    owner_uid: int
    mode: int


@dataclass(frozen=True)
class ResourceIdentity:
    kind: str
    name: str
    identity: dict


@dataclass(frozen=True)
class Receipt:
    schema_version: int
    attempt_id: str
    boot_id: str
    files: tuple[FileIdentity, ...] = ()
    resources: tuple[ResourceIdentity, ...] = ()


def _name(name: str) -> None:
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', name) or
            name in ('.', '..')):
        raise OwnershipError('state file requires a single safe basename')


def _directory(fd: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise OwnershipError('state directory is not private')
    return info


def open_private_dir(path, *, create: bool = False, owner_uid: int = 0) -> int:
    """Open without symlink traversal; create only the final component if asked.

    Ancestors must belong to root/owner_uid and must not be group/other writable.
    The leaf must be owned by owner_uid with mode exactly 0700. Existing paths
    are never repaired, chmodded, or adopted based only on their names.
    """
    text = os.fspath(path)
    if (not isinstance(text, str) or not text.startswith('/') or '\x00' in text or
            type(owner_uid) is not int or owner_uid < 0 or
            any(p in ('', '.', '..') for p in text.split('/')[1:])):
        raise OwnershipError('private directory requires an absolute normal path')
    fd = -1
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = text.split('/')[1:]
        for index, part in enumerate(parts):
            parent = os.fstat(fd)
            if parent.st_uid not in (0, owner_uid) or parent.st_mode & 0o022:
                raise OwnershipError('private directory has an unsafe ancestor')
            last = index == len(parts) - 1
            if last and create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = _directory(fd)
        if leaf.st_uid != owner_uid:
            raise OwnershipError('private directory has a foreign owner')
        return fd
    except (OSError, ValueError):
        if fd >= 0:
            os.close(fd)
        raise OwnershipError('cannot open a verified private directory') from None
    except BaseException:
        if fd >= 0:
            os.close(fd)
        raise


def _regular(fd: int, directory: int) -> os.stat_result:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != _directory(directory).st_uid or stat.S_IMODE(info.st_mode) != 0o600):
        raise OwnershipError('state file is not a private singly linked owned regular file')
    return info


def _same_file(left, right) -> bool:
    return (left.st_dev, left.st_ino, left.st_ctime_ns, left.st_mtime_ns, left.st_size) == (
        right.st_dev, right.st_ino, right.st_ctime_ns, right.st_mtime_ns, right.st_size)


def _open_file(directory: int, name: str) -> int:
    _name(name)
    _directory(directory)
    return os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)


def file_identity(directory: int, name: str) -> FileIdentity:
    """Read exact inode/ctime/hash identity; this does not claim birth ownership."""
    fd = -1
    try:
        fd = _open_file(directory, name)
        before = _regular(fd, directory)
        digest = hashlib.sha256()
        while chunk := os.read(fd, 65536):
            digest.update(chunk)
        after = _regular(fd, directory)
        if not _same_file(before, after):
            raise OwnershipError('state file changed during inspection')
        return FileIdentity(name, after.st_dev, after.st_ino, after.st_ctime_ns,
                            after.st_size, digest.hexdigest(), after.st_uid, 0o600)
    except OSError:
        raise OwnershipError('cannot inspect owned file identity') from None
    finally:
        if fd >= 0:
            os.close(fd)


def verify_file(directory: int, name: str, expected: FileIdentity) -> None:
    if not isinstance(expected, FileIdentity) or file_identity(directory, name) != expected:
        raise OwnershipError('live file does not match the recorded ownership identity')


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OwnershipError('incomplete state file write')
        view = view[written:]


def _unlink_if_same(directory: int, name: str, fd: int) -> None:
    """Failure cleanup is limited to the inode exclusively created by this call."""
    try:
        live = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    held = os.fstat(fd)
    if (live.st_dev, live.st_ino) != (held.st_dev, held.st_ino):
        raise OwnershipError('refusing cleanup of a replaced state file')
    os.unlink(name, dir_fd=directory)


def create_owned_file(directory: int, name: str, content: bytes) -> FileIdentity:
    """Create with O_EXCL, fsync, and capture birth evidence; never overwrite.

    Record the returned identity in the current attempt's receipt immediately.
    An identity reconstructed by reading an existing file is not this acquisition.
    """
    _name(name)
    _directory(directory)
    if name in (_LOCK, _RECEIPT) or not isinstance(content, bytes):
        raise OwnershipError('invalid owned file acquisition')
    fd = -1
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        os.fchmod(fd, 0o600)
        _write_all(fd, content)
        os.fsync(fd)
        _regular(fd, directory)
        os.fsync(directory)
        identity = file_identity(directory, name)
        if (identity.device, identity.inode) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
            raise OwnershipError('owned file was replaced during acquisition')
        return identity
    except (OSError, OwnershipError):
        if fd >= 0:
            _unlink_if_same(directory, name, fd)
        raise OwnershipError('owned file acquisition failed') from None
    finally:
        if fd >= 0:
            os.close(fd)


@contextmanager
def locked_state(path=STATE_ROOT, *, owner_uid: int = 0, timeout: float = 0):
    """Exclusive flock on a verified FD; optional bounded management serialization."""
    if type(timeout) not in (int, float) or not 0 <= timeout <= 60:
        raise OwnershipError('invalid state lock timeout')
    directory = open_private_dir(path, owner_uid=owner_uid)
    fd = -1
    try:
        try:
            fd = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            os.fsync(directory)
        except FileExistsError:
            fd = os.open(_LOCK, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
        _regular(fd, directory)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OwnershipError('another management operation holds the state lock') from None
                time.sleep(min(0.025, remaining))
        held, live = os.fstat(fd), os.stat(_LOCK, dir_fd=directory, follow_symlinks=False)
        if (held.st_dev, held.st_ino) != (live.st_dev, live.st_ino):
            raise OwnershipError('state lock was replaced')
        yield directory
    except OSError:
        raise OwnershipError('cannot acquire or use the owned state lock') from None
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory)


def _uuid(value) -> str:
    if not isinstance(value, str):
        raise OwnershipError('receipt requires canonical nonzero UUID identities')
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise OwnershipError('receipt requires canonical nonzero UUID identities') from None
    if str(parsed) != value or not parsed.int:
        raise OwnershipError('receipt requires canonical nonzero UUID identities')
    return value


def current_boot_id() -> str:
    try:
        return _uuid(Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    except OSError:
        raise OwnershipError('cannot determine current boot identity') from None


def new_receipt(*, boot_id: str | None = None) -> Receipt:
    return Receipt(1, str(uuid.uuid4()), _uuid(boot_id) if boot_id is not None else current_boot_id())


def validate_receipt(receipt: Receipt, *, boot_id: str, attempt_id: str) -> None:
    _decode_receipt(asdict(receipt))
    if receipt.boot_id != _uuid(boot_id) or receipt.attempt_id != _uuid(attempt_id):
        raise OwnershipError('receipt belongs to another boot or acquisition attempt')


def verify_resource(receipt: Receipt, kind: str, name: str, live_identity: dict, *,
                    boot_id: str, attempt_id: str) -> None:
    """Compare a caller-observed live identity with this boot/attempt's record.

    The network adapter supplies complete observed attributes; same-name or
    partial status is insufficient. This helper does not discover live state.
    """
    validate_receipt(receipt, boot_id=boot_id, attempt_id=attempt_id)
    if not isinstance(live_identity, dict) or not live_identity:
        raise OwnershipError('unsupported live resource identity')
    _json_identity(live_identity)
    for resource in receipt.resources:
        if (resource.kind == kind and resource.name == name and
                _json_text(resource.identity) == _json_text(live_identity)):
            return
    raise OwnershipError('live resource does not match the recorded ownership identity')


def _json_identity(value, depth=0):
    if depth > 8:
        raise OwnershipError('resource identity is too deeply nested')
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, str) and len(value) <= 4096:
        return
    if isinstance(value, list) and len(value) <= 1024:
        for item in value:
            _json_identity(item, depth + 1)
        return
    if isinstance(value, dict) and len(value) <= 128:
        for key, item in value.items():
            if (not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', key) or
                    key.lower().replace('_', '').replace('-', '') in
                    {'privatekey', 'presharedkey', 'profile', 'profiletext'}):
                raise OwnershipError('unsupported resource identity field')
            _json_identity(item, depth + 1)
        return
    raise OwnershipError('unsupported resource identity value')


def _json_text(value) -> str:
    """Canonical JSON equality retains distinctions such as true versus 1."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _decode_receipt(data) -> Receipt:
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'attempt_id', 'boot_id', 'files', 'resources'} or
            type(data['schema_version']) is not int or data['schema_version'] != 1):
        raise OwnershipError('unsupported receipt schema')
    attempt, boot = _uuid(data['attempt_id']), _uuid(data['boot_id'])
    files, resources = [], []
    if any(not isinstance(data[key], (list, tuple)) or len(data[key]) > 4096 for key in ('files', 'resources')):
        raise OwnershipError('unsupported receipt inventory')
    for entry in data['files']:
        if not isinstance(entry, dict) or set(entry) != set(FileIdentity.__dataclass_fields__):
            raise OwnershipError('unsupported file ownership identity')
        _name(entry['name'])
        for key in ('device', 'inode', 'ctime_ns', 'size', 'owner_uid', 'mode'):
            if type(entry[key]) is not int or entry[key] < 0:
                raise OwnershipError('invalid file ownership metadata')
        if (not entry['inode'] or not entry['ctime_ns'] or entry['mode'] != 0o600 or
                not isinstance(entry['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', entry['sha256'])):
            raise OwnershipError('invalid file ownership metadata')
        files.append(FileIdentity(**entry))
    for entry in data['resources']:
        if (not isinstance(entry, dict) or set(entry) != {'kind', 'name', 'identity'} or
                not isinstance(entry['kind'], str) or entry['kind'] not in _RESOURCE_KINDS or
                not isinstance(entry['name'], str) or not 1 <= len(entry['name']) <= 256 or
                any(ord(c) < 32 for c in entry['name']) or not isinstance(entry['identity'], dict) or
                not entry['identity']):
            raise OwnershipError('unsupported resource ownership identity')
        _json_identity(entry['identity'])
        resources.append(ResourceIdentity(**entry))
    if (len({f.name for f in files}) != len(files) or
            len({(r.kind, r.name) for r in resources}) != len(resources)):
        raise OwnershipError('receipt has duplicate resource identities')
    return Receipt(1, attempt, boot, tuple(files), tuple(resources))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OwnershipError('receipt contains duplicate JSON fields')
        result[key] = value
    return result


def _reject_constant(_value):
    raise OwnershipError('receipt contains an invalid JSON constant')


def read_receipt(directory: int) -> Receipt:
    fd = -1
    try:
        fd = _open_file(directory, _RECEIPT)
        before = _regular(fd, directory)
        if before.st_size > _MAX_RECEIPT:
            raise OwnershipError('receipt is too large')
        chunks, size = [], 0
        while chunk := os.read(fd, min(65536, _MAX_RECEIPT + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_RECEIPT:
                raise OwnershipError('receipt is too large')
        if not _same_file(before, _regular(fd, directory)):
            raise OwnershipError('receipt changed during inspection')
        data = json.loads(b''.join(chunks), object_pairs_hook=_pairs, parse_constant=_reject_constant)
        return _decode_receipt(data)
    except (OSError, ValueError, RecursionError):
        raise OwnershipError('cannot read a valid owned receipt') from None
    finally:
        if fd >= 0:
            os.close(fd)


def write_receipt(directory: int, receipt: Receipt, *, expected: Receipt | None = None) -> None:
    """Publish under locked_state: O_EXCL birth or exact expected-receipt update.

    Each file and parent directory is fsynced. An error after replacement/fsync
    can mean publication occurred: re-read before deciding recovery actions.
    """
    _directory(directory)
    if not isinstance(receipt, Receipt):
        raise OwnershipError('unsupported receipt value')
    data = asdict(receipt)
    _decode_receipt(data)
    content = (_json_text(data) + '\n').encode()
    if len(content) > _MAX_RECEIPT:
        raise OwnershipError('receipt is too large')
    if expected is not None:
        _decode_receipt(asdict(expected))
        validate_receipt(receipt, boot_id=expected.boot_id, attempt_id=expected.attempt_id)
        if _json_text(asdict(read_receipt(directory))) != _json_text(asdict(expected)):
            raise OwnershipError('receipt changed or belongs to another attempt')
    temporary = '.receipt-' + uuid.uuid4().hex
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        os.fchmod(fd, 0o600)
        _write_all(fd, content)
        os.fsync(fd)
        if expected is None:
            # link creates the destination atomically without replacing any file.
            os.link(temporary, _RECEIPT, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        else:
            os.replace(temporary, _RECEIPT, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError:
        raise OwnershipError('receipt publication failed; inspect current receipt before recovery') from None
    finally:
        if fd >= 0:
            try:
                _unlink_if_same(directory, temporary, fd)
            finally:
                os.close(fd)
