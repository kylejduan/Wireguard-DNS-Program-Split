"""Install reviewed build artifacts; preserve configurations and modified files."""
import hashlib
import json
import os
from pathlib import Path
import stat

from .config import parse_profile, parse_settings, settings_json


LAYOUT = {
    'wg-program-split.pyz': ('usr/lib/wg-program-split/wg-program-split.pyz', 0o644),
    'bpf-loader': ('usr/lib/wg-program-split/bpf-loader', 0o755),
    'classifier.bpf.o': ('usr/lib/wg-program-split/classifier.bpf.o', 0o644),
    'wg-program-split-guard.service': ('usr/lib/systemd/system/wg-program-split-guard.service', 0o644),
    'wg-program-split.service': ('usr/lib/systemd/system/wg-program-split.service', 0o644),
}
LAUNCHER = b'#!/bin/sh\nexec /usr/bin/python3 -I /usr/lib/wg-program-split/wg-program-split.pyz "$@"\n'
COMMAND = 'usr/bin/wg-program-split'
CONFIG = 'etc/wg-program-split'
MANIFEST = CONFIG + '/installation.json'
ALLOWED = {path for path, _ in LAYOUT.values()} | {COMMAND}


class InstallError(RuntimeError):
    pass


def _identity(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InstallError('installation file must be singly linked and regular')
        digest = hashlib.sha256()
        while block := os.read(fd, 65536):
            digest.update(block)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallError('installation file changed during inspection')
        return {'device': after.st_dev, 'inode': after.st_ino, 'owner': after.st_uid,
                'ctime_ns': after.st_ctime_ns, 'mode': stat.S_IMODE(after.st_mode), 'sha256': digest.hexdigest()}
    finally:
        os.close(fd)


def _directories(root, relative, created, *, create=True):
    current = root
    for component in Path(relative).parts:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                raise InstallError('installation directory is missing') from None
            current.mkdir(mode=0o700 if current == root / CONFIG else 0o755)
            created.append(current)
            info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise InstallError('installation directory is foreign, writable, or a symlink')
    if relative == CONFIG and stat.S_IMODE(current.stat().st_mode) != 0o700:
        raise InstallError('configuration directory must have mode 0700')


def _root(root):
    root = Path(root)
    if not root.is_absolute() or root != root.resolve() or root.is_symlink():
        raise InstallError('installation root must be an absolute resolved directory')
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise InstallError('installation root has unsafe ownership or permissions')
    if root == Path('/') and os.geteuid() != 0:
        raise InstallError('installation requires root')
    return root


def _create(path, content, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        remaining = memoryview(content)
        while remaining:
            wrote = os.write(fd, remaining)
            if wrote <= 0:
                raise InstallError('incomplete installation write')
            remaining = remaining[wrote:]
        os.fsync(fd)
    except BaseException:
        held = os.fstat(fd)
        live = path.lstat()
        if (live.st_dev, live.st_ino) == (held.st_dev, held.st_ino):
            path.unlink()
        raise
    finally:
        os.close(fd)
    return _identity(path)


def install(artifacts, profile_text, settings_text, *, root=Path('/')):
    """Install once without enabling services or changing live networking."""
    root = _root(root)
    parse_profile(profile_text)
    settings_text = settings_json(parse_settings(settings_text))
    payloads = {}
    artifacts = Path(artifacts)
    for name, (destination, mode) in LAYOUT.items():
        source = artifacts / name
        _identity(source)
        payloads[destination] = (source.read_bytes(), mode)
    payloads[COMMAND] = (LAUNCHER, 0o755)
    if (root / MANIFEST).exists() or (root / MANIFEST).is_symlink():
        raise InstallError('already installed; disable and uninstall before replacing this build')
    created_dirs, created_files, entries = [], [], {}
    try:
        for relative in ('usr/lib/wg-program-split', 'usr/lib/systemd/system', 'usr/bin', CONFIG):
            _directories(root, relative, created_dirs)
        for destination in payloads:
            if (root / destination).exists() or (root / destination).is_symlink():
                raise InstallError('refusing to overwrite an existing installation file')
        for name, content in (('profile.conf', profile_text), ('settings.json', settings_text)):
            path = root / CONFIG / name
            if path.exists() or path.is_symlink():
                existing = _identity(path)
                if (existing['owner'] != os.geteuid() or existing['mode'] != 0o600 or
                        path.read_bytes() != content.encode()):
                    raise InstallError('existing private configuration differs; it was preserved')
            else:
                identity = _create(path, content.encode(), 0o600)
                created_files.append((path, identity))
        for relative, (content, mode) in payloads.items():
            identity = _create(root / relative, content, mode)
            created_files.append((root / relative, identity))
            entries[relative] = identity
        manifest = {'schema_version': 1, 'files': entries}
        identity = _create(root / MANIFEST, (json.dumps(manifest, sort_keys=True) + '\n').encode(), 0o600)
        created_files.append((root / MANIFEST, identity))
        for directory in {path.parent for path, _ in created_files}:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return {'installed': sorted(entries), 'activated': False, 'configuration_retained': True}
    except BaseException:
        for path, identity in reversed(created_files):
            if path.exists() and _identity(path) == identity:
                path.unlink()
        for directory in reversed(created_dirs):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise


def _manifest(root):
    _directories(root, CONFIG, [], create=False)
    identity = _identity(root / MANIFEST)
    if identity['owner'] != os.geteuid() or identity['mode'] != 0o600:
        raise InstallError('invalid installation manifest ownership')
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise InstallError('duplicate installation manifest key')
            value[key] = item
        return value
    document = json.loads((root / MANIFEST).read_text(), object_pairs_hook=unique)
    if (not isinstance(document, dict) or set(document) != {'schema_version', 'files'} or
            type(document['schema_version']) is not int or document['schema_version'] != 1 or
            not isinstance(document['files'], dict) or set(document['files']) != ALLOWED):
        raise InstallError('invalid installation manifest')
    if _identity(root / MANIFEST) != identity:
        raise InstallError('installation manifest changed during inspection')
    return document, identity


def verify_units(*, root=Path('/')):
    """Prove the two installed unit files before controlling named services."""
    root = _root(root)
    document, _ = _manifest(root)
    units = ('wg-program-split-guard.service', 'wg-program-split.service')
    for unit in units:
        relative, _ = LAYOUT[unit]
        _directories(root, str(Path(relative).parent), [], create=False)
        if _identity(root / relative) != document['files'][relative]:
            raise InstallError('installed unit changed; refusing service control')
    return units


def uninstall(*, root=Path('/')):
    """Call only after controller.disable; retain private config and modified files."""
    root = _root(root)
    document, identity = _manifest(root)
    removed, retained, verified = [], [], []
    for relative, expected in document['files'].items():
        path = root / relative
        try:
            _directories(root, str(Path(relative).parent), [], create=False)
            try:
                actual = _identity(path)
            except FileNotFoundError:
                removed.append(relative)  # Resume exact already-removed entries.
                continue
            matches = actual == expected
        except (OSError, InstallError):
            matches = False
        if matches:
            verified.append((relative, expected))
        else:
            retained.append(relative)
    if retained:
        # Preserve a runnable CLI and its unit evidence for an operator retry.
        return {'removed': sorted(removed), 'retained': sorted(retained),
                'removal_deferred': True, 'configuration_retained': True}
    for relative, expected in verified:
        path = root / relative
        if _identity(path) != expected:
            raise InstallError('installation changed during removal')
        path.unlink()
        removed.append(relative)
    if not retained and _identity(root / MANIFEST) == identity:
        (root / MANIFEST).unlink()
    return {'removed': sorted(removed), 'retained': sorted(retained),
            'removal_deferred': False, 'configuration_retained': True}
