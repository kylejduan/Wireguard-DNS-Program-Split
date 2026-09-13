"""Serialized lifecycle with pinned protection and a durable policy-edit journal.

The controller owns controller.json; Network exclusively owns receipt.json.
No exception handler tears down networking or pinned enforcement.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import threading
import time
import uuid

from . import ownership as own
from .config import (Settings, canonical_executable, parse_policy, parse_profile,
                     policy_path, settings_json)
from .network import Allocation, Network, allocate, inspect
from .preflight import (ControllerError, NativeGuard, check_host, process_snapshot,
                        read_private, readiness_probe, restart_audit)


_JOURNAL_MAX_BYTES = 80 * 1024 * 1024
_RESTART_DETAIL_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class Paths:
    config: Path = Path('/etc/wg-program-split')
    state: Path = Path('/run/wg-program-split')
    pins: Path = Path('/sys/fs/bpf/wg_program_split')
    artifacts: Path = Path('/usr/lib/wg-program-split')


def _present(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False)


def _same(a, b):
    return _json(a) == _json(b)


def _replace(directory, name, content, expected):
    """Fsync publication under the state lock; reject external file replacement."""
    temporary = '.publish-' + uuid.uuid4().hex
    identity = own.create_owned_file(directory, temporary, content.encode('utf-8'))
    try:
        if expected is None:
            # link supplies no-replace publication, unlike rename.
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        else:
            own.verify_file(directory, name, expected)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        return own.file_identity(directory, name)
    finally:
        if _present(directory, temporary):
            own.verify_file(directory, temporary, identity)
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)


class Controller:
    def __init__(self, *, paths=Paths(), owner_uid=0, kernel=None,
                 network_factory=Network, host_check=check_host,
                 select_allocation=None, probe=None, processes=process_snapshot):
        self.paths, self.owner_uid = paths, owner_uid
        self.kernel = kernel or NativeGuard(paths.artifacts, paths.pins)
        self.network_factory, self.host_check = network_factory, host_check
        self.select_allocation = select_allocation or (lambda profile: allocate(inspect(profile, require_underlay=False)))
        self.probe = probe or (lambda profile, allocation: readiness_probe(profile, allocation, self.kernel))
        self.processes = processes

    @contextmanager
    def _locked(self, *, create=True):
        fd = own.open_private_dir(self.paths.state, create=create, owner_uid=self.owner_uid)
        os.close(fd)
        with own.locked_state(self.paths.state, owner_uid=self.owner_uid, timeout=30) as state:
            config = own.open_private_dir(self.paths.config, owner_uid=self.owner_uid)
            try:
                yield state, config
            finally:
                os.close(config)

    def _inputs(self, config):
        raw, _ = read_private(config, 'profile.conf', 65536)
        policy, identity = read_private(config, 'settings.json', 32 * 1024 * 1024)
        keys = list(parse_policy(policy).included_executables)
        if str(self.paths.artifacts / 'bpf-loader') in keys:
            raise ControllerError('the management probe executable cannot be enrolled')
        return parse_profile(raw), hashlib.sha256(raw.encode()).hexdigest(), keys, identity

    def _journal(self, state):
        if not _present(state, 'controller.json'):
            return None, None
        raw, identity = read_private(state, 'controller.json', _JOURNAL_MAX_BYTES)
        try:
            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError()
                    result[key] = value
                return result
            value = json.loads(raw, object_pairs_hook=pairs)
            required = {'schema', 'boot_id', 'generation', 'state', 'allocation',
                        'profile_digest', 'policy', 'pins', 'pending', 'restart_required',
                        'probe_at', 'reason', 'network_started', 'restart_boundary_unresolved'}
            if (set(value) != required or type(value['schema']) is not int or value['schema'] != 1 or
                    value['boot_id'] != own.current_boot_id() or
                    type(value['generation']) is not int or value['generation'] < 1 or
                    type(value['network_started']) is not bool or
                    type(value['restart_boundary_unresolved']) is not bool or
                    value['state'] not in ('loading', 'blocked', 'preparing', 'ready', 'degraded', 'disabling', 'disabled') or
                    type(value['profile_digest']) is not str or len(value['profile_digest']) != 64 or
                    not isinstance(value['policy'], list) or not isinstance(value['restart_required'], list) or
                    (value['pins'] is not None and not isinstance(value['pins'], dict))):
                raise ValueError()
            Allocation(**value['allocation'])
            parse_policy(_json({'schema_version': 1, 'included_executables': value['policy']}))
            pending = value['pending']
            if pending is not None:
                if (set(pending) != {'action', 'path', 'policy', 'generation'} or
                        pending['action'] not in ('add', 'remove') or
                        type(pending['generation']) is not int or pending['generation'] != value['generation'] + 1):
                    raise ValueError()
                policy_path(pending['path'])
                proposed = set(value['policy'])
                if pending['action'] == 'add':
                    proposed.add(pending['path'])
                else:
                    proposed.discard(pending['path'])
                if sorted(proposed) != pending['policy']:
                    raise ValueError()
            for process in value['restart_required']:
                if (set(process) != {'pid', 'ppid', 'starttime', 'exe'} or
                        any(type(process[k]) is not int or process[k] < 0 for k in ('pid', 'ppid', 'starttime')) or
                        type(process['exe']) is not str):
                    raise ValueError()
            return value, identity
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ControllerError('controller journal is invalid or belongs to another boot') from None

    def _save(self, state, journal, identity):
        content = _json(journal) + '\n'
        if len(content.encode('utf-8')) > _JOURNAL_MAX_BYTES:
            raise ControllerError('controller journal exceeds its recoverable size limit')
        return _replace(state, 'controller.json', content, identity)

    def _observed(self, journal, *, policy=True):
        observed = self.kernel.snapshot()
        allocation = journal['allocation']
        if (journal['pins'] is None or not _same(observed['pins'], journal['pins']) or
                observed['mask'] != allocation['mask'] or observed['mark'] != allocation['mark']):
            raise ControllerError('pinned guard identity no longer matches this lifetime')
        if policy and sorted(observed['paths']) != sorted(journal['policy']):
            raise ControllerError('kernel policy differs from the committed policy generation')
        return observed

    def _block(self, journal, *, policy=True):
        self._observed(journal, policy=policy)
        self.kernel.set_state('blocked')
        if self._observed(journal, policy=policy)['state'] != 'blocked':
            raise ControllerError('guard did not enter blocked state')

    def _network(self, state, profile, journal):
        receipt = own.read_receipt(state) if _present(state, 'receipt.json') else None
        return self.network_factory(profile, state, owner_uid=self.owner_uid,
                                    allocation=Allocation(**journal['allocation']), receipt=receipt)

    def _audit(self, journal, paths=()):
        if not paths and not journal['restart_required']:
            return  # No enrollment or retained lineage to inspect; sticky flag stays intact.
        observed = restart_audit(paths, self.processes(), journal['restart_required'])
        if observed:
            journal['restart_boundary_unresolved'] = True
        # Diagnostic truncation never clears the boot-lifetime uncertainty flag.
        details, size = [], 2
        for process in observed[:1024]:
            size += len(_json(process).encode('utf-8')) + 1
            if size > _RESTART_DETAIL_BYTES:
                break
            details.append(process)
        journal['restart_required'] = details

    def _recover_edit(self, state, config, journal, identity, disk_policy, settings_identity):
        pending = journal['pending']
        if disk_policy not in (journal['policy'], pending['policy']):
            raise ControllerError('settings changed outside the pending policy transaction')
        self._block(journal, policy=False)
        actual = set(self._observed(journal, policy=False)['paths'])
        old, new = set(journal['policy']), set(pending['policy'])
        if actual not in (old, new):
            raise ControllerError('policy changed outside the pending transaction')
        path = pending['path']
        if actual != new:
            if pending['action'] == 'add':
                self.kernel.add(path)
            else:
                self.kernel.remove(path)
        if set(self._observed(journal, policy=False)['paths']) != new:
            raise ControllerError('kernel policy update readback failed')
        if pending['action'] == 'add':
            self._audit(journal, (path,))
        if disk_policy != pending['policy']:
            text = settings_json(Settings(1, tuple(pending['policy'])))
            _replace(config, 'settings.json', text, settings_identity)
        journal.update(policy=pending['policy'], generation=pending['generation'],
                       pending=None, state='blocked', reason=None, probe_at=None)
        return self._save(state, journal, identity)

    def _guard(self, state, config, *, activate=False):
        journal, identity = self._journal(state)
        if journal is not None:
            if journal['state'] == 'disabling':
                raise ControllerError('explicit disable must finish before activation')
            if journal['state'] == 'disabled' and not activate:
                return None, journal, identity
            if journal['pins'] is not None:
                self._block(journal, policy=False)
        self.host_check()
        profile, digest, policy, settings_identity = self._inputs(config)
        if journal is None or journal['state'] == 'disabled':
            if self.kernel.exists() or _present(state, 'receipt.json'):
                raise ControllerError('unclaimed live state prevents a new guard lifetime')
            allocation = self.select_allocation(profile)
            previous = journal
            journal = {'schema': 1, 'boot_id': own.current_boot_id(), 'generation': 1,
                       'state': 'loading', 'allocation': asdict(allocation), 'profile_digest': digest,
                       'policy': sorted(policy), 'pins': None, 'pending': None,
                       'restart_required': previous['restart_required'] if previous else [],
                       'restart_boundary_unresolved': previous['restart_boundary_unresolved'] if previous else False,
                       'probe_at': None, 'reason': None, 'network_started': False}
            self._audit(journal, policy)
            identity = self._save(state, journal, identity)
        if digest != journal['profile_digest']:
            raise ControllerError('profile change requires explicit disable and reactivation')
        if journal['pending'] is None and sorted(policy) != sorted(journal['policy']):
            raise ControllerError('settings differ from the committed generation; use include commands')
        if journal['pins'] is None:
            if self.kernel.exists():
                raise ControllerError('guard birth was not journaled; existing pins cannot be adopted')
            self.kernel.load(journal['policy'], Allocation(**journal['allocation']))
            observed = self.kernel.snapshot()
            if (observed['state'] != 'blocked' or observed['mask'] != journal['allocation']['mask'] or
                    observed['mark'] != journal['allocation']['mark'] or
                    sorted(observed['paths']) != sorted(journal['policy'])):
                raise ControllerError('new guard did not satisfy blocked policy readback')
            journal['pins'] = observed['pins']
            self._audit(journal, journal['policy'])
            identity = self._save(state, journal, identity)
        if journal['pending'] is not None:
            identity = self._recover_edit(state, config, journal, identity, policy, settings_identity)
        self._block(journal)
        journal.update(state='blocked', reason=None, probe_at=None)
        self._audit(journal)
        identity = self._save(state, journal, identity)
        return profile, journal, identity

    def _degrade(self, state, journal, identity):
        try:
            self._block(journal, policy=journal['pending'] is None)
        except (RuntimeError, OSError, ValueError, KeyError):
            pass  # Changed or missing pins are never adopted to make a status claim.
        journal.update(state='degraded', reason='readiness or ownership verification failed', probe_at=None)
        self._save(state, journal, identity)

    def guard(self):
        try:
            with self._locked() as (state, config):
                _, journal, _ = self._guard(state, config)
                return self._result(journal, protection=journal['state'] != 'disabled')
        except (OSError, ValueError, RuntimeError):
            raise ControllerError('guard activation failed; existing protection was retained') from None

    def _ready(self, state, profile, journal, identity):
        observed = self._observed(journal)
        was_ready = observed['state'] == 'ready' and journal['state'] == 'ready'
        if not was_ready:
            self._block(journal)
        network = self._network(state, profile, journal)
        health = network.health()
        if health.missing and not health.changed:
            self._block(journal)
            was_ready = False
            network.repair_missing(guard_blocked=True)
            health = network.health()
        if not health.ready or health.changed or health.missing:
            raise ControllerError('owned network is incomplete or changed')
        proof = self.probe(profile, Allocation(**journal['allocation']))
        if proof.get('dns') is not True or proof.get('handshake_recent') is not True:
            raise ControllerError('live readiness evidence is incomplete')
        health = network.health()
        if not health.ready or health.changed or health.missing:
            raise ControllerError('owned network changed during readiness probe')
        observed = self._observed(journal)
        if not was_ready:
            self.kernel.set_state('ready')
            observed = self._observed(journal)
        if observed['state'] != 'ready':
            raise ControllerError('ready state readback failed')
        journal.update(state='ready', reason=None, probe_at=time.time())
        self._audit(journal)
        self._save(state, journal, identity)
        return self._result(journal, protection=True)

    def activate(self):
        try:
            with self._locked() as (state, config):
                profile, journal, identity = self._guard(state, config, activate=True)
                try:
                    if journal['network_started'] and not _present(state, 'receipt.json'):
                        raise ControllerError('the owned network receipt disappeared')
                    journal['state'] = 'preparing'
                    journal['network_started'] = True
                    identity = self._save(state, journal, identity)
                    if not _present(state, 'receipt.json'):
                        self._network(state, profile, journal).prepare(guard_blocked=True)
                    return self._ready(state, profile, journal, identity)
                except (OSError, ValueError, RuntimeError):
                    # Refresh CAS identity if readiness persisted before a later failure.
                    _, identity = self._journal(state)
                    self._degrade(state, journal, identity)
                    raise
        except (OSError, ValueError, RuntimeError):
            raise ControllerError('activation failed; guard and network protections were retained') from None

    def _result(self, journal, *, protection):
        return {'state': journal['state'], 'generation': journal['generation'],
                'enforcement_state': journal['state'],
                'protection_verified': protection and not journal['restart_boundary_unresolved'],
                'restart_boundary_unresolved': journal['restart_boundary_unresolved'],
                'restart_required': journal['restart_required'],
                'restart_audit': 'Observed application trees require restart; unresolved descendants remain a boot-lifetime boundary',
                'lineage_audit_complete': False, 'dns_last_checked': journal['probe_at'],
                'reason': journal['reason']}

    def status(self):
        if not self.paths.state.exists():
            return {'state': 'inactive', 'protection_verified': False, 'restart_required': []}
        try:
            with self._locked(create=False) as (state, config):
                journal, _ = self._journal(state)
                if journal is None:
                    return {'state': 'inactive', 'protection_verified': False, 'restart_required': []}
                if journal['state'] == 'disabled':
                    return self._result(journal, protection=False)
                profile, digest, policy, _ = self._inputs(config)
                observed = self._observed(journal)
                health = self._network(state, profile, journal).health() if _present(state, 'receipt.json') else None
                protected = (digest == journal['profile_digest'] and sorted(policy) == sorted(journal['policy']) and
                             (not journal['network_started'] or health is not None) and
                             (health is None or (health.ready and not health.missing and not health.changed)))
                if not protected or (journal['state'] == 'ready' and observed['state'] != 'ready'):
                    journal['state'] = 'degraded'
                self._audit(journal)
                return self._result(journal, protection=protected)
        except (OSError, ValueError, RuntimeError, KeyError):
            return {'state': 'degraded', 'protection_verified': False,
                    'reason': 'live ownership or configuration verification failed', 'restart_required': []}

    def check(self):
        with self._locked() as (state, config):
            journal, identity = self._journal(state)
            if journal is None or journal['state'] in ('disabled', 'disabling'):
                return {'state': 'inactive' if journal is None else journal['state'], 'protection_verified': False}
            try:
                self.host_check()
                profile, digest, policy, _ = self._inputs(config)
                if digest != journal['profile_digest'] or sorted(policy) != sorted(journal['policy']) or journal['pending']:
                    raise ControllerError('configuration needs guarded recovery')
                return self._ready(state, profile, journal, identity)
            except (OSError, ValueError, RuntimeError):
                _, identity = self._journal(state)
                self._degrade(state, journal, identity)
                protected = False
                try:
                    self._observed(journal)
                    health = self._network(state, profile, journal).health()
                    protected = health.ready and not health.changed and not health.missing
                except (OSError, ValueError, RuntimeError, UnboundLocalError):
                    pass
                return self._result(journal, protection=protected)

    def _edit(self, action, path):
        try:
            with self._locked() as (state, config):
                previous, identity = self._journal(state)
                was_ready = previous is not None and previous['state'] == 'ready'
                if (was_ready and previous['pending'] is None and
                        (action == 'add') == (path in previous['policy'])):
                    try:
                        self.host_check()
                        profile, digest, policy, _ = self._inputs(config)
                        if digest != previous['profile_digest'] or sorted(policy) != sorted(previous['policy']):
                            raise ControllerError('configuration needs guarded recovery')
                        # _ready verifies current kernel identity/policy and real
                        # network/DNS health before retaining an already-ready state.
                        return self._ready(state, profile, previous, identity)
                    except (OSError, ValueError, RuntimeError):
                        try:
                            self._block(previous, policy=False)
                        except (OSError, ValueError, RuntimeError, KeyError):
                            pass  # Changed pin identities must never be adopted.
                        _, identity = self._journal(state)
                        self._degrade(state, previous, identity)
                        raise
                profile, journal, identity = self._guard(state, config)
                if journal['state'] == 'disabled':
                    raise ControllerError('activate the guard before changing enrolled policy')
                policy = set(journal['policy'])
                if (action == 'add') == (path in policy):
                    if was_ready:
                        return self._ready(state, profile, journal, identity)
                    return self._result(journal, protection=True)
                if action == 'add':
                    policy.add(path)
                else:
                    policy.remove(path)
                settings_json(Settings(1, tuple(sorted(policy))))
                self._audit(journal, (path,))
                journal['pending'] = {'action': action, 'path': path, 'policy': sorted(policy),
                                      'generation': journal['generation'] + 1}
                identity = self._save(state, journal, identity)
                try:
                    _, _, disk_policy, settings_identity = self._inputs(config)
                    identity = self._recover_edit(state, config, journal, identity, disk_policy, settings_identity)
                    if was_ready:
                        return self._ready(state, profile, journal, identity)
                    return self._result(journal, protection=True)
                except (OSError, ValueError, RuntimeError):
                    _, identity = self._journal(state)
                    self._degrade(state, journal, identity)
                    raise
        except (OSError, ValueError, RuntimeError):
            raise ControllerError('policy edit is blocked; its durable intent is retained for recovery') from None

    def include_list(self):
        directory = own.open_private_dir(self.paths.config, owner_uid=self.owner_uid)
        try:
            text, _ = read_private(directory, 'settings.json', 32 * 1024 * 1024)
            paths = list(parse_policy(text).included_executables)
        finally:
            os.close(directory)
        return {'mode': 'include', 'source': 'configured', 'live_enforcement': 'not_checked',
                'included_executables': paths}

    def include_add(self, path):
        key = canonical_executable(path)
        if key == str(self.paths.artifacts / 'bpf-loader'):
            raise ControllerError('the management probe executable cannot be enrolled')
        return self._edit('add', key)

    def include_remove(self, exact_key):
        return self._edit('remove', policy_path(exact_key))

    def disable(self):
        try:
            with self._locked() as (state, config):
                journal, identity = self._journal(state)
                if journal is None:
                    if self.kernel.exists() or _present(state, 'receipt.json'):
                        raise ControllerError('unclaimed resources cannot be disabled')
                    return {'state': 'disabled', 'protection_verified': False, 'restart_required': []}
                if journal['state'] == 'disabled':
                    return self._result(journal, protection=False)
                profile, digest, _, _ = self._inputs(config)
                if digest != journal['profile_digest']:
                    raise ControllerError('restore the owned profile before cleanup')
                if journal['pending'] is not None:
                    _, _, disk_policy, settings_identity = self._inputs(config)
                    identity = self._recover_edit(state, config, journal, identity, disk_policy, settings_identity)
                if not self.kernel.exists():
                    if journal['state'] != 'disabling' or _present(state, 'receipt.json'):
                        raise ControllerError('guard disappeared outside verified final disable')
                else:
                    self._block(journal)
                self._audit(journal, journal['policy'])
                journal['state'] = 'disabling'
                identity = self._save(state, journal, identity)
                if _present(state, 'receipt.json'):
                    network = self._network(state, profile, journal)
                    if network.health().changed:
                        raise ControllerError('changed network resources cannot be removed')
                    receipt = network.disable(guard_blocked=True)
                    if receipt.resources:
                        raise ControllerError('network cleanup is incomplete')
                    identity_receipt = own.file_identity(state, 'receipt.json')
                    if own.read_receipt(state).resources:
                        raise ControllerError('network receipt changed during cleanup')
                    own.verify_file(state, 'receipt.json', identity_receipt)
                    os.unlink('receipt.json', dir_fd=state)
                    os.fsync(state)
                if self.kernel.exists():
                    self._observed(journal)
                    self.kernel.unload()
                if self.kernel.exists():
                    raise ControllerError('guard removal did not complete')
                journal.update(state='disabled', pins=None, pending=None, reason=None, probe_at=None)
                self._save(state, journal, identity)
                return self._result(journal, protection=False)
        except (OSError, ValueError, RuntimeError):
            raise ControllerError('disable stopped because resource ownership or cleanup could not be verified') from None

    def watch(self, *, interval=5, stop=None):
        if not 1 <= interval <= 60:
            raise ControllerError('health interval must be between one and sixty seconds')
        event = stop or threading.Event()
        old = {}
        if stop is None:
            for signum in (signal.SIGTERM, signal.SIGINT):
                old[signum] = signal.signal(signum, lambda *_: event.set())
        try:
            with self._locked() as (state, _):
                journal, _ = self._journal(state)
                disabled = journal is not None and journal['state'] in ('disabled', 'disabling')
                ready = journal is not None and journal['state'] == 'ready' and journal['pending'] is None
            if not disabled:
                checked = None
                if ready:
                    try:
                        checked = self.check()['state']
                    except (OSError, ValueError, RuntimeError):
                        pass  # Uncertain startup still requires guarded activation.
                if checked not in ('ready', 'disabled', 'disabling'):
                    self.activate()
            while not event.wait(interval):
                self.check()
        finally:
            for signum, handler in old.items():
                signal.signal(signum, handler)
            # Deliberately leave pinned links, marks, routes, and firewall intact.
