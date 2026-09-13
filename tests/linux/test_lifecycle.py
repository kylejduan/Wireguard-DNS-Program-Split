"""Lifecycle state transitions with real private files and simulated kernel state."""
import base64
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from wg_program_split.controller import Controller, ControllerError, Paths
from wg_program_split.network import Allocation, Health
from wg_program_split import ownership as own
from wg_program_split.preflight import NativeGuard, validate_nss, restart_audit, readiness_probe
from wg_program_split.config import parse_profile


ALLOCATION = Allocation(0x3000000, 0x1000000, 0x2000000, 57001, 1, 57001)
KEY = base64.b64encode(bytes(range(1, 33))).decode()
PROFILE = f'''[Interface]
PrivateKey={KEY}
Address=10.20.0.2/32
DNS=10.20.0.1
[Peer]
PublicKey={KEY}
AllowedIPs=0.0.0.0/0
Endpoint=192.0.2.1:51820
'''


class Kernel:
    def __init__(self):
        self.state = None
        self.paths = []
        self.ids = {'link': 100, 'paths': 101}
        self.events = []
        self.fail_add = False

    def exists(self):
        return self.state is not None

    def load(self, paths, allocation):
        if self.exists():
            raise RuntimeError('existing pins')
        self.events.append('load-blocked')
        self.state, self.paths = 'blocked', sorted(paths)

    def snapshot(self):
        if not self.exists():
            raise RuntimeError('missing pins')
        return {'abi': 3, 'state': self.state, 'mask': ALLOCATION.mask,
                'mark': ALLOCATION.mark, 'pins': dict(self.ids), 'paths': sorted(self.paths)}

    def set_state(self, state):
        self.events.append('state-' + state)
        self.state = state

    def add(self, path):
        self.events.append('add')
        if self.fail_add:
            raise RuntimeError('injected update failure')
        if path not in self.paths:
            self.paths.append(path)

    def remove(self, path):
        self.events.append('remove-path')
        if path in self.paths:
            self.paths.remove(path)

    def unload(self):
        self.events.append('unload')
        self.state = None


class NetworkFixture:
    def __init__(self, events):
        self.events, self.present = events, False
        self.fail_prepare = False
        self.changed = False
        self.missing = False
        self.repairable = False

    def factory(self, profile, directory_fd, **kwargs):
        outer = self

        class Instance:
            def prepare(self, *, guard_blocked):
                if not guard_blocked:
                    raise RuntimeError('unguarded network')
                outer.events.append('network-prepare')
                outer.present = True
                receipt = own.new_receipt()
                own.write_receipt(directory_fd, receipt)
                if outer.fail_prepare:
                    raise RuntimeError('injected prepare failure')
                return receipt

            def health(self):
                if kwargs.get('receipt') is None:
                    return Health((), (), ())
                return Health(('nft_table:owned',) if outer.present else (),
                              ('interface:owned',) if outer.missing else (),
                              ('nft_table:owned',) if outer.changed else (),
                              ready=outer.present and not outer.missing and not outer.changed)

            def disable(self, *, guard_blocked):
                if not guard_blocked or outer.changed:
                    raise RuntimeError('unsafe disable')
                outer.events.append('network-disable')
                outer.present = False
                return own.read_receipt(directory_fd)

            def repair_missing(self, *, guard_blocked):
                if not guard_blocked or outer.changed or not outer.repairable:
                    raise RuntimeError('unverified repair')
                outer.events.append('network-repair')
                outer.missing = False
                return own.read_receipt(directory_fd)

        return Instance()


class LifecycleTests(unittest.TestCase):
    def test_controller_waits_for_another_owned_operation(self):
        self.processes = []
        self.controller.guard()
        result = []
        entered = threading.Event()
        def read_status():
            entered.set()
            result.append(self.new_controller().status())
        worker = threading.Thread(target=read_status)
        with own.locked_state(self.paths.state, owner_uid=os.getuid()):
            worker.start()
            self.assertTrue(entered.wait(1))
            worker.join(0.05)
            waiting = worker.is_alive()
        worker.join(2)
        self.assertTrue(waiting, 'routine lock contention prematurely failed the controller')
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0]['state'], 'blocked')

    def test_missing_owned_interface_repairs_only_after_blocking_then_reprobes(self):
        self.processes = []
        self.controller.activate()
        self.network.missing = self.network.repairable = True
        self.kernel.events.clear()
        result = self.controller.check()
        self.assertEqual(result['state'], 'ready')
        self.assertTrue(result['protection_verified'])
        events = self.kernel.events
        self.assertLess(events.index('state-blocked'), events.index('network-repair'))
        self.assertLess(events.index('network-repair'), events.index('probe'))
        self.assertLess(events.index('probe'), events.index('state-ready'))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wgps-lifecycle-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.paths = Paths(config=root / 'config', state=root / 'state',
                           pins=root / 'pins', artifacts=root / 'artifacts')
        self.paths.config.mkdir(mode=0o700)
        for name, content in [('profile.conf', PROFILE), ('settings.json', json.dumps({
                'schema_version': 1, 'included_executables': ['/missing/selected']}))]:
            p = self.paths.config / name
            p.write_text(content)
            p.chmod(0o600)
        self.kernel = Kernel()
        self.network = NetworkFixture(self.kernel.events)
        self.processes = [{'pid': 50, 'starttime': 100, 'ppid': 1, 'exe': '/missing/selected'}]
        self.probe_ok = True
        self.controller = self.new_controller()

    def new_controller(self):
        def probe(profile, allocation):
            self.kernel.events.append('probe')
            if not self.probe_ok:
                raise RuntimeError('no DNS/handshake')
            return {'dns': True, 'handshake_recent': True}
        return Controller(paths=self.paths, owner_uid=os.getuid(), kernel=self.kernel,
                          network_factory=self.network.factory, host_check=lambda: None,
                          select_allocation=lambda profile: ALLOCATION, probe=probe,
                          processes=lambda: list(self.processes))

    def test_large_accepted_policy_loads_and_interrupted_edit_recovers(self):
        stem = '/' + '/'.join(['x' * 240] * 5)
        paths = [stem + '/' + str(i) for i in range(1023)]
        settings = self.paths.config / 'settings.json'
        settings.write_text(json.dumps({'schema_version': 1, 'included_executables': paths}))
        self.assertGreater(settings.stat().st_size, 1024 * 1024)
        self.processes = [{'pid': i + 1, 'ppid': 0, 'starttime': i + 1, 'exe': paths[0]}
                          for i in range(500)]
        self.controller.guard()
        self.kernel.fail_add = True
        with patch('wg_program_split.controller.canonical_executable', return_value='/last/program'):
            with self.assertRaises(ControllerError):
                self.controller.include_add('/last/program')
        journal = self.paths.state / 'controller.json'
        self.assertGreater(journal.stat().st_size, 2 * 1024 * 1024)
        self.assertIsNotNone(json.loads(journal.read_text())['pending'])
        self.kernel.fail_add = False
        result = self.new_controller().guard()
        self.assertEqual(result['generation'], 2)
        self.assertEqual(len(self.kernel.paths), 1024)
        self.assertFalse(result['protection_verified'])
        self.assertEqual(self.new_controller().disable()['state'], 'disabled')

    def test_restart_details_are_bounded_without_clearing_uncertainty(self):
        self.processes = [{'pid': i + 1, 'ppid': 0, 'starttime': i + 1,
                           'exe': '/missing/selected'} for i in range(1100)]
        result = self.controller.guard()
        self.assertEqual(len(result['restart_required']), 1024)
        self.assertTrue(result['restart_boundary_unresolved'])
        self.processes = []
        result = self.new_controller().check()
        self.assertFalse(result['protection_verified'])
        self.assertTrue(result['restart_boundary_unresolved'])

    def test_oversized_journal_is_rejected_before_replacing_recovery_file(self):
        self.controller.guard()
        path = self.paths.state / 'controller.json'
        before = path.read_bytes()
        with self.controller._locked() as (state, _):
            journal, identity = self.controller._journal(state)
            with patch('wg_program_split.controller._JOURNAL_MAX_BYTES', 1, create=True):
                with self.assertRaises(ControllerError):
                    self.controller._save(state, journal, identity)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.new_controller().guard()['state'], 'blocked')

    def test_guard_loads_missing_stored_paths_blocked_without_network(self):
        result = self.controller.guard()
        self.assertEqual(self.kernel.paths, ['/missing/selected'])
        self.assertEqual(self.kernel.state, 'blocked')
        self.assertFalse(self.network.present)
        self.assertEqual(result['state'], 'blocked')
        self.assertEqual(result['restart_required'][0]['pid'], 50)

    def test_activation_requires_blocked_guard_network_and_live_probe_before_ready(self):
        result = self.controller.activate()
        self.assertEqual(result['state'], 'ready')
        events = self.kernel.events
        self.assertLess(events.index('load-blocked'), events.index('network-prepare'))
        self.assertLess(events.index('network-prepare'), events.index('probe'))
        self.assertLess(events.index('probe'), events.index('state-ready'))
        self.assertTrue(result['restart_required'])
        self.assertFalse(result['protection_verified'])
        self.assertEqual(result['enforcement_state'], 'ready')

    def test_probe_failure_retains_network_and_blocks_selected_processes(self):
        self.probe_ok = False
        with self.assertRaises(ControllerError):
            self.controller.activate()
        self.assertEqual(self.kernel.state, 'blocked')
        self.assertTrue(self.network.present)
        self.assertNotIn('network-disable', self.kernel.events)
        self.assertEqual(self.controller.status()['state'], 'degraded')

    def test_prepare_failure_never_rolls_back_guards_or_existing_marked_socket_rules(self):
        self.network.fail_prepare = True
        with self.assertRaises(ControllerError):
            self.controller.activate()
        self.assertEqual(self.kernel.state, 'blocked')
        self.assertNotIn('unload', self.kernel.events)
        self.assertNotIn('network-disable', self.kernel.events)

    def test_new_controller_adopts_only_matching_pinned_ids_and_observed_network(self):
        self.controller.activate()
        recreated = self.new_controller()
        self.assertEqual(recreated.check()['state'], 'ready')
        self.network.changed = True
        self.assertEqual(recreated.check()['state'], 'degraded')
        self.assertEqual(self.kernel.state, 'blocked')
        self.assertEqual(self.kernel.events.count('network-prepare'), 1)

    def test_replaced_pin_cannot_be_adopted_or_explicitly_removed(self):
        self.controller.activate()
        self.kernel.ids['link'] = 999
        with self.assertRaises(ControllerError):
            self.controller.disable()
        self.assertTrue(self.kernel.exists())
        self.assertTrue(self.network.present)
        self.assertFalse(self.controller.status()['protection_verified'])

    def test_explicit_disable_keeps_configs_and_releases_network_before_pins(self):
        self.controller.activate()
        result = self.controller.disable()
        self.assertEqual(result['state'], 'disabled')
        self.assertLess(self.kernel.events.index('network-disable'), self.kernel.events.index('unload'))
        self.assertTrue((self.paths.config / 'settings.json').exists())
        self.assertTrue(result['restart_required'])

    def test_status_does_not_accept_persisted_ready_without_live_network(self):
        self.controller.activate()
        self.network.missing = True
        result = self.controller.status()
        self.assertNotEqual(result['state'], 'ready')
        self.assertFalse(result['protection_verified'])

    def test_pending_policy_removal_survives_kernel_failure_and_recovery(self):
        self.controller.guard()
        original = self.kernel.remove
        self.kernel.remove = lambda path: (_ for _ in ()).throw(RuntimeError('injected'))
        with self.assertRaises(ControllerError):
            self.controller.include_remove('/missing/selected')
        self.assertEqual(self.kernel.state, 'blocked')
        self.kernel.remove = original
        result = self.new_controller().guard()
        self.assertEqual(self.kernel.paths, [])
        self.assertEqual(result['generation'], 2)
        self.assertEqual(json.loads((self.paths.config / 'settings.json').read_text())['included_executables'], [])

    def test_healthy_periodic_check_does_not_briefly_block_application_traffic(self):
        self.controller.activate()
        self.kernel.events.clear()
        self.assertEqual(self.controller.check()['state'], 'ready')
        self.assertNotIn('state-blocked', self.kernel.events)

    def test_disabled_intent_is_not_reversed_by_guard_or_daemon_restart(self):
        self.controller.activate()
        self.controller.disable()
        self.assertEqual(self.controller.guard()['state'], 'disabled')
        self.assertFalse(self.kernel.exists())
        self.assertEqual(self.controller.check()['state'], 'disabled')
        self.assertEqual(self.controller.activate()['state'], 'ready')

    def test_missing_network_receipt_cannot_leave_status_ready(self):
        self.controller.activate()
        (self.paths.state / 'receipt.json').unlink()
        self.assertEqual(self.controller.status()['state'], 'degraded')
        self.controller.check()
        self.assertFalse(self.controller.status()['protection_verified'])

    def test_config_replacement_guard_failure_still_blocks_known_guard(self):
        self.controller.activate()
        (self.paths.config / 'settings.json').write_text('{}')
        with self.assertRaises(ControllerError):
            self.controller.guard()
        self.assertEqual(self.kernel.state, 'blocked')

    def test_pending_add_recovery_keeps_key_when_image_disappears(self):
        self.controller.guard()
        self.kernel.fail_add = True
        with patch('wg_program_split.controller.canonical_executable', return_value='/vanished/program'):
            with self.assertRaises(ControllerError):
                self.controller.include_add('/vanished/program')
        self.kernel.fail_add = False
        self.assertEqual(self.new_controller().guard()['generation'], 2)
        self.assertIn('/vanished/program', self.kernel.paths)

    def test_birth_during_enrollment_is_audited_after_map_update(self):
        self.processes = []
        self.controller.activate()
        original = self.kernel.add
        def add(path):
            self.processes.append({'pid': 99, 'ppid': 1, 'starttime': 900, 'exe': path})
            original(path)
        self.kernel.add = add
        with patch('wg_program_split.controller.canonical_executable', return_value='/new/program'):
            result = self.controller.include_add('/new/program')
        self.assertFalse(result['protection_verified'])
        self.assertTrue(result['restart_boundary_unresolved'])
        self.assertEqual(result['restart_required'][0]['pid'], 99)

    def test_already_applied_pending_add_recovery_audits_target(self):
        self.processes = []
        self.controller.activate()
        self.kernel.fail_add = True
        with patch('wg_program_split.controller.canonical_executable', return_value='/new/program'):
            with self.assertRaises(ControllerError):
                self.controller.include_add('/new/program')
        self.kernel.fail_add = False
        self.kernel.add('/new/program')
        self.processes = [{'pid': 99, 'ppid': 1, 'starttime': 900, 'exe': '/new/program'}]
        result = self.new_controller().activate()
        self.assertFalse(result['protection_verified'])
        self.assertTrue(result['restart_boundary_unresolved'])

    def test_crash_after_pin_removal_allows_explicit_disable_to_finish(self):
        self.controller.activate()
        save = self.controller._save
        def fail_disabled(state, journal, identity):
            if journal['state'] == 'disabled':
                raise RuntimeError('power loss before final journal publication')
            return save(state, journal, identity)
        with patch.object(self.controller, '_save', side_effect=fail_disabled):
            with self.assertRaises(ControllerError):
                self.controller.disable()
        self.assertFalse(self.kernel.exists())
        self.assertEqual(self.new_controller().disable()['state'], 'disabled')

    def test_probe_failure_preserves_known_protection_separately_from_connectivity(self):
        self.processes = []
        self.controller.activate()
        self.probe_ok = False
        result = self.controller.check()
        self.assertEqual(result['state'], 'degraded')
        self.assertTrue(result['protection_verified'])

    def test_active_enrollment_edit_restores_ready_after_live_probe(self):
        self.controller.activate()
        self.assertEqual(self.controller.include_remove('/missing/selected')['state'], 'ready')

    def test_full_policy_rejects_add_before_recording_unreplayable_intent(self):
        policy = {'schema_version': 1, 'included_executables': [f'/program/{i}' for i in range(1024)]}
        (self.paths.config / 'settings.json').write_text(json.dumps(policy))
        self.controller.guard()
        with patch('wg_program_split.controller.canonical_executable', return_value='/one-too-many'):
            with self.assertRaises(ControllerError):
                self.controller.include_add('/one-too-many')
        journal = json.loads((self.paths.state / 'controller.json').read_text())
        self.assertIsNone(journal['pending'])
        self.assertEqual(len(self.kernel.paths), 1024)

    def test_unseen_orphan_keeps_sticky_restart_boundary_after_known_parent_exits(self):
        self.controller.activate()
        self.processes = [{'pid': 51, 'ppid': 1, 'starttime': 101, 'exe': '/unseen-helper'}]
        result = self.new_controller().check()
        self.assertEqual(result['restart_required'], [])
        self.assertFalse(result['protection_verified'])
        self.assertTrue(result['restart_boundary_unresolved'])

    def test_clean_initial_lifetime_can_verify_protection(self):
        self.processes = []
        result = self.controller.activate()
        self.assertTrue(result['protection_verified'])
        self.assertFalse(result['restart_boundary_unresolved'])

    def test_selected_process_born_during_guard_attachment_is_audited_after_load(self):
        self.processes = []
        load = self.kernel.load
        def birth(paths, allocation):
            load(paths, allocation)
            self.processes = [{'pid': 99, 'ppid': 1, 'starttime': 110, 'exe': '/missing/selected'}]
        self.kernel.load = birth
        result = self.controller.guard()
        self.assertEqual([p['pid'] for p in result['restart_required']], [99])
        self.assertTrue(result['restart_boundary_unresolved'])

    def test_disable_reactivation_does_not_erase_unresolved_same_boot_lineage(self):
        self.controller.activate()
        self.controller.disable()
        self.processes = []
        result = self.new_controller().activate()
        self.assertFalse(result['protection_verified'])
        self.assertTrue(result['restart_boundary_unresolved'])

    def test_ready_kernel_with_preparing_journal_recovers_in_one_check(self):
        self.processes = []
        self.controller.activate()
        path = self.paths.state / 'controller.json'
        journal = json.loads(path.read_text())
        journal['state'] = 'preparing'
        path.write_text(json.dumps(journal))
        self.assertEqual(self.new_controller().check()['state'], 'ready')

    def test_early_allocation_does_not_require_a_live_underlay_route(self):
        with patch('wg_program_split.controller.inspect', return_value='inventory') as inspection, \
                patch('wg_program_split.controller.allocate', return_value=ALLOCATION):
            controller = Controller(kernel=self.kernel)
            self.assertEqual(controller.select_allocation('profile'), ALLOCATION)
            inspection.assert_called_once_with('profile', require_underlay=False)


class PreflightTests(unittest.TestCase):
    def test_native_probe_must_return_boolean_evidence(self):
        native = NativeGuard('/usr/lib/wg-program-split', '/sys/fs/bpf/wg_program_split')
        with patch.object(native, '_run', return_value='{"dns":1}'):
            with self.assertRaises(ControllerError):
                native.probe_dns()

    def test_native_dns_success_cannot_replace_a_recent_wireguard_handshake(self):
        class Guard:
            def probe_dns(self):
                pass
        with patch('wg_program_split.preflight.command', return_value=KEY + '\t0\n'):
            with self.assertRaises(ControllerError):
                readiness_probe(parse_profile(PROFILE), ALLOCATION, Guard())
        with patch('wg_program_split.preflight.command', return_value=KEY + '\t900\n'), \
                patch('wg_program_split.preflight.time.time', return_value=1000):
            self.assertTrue(readiness_probe(parse_profile(PROFILE), ALLOCATION, Guard())['handshake_recent'])

    def test_deleted_selected_image_is_still_reported_for_restart(self):
        processes = [{'pid': 10, 'ppid': 1, 'starttime': 99, 'exe': '/selected (deleted)'}]
        self.assertEqual(restart_audit(['/selected'], processes, [])[0]['pid'], 10)

    def test_nss_accepts_only_proven_paths_and_rejects_daemon_backend(self):
        for hosts in ('files dns', 'files mdns4_minimal [NOTFOUND=return] dns'):
            validate_nss('passwd: files\nhosts: ' + hosts + '\n')
        for hosts in ('resolve files dns', 'files myhostname dns', 'dns', 'files dns\nhosts: files dns'):
            with self.assertRaises(ControllerError):
                validate_nss('hosts: ' + hosts)

    def test_restart_lineage_keeps_child_after_parent_exit_and_rejects_pid_reuse(self):
        initial = [{'pid': 10, 'starttime': 1, 'ppid': 1, 'exe': '/selected'},
                   {'pid': 11, 'starttime': 2, 'ppid': 10, 'exe': '/helper'}]
        audit = restart_audit(['/selected'], initial, [])
        self.assertEqual({p['pid'] for p in audit}, {10, 11})
        next_snapshot = [{'pid': 11, 'starttime': 2, 'ppid': 1, 'exe': '/helper'},
                         {'pid': 10, 'starttime': 9, 'ppid': 1, 'exe': '/other'}]
        self.assertEqual([p['pid'] for p in restart_audit([], next_snapshot, audit)], [11])


if __name__ == '__main__':
    unittest.main()
