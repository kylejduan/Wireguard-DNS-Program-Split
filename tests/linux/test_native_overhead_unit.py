#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged boundaries for native ownership and CPU measurement."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
MODULES = ('native_overhead_owner', 'native_overhead_cpu', 'native_overhead_runtime', 'test_native_overhead')
AVAILABLE = all(importlib.util.find_spec(name) for name in MODULES)
if AVAILABLE:
    import native_overhead_owner as own
    import native_overhead_cpu as cpu
    import native_overhead_runtime as runtime
    import test_native_overhead as runner


class ImplementationTests(unittest.TestCase):
    def test_native_boundary_is_implemented(self):
        self.assertTrue(AVAILABLE, 'native ownership, accounting, runtime and runner are missing')


@unittest.skipUnless(AVAILABLE, 'implementation absent')
class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.host = {'uid': 0, 'hostname': 'TV', 'release': '6.8-generic', 'boot_id': 'boot',
                     'machine_id': 'machine', 'virtualization': 'none', 'vm_marker': False}
        self.manifest = {'mode': 'native-tv', 'boot_id': 'boot', 'machine_id': 'machine'}

    def test_native_machine_and_boot_are_bound(self):
        own.admit(self.manifest, self.host, 'native-tv')
        for key, value in [('uid', 1), ('hostname', 'other'), ('release', 'microsoft'),
                           ('boot_id', 'new'), ('machine_id', 'other'), ('virtualization', 'kvm')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                own.admit(self.manifest, {**self.host, key: value}, 'native-tv')

    def test_rehearsal_cannot_produce_native_evidence(self):
        vm = {**self.host, 'hostname': 'wgps-vm', 'virtualization': 'kvm', 'vm_marker': True}
        manifest = {**self.manifest, 'mode': 'vm-rehearsal'}
        own.admit(manifest, vm, 'vm-rehearsal')
        for mode, host in [('native-tv', vm), ('vm-rehearsal', self.host)]:
            with self.assertRaises(ValueError): own.admit(manifest, host, mode)

    def test_collision_checks_allow_unrelated_host_state(self):
        manifest = {'names': {'underlay': 'nu123', 'remote': 'nr123', 'namespace': 'nn123'},
                    'underlay': '192.0.2.0/30', 'host_tunnel': '10.244.0.1',
                    'peer_tunnel': '10.244.0.2', 'host_port': 55101, 'reserved_networks': []}
        inventory = {'paths': [], 'units': [], 'namespaces': [], 'tables': [], 'links': [],
                     'routes': [{'dst': 'default'}, {'dst': '192.168.1.0/24'}],
                     'addresses': ['192.168.1.4/24'], 'udp_ports': [41641]}
        own.preflight(manifest, inventory)
        for key, value in [('paths', ['/etc/wg-program-split']), ('units', ['wg-program-split.service']),
                           ('links', ['wgps0']), ('links', ['nu123']), ('tables', ['wg_program_split']),
                           ('namespaces', ['nn123']), ('udp_ports', [55101]),
                           ('routes', [{'dst': '10.244.0.0/16', 'table': '200'}]),
                           ('addresses', ['192.0.2.1/30'])]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                own.preflight(manifest, {**inventory, key: value})
        with self.assertRaises(ValueError):
            own.preflight({**manifest, 'reserved_networks': ['10.0.0.0/8']}, inventory)


@unittest.skipUnless(AVAILABLE, 'implementation absent')
class OwnershipTests(unittest.TestCase):
    def test_file_replacement_symlink_and_edit_are_not_owned(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary) / 'owned'; path.write_text('first')
            before = own.file_identity(path)
            path.write_text('changed')
            with self.assertRaises(ValueError): own.same_identity(before, own.file_identity(path))
            path.unlink(); path.symlink_to('/etc/hosts')
            with self.assertRaises((ValueError, OSError)): own.file_identity(path)

    def test_link_and_pid_reuse_refuse_cleanup(self):
        for first, last in [({'ifindex': 4, 'ifalias': 'uuid'}, {'ifindex': 5, 'ifalias': 'uuid'}),
                            ({'ifindex': 4, 'ifalias': 'uuid'}, {'ifindex': 4, 'ifalias': 'other'}),
                            ({'pid': 44, 'starttime': 9}, {'pid': 44, 'starttime': 10})]:
            with self.assertRaises(ValueError): own.same_identity(first, last)

    def test_cleanup_retains_changed_object_and_continues_other_owned_objects(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            journal = own.Journal(root / 'journal.jsonl', 'run')
            a, b = root / 'a', root / 'b'
            for path in (a, b):
                path.write_text('original')
                journal.acquire('file', str(path), own.file_identity(path))
            b.write_text('foreign edit')
            errors = journal.cleanup()
            self.assertFalse(a.exists())
            self.assertEqual(b.read_text(), 'foreign edit')
            self.assertEqual(len(errors), 1)
            self.assertIn(str(b), errors[0])
            journal.close()

    def test_interrupted_acquisition_is_persistent_and_blocks_cleanup(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary) / 'journal.jsonl'
            journal = own.Journal(path, 'run')
            self.assertTrue(callable(getattr(journal, 'begin', None)), 'acquisition intents missing')
            journal.begin('link', 'fixture-link')
            journal.close()
            recovered = own.Journal(path, 'run', resume=True)
            errors = recovered.cleanup()
            self.assertTrue(any('fixture-link' in message for message in errors))
            self.assertEqual(len(recovered.pending), 1)
            recovered.close()

    def test_acquisition_failure_cleans_only_identity_proven_fixture_objects(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            journal = own.Journal(Path(temporary) / 'journal.jsonl', 'run')
            links = {'owned': {'ifindex': 42, 'ifalias': 'run'}}
            journal.acquire('link', 'owned', links['owned'].copy())
            commands = []
            def command(*argv):
                commands.append(argv)
                if argv == ('ip', 'link', 'delete', 'dev', 'owned'):
                    del links['owned']; return None
                raise RuntimeError('injected acquisition failure')
            with patch.object(own, 'run', side_effect=command), \
                 patch.object(own, 'link_identity', side_effect=lambda name: links[name]):
                try: command('ip', 'netns', 'add', 'new')
                except RuntimeError: errors = journal.cleanup()
            self.assertEqual(errors, [])
            self.assertEqual(links, {})
            self.assertEqual(commands[-1], ('ip', 'link', 'delete', 'dev', 'owned'))
            self.assertFalse(journal.records)
            journal.close()

    def test_manifest_file_requires_private_ownership_and_lock(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); root.chmod(0o700)
            path = root / 'manifest.json'; path.write_text('{}'); path.chmod(0o600)
            with own.lock_manifest(path, owner_uid=os.getuid()) as (document, first):
                self.assertEqual(document, {})
                with self.assertRaises((BlockingIOError, ValueError)):
                    with own.lock_manifest(path, owner_uid=os.getuid()): pass
                self.assertEqual(first, own.file_identity(path))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                with own.lock_manifest(path, owner_uid=os.getuid()): pass


@unittest.skipUnless(AVAILABLE, 'implementation absent')
class AccountingTests(unittest.TestCase):
    def sample(self, second, user=10, system=20, idle=970, guest=100):
        # Aggregate has two CPUs. Guest is already included in user, never add it.
        ticks = [user, 0, system, idle, 0, 0, 0, 0, guest, 0]
        return {'read_start_ns': int(second * 1e9), 'read_end_ns': int(second * 1e9 + 1000),
                'hz': 100, 'online': '0-1', 'cpus': {'cpu': [v * 2 for v in ticks],
                    'cpu0': ticks, 'cpu1': ticks}, 'ctxt': int(second * 100),
                'processes': {}, 'cgroups': {}}

    def test_elapsed_online_and_guest_accounting(self):
        before, after = self.sample(0), self.sample(10, 60, 70, 1870, 110)
        value = cpu.account(before, after)
        self.assertTrue(value['valid'], value)
        self.assertEqual(value['host_busy_seconds'], 2)
        self.assertAlmostEqual(value['elapsed_seconds'], 10)
        self.assertEqual(value['host_steal_seconds'], 0)
        after['cpus']['cpu'][4] += 50
        after['cpus']['cpu'][3] -= 50
        self.assertEqual(cpu.account(before, after)['host_busy_seconds'], 2)

    def test_tick_deficit_hotplug_counter_regression_and_negative_residual_fail(self):
        before = self.sample(0)
        variants = [self.sample(10, 11, 21, 978), self.sample(10, 60, 70, 1870)]
        variants[1]['online'] = '0'
        regressed = self.sample(10, 60, 70, 1870); regressed['cpus']['cpu0'][0] = 0
        variants.append(regressed)
        for after in variants:
            with self.subTest(after=after): self.assertFalse(cpu.account(before, after)['valid'])
        after = self.sample(10, 60, 70, 1870)
        value = cpu.account(before, after, client_cpu_seconds=4)
        self.assertFalse(value['valid'])
        self.assertLess(value['residual_seconds'], 0)

    def test_nested_cgroup_and_member_process_totals_are_rejected(self):
        before, after = self.sample(0), self.sample(10, 60, 70, 1870)
        for row in (before, after):
            row['cgroups'] = {'controller': {'path': '/a', 'inode': 1, 'usage_usec': 0},
                              'guard': {'path': '/a/child', 'inode': 2, 'usage_usec': 0}}
        self.assertFalse(cpu.account(before, after)['valid'])

    def test_full_series_rejects_transient_hotplug_and_counter_regression(self):
        self.assertTrue(callable(getattr(cpu, 'account_series', None)), 'full-series accounting missing')
        before, middle, after = self.sample(0), self.sample(5, 35, 45, 1420), self.sample(10, 60, 70, 1870)
        self.assertTrue(cpu.account_series([before, middle, after])['valid'])
        variants = []
        hotplug = copy.deepcopy(middle); hotplug['online'] = '0'; variants.append(hotplug)
        missing = copy.deepcopy(middle); del missing['cpus']['cpu1']; variants.append(missing)
        regressed = copy.deepcopy(middle); regressed['cpus']['cpu0'][0] = 9; variants.append(regressed)
        for row in variants:
            with self.subTest(row=row):
                self.assertTrue(cpu.account(before, after)['valid'])
                result = cpu.account_series([before, row, after])
                self.assertFalse(result['valid'])
                self.assertTrue(result['series_errors'])
        for row, usage in ((before, 0), (middle, 2000000), (after, 1000000)):
            row['cgroups'] = {'controller': {'path': '/group', 'inode': 1, 'usage_usec': usage}}
        self.assertFalse(cpu.account_series([before, middle, after])['valid'])

    def test_drain_is_bracketed_before_report_serialization(self):
        events, clock = [], [0.0]
        def now(): return clock[0]
        def sleep(seconds): clock[0] += seconds
        def pending(): return clock[0] < 1.4
        def sample():
            events.append(clock[0]); return {'at': clock[0]}
        samples, boundary = cpu.sample_through_drain(pending, sample, 1.0, 2.0, clock=now, sleep=sleep, interval=.2)
        self.assertGreaterEqual(samples[-1]['at'], 1.4)
        self.assertGreaterEqual(samples[boundary]['at'], 1.0)
        self.assertLess(samples[boundary]['at'], samples[-1]['at'])

    def test_drain_timeout_remains_failure(self):
        clock = [0.0]
        def sleep(n): clock[0] += n
        with self.assertRaises(TimeoutError):
            cpu.sample_through_drain(lambda: True, lambda: {}, 1, 2,
                                    clock=lambda: clock[0], sleep=sleep, interval=.5)


@unittest.skipUnless(AVAILABLE, 'implementation absent')
class ProductRecoveryTests(unittest.TestCase):
    def fixture(self, root, journal):
        import contextlib
        stack = contextlib.ExitStack(); self.addCleanup(stack.close)
        paths = {name: root / name.lower() for name in ('CLI', 'ARTIFACTS', 'CONFIG', 'STATE', 'PINS')}
        for name, path in paths.items(): stack.enter_context(patch.object(runtime, name, path))
        for name in ('ARTIFACTS', 'CONFIG', 'STATE'): paths[name].mkdir()
        paths['CLI'].write_text('launcher')
        payload = paths['ARTIFACTS'] / 'wg-program-split.pyz'; payload.write_text('payload')
        for name in ('profile.conf', 'settings.json', 'installation.json'): (paths['CONFIG'] / name).write_text(name)
        (paths['STATE'] / '.lock').write_text('')
        config = {str(paths['CONFIG'] / name): own.file_identity(paths['CONFIG'] / name) for name in ('profile.conf', 'settings.json')}
        (paths['STATE'] / 'controller.json').write_text(json.dumps({'state': 'disabled', 'pins': None, 'pending': None,
            'boot_id': 'boot', 'profile_digest': config[str(paths['CONFIG'] / 'profile.conf')]['sha256']}))
        def directory(path):
            value = Path(path).lstat()
            return {'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid, 'mode': value.st_mode}
        stack.enter_context(patch.object(own, 'directory_identity', side_effect=directory))
        topology = type('Fixture', (), {'m': {'boot_id': 'boot'}, 'j': journal})()
        product = runtime.Product(topology, 'baseline', root)
        product.receipt = journal.acquire('product', str(paths['CLI']), {
            'files': {str(path): own.file_identity(path) for path in (paths['CLI'], payload)},
            'manifest': own.file_identity(paths['CONFIG'] / 'installation.json'),
            'directories': {str(paths[name]): directory(paths[name]) for name in ('ARTIFACTS', 'CONFIG')}, 'config': config})
        product.state_receipt = journal.acquire('product-state', str(paths['STATE']),
            {'directory': directory(paths['STATE']), 'lock': own.file_identity(paths['STATE'] / '.lock')})
        # Kernel/service inventory is fake; filesystem removals and journal replay are real.
        stack.enter_context(patch.object(runtime.Product, '_verify_retired_runtime', return_value=None, create=True))
        def command(*args, **kwargs):
            from types import SimpleNamespace
            if args != ('systemctl', 'daemon-reload'): raise AssertionError('unmocked privileged command: ' + repr(args))
            return SimpleNamespace(stdout='', stderr='', returncode=0)
        stack.enter_context(patch.object(own, 'run', side_effect=command))
        return product, paths, payload

    def test_recovery_after_uninstall_finished_before_checkpoint(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); journal = own.Journal(root / 'journal.jsonl', 'run')
            product, paths, payload = self.fixture(root, journal)
            def cli(command):
                if command == 'disable': return {'state': 'disabled'}
                paths['CLI'].unlink(); payload.unlink(); (paths['CONFIG'] / 'installation.json').unlink()
                raise RuntimeError('injected crash after uninstall')
            with patch.object(product, 'cli', side_effect=cli):
                with self.assertRaises(RuntimeError): product.close()
            journal.close()
            recovered = own.Journal(root / 'journal.jsonl', 'run', resume=True)
            product.j = recovered
            product.receipt = next(r for r in recovered.records if r['kind'] == 'product')
            product.state_receipt = next(r for r in recovered.records if r['kind'] == 'product-state')
            product.close()
            self.assertFalse(any(paths[name].exists() for name in ('CLI', 'ARTIFACTS', 'CONFIG', 'STATE')))
            self.assertFalse(recovered.records)
            recovered.close()

    def test_private_file_removal_resumes(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); journal = own.Journal(root / 'journal.jsonl', 'run')
            product, paths, payload = self.fixture(root, journal)
            def cli(command):
                if command == 'disable': return {'state': 'disabled'}
                paths['CLI'].unlink(); payload.unlink(); (paths['CONFIG'] / 'installation.json').unlink()
                return {'retained': [], 'removal_deferred': False}
            original = Path.unlink
            def interrupted(path, *args, **kwargs):
                if path.name == 'settings.json': raise RuntimeError('injected private cleanup failure')
                return original(path, *args, **kwargs)
            with patch.object(product, 'cli', side_effect=cli), patch.object(Path, 'unlink', interrupted):
                with self.assertRaises(RuntimeError): product.close()
            self.assertFalse((paths['CONFIG'] / 'profile.conf').exists())
            product.close()
            self.assertFalse(journal.records)
            journal.close()

    def test_partial_package_removal_uses_verified_production_uninstaller(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); journal = own.Journal(root / 'journal.jsonl', 'run')
            product, paths, payload = self.fixture(root, journal)
            package = root / 'staged.pyz'; package.write_text('exact staged package')
            journal.checkpoint(product.receipt, identity={**product.receipt['identity'],
                'package': {'path': str(package), 'identity': own.file_identity(package)}})
            def cli(command):
                if command == 'disable': return {'state': 'disabled'}
                paths['CLI'].unlink()
                raise RuntimeError('injected crash halfway through package uninstall')
            with patch.object(product, 'cli', side_effect=cli):
                with self.assertRaises(RuntimeError): product.close()
            journal.close()
            recovered = own.Journal(root / 'journal.jsonl', 'run', resume=True)
            product.j = recovered
            product.receipt = next(r for r in recovered.records if r['kind'] == 'product')
            product.state_receipt = next(r for r in recovered.records if r['kind'] == 'product-state')
            commands = []
            def command(*args, **kwargs):
                commands.append(args)
                if args[0] == '/usr/bin/python3':
                    self.assertEqual(args[1:3], ('-I', '-c'))
                    self.assertIn('from wg_program_split.install import uninstall', args[3])
                    self.assertEqual(args[-1], str(package))
                    payload.unlink(); (paths['CONFIG'] / 'installation.json').unlink()
                    return SimpleNamespace(stdout='{"retained": [], "removal_deferred": false}')
                self.assertEqual(args, ('systemctl', 'daemon-reload'))
                return SimpleNamespace(stdout='')
            with patch.object(own, 'run', side_effect=command): product.close()
            self.assertFalse(recovered.records)
            self.assertTrue(any(argv[0] == '/usr/bin/python3' for argv in commands))
            recovered.close()

    def test_recovery_retains_foreign_private_replacement(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); journal = own.Journal(root / 'journal.jsonl', 'run')
            product, paths, payload = self.fixture(root, journal)
            def cli(command):
                if command == 'disable': return {'state': 'disabled'}
                paths['CLI'].unlink(); payload.unlink(); (paths['CONFIG'] / 'installation.json').unlink()
                raise RuntimeError('injected interruption')
            with patch.object(product, 'cli', side_effect=cli):
                with self.assertRaises(RuntimeError): product.close()
            foreign = paths['CONFIG'] / 'settings.json'; foreign.write_text('foreign replacement')
            with self.assertRaises(ValueError): product.close()
            self.assertEqual(foreign.read_text(), 'foreign replacement')
            self.assertTrue(journal.records)
            journal.close()

    def test_failed_installer_never_adopts_concurrent_matching_installation(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); journal = own.Journal(root / 'journal.jsonl', 'run')
            product, paths, _ = self.fixture(root, journal)
            journal.release(product.receipt); journal.release(product.state_receipt)
            product.receipt = product.state_receipt = None
            build = root / 'build'; build.mkdir()
            names = ('wg-program-split.pyz', 'bpf-loader', 'classifier.bpf.o', *own.UNITS)
            for name in names: (build / name).write_text(name)
            product.m.update(evidence=str(root), builds={'baseline': {'directory': str(build),
                'sha256': {name: own.digest(build / name) for name in names}}})
            product.t.profile = lambda: 'new fixture profile'
            foreign_identity = own.file_identity(paths['CONFIG'] / 'profile.conf')
            observed = {'paths': [], 'units': [], 'links': [], 'tables': []}
            real_identity = own.file_identity
            def identity(path):
                if str(path).startswith(str(paths['CONFIG'])) or str(path).startswith(str(paths['ARTIFACTS'])) or path == paths['CLI']:
                    raise AssertionError('failed installer attempted to adopt foreign installation')
                return real_identity(path)
            with patch.object(own, 'inventory', return_value=observed), \
                 patch.object(own, 'run', return_value=SimpleNamespace(returncode=1, stdout='')), \
                 patch.object(own, 'file_identity', side_effect=identity):
                with self.assertRaises(RuntimeError): product.enter()
                product.close()
            self.assertIsNone(product.receipt)
            self.assertEqual(foreign_identity, own.file_identity(paths['CONFIG'] / 'profile.conf'))
            self.assertTrue(any(row['kind'] == 'product' for row in journal.pending))
            journal.close()


@unittest.skipUnless(AVAILABLE, 'implementation absent')
class ManagementRouteTests(unittest.TestCase):
    def snapshots(self):
        first = {key: {} for key in ('resolver', 'rules4', 'rules6', 'protected_services', 'sysctls')}
        first.update(routes6=[], bpf_links=[], nft={'nftables': []})
        first['management_routes'] = {'192.0.2.10': [{'type': 'local', 'dst': '192.0.2.10',
            'dev': 'lo', 'prefsrc': '192.0.2.10', 'cache': ['local'], 'flags': [], 'uid': 0}]}
        first['routes4'] = [{'type': 'local', 'dst': '192.0.2.10', 'dev': 'eth0', 'table': 'local',
                             'protocol': 'kernel', 'scope': 'host', 'prefsrc': '192.0.2.10'}]
        last = copy.deepcopy(first)
        last['management_routes']['192.0.2.10'][0]['table'] = 'local'
        return first, last

    def test_optional_local_table_annotation_matches_proved_host_fib_without_editing_raw(self):
        first, last = self.snapshots(); original = copy.deepcopy((first, last))
        self.assertEqual(runtime.verify_snapshot(first, last), [])
        self.assertEqual((first, last), original)

    def test_local_annotation_requires_matching_local_host_fib_in_both_snapshots(self):
        for field, value in [('table', 'main'), ('type', 'unicast'), ('scope', 'link'),
                             ('dst', '192.0.2.11'), ('dst', '192.0.2.0/24')]:
            with self.subTest(field=field, value=value):
                first, last = self.snapshots()
                for snapshot in (first, last): snapshot['routes4'][0][field] = value
                self.assertIn('management_routes changed', runtime.verify_snapshot(first, last))
        first, last = self.snapshots(); last['routes4'] = []
        self.assertIn('management_routes changed', runtime.verify_snapshot(first, last))

    def test_nonlocal_table_and_other_forwarding_changes_remain_failures(self):
        first, last = self.snapshots()
        for snapshot in (first, last):
            snapshot['management_routes']['192.0.2.10'][0].update(type='unicast', dev='eth0', cache=[])
        self.assertIn('management_routes changed', runtime.verify_snapshot(first, last))
        for field, value in [('table', 200), ('dev', 'other'), ('gateway', '192.0.2.1'),
                             ('prefsrc', '192.0.2.20'), ('metric', 100)]:
            with self.subTest(field=field):
                first, last = self.snapshots(); last['management_routes']['192.0.2.10'][0][field] = value
                self.assertIn('management_routes changed', runtime.verify_snapshot(first, last))


@unittest.skipUnless(AVAILABLE, 'implementation absent')
class RunnerTests(unittest.TestCase):
    def test_failed_client_report_is_drained_before_retirement(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            journal = own.Journal(root / 'journal.jsonl', 'run')
            process = runtime.child(journal, [sys.executable, '-c',
                "import sys; print('partial failure report', flush=True); sys.exit(2)"], root / 'stderr')
            topology = type('Fixture', (), {'j': journal})()
            runner.save_and_retire(topology, root, {'failed': process}, None)
            self.assertEqual((root / 'failed.json').read_text(), 'partial failure report\n')
            self.assertEqual(process.returncode, 2)
            self.assertFalse(journal.records)
            journal.close()

    def test_executable_identity_is_rechecked_before_launch(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); binary = root / 'bin'; binary.mkdir()
            path = binary / 'direct-ip'; path.write_bytes(b'original')
            journal = own.Journal(root / 'journal.jsonl', 'run')
            journal.acquire('file', str(path), own.file_identity(path))
            path.write_bytes(b'replacement')
            topology = type('Fixture', (), {'j': journal, 'evidence': root,
                'm': {'peer_tunnel': '10.244.0.2', 'payload_port': 55553}, 'peer': '192.0.2.2'})()
            with self.assertRaises(ValueError):
                runner.launch(topology, root, runner.CASES[2], 'absent', 0, 10)
            journal.close()

    def test_profiler_structured_error_is_unavailable_even_with_zero_exit(self):
        from types import SimpleNamespace
        self.assertTrue(callable(getattr(runner, 'profile_unavailable', None)), 'profiler result parser missing')
        error = 'bpftool prog profile command is not supported; rebuild with clang'
        self.assertEqual(runner.profile_unavailable(SimpleNamespace(returncode=0, stdout=json.dumps({'error': error}))), error)
        self.assertIsNotNone(runner.profile_unavailable(SimpleNamespace(returncode=1, stdout='{}')))
        self.assertIsNone(runner.profile_unavailable(SimpleNamespace(returncode=0, stdout='{"cycles": 42}')))

    def test_balanced_schedule_and_native_workloads(self):
        import overhead_stats
        self.assertEqual(len(runner.CASES), 16)
        self.assertEqual(len({tuple(x) for x in overhead_stats.schedule(6, 7)}), 6)
        self.assertEqual(runtime.PINS, Path('/sys/fs/bpf/wg_program_split'))
        self.assertEqual(runtime.ARTIFACTS, Path('/usr/lib/wg-program-split'))

    def test_native_modules_never_import_vm_or_mutate_resolver(self):
        import ast
        for name in MODULES[:-1]:
            tree = ast.parse((HERE / (name + '.py')).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(node.module, ('fixtures', 'test_acceptance', 'test_overhead'))
        # Existing VM admission is exercised as code, with no privileged command.
        import test_acceptance
        with patch('test_acceptance.os.geteuid', return_value=0), \
             patch.dict(os.environ, WG_CLASSIFIER_DISPOSABLE_VM='1'), \
             patch('test_acceptance.socket.gethostname', return_value='TV'), \
             patch('test_acceptance.Path.is_file', return_value=True):
            with self.assertRaises(SystemExit): test_acceptance.require_vm()


if __name__ == '__main__': unittest.main()
