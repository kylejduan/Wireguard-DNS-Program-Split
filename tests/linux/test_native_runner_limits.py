#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runner fixture-cgroup, NO_HZ readback, acceptance, lifecycle, stop and recovery contracts.

Real child processes stand in for peers and clients; host CPU samples, the
fixture cgroup and host snapshots are synthetic, so no privileged command runs.
"""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

import native_overhead_cpu as cpu
import native_overhead_owner as own
import native_overhead_runtime as runtime
import overhead_stats as statistics
import test_native_overhead as runner

HERE = Path(__file__).resolve().parent
RCVBUF = 2097152  # Effective size the probe reports after requesting 1 MiB.
# Fakes mirror the probe contract: null means the counter is unavailable.
CLIENT = r'''
import json, sys, time
value = lambda text: None if text == 'null' else int(text)
print(json.dumps({'ready': True}), flush=True)
begin = int(sys.stdin.readline().split()[1])
time.sleep(max(0, (begin - time.monotonic_ns()) / 1e9 + float(sys.argv[1])))
print(json.dumps({'planned': 2, 'cpu_ns': 1000, 'receive_drops': value(sys.argv[2]), 'rcvbuf': value(sys.argv[3]),
                  'stream_errno': None, 'samples': [[1, 0, 0, 10], [1, 0, 0, 10]]}), flush=True)
'''
PEER = r'''
import json, sys
value = lambda text: None if text == 'null' else int(text)
seconds, drops, calls = int(sys.argv[1]), value(sys.argv[2]), 0
print(json.dumps({'ready': True, 'payload_rcvbuf': value(sys.argv[3])}), flush=True)
while sys.stdin.readline():
    print(json.dumps({'dns': calls * 1000 * seconds, 'payload': calls * 1200 * seconds,
                      'payload_drops': None if drops is None else calls * drops}), flush=True); calls += 1
'''
STOP = r'''
import os, signal, subprocess, sys, time
import test_native_overhead as runner
runner.unwind_on_stop()
try:
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(5)
    print('stop ignored', flush=True)
finally:
    os.kill(os.getpid(), signal.SIGTERM); os.kill(os.getpid(), signal.SIGHUP)
    child = subprocess.run([sys.executable, '-c', 'import signal; print(signal.getsignal(signal.SIGTERM) == signal.SIG_DFL)'],
                           capture_output=True, text=True)
    print('cleanup complete; child default SIGTERM', child.stdout.strip(), flush=True)
'''
CASES = (('fake_udp', 'udp', False, 1000), ('fake_tcp', 'tcp', False, 200))
STREAM = (('fake_udp_stream', 'udp_stream', False, 1000), ('fake_tcp', 'tcp', False, 200))
# Source contract from cpu-api-handoff.md: verified HZ=250 via config and a 0.5 s jiffies readback.
NOHZ = {'valid': True, 'online': '0-1', 'clocksource': 'tsc',
        'cpus': {'cpu0': {'nohz': 1, 'hres_active': 1}, 'cpu1': {'nohz': 1, 'hres_active': 1}},
        'kernel_config': {'path': '/boot/config-test', 'HZ': '250'}, 'nohz_full': None, 'cmdline_timing': [],
        'tick_rate': {'jiffies': [0, 125], 'ns': [[0, 1000], [500000000, 500001000]]}}


class Fixture:
    """Topology stand-in: owned peers, a fake fixture cgroup and a fully idle two-CPU host."""
    def __init__(self, root, peer_drops=(0, 0)):
        self.evidence, self.j, self.launched, self.record = root, own.Journal(root / 'journal.jsonl', 'run'), [], True
        self.client_meta, self.proofs, self.route_error = {}, [], None
        self.fixture_group = root / 'system.slice' / 'wgps-overhead-0123456789.service'
        self.fixture_group.mkdir(parents=True)
        (self.fixture_group / 'memory.current').write_text('0\n')
        (self.fixture_group / 'cgroup.stat').write_text('nr_descendants 0\nnr_dying_descendants 0\n')
        (self.fixture_group / 'cgroup.procs').write_text(str(os.getpid()) + '\n')
        self.usage(0)
        self.origin = time.monotonic_ns()
        self.servers = [self.spawn([sys.executable, '-c', PEER, 1, drops, RCVBUF], root / (name + '-peer.stderr'))
                        for name, drops in zip(('vpn', 'direct'), peer_drops)]
        self.peer_ready = [process.ready for process in self.servers]  # runtime.Topology contract.

    def usage(self, value):
        (self.fixture_group / 'cpu.stat').write_text(f'usage_usec {value}\nuser_usec {value}\nsystem_usec 0\n')
        self.current = value

    def spawn(self, argv, stderr):
        process = runtime.child(self.j, argv, stderr)
        process.ready = runtime.line(process)
        if not process.ready.get('ready'): raise ValueError('fake child not ready')
        if self.record:
            with (self.fixture_group / 'cgroup.procs').open('a') as procs: procs.write(str(process.pid) + '\n')
        return process

    def launch(self, topology, directory, case, arm, mark, seconds):
        drops, rcvbuf = self.client_meta.get(case[0], (0, RCVBUF) if case[1] == 'udp_stream' else ('null', 'null'))
        process = self.spawn([sys.executable, '-c', CLIENT, seconds, drops, rcvbuf], directory / (case[0] + '.stderr'))
        self.launched.append(process)
        self.usage(self.current + 5000)  # Setup CPU belongs to the lifecycle, not the primary window.
        return process

    def route_proof(self, topology, mark=0):
        self.proofs.append({'mark': mark, 'at_ns': time.monotonic_ns(), 'launched': len(self.launched)})
        if self.route_error: raise self.route_error
        return [{'check': 'fake'}]

    def sample(self, processes, groups, source=None):
        """Mirrors cpu.sample output for a fully idle host; membership reads are real."""
        begin = time.monotonic_ns()
        ticks = [0, 0, 0, (begin - self.origin) // 10000000, 0, 0, 0, 0, 0, 0]
        cpus = {'cpu': [2 * v for v in ticks], 'cpu0': ticks, 'cpu1': list(ticks)}
        # Two consecutive, non-overlapping reads of an idle host agree (zero idle delta).
        raw = ''.join(name + ' ' + ' '.join(map(str, v)) + '\n' for name, v in cpus.items()) + 'ctxt 0\n'
        reads = [{'ns': [begin + 2000 * i, begin + 2000 * i + 1000], 'raw': raw} for i in range(2)]
        member = '0::' + str(self.fixture_group).removeprefix('/sys/fs/cgroup') + '\n'
        row = {'read_start_ns': begin, 'stat_ns': reads[0]['ns'], 'boottime_ns': begin, 'hz': 100, 'online': '0-1', 'ctxt': 0,
               'cpus': cpus,
               'processes': {name: {'pid': pid, 'starttime': own.pid_identity(pid)['starttime'], 'cgroup': member}
                             for name, pid in processes.items()},
               'cgroups': {name: {**statistics.cgroup_sample(path), 'path': str(path)} for name, path in groups.items()}}
        if source is not None:
            row['nonidle_source'] = source
            if 'fixture' in groups: row['cgroups']['fixture'].update(cpu.members(groups['fixture']))
            row['schedstat'] = {'version': 17, 'cpus': {'cpu0': [0] * 9, 'cpu1': [0] * 9}}
            row['stat_consistency'] = {'reads': reads, 'checks': [{'reads': [0, 1], 'errors': []}],
                                       'accepted': 0, 'bound': getattr(cpu, 'STAT_READS', 4)}
        row['read_end_ns'] = max(time.monotonic_ns(), begin + 4000)
        return row

    def measure(self, round_id=0, sources=None, plain=None, cases=CASES):
        sources = iter(sources or (NOHZ, NOHZ))
        with patch.object(runner, 'launch', self.launch), patch.object(cpu, 'sample', self.sample), \
             patch.object(cpu, 'nohz_capability', side_effect=lambda: copy.deepcopy(next(sources))), \
             patch.object(runtime, 'route_proof', self.route_proof), \
             patch.object(runtime, 'plain', plain or (lambda topology: contextlib.nullcontext())):
            return runner.measure(self, 'absent', round_id, 1, cases)

    def evidence_for(self, round_id=0):
        return json.loads((self.evidence / (str(round_id) + '-absent') / 'resources.json').read_text())

    def owned_pids(self):
        return sorted(int(r['name']) for r in self.j.records if r['kind'] == 'pid')

    def close(self):
        for process in self.servers: runtime.retire(self.j, process)
        self.j.close()


@contextlib.contextmanager
def no_host_access():
    refused = AssertionError('host inventory reached before admission')
    with patch.object(own, 'validate_manifest'), patch.object(own, 'inventory', side_effect=refused), \
         patch.object(own, 'preflight', side_effect=refused), patch.object(runtime, 'snapshot', side_effect=refused), \
         patch.object(runtime, 'Topology', side_effect=refused), patch.object(own, 'Journal', side_effect=refused):
        yield


class RunnerLimitTests(unittest.TestCase):
    def fixture(self, **options):
        temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temporary.cleanup)
        value = Fixture(Path(temporary.name), **options)
        self.addCleanup(value.close)
        return value

    def assert_clients_retired(self, fixture):
        self.assertTrue(fixture.launched)
        self.assertTrue(all(process.returncode is not None for process in fixture.launched))
        self.assertEqual(fixture.owned_pids(), sorted(p.pid for p in fixture.servers))

    def test_serial_default_retains_prior_workloads(self):
        args = runner.arguments(['--vm-rehearsal', '--manifest', 'manifest.json'])
        self.assertEqual(args.udp_mode, 'serial')
        self.assertEqual(runner.case_set(args.udp_mode), runner.CASES)
        changed = [(a, b) for a, b in zip(runner.CASES, runner.case_set('stream')) if a != b]
        self.assertEqual([b[0] for _, b in changed], ['included_udp_stream', 'unlisted_udp_stream'])
        self.assertTrue(all(b[1] == 'udp_stream' and a[2:] == b[2:] for a, b in changed))

    def test_execute_refuses_incomplete_cpu_prerequisites_before_host_access(self):
        args = runner.arguments(['--vm-rehearsal', '--manifest', 'unused'])
        # Timer capability alone is not enough: the kernel-HZ publication-lag model must verify too.
        variants = {'outside unit': (None, 'wgps-overhead'), 'no NO_HZ': ({**NOHZ, 'valid': False}, 'NO_HZ'),
                    'no CONFIG_HZ': ({**NOHZ, 'kernel_config': {'errors': ['no config']}}, 'CONFIG_HZ unavailable'),
                    'contradicted HZ': ({**NOHZ, 'tick_rate': {**NOHZ['tick_rate'], 'jiffies': [0, 25]}}, 'disagrees with CONFIG_HZ'),
                    'nohz_full': ({**NOHZ, 'nohz_full': '1'}, 'nohz_full CPUs')}
        for variant, (source, message) in variants.items():
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
                evidence = Path(temporary) / 'evidence'
                manifest = {'run_id': str(uuid.uuid4()), 'evidence': str(evidence), 'mode': 'vm-rehearsal'}
                with no_host_access(), contextlib.ExitStack() as stack:
                    if source is not None:
                        stack.enter_context(patch.object(cpu, 'fixture_group', return_value=Path(temporary)))
                        stack.enter_context(patch.object(cpu, 'nohz_capability', return_value=source))
                    # Without a source patch the test process is outside the transient unit, so the real check refuses.
                    with self.assertRaisesRegex(ValueError, message): runner.execute(args, manifest, {})
                self.assertFalse(evidence.exists())
        self.assertIsNone(runner.cpu.kernel_hz(NOHZ)[1])  # The accepted fake source really verifies.

    def test_arm_records_readbacks_membership_route_proof_and_separate_lifecycle(self):
        fixture = self.fixture()
        rows, resource = fixture.measure()
        self.assertEqual(len(rows), 2)
        self.assertEqual(resource['nonidle_source_before'], NOHZ)
        self.assertEqual(resource['nonidle_source_after'], NOHZ)
        self.assertIs(resource['samples'][0]['nonidle_source'], resource['nonidle_source_before'])
        self.assertIs(resource['samples'][-1]['nonidle_source'], resource['nonidle_source_after'])
        # One route proof after every client is ready and before the first CPU sample.
        self.assertEqual([(p['mark'], p['launched']) for p in fixture.proofs], [(0, 2)])
        self.assertLess(fixture.proofs[0]['at_ns'], resource['samples'][0]['read_start_ns'])
        self.assertEqual(resource['route_proof_before_go'], [{'check': 'fake'}])
        # Full span starts before GO; the planned account starts at GO.
        self.assertEqual(resource['planned_start_index'], 1)
        self.assertLess(resource['samples'][0]['read_end_ns'], resource['start_ns'])
        self.assertGreaterEqual(resource['samples'][1]['read_start_ns'], resource['start_ns'])
        # One planned second; starting at the pre-GO sample would add the 200 ms GO lead.
        self.assertAlmostEqual(resource['cpu_planned']['elapsed_seconds'], 1, delta=.1)
        for name in runner.ACCOUNTS:
            self.assertTrue(resource[name]['valid'], resource[name])
            self.assertEqual(resource[name]['host_cpu_method'], 'nohz-idle-complement')
        self.assertTrue(runner.cpu_valid([resource]))
        # Fixture cgroup is the only process scope; client loop CPU and observed
        # harness/peer processes are never added to it.
        self.assertEqual(set(resource['cpu']['scope_seconds']), {'fixture'})
        self.assertEqual(resource['cpu']['clients_primary_seconds'], 2e-6)
        self.assertIn('bounds the full-span fixture total from below', resource['cpu_planned']['note'])
        before = resource['fixture_before']
        self.assertEqual((before['errors'], before['descendants']), ([], 0))
        owned = {os.getpid(), *(p.pid for p in fixture.servers + fixture.launched)}
        self.assertTrue(owned <= {pid for pid, _ in before['members']})
        self.assertEqual(resource['fixture_after']['errors'], [])
        self.assertGreater(resource['observer_cpu_seconds'], 0)
        self.assertEqual(resource['fixture_lifecycle']['usage_usec'], 10000)
        self.assertEqual(resource['cpu']['scope_seconds']['fixture'], 0)
        self.assertEqual(fixture.evidence_for()['fixture_lifecycle'], resource['fixture_lifecycle'])
        # Serial clients have no receive counters; the peers still report theirs.
        self.assertEqual(resource['fixture_receive'], {'vpn_peer': {'rcvbuf': RCVBUF, 'drops': 0},
                                                       'direct_peer': {'rcvbuf': RCVBUF, 'drops': 0}})
        self.assert_clients_retired(fixture)

    def test_stream_requires_available_receive_evidence(self):
        _, resource = self.fixture().measure(cases=STREAM)
        self.assertEqual(resource['fixture_receive']['fake_udp_stream'],
                         {'rcvbuf': RCVBUF, 'receive_drops': 0, 'stream_errno': None})
        self.assertEqual(resource['fixture_receive']['direct_peer'], {'rcvbuf': RCVBUF, 'drops': 0})
        for variant in ('peer counter', 'peer ready', 'client counter'):
            with self.subTest(variant=variant):
                fixture = self.fixture(peer_drops=(0, 'null') if variant == 'peer counter' else (0, 0))
                if variant == 'peer ready': fixture.peer_ready = []
                if variant == 'client counter': fixture.client_meta['fake_udp_stream'] = ('null', RCVBUF)
                with self.assertRaisesRegex(ValueError, 'unavailable'): fixture.measure(cases=STREAM)
                self.assertTrue(any('unavailable' in f for f in fixture.evidence_for()['failures']))
                self.assert_clients_retired(fixture)
        # Serial mode records missing peer counters as unavailable, not zero, without failing.
        _, resource = self.fixture(peer_drops=('null', 'null')).measure()
        self.assertEqual(resource['fixture_receive']['vpn_peer'], {'rcvbuf': RCVBUF, 'drops': None})

    def test_fixture_socket_drops_fail_arm_distinct_from_path_loss(self):
        fixture = self.fixture(peer_drops=(0, 3))
        fixture.client_meta['fake_udp_stream'] = (2, RCVBUF)
        with self.assertRaisesRegex(ValueError, 'fixture socket drop'): fixture.measure(cases=STREAM)
        evidence = fixture.evidence_for()
        self.assertEqual(evidence['fixture_receive']['direct_peer'], {'rcvbuf': RCVBUF, 'drops': 3})
        self.assertIn('fixture socket drop at direct_peer: 3', evidence['failures'])
        self.assertIn('fake_udp_stream: fixture socket drop', evidence['failures'])
        self.assertNotIn('peer payload count mismatch', evidence['failures'])
        self.assert_clients_retired(fixture)

    def test_changed_source_readback_invalidates_totals_but_keeps_timing(self):
        fixture = self.fixture()
        rows, resource = fixture.measure(sources=(NOHZ, {**NOHZ, 'clocksource': 'hpet'}))
        self.assertEqual(len(rows), 2)
        self.assertTrue(resource['cpu_planned']['valid'], resource['cpu_planned'])
        for name in ('cpu', 'cpu_drain'):
            self.assertFalse(resource[name]['valid'])
            self.assertIn('high-resolution NO_HZ source unverified or changed', resource[name]['errors'])
        self.assertFalse(runner.cpu_valid([resource]))

    def test_route_escape_or_nonexclusive_fixture_refuses_go_and_retires_clients(self):
        for variant in ('route', 'foreign', 'nested', 'missing'):
            with self.subTest(variant=variant):
                fixture = self.fixture()
                if variant == 'route': fixture.route_error = ValueError('fixture tunnel route leaves the owned link wgps0')
                elif variant == 'foreign':
                    with (fixture.fixture_group / 'cgroup.procs').open('a') as procs: procs.write(f'{os.getppid()}\n')
                elif variant == 'nested':
                    (fixture.fixture_group / 'cgroup.stat').write_text('nr_descendants 1\nnr_dying_descendants 0\n')
                else: fixture.record = False  # Clients would run outside the fixture cgroup.
                message = 'owned link' if variant == 'route' else 'not exclusive'
                with self.assertRaisesRegex(ValueError, message): fixture.measure()
                evidence = fixture.evidence_for()
                self.assertEqual(evidence['samples'], [])
                self.assertIn(message, evidence['failure'])
                if variant != 'route': self.assertTrue(evidence['fixture_before']['errors'])
                self.assert_clients_retired(fixture)

    def test_product_scopes_use_exact_unit_names_and_inventory(self):
        controller = {'cgroup_inode': 7, 'ControlGroup': '/system.slice/' + own.UNITS[1]}
        instance = {own.UNITS[0]: {'cgroup_inode': None, 'ControlGroup': ''}, own.UNITS[1]: controller}
        groups, inodes = runner.product_scopes(instance)
        self.assertEqual(groups, {own.UNITS[1]: Path('/sys/fs/cgroup/system.slice') / own.UNITS[1]})
        self.assertEqual(inodes, {own.UNITS[1]: 7})
        for changed in ({**instance, 'other.service': controller}, {own.UNITS[1]: controller}):
            with self.subTest(changed=sorted(changed)), self.assertRaisesRegex(ValueError, 'inventory'):
                runner.product_scopes(changed)

    def test_lifecycle_read_failure_keeps_original_error_retirement_and_evidence(self):
        fixture = self.fixture()
        @contextlib.contextmanager
        def broken(topology):
            (topology.fixture_group / 'cpu.stat').unlink()
            raise RuntimeError('injected product failure')
            yield
        with self.assertRaisesRegex(RuntimeError, 'injected product failure'): fixture.measure(plain=broken)
        evidence = fixture.evidence_for()
        self.assertIn('injected product failure', evidence['failure'])
        self.assertFalse(evidence['fixture_lifecycle']['valid'])
        self.assertIn('error', evidence['fixture_lifecycle']['end'])
        self.assert_clients_retired(fixture)

    def test_retirement_failure_is_recorded_in_arm_evidence(self):
        fixture = self.fixture()
        real = runner.save_and_retire
        def failing(*args):
            real(*args); raise RuntimeError('injected retirement failure')
        with patch.object(runner, 'save_and_retire', failing):
            with self.assertRaisesRegex(RuntimeError, 'injected retirement failure'): fixture.measure()
        evidence = fixture.evidence_for()
        self.assertIn('injected retirement failure', evidence['retirement_failure'])
        self.assertTrue(evidence['fixture_lifecycle']['valid'])
        self.assert_clients_retired(fixture)

    def test_stop_signal_unwinds_through_cleanup_once(self):
        result = subprocess.run([sys.executable, '-c', STOP], cwd=HERE, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertEqual(result.stdout, 'cleanup complete; child default SIGTERM True\n')

    def test_recovery_repeats_final_invariant_readback(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary) / 'evidence'; root.mkdir(mode=0o700)
            run_id = str(uuid.uuid4())
            manifest = {'run_id': run_id, 'evidence': str(root)}
            runtime.report(root / 'metadata.json', {'run_id': run_id, 'owner': {'pid': os.getpid(), 'starttime': -1}})
            runtime.report(root / 'before.json', {'state': 'before'})
            own.Journal(root / 'ownership.jsonl', run_id).close()
            for differences in (['sysctls changed'], []):
                with self.subTest(differences=differences):
                    compared = []
                    def verify(first, last):
                        compared.append((first, last)); return differences
                    with patch.object(own, 'directory_identity'), \
                         patch.object(runtime, 'snapshot', return_value={'state': 'after'}), \
                         patch.object(runtime, 'verify_snapshot', side_effect=verify), \
                         patch.object(own, 'inventory', return_value={'inventory': True}), \
                         patch.object(own, 'preflight') as preflight:
                        if differences:
                            with self.assertRaisesRegex(RuntimeError, 'recovery.json'): runner.recover(manifest)
                        else: runner.recover(manifest)
                    report = json.loads((root / 'recovery.json').read_text())
                    self.assertEqual(compared, [({'state': 'before'}, {'state': 'after'})])
                    self.assertEqual((report['errors'], report['invariant_errors']), ([], differences))
                    preflight.assert_called_once_with(manifest, {'inventory': True})


class AcceptanceTests(unittest.TestCase):
    """execute() with real journal, evidence files and cleanup; host and windows are fakes."""
    def run_execute(self, mode, bad=None, steal=None):
        temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / 'evidence'
        manifest = {'run_id': str(uuid.uuid4()), 'mode': mode, 'evidence': str(root), 'probe': 'unused', 'probe_sha256': 'unused'}
        calls = []
        def measure(topology, arm, round_id, seconds, cases):
            calls.append((round_id, arm))
            accounts = {name: {'valid': True, 'errors': [], 'series_errors': [], 'host_steal_seconds': 0.0} for name in runner.ACCOUNTS}
            if (round_id, arm) == bad: accounts['cpu_planned'].update(valid=False, errors=['injected invalid account'])
            if (round_id, arm) == steal: accounts['cpu']['host_steal_seconds'] = .01
            return [], {'round': round_id, 'arm': arm, 'samples': [{'retained': True}], **accounts}
        class Topology:
            def __init__(self, manifest, journal): self.j = journal
            def create(self): pass
            def retire(self): return []
        def directory(path):
            value = Path(path).lstat()
            return {'device': value.st_dev, 'inode': value.st_ino}
        output, raised = io.StringIO(), None
        with contextlib.ExitStack() as stack:
            for target, name, value in ((own, 'validate_manifest', None), (own, 'inventory', {}), (own, 'preflight', None),
                                        (own, 'staged_bytes', b'probe'), (runtime, 'snapshot', {'state': 1}),
                                        (runtime, 'verify_snapshot', []), (cpu, 'fixture_group', root.parent),
                                        (cpu, 'nohz_capability', NOHZ), (statistics, 'summarize', {})):
                stack.enter_context(patch.object(target, name, return_value=value))
            stack.enter_context(patch.object(own, 'directory_identity', side_effect=directory))
            stack.enter_context(patch.object(runtime, 'Topology', Topology))
            stack.enter_context(patch.object(runner, 'measure', measure))
            stack.enter_context(contextlib.redirect_stdout(output))
            try: runner.execute(runner.arguments(['--vm-rehearsal', '--manifest', 'unused']), manifest, {})
            except runner.MeasurementRejected as error: raised = error
        def read(name):
            return json.loads((root / name).read_text()) if (root / name).exists() else None
        return raised, read, calls, output.getvalue()

    def test_invalid_window_rejects_after_every_window_with_normal_cleanup(self):
        raised, read, calls, output = self.run_execute('vm-rehearsal', bad=(0, 'baseline'))
        self.assertIsInstance(raised, runner.MeasurementRejected)
        # Every scheduled window ran once, in order: no early stop, retry or skipped window.
        self.assertEqual(calls, [(r, arm) for r, order in enumerate(statistics.schedule(6, 20260914)) for arm in order])
        resources = read('resources.json')
        self.assertEqual(len(resources), 18)
        self.assertFalse(next(r for r in resources if (r['round'], r['arm']) == (0, 'baseline'))['cpu_planned']['valid'])
        acceptance = read('summary.json')['acceptance']
        self.assertEqual((acceptance['accepted'], acceptance['workload_complete'], acceptance['windows']), (False, True, 18))
        self.assertEqual([(e['round'], e['arm'], e['account']) for e in acceptance['errors']], [(0, 'baseline', 'cpu_planned')])
        self.assertEqual((read('failure.json')['type'], read('failure.json')['accepted']), ('MeasurementRejected', False))
        self.assertEqual((read('cleanup.json')['errors'], read('cleanup.json')['remaining']), ([], []))
        self.assertIsNotNone(read('after.json'))
        self.assertNotIn('"completed"', output)

    def test_native_steal_rejects_but_vm_steal_is_recorded(self):
        raised, read, _, _ = self.run_execute('native-tv', steal=(0, 'absent'))
        self.assertIsInstance(raised, runner.MeasurementRejected)
        self.assertIn('native host steal', read('summary.json')['acceptance']['errors'][0]['errors'][0])
        raised, read, _, output = self.run_execute('vm-rehearsal', steal=(0, 'absent'))
        self.assertIsNone(raised)
        acceptance = read('summary.json')['acceptance']
        self.assertEqual((acceptance['accepted'], acceptance['max_host_steal_seconds']), (True, .01))
        self.assertIsNone(read('failure.json'))
        self.assertEqual(read('cleanup.json')['errors'], [])
        self.assertTrue(json.loads(output.splitlines()[-1])['accepted'])

    def test_main_exits_nonzero_for_rejected_measurement(self):
        @contextlib.contextmanager
        def lock(path): yield {'mode': 'vm-rehearsal'}, None
        with patch.object(runner, 'unwind_on_stop'), patch.object(os, 'umask'), patch.object(own, 'lock_manifest', lock), \
             patch.object(own, 'host_identity', return_value={}), patch.object(own, 'admit'), \
             patch.object(runner, 'execute', side_effect=runner.MeasurementRejected('1 CPU acceptance failures')), \
             patch.object(sys, 'argv', ['runner', '--vm-rehearsal', '--manifest', 'unused']):
            with self.assertRaises(SystemExit) as caught: runner.main()
        # A string exit code makes the interpreter print it and exit with status 1.
        self.assertIsInstance(caught.exception.code, str)
        self.assertIn('measurement not accepted', caught.exception.code)


if __name__ == '__main__': unittest.main()
