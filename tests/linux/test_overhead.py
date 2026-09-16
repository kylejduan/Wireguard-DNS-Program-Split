#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Three-arm local-overhead experiment; privileged execution requires --vm."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid
import zipfile

import overhead_stats as statistics

REPO = Path(__file__).resolve().parents[2]


def line(process, timeout=10):
    deadline, value = time.monotonic() + timeout, bytearray()
    while len(value) < 8192:
        if not select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            raise RuntimeError('native fixture report timed out')
        part = os.read(process.stdout.fileno(), 1)
        if not part: raise RuntimeError('native fixture exited before readiness')
        if part == b'\n': return json.loads(value)
        value += part
    raise RuntimeError('native fixture report is oversized')


def stop(process):
    if process.poll() is None: process.terminate()
    try: process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=3)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream: stream.close()


def retire_clients(children, directory):
    """Drain complete/partial reports before their owned transport is removed."""
    failures = []
    for label, child in children.items():
        try:
            if child.stdout and not child.stdout.closed:
                try: output, _ = child.communicate(timeout=.1)
                except subprocess.TimeoutExpired:
                    child.terminate()
                    try: output, _ = child.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill(); output, _ = child.communicate(timeout=3)
                (directory / (label + '.json')).write_bytes(output)
        except Exception as error: failures.append(label + ': ' + type(error).__name__)
        finally:
            try: stop(child)
            except Exception as error: failures.append(label + ': ' + type(error).__name__)
    if failures: raise RuntimeError('client retirement failed: ' + ', '.join(failures))


def artifact_manifest(root):
    """Record exact artifacts and prove packaged Python matches supplied source."""
    files = [p for p in (root / 'src/linux').rglob('*') if p.is_file() and p.suffix in ('.py', '.cpp', '.h', '.c', '.service')]
    result = {'source': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}}
    build = root / 'build/linux'
    names = ('wg-program-split.pyz', 'bpf-loader', 'classifier.bpf.o', 'wg-program-split-guard.service', 'wg-program-split.service')
    result['artifacts'] = {name: hashlib.sha256((build / name).read_bytes()).hexdigest() for name in names}
    with zipfile.ZipFile(build / 'wg-program-split.pyz') as archive:
        for path in (root / 'src/linux/wg_program_split').glob('*.py'):
            assert archive.read('wg_program_split/' + path.name) == path.read_bytes(), 'package/source mismatch'
    return result


@contextlib.contextmanager
def plain_wireguard(peer, token):
    """Only a literal controlled peer route; remove our observed interface birth."""
    from test_acceptance import execute
    def links(): return json.loads(execute('ip', '-j', '-d', 'link', 'show').stdout)
    assert not any(p['ifname'] == 'wgps0' for p in links())
    acquired, route = None, None
    marker = 'wgps-overhead:' + token
    try:
        execute('ip', 'link', 'add', 'wgps0', 'type', 'wireguard')
        acquired = next(p for p in links() if p['ifname'] == 'wgps0')
        execute('ip', 'link', 'set', 'wgps0', 'alias', marker)
        execute('wg', 'set', 'wgps0', 'private-key', peer / 'host.key', 'listen-port', '51821',
                'peer', (peer / 'peer.pub').read_text(), 'allowed-ips', '0.0.0.0/0', 'endpoint', '192.0.2.2:51822')
        execute('ip', 'addr', 'add', '10.200.0.1/32', 'dev', 'wgps0', 'noprefixroute')
        execute('ip', 'link', 'set', 'wgps0', 'mtu', '1420', 'up')
        execute('ip', 'route', 'add', '10.200.0.3/32', 'dev', 'wgps0', 'src', '10.200.0.1', 'metric', '77')
        route = json.loads(execute('ip', '-j', '-4', 'route', 'show', '10.200.0.3/32').stdout)
        assert len(route) == 1 and route[0]['dev'] == 'wgps0'
        time.sleep(6)  # Same fixed settling interval as installed arms; no timed samples yet.
        yield None
    finally:
        if acquired is not None:
            current = [p for p in links() if p['ifname'] == 'wgps0']
            assert len(current) == 1 and current[0]['ifindex'] == acquired['ifindex']
            assert current[0].get('ifalias') == marker, 'plain WireGuard ownership changed; retained'
            if route is not None:
                assert json.loads(execute('ip', '-j', '-4', 'route', 'show', '10.200.0.3/32').stdout) == route
                execute('ip', 'route', 'delete', '10.200.0.3/32', 'dev', 'wgps0', 'metric', '77')
            execute('ip', 'link', 'delete', 'wgps0')


@contextlib.contextmanager
def installed(root, directory, peer):
    from test_acceptance import Acceptance, CONFIG, STATE, identity
    runtime = Acceptance(root, directory)
    try:
        runtime.install(peer, [directory / 'selected-ip', directory / 'selected-dns'])
        # Use the extra owned native DNS peer, leaving the existing Python
        # fixture responder intact. These are exact owned private input edits.
        for path in (directory / 'profile.conf', CONFIG / 'profile.conf'):
            assert identity(path) == runtime.files[path]
            text = path.read_text().replace('DNS = 10.200.0.2', 'DNS = 10.200.0.3')
            with path.open('w') as stream: stream.write(text); stream.flush(); os.fsync(stream.fileno())
            runtime.files[path] = identity(path)
        runtime.profile_hash = runtime.files[CONFIG / 'profile.conf'][-1]
        result = runtime.cli('activate', timeout=100)
        activated_at = time.time()
        assert result.get('enforcement_state', result.get('state')) == 'ready'
        runtime.remember_directories()
        runtime.files[STATE / '.lock'] = identity(STATE / '.lock')
        runtime.benchmark_instance = await_daemon_readiness(runtime, directory, activated_at)
        yield runtime
    finally:
        errors = runtime.cleanup()
        if errors: raise RuntimeError('installed benchmark cleanup failed: ' + '; '.join(errors))


CASES = (
    ('included_socket_udp', 'socket_udp', True, 1000), ('included_socket_tcp', 'socket_tcp', True, 1000),
    ('unlisted_socket_udp', 'socket_udp', False, 1000), ('unlisted_socket_tcp', 'socket_tcp', False, 1000),
    ('included_dns_udp', 'dns_udp', True, 100), ('included_dns_tcp', 'dns_tcp', True, 100),
    ('unlisted_dns_udp', 'dns_udp', False, 100), ('unlisted_dns_tcp', 'dns_tcp', False, 100),
    ('included_udp', 'udp', True, 1000), ('included_tcp', 'tcp', True, 200),
    ('unlisted_udp', 'udp', False, 1000), ('unlisted_tcp', 'tcp', False, 200),
    ('unlisted_file', 'file', False, 1000), ('unlisted_mmap', 'mmap', False, 1000),
    ('unlisted_ipc_fresh', 'ipc_fresh', False, 1000), ('unlisted_ipc_old', 'ipc_old', False, 1000),
)


def launch(directory, case, arm, mark, seconds, prefix=''):
    label, mode, included, rate = case
    binary = directory / ('selected-dns' if included and mode.startswith('dns') else 'selected-ip' if included else 'direct-ip')
    address = '10.200.0.3' if included else '192.0.2.2'
    if included and mode.startswith('dns') and arm != 'absent': address = '127.0.0.53'
    errors = (directory / (prefix + label + '.stderr')).open('wb')
    try:
        child = subprocess.Popen([str(binary), 'client', mode, address, '53', '57053',
                                  str(seconds * 1000), str(rate), str(mark if included else 0), str(directory / 'ordinary-file')],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
    finally: errors.close()
    try:
        assert line(child)['ready'] is True
        return child
    except BaseException as error:
        stop(child)
        (directory / (prefix + label + '.setup.json')).write_text(json.dumps(
            {'arm': arm, 'case': label, 'exit': child.returncode, 'failure': type(error).__name__}) + '\n')
        raise


def counters(runtime):
    if runtime is None: return {}
    from test_acceptance import ARTIFACTS, PINS, ENV, execute
    return {key: int(value) for row in execute(ARTIFACTS / 'bpf-loader', 'status', PINS, env=ENV).stdout.splitlines()
            if '=' in row for key, value in [row.split('=', 1)] if value.isdecimal()}


def service_instance():
    from test_acceptance import ENV, execute
    result = execute('systemctl', 'show', 'wg-program-split.service', '-p', 'ActiveState', '-p', 'SubState',
                     '-p', 'MainPID', '-p', 'NRestarts', '-p', 'ControlGroup', env=ENV)
    value = dict(row.split('=', 1) for row in result.stdout.splitlines())
    assert value['ActiveState'] == 'active' and value['SubState'] == 'running' and int(value['MainPID']) > 0
    return value


def await_daemon_readiness(runtime, directory, activated_at):
    # CLI activation and daemon startup are separate writers in the baseline.
    # Status is read-only: with no further CLI mutations, only this daemon can
    # publish a later readiness timestamp. Never launch selected waiters first.
    instance = service_instance()
    daemon = statistics.process_sample(int(instance['MainPID']))
    observations, deadline = [], time.monotonic() + 25
    try:
        time.sleep(6)
        while True:
            status = runtime.cli('status')
            current = statistics.process_sample(daemon['pid'])
            observations.append({'status': status, 'daemon': current})
            statistics.validate_daemon([{'daemon': current}], daemon)
            if statistics.fresh_readiness(status, activated_at):
                assert service_instance() == instance, 'daemon restarted during startup settling'
                return instance
            if time.monotonic() >= deadline: raise RuntimeError('daemon did not publish fresh readiness')
            time.sleep(.25)
    finally:
        (directory / 'startup.json').write_text(json.dumps({'activated_at': activated_at,
            'instance': instance, 'observations': observations}, indent=2) + '\n')


def sample_resources(cgroup, peers, daemon=None):
    value = statistics.resources(cgroup, peers[0].pid)
    value['direct_peer'] = statistics.process_sample(peers[1].pid)
    if daemon:
        try: value['daemon'] = statistics.process_sample(daemon['pid'])
        except FileNotFoundError: value['daemon'] = {'missing': True, 'pid': daemon['pid']}
    return value


def payload_counter_observation(runtime, directory, arm, mark):
    """One predeclared payload-only observation; never select or retry a window."""
    children = {}
    try:
        for case in CASES[8:10]:
            children[case[0]] = launch(directory, case, arm, mark, 1, prefix='counter-')
        before = counters(runtime)
        begin = time.monotonic_ns() + 100000000
        for child in children.values():
            child.stdin.write(('go ' + str(begin) + '\n').encode()); child.stdin.flush()
        results, failed = {}, []
        for label, child in children.items():
            output, _ = child.communicate(timeout=5)
            (directory / ('counter-' + label + '.json')).write_bytes(output)
            try:
                result = json.loads(output); results[label] = result
                assert child.returncode == 0 and len(result['samples']) == result['planned']
                assert not any(sample[2] for sample in result['samples'])
            except (ValueError, KeyError, AssertionError): failed.append(label)
        after = counters(runtime)
        delta = {key: after[key] - value for key, value in before.items()}
        proof = {'before': before, 'after': after, 'delta': delta,
                 'payload_operations': {name: len(row['samples']) for name, row in results.items()},
                 'guard_lookup_observation': 'zero globally' if delta['guard_path_lookups'] == 0 else
                    'global background activity or payload lookup; attribution inconclusive; no retry',
                 'note': 'Client sockets already existed at first snapshot. Daemon remains active. '
                         'These separate samples do not enter primary latency statistics.'}
        (directory / 'payload-counter-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
        assert not failed and delta['included'] == 0, 'payload counter observation failed'
    finally:
        for child in children.values(): stop(child)


def measured_arm(arm, round_id, root, directory, peer, peers, seconds, profiler):
    from test_acceptance import ENV, execute
    children, rows = {}, []
    resources = {'arm': arm, 'round': round_id, 'samples': []}
    try:
        # This unlisted stream really predates attachment in each product arm.
        children['unlisted_ipc_old'] = launch(directory, CASES[-1], arm, 0, seconds)
        manager = plain_wireguard(peer, directory.name) if arm == 'absent' else installed(root, directory, peer)
        with manager as runtime:
            try:
                mark = runtime.native()['mark'] if runtime else 0
                cgroup, instance, daemon = None, None, None
                if runtime:
                    instance = service_instance()
                    assert instance == runtime.benchmark_instance, 'daemon changed after startup proof'
                    daemon = statistics.process_sample(int(instance['MainPID']))
                    group = instance['ControlGroup']
                    assert group.startswith('/system.slice/')
                    cgroup = Path('/sys/fs/cgroup') / group.lstrip('/')
                for case in CASES[:-1]: children[case[0]] = launch(directory, case, arm, mark, seconds)
                before_counters = counters(runtime)
                for server in peers:
                    server.stdin.write(b'stats\n'); server.stdin.flush()
                peer_before = [line(server) for server in peers]
                begin = time.monotonic_ns() + 500000000
                for child in children.values():
                    child.stdin.write(('go ' + str(begin) + '\n').encode()); child.stdin.flush()
                time.sleep(max(0, (begin - time.monotonic_ns()) / 1e9))
                resource_rows = [sample_resources(cgroup, peers, daemon)]
                resources.update(samples=resource_rows, counters_before=before_counters, peer_before=peer_before, daemon_before=instance)
                for second in range(1, seconds + 1):
                    time.sleep(max(0, (begin + second * 1000000000 - time.monotonic_ns()) / 1e9))
                    resource_rows.append(sample_resources(cgroup, peers, daemon))
                failed = []
                for label, child in children.items():
                    try:
                        output, _ = child.communicate(timeout=8)
                    except subprocess.TimeoutExpired:
                        child.kill(); output, _ = child.communicate(timeout=3)
                    (directory / (label + '.json')).write_bytes(output)
                    try: result = json.loads(output)
                    except (ValueError, UnicodeError):
                        failed.append(label + ': malformed or incomplete report'); continue
                    result.update(case=label, arm=arm, round=round_id)
                    rows.append(result)
                    if child.returncode or len(result['samples']) != result['planned'] or any(s[2] for s in result['samples']):
                        failed.append(label)
                after_counters = counters(runtime)
                resources.update(counters_after=after_counters)
                for server in peers:
                    server.stdin.write(b'stats\n'); server.stdin.flush()
                peer_after = [line(server) for server in peers]
                delta = {key: after_counters[key] - value for key, value in before_counters.items()}
                resources.update({'arm': arm, 'round': round_id, 'samples': resource_rows, 'counters_before': before_counters,
                             'counters_after': after_counters, 'counter_delta': delta, 'peer_before': peer_before, 'peer_after': peer_after,
                             'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'), 'daemon_before': instance})
                (directory / 'resources.json').write_text(json.dumps(resources, indent=2) + '\n')
                assert not failed, 'operations failed: ' + ', '.join(failed)
                for index, server in enumerate(peers):
                    assert server.poll() is None, 'native peer exited'
                    expected_dns = seconds * 200
                    expected_payload = seconds * 1200
                    assert peer_after[index]['dns'] - peer_before[index]['dns'] >= expected_dns
                    assert peer_after[index]['payload'] - peer_before[index]['payload'] == expected_payload
                    field = 'peer' if index == 0 else 'direct_peer'
                    assert resource_rows[0][field]['starttime'] == resource_rows[-1][field]['starttime']
                if runtime:
                    current_instance = service_instance()
                    resources['daemon_after'] = current_instance
                    (directory / 'resources.json').write_text(json.dumps(resources, indent=2) + '\n')
                    assert current_instance == instance, 'daemon instance changed during measurement'
                    statistics.validate_daemon(resource_rows, daemon)
                    assert all(r['controller']['inode'] == resource_rows[0]['controller']['inode'] for r in resource_rows)
                    assert runtime.ready(), 'controller did not remain ready'
                    if round_id == 0: payload_counter_observation(runtime, directory, arm, mark)
                    if profiler and round_id == 0:
                        execute('/usr/bin/python3', profiler, '--count', '5', '--warmup', '0',
                                '--output', directory / 'controller-profile.json', timeout=100,
                                env={**ENV, 'WG_CLASSIFIER_DISPOSABLE_VM': '1'})
                return rows, resources
            except BaseException as error:
                resources['failure'] = type(error).__name__
                if runtime:
                    try: resources['failure_observation'] = {'native': runtime.native(), 'status': runtime.cli('status')}
                    except Exception as observation_error: resources['failure_observation_error'] = type(observation_error).__name__
                raise
            finally:
                try: (directory / 'resources.json').write_text(json.dumps(resources, indent=2) + '\n')
                finally: retire_clients(children, directory)
    finally:
        retire_clients(children, directory)


def vm(args):
    sys.path.insert(0, str(REPO / 'src/linux'))
    os.environ['PYTHONPATH'] = str(REPO / 'src/linux')  # Existing fixture responder subprocesses only.
    from fixtures import vpn_fixture
    from test_acceptance import ENV, execute, pristine, require_vm, snapshot
    require_vm(); pristine()
    orders = statistics.schedule(args.rounds, args.seed)
    if not 10 <= args.seconds <= 30: raise ValueError('each measured arm must last 10..30 seconds')
    roots = {'baseline': args.baseline_root.resolve(strict=True), 'candidate': args.candidate_root.resolve(strict=True)}
    manifests = {arm: artifact_manifest(root) for arm, root in roots.items()}
    before = snapshot()
    output = REPO / 'local/validation' / ('overhead-' + uuid.uuid4().hex[:10])
    output.mkdir(parents=True, mode=0o700)
    print('Evidence:', output, flush=True)
    metadata = {'schema': 1, 'baseline_declared_revision': args.baseline_revision, 'candidate_declared_revision': args.candidate_revision,
                'builds': manifests, 'schedule': orders, 'seed': args.seed, 'seconds_per_arm': args.seconds,
                'rounds': args.rounds, 'kernel': os.uname().release, 'machine': os.uname().machine,
                'online_cpus': os.cpu_count(), 'cpu_affinity': sorted(os.sched_getaffinity(0)),
                'probe_source_sha256': hashlib.sha256((REPO / 'tests/linux/overhead_probe.c').read_bytes()).hexdigest(),
                'cases': CASES, 'sample_columns': ['latency_ns', 'schedule_lateness_ns', 'errno', 'payload_bytes'],
                'note': 'All fixed-schedule samples count; no counter-noise filtering or timing retries. '
                        'Paced operations report scheduled lateness separately; throughput is offered-load goodput. '
                        'Paired intervals estimate mean batch-quantile shifts, not per-request or Internet RTT guarantees. '
                        'Both native peers share the VM kernel and use TCP_NODELAY; client CPU and peer CPU are separate. '
                        'Controller resource samples cover the fixed measured window and include service children. '
                        'Each arm has fixed six-second settling; installed arms also require fresh daemon-produced readiness. '
                        'No accepted CPU or latency SLO is inferred.'}
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    binary = output / 'overhead-probe'
    execute('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', REPO / 'tests/linux/overhead_probe.c', '-o', binary)
    metadata['probe_binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    rows, resource_rows, servers = [], [], []
    try:
        with vpn_fixture(owned_host=False) as peer:
            execute('ip', '-n', 'wgps-peer', 'addr', 'add', '10.200.0.3/32', 'dev', 'wgps-wgpeer')
            try:
                for label, address, source in (('vpn', '10.200.0.3', '10.200.0.1'), ('direct', '192.0.2.2', '192.0.2.1')):
                    with (output / (label + '-peer.stderr')).open('wb') as errors:
                        process = subprocess.Popen(['ip', 'netns', 'exec', 'wgps-peer', str(binary), 'peer', address, '53', '57053', source],
                                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, env=ENV)
                    servers.append(process); assert line(process)['ready']
                for round_id, order in enumerate(orders):
                    for arm in order:
                        directory = output / (str(round_id) + '-' + arm); directory.mkdir(mode=0o700)
                        for name in ('selected-ip', 'selected-dns', 'direct-ip'): shutil.copyfile(binary, directory / name); (directory / name).chmod(0o755)
                        (directory / 'ordinary-file').write_bytes(b'Z' * 4096)
                        observed, resource = measured_arm(arm, round_id, roots.get(arm), directory, peer, servers, args.seconds, args.controller_profiler)
                        rows.extend(observed); resource_rows.append(resource)
                        (output / 'rows.json').write_text(json.dumps(rows) + '\n')
                        (output / 'resources.json').write_text(json.dumps(resource_rows, indent=2) + '\n')
                        print('Completed round', round_id + 1, arm, flush=True)
            finally:
                for server in servers: stop(server)
                assert all(server.returncode == 0 for server in servers), 'native peer failed or needed forced cleanup'
        assert snapshot() == before, 'host baseline changed after benchmark cleanup'
        pristine()
        assert {arm: artifact_manifest(root) for arm, root in roots.items()} == manifests, 'artifacts changed during experiment'
        summary = {'latency': statistics.summarize(rows, args.seed),
                   'resources': statistics.summarize_resources(resource_rows)}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps({'completed': True, 'evidence': str(output), 'measured_seconds_per_arm': args.rounds * args.seconds}))
    finally:
        # No secret profile is ever unlinked without the installation helper's
        # exact captured identity. Ambiguous cleanup failures retain evidence.
        for server in servers:
            if server.poll() is None: stop(server)


class NativeOverheadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='wgps-overhead-test-', dir=Path.home())
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name); cls.binary = cls.root / 'probe'
        source = REPO / 'tests/linux/overhead_probe.c'
        assert source.is_file(), 'native overhead probe is not implemented'
        subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(cls.binary)],
                       check=True, capture_output=True, timeout=30)

    def test_native_peer_and_every_operation_retain_ordered_samples(self):
        peer = subprocess.Popen([str(self.binary), 'peer', '127.0.0.1', '0', '0', '127.0.0.1'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ports = line(peer)
            data = self.root / 'ordinary-file'; data.write_bytes(b'Z' * 4096)
            for case in ('socket_udp', 'socket_tcp', 'file', 'mmap', 'ipc_fresh', 'ipc_old',
                         'dns_udp', 'dns_tcp', 'udp', 'tcp'):
                with self.subTest(case=case):
                    client = subprocess.Popen([str(self.binary), 'client', case, '127.0.0.1',
                        str(ports['dns_port']), str(ports['payload_port']), '50', '200', '0', str(data)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    try:
                        self.assertTrue(line(client)['ready'])
                        output, errors = client.communicate(('go ' + str(time.monotonic_ns() + 10000000) + '\n').encode(), timeout=4)
                        self.assertEqual(client.returncode, 0, errors)
                        result = json.loads(output)
                        self.assertEqual(result['planned'], 10)
                        self.assertEqual(len(result['samples']), 10)
                        self.assertTrue(all(len(s) == 4 and s[0] > 0 and s[2] == 0 for s in result['samples']))
                    finally: stop(client)
            peer.stdin.write(b'stats\n'); peer.stdin.flush()
            observed = line(peer)
            self.assertEqual(observed['dns'], 20)
            self.assertEqual(observed['payload'], 20)
        finally: stop(peer)
        self.assertEqual(peer.returncode, 0)

    def test_peer_stops_when_owning_control_pipe_closes(self):
        peer = subprocess.Popen([str(self.binary), 'peer', '127.0.0.1', '0', '0', '127.0.0.1'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(line(peer)['ready'])
            peer.stdin.close(); peer.stdin = None
            self.assertEqual(peer.wait(timeout=1), 0)
        finally: stop(peer)

    def test_terminated_window_retains_completed_native_samples(self):
        child = subprocess.Popen([str(self.binary), 'client', 'socket_udp', '127.0.0.1', '53', '57053',
                                  '1000', '1000', '0', '/unused'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(line(child)['ready'])
            child.stdin.write(('go ' + str(time.monotonic_ns()) + '\n').encode()); child.stdin.flush()
            time.sleep(.03); child.terminate()
            output, _ = child.communicate(timeout=3)
            result = json.loads(output)
            self.assertEqual(child.returncode, 1)
            self.assertGreater(len(result['samples']), 0)
            self.assertLess(len(result['samples']), result['planned'])
        finally: stop(child)

    def test_failed_counter_read_preserves_reports_and_stops_clients_before_transport(self):
        child = subprocess.Popen([str(self.binary), 'client', 'socket_udp', '127.0.0.1', '53', '57053',
                                  '50', '200', '0', '/unused'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        directory = self.root / 'failed-counter'; directory.mkdir()
        events = []
        @contextlib.contextmanager
        def transport(*unused):
            try: yield None
            finally:
                self.assertIsNotNone(child.poll())
                self.assertTrue(child.stdout.closed)
                self.assertEqual(len(json.loads((directory / 'unlisted_ipc_old.json').read_bytes())['samples']), 10)
                events.append('transport retired after samples and clients')
        try:
            self.assertTrue(line(child)['ready'])
            with mock.patch(__name__ + '.plain_wireguard', transport), mock.patch(__name__ + '.launch', return_value=child), \
                    mock.patch(__name__ + '.CASES', (CASES[-1],)), mock.patch(__name__ + '.sample_resources', return_value={}), \
                    mock.patch(__name__ + '.counters', side_effect=[{}, RuntimeError('injected status failure')]):
                with self.assertRaisesRegex(RuntimeError, 'injected status failure'):
                    measured_arm('absent', 0, None, directory, None, [], 0, None)
            self.assertEqual(len(events), 1)
            self.assertEqual(json.loads((directory / 'resources.json').read_text())['failure'], 'RuntimeError')
        finally: stop(child)

    def test_wrong_automatic_mark_is_a_recorded_failure_not_a_dropped_sample(self):
        client = subprocess.Popen([str(self.binary), 'client', 'socket_udp', '127.0.0.1', '53', '57053',
                                   '50', '200', '1', '/unused'],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(line(client)['ready'])
            output, errors = client.communicate(('go ' + str(time.monotonic_ns() + 10000000) + '\n').encode(), timeout=4)
            self.assertEqual(client.returncode, 1)
            result = json.loads(output)
            self.assertEqual(len(result['samples']), 1)
            self.assertGreater(result['samples'][0][2], 0)
            self.assertEqual(result['planned'], 10)
            self.assertIn(b'mark mismatch expected=1 observed=0', errors)
        finally: stop(client)

    def test_socket_errno_survives_a_successful_clock_call_that_changes_errno(self):
        source, library = self.root / 'errno-clock.c', self.root / 'errno-clock.so'
        source.write_text('''#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
int socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol; errno=EPERM; return -1;
}
int clock_gettime(clockid_t clock, struct timespec *value) {
    int (*next)(clockid_t,struct timespec *)=dlsym(RTLD_NEXT,"clock_gettime");
    int result=next(clock,value); errno=EINVAL; return result;
}
''')
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', str(source), '-ldl', '-o', str(library)],
                       check=True, capture_output=True, timeout=30)
        client = subprocess.Popen([str(self.binary), 'client', 'socket_udp', '127.0.0.1', '53', '57053',
                                   '50', '200', '0', '/unused'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env={**os.environ, 'LD_PRELOAD': str(library)})
        try:
            self.assertTrue(line(client)['ready'])
            output, errors = client.communicate(('go ' + str(time.monotonic_ns()) + '\n').encode(), timeout=4)
            self.assertEqual(client.returncode, 1)
            self.assertEqual(json.loads(output)['samples'][0][2], 1)
            self.assertIn(b'socket errno=1', errors)
        finally: stop(client)

    def test_persistent_socket_setup_failure_identifies_mark_check(self):
        result = subprocess.run([str(self.binary), 'client', 'udp', '127.0.0.1', '53', '57053',
                                 '50', '200', '1', '/unused'], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'connection mark errno=', result.stderr)
        self.assertIn(b'expected=1', result.stderr)


if __name__ == '__main__':
    if '--vm' not in sys.argv: unittest.main()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--vm', action='store_true', required=True)
        parser.add_argument('--baseline-root', type=Path, required=True)
        parser.add_argument('--baseline-revision', default='7297931', help='Exact baseline revision and any explicit correctness backport')
        parser.add_argument('--candidate-root', type=Path, required=True)
        parser.add_argument('--candidate-revision', required=True)
        parser.add_argument('--rounds', type=int, default=6)
        parser.add_argument('--seconds', type=int, default=10)
        parser.add_argument('--seed', type=int, default=20260913)
        parser.add_argument('--controller-profiler', type=Path)
        vm(parser.parse_args())
