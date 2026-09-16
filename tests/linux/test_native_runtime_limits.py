#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runtime safeguards: manifest-bound payloads, root-controlled staging, route proof,
bidirectional host snapshots and narrowly resolved spawn intents.

Filesystem, journal and child-process behaviour is real. Kernel routing, systemd and
the production installer are fakes, so no privileged command runs.
"""
import contextlib
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_overhead_owner as own
import native_overhead_runtime as runtime

NAMES = ('wg-program-split.pyz', 'bpf-loader', 'classifier.bpf.o', *own.UNITS)
FIXTURE = {'underlay': 'nu0123456789', 'remote': 'nr0123456789', 'namespace': 'nn0123456789'}
PEER, HOST, PEER_TUNNEL, HOST_TUNNEL = '192.0.2.2', '192.0.2.1', '10.244.0.2', '10.244.0.1'
OWNED = {(None, PEER, 0): FIXTURE['underlay'], (None, PEER, 0x4000): FIXTURE['underlay'],
         (None, PEER_TUNNEL, 8): 'wgps0', (None, PEER_TUNNEL, 0): 'wgps0',
         (FIXTURE['namespace'], HOST, 0): FIXTURE['remote'], (FIXTURE['namespace'], HOST_TUNNEL, 0): 'peerwg'}


def temporary(test):
    value = tempfile.TemporaryDirectory(dir=Path.home())
    test.addCleanup(value.cleanup)
    root = Path(value.name); root.chmod(0o700)
    return root


def journal(test, root):
    value = own.Journal(root / 'journal.jsonl', 'run')
    test.addCleanup(value.close)
    return value


def replay(root):
    value = own.Journal(root / 'journal.jsonl', 'run', resume=True)
    try: return list(value.pending), list(value.records)
    finally: value.close()


def events(root, name):
    return [json.loads(row) for row in (root / 'journal.jsonl').read_text().splitlines() if json.loads(row)['event'] == name]


def topology(j, **extra):
    m = {'names': dict(FIXTURE), 'peer_tunnel': PEER_TUNNEL, 'host_tunnel': HOST_TUNNEL, **extra}
    return SimpleNamespace(m=m, j=j, peer=PEER, host=HOST, ns=FIXTURE['namespace'])


class Kernel:
    """Route decisions keyed by (namespace, destination, mark); anything unlisted leaves via eth0."""
    def __init__(self, fwmark='0x4000', **overrides):
        self.fwmark, self.table, self.calls = fwmark, {**OWNED, **overrides.get('table', {})}, []

    def run(self, *args, **kwargs):
        args = tuple(map(str, args)); self.calls.append(args)
        if args == ('wg', 'show', 'wgps0', 'fwmark'): return SimpleNamespace(returncode=0, stdout=self.fwmark + '\n')
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    def data(self, *args):
        args = tuple(map(str, args)); self.calls.append(args)
        if 'get' not in args: return self.other(args)
        namespace = args[2] if args[1] == '-n' else None
        address = args[args.index('get') + 1]
        mark = int(args[args.index('mark') + 1]) if 'mark' in args else 0
        value = self.table.get((namespace, address, mark), 'eth0')
        return value if isinstance(value, list) else [{'dst': address, 'dev': value, 'flags': [], 'cache': []}]

    def other(self, args): raise AssertionError('unexpected kernel query: ' + repr(args))


class RouteProofTests(unittest.TestCase):
    def test_owned_links_are_proved_with_product_and_endpoint_marks(self):
        root = temporary(self); j = journal(self, root); kernel = Kernel()
        with patch.object(own, 'run', kernel.run), patch.object(own, 'data', kernel.data):
            proof = runtime.route_proof(topology(j), 8)
        by = {row['check']: row for row in proof}
        self.assertEqual(set(by), {'direct', 'endpoint', 'tunnel', 'peer-direct', 'peer-tunnel'})
        self.assertEqual((by['tunnel']['mark'], by['tunnel']['expected_dev']), (8, 'wgps0'))
        # Encapsulated packets carry the WireGuard outer fwmark and must stay on the veth.
        self.assertEqual((by['endpoint']['mark'], by['endpoint']['expected_dev']), (0x4000, FIXTURE['underlay']))
        self.assertIn(('ip', '-j', 'route', 'get', PEER_TUNNEL, 'mark', '8'), kernel.calls)
        self.assertEqual(events(root, 'route-proof')[0]['checks'], proof)

    def test_policy_escape_or_non_unicast_decision_is_refused(self):
        # Tailscale's earlier rule with an exit node, a foreign table and routing loops.
        variants = {'marked tunnel via tailscale0': {(None, PEER_TUNNEL, 8): 'tailscale0'},
                    'direct via tailscale0': {(None, PEER, 0): 'tailscale0'},
                    'endpoint into its own tunnel': {(None, PEER, 0x4000): 'wgps0'},
                    'namespace answers elsewhere': {(FIXTURE['namespace'], HOST_TUNNEL, 0): 'lo'},
                    'blackhole': {(None, PEER_TUNNEL, 8): [{'type': 'blackhole', 'dst': PEER_TUNNEL, 'dev': 'wgps0'}]},
                    'ambiguous': {(None, PEER, 0): [{'dev': FIXTURE['underlay']}, {'dev': 'eth0'}]}}
        for label, table in variants.items():
            with self.subTest(label):
                root = temporary(self); j = journal(self, root); kernel = Kernel(table=table)
                with patch.object(own, 'run', kernel.run), patch.object(own, 'data', kernel.data):
                    with self.assertRaisesRegex(ValueError, 'leaves the owned link'): runtime.route_proof(topology(j), 8)
                self.assertEqual(events(root, 'route-proof'), [])

    def plain(self, kernel, root, j):
        (root / 'peer.pub').write_text('public\n')
        fixture = topology(j, run_id='run', host_port=51820, peer_port=51821)
        fixture.private = root
        def other(args):
            if args == ('ip', '-j', 'link', 'show'): return []
            if args[:5] == ('ip', '-j', '-4', 'route', 'show'): return [{'dst': PEER_TUNNEL, 'dev': 'wgps0', 'metric': 77}]
            raise AssertionError('unexpected kernel query: ' + repr(args))
        kernel.other = other
        stack = contextlib.ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch.object(own, 'run', kernel.run)); stack.enter_context(patch.object(own, 'data', kernel.data))
        stack.enter_context(patch.object(own, 'link_identity', return_value={'ifindex': 9, 'ifname': 'wgps0',
                                                                           'ifalias': 'wgps-native:run', 'link_netnsid': None}))
        stack.enter_context(patch.object(runtime.time, 'sleep'))
        return fixture

    def test_plain_arm_proves_routes_before_any_client_can_start(self):
        root = temporary(self); j = journal(self, root); kernel = Kernel(fwmark='off')
        with runtime.plain(self.plain(kernel, root, j)):
            self.assertEqual({row['check'] for row in events(root, 'route-proof')[0]['checks']},
                             {'direct', 'endpoint', 'tunnel', 'peer-direct', 'peer-tunnel'})
        self.assertIn(('ip', '-j', 'route', 'get', PEER_TUNNEL), kernel.calls)  # Plain clients send unmarked.
        self.assertEqual((j.pending, j.records), ([], []))

    def test_plain_arm_escape_never_yields_and_removes_only_owned_objects(self):
        root = temporary(self); j = journal(self, root)
        kernel = Kernel(fwmark='off', table={(None, PEER_TUNNEL, 0): 'tailscale0'})
        entered = False
        with self.assertRaisesRegex(ValueError, 'tunnel route'):
            with runtime.plain(self.plain(kernel, root, j)): entered = True
        self.assertFalse(entered)
        self.assertIn(('ip', 'route', 'delete', PEER_TUNNEL + '/32', 'dev', 'wgps0', 'metric', '77'), kernel.calls)
        self.assertEqual(kernel.calls[-1], ('ip', 'link', 'delete', 'wgps0'))
        self.assertEqual((j.pending, j.records), ([], []))


class InstallHarness:
    """Production-installer stand-in that copies whatever the build directory holds when it runs."""
    def __init__(self, test, *, kernel=None):
        self.root = root = temporary(test)
        self.paths = {name: root / name.lower() for name in ('CLI', 'ARTIFACTS', 'CONFIG', 'STATE', 'PINS', 'UNIT_DIR')}
        self.paths['UNIT_DIR'].mkdir()
        self.build = root / 'build'; self.build.mkdir()
        for name in NAMES: (self.build / name).write_bytes(b'accepted ' + name.encode())
        self.sha = {name: own.digest(self.build / name) for name in NAMES}
        self.j = journal(test, root)
        self.directory = root / 'arm'; self.directory.mkdir()
        fixture = topology(self.j, evidence=str(root), builds={'candidate': {'directory': str(self.build), 'sha256': self.sha}})
        fixture.profile = lambda: 'fixture profile\n'
        self.product = runtime.Product(fixture, 'candidate', self.directory)
        self.during = self.after = self.stop = None
        self.shim = runtime.SHIM
        self.kernel = kernel or Kernel()
        self.kernel.other = lambda args: {'mark': 8} if args[0] == str(self.paths['ARTIFACTS'] / 'bpf-loader') else self.fail(args)
        stack = contextlib.ExitStack(); test.addCleanup(stack.close)
        for name, path in self.paths.items(): stack.enter_context(patch.object(runtime, name, path))
        stack.enter_context(patch.object(own, 'inventory', return_value={'paths': [], 'units': [], 'links': [], 'tables': []}))
        stack.enter_context(patch.object(own, 'directory_identity', side_effect=lambda p: {'inode': Path(p).lstat().st_ino}))
        stack.enter_context(patch.object(own, 'run', side_effect=self.command))
        stack.enter_context(patch.object(own, 'data', side_effect=self.kernel.data))
        stack.enter_context(patch.object(runtime, 'service_instances', return_value={}))
        stack.enter_context(patch.object(runtime.stats, 'fresh_readiness', return_value=True))
        stack.enter_context(patch.object(runtime.time, 'sleep'))

    def fail(self, args): raise AssertionError('unexpected query: ' + repr(args))

    def install(self):
        if self.during: self.during()
        p = self.paths
        p['CLI'].write_bytes(self.shim); p['ARTIFACTS'].mkdir(); p['CONFIG'].mkdir()
        for name in NAMES[:3]: (p['ARTIFACTS'] / name).write_bytes((self.build / name).read_bytes())
        for name in own.UNITS: (p['UNIT_DIR'] / name).write_bytes((self.build / name).read_bytes())
        for name in ('profile.conf', 'settings.json'): (p['CONFIG'] / name).write_bytes((self.directory / name).read_bytes())
        (p['CONFIG'] / 'installation.json').write_text('{}')
        if self.after: self.after()

    def command(self, *args, **kwargs):
        args = tuple(map(str, args))
        if args[:2] == ('/usr/bin/python3', '-I') and args[3] == 'install':
            self.install(); return SimpleNamespace(returncode=0, stdout='', stderr='')
        if args[0] == str(self.paths['CLI']):
            if args[1] == self.stop: raise RuntimeError('stopped at ' + args[1])
            if args[1] == 'activate':
                self.paths['STATE'].mkdir()
                for name in ('.lock', 'controller.json', 'receipt.json'): (self.paths['STATE'] / name).write_text('{}')
            return SimpleNamespace(returncode=0, stdout='{}')
        return self.kernel.run(*args)

    def installed(self):
        return {str(p): p for p in (self.paths['CLI'], *(self.paths['ARTIFACTS'] / n for n in NAMES[:3]),
                                    *(self.paths['UNIT_DIR'] / n for n in own.UNITS))}


class PayloadBindingTests(unittest.TestCase):
    def test_build_substitution_is_refused_even_when_installed_equals_build(self):
        # The earlier check compared installed bytes with a re-read of the build
        # directory, which accepted a substitution made before the installer copied.
        for name in NAMES:
            with self.subTest(name=name):
                harness = InstallHarness(self)
                harness.during = lambda: (harness.build / name).write_bytes(b'substituted')
                with self.assertRaisesRegex(ValueError, 'differs from manifest sha256'): harness.product.enter()
                self.assertIsNone(harness.product.receipt)
                self.assertEqual([r['kind'] for r in harness.j.pending], ['product'])  # Retained, never adopted.
                self.assertTrue(all(path.exists() for path in harness.installed().values()))

    def test_unexpected_launcher_is_refused(self):
        harness = InstallHarness(self)
        harness.shim = runtime.SHIM + b'# foreign\n'
        with self.assertRaisesRegex(ValueError, 'differs from manifest sha256'): harness.product.enter()
        self.assertIsNone(harness.product.receipt)

    def test_package_replaced_after_install_is_not_recorded_for_recovery(self):
        harness = InstallHarness(self)
        harness.after = lambda: (harness.build / 'wg-program-split.pyz').write_bytes(b'substituted')
        with self.assertRaisesRegex(ValueError, 'staged package changed'): harness.product.enter()
        self.assertIsNone(harness.product.receipt)

    def test_exact_payload_is_adopted_with_manifest_hashes_and_marked_route_proof(self):
        harness = InstallHarness(self)
        self.assertIs(harness.product.enter(), harness.product)
        identity = harness.product.receipt['identity']
        for path in harness.installed().values():
            wanted = own.digest(path) if path == harness.paths['CLI'] else harness.sha[path.name]
            self.assertEqual(identity['files'][str(path)]['sha256'], wanted)
        self.assertEqual(identity['package']['identity']['sha256'], harness.sha['wg-program-split.pyz'])
        proof = json.loads((harness.directory / 'route-proof.json').read_text())
        self.assertEqual({(row['check'], row['mark']) for row in proof if row['check'] in ('tunnel', 'endpoint')},
                         {('tunnel', 8), ('endpoint', 0x4000)})

    def test_escaping_marked_route_refuses_product_arm_before_clients(self):
        harness = InstallHarness(self, kernel=Kernel(table={(None, PEER_TUNNEL, 8): 'tailscale0'}))
        with self.assertRaisesRegex(ValueError, 'tunnel route'): harness.product.enter()
        self.assertFalse((harness.directory / 'route-proof.json').exists())
        self.assertIsNotNone(harness.product.receipt)  # installed() closes it through the owned path.


class StagingTests(unittest.TestCase):
    def stage(self):
        root = temporary(self)
        path = root / 'bpf-loader'; path.write_bytes(b'accepted'); path.chmod(0o755)
        return root, path, own.digest(path)

    def unchanged(self, path):
        value = path.lstat()
        return (value.st_mode, value.st_uid, value.st_gid, value.st_ino, value.st_nlink, path.read_bytes())

    def test_root_controlled_copy_returns_exactly_the_hashed_bytes(self):
        _, path, sha = self.stage()
        self.assertEqual(own.staged_file(path, sha, owner_uid=os.getuid())['sha256'], sha)
        self.assertEqual(own.staged_bytes(path, sha, owner_uid=os.getuid()), b'accepted')

    def test_writable_linked_or_mismatched_inputs_fail_actionably_without_mutation(self):
        variants = {'not root-controlled': lambda root, path: (root.chmod(0o777), path)[1],
                    'group/other write': lambda root, path: (path.chmod(0o666), path)[1],
                    'differs from the manifest': lambda root, path: (path.write_bytes(b'substituted'), path)[1],
                    'resolved absolute': lambda root, path: ((root / 'alias').symlink_to(path), root / 'alias')[1],
                    'singly linked': lambda root, path: (os.link(path, root / 'second'), path)[1]}
        for message, change in variants.items():
            with self.subTest(message):
                root, path, sha = self.stage()
                target = change(root, path)
                before = self.unchanged(path)
                with self.assertRaisesRegex(ValueError, message):
                    own.staged_bytes(target, sha, owner_uid=os.getuid())
                self.assertEqual(self.unchanged(path), before)
        with self.assertRaisesRegex(ValueError, 'resolved absolute'): own.staged_file('relative/probe', sha)

    @unittest.skipIf(os.geteuid() == 0, 'requires an unprivileged account to model user-owned source')
    def test_user_owned_source_names_the_private_staging_step(self):
        _, path, sha = self.stage()
        before = self.unchanged(path)
        with self.assertRaises(ValueError) as caught: own.staged_file(path, sha)
        self.assertIn('install -d -m 0700', str(caught.exception))
        self.assertIn('never edits or re-owns the source', str(caught.exception))
        self.assertEqual(self.unchanged(path), before)

    def manifest(self, root):
        run_id = '01234567-89ab-cdef-0123-456789abcdef'
        builds = {}
        for arm in ('baseline', 'candidate'):
            directory = root / arm; directory.mkdir(mode=0o700)
            for name in NAMES: (directory / name).write_bytes(arm.encode() + name.encode()); (directory / name).chmod(0o644)
            builds[arm] = {'directory': str(directory), 'revision': 'b843960' if arm == 'baseline' else 'candidate',
                           'sha256': {name: own.digest(directory / name) for name in NAMES}}
        probe = root / 'probe'; probe.write_bytes(b'probe'); probe.chmod(0o755)
        return {'schema': 1, 'run_id': run_id, 'names': own.names(run_id), 'evidence': str(root / 'evidence'),
                'root_preflight_complete': True, 'protected_services_reviewed': ['ssh.service'], 'builds': builds,
                'probe': str(probe), 'probe_sha256': own.digest(probe), 'management_ips': ['192.0.2.10'],
                'host_port': 51820, 'peer_port': 51821, 'payload_port': 55553, 'underlay': '192.0.2.0/30',
                'host_tunnel': '10.244.0.1', 'peer_tunnel': '10.244.0.2'}

    def test_manifest_validation_checks_every_artifact_and_probe_staging(self):
        root = temporary(self); manifest = self.manifest(root)
        real, seen = own.staged_file, []
        def staged(path, expected):
            seen.append(Path(path).name); return real(path, expected, owner_uid=os.getuid())
        with patch.object(own, 'directory_identity'), patch.object(own, 'staged_file', side_effect=staged):
            own.validate_manifest(manifest)
            self.assertEqual(sorted(seen), sorted([*NAMES, *NAMES, 'probe']))
            Path(manifest['builds']['candidate']['directory']).chmod(0o770)
            with self.assertRaisesRegex(ValueError, 'not root-controlled'): own.validate_manifest(manifest)
            Path(manifest['builds']['candidate']['directory']).chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'differs from the manifest'):
                own.validate_manifest({**manifest, 'probe_sha256': '0' * 64})
        self.assertFalse(Path(manifest['evidence']).exists())

    @unittest.skipIf(os.geteuid() == 0, 'requires an unprivileged account to model user-owned source')
    def test_manifest_with_user_owned_builds_is_refused_before_any_run_state(self):
        root = temporary(self); manifest = self.manifest(root)
        with patch.object(own, 'directory_identity'):
            with self.assertRaisesRegex(ValueError, 'install -d -m 0700'): own.validate_manifest(manifest)
        self.assertFalse(Path(manifest['evidence']).exists())


class SpawnIntentTests(unittest.TestCase):
    @unittest.skipUnless(Path('/proc/thread-self/children').exists(), 'kernel cannot list thread children')
    def test_exec_failure_resolves_only_its_own_intent(self):
        root = temporary(self)
        executable = root / 'not-executable'; executable.write_text('#!/bin/sh\n'); executable.chmod(0o600)
        for index, program in enumerate((root / 'missing', executable)):
            with self.subTest(program=program.name):
                j = journal(self, temporary(self))
                unrelated = j.begin('link', 'unknown-birth')
                with self.assertRaises(OSError): runtime.child(j, [program, 'client'], root / f'{index}.stderr')
                self.assertEqual((j.pending, j.records), ([unrelated], []))
                pending, records = replay(j.path.parent)
                self.assertEqual(([row['name'] for row in pending], records), (['unknown-birth'], []))

    def test_unprovable_failures_keep_the_intent_pending(self):
        variants = {'children unavailable': (dict(return_value=None), None),
                    'new child observed': (dict(side_effect=[{'100'}, {'100', '101'}]), None),
                    'non-OSError from Popen': (dict(return_value=set()), subprocess.SubprocessError('preexec failed'))}
        for label, (children, popen_error) in variants.items():
            with self.subTest(label):
                root = temporary(self); j = journal(self, root)
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(runtime, '_children', **children))
                    if popen_error: stack.enter_context(patch.object(runtime.subprocess, 'Popen', side_effect=popen_error))
                    with self.assertRaises((OSError, subprocess.SubprocessError)):
                        runtime.child(j, [root / 'missing'], root / 'client.stderr')
                self.assertEqual([row['kind'] for row in j.pending], ['spawn'])
                self.assertEqual([row['kind'] for row in replay(root)[0]], ['spawn'])

    def test_existing_stderr_evidence_fails_before_any_intent(self):
        root = temporary(self); j = journal(self, root)
        (root / 'client.stderr').write_text('earlier evidence')
        with self.assertRaises(FileExistsError): runtime.child(j, [sys.executable, '-c', 'pass'], root / 'client.stderr')
        self.assertEqual((root / 'client.stderr').read_text(), 'earlier evidence')
        self.assertEqual(events(root, 'intent'), [])

    def test_successful_spawn_still_acquires_identity(self):
        root = temporary(self); j = journal(self, root)
        process = runtime.child(j, [sys.executable, '-c', 'print("{\\"ready\\": true}", flush=True)'], root / 'client.stderr')
        self.assertEqual((j.pending, [r['kind'] for r in j.records]), ([], ['pid']))
        self.assertTrue(runtime.line(process)['ready'])
        runtime.retire(j, process)
        self.assertEqual(j.records, [])


class SnapshotTests(unittest.TestCase):
    def snapshot(self):
        return {'resolver': {}, 'rules4': [], 'rules6': [], 'protected_services': {}, 'sysctls': {}, 'management_routes': {},
                'routes4': [{'dst': '192.168.1.0/24', 'dev': 'eth0'}], 'routes6': [{'dst': 'fe80::/64', 'dev': 'eth0'}],
                'bpf_links': [{'id': 3, 'type': 'cgroup'}],
                'nft': {'nftables': [{'metainfo': {'version': '1.0.9'}}, {'table': {'family': 'inet', 'name': 'tailscale'}}]},
                'links': [{'ifindex': 2, 'ifname': 'eth0', 'ifalias': None, 'kind': None, 'link_type': 'ether',
                           'address': '52:54:00:00:00:01', 'mtu': 1500, 'master': None}],
                'addresses': [{'ifname': 'eth0', 'family': 'inet', 'local': '192.168.1.4', 'prefixlen': 24, 'scope': 'global'}],
                'resolver_links': {'dns': {'exit': 0, 'stdout': 'Global:\nLink 2 (eth0): 192.168.1.1\n'}}}

    def test_unchanged_host_and_nft_metainfo_are_clean(self):
        first = self.snapshot(); last = copy.deepcopy(first)
        last['nft']['nftables'][0]['metainfo']['version'] = '1.1.0'
        self.assertEqual(runtime.verify_snapshot(first, last), [])

    def test_left_behind_objects_are_reported_in_every_family(self):
        additions = {'routes4': {'dst': PEER_TUNNEL, 'dev': 'wgps0', 'table': '57001'}, 'routes6': {'dst': 'fe80::/64', 'dev': 'wgps0'},
                     'bpf_links': {'id': 44, 'type': 'cgroup', 'attach_type': 'cgroup_inet_sock_create'},
                     'links': {'ifindex': 30, 'ifname': 'wgps0', 'kind': 'wireguard'},
                     'addresses': {'ifname': 'wgps0', 'family': 'inet', 'local': HOST_TUNNEL, 'prefixlen': 32, 'scope': 'global'}}
        for name, row in additions.items():
            with self.subTest(name=name):
                first = self.snapshot(); last = copy.deepcopy(first); last[name].append(row)
                self.assertEqual([e.split(':')[0] for e in runtime.verify_snapshot(first, last)], [name + ' entry added'])
        first = self.snapshot(); last = copy.deepcopy(first)
        last['nft']['nftables'].append({'table': {'family': 'inet', 'name': 'wg_program_split'}})
        self.assertEqual([e.split(':')[0] for e in runtime.verify_snapshot(first, last)], ['nft entry added'])

    def test_removed_or_changed_foreign_state_is_reported(self):
        for name in ('links', 'addresses', 'routes4', 'bpf_links'):
            with self.subTest(name=name):
                first = self.snapshot(); last = copy.deepcopy(first); last[name] = []
                self.assertIn('original ' + name + ' entry missing or changed', runtime.verify_snapshot(first, last)[0])
        first = self.snapshot(); last = copy.deepcopy(first); last['links'][0]['mtu'] = 1420
        self.assertEqual(len(runtime.verify_snapshot(first, last)), 2)  # Missing original and added replacement.
        first = self.snapshot(); last = copy.deepcopy(first)
        last['resolver_links']['dns']['stdout'] = 'Global:\nLink 2 (eth0): 10.244.0.2\n'
        self.assertEqual(runtime.verify_snapshot(first, last), ['resolver per-link configuration changed'])

    def test_legacy_original_snapshot_is_compared_only_on_recorded_keys(self):
        first = self.snapshot()
        for name in ('links', 'addresses', 'resolver_links'): del first[name]
        original = copy.deepcopy(first)
        last = {**copy.deepcopy(first), **{k: v for k, v in self.snapshot().items() if k not in first}}
        last['links'].append({'ifindex': 9, 'ifname': 'docker0'})
        self.assertEqual(runtime.verify_snapshot(first, last), [])
        self.assertEqual(first, original)
        last['routes4'].append({'dst': PEER_TUNNEL, 'dev': 'wgps0'})  # Recorded legacy keys are bidirectional now.
        self.assertEqual(len(runtime.verify_snapshot(first, last)), 1)

    def test_new_observations_keep_legacy_keys_and_ignore_only_rotating_state(self):
        rows = [{'ifname': 'eth0', 'addr_info': [
            {'family': 'inet6', 'local': '2001:db8::1', 'prefixlen': 64, 'scope': 'global', 'valid_life_time': 100},
            {'family': 'inet6', 'local': '2001:db8::99', 'prefixlen': 64, 'scope': 'global', 'temporary': True}]}]
        def data(*args):
            if args[:2] == ('ip', '-j') and args[2] == 'address': return rows
            return {'nftables': []} if args[0] == 'nft' else []
        def run(*args, **kwargs):
            if args[0] == 'resolvectl': raise FileNotFoundError(args[0])
            return SimpleNamespace(returncode=0, stdout='')
        with patch.object(own, 'data', side_effect=data), patch.object(own, 'run', side_effect=run), \
             patch.object(runtime, 'resolver_identity', return_value={}):
            value = runtime.snapshot({'management_ips': ['192.0.2.10'], 'protected_services_reviewed': ['ssh.service']})
        legacy = {'resolver', 'management_routes', 'routes4', 'routes6', 'rules4', 'rules6', 'bpf_links', 'bpf_programs',
                  'nft', 'listeners', 'active_services', 'protected_services', 'sysctls'}
        self.assertEqual(set(value) - legacy, {'links', 'addresses', 'resolver_links'})
        self.assertEqual(value['addresses'], [{'ifname': 'eth0', 'family': 'inet6', 'local': '2001:db8::1',
                                               'prefixlen': 64, 'scope': 'global'}])
        self.assertEqual(value['resolver_links']['dns'], {'exit': None, 'stdout': 'resolvectl unavailable'})
        self.assertEqual(runtime.verify_snapshot(value, copy.deepcopy(value)), [])


class TopologyPreflightTests(unittest.TestCase):
    def test_absent_or_unsafe_private_parent_fails_before_any_intent(self):
        root = temporary(self)
        for parent, error in ((root / 'absent', FileNotFoundError), (root, ValueError)):
            if error is ValueError and os.geteuid() == 0: continue
            with self.subTest(parent=parent.name):
                j = journal(self, temporary(self))
                fixture = runtime.Topology({'evidence': str(root), 'run_id': 'run', 'names': dict(FIXTURE),
                                            'underlay': '192.0.2.0/30'}, j)
                fixture.private = parent / 'native-run'
                with patch.object(own, 'run', side_effect=AssertionError('host command before preflight')):
                    with self.assertRaises(error): fixture.create()
                self.assertEqual((j.pending, j.records), ([], []))
                self.assertFalse(fixture.private.exists())


PEER_READY = r'''
import sys
print(sys.argv[1], flush=True)
sys.stdin.read()
'''


class TopologyReadinessTests(unittest.TestCase):
    """Real peer children report readiness; host networking commands are fakes."""
    def create(self, lines):
        root = temporary(self); j = journal(self, root)
        fixture = runtime.Topology({'evidence': str(root), 'run_id': 'run', 'names': dict(FIXTURE), 'underlay': '192.0.2.0/30',
                                    'peer_tunnel': PEER_TUNNEL, 'host_tunnel': HOST_TUNNEL, 'peer_port': 51821,
                                    'payload_port': 55553}, j)
        fixture.private = root / 'native-run'
        self.fixture = fixture
        self.addCleanup(fixture.retire)
        argv, real, replies = [], runtime.child, iter(lines)
        def peer(journal, command, errors):
            argv.append([str(value) for value in command])
            return real(journal, [sys.executable, '-c', PEER_READY, json.dumps(next(replies))], errors)
        def run(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout='key\n' if args[:2] in (('wg', 'genkey'), ('wg', 'pubkey')) else '')
        link = {'ifindex': 7, 'ifname': FIXTURE['underlay'], 'ifalias': 'wgps-native:run', 'link_netnsid': 0}
        with patch.object(runtime, 'child', peer), patch.object(own, 'run', side_effect=run), \
             patch.object(own, 'data', return_value=[]), patch.object(own, 'link_identity', return_value=link), \
             patch.object(own, 'directory_identity', side_effect=lambda p: {'inode': Path(p).lstat().st_ino}), \
             patch.object(own, 'namespace_identity', return_value={}), patch.object(runtime.time, 'sleep'):
            fixture.create()
        return fixture, argv

    def ready(self, rcvbuf, ready=True):
        return {'ready': ready, 'dns_port': 53, 'payload_port': 55553, 'payload_rcvbuf': rcvbuf}

    def test_peer_ready_metadata_is_retained_in_server_order(self):
        fixture, argv = self.create([self.ready(425984), self.ready(212992)])
        self.assertEqual(fixture.peer_ready, [self.ready(425984), self.ready(212992)])
        self.assertEqual(len(fixture.servers), 2)
        # Index 0 is the WireGuard peer, index 1 the direct peer, matching topology.servers.
        self.assertEqual([command[6] for command in argv], [PEER_TUNNEL, fixture.peer])
        self.assertTrue(all(process.poll() is None for process in fixture.servers))

    def test_refused_peer_readiness_is_retained_as_failure_evidence(self):
        with self.assertRaisesRegex(ValueError, 'native peer not ready'):
            self.create([self.ready(425984), self.ready(-1, ready=False)])
        self.assertEqual(self.fixture.peer_ready, [self.ready(425984), self.ready(-1, ready=False)])
        self.assertEqual(len(self.fixture.servers), 2)


if __name__ == '__main__': unittest.main()
