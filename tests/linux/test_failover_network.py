# SPDX-License-Identifier: GPL-3.0-or-later
"""Real network adapter receipts across retained-anchor peer transitions."""
from dataclasses import replace
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_network as fixture
from test_lifecycle import Died
from wg_program_split.network import Network, NetworkError
from wg_program_split import ownership as own


class PeerKernel(fixture.Kernel):
    def __init__(self):
        super().__init__()
        self.peer = fixture.PUBLIC
        self.endpoint = '192.0.2.8:51820'

    def __call__(self, argv, *, input=None):
        if tuple(argv[:2]) == ('wg', 'setconf'):
            fields = dict(line.split(' = ', 1) for line in Path(argv[3]).read_text().splitlines()
                          if ' = ' in line)
            self.peer, self.endpoint = fields['PublicKey'], fields['Endpoint']
        return super().__call__(argv, input=input)

    def wireguard_dump(self):
        return super().wireguard_dump().replace(fixture.PUBLIC, self.peer).replace(
            '192.0.2.8:51820', self.endpoint)


class NetworkSwitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wgps-peer-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state = root / 'state'
        self.wireguard = root / 'wireguard'
        self.wireguard.mkdir(mode=0o700)
        self.fd = own.open_private_dir(self.state, create=True, owner_uid=os.getuid())
        self.addCleanup(os.close, self.fd)
        self.kernel = PeerKernel()
        self.target = replace(fixture.PROFILE, endpoint_host='192.0.2.9',
                              public_key=base64.b64encode(b'z' * 32).decode())
        self.network = self.make_network()
        self.network.prepare(guard_blocked=True)
        self.initial_rules = list(self.kernel.rules)
        self.initial_nft = json.dumps(self.kernel.nft, sort_keys=True)
        self.initial_fallback = [r for r in self.kernel.routes if r.get('type') == 'unreachable']

    def make_network(self):
        receipt = own.read_receipt(self.fd) if (self.state / 'receipt.json').exists() else None
        return Network(fixture.PROFILE, self.fd, runner=self.kernel,
                       wireguard_root=self.wireguard, owner_uid=os.getuid(), receipt=receipt)

    def assert_anchors(self):
        self.assertEqual(self.kernel.rules, self.initial_rules)
        self.assertEqual(json.dumps(self.kernel.nft, sort_keys=True), self.initial_nft)
        self.assertEqual([r for r in self.kernel.routes if r.get('type') == 'unreachable'],
                         self.initial_fallback)

    def test_switch_preserves_all_packet_level_anchors(self):
        self.network.switch_peer(self.target, guard_blocked=True)
        self.assertTrue(self.network.health().ready)
        self.assertEqual(self.kernel.peer, self.target.public_key)
        self.assert_anchors()
        before = len(self.kernel.calls)
        self.make_network().switch_peer(self.target, guard_blocked=True)
        self.assert_anchors()
        self.assertFalse(any(c[:3] == ('ip', 'link', 'delete') for c in self.kernel.calls[before:]))

    def test_every_kernel_mutation_boundary_recovers_or_refuses_unrecorded_birth(self):
        def mutation(argv):
            return ((argv[0] == 'ip' and any(x in argv for x in ('add', 'set', 'delete'))) or
                    argv[:2] in (('wg', 'setconf'), ('sysctl', '-w'), ('conntrack', '-D')))
        calls = []
        runner = self.kernel
        def observe(argv, **kwargs):
            value = runner(argv, **kwargs)
            if mutation(tuple(argv)): calls.append(tuple(argv))
            return value
        self.network.runner = observe
        self.network.switch_peer(self.target, guard_blocked=True)
        for index, boundary in enumerate(calls):
            with self.subTest(index=index, boundary=boundary[:4]):
                self.setUp()
                kernel, counter = self.kernel, []
                def interrupted(argv, **kwargs):
                    value = kernel(argv, **kwargs)
                    if mutation(tuple(argv)):
                        counter.append(tuple(argv))
                        if len(counter) - 1 == index: raise Died()
                    return value
                self.network.runner = interrupted
                with self.assertRaises(Died):
                    self.network.switch_peer(self.target, guard_blocked=True)
                self.assert_anchors()
                resumed = self.make_network()
                if boundary[:3] == ('ip', 'link', 'add'):
                    # No ifindex was ever recorded. Never adopt that birth.
                    with self.assertRaises(NetworkError):
                        resumed.switch_peer(self.target, guard_blocked=True)
                else:
                    resumed.switch_peer(self.target, guard_blocked=True)
                    self.assertTrue(resumed.health().ready)
                self.assert_anchors()

    def test_unrecorded_private_file_and_directory_are_safely_removed(self):
        for kind in ('private_directory', 'private_file'):
            with self.subTest(kind=kind):
                self.setUp()
                record = self.network._record
                def interrupted(which, name, identity):
                    if which == kind: raise Died()
                    return record(which, name, identity)
                with patch.object(self.network, '_record', side_effect=interrupted):
                    with self.assertRaises(Died):
                        self.network.switch_peer(self.target, guard_blocked=True)
                self.assert_anchors()
                resumed = self.make_network()
                resumed.switch_peer(self.target, guard_blocked=True)
                self.assertTrue(resumed.health().ready)
                self.assertFalse(list(self.wireguard.iterdir()))

    def test_removed_private_objects_before_receipt_forget_replay(self):
        for kind in ('private_file', 'private_directory'):
            with self.subTest(kind=kind):
                self.setUp()
                forget = self.network._forget
                def interrupted(resource):
                    if resource.kind == kind: raise Died()
                    return forget(resource)
                with patch.object(self.network, '_forget', side_effect=interrupted):
                    with self.assertRaises(Died):
                        self.network.switch_peer(self.target, guard_blocked=True)
                self.assert_anchors()
                resumed = self.make_network()
                resumed.switch_peer(self.target, guard_blocked=True)
                self.assertTrue(resumed.health().ready)
                self.assertFalse(list(self.wireguard.iterdir()))

    def test_post_birth_capture_cannot_adopt_a_replacement_interface(self):
        link = next(x for x in self.kernel.links if x['ifname'] == 'wgps0')
        link['ifindex'] += 100
        with self.assertRaises(NetworkError):
            self.network._capture('interface', 'wgps0')
        self.assertIn('interface:wgps0', self.network.health().changed)
        self.assert_anchors()

    def test_unsafe_unrecorded_configuration_is_never_removed(self):
        record = self.network._record
        def interrupted(which, name, identity):
            if which == 'private_file': raise Died()
            return record(which, name, identity)
        with patch.object(self.network, '_record', side_effect=interrupted):
            with self.assertRaises(Died):
                self.network.switch_peer(self.target, guard_blocked=True)
        config = next(self.wireguard.glob('*/wg.conf'))
        config.chmod(0o644)
        with self.assertRaises((NetworkError, own.OwnershipError)):
            self.make_network().switch_peer(self.target, guard_blocked=True)
        self.assertTrue(config.exists())
        self.assert_anchors()

    def test_underlay_loss_after_binding_leaves_fences_for_later_repair(self):
        from wg_program_split.network import UnderlayUnavailable
        record = self.network._record
        def lose_underlay(kind, name, identity):
            record(kind, name, identity)
            if kind == 'nft_table':
                self.kernel.fail_prefix = ('ip', '-j', '-4', 'route', 'get')
        with patch.object(self.network, '_record', side_effect=lose_underlay):
            with self.assertRaises(UnderlayUnavailable):
                self.network.switch_peer(self.target, guard_blocked=True)
        self.assert_anchors()
        self.kernel.fail_prefix = None
        resumed = self.make_network()
        resumed.switch_peer(self.target, guard_blocked=True)
        self.assertTrue(resumed.health().ready)

    def test_interruptions_after_old_route_or_interface_deletion_resume(self):
        for prefix in [('ip', '-4', 'route', 'delete'), ('ip', 'link', 'delete')]:
            with self.subTest(prefix=prefix):
                runner = self.kernel
                fired = []

                def interrupted(argv, **kwargs):
                    result = runner(argv, **kwargs)
                    if tuple(argv[:len(prefix)]) == prefix and not fired:
                        fired.append(True)
                        raise Died()
                    return result

                self.network = self.make_network()
                self.network.runner = interrupted
                # Switch back to the original peer between scenarios.
                target = self.target if self.kernel.peer == fixture.PUBLIC else fixture.PROFILE
                self.network.profile = self.target if self.kernel.peer != fixture.PUBLIC else fixture.PROFILE
                with self.assertRaises(Died):
                    self.network.switch_peer(target, guard_blocked=True)
                self.assert_anchors()
                resumed = self.make_network()
                if target == fixture.PROFILE:
                    resumed.profile = self.target
                resumed.switch_peer(target, guard_blocked=True)
                self.assertTrue(resumed.health().ready)
                self.assert_anchors()

    def test_crash_after_profile_binding_resumes_against_target_receipt(self):
        record = self.network._record

        def interrupted(kind, name, identity):
            record(kind, name, identity)
            if kind == 'nft_table':
                raise Died()

        with patch.object(self.network, '_record', side_effect=interrupted):
            with self.assertRaises(Died):
                self.network.switch_peer(self.target, guard_blocked=True)
        self.assert_anchors()
        resumed = self.make_network()
        resumed.switch_peer(self.target, guard_blocked=True)
        self.assertTrue(resumed.health().ready)
        self.assert_anchors()

    def test_foreign_firewall_and_incompatible_profile_are_refused(self):
        with self.assertRaises(NetworkError):
            self.network.switch_peer(replace(self.target, resolver='10.20.0.8'), guard_blocked=True)
        self.kernel.nft['nftables'].append({'rule': {'family': 'inet', 'table': 'wg_program_split',
                                                  'chain': 'egress', 'expr': [{'drop': None}]}})
        with self.assertRaises(NetworkError):
            self.network.switch_peer(self.target, guard_blocked=True)
        self.assertEqual(self.kernel.peer, fixture.PUBLIC)

    def test_explicit_disable_after_binding_commit_does_not_need_underlay(self):
        record = self.network._record

        def interrupted(kind, name, identity):
            record(kind, name, identity)
            if kind == 'nft_table':
                raise Died()

        with patch.object(self.network, '_record', side_effect=interrupted):
            with self.assertRaises(Died):
                self.network.switch_peer(self.target, guard_blocked=True)
        self.kernel.fail_prefix = ('ip', '-j', '-4', 'route', 'get')
        receipt = self.make_network().cancel_peer_change(self.target, guard_blocked=True)
        self.assertEqual(receipt.resources, ())
        self.assertFalse(any(x['ifname'] == 'wgps0' for x in self.kernel.links))


if __name__ == '__main__':
    unittest.main()
