# SPDX-License-Identifier: GPL-3.0-or-later
"""Peer outage recovery, durable interruption boundaries and legacy compatibility."""
import base64
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_lifecycle as lifecycle
from test_lifecycle import ALLOCATION, PROFILE, Died
from wg_program_split.controller import Controller, ControllerError
from wg_program_split import failover
from wg_program_split.config import parse_profile, ConfigError


BACKUP_KEY = base64.b64encode(b'z' * 32).decode()
POOL = json.dumps({'schema_version': 1, 'peers': [
    {'public_key': BACKUP_KEY, 'endpoint': '192.0.2.2:51820'}]})


class PeerParsingTests(unittest.TestCase):
    def test_trusted_pool_preserves_non_peer_configuration(self):
        primary = parse_profile(PROFILE)
        peers = failover.parse_peers(POOL, primary)
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[1].endpoint_host, '192.0.2.2')
        self.assertEqual(peers[1].private_key, primary.private_key)
        self.assertEqual(peers[1].resolver, primary.resolver)
        self.assertEqual(peers[1].address, primary.address)
        self.assertEqual(peers[1].mtu, primary.mtu)

    def test_rejects_ambiguous_or_unsafe_pools(self):
        invalid = [POOL.replace('192.0.2.2', 'example.com'),
                   POOL.replace('192.0.2.2', '127.0.0.1'),
                   POOL.replace('51820', '65536'),
                   POOL.replace('"schema_version": 1', '"schema_version": true'),
                   '{"schema_version":1,"schema_version":1,"peers":[]}',
                   POOL.replace('"peers":', '"extra": 1, "peers":')]
        obj = json.loads(POOL)
        obj['peers'] *= 8
        invalid.append(json.dumps(obj))
        obj['peers'] = [obj['peers'][0]] * 2
        invalid.append(json.dumps(obj))
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ConfigError):
                failover.parse_peers(text, parse_profile(PROFILE))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.dead = set()
        self.seen = []
        lifecycle.LifecycleTests.setUp(self)
        self.processes = []
        self.pool = self.paths.config / 'failover.json'
        self.pool.write_text(POOL)
        self.pool.chmod(0o600)
        self.addCleanup(patch.stopall)
        patch('wg_program_split.failover.boot_seconds', side_effect=lambda: self.now).start()

    def new_controller(self):
        def probe(profile, allocation):
            self.kernel.events.append('probe')
            self.seen.append(profile)
            if profile.endpoint_host in self.dead:
                raise RuntimeError('simulated peer outage')
            return {'dns': True, 'handshake_recent': True}
        return Controller(paths=self.paths, owner_uid=os.getuid(), kernel=self.kernel,
                          network_factory=self.network_factory, host_check=lambda: None,
                          select_allocation=lambda profile: ALLOCATION, probe=probe,
                          processes=lambda: list(self.processes))

    def network_factory(self, profile, directory_fd, **kwargs):
        instance = self.network.factory(profile, directory_fd, **kwargs)

        def switch_peer(target, *, guard_blocked):
            self.assertTrue(guard_blocked)
            self.assertEqual(self.kernel.state, 'blocked')
            self.kernel.events.append('network-switch')
            return instance.receipt

        instance.switch_peer = switch_peer
        return instance

    def journal(self):
        return json.loads((self.paths.state / 'controller.json').read_text())

    def fail_primary(self):
        self.controller.activate()
        self.dead = {'192.0.2.1'}
        for _ in range(3):
            self.controller.check()

    def test_legacy_profile_and_receipt_identity_are_unchanged(self):
        self.pool.unlink()
        self.controller.activate()
        self.assertNotIn('failover', self.journal())
        self.assertEqual(self.journal()['profile_digest'], hashlib.sha256(PROFILE.encode()).hexdigest())
        self.dead.add('192.0.2.1')
        self.assertEqual(self.controller.check()['state'], 'degraded')
        self.assertNotIn('network-disable', self.kernel.events)

    def test_switch_blocks_before_cleanup_and_retains_pinned_guard(self):
        self.fail_primary()
        self.assertEqual(self.journal()['failover']['active'], 1)
        self.assertTrue(self.journal()['network_started'])
        self.assertEqual(self.kernel.state, 'blocked')
        self.assertNotIn('unload', self.kernel.events)
        self.assertEqual(self.kernel.events.count('load-blocked'), 1)
        self.assertLess(self.kernel.events.index('state-blocked'), self.kernel.events.index('network-switch'))
        status = self.controller.activate()
        self.assertEqual(status['state'], 'ready')
        self.assertTrue(status['protection_verified'])
        self.assertEqual(self.seen[-1].endpoint_host, '192.0.2.2')
        self.dead.clear()
        self.controller.check()
        self.assertEqual(self.journal()['failover']['active'], 1)  # No preemption.

    def test_failures_survive_controller_restarts(self):
        self.controller.activate()
        self.dead.add('192.0.2.1')
        for _ in range(3):
            self.new_controller().check()
        self.assertEqual(self.journal()['failover']['active'], 1)
        self.assertEqual(self.new_controller().activate()['state'], 'ready')

    def test_all_down_is_rate_limited_independently_of_wall_clock(self):
        self.fail_primary()
        self.dead.add('192.0.2.2')
        self.controller.activate()
        with patch('wg_program_split.controller.time.time', return_value=10**12):
            for _ in range(10):
                self.new_controller().check()
        self.assertEqual(self.journal()['failover']['active'], 1)
        self.assertEqual(self.kernel.events.count('network-switch'), 1)
        self.now += failover.SWITCH_INTERVAL
        self.controller.check()
        self.assertEqual(self.journal()['failover']['active'], 0)
        self.assertEqual(self.kernel.state, 'blocked')

    def test_foreign_network_changes_never_trigger_peer_rotation(self):
        self.controller.activate()
        self.dead.add('192.0.2.1')
        self.network.changed = True
        for _ in range(5):
            result = self.controller.check()
        self.assertFalse(result['protection_verified'])
        self.assertEqual(self.journal()['failover']['active'], 0)
        self.assertNotIn('network-disable', self.kernel.events)

    def test_changed_pool_requires_explicit_reconfiguration(self):
        self.controller.activate()
        self.pool.write_text(POOL.replace('192.0.2.2', '192.0.2.3'))
        result = self.controller.check()
        self.assertEqual(result['state'], 'degraded')
        self.assertEqual(self.kernel.state, 'blocked')
        self.assertNotIn('network-disable', self.kernel.events)

    def test_foreign_change_during_probe_does_not_authorize_cleanup(self):
        self.controller.activate()

        def changed_probe(*args):
            self.network.changed = True
            raise RuntimeError('probe failed after foreign change')

        self.controller.probe = changed_probe
        self.controller.check()
        self.assertEqual(self.journal()['failover']['failures'], 0)
        self.assertNotIn('network-disable', self.kernel.events)

    def test_missing_receipt_during_pending_rotation_is_not_adopted(self):
        self.controller.activate()
        path = self.paths.state / 'controller.json'
        journal = self.journal()
        journal['failover']['pending'] = 1
        path.write_text(json.dumps(journal))
        (self.paths.state / 'receipt.json').unlink()
        with self.assertRaises(ControllerError):
            self.controller.activate()
        self.assertEqual(self.kernel.state, 'blocked')
        self.assertEqual(self.kernel.events.count('network-prepare'), 1)

    def test_pool_symlinks_and_public_permissions_are_rejected(self):
        self.controller.activate()
        self.pool.chmod(0o644)
        result = self.controller.check()
        self.assertEqual(result['state'], 'degraded')
        self.assertEqual(self.kernel.state, 'blocked')
        self.pool.unlink()
        self.pool.symlink_to(self.paths.config / 'profile.conf')
        with self.assertRaises(ControllerError):
            self.controller.activate()

    def test_interrupted_rotation_resumes_each_durable_boundary(self):
        for boundary in ('intent', 'selected'):
            with self.subTest(boundary=boundary):
                # Complete the previous scenario before setting up another rotation.
                self.dead.clear()
                self.controller.activate()
                active = self.journal()['failover']['active']
                self.now += 100
                self.dead = {self.seen[-1].endpoint_host}
                self.controller.check()
                self.controller.check()
                original_save = self.controller._save

                def save(state, journal, identity):
                    result = original_save(state, journal, identity)
                    rotation = journal['failover']
                    if ((boundary == 'intent' and rotation['pending'] is not None and journal['network_started']) or
                            (boundary == 'selected' and rotation['active'] != active and rotation['pending'] is None)):
                        raise Died()
                    return result

                with patch.object(self.controller, '_save', side_effect=save):
                    with self.assertRaises(Died):
                        self.controller.check()
                self.assertEqual(self.kernel.state, 'blocked')
                self.controller = self.new_controller()
                self.assertEqual(self.controller.activate()['state'], 'ready')
                self.assertNotEqual(self.journal()['failover']['active'], active)
                self.assertNotIn('unload', self.kernel.events)

    def test_unsafe_pending_index_is_refused(self):
        self.controller.activate()
        path = self.paths.state / 'controller.json'
        journal = self.journal()
        journal['failover']['pending'] = 7
        path.write_text(json.dumps(journal))
        with self.assertRaises(ControllerError):
            self.controller.activate()
        self.assertNotIn('network-disable', self.kernel.events)


if __name__ == '__main__':
    unittest.main()
