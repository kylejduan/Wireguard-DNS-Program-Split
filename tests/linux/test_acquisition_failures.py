# SPDX-License-Identifier: GPL-3.0-or-later
"""Modeled errors around every prepare command/publication, not native SIGKILL.

Real private files/receipts and the argv-aware network fixture are reused. An
ambiguous outcome must retain resources; this suite does not demand rollback
after losing exclusive-birth evidence.
"""
from contextlib import contextmanager
import copy
import hashlib
import unittest
from unittest.mock import patch

import test_network as fixtures
from wg_program_split import network, ownership


def mutates(argv):
    return not (argv[0] in ('iptables-legacy-save', 'ip6tables-legacy-save') or
                argv[:2] in (('ip', '-j'), ('nft', '-j'), ('nft', '-c'),
                             ('wg', 'show'), ('sysctl', '-n'), ('conntrack', '-L')))


def state(fixture):
    kernel = fixture.kernel
    files = {}
    for path in sorted(fixture.wireguard.rglob('*')):
        info = path.lstat()
        files[str(path.relative_to(fixture.wireguard))] = {
            'inode': info.st_ino, 'mode': info.st_mode,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None}
    return copy.deepcopy({'links': kernel.links, 'routes': kernel.routes,
                          'rules': kernel.rules, 'rules6': kernel.rules6,
                          'nft': kernel.nft, 'addresses': kernel.addresses,
                          'configured': kernel.configured, 'localnet': kernel.localnet,
                          'conntrack': kernel.conntrack, 'files': files})


@contextmanager
def fixture():
    case = fixtures.NetworkTests(methodName='runTest')
    try:
        case.setUp()
        case.kernel.links.append({'ifindex': 44, 'ifname': 'foreign0', 'mtu': 1500})
        case.kernel.routes.append({'dst': '198.51.100.0/24', 'gateway': '192.0.2.1',
                                   'dev': 'eth0', 'table': 'main'})
        case.kernel.rules.append({'priority': 30000, 'src': 'all', 'table': 12345})
        foreign = case.wireguard / 'foreign.conf'
        foreign.write_text('unrelated fixture-owned configuration\n')
        foreign.chmod(0o600)
        yield case
    finally:
        case.doCleanups()


class Boundaries:
    def __init__(self, fixture, target=None):
        self.fixture, self.target = fixture, target
        self.trace, self.counts = [], {'command': 0, 'receipt': 0}
        self.injected = False
        self.at_failure = None
        self.write = ownership.write_receipt

    def point(self, kind, index, side, description):
        point = (kind, index, side)
        self.trace.append((point, description))
        if point == self.target:
            self.injected = True
            self.at_failure = state(self.fixture)
            error = ownership.OwnershipError if kind == 'receipt' else RuntimeError
            raise error('injected acquisition boundary')

    def runner(self, argv, *, input=None):
        argv = tuple(argv)
        if not mutates(argv):
            return self.fixture.kernel(argv, input=input)
        self.counts['command'] += 1
        index = self.counts['command']
        # Do not store private configuration contents or temporary argv paths.
        description = ' '.join(argv[:4]) if argv[0] != 'wg' else 'wg setconf <owned interface>'
        self.point('command', index, 'before', description)
        result = self.fixture.kernel(argv, input=input)
        self.point('command', index, 'after', description)
        return result

    def publication(self, directory, receipt, **kwargs):
        self.counts['receipt'] += 1
        index = self.counts['receipt']
        description = ','.join(resource.kind + ':' + resource.name for resource in receipt.resources)
        self.point('receipt', index, 'before', description)
        result = self.write(directory, receipt, **kwargs)
        self.point('receipt', index, 'after', description)
        return result


class AcquisitionFailureTests(unittest.TestCase):
    def prepare_trace(self):
        with fixture() as case:
            baseline = state(case)
            boundaries = Boundaries(case)
            case.net.runner = boundaries.runner
            with patch.object(ownership, 'write_receipt', side_effect=boundaries.publication):
                case.net.prepare(guard_blocked=True)
            self.assertTrue(case.net.health().ready)
            trace = list(boundaries.trace)
            # Prove the trace spans creation, configuration and final routing;
            # future added mutating commands are automatically included too.
            commands = [label for (kind, _, side), label in trace if kind == 'command' and side == 'before']
            for prefix in ('ip -4 route add', 'ip -4 rule add', 'nft -f -',
                           'ip link add name', 'ip link set dev', 'ip -4 address add',
                           'wg setconf', 'sysctl -w'):
                self.assertTrue(any(command.startswith(prefix) for command in commands), prefix)
            publications = [label for (kind, _, side), label in trace if kind == 'receipt' and side == 'before']
            for resource in ('route:fallback', 'rule:vpn', 'nft_table:wg_program_split',
                             'conntrack_zone:vpn', 'interface:wgps0', 'private_directory:configuration',
                             'private_file:configuration', 'sysctl:route_localnet', 'route:preferred'):
                self.assertTrue(any(resource in publication for publication in publications), resource)
            case.net.runner = case.kernel
            case.net.disable(guard_blocked=True)
            self.assertEqual(state(case), baseline)
            return trace

    def assert_foreign_preserved(self, case, baseline):
        current = state(case)
        for name in ('links', 'routes', 'rules', 'rules6'):
            for resource in baseline[name]:
                self.assertIn(resource, current[name], name)
        self.assertEqual(current['files']['foreign.conf'], baseline['files']['foreign.conf'])

    def test_every_prepare_mutation_and_receipt_boundary_retains_or_rolls_back_proved_state(self):
        trace = self.prepare_trace()
        retained, rolled_back = [], []
        for point, description in trace:
            with self.subTest(boundary=point, operation=description), fixture() as case:
                baseline = state(case)
                boundaries = Boundaries(case, point)
                case.net.runner = boundaries.runner
                with patch.object(ownership, 'write_receipt', side_effect=boundaries.publication):
                    with self.assertRaises(network.NetworkError) as raised:
                        case.net.prepare(guard_blocked=True)
                self.assertTrue(boundaries.injected, 'prepare failed before reaching the requested boundary')
                self.assertNotIn(fixtures.PRIVATE, str(raised.exception))
                # No exception handler is allowed to delete uncertain live state.
                self.assertEqual(state(case), boundaries.at_failure)
                self.assert_foreign_preserved(case, baseline)
                case.net.runner = case.kernel
                health = case.net.health()
                self.assertFalse(health.ready, 'failed acquisition advertised a complete network')
                receipt_path = case.state / 'receipt.json'
                if receipt_path.exists():
                    self.assertEqual(ownership.read_receipt(case.fd), case.net.receipt)
                    self.assertNotIn(fixtures.PRIVATE, receipt_path.read_text())
                before_rollback = state(case)
                table_missing = 'nft_table:wg_program_split' in health.missing
                if case.net.uncertain or health.changed or ('conntrack_zone:vpn' in health.missing and not table_missing):
                    with self.assertRaises(network.NetworkError):
                        case.net.disable(guard_blocked=True)
                    self.assertEqual(state(case), before_rollback)
                    retained.append(point)
                else:
                    # Only an exact, unambiguous receipt may authorize cleanup.
                    result = case.net.disable(guard_blocked=True)
                    self.assertFalse(result.resources)
                    self.assertEqual(state(case), baseline)
                    rolled_back.append(point)
                self.assert_foreign_preserved(case, baseline)
        self.assertTrue(retained, 'matrix must exercise ambiguous live acquisitions')
        self.assertTrue(rolled_back, 'matrix must exercise recoverable exact receipts')


if __name__ == '__main__':
    unittest.main()
