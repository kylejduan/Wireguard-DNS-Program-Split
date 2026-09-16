# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned IPv6 setup must settle before strict fixture snapshots start."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import fixtures


class FixtureReadinessTests(unittest.TestCase):
    def run_wait(self, states, route_states, **kwargs):
        addresses, routes, calls = iter(states), iter(route_states), []
        def run(*argv):
            calls.append(argv)
            if 'sysctl' in argv: return SimpleNamespace(stdout='0\n')
            if 'link' in argv: value = [{'ifindex': 7, 'ifname': 'owned-test'}]
            elif 'address' in argv:
                value = [{'ifindex': 7, 'ifname': 'owned-test', 'addr_info': next(addresses)}]
            else: value = next(routes)
            return SimpleNamespace(stdout=json.dumps(value))
        with patch.object(fixtures, 'run', side_effect=run), patch.object(fixtures.time, 'sleep') as sleep:
            fixtures.wait_ipv6_ready('owned-test', **kwargs)
        return calls, sleep.call_count

    def test_waits_for_empty_tentative_and_local_route_publication(self):
        ready = {'family': 'inet6', 'local': 'fe80::1', 'scope': 'link'}
        calls, sleeps = self.run_wait([[], [{**ready, 'tentative': True}],
            [{**ready, 'flags': ['tentative']}], [ready], [ready]],
            [[], [{'type': 'local', 'dst': 'fe80::1', 'dev': 'owned-test'}]])
        self.assertEqual(sleeps, 4)
        self.assertTrue(all('owned-test' in call or 'sysctl' in call for call in calls))

    def test_dad_failure_fails_instead_of_accepting_a_non_tentative_address(self):
        for flag in ({'dadfailed': True}, {'flags': ['dadfailed']}):
            with self.subTest(flag=flag), self.assertRaisesRegex(RuntimeError, 'duplicate address'):
                self.run_wait([[{'family': 'inet6', 'local': 'fe80::1', **flag}]], [])

    def test_peer_wait_uses_only_the_owned_namespace_device(self):
        calls, sleeps = self.run_wait([[{'family': 'inet6', 'local': 'fe80::1'}]],
            [[{'type': 'local', 'dst': 'fe80::1/128'}]], namespace='owned-peer')
        self.assertEqual(sleeps, 0)
        self.assertTrue(all('owned-peer' in call for call in calls))

    def test_tentative_address_times_out_without_changing_host_ipv6(self):
        with patch.object(fixtures.time, 'monotonic', side_effect=[0, 0, 6]):
            with self.assertRaisesRegex(RuntimeError, 'did not finish'):
                self.run_wait([[{'family': 'inet6', 'local': 'fe80::1', 'tentative': True}]], [])


if __name__ == '__main__': unittest.main()
