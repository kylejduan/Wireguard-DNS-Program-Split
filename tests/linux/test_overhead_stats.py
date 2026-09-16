# SPDX-License-Identifier: GPL-3.0-or-later
"""Measurement analysis must preserve noise, pair rounds, and reject errors."""
import unittest

import overhead_stats as stats


def row(round_id, arm, shift=0, noisy=False):
    return {'round': round_id, 'arm': arm, 'case': 'socket_udp',
            'counter_noise': noisy, 'planned': 100, 'cpu_ns': 10000,
            'samples': [[i + shift, 0, 0, 0] for i in range(100)]}


class OverheadStatisticsTests(unittest.TestCase):
    def test_schedule_balances_every_arm_position_without_timing_feedback(self):
        schedule = stats.schedule(6, 42)
        self.assertEqual(schedule, stats.schedule(6, 42))
        self.assertEqual(len({tuple(order) for order in schedule}), 6)
        for arm in stats.ARMS:
            for position in range(3):
                self.assertEqual(sum(order[position] == arm for order in schedule), 2)
        with self.assertRaises(ValueError): stats.schedule(7, 42)

    def test_paired_added_quantile_shift_has_known_value_and_keeps_noisy_rows(self):
        rows = [row(i, arm, shift, noisy=i % 2 == 0)
                for i in range(6) for arm, shift in zip(stats.ARMS, (0, 200, 50))]
        result = stats.summarize(rows, seed=12)
        case = result['socket_udp']
        self.assertEqual(case['arms']['candidate']['operations'], 600)
        for percentile in ('p50', 'p95', 'p99'):
            delta = case['comparisons']['candidate-minus-absent'][percentile]
            self.assertEqual((delta['mean_ns'], delta['low95_ns'], delta['high95_ns']), (50, 50, 50))
            self.assertEqual(case['comparisons']['candidate-minus-baseline'][percentile]['mean_ns'], -150)

    def test_tail_outliers_are_not_removed_by_counter_noise(self):
        rows = [row(i, arm) for i in range(6) for arm in stats.ARMS]
        for item in rows:
            if item['arm'] == 'candidate':
                item['counter_noise'] = True
                item['samples'][-2:] = [[2000000, 4000000, 0, 0]] * 2
        result = stats.summarize(rows)
        self.assertEqual(result['socket_udp']['arms']['candidate']['p99_ns'], 2000000)
        self.assertEqual(result['socket_udp']['arms']['candidate']['max_lateness_ns'], 4000000)

    def test_resource_summary_uses_measured_duration_and_reports_peer_separately(self):
        samples = []
        for arm in stats.ARMS:
            for index in range(6):
                samples.append({'arm': arm, 'round': index, 'clock_ticks_per_second': 100,
                    'samples': [{'monotonic_ns': t * 1000000000,
                        'controller': {'usage_usec': t * 25000, 'memory_current': 1000 + t},
                        'peer': {'ticks': t * 2}, 'direct_peer': {'ticks': t},
                        'guest_active_ticks': t * 20} for t in (0, 10)]})
        result = stats.summarize_resources(samples)
        for arm in stats.ARMS:
            self.assertEqual(result[arm]['measured_seconds'], 60)
            self.assertEqual(result[arm]['controller_percent_one_core'], 2.5)
            self.assertEqual(result[arm]['vpn_peer_percent_one_core'], 2)
            self.assertEqual(result[arm]['direct_peer_percent_one_core'], 1)
            self.assertEqual(result[arm]['controller_max_memory_bytes'], 1010)

    def test_daemon_stopped_dead_or_restarted_cannot_pass_resource_validation(self):
        expected = {'pid': 123, 'starttime': 44, 'state': 'S', 'ticks': 2}
        stats.validate_daemon([{'daemon': dict(expected)}], expected)
        for changed in ({'state': 'T'}, {'state': 'Z'}, {'starttime': 45}, {'pid': 124}, {'missing': True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                stats.validate_daemon([{'daemon': {**expected, **changed}}], expected)

    def test_startup_requires_fresh_daemon_readiness_not_inherited_ready_state(self):
        status = {'state': 'ready', 'protection_verified': True, 'restart_required': [],
                  'restart_boundary_unresolved': False, 'dns_last_checked': 99.0}
        self.assertFalse(stats.fresh_readiness(status, 100.0))
        self.assertFalse(stats.fresh_readiness({**status, 'dns_last_checked': 100.0}, 100.0))
        self.assertTrue(stats.fresh_readiness({**status, 'dns_last_checked': 101.0}, 100.0))
        for change in ({'state': 'blocked'}, {'protection_verified': False},
                       {'dns_last_checked': float('inf')}, {'restart_boundary_unresolved': True}):
            self.assertFalse(stats.fresh_readiness({**status, 'dns_last_checked': 101.0, **change}, 100.0))

    def test_errors_incomplete_pairs_and_duplicate_rounds_are_failures(self):
        rows = [row(i, arm) for i in range(6) for arm in stats.ARMS]
        bad = [dict(item) for item in rows]
        bad[0]['samples'] = [[1, 0, 110, 0]]
        for invalid in (bad, rows[:-1], rows + [rows[0]]):
            with self.assertRaises(ValueError): stats.summarize(invalid)


if __name__ == '__main__': unittest.main()
