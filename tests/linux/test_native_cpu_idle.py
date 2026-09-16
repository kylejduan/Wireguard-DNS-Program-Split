# SPDX-License-Identifier: GPL-3.0-or-later
"""NO_HZ accounting uses timed idle, with explicit capacity and scope bounds."""
import copy
import gzip
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import native_overhead_cpu as cpu
import test_native_overhead_unit as legacy

# Two online CPUs, CONFIG_HZ=250 confirmed by 125 jiffies in 0.5 s.
SOURCE = {'valid': True, 'online': '0-1', 'cpus': {'cpu0': 1, 'cpu1': 1},
          'kernel_config': {'path': '/boot/config-test', 'HZ': '250'}, 'nohz_full': None, 'cmdline_timing': [],
          'tick_rate': {'jiffies': [0, 125], 'ns': [[0, 1000], [500000000, 500001000]]}}


def stat_text(cpus, ctxt):
    return ''.join(name + ' ' + ' '.join(map(str, values)) + '\n' for name, values in cpus.items()) + 'ctxt %d\n' % ctxt


def seal(row):
    """Record the sample's /proc/stat read plus one consistent re-read, as cpu.sample does."""
    start, end = row.setdefault('stat_ns', [row['read_start_ns'], row['read_start_ns'] + 400])
    read = {'ns': [start, end], 'raw': stat_text(row['cpus'], row['ctxt'])}
    row['stat_consistency'] = {'reads': [read, {'ns': [end + 100, end + 500], 'raw': read['raw']}],
                               'checks': [{'reads': [0, 1], 'errors': []}], 'accepted': 0, 'bound': cpu.STAT_READS}
    return row


def precise(row, usage):
    row['cpus'] = {name: list(values) for name, values in row['cpus'].items()}  # Unshare CPU rows.
    row['nonidle_source'] = copy.deepcopy(SOURCE)
    row['boottime_ns'] = row['read_start_ns']
    row['processes'] = {'harness': {'pid': 10, 'starttime': 1, 'user_ticks': 0,
                                    'system_ticks': 0, 'cgroup': '0::/fixture\n'}}
    row['cgroups'] = {'fixture': {'path': '/sys/fs/cgroup/fixture', 'inode': 1, 'usage_usec': usage,
                                  'descendants': 0, 'members': [[10, 1], [11, 10]]}}
    return seal(row)


def samples():
    fixture = legacy.AccountingTests()
    # Precise idle advances by 18 seconds across two CPUs; tick busy advances
    # by only 1.2 seconds. The missing .8 seconds is not idle or zero-cost work.
    return precise(fixture.sample(0), 0), precise(fixture.sample(10, 40, 50, 1870), 1000000)


def timer_list(cpus, nohz=1):
    body = ''.join('cpu: %d\n clock 0:\n  .index:      0\nactive timers:\n'
                   '  .hres_active    : 1\n  .nohz           : %d\n  .tick_stopped   : 0\n'
                   'jiffies: 1\n\n' % (n, nohz) for n in cpus)
    return 'Timer List Version: v0.10\n\n' + body + 'Tick Device: mode:     1\nPer CPU device: 0\n'


class IdleAccountingTests(unittest.TestCase):
    def test_tick_aliasing_does_not_invalidate_precise_nonidle_time(self):
        first, last = samples()
        value = cpu.account(first, last, client_cpu_seconds=.8)
        self.assertTrue(value['valid'], value)
        self.assertEqual(value['host_cpu_method'], 'nohz-idle-complement')
        self.assertAlmostEqual(value['host_busy_seconds'], 2)
        self.assertAlmostEqual(value['tick_busy_seconds'], 1.2)
        self.assertAlmostEqual(value['tick_deficit_seconds'], .8)
        self.assertAlmostEqual(value['scoped_seconds'], 1)
        self.assertAlmostEqual(value['residual_seconds'], 1)

    def test_iowait_reclassification_is_not_cpu_execution(self):
        first, last = samples()
        for name in first['cpus']:
            first['cpus'][name][4] += 10; first['cpus'][name][3] -= 10
        seal(first)
        self.assertTrue(cpu.account(first, last)['valid'])
        self.assertAlmostEqual(cpu.account(first, last)['host_busy_seconds'], 2)

    def test_unverified_source_idle_regression_capacity_suspend_and_scope_fail(self):
        first, last = samples()
        variants = []
        bad = copy.deepcopy(last); bad['nonidle_source']['valid'] = False; variants.append(bad)
        bad = copy.deepcopy(last); bad['cpus']['cpu0'][3] = 900; variants.append(seal(bad))
        bad = copy.deepcopy(last); bad['cpus']['cpu0'][3] = 2100; variants.append(seal(bad))
        bad = copy.deepcopy(last); bad['boottime_ns'] += 1000000000; variants.append(bad)
        bad = copy.deepcopy(last); bad['boottime_ns'] += 2000000; variants.append(bad)
        bad = copy.deepcopy(last); bad['online'] = '0'; variants.append(bad)
        bad = copy.deepcopy(last); bad['cgroups']['fixture']['usage_usec'] = 4000000; variants.append(bad)
        for changed in variants:
            with self.subTest(changed=changed): self.assertFalse(cpu.account(first, changed)['valid'])
        self.assertFalse(cpu.account(first, last, client_cpu_seconds=2)['valid'])

    def test_idle_capacity_admits_only_rounding_and_read_skew(self):
        # Per CPU: two USER_HZ units (.02 s) plus half the stat read skew.
        for idle, valid in ((1971, True), (1973, False), (969, True), (967, False)):
            first, last = samples()
            last['cpus']['cpu0'][3] = idle
            with self.subTest(idle=idle): self.assertEqual(cpu.account(first, seal(last))['valid'], valid)

    def test_busy_uses_aggregate_row_not_per_cpu_truncation(self):
        first, last = samples()
        for name in ('cpu0', 'cpu1'): last['cpus'][name][3] = 1869  # Rows sum .02 s above aggregate busy.
        value = cpu.account(first, seal(last))
        self.assertTrue(value['valid'], value)
        self.assertAlmostEqual(value['host_busy_seconds'], 2)
        self.assertLess(value['host_busy_tolerance_seconds'], .021)

    def test_elapsed_uses_stat_bracket_not_whole_sampler_bracket(self):
        first, last = samples()
        first.update(read_end_ns=50000000, stat_ns=[0, 1000])
        last.update(read_end_ns=10200000000, stat_ns=[10000000000, 10000001000])
        value = cpu.account(seal(first), seal(last))
        self.assertTrue(value['valid'], value)
        self.assertAlmostEqual(value['elapsed_seconds'], 10)
        self.assertAlmostEqual(value['host_busy_seconds'], 2)

    def test_mid_series_idle_jump_invalidates_series(self):
        fixture = legacy.AccountingTests()
        first, last = samples()
        middle = precise(fixture.sample(5, 25, 35, 1420), 500000)
        self.assertTrue(cpu.account_series([first, middle, last])['valid'])
        # cpu0 reports 5.1 s idle in 5 s, then a correspondingly short next interval.
        middle['cpus']['cpu0'][3] += 60; middle['cpus']['cpu'][3] += 60
        self.assertTrue(cpu.account(first, last)['valid'])
        self.assertFalse(cpu.account_series([first, seal(middle), last])['valid'])

    def test_suspend_below_read_skew_plus_millisecond_is_admitted(self):
        first, last = samples()
        last['boottime_ns'] += 500000
        self.assertTrue(cpu.account(first, last)['valid'])

    def test_online_inventory_must_match_stat_rows_and_source(self):
        first, last = samples()
        for row in (first, last): row['online'] = '0,2'
        self.assertFalse(cpu.account(first, last)['valid'])
        first, last = samples()
        for row in (first, last): row['nonidle_source']['online'] = '0-2'
        self.assertFalse(cpu.account(first, last)['valid'])

    def test_observed_process_in_fixture_is_not_counted_twice(self):
        first, last = samples()
        for row, ticks in ((first, 0), (last, 100)):
            row['processes']['peer'] = {'pid': 12, 'starttime': 1, 'user_ticks': ticks,
                                       'system_ticks': 0, 'cgroup': '0::/fixture\n'}
        value = cpu.account(first, last)
        self.assertTrue(value['valid'], value)
        self.assertEqual(value['scoped_seconds'], 1)
        last['processes']['peer']['cgroup'] = '0::/foreign\n'
        self.assertFalse(cpu.account_series([first, last])['valid'])

    def test_fixture_must_remain_one_sampled_runner_tree_without_child_cgroups(self):
        first, last = samples()
        self.assertTrue(cpu.account(first, last)['valid'])
        foreign = copy.deepcopy(last); foreign['cgroups']['fixture']['members'].append([99, 1])
        nested = copy.deepcopy(last); nested['cgroups']['fixture']['descendants'] = 1
        unsampled = copy.deepcopy(last); del unsampled['cgroups']['fixture']['members']
        uncounted = copy.deepcopy(last); del uncounted['cgroups']['fixture']['descendants']
        for changed in (foreign, nested, unsampled, uncounted):
            with self.subTest(changed=changed):
                self.assertFalse(cpu.account(first, changed)['valid'])
                self.assertFalse(cpu.account_series([first, changed, last])['valid'])
        self.assertIn('fixture membership not sampled', cpu.account(first, unsampled)['errors'])
        stray, rootless = copy.deepcopy(first), copy.deepcopy(last)
        for row in (stray, rootless): del row['processes']['harness']
        self.assertFalse(cpu.account(stray, rootless)['valid'])

    def test_fixture_is_the_only_scope_for_member_cpu(self):
        first, last = samples()
        for row in (first, last):
            row['cgroups']['inner'] = {'path': '/sys/fs/cgroup/fixture/inner', 'inode': 2, 'usage_usec': 0}
        self.assertFalse(cpu.account(first, last)['valid'])
        first, last = samples()
        for row in (first, last): del row['cgroups']['fixture']
        self.assertFalse(cpu.account(first, last)['valid'])

    def test_legacy_raw_data_remains_strict_and_modes_cannot_mix(self):
        fixture = legacy.AccountingTests()
        first, last = fixture.sample(0), fixture.sample(10, 40, 50, 1870)
        value = cpu.account(first, last)
        self.assertEqual(value['host_cpu_method'], 'legacy-tick-sum')
        self.assertIn('tick growth inconsistent with elapsed time: cpu', value['errors'])
        self.assertIsNone(value['kernel_hz'])
        precise_first, _ = samples()
        self.assertFalse(cpu.account(precise_first, last)['valid'])

    def test_scheduler_counters_are_diagnostic_only(self):
        first, last = samples()
        for row, run, slices in ((first, 0, 0), (last, 900000000, 40)):
            row['schedstat'] = {'version': 17, 'cpus': {n: [0] * 6 + [run, 0, slices] for n in ('cpu0', 'cpu1')}}
        value = cpu.account(first, last)
        self.assertTrue(value['valid'], value)
        self.assertAlmostEqual(value['scheduler']['task_residence_seconds'], 1.8)
        self.assertAlmostEqual(value['scheduler']['nonidle_minus_task_seconds'], .2)
        last['schedstat']['cpus']['cpu0'][6] = -1
        value = cpu.account(first, last)
        self.assertTrue(value['valid'], value)
        self.assertEqual(value['scheduler']['errors'], ['counter inventory/regression: cpu0'])
        last['schedstat'] = {'error': 'FileNotFoundError: absent'}
        self.assertEqual(cpu.account(first, last)['scheduler'], {'available': False})

    def test_unreadable_schedstat_does_not_abort_sampling(self):
        with mock.patch.object(cpu.Path, 'read_text', side_effect=FileNotFoundError('absent')):
            self.assertIn('error', cpu.schedstat())

    def test_sampler_cost_is_reported_for_the_series(self):
        first, last = samples()
        first['sampler_cpu_ns'], last['sampler_cpu_ns'] = 3000000, 1000000
        self.assertAlmostEqual(cpu.account_series([first, last])['sampler_cpu_seconds'], .004)

    def test_nohz_readback_requires_each_online_cpu(self):
        raw = 'cpu: 0\n .hres_active : 1\n .nohz : 1\ncpu: 1\n .hres_active : 1\n .nohz : 1\n'
        self.assertTrue(cpu.parse_nohz(raw, '0-1')['valid'])
        for changed in (raw.replace('cpu: 1', 'cpu: 0'), raw.replace('.nohz : 1', '.nohz : 0'), '', raw[:40]):
            self.assertFalse(cpu.parse_nohz(changed, '0-1')['valid'])

    def test_nohz_fields_are_read_only_from_per_cpu_blocks(self):
        self.assertTrue(cpu.parse_nohz(timer_list(range(4)), '0-3')['valid'])
        self.assertFalse(cpu.parse_nohz(timer_list(range(4)), '0-1,3')['valid'])
        self.assertFalse(cpu.parse_nohz(timer_list(range(4), nohz=0), '0-3')['valid'])
        # Pre-6.9 kernels print nohz_mode; that format fails closed.
        self.assertFalse(cpu.parse_nohz(timer_list(range(2)).replace('.nohz    ', '.nohz_mode'), '0-1')['valid'])
        # A missing last-CPU field must not be satisfied by the device section.
        raw = timer_list(range(2)).replace('  .nohz           : 1\n  .tick_stopped   : 0\njiffies: 1\n\nTick',
                                           '  .tick_stopped   : 0\njiffies: 1\n\nTick')
        raw += ' .nohz : 1\n'
        self.assertEqual(cpu.parse_nohz(raw, '0-1')['cpus']['cpu1']['nohz'], None)
        self.assertFalse(cpu.parse_nohz(raw, '0-1')['valid'])

    def test_members_reads_parent_and_skips_reaped_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'cgroup.stat').write_text('nr_descendants 0\nnr_dying_descendants 3\n')
            (path / 'cgroup.procs').write_text('%d\n%d\n' % (os.getpid(), 4194305))
            self.assertEqual(cpu.members(path), {'descendants': 0, 'members': [[os.getpid(), os.getppid()]]})


class SourceReadConsistencyTests(unittest.TestCase):
    CPUS = {'cpu': [10, 0, 20, 1940, 0, 0, 0, 0, 0, 0], 'cpu0': [5, 0, 10, 970, 0, 0, 0, 0, 0, 0],
            'cpu1': [5, 0, 10, 970, 0, 0, 0, 0, 0, 0]}

    def read(self, at, idle=(0, 0, 0), iowait=(0, 0, 0), width=1000):
        cpus = copy.deepcopy(self.CPUS)
        for name, extra, wait in zip(('cpu', 'cpu0', 'cpu1'), idle, iowait):
            cpus[name][3] += extra; cpus[name][4] += wait
        return {'ns': [at, at + width], 'raw': stat_text(cpus, 7)}

    def reader(self, reads):
        reads, calls = iter(reads), []
        def read():
            calls.append(1); return next(reads)
        return read, calls

    def test_normal_quantization_and_reclassification_are_accepted(self):
        base = self.read(0)
        for later, consistent in ((self.read(2000, (-1, -1, 0)), True),                  # Split truncation.
                                  (self.read(2000, (-10, -10, 0), (10, 10, 0)), True),    # idle -> iowait.
                                  (self.read(20000000, (6, 2, 2)), True),                 # 2 units + 20 ms span.
                                  (self.read(2000, (-2, -2, 0)), False),
                                  (self.read(2000, (0, 3, 0)), False),
                                  (self.read(500, (0, 0, 0)), False)):                    # Overlapping brackets.
            with self.subTest(later=later['raw'], at=later['ns']):
                self.assertEqual(not cpu.stat_violations(base, later, 100), consistent)

    def test_injected_split_race_is_retried_and_every_read_retained(self):
        raced = self.read(3000, (60, 60, 0))  # One idle period double-counted on cpu0.
        read, calls = self.reader([self.read(0), raced, self.read(6000), self.read(9000)])
        evidence = cpu.read_stat(100, read)
        self.assertEqual(len(calls), 4)
        self.assertEqual(evidence['accepted'], 2)
        self.assertEqual([bool(check['errors']) for check in evidence['checks']], [True, True, False])
        self.assertEqual(evidence['reads'][1], raced)
        read, calls = self.reader([self.read(0), self.read(3000), self.read(6000)])
        self.assertEqual(cpu.read_stat(100, read)['accepted'], 0)
        self.assertEqual(len(calls), 2)

    def test_exhausted_attempts_fail_closed_without_more_reads(self):
        reads = [self.read(3000 * n, (60 * (n % 2), 60 * (n % 2), 0)) for n in range(10)]
        read, calls = self.reader(reads)
        evidence = cpu.read_stat(100, read)
        self.assertEqual((len(calls), evidence['accepted'], len(evidence['checks'])), (cpu.STAT_READS, None, cpu.STAT_READS - 1))
        first, last = samples()
        last['stat_consistency'] = evidence
        self.assertIn('/proc/stat reads inconsistent after 4 bounded attempts', cpu.account(first, last)['errors'])

    def test_missing_insufficient_or_mismatched_evidence_fails(self):
        first, last = samples()
        variants = {}
        variants['missing'] = copy.deepcopy(last); del variants['missing']['stat_consistency']
        variants['single read'] = copy.deepcopy(last); variants['single read']['stat_consistency']['accepted'] = 1
        variants['over bound'] = copy.deepcopy(last)
        variants['over bound']['stat_consistency']['reads'] *= 3
        variants['unsealed'] = copy.deepcopy(last); variants['unsealed']['cpus']['cpu1'][0] += 1
        variants['moved bracket'] = copy.deepcopy(last); variants['moved bracket']['stat_ns'][0] -= 1
        # A decision recorded as consistent is rechecked against the retained re-read.
        variants['false decision'] = copy.deepcopy(last)
        check = variants['false decision']['stat_consistency']['reads'][1]
        check['raw'] = check['raw'].replace('cpu0 40 0 50 1870', 'cpu0 40 0 50 1930')
        expected = {'missing': 'missing or malformed', 'single read': 'insufficient', 'over bound': 'declared bound',
                    'unsealed': 'differs from its accepted', 'moved bracket': 'differs from its accepted',
                    'false decision': 'recheck: idle+iowait outside read span: cpu0'}
        for name, row in variants.items():
            with self.subTest(name=name):
                errors = cpu.account(first, row)['errors']
                self.assertTrue(any(expected[name] in error for error in errors), errors)

    def test_sample_records_accepted_read_and_all_attempts(self):
        reads = [self.read(0), self.read(3000, (60, 60, 0)), self.read(6000), self.read(9000)]
        with mock.patch.object(cpu, 'read_proc_stat', side_effect=reads):
            row = cpu.sample({}, {}, copy.deepcopy(SOURCE))
        self.assertEqual(row['stat_consistency']['reads'], reads)
        self.assertEqual(row['stat_ns'], reads[2]['ns'])
        self.assertEqual((row['cpus'], row['ctxt']), cpu.parse_stat(reads[2]['raw']))
        self.assertNotIn('proc_stat', row)
        self.assertEqual(cpu.stat_evidence_errors(row, 100), [])


class KernelHzTests(unittest.TestCase):
    def test_verified_config_hz_sets_publication_lag(self):
        self.assertEqual(cpu.kernel_hz(SOURCE), (250, None))
        value = cpu.account(*samples())
        self.assertEqual(value['kernel_hz'], 250)
        self.assertAlmostEqual(value['cgroup_publication_lag_seconds'], 2 / 250)

    def test_unknown_or_contradicted_hz_is_explicitly_invalid(self):
        cases = {'kernel CONFIG_HZ unavailable': ('kernel_config', {'errors': ['absent']}),
                 'live jiffies readback unavailable': ('tick_rate', {'error': 'OSError'}),
                 'interval under 0.4 s': ('tick_rate', {'jiffies': [0, 75], 'ns': [[0, 1000], [300000000, 300001000]]}),
                 'rate disagrees': ('tick_rate', {'jiffies': [0, 50], 'ns': [[0, 1000], [500000000, 500001000]]}),
                 'nohz_full': ('nohz_full', '1-3')}
        for reason, (key, value) in cases.items():
            with self.subTest(reason=reason):
                first, last = samples()
                for row in (first, last): row['nonidle_source'][key] = value
                result = cpu.account(first, last)
                self.assertFalse(result['valid'])
                self.assertTrue(any(error.startswith('cgroup publication lag unbounded') and reason in error
                                    for error in result['errors']), result['errors'])
                self.assertIsNone(result['cgroup_publication_lag_seconds'])
        source = dict(SOURCE, cmdline_timing=['nohz_full=1-3'])
        self.assertEqual(cpu.kernel_hz(source)[0], None)

    def test_jiffies_margin_is_three_ticks(self):
        for delta, verified in ((122, True), (128, True), (121, False), (129, False)):
            source = dict(SOURCE, tick_rate=dict(SOURCE['tick_rate'], jiffies=[0, delta]))
            with self.subTest(delta=delta): self.assertEqual(cpu.kernel_hz(source)[0] == 250, verified)

    def test_rate_measurement_may_differ_but_kernel_identity_may_not(self):
        first, last = samples()
        last['nonidle_source']['tick_rate'] = {'jiffies': [9000, 9126], 'ns': [[0, 1000], [500000000, 500002000]]}
        self.assertTrue(cpu.account(first, last)['valid'])
        last['nonidle_source']['kernel_config'] = {'path': '/boot/config-test', 'HZ': '300'}
        self.assertFalse(cpu.account(first, last)['valid'])

    def test_kernel_config_reads_first_available_plain_or_gzip_config(self):
        with tempfile.TemporaryDirectory() as directory:
            text = b'CONFIG_HZ=300\n# CONFIG_NO_HZ_FULL is not set\nCONFIG_NO_HZ_IDLE=y\nCONFIG_IRQ_TIME_ACCOUNTING=y\n'
            compressed = Path(directory, 'config.gz'); compressed.write_bytes(gzip.compress(text))
            missing = Path(directory, 'absent')
            value = cpu.kernel_config([missing, compressed])
            self.assertEqual((value['path'], value['HZ'], value['NO_HZ_FULL'], value['NO_HZ_IDLE'], value['IRQ_TIME_ACCOUNTING']),
                             (str(compressed), '300', None, 'y', 'y'))
            self.assertEqual(value['sha256'], hashlib.sha256(compressed.read_bytes()).hexdigest())
            self.assertEqual(list(cpu.kernel_config([missing])), ['errors'])

    @unittest.skipUnless(Path('/proc/schedstat').exists(), 'schedstat absent')
    def test_live_jiffies_readback_is_bracketed(self):
        rate = cpu.tick_rate(sleep=lambda seconds: None)
        (j0, j1), (a, b) = rate['jiffies'], rate['ns']
        self.assertLessEqual(j0, j1)
        self.assertTrue(a[0] <= a[1] <= b[0] <= b[1])
        self.assertEqual(cpu.kernel_hz(dict(SOURCE, tick_rate=rate))[1], 'jiffies readback interval under 0.4 s')


class DrainBoundaryTests(unittest.TestCase):
    def run_drain(self, pending, planned_end, deadline, interval):
        clock = [0.0]
        def sleep(seconds): clock[0] += seconds
        rows = []
        try:
            _, boundary = cpu.sample_through_drain(pending(clock), lambda: {'at': clock[0]}, planned_end, deadline,
                                                   clock=lambda: clock[0], sleep=sleep, interval=interval, output=rows)
        except TimeoutError: boundary = None
        return rows, boundary

    def test_boundary_sample_lands_at_planned_end(self):
        rows, boundary = self.run_drain(lambda clock: lambda: clock[0] < 1.4, 1.0, 3.0, .3)
        self.assertLessEqual(rows[boundary]['at'] - 1.0, .001)
        self.assertGreaterEqual(rows[boundary]['at'], 1.0)
        self.assertGreaterEqual(rows[-1]['at'], 1.4)

    def test_timeout_appends_final_sample_before_raising(self):
        rows, _ = self.run_drain(lambda clock: lambda: True, 1.0, 2.0, .3)
        self.assertGreaterEqual(rows[-1]['at'], 2.0)


if __name__ == '__main__': unittest.main()
