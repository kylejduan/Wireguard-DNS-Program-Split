# SPDX-License-Identifier: GPL-3.0-or-later
"""Native /proc accounting with explicit read skew, hotplug and drain validity."""
import gzip
import hashlib
import os
from pathlib import Path
import re
import time
import uuid

from overhead_stats import cgroup_sample

# /proc/stat reads per precise sample. This retries the source read only; the
# workload window is never repeated and no sample is discarded.
STAT_READS = 4
CONFIG_KEYS = ('HZ', 'NO_HZ_IDLE', 'NO_HZ_FULL', 'HIGH_RES_TIMERS', 'IRQ_TIME_ACCOUNTING', 'TICK_CPU_ACCOUNTING',
               'VIRT_CPU_ACCOUNTING_GEN', 'PARAVIRT_TIME_ACCOUNTING', 'SCHEDSTATS', 'SCHED_CLASS_EXT')
TIMING_ARGS = ('nohz', 'nohz_full', 'isolcpus', 'rcu_nocbs', 'tsc', 'clocksource')


def process(pid):
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    status = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines())
    return {'pid': pid, 'starttime': int(fields[19]), 'state': fields[0],
            'user_ticks': int(fields[11]), 'system_ticks': int(fields[12]),
            'voluntary_ctxt': int(status['voluntary_ctxt_switches']),
            'involuntary_ctxt': int(status['nonvoluntary_ctxt_switches']),
            'cgroup': Path('/proc', str(pid), 'cgroup').read_text()}


def members(path):
    """Child-cgroup count and [pid, ppid] of each live process in a cgroup."""
    path = Path(path)
    stat = dict(line.split() for line in (path / 'cgroup.stat').read_text().splitlines())
    rows = []
    for pid in map(int, (path / 'cgroup.procs').read_text().split()):
        try: rows.append([pid, int(Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()[1])])
        except (FileNotFoundError, ProcessLookupError): pass  # Exited and reaped after listing.
    return {'descendants': int(stat['nr_descendants']), 'members': rows}


def schedstat():
    try:
        rows = [line.split() for line in Path('/proc/schedstat').read_text().splitlines()]
        return {'version': int(rows[0][1]),
                'cpus': {row[0]: list(map(int, row[1:])) for row in rows if row[0].startswith('cpu')}}
    except (OSError, IndexError, ValueError) as error: return {'error': type(error).__name__ + ': ' + str(error)}


def parse_stat(raw):
    rows = [line.split() for line in raw.splitlines()]
    return ({row[0]: list(map(int, row[1:])) for row in rows if row and row[0].startswith('cpu')},
            next(int(row[1]) for row in rows if row and row[0] == 'ctxt'))


def read_proc_stat():
    start = time.monotonic_ns()
    raw = Path('/proc/stat').read_text()
    return {'ns': [start, time.monotonic_ns()], 'raw': raw}


def stat_violations(a, b, hz):
    """Idle+iowait between two back-to-back reads must fit their combined span.

    Idle and iowait truncate separately, so an honest per-row delta lies within
    two USER_HZ units of [0, rows x span]. An idle/iowait split race in either
    read that is larger than that is rejected; smaller ones look like rounding.
    """
    if not a['ns'][0] <= a['ns'][1] <= b['ns'][0] <= b['ns'][1]: return ['read brackets overlap or regress']
    (left, _), (right, _) = parse_stat(a['raw']), parse_stat(b['raw'])
    if set(left) != set(right) or 'cpu' not in left: return ['CPU inventory changed between reads']
    span, rows, errors = (b['ns'][1] - a['ns'][0]) * hz / 1e9, len(left) - 1, []
    for name, x in left.items():
        y = right[name]
        if len(x) != len(y) or len(x) < 8 or any(q < p for i, (p, q) in enumerate(zip(x, y)) if i not in (3, 4)):
            errors.append('field inventory or regression: ' + name); continue
        if not -2 < y[3] + y[4] - x[3] - x[4] < span * (rows if name == 'cpu' else 1) + 2:
            errors.append('idle+iowait outside read span: ' + name)
    return errors


def read_stat(hz, reader=None, attempts=STAT_READS):
    """Read until two consecutive reads agree, at most `attempts` reads. Every read is kept."""
    reader = reader or read_proc_stat
    evidence = {'reads': [reader()], 'checks': [], 'accepted': None, 'bound': attempts}
    while len(evidence['reads']) < attempts:
        evidence['reads'].append(reader())
        index = len(evidence['reads']) - 2
        errors = stat_violations(evidence['reads'][index], evidence['reads'][index + 1], hz)
        evidence['checks'].append({'reads': [index, index + 1], 'errors': errors})
        if not errors:
            evidence['accepted'] = index; break
    return evidence


def stat_evidence_errors(row, hz):
    """Re-verify the retained source-read decision instead of trusting its flag."""
    try:
        reads, index = row['stat_consistency']['reads'], row['stat_consistency']['accepted']
        if len(reads) > STAT_READS: return ['more /proc/stat reads than the declared bound']
        if index is None: return ['/proc/stat reads inconsistent after %d bounded attempts' % len(reads)]
        if not 0 <= index < len(reads) - 1: return ['/proc/stat consistency evidence insufficient']
        cpus, ctxt = parse_stat(reads[index]['raw'])
        if (cpus, ctxt, list(reads[index]['ns'])) != (row['cpus'], row['ctxt'], list(row['stat_ns'])):
            return ['sample differs from its accepted /proc/stat read']
        return ['/proc/stat consistency recheck: ' + error for error in stat_violations(reads[index], reads[index + 1], hz)]
    except (TypeError, KeyError, ValueError, IndexError, StopIteration):
        return ['/proc/stat consistency evidence missing or malformed']


def sample(processes, groups, nonidle_source=None):
    begin, work = time.monotonic_ns(), time.thread_time_ns()
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    hz = os.sysconf('SC_CLK_TCK')
    evidence = None if nonidle_source is None else read_stat(hz)
    read = read_proc_stat() if evidence is None else evidence['reads'][evidence['accepted'] or 0]
    cpus, ctxt = parse_stat(read['raw'])
    online = Path('/sys/devices/system/cpu/online').read_text().strip()
    try: pressure = Path('/proc/pressure/cpu').read_text()
    except OSError: pressure = None  # PSI disabled; diagnostic only.
    result = {'read_start_ns': begin, 'boottime_ns': boot, 'stat_ns': read['ns'], 'hz': hz, 'online': online,
              'cpus': cpus, 'ctxt': ctxt, 'cpu_pressure': pressure,
              'processes': {name: process(pid) for name, pid in processes.items()},
              'cgroups': {name: {**cgroup_sample(path), 'path': str(path)} for name, path in groups.items()}}
    if evidence is None: result['proc_stat'] = read['raw']
    else:
        result.update(nonidle_source=nonidle_source, stat_consistency=evidence)
        if 'fixture' in groups: result['cgroups']['fixture'].update(members(groups['fixture']))
        result['schedstat'] = schedstat()
    result['read_end_ns'] = time.monotonic_ns()
    result['sampler_cpu_ns'] = time.thread_time_ns() - work
    return result


def _online(value):
    cpus = set()
    for part in value.split(','):
        bounds = list(map(int, part.split('-')))
        cpus.update(range(bounds[0], bounds[-1] + 1))
    return cpus


def online_count(value):
    return len(_online(value))


def parse_nohz(raw, online):
    """Require live high-resolution NO_HZ readback for every online CPU."""
    # Per-CPU hrtimer/tick-sched blocks precede the clock-event device section.
    blocks = re.split(r'^cpu: (\d+)\s*$', re.split(r'^Tick Device:', raw, maxsplit=1, flags=re.M)[0], flags=re.M)
    cpus, duplicates = {}, False
    for name, body in zip(blocks[1::2], blocks[2::2]):
        key = 'cpu' + name
        duplicates |= key in cpus
        values = {}
        for field in ('nohz', 'hres_active'):
            match = re.search(r'^\s*\.' + field + r'\s*:\s*(\d+)\s*$', body, re.M)
            values[field] = int(match[1]) if match else None
        cpus[key] = values
    valid = not duplicates and set(cpus) == {'cpu' + str(i) for i in _online(online)}
    valid &= all(row == {'nohz': 1, 'hres_active': 1} for row in cpus.values())
    return {'valid': valid, 'cpus': cpus}


def kernel_config(paths=None):
    """Declared build options from the first readable config; absence is recorded, not guessed."""
    errors = []
    for path in map(Path, paths or ('/boot/config-' + os.uname().release, '/proc/config.gz')):
        try:
            data = path.read_bytes()
            text = (gzip.decompress(data) if path.suffix == '.gz' else data).decode()
        except (OSError, EOFError, UnicodeDecodeError) as error:
            errors.append(str(path) + ': ' + str(error)); continue
        values = dict(line.split('=', 1) for line in text.splitlines() if line.startswith('CONFIG_') and '=' in line)
        return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
                **{key: values.get('CONFIG_' + key) for key in CONFIG_KEYS}}
    return {'errors': errors}


def jiffies():
    """/proc/schedstat's timestamp line is jiffies; bracketed by CLOCK_MONOTONIC."""
    start = time.monotonic_ns()
    raw = Path('/proc/schedstat').read_text()
    return int(next(line.split()[1] for line in raw.splitlines() if line.startswith('timestamp '))), [start, time.monotonic_ns()]


def tick_rate(sleep=time.sleep, seconds=.5):
    try:
        first, before = jiffies()
        sleep(seconds)
        last, after = jiffies()
    except (OSError, StopIteration, ValueError, IndexError) as error:
        return {'error': type(error).__name__ + ': ' + str(error)}
    return {'jiffies': [first, last], 'ns': [before, after]}


def kernel_hz(source):
    """CONFIG_HZ, when the live jiffies rate confirms it and busy CPUs keep their tick.

    A running task's cgroup CPU is published by update_curr at the next tick or
    switch, so each endpoint lags by under one tick per CPU. nohz_full breaks that.
    """
    try: declared = int(source['kernel_config']['HZ'])
    except (KeyError, TypeError, ValueError): return None, 'kernel CONFIG_HZ unavailable'
    try: (j0, j1), (a, b) = source['tick_rate']['jiffies'], source['tick_rate']['ns']
    except (KeyError, TypeError, ValueError): return None, 'live jiffies readback unavailable'
    if b[0] - a[1] < 400000000: return None, 'jiffies readback interval under 0.4 s'
    # Integer jiffies, updated lazily under NO_HZ: an empirical three-jiffy margin.
    if not declared * (b[0] - a[1]) / 1e9 - 3 <= j1 - j0 <= declared * (b[1] - a[0]) / 1e9 + 3:
        return None, 'live jiffies rate disagrees with CONFIG_HZ'
    if source.get('nohz_full') or any(arg.startswith('nohz_full=') for arg in source.get('cmdline_timing', ())):
        return None, 'nohz_full CPUs may run without a tick'
    return declared, None


def _nohz_full():
    try: value = Path('/sys/devices/system/cpu/nohz_full').read_text().strip()
    except FileNotFoundError: return None
    return '' if value == '(null)' else value


def nohz_capability(sleep=time.sleep):
    online = Path('/sys/devices/system/cpu/online').read_text().strip()
    try: result = parse_nohz(Path('/proc/timer_list').read_text(), online)
    except OSError as error: result = {'valid': False, 'error': str(error), 'cpus': {}}
    return {**result, 'online': online, 'kernel': os.uname().release,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'clocksource': Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),
            'kernel_config': kernel_config(), 'nohz_full': _nohz_full(),
            'cmdline_timing': [arg for arg in Path('/proc/cmdline').read_text().split() if arg.split('=', 1)[0] in TIMING_ARGS],
            'tick_rate': tick_rate(sleep)}


def _identity(source):
    """Before/after readbacks must match except for the jiffies-rate measurement itself."""
    return {key: value for key, value in source.items() if key != 'tick_rate'}


def fixture_group(run_id):
    """The root-created transient unit must initially contain only this runner."""
    expected = '/system.slice/wgps-overhead-' + uuid.UUID(run_id).hex[:10] + '.service'
    actual = Path('/proc/self/cgroup').read_text().strip()
    if actual != '0::' + expected:
        raise ValueError('run inside the dedicated systemd service wgps-overhead-' + uuid.UUID(run_id).hex[:10])
    path = Path('/sys/fs/cgroup') / expected.lstrip('/')
    state = members(path)
    if path.stat().st_uid != 0 or state['descendants'] or [pid for pid, _ in state['members']] != [os.getpid()]:
        raise ValueError('fixture cgroup is not initially exclusive to this runner')
    return path


def fixture_errors(row, root):
    """One process tree rooted at the runner; no child cgroups hide other members."""
    group = row['cgroups'].get('fixture', {})
    if 'members' not in group or 'descendants' not in group: return ['fixture membership not sampled']
    errors = ['fixture has child cgroups'] if group['descendants'] else []
    pids = {pid for pid, _ in group['members']}
    roots = {pid for pid, parent in group['members'] if parent not in pids}
    if root is None or roots != {root}: errors.append('fixture cgroup contains processes outside the runner tree')
    return errors


def account(first, last, client_cpu_seconds=0.0):
    """Sum disjoint scope only. Negative residuals never become zero-cost claims."""
    errors = []
    elapsed = ((last['read_start_ns'] + last['read_end_ns']) -
               (first['read_start_ns'] + first['read_end_ns'])) / 2e9
    skew = ((last['read_end_ns'] - last['read_start_ns']) +
            (first['read_end_ns'] - first['read_start_ns'])) / 1e9
    hz = first['hz']
    count = online_count(first['online'])
    nonidle = 'nonidle_source' in first or 'nonidle_source' in last
    # Legacy records retain their original strict tick-sum gate.
    tolerance = max(.05, elapsed * .02) * count + skew * count + 4 * count / hz
    kernel = lag = None
    if nonidle:
        # Only /proc/stat is inside stat_ns. Idle and iowait truncate separately,
        # each by under one USER_HZ unit; the aggregate row truncates summed ns.
        brackets = [row.get('stat_ns', (row['read_start_ns'], row['read_end_ns'])) for row in (first, last)]
        elapsed = (sum(brackets[1]) - sum(brackets[0])) / 2e9
        stat_skew = sum(end - start for start, end in brackets) / 1e9
        row_tolerance = stat_skew / 2 + 2 / hz
        busy_tolerance = count * stat_skew / 2 + 2 / hz
    if elapsed <= 0 or hz != last['hz']: errors.append('clock or tick frequency changed')
    if first['online'] != last['online'] or set(first['cpus']) != set(last['cpus']):
        errors.append('CPU hotplug or CPU inventory changed')
    if nonidle:
        source, later = first.get('nonidle_source') or {}, last.get('nonidle_source') or {}
        if not source.get('valid') or _identity(source) != _identity(later) or set(source.get('cpus', {})) != set(first['cpus']) - {'cpu'}:
            errors.append('high-resolution NO_HZ source unverified or changed')
        # Per-CPU rows are online CPUs; capacity uses the online count.
        if source.get('online') != first['online'] or set(first['cpus']) - {'cpu'} != {'cpu' + str(i) for i in _online(first['online'])}:
            errors.append('online CPU inventory disagrees with /proc/stat or NO_HZ source')
        boot_elapsed = (last.get('boottime_ns', 0) - first.get('boottime_ns', 0)) / 1e9
        if abs(boot_elapsed - elapsed) > skew + .001: errors.append('suspend or monotonic/boottime disagreement')
        errors.extend(dict.fromkeys(stat_evidence_errors(first, hz) + stat_evidence_errors(last, hz)))
        (kernel, reason), (other, other_reason) = kernel_hz(source), kernel_hz(later)
        if kernel is None or other != kernel:
            errors.append('cgroup publication lag unbounded: ' + (reason or other_reason or 'kernel HZ changed'))
            kernel = None
        # Scopes are read elsewhere in each bracket; each running slice is
        # published by the next kernel tick. Unverified HZ is already invalid,
        # and USER_HZ only keeps the reported tolerance finite.
        lag = count / kernel if kernel else None
        tolerance = busy_tolerance + count * skew + (lag if lag is not None else count / hz)
    for name in first['cpus'].keys() & last['cpus'].keys():
        a, b = first['cpus'][name], last['cpus'][name]
        if len(a) != len(b) or len(a) < 8:
            errors.append('CPU field inventory changed: ' + name); continue
        if any(y < x for i, (x, y) in enumerate(zip(a, b)) if not nonidle or i not in (3, 4)):
            errors.append('nonmonotonic ticks: ' + name)
        growth = (sum(b[:8]) - sum(a[:8])) / hz
        expected = elapsed * (count if name == 'cpu' else 1)
        allowed = tolerance if name == 'cpu' else tolerance / count
        if nonidle:
            # Per-CPU rows bound capacity only; busy uses the aggregate row.
            allowed = busy_tolerance if name == 'cpu' else row_tolerance
            idle = (b[3] + b[4] - a[3] - a[4]) / hz
            if idle < -allowed or idle > expected + allowed: errors.append('idle time outside elapsed capacity: ' + name)
        elif abs(growth - expected) > allowed: errors.append('tick growth inconsistent with elapsed time: ' + name)
    a, b = first['cpus']['cpu'], last['cpus']['cpu']
    tick_busy = sum(b[i] - a[i] for i in (0, 1, 2, 5, 6)) / hz
    steal = (b[7] - a[7]) / hz
    busy = count * elapsed - (b[3] + b[4] - a[3] - a[4]) / hz - steal if nonidle else tick_busy
    busy_bound = busy_tolerance if nonidle else tolerance
    if busy < -busy_bound: errors.append('negative execution time beyond read/rounding bound')
    scoped, detail = (0.0, {}) if nonidle else (client_cpu_seconds, {'clients_primary': client_cpu_seconds})
    groups = first['cgroups']
    group_paths = [row['path'].rstrip('/') for row in groups.values()]
    if any(a != b and b.startswith(a + '/') for a in group_paths for b in group_paths) or len(set(group_paths)) != len(group_paths):
        errors.append('nested or duplicate cgroups')
    for name, before in groups.items():
        after = last['cgroups'].get(name, {})
        if any(before.get(k) != after.get(k) for k in ('path', 'inode')):
            errors.append('cgroup identity changed: ' + name); continue
        delta = (after['usage_usec'] - before['usage_usec']) / 1e6
        if delta < 0: errors.append('nonmonotonic cgroup CPU: ' + name)
        detail[name] = delta; scoped += delta
    if nonidle:
        if 'fixture' not in groups: errors.append('whole-fixture cgroup required')
        else:
            root = first['processes'].get('harness', {}).get('pid')
            errors.extend(dict.fromkeys(fixture_errors(first, root) + fixture_errors(last, root)))
            if detail.get('fixture', 0) < client_cpu_seconds - tolerance:
                errors.append('fixture CPU smaller than client primary CPU')
    pids = set()
    for name, before in first['processes'].items():
        after = last['processes'].get(name, {})
        if any(before.get(k) != after.get(k) for k in ('pid', 'starttime')):
            errors.append('process identity changed: ' + name); continue
        if before['pid'] in pids: errors.append('duplicate process scope')
        pids.add(before['pid'])
        group = before.get('cgroup', '').strip().removeprefix('0::')
        if nonidle:
            fixture = groups.get('fixture', {}).get('path', '').removeprefix('/sys/fs/cgroup')
            if not fixture or group != fixture: errors.append('observed process outside fixture cgroup: ' + name)
            continue  # Identity observations; execution is already in the fixture cgroup.
        if any(group == path.removeprefix('/sys/fs/cgroup') or
               group.startswith(path.removeprefix('/sys/fs/cgroup') + '/') for path in group_paths):
            errors.append('process overlaps sampled cgroup: ' + name)
        delta = sum(after[k] - before[k] for k in ('user_ticks', 'system_ticks')) / hz
        if delta < 0: errors.append('nonmonotonic process CPU: ' + name)
        detail[name] = delta; scoped += delta
    residual = busy - scoped
    if residual < -tolerance: errors.append('negative host-minus-scoped CPU beyond accounting tolerance')
    # Diagnostic only: scheduler counters never change measurement validity.
    scheduler = {'available': False}
    if 'schedstat' in first and 'schedstat' in last:
        left, right = first['schedstat'], last['schedstat']
        if left.get('version') == right.get('version') == 17 and set(left['cpus']) == set(right['cpus']) == set(first['cpus']) - {'cpu'}:
            scheduler = {'available': True, 'task_residence_seconds': 0.0, 'slices': {}, 'errors': []}
            for name, values in left['cpus'].items():
                end = right['cpus'][name]
                if len(values) != 9 or len(end) != 9 or any(b < a for a, b in zip(values, end)):
                    scheduler['errors'].append('counter inventory/regression: ' + name); continue
                scheduler['task_residence_seconds'] += (end[6] - values[6]) / 1e9
                scheduler['slices'][name] = end[8] - values[8]
            scheduler['nonidle_minus_task_seconds'] = busy - scheduler['task_residence_seconds']
            scheduler['note'] = 'Diagnostic: rq_clock residence excludes idle tasks, includes IRQ on tasks, and publishes at switch-out. Endpoint slices are not bounded by this counter.'
    return {'valid': not errors, 'errors': errors, 'elapsed_seconds': elapsed,
            'endpoint_skew_seconds': skew, 'accounting_tolerance_seconds': tolerance,
            'host_busy_tolerance_seconds': busy_bound,
            'host_busy_seconds': busy, 'host_steal_seconds': steal,
            'host_cpu_method': 'nohz-idle-complement' if nonidle else 'legacy-tick-sum',
            'tick_busy_seconds': tick_busy, 'tick_deficit_seconds': busy - tick_busy,
            'clients_primary_seconds': client_cpu_seconds,
            'kernel_hz': kernel, 'cgroup_publication_lag_seconds': lag,
            'scheduler': scheduler,
            'scoped_seconds': scoped, 'scope_seconds': detail, 'residual_seconds': residual,
            'host_context_switches': last['ctxt'] - first['ctxt'],
            'note': 'Residual is host non-idle time outside sampled scopes: other tasks, kernel threads and '
                    'interrupt/idle-loop time; neither unrelated-only nor feature-only. Guest ticks are not added; iowait is not execution.'}


def account_series(rows, client_cpu_seconds=0.0):
    """Endpoint totals plus validity of every observed intermediate transition."""
    if len(rows) < 2: raise ValueError('at least two CPU samples required')
    result = account(rows[0], rows[-1], client_cpu_seconds)
    errors = []
    for index, (before, after) in enumerate(zip(rows, rows[1:]), 1):
        observed = account(before, after)
        failures = list(observed['errors'])
        if after['read_start_ns'] < before['read_end_ns'] or after['read_end_ns'] < after['read_start_ns']:
            failures.append('nonmonotonic sample read brackets')
        for kind in ('processes', 'cgroups'):
            if set(before[kind]) != set(after[kind]): failures.append(kind + ' inventory changed')
            for name in before[kind].keys() & after[kind].keys():
                a, b = before[kind][name], after[kind][name]
                if kind == 'processes' and a.get('cgroup') != b.get('cgroup'):
                    failures.append('process cgroup membership changed: ' + name)
                keys = ('user_ticks', 'system_ticks', 'voluntary_ctxt', 'involuntary_ctxt') if kind == 'processes' else ('usage_usec', 'user_usec', 'system_usec')
                if any(k in a and k in b and b[k] < a[k] for k in keys): failures.append('counter regressed: ' + name)
        if failures: errors.append({'sample_index': index, 'errors': failures})
    result['series_errors'] = errors
    result['valid'] = result['valid'] and not errors
    # The fixture pays for its own sampler; caller work between samples is excluded.
    result['sampler_cpu_seconds'] = sum(row.get('sampler_cpu_ns', 0) for row in rows) / 1e9
    return result


def sample_through_drain(pending, sampler, planned_end, deadline, *, clock=time.monotonic,
                         sleep=time.sleep, interval=.2, output=None):
    """Keep sampling until all output has drained and all clients have exited.

    pending must collect output without blocking or parsing it. Caller serializes
    after this returns. A final sample brackets delayed work even past planned_end.
    """
    rows = [] if output is None else output
    rows.append(sampler())
    boundary = None
    while True:
        active = pending()
        now = clock()
        if now >= planned_end and boundary is None:
            rows.append(sampler()); boundary = len(rows) - 1
        if not active and now >= planned_end:
            rows.append(sampler())
            return rows, boundary
        if now >= deadline:
            rows.append(sampler())
            raise TimeoutError('clients did not finish inside the declared drain limit')
        # Wake at planned_end so the boundary sample is not an interval late.
        sleep(min(interval, max(.001, (deadline if boundary is not None else planned_end) - now)))
        rows.append(sampler())
