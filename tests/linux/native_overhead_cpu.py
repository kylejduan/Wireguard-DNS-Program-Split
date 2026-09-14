"""Native /proc accounting with explicit read skew, hotplug and drain validity."""
import os
from pathlib import Path
import time

from overhead_stats import cgroup_sample


def process(pid):
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    status = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines())
    return {'pid': pid, 'starttime': int(fields[19]), 'state': fields[0],
            'user_ticks': int(fields[11]), 'system_ticks': int(fields[12]),
            'voluntary_ctxt': int(status['voluntary_ctxt_switches']),
            'involuntary_ctxt': int(status['nonvoluntary_ctxt_switches']),
            'cgroup': Path('/proc', str(pid), 'cgroup').read_text()}


def sample(processes, groups):
    begin = time.monotonic_ns()
    raw = Path('/proc/stat').read_text()
    online = Path('/sys/devices/system/cpu/online').read_text().strip()
    rows = [line.split() for line in raw.splitlines()]
    cpus = {row[0]: list(map(int, row[1:])) for row in rows if row[0].startswith('cpu')}
    result = {'read_start_ns': begin, 'hz': os.sysconf('SC_CLK_TCK'), 'online': online,
              'proc_stat': raw, 'cpus': cpus, 'ctxt': next(int(row[1]) for row in rows if row[0] == 'ctxt'),
              'cpu_pressure': Path('/proc/pressure/cpu').read_text(),
              'processes': {name: process(pid) for name, pid in processes.items()},
              'cgroups': {name: {**cgroup_sample(path), 'path': str(path)} for name, path in groups.items()}}
    result['read_end_ns'] = time.monotonic_ns()
    return result


def online_count(value):
    cpus = set()
    for part in value.split(','):
        bounds = list(map(int, part.split('-')))
        cpus.update(range(bounds[0], bounds[-1] + 1))
    return len(cpus)


def account(first, last, client_cpu_seconds=0.0):
    """Sum disjoint scope only. Negative residuals never become zero-cost claims."""
    errors = []
    elapsed = ((last['read_start_ns'] + last['read_end_ns']) -
               (first['read_start_ns'] + first['read_end_ns'])) / 2e9
    skew = ((last['read_end_ns'] - last['read_start_ns']) +
            (first['read_end_ns'] - first['read_start_ns'])) / 1e9
    hz = first['hz']
    count = online_count(first['online'])
    # Tick rounding, endpoint read skew and NO_HZ publication jitter are explicit.
    tolerance = max(.05, elapsed * .02) * count + skew * count + 4 * count / hz
    if elapsed <= 0 or hz != last['hz']: errors.append('clock or tick frequency changed')
    if first['online'] != last['online'] or set(first['cpus']) != set(last['cpus']):
        errors.append('CPU hotplug or CPU inventory changed')
    for name in first['cpus'].keys() & last['cpus'].keys():
        a, b = first['cpus'][name], last['cpus'][name]
        if len(a) != len(b) or any(y < x for x, y in zip(a, b)):
            errors.append('nonmonotonic ticks: ' + name)
        growth = (sum(b[:8]) - sum(a[:8])) / hz
        expected = elapsed * (count if name == 'cpu' else 1)
        allowed = tolerance if name == 'cpu' else tolerance / count
        if abs(growth - expected) > allowed: errors.append('tick growth inconsistent with elapsed time: ' + name)
    a, b = first['cpus']['cpu'], last['cpus']['cpu']
    busy = sum(b[i] - a[i] for i in (0, 1, 2, 5, 6)) / hz
    steal = (b[7] - a[7]) / hz
    scoped, detail = client_cpu_seconds, {'clients_primary': client_cpu_seconds}
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
    pids = set()
    for name, before in first['processes'].items():
        after = last['processes'].get(name, {})
        if any(before.get(k) != after.get(k) for k in ('pid', 'starttime')):
            errors.append('process identity changed: ' + name); continue
        if before['pid'] in pids: errors.append('duplicate process scope')
        pids.add(before['pid'])
        group = before.get('cgroup', '').strip().removeprefix('0::')
        if any(group == path.removeprefix('/sys/fs/cgroup') or
               group.startswith(path.removeprefix('/sys/fs/cgroup') + '/') for path in group_paths):
            errors.append('process overlaps sampled cgroup: ' + name)
        delta = sum(after[k] - before[k] for k in ('user_ticks', 'system_ticks')) / hz
        if delta < 0: errors.append('nonmonotonic process CPU: ' + name)
        detail[name] = delta; scoped += delta
    residual = busy - scoped
    if residual < -tolerance: errors.append('negative host-minus-scoped CPU beyond accounting tolerance')
    return {'valid': not errors, 'errors': errors, 'elapsed_seconds': elapsed,
            'endpoint_skew_seconds': skew, 'accounting_tolerance_seconds': tolerance,
            'host_busy_seconds': busy, 'host_steal_seconds': steal,
            'scoped_seconds': scoped, 'scope_seconds': detail, 'residual_seconds': residual,
            'host_context_switches': last['ctxt'] - first['ctxt'],
            'note': 'Residual includes unrelated activity and kernel workers. Guest ticks are not added; iowait is not execution.'}


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
        sleep(min(interval, max(.001, deadline - now)))
        rows.append(sampler())
