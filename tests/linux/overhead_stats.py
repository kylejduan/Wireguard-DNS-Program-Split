"""Paired descriptive latency shifts; never infer Internet RTT or equivalence."""
import itertools
import math
from pathlib import Path
import random
import statistics
import time

ARMS = ('absent', 'baseline', 'candidate')
PERCENTILES = {'p50': .5, 'p95': .95, 'p99': .99}


def schedule(rounds, seed):
    if type(rounds) is not int or rounds < 6 or rounds > 60 or rounds % 6:
        raise ValueError('rounds must be a multiple of six, from six to sixty')
    randomizer, result = random.Random(seed), []
    for _ in range(rounds // 6):
        orders = list(itertools.permutations(ARMS))
        randomizer.shuffle(orders)
        result.extend(orders)
    return result


def quantile(values, fraction):
    """Nearest-rank empirical quantile, with no interpolation or trimming."""
    ordered = sorted(values)
    if not ordered: raise ValueError('empty latency sample')
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def summarize(rows, seed=1, resamples=4000):
    """Bootstrap complete paired-round quantile shifts, not individual packets.

    Intervals estimate the mean batch-quantile difference across these rounds.
    They are approximate, conditional on this workload/environment, and are not
    the p99 of per-request counterfactual overhead or a worst-case guarantee.
    """
    grouped = {}
    for row in rows:
        if row['arm'] not in ARMS: raise ValueError('unknown arm')
        samples = row['samples']
        if (row['planned'] != len(samples) or not samples or
                any(len(s) != 4 or any(type(x) is not int or x < 0 for x in s) or s[2] for s in samples)):
            raise ValueError('failed or incomplete operation samples')
        key = (row['round'], row['arm'])
        case = grouped.setdefault(row['case'], {})
        if key in case: raise ValueError('duplicate paired round')
        case[key] = row
    output, randomizer = {}, random.Random(seed)
    for name, case in sorted(grouped.items()):
        rounds = sorted({i for i, _ in case})
        if len(rounds) < 6 or set(case) != set(itertools.product(rounds, ARMS)):
            raise ValueError('incomplete paired measurements')
        arms, comparisons = {}, {}
        for arm in ARMS:
            selected = [case[(i, arm)] for i in rounds]
            samples = [sample for row in selected for sample in row['samples']]
            arms[arm] = {p + '_ns': quantile([s[0] for s in samples], q) for p, q in PERCENTILES.items()}
            arms[arm].update(operations=len(samples), client_cpu_ns_per_operation=sum(r['cpu_ns'] for r in selected) / len(samples),
                             max_lateness_ns=max(s[1] for s in samples),
                             p99_lateness_ns=quantile([s[1] for s in samples], .99),
                             p99_scheduled_completion_ns=quantile([s[0] + s[1] for s in samples], .99))
            if all('elapsed_ns' in r for r in selected):
                seconds = sum(r['elapsed_ns'] for r in selected) / 1e9
                arms[arm].update(client_cpu_seconds=sum(r['cpu_ns'] for r in selected) / 1e9,
                                 payload_goodput_bytes_per_second=sum(s[3] for s in samples) / seconds)
        for candidate, baseline in (('candidate', 'absent'), ('candidate', 'baseline'), ('baseline', 'absent')):
            differences = {}
            for label, fraction in PERCENTILES.items():
                delta = [quantile([s[0] for s in case[(i, candidate)]['samples']], fraction) -
                         quantile([s[0] for s in case[(i, baseline)]['samples']], fraction) for i in rounds]
                draws = [statistics.fmean(randomizer.choices(delta, k=len(delta))) for _ in range(resamples)]
                differences[label] = {'mean_ns': statistics.fmean(delta), 'low95_ns': quantile(draws, .025),
                                      'high95_ns': quantile(draws, .975), 'round_differences_ns': delta}
            comparisons[candidate + '-minus-' + baseline] = differences
        output[name] = {'arms': arms, 'comparisons': comparisons}
    return output


def cgroup_sample(path):
    if path is None: return {'usage_usec': 0, 'memory_current': 0}
    path = Path(path)
    result = {name: int(value) for name, value in (line.split() for line in (path / 'cpu.stat').read_text().splitlines())}
    result.update(memory_current=int((path / 'memory.current').read_text()), inode=path.stat().st_ino)
    return result


def summarize_resources(rows):
    """Time-weighted CPU utilization; 100 percent means one logical CPU."""
    output = {}
    for arm in ARMS:
        windows = [r for r in rows if r['arm'] == arm]
        if not windows: raise ValueError('missing resource arm')
        seconds, controller, vpn, direct, guest, memory = 0, 0, 0, 0, 0, 0
        for row in windows:
            first, last = row['samples'][0], row['samples'][-1]
            duration = (last['monotonic_ns'] - first['monotonic_ns']) / 1e9
            if duration <= 0: raise ValueError('invalid resource duration')
            seconds += duration
            controller += (last['controller']['usage_usec'] - first['controller']['usage_usec']) / 1e6
            vpn += (last['peer']['ticks'] - first['peer']['ticks']) / row['clock_ticks_per_second']
            direct += (last['direct_peer']['ticks'] - first['direct_peer']['ticks']) / row['clock_ticks_per_second']
            guest += (last['guest_active_ticks'] - first['guest_active_ticks']) / row['clock_ticks_per_second']
            memory = max(memory, *(r['controller']['memory_current'] for r in row['samples']))
        output[arm] = {'measured_seconds': seconds, 'controller_cpu_seconds': controller,
                       'controller_percent_one_core': 100 * controller / seconds,
                       'vpn_peer_percent_one_core': 100 * vpn / seconds,
                       'direct_peer_percent_one_core': 100 * direct / seconds,
                       'guest_active_percent_one_core': 100 * guest / seconds,
                       'controller_max_memory_bytes': memory}
    return output


def process_sample(pid):
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    return {'pid': pid, 'state': fields[0], 'starttime': int(fields[19]), 'ticks': int(fields[11]) + int(fields[12])}


def validate_daemon(rows, expected):
    for row in rows:
        daemon = row['daemon']
        if (daemon.get('missing') or daemon.get('state') not in ('R', 'S', 'D', 'I') or
                any(daemon.get(k) != expected[k] for k in ('pid', 'starttime'))):
            raise ValueError('controller daemon vanished, stopped, or changed during measurement')


def fresh_readiness(status, after):
    value = status.get('dns_last_checked')
    return (status.get('state') == 'ready' and status.get('protection_verified') is True and
            not status.get('restart_required') and not status.get('restart_boundary_unresolved') and
            type(value) in (int, float) and math.isfinite(value) and value > after)


def resources(cgroup, peer_pid):
    fields = [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
    return {'monotonic_ns': time.monotonic_ns(), 'controller': cgroup_sample(cgroup),
            'peer': process_sample(peer_pid), 'guest_active_ticks': sum(fields[i] for i in (0, 1, 2, 5, 6)),
            'guest_steal_ticks': fields[7]}
