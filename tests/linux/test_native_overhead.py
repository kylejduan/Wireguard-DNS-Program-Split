#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guarded native local comparison. Root owns host preparation and provider cutover."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import time

import native_overhead_cpu as cpu
import native_overhead_owner as own
import native_overhead_runtime as runtime
import overhead_stats as statistics

# Identical names, rates and native modes to the established overhead experiment.
CASES = (
    ('included_socket_udp', 'socket_udp', True, 1000), ('included_socket_tcp', 'socket_tcp', True, 1000),
    ('unlisted_socket_udp', 'socket_udp', False, 1000), ('unlisted_socket_tcp', 'socket_tcp', False, 1000),
    ('included_dns_udp', 'dns_udp', True, 100), ('included_dns_tcp', 'dns_tcp', True, 100),
    ('unlisted_dns_udp', 'dns_udp', False, 100), ('unlisted_dns_tcp', 'dns_tcp', False, 100),
    ('included_udp', 'udp', True, 1000), ('included_tcp', 'tcp', True, 200),
    ('unlisted_udp', 'udp', False, 1000), ('unlisted_tcp', 'tcp', False, 200),
    ('unlisted_file', 'file', False, 1000), ('unlisted_mmap', 'mmap', False, 1000),
    ('unlisted_ipc_fresh', 'ipc_fresh', False, 1000), ('unlisted_ipc_old', 'ipc_old', False, 1000),
)


def case_set(udp_mode):
    if udp_mode not in ('serial', 'stream'): raise ValueError('unknown UDP pacing mode')
    return tuple((label + '_stream', 'udp_stream', included, rate)
                 if udp_mode == 'stream' and mode == 'udp' else (label, mode, included, rate)
                 for label, mode, included, rate in CASES)


def launch(topology, directory, case, arm, mark, seconds):
    label, mode, included, rate = case
    root = topology.evidence / 'bin'
    binary = root / ('selected-dns' if included and mode.startswith('dns') else 'selected-ip' if included else 'direct-ip')
    receipts = [r for r in topology.j.records if r['kind'] == 'file' and r['name'] == str(binary)]
    if len(receipts) != 1: raise ValueError('selected/unlisted executable receipt missing')
    own.same_identity(receipts[0]['identity'], own.file_identity(binary))
    address = topology.m['peer_tunnel'] if included else topology.peer
    if included and mode.startswith('dns') and arm != 'absent': address = '127.0.0.53'
    process = runtime.child(topology.j, [binary, 'client', mode, address, 53, topology.m['payload_port'],
                                        seconds * 1000, rate, mark if included else 0, root / 'ordinary-file'],
                            directory / (label + '.stderr'))
    try:
        if not runtime.line(process).get('ready'): raise ValueError('client not ready')
        return process
    except BaseException:
        runtime.retire(topology.j, process)
        runtime.report(directory / (label + '.setup-failure.json'), {'exit': process.returncode, 'arm': arm, 'case': label})
        raise


def save_and_retire(topology, directory, children, drain):
    """Preserve trailing failure bytes before closing each owned pipe."""
    import subprocess
    errors = []
    for name, process in children.items():
        path = directory / (name + '.json')
        try:
            if process.stdout and not process.stdout.closed:
                try: trailing, _ = process.communicate(timeout=.1)
                except subprocess.TimeoutExpired:
                    own.same_identity(process.ownership_receipt['identity'], own.pid_identity(process.pid))
                    process.terminate()
                    try: trailing, _ = process.communicate(timeout=4)
                    except subprocess.TimeoutExpired:
                        own.same_identity(process.ownership_receipt['identity'], own.pid_identity(process.pid))
                        process.kill(); trailing, _ = process.communicate(timeout=4)
                if not path.exists():
                    prefix = bytes(drain.buffers[name]) if drain is not None else b''
                    path.write_bytes(prefix + trailing)
        except Exception as error: errors.append(name + ': ' + str(error))
        finally:
            try: runtime.retire(topology.j, process)
            except Exception as error: errors.append(name + ': ' + str(error))
    if errors: raise RuntimeError('client retirement incomplete: ' + '; '.join(errors))


class Drain:
    """Read complete/partial bytes without JSON work while other clients run."""
    def __init__(self, children):
        self.children = children
        self.buffers = {name: bytearray() for name in children}
        self.eof = set()
        for child in children.values(): os.set_blocking(child.stdout.fileno(), False)

    def pending(self):
        active = False
        for name, child in self.children.items():
            if name not in self.eof:
                while True:
                    try: block = os.read(child.stdout.fileno(), 65536)
                    except BlockingIOError: break
                    if not block: self.eof.add(name); break
                    self.buffers[name].extend(block)
                    if len(self.buffers[name]) > 16 * 1024 * 1024: raise ValueError('oversized client output')
            active |= name not in self.eof or child.poll() is None
        return active


def peer_counts(peers):
    for server in peers: server.stdin.write(b'stats\n'); server.stdin.flush()
    return [runtime.line(server) for server in peers]


def fixture_members(fixture, required=()):
    """Only this runner's process tree may execute in the fixture, with no child cgroups."""
    value = cpu.members(fixture)
    pids = {pid for pid, _ in value['members']}
    value['errors'] = (cpu.fixture_errors({'cgroups': {'fixture': value}}, os.getpid()) +
                       [f'owned process {pid} outside fixture' for pid in sorted(set(required) - pids)])
    return value


def product_scopes(instance):
    """Product cgroups keyed by exact unit name; the inventory must be exactly the product units."""
    if set(instance) != set(own.UNITS): raise ValueError('unexpected product unit inventory: ' + ', '.join(sorted(instance)))
    groups, inodes = {}, {}
    for unit, value in instance.items():
        if value['cgroup_inode'] is not None:
            groups[unit] = Path('/sys/fs/cgroup') / value['ControlGroup'].lstrip('/')
            inodes[unit] = value['cgroup_inode']
    return groups, inodes


ACCOUNTS = ('cpu', 'cpu_planned', 'cpu_drain')


class MeasurementRejected(RuntimeError):
    """Every window completed and is retained, but the measurement is not accepted."""


def cpu_valid(resources):
    return all(row[name]['valid'] for row in resources for name in ACCOUNTS)


def acceptance(resources, mode):
    """Measurement acceptance is separate from workload completion; nothing is retried or dropped."""
    errors = []
    for row in resources:
        for name in ACCOUNTS:
            account, where = row[name], {'round': row['round'], 'arm': row['arm'], 'account': name}
            if not account['valid']:
                errors.append({**where, 'errors': account['errors'], 'series_errors': len(account.get('series_errors', []))})
            if mode == 'native-tv' and account['host_steal_seconds']:
                errors.append({**where, 'errors': [f"native host steal {account['host_steal_seconds']} s"]})
    return {'accepted': not errors, 'workload_complete': True, 'windows': len(resources), 'errors': errors,
            'max_host_steal_seconds': max((row[name]['host_steal_seconds'] for row in resources for name in ACCOUNTS), default=0),
            'note': 'Native steal must be zero.' if mode == 'native-tv' else 'VM rehearsal validates plumbing only; steal is recorded, not gated.'}


def fixture_usage(fixture):
    try:
        value = statistics.cgroup_sample(fixture)
        return {'monotonic_ns': time.monotonic_ns(), **{k: value[k] for k in ('usage_usec', 'user_usec', 'system_usec')}}
    except Exception as error: return {'error': type(error).__name__ + ': ' + str(error)}


def lifecycle(start, end):
    note = ('Whole-arm fixture cgroup CPU from before the first client launch through retirement: client setup, '
            'runner-invoked product commands, peers, sampling and output parsing. Product services use their own '
            'cgroups. Separate from, and never added to, the primary window accounts.')
    if 'error' in start or 'error' in end: return {'valid': False, 'start': start, 'end': end, 'note': note}
    delta = {k: end[k] - start[k] for k in ('usage_usec', 'user_usec', 'system_usec')}
    return {'valid': all(v >= 0 for v in delta.values()), 'elapsed_ns': end['monotonic_ns'] - start['monotonic_ns'],
            **delta, 'note': note}


def measure(topology, arm, round_id, seconds, cases=CASES):
    directory = topology.evidence / (str(round_id) + '-' + arm)
    directory.mkdir(mode=0o700)
    children, rows, resource = {}, [], {'arm': arm, 'round': round_id, 'samples': []}
    fixture = topology.fixture_group
    lifecycle_start = fixture_usage(fixture)
    drain = None
    try:
        children[cases[-1][0]] = launch(topology, directory, cases[-1], arm, 0, seconds)
        manager = runtime.plain(topology) if arm == 'absent' else runtime.installed(topology, arm, directory)
        with manager as product:
            try:
                mark = product.mark() if product else 0
                for case in cases[:-1]: children[case[0]] = launch(topology, directory, case, arm, mark, seconds)
                groups, inodes = {'fixture': fixture}, {}
                source = cpu.nohz_capability()
                resource['nonidle_source_before'] = source
                if product:
                    scopes, inodes = product_scopes(product.instance)
                    groups.update(scopes)
                    resource['service_before'] = product.instance
                    resource['native_before'] = own.data(runtime.ARTIFACTS / 'bpf-loader', 'snapshot', runtime.PINS)
                processes = {'harness': os.getpid(), 'vpn_peer': topology.servers[0].pid, 'direct_peer': topology.servers[1].pid}
                observer = [0]
                def sampler():
                    started = time.thread_time_ns()
                    value = cpu.sample(processes, groups, source)
                    if product:
                        value['daemon'] = statistics.process_sample(int(product.instance[own.UNITS[1]]['MainPID']))
                    observer[0] += time.thread_time_ns() - started
                    return value
                resource['counters_before'] = product.counters() if product else {}
                resource['peer_before'] = peer_counts(topology.servers)
                resource['client_setup'] = {name: cpu.process(p.pid) for name, p in children.items()}
                # Final kernel route decision before any send, outside every measured span.
                resource['route_proof_before_go'] = runtime.route_proof(topology, mark)
                required = {*processes.values(), *(p.pid for p in children.values())}
                resource['fixture_before'] = fixture_members(fixture, required)
                if resource['fixture_before']['errors']:
                    raise ValueError('fixture cgroup is not exclusive to this run: ' + '; '.join(resource['fixture_before']['errors']))
                # First CPU read precedes GO, and final read follows the last exit/output.
                initial = sampler()
                if any(initial['cgroups'][name]['inode'] != inode for name, inode in inodes.items()):
                    raise ValueError('product service cgroup changed before GO')
                begin = time.monotonic_ns() + 200000000
                resource.update(start_ns=begin, intended_seconds=seconds)
                drain = Drain(children)
                for process in children.values():
                    process.stdin.write(('go ' + str(begin) + '\n').encode()); process.stdin.flush()
                resource['samples'].append(initial)
                # Clients wait for GO without output, so the drain's first sample anchors the planned window at GO.
                time.sleep(max(0, (begin - time.monotonic_ns()) / 1e9))
                _, boundary = cpu.sample_through_drain(drain.pending, sampler, begin / 1e9 + seconds,
                    begin / 1e9 + seconds + 15, output=resource['samples'])
                resource.update(planned_start_index=1, planned_boundary_index=boundary)
                resource['nonidle_source_after'] = cpu.nohz_capability()
                # The final sample carries the later readback, so any change invalidates CPU totals.
                resource['samples'][-1]['nonidle_source'] = resource['nonidle_source_after']
                # Sampler thread CPU runs inside the fixture; product arms read more scopes.
                resource['observer_cpu_seconds'] = observer[0] / 1e9
                resource['fixture_after'] = fixture_members(fixture, processes.values())
                failures = ['fixture cgroup: ' + error for error in resource['fixture_after']['errors']]
                # Effective receive buffers and drop counters; null is unavailable evidence, never zero.
                modes, ready = {case[0]: case[1] for case in cases}, getattr(topology, 'peer_ready', [])
                stream, resource['fixture_receive'] = 'udp_stream' in modes.values(), {}
                for name, process in children.items():
                    output = bytes(drain.buffers[name]); (directory / (name + '.json')).write_bytes(output)
                    try:
                        row = json.loads(output)
                        row.update(case=name, arm=arm, round=round_id, exit=process.returncode,
                                   offered_operations=seconds * next(c[3] for c in cases if c[0] == name))
                        row['intended_ns'] = seconds * 1000000000
                        row['delivered_operations'] = len(row['samples'])
                        row['delivered_bytes'] = sum(s[3] for s in row['samples'])
                        rows.append(row)
                        if process.returncode or len(row['samples']) != row['planned'] or any(s[2] for s in row['samples']):
                            failures.append(name)
                        if (row.get('receive_drops') or 0) > 0: failures.append(name + ': fixture socket drop')
                        if modes[name] == 'udp_stream':
                            resource['fixture_receive'][name] = {k: row.get(k) for k in ('rcvbuf', 'receive_drops', 'stream_errno')}
                            if row.get('rcvbuf') is None or row.get('receive_drops') is None:
                                failures.append(name + ': receive buffer or drop counter unavailable')
                    except (ValueError, KeyError, TypeError): failures.append(name + ': incomplete report')
                resource['peer_after'] = peer_counts(topology.servers)
                resource['counters_after'] = product.counters() if product else {}
                resource['counter_delta'] = {k: resource['counters_after'][k] - v for k, v in resource['counters_before'].items()}
                client_cpu = sum(row['cpu_ns'] for row in rows) / 1e9
                resource['cpu'] = cpu.account_series(resource['samples'], client_cpu)
                resource['cpu_planned'] = cpu.account_series(resource['samples'][1:boundary + 1])
                resource['cpu_drain'] = cpu.account_series(resource['samples'][boundary:])
                resource['cpu_planned']['note'] += (
                    ' The fixture cgroup already contains client CPU; client loop CPU only bounds the full-span fixture total from below.'
                    if resource['cpu'].get('host_cpu_method') == 'nohz-idle-complement' else
                    ' Client primary CPU is assigned only to the full-span account.')
                resource['sampled_memory_maxima'] = {name: max(row['cgroups'][name]['memory_current'] for row in resource['samples']) for name in groups}
                resource['cpu_seconds_per_completed_operation'] = client_cpu / sum(len(row['samples']) for row in rows) if rows else None
                for index, server in enumerate(topology.servers):
                    if server.poll() is not None: failures.append('peer exited')
                    before, after = resource['peer_before'][index], resource['peer_after'][index]
                    key = 'vpn_peer' if index == 0 else 'direct_peer'
                    # Receive-queue drops are fixture capacity failures, not path loss.
                    drops = (None if None in (before.get('payload_drops'), after.get('payload_drops'))
                             else after['payload_drops'] - before['payload_drops'])
                    rcvbuf = ready[index].get('payload_rcvbuf') if index < len(ready) else None
                    resource['fixture_receive'][key] = {'rcvbuf': rcvbuf, 'drops': drops}
                    if drops: failures.append(f'fixture socket drop at {key}: {drops}')
                    if stream and (drops is None or rcvbuf is None or rcvbuf < 0):
                        failures.append(key + ': receive buffer or drop counter unavailable')
                    if after['dns'] - before['dns'] < seconds * 200: failures.append('missing peer DNS')
                    if after['payload'] - before['payload'] != seconds * 1200: failures.append('peer payload count mismatch')
                    for sample in resource['samples']:
                        if any(initial['processes'][key][field] != sample['processes'][key][field] for field in ('pid', 'starttime')):
                            failures.append('peer identity changed')
                if product:
                    resource['service_after'] = runtime.service_instances()
                    own.same_identity(product.instance, resource['service_after'])
                    statistics.validate_daemon(resource['samples'], resource['samples'][0]['daemon'])
                    resource['status_after'] = product.cli('status')
                    if not statistics.fresh_readiness(resource['status_after'], begin / 1e9 + time.time() - time.monotonic()):
                        failures.append('readiness not refreshed during primary window')
                    for name in groups:
                        if any(row['cgroups'][name]['inode'] != initial['cgroups'][name]['inode'] for row in resource['samples']):
                            failures.append('cgroup identity changed')
                resource['failures'] = failures
                runtime.report(directory / 'rows.json', rows)
                if failures: raise ValueError('primary operations/health failed: ' + ', '.join(failures))
                return rows, resource
            finally:
                # Product teardown cannot overlap any still-running client.
                save_and_retire(topology, directory, children, drain)
    except BaseException as error:
        resource['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        # Retirement is idempotent after the inner pass; evidence is written even if it fails.
        try: save_and_retire(topology, directory, children, drain)
        except Exception as error:
            resource['retirement_failure'] = str(error); raise
        finally:
            resource['fixture_lifecycle'] = lifecycle(lifecycle_start, fixture_usage(fixture))
            runtime.report(directory / 'resources.json', resource)


def profile_unavailable(result):
    """Some distro builds return a JSON error with exit zero for unsupported profiling."""
    if result.returncode: return 'bpftool profile failed with exit ' + str(result.returncode)
    try: value = json.loads(result.stdout)
    except ValueError: return 'bpftool profile did not return valid JSON'
    if isinstance(value, dict) and 'error' in value: return str(value['error'])
    return None


def profile(topology, arm, cases=CASES):
    """Optional exact-ID BPF diagnostic, after all primary windows are complete."""
    directory = topology.evidence / ('profile-' + arm); directory.mkdir(mode=0o700)
    evidence = {'arm': arm, 'primary': False, 'global_sysctl_mutated': False, 'windows': []}
    runtime.report(directory / 'profile.json', evidence)
    with runtime.installed(topology, arm, directory) as product:
        snapshot = own.data(runtime.ARTIFACTS / 'bpf-loader', 'snapshot', runtime.PINS)
        ids = sorted({v['program_id'] for v in snapshot['links'].values()})
        help_text = own.run('bpftool', 'prog', 'help', okay=False).stderr
        evidence['capability_help'] = help_text
        evidence['programs'] = [own.data('bpftool', '-j', 'prog', 'show', 'id', pid) for pid in ids]
        if 'profile' not in help_text or 'cycles' not in help_text:
            evidence['unsupported'] = 'bpftool does not advertise required profile/cycles support'
        else:
            for case in (cases[0], cases[8]):  # Socket UDP and this experiment's UDP payload mode.
                for pid in ids:
                    window = directory / (case[0] + '-' + str(pid)); window.mkdir(mode=0o700)
                    process = launch(topology, window, case, arm, product.mark(), 2)
                    try:
                        begin = time.monotonic_ns() + 200000000
                        process.stdin.write(('go ' + str(begin) + '\n').encode()); process.stdin.flush()
                        observed = own.run('bpftool', '-j', 'prog', 'profile', 'id', pid, 'duration', '1', 'cycles', 'instructions', okay=False, timeout=8)
                        unavailable = profile_unavailable(observed)
                        output, _ = process.communicate(timeout=6)
                        (window / 'client.json').write_bytes(output)
                        evidence['windows'].append({'program_id': pid, 'case': case[0], 'duration_seconds': 1,
                            'profiler_exit': observed.returncode, 'stdout': observed.stdout, 'stderr': observed.stderr,
                            'client_exit': process.returncode, 'controller_status_after': product.cli('status')})
                        if unavailable is not None:
                            evidence.update(available=False, unsupported=unavailable)
                            runtime.report(directory / 'profile.json', evidence)
                            return False  # Retire this client/product; no further profiling windows.
                    finally: runtime.retire(topology.j, process)
        evidence['available'] = 'unsupported' not in evidence
        runtime.report(directory / 'profile.json', evidence)
    return evidence['available']


def recover(manifest):
    root = Path(manifest['evidence']); own.directory_identity(root)
    metadata = json.loads((root / 'metadata.json').read_text())
    if metadata['run_id'] != manifest['run_id']: raise ValueError('different run evidence')
    owner = metadata['owner']
    try:
        if own.pid_identity(owner['pid']) == owner: raise ValueError('original harness is still alive')
    except FileNotFoundError: pass
    journal = own.Journal(root / 'ownership.jsonl', manifest['run_id'], resume=True)
    try:
        product_records = [r for r in journal.records if r['kind'] == 'product']
        if len(product_records) > 1: raise ValueError('multiple product receipts retained')
        if journal.pending: raise ValueError('unresolved acquisition intent; inspect ownership.jsonl before root recovery')
        if product_records:
            topology = runtime.Topology(manifest, journal)
            product = runtime.Product(topology, 'recovery', root)
            product.receipt = product_records[0]
            states = [r for r in journal.records if r['kind'] == 'product-state']
            if len(states) > 1: raise ValueError('multiple runtime state receipts retained')
            product.state_receipt = states[0] if states else None
            product.close()
        errors = journal.cleanup()
        invariants = []
        try:  # The same postconditions as a normal run's final readback.
            last = runtime.snapshot(manifest); runtime.report(root / 'recovery-after.json', last)
            invariants.extend(runtime.verify_snapshot(json.loads((root / 'before.json').read_text()), last))
            if not journal.records and not journal.pending: own.preflight(manifest, own.inventory())
        except Exception as error: invariants.append('final readback: ' + type(error).__name__ + ': ' + str(error))
        runtime.report(root / 'recovery.json', {'errors': errors, 'invariant_errors': invariants,
                                                'remaining': journal.records, 'unresolved_acquisitions': journal.pending})
        if errors or invariants: raise RuntimeError('recovery retained objects or host state differs; inspect recovery.json')
    finally: journal.close()


def execute(args, manifest, host):
    own.validate_manifest(manifest)
    orders = statistics.schedule(args.rounds, args.seed)
    cases = case_set(args.udp_mode)
    fixture = cpu.fixture_group(manifest['run_id'])
    source = cpu.nohz_capability()
    if not source['valid']: raise ValueError('live high-resolution NO_HZ readback failed; CPU totals would be invalid')
    # Same publication-lag prerequisite that every account rechecks, before any host state.
    if cpu.kernel_hz(source)[0] is None:
        raise ValueError('CPU accounting prerequisite failed: ' + cpu.kernel_hz(source)[1] + '. Provide a readable '
                         '/boot/config-<release> or /proc/config.gz with CONFIG_HZ matching the live jiffies rate, '
                         'and no nohz_full CPUs; nothing was created')
    if not 10 <= args.seconds <= 30: raise ValueError('each arm must run for 10..30 seconds')
    own.preflight(manifest, own.inventory())
    first = runtime.snapshot(manifest)
    root = Path(manifest['evidence']); root.mkdir(mode=0o700)
    runtime.report(root / 'before.json', first)
    metadata = {'schema': 1, 'run_id': manifest['run_id'], 'mode': manifest['mode'], 'host': host,
                'owner': own.pid_identity(os.getpid()), 'manifest': manifest, 'cases': cases, 'udp_mode': args.udp_mode,
                'schedule': orders, 'rounds': args.rounds, 'seconds_per_arm': args.seconds, 'seed': args.seed,
                'fixture_cgroup': str(fixture), 'nonidle_source_admission': source,
                'cpu_affinity': sorted(os.sched_getaffinity(0)), 'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
                'cpu_states': {str(p): p.read_text().strip() for p in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')},
                'sample_columns': ['latency_ns', 'schedule_lateness_ns', 'errno', 'payload_bytes'],
                'note': 'Local combined host client/peer kernel. Synthetic DNS does not prove ordinary libc/NSS. '
                        'Socket latency excludes mark check/close; DNS includes query/close. Fixed-rate goodput is not saturation throughput. '
                        'Client CPU is primary-window CPU; host/scoped spans bracket output drain. Fixture cgroup includes client serialization. '
                        'Serial and stream UDP are separate workloads; compare arms only within one mode. '
                        'Sampled memory maxima exclude some kernel/BPF allocations. Six paired rounds give weak tail precision. '
                        'Intervals estimate mean paired round quantile shifts, not per-request counterfactuals or worst-case guarantees.'}
    runtime.report(root / 'metadata.json', metadata)
    journal = own.Journal(root / 'ownership.jsonl', manifest['run_id'])
    topology = runtime.Topology(manifest, journal)
    topology.fixture_group = fixture
    rows, resources, errors = [], [], []
    try:
        binaries = root / 'bin'; binaries.mkdir(mode=0o700)
        journal.acquire('directory', str(binaries), own.directory_identity(binaries))
        probe = own.staged_bytes(manifest['probe'], manifest['probe_sha256'])  # Copied from the hash-verified read.
        for name in ('probe', 'selected-ip', 'selected-dns', 'direct-ip'): journal.create_file(binaries / name, probe, 0o755)
        journal.create_file(binaries / 'ordinary-file', b'Z' * 4096)
        topology.create()
        for round_id, order in enumerate(orders):
            for arm in order:
                observed, resource = measure(topology, arm, round_id, args.seconds, cases)
                rows.extend(observed); resources.append(resource)
                runtime.report(root / 'rows.json', rows); runtime.report(root / 'resources.json', resources)
                print(f'Completed {manifest["mode"]} round {round_id + 1}: {arm}', flush=True)
        summary = {'latency': statistics.summarize(rows, args.seed),
                   'cpu_valid': cpu_valid(resources), 'acceptance': acceptance(resources, manifest['mode']),
                   'cpu': [{'round': row['round'], 'arm': row['arm'], **row['cpu']} for row in resources],
                   'acceptance_limitations': ['ordinary libc/NSS resolver acceptance is separate',
                       'provider exit/DNS and durable boot acceptance are root-owned separate records',
                       'local loss/recovery and controller restart are not automated by this runner',
                       'BPF profiling excludes total packet-path CPU; no nft packet-cost profiler']}
        runtime.report(root / 'summary.json', summary)
        if not summary['acceptance']['accepted']:
            # All windows stay in evidence; cleanup below still runs before the nonzero exit.
            raise MeasurementRejected(f"{len(summary['acceptance']['errors'])} CPU acceptance failures; inspect summary.json")
        if args.profile:
            for arm in ('baseline', 'candidate'):
                if not profile(topology, arm, cases): break
    except BaseException as error:
        runtime.report(root / 'failure.json', {'type': type(error).__name__, 'message': str(error), 'accepted': False})
        raise
    finally:
        errors.extend(topology.retire())
        if any(r['kind'].startswith('product') for r in [*journal.records, *journal.pending]):
            errors.append('product cleanup incomplete; fixture networking and private inputs retained for --recover')
        else: errors.extend(journal.cleanup())
        try:
            last = runtime.snapshot(manifest); runtime.report(root / 'after.json', last)
            errors.extend(runtime.verify_snapshot(first, last))
            if not journal.records and not journal.pending: own.preflight(manifest, own.inventory())
        except Exception as error: errors.append('final readback: ' + str(error))
        runtime.report(root / 'cleanup.json', {'errors': errors, 'remaining': journal.records, 'unresolved_acquisitions': journal.pending})
        journal.close()
        if errors: raise RuntimeError('cleanup/invariant validation incomplete; inspect cleanup.json')
    print(json.dumps({'completed': True, 'accepted': True, 'mode': manifest['mode'], 'evidence': str(root)}))


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--native-tv', action='store_true')
    modes.add_argument('--vm-rehearsal', action='store_true')
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=6)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--seed', type=int, default=20260914)
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--udp-mode', choices=('serial', 'stream'), default='serial')
    parser.add_argument('--recover', action='store_true')
    return parser.parse_args(argv)


def unwind_on_stop():
    """Turn the unit's SIGTERM/SIGHUP into normal unwinding so cleanup runs.

    Later signals get a no-op Python handler, not SIG_IGN: exec resets it, so
    cleanup commands and retired children still honor terminate().
    """
    def stop(signum, _):
        for name in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT): signal.signal(name, lambda *_: None)
        raise SystemExit(128 + signum)
    for name in (signal.SIGTERM, signal.SIGHUP): signal.signal(name, stop)


def main():
    args = arguments()
    unwind_on_stop()
    os.umask(0o077)
    with own.lock_manifest(args.manifest) as (manifest, _):
        host = own.host_identity()
        own.admit(manifest, host, 'native-tv' if args.native_tv else 'vm-rehearsal')
        if args.recover: recover(manifest)
        else:
            try: execute(args, manifest, host)
            except MeasurementRejected as error: raise SystemExit('measurement not accepted: ' + str(error))


if __name__ == '__main__': main()
