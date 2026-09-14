#!/usr/bin/env python3
"""Guarded native local comparison. Root owns host preparation and provider cutover."""
import argparse
import contextlib
import json
import os
from pathlib import Path
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


def measure(topology, arm, round_id, seconds, cases=CASES):
    directory = topology.evidence / (str(round_id) + '-' + arm)
    directory.mkdir(mode=0o700)
    children, rows, resource = {}, [], {'arm': arm, 'round': round_id, 'samples': []}
    drain = None
    try:
        children[cases[-1][0]] = launch(topology, directory, cases[-1], arm, 0, seconds)
        manager = runtime.plain(topology) if arm == 'absent' else runtime.installed(topology, arm, directory)
        with manager as product:
            try:
                mark = product.mark() if product else 0
                for case in cases[:-1]: children[case[0]] = launch(topology, directory, case, arm, mark, seconds)
                groups = {}
                if product:
                    for unit, value in product.instance.items():
                        if value['cgroup_inode'] is not None:
                            groups['controller' if unit == own.UNITS[1] else 'early_guard'] = Path('/sys/fs/cgroup') / value['ControlGroup'].lstrip('/')
                    resource['service_before'] = product.instance
                    resource['native_before'] = own.data(runtime.ARTIFACTS / 'bpf-loader', 'snapshot', runtime.PINS)
                processes = {'harness': os.getpid(), 'vpn_peer': topology.servers[0].pid, 'direct_peer': topology.servers[1].pid}
                def sampler():
                    value = cpu.sample(processes, groups)
                    if product:
                        value['daemon'] = statistics.process_sample(int(product.instance[own.UNITS[1]]['MainPID']))
                    return value
                resource['counters_before'] = product.counters() if product else {}
                resource['peer_before'] = peer_counts(topology.servers)
                resource['client_setup'] = {name: cpu.process(p.pid) for name, p in children.items()}
                # First CPU read precedes GO, and final read follows the last exit/output.
                initial = sampler()
                begin = time.monotonic_ns() + 200000000
                resource.update(start_ns=begin, intended_seconds=seconds)
                drain = Drain(children)
                for process in children.values():
                    process.stdin.write(('go ' + str(begin) + '\n').encode()); process.stdin.flush()
                resource['samples'].append(initial)
                _, boundary = cpu.sample_through_drain(drain.pending, sampler, begin / 1e9 + seconds,
                    begin / 1e9 + seconds + 15, output=resource['samples'])
                resource['planned_boundary_index'] = boundary
                failures = []
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
                    except (ValueError, KeyError, TypeError): failures.append(name + ': incomplete report')
                resource['peer_after'] = peer_counts(topology.servers)
                resource['counters_after'] = product.counters() if product else {}
                resource['counter_delta'] = {k: resource['counters_after'][k] - v for k, v in resource['counters_before'].items()}
                client_cpu = sum(row['cpu_ns'] for row in rows) / 1e9
                resource['cpu'] = cpu.account_series(resource['samples'], client_cpu)
                resource['cpu_planned'] = cpu.account_series(resource['samples'][:boundary + 1])
                resource['cpu_drain'] = cpu.account_series(resource['samples'][boundary:])
                resource['cpu_planned']['note'] += ' Client primary CPU is assigned only to the full-span account.'
                resource['sampled_memory_maxima'] = {name: max(row['cgroups'][name]['memory_current'] for row in resource['samples']) for name in groups}
                resource['cpu_seconds_per_completed_operation'] = client_cpu / sum(len(row['samples']) for row in rows) if rows else None
                for index, server in enumerate(topology.servers):
                    if server.poll() is not None: failures.append('peer exited')
                    before, after = resource['peer_before'][index], resource['peer_after'][index]
                    if after['dns'] - before['dns'] < seconds * 200: failures.append('missing peer DNS')
                    if after['payload'] - before['payload'] != seconds * 1200: failures.append('peer payload count mismatch')
                    key = 'vpn_peer' if index == 0 else 'direct_peer'
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
        runtime.report(directory / 'resources.json', resource)
        save_and_retire(topology, directory, children, drain)


def profile_unavailable(result):
    """Some distro builds return a JSON error with exit zero for unsupported profiling."""
    if result.returncode: return 'bpftool profile failed with exit ' + str(result.returncode)
    try: value = json.loads(result.stdout)
    except ValueError: return 'bpftool profile did not return valid JSON'
    if isinstance(value, dict) and 'error' in value: return str(value['error'])
    return None


def profile(topology, arm):
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
            for case in (CASES[0], CASES[8]):
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
        runtime.report(root / 'recovery.json', {'errors': errors, 'remaining': journal.records, 'unresolved_acquisitions': journal.pending})
        if errors: raise RuntimeError('recovery retained ambiguous objects; inspect recovery.json')
    finally: journal.close()


def execute(args, manifest, host):
    own.validate_manifest(manifest)
    orders = statistics.schedule(args.rounds, args.seed)
    cases = case_set(args.udp_mode)
    if not 10 <= args.seconds <= 30: raise ValueError('each arm must run for 10..30 seconds')
    own.preflight(manifest, own.inventory())
    first = runtime.snapshot(manifest)
    root = Path(manifest['evidence']); root.mkdir(mode=0o700)
    runtime.report(root / 'before.json', first)
    metadata = {'schema': 1, 'run_id': manifest['run_id'], 'mode': manifest['mode'], 'host': host,
                'owner': own.pid_identity(os.getpid()), 'manifest': manifest, 'cases': cases, 'udp_mode': args.udp_mode,
                'schedule': orders, 'rounds': args.rounds, 'seconds_per_arm': args.seconds, 'seed': args.seed,
                'cpu_affinity': sorted(os.sched_getaffinity(0)), 'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
                'cpu_states': {str(p): p.read_text().strip() for p in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_governor')},
                'sample_columns': ['latency_ns', 'schedule_lateness_ns', 'errno', 'payload_bytes'],
                'note': 'Local combined host client/peer kernel. Synthetic DNS does not prove ordinary libc/NSS. '
                        'Socket latency excludes mark check/close; DNS includes query/close. Fixed-rate goodput is not saturation throughput. '
                        'Client CPU is primary-window CPU; host/scoped spans bracket output drain. Residual also includes client serialization. '
                        'Sampled memory maxima exclude some kernel/BPF allocations. Six paired rounds give weak tail precision. '
                        'Intervals estimate mean paired round quantile shifts, not per-request counterfactuals or worst-case guarantees.'}
    runtime.report(root / 'metadata.json', metadata)
    journal = own.Journal(root / 'ownership.jsonl', manifest['run_id'])
    topology = runtime.Topology(manifest, journal)
    rows, resources, errors = [], [], []
    try:
        binaries = root / 'bin'; binaries.mkdir(mode=0o700)
        journal.acquire('directory', str(binaries), own.directory_identity(binaries))
        probe = Path(manifest['probe']).read_bytes()
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
                   'cpu_valid': all(row['cpu']['valid'] for row in resources),
                   'cpu': [{'round': row['round'], 'arm': row['arm'], **row['cpu']} for row in resources],
                   'acceptance_limitations': ['ordinary libc/NSS resolver acceptance is separate',
                       'provider exit/DNS and durable boot acceptance are root-owned separate records',
                       'local loss/recovery and controller restart are not automated by this runner',
                       'BPF profiling excludes total packet-path CPU; no nft packet-cost profiler']}
        runtime.report(root / 'summary.json', summary)
        if args.profile:
            for arm in ('baseline', 'candidate'):
                if not profile(topology, arm): break
    except BaseException as error:
        runtime.report(root / 'failure.json', {'type': type(error).__name__, 'message': str(error)})
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
    print(json.dumps({'completed': True, 'mode': manifest['mode'], 'evidence': str(root),
                      'cpu_valid': all(row['cpu']['valid'] for row in resources)}))


def main():
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
    args = parser.parse_args()
    os.umask(0o077)
    with own.lock_manifest(args.manifest) as (manifest, _):
        host = own.host_identity()
        own.admit(manifest, host, 'native-tv' if args.native_tv else 'vm-rehearsal')
        if args.recover: recover(manifest)
        else: execute(args, manifest, host)


if __name__ == '__main__': main()
