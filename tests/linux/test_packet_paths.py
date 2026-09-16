# SPDX-License-Identifier: GPL-3.0-or-later
"""Persistent payload and large-DNS proof; privileged work requires --vm."""
import json
import hashlib
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


REPO = Path(__file__).resolve().parents[2]


class CounterNoise(RuntimeError):
    def __init__(self, row):
        super().__init__('unlisted unknown AF_UNIX activity contaminated global counters')
        self.row = row


def read_json(process, timeout=30):
    deadline, line = time.monotonic() + timeout, bytearray()
    while len(line) < 8192:
        if not select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            raise RuntimeError('owned packet process did not report within deadline')
        byte = os.read(process.stdout.fileno(), 1)
        if not byte:
            raise RuntimeError('owned packet process exited before its report')
        if byte == b'\n':
            return json.loads(line)
        line.extend(byte)
    raise RuntimeError('owned packet process report exceeded its bound')


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream:
                stream.close()


def ledger(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def guest_cpu():
    ticks = [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
    return sum(ticks[i] for i in (0, 1, 2, 5, 6)) / os.sysconf('SC_CLK_TCK')


def payload_digest(size, count):
    digest = hashlib.sha256()
    base = bytes((j ^ 0x5a) & 255 for j in range(size))
    for sequence in range(count):
        digest.update(base.translate(bytes(x ^ (sequence & 255) for x in range(256))))
    return digest.hexdigest()


def measure(binary, proto, size, count, mark, prefix, stats, peer_ledger, log):
    first_peer_row = len(ledger(peer_ledger))
    with log.open('wb') as errors:
        process = subprocess.Popen([*prefix, str(binary), proto, '10.200.0.2', '57053',
                                    str(size), str(count), str(mark)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True)
    try:
        connected = read_json(process)
        assert connected['connected'] and connected['source'] == '10.200.0.1'
        before = stats()
        time.sleep(.1)
        idle = stats()
        log.with_suffix('.idle.json').write_text(json.dumps({key: idle[key] - before[key] for key in before}))
        before = idle
        cpu = guest_cpu()
        process.stdin.write('go\n')
        process.stdin.flush()
        result = read_json(process)
        cpu = guest_cpu() - cpu
        after = stats()
        # Start after socket creation/connect; finish before client close/exit.
        # All IP payload send/receive calls occur inside these snapshots.
        delta = {key: after[key] - before[key] for key in before}
        log.with_suffix('.counters.json').write_text(json.dumps({'before': before, 'after': after, 'delta': delta}))
        assert delta['included'] == 0, delta
        assert result['operations'] == count and result['bytes'] == size * count
        assert (result['peer'], result['peer_port']) == ('10.200.0.2', 57053)
        process.stdin.write('close\n')
        process.stdin.flush()
        assert process.wait(timeout=3) == 0
        deadline = time.monotonic() + 2
        while True:
            matches = [r for r in ledger(peer_ledger)[first_peer_row:] if r['kind'] == 'payload' and
                       r['protocol'] == proto and r['peer'] == ['10.200.0.1', connected['source_port']]]
            if matches:
                break
            assert time.monotonic() < deadline, 'peer did not record the completed stream'
            time.sleep(.01)
        observed = matches[-1]
        assert observed['operations'] == count and observed['bytes'] == size * count
        assert observed['sha256'] == payload_digest(size, count)
        result.update({'protocol': proto, 'payload_bytes': size, 'source': connected,
                       'guard_counter_delta': delta, 'peer_observation': observed,
                       'guest_active_cpu_ns_per_operation': cpu * 1e9 / count,
                       'client_cpu_ns_per_operation': result['client_cpu_ns'] / count,
                       'echo_payload_bytes_per_second': result['bytes'] * 1e9 / result['elapsed_ns']})
        if delta['guard_path_lookups']:
            # Selected guard lookups increment denies; IP sockets never take
            # stream_guard's AF_UNIX unknown-stream branch. Retain this row and
            # retry only this precise global-counter contamination signature.
            assert delta['guard_path_lookups'] == delta['guard_unknown_stream'], delta
            assert delta['guard_denies'] == 0 and delta['guard_objects'] == 0, delta
            raise CounterNoise(result)
        return result
    finally:
        stop(process)


def vm():
    from fixtures import clear_owned_zone, run, vpn_fixture
    from wg_program_split.firewall import Firewall
    assert os.geteuid() == 0 and os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert socket.gethostname() != 'TV' and Path('/var/lib/wgps-vm-provisioned').is_file()
    output = REPO / 'local/validation' / ('wgps-payload-' + uuid.uuid4().hex[:8])
    output.mkdir(parents=True)
    print('Evidence:', output, flush=True)
    clients = Path(tempfile.mkdtemp(prefix='wgps-payload-', dir='/run'))
    try:
        clients.chmod(0o755)
        selected, ordinary = clients / 'selected', clients / 'ordinary'
        run('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
            str(REPO / 'tests/linux/payload_client.c'), '-o', str(selected))
        shutil.copy2(selected, ordinary)
        uid = '65534'
        assert subprocess.run(['pgrep', '-u', uid], capture_output=True, timeout=3).returncode == 1
        assert not any(r.get('priority') == 5702 for r in json.loads(run('ip', '-j', 'rule').stdout))
        prefix = ('setpriv', '--reuid', uid, '--regid', uid, '--clear-groups')
        loader, pins = str(REPO / 'build/linux/bpf-loader'), '/sys/fs/bpf/' + clients.name
        rows, dns_rows, contaminated = [], [], []
        loaded = rule = False
        server = None
        with vpn_fixture() as fixture:
            try:
                run('ip', '-n', 'wgps-peer', 'addr', 'add', '10.200.0.3/32', 'dev', 'wgps-wgpeer')
                with (output / 'peer-stderr.txt').open('wb') as errors:
                    server = subprocess.Popen(['ip', 'netns', 'exec', 'wgps-peer', sys.executable,
                        str(REPO / 'tests/linux/packet_server.py'), '10.200.0.2', '10.200.0.3',
                        '57053', '53', str(output / 'peer.jsonl')],
                        stdout=subprocess.PIPE, stderr=errors, text=True)
                assert read_json(server)['ready']
                # Both candidates use the same UID and executable bytes. This
                # route only supplies the test baseline; product clients use paths.
                run('ip', 'rule', 'add', 'priority', '5702', 'uidrange', uid + '-' + uid, 'table', '57001')
                rule = True
                result = run(loader, 'load', str(REPO / 'build/linux/classifier.bpf.o'), pins,
                             '/sys/fs/cgroup', '0xffff0000', '0x10000', str(selected))
                loaded = True
                (output / 'verifier.txt').write_text(result.stderr)
                run(loader, 'state', pins, 'ready')

                def stats():
                    lines = run(loader, 'status', pins).stdout.splitlines()
                    return {key: int(value) for line in lines if '=' in line
                            for key, value in [line.split('=', 1)] if value.isdecimal()}

                for proto, size, count in (('udp', 1200, 2000), ('tcp', 16384, 1000)):
                    for repeat in range(5):
                        candidates = [('plain-wireguard', ordinary, 0), ('selected', selected, 0x10000)]
                        for name, binary, mark in candidates[::1 if repeat % 2 == 0 else -1]:
                            # Remove prior tuple state before either class reuses a port.
                            for attempt in range(4):
                                clear_owned_zone(57001)
                                try:
                                    row = measure(binary, proto, size, count, mark, prefix, stats,
                                                  output / 'peer.jsonl',
                                                  output / f'{proto}-{repeat}-{name}-{attempt}.stderr')
                                    break
                                except CounterNoise as error:
                                    contaminated.append({'candidate': name, 'repeat': repeat, 'attempt': attempt,
                                                         **error.row})
                                    (output / 'contaminated.json').write_text(json.dumps(contaminated, indent=2) + '\n')
                            else:
                                raise RuntimeError('no zero-lookup payload window in four bounded attempts')
                            assert row['guard_counter_delta']['guard_path_lookups'] == 0
                            row.update({'candidate': name, 'repeat': repeat})
                            rows.append(row)
                            (output / 'payload.json').write_text(json.dumps(rows, indent=2) + '\n')
                        print('Completed persistent', proto, 'pair', repeat + 1, flush=True)

                run(loader, 'state', pins, 'blocked')
                clear_owned_zone(57001)
                rules = Firewall('10.200.0.1', '10.200.0.3', table='wgps_dns_proof', mask=0xffff0000).render()
                run('nft', '-f', '-', input='delete table inet wgps_dns_proof\n' + rules)
                run('sysctl', '-w', 'net.ipv4.conf.wgps0.route_localnet=1')
                run(loader, 'state', pins, 'ready')
                direct_before = ledger(fixture / 'direct.jsonl')
                for mode in ('edns', 'fallback'):
                    observed = json.loads(run(str(selected), mode, '127.0.0.60', '53',
                                              '198.51.100.7', '0x10000').stdout)
                    assert observed['response_bytes'] > 2048 and observed['tcp_fallback'] == (mode == 'fallback')
                    dns_rows.append({'mode': mode, **observed})
                deadline = time.monotonic() + 2
                while len([r for r in ledger(output / 'peer.jsonl') if r['kind'] == 'dns']) < 3:
                    assert time.monotonic() < deadline, 'large DNS peer evidence missing'
                    time.sleep(.01)
                dns_peer = [r for r in ledger(output / 'peer.jsonl') if r['kind'] == 'dns']
                assert [(r['name'], r['protocol'], r['truncated']) for r in dns_peer] == [
                    ('large.test', 'udp', False), ('fallback.test', 'udp', True), ('fallback.test', 'tcp', False)]
                assert all(r['peer'][0] == '10.200.0.1' and r['edns_size'] == 4096 for r in dns_peer)
                peer_mtu = json.loads(run('ip', '-n', 'wgps-peer', '-j', 'link', 'show', 'wgps-wgpeer').stdout)[0]['mtu']
                assert dns_peer[0]['bytes'] > max(2048, peer_mtu) and dns_peer[2]['bytes'] > 2048
                assert ledger(fixture / 'direct.jsonl') == direct_before, 'selected DNS reached direct responder'
                (output / 'dns.json').write_text(json.dumps({'results': dns_rows, 'peer': dns_peer,
                                                            'peer_wireguard_mtu': peer_mtu}, indent=2) + '\n')
                (output / 'guard-status.txt').write_text(run(loader, 'status', pins).stdout)
                for name in ('direct.jsonl', 'vpn.jsonl'):
                    (output / name).write_text((fixture / name).read_text() if (fixture / name).exists() else '')
            finally:
                failures = []
                def cleanup(action):
                    try:
                        action()
                    except Exception as error:
                        failures.append(str(error))
                if loaded:
                    cleanup(lambda: run(loader, 'state', pins, 'blocked'))
                if server:
                    cleanup(lambda: stop(server))
                    if server.returncode != 0:
                        failures.append(f'owned packet server exited with {server.returncode}')
                if loaded:
                    cleanup(lambda: run(loader, 'remove', pins))
                if rule:
                    cleanup(lambda: run('ip', 'rule', 'delete', 'priority', '5702',
                                        'uidrange', uid + '-' + uid, 'table', '57001'))
                if failures:
                    raise RuntimeError('Packet fixture cleanup failed: ' + '; '.join(failures))
        result = {'kernel': os.uname().release, 'rows': rows, 'dns': dns_rows, 'contaminated_rows': contaminated,
                  'note': 'VM observations, no SLO verdict. Persistent sequential echo RTT includes the Python peer. '
                          'Echo throughput counts one payload direction, not link capacity. Client CPU excludes the peer; '
                          'guest active CPU includes all guest work at scheduler-tick resolution. Both candidates have '
                          'the guards attached; plain WireGuard uses a test-only UID route and no selected mark. '
                          'The payload counter window excludes socket creation and teardown. '
                          'At most four attempts per candidate reject only unlisted unknown AF_UNIX counter noise; '
                          'rejected raw measurements remain recorded. Accepted timing rows are conditional on a '
                          'quiet counter window and can have selection bias.'}
        (output / 'measurements.json').write_text(json.dumps(result, indent=2) + '\n')
        print('PASS: 20 persistent transfers, payload lookup counters, large EDNS, and TCP fallback')
    finally:
        shutil.rmtree(clients)


class NativePacketTests(unittest.TestCase):
    def test_persistent_tcp_udp_integrity_and_large_dns_protocols(self):
        from packet_server import Servers
        with tempfile.TemporaryDirectory(prefix='wgps-packet-', dir=Path.home()) as directory:
            binary = str(Path(directory) / 'client')
            subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(REPO / 'tests/linux/payload_client.c'), '-o', binary],
                           check=True, capture_output=True, timeout=30)
            with Servers('127.0.0.1', '127.0.0.1', 0, 0, Path(directory) / 'ledger.jsonl') as server:
                for proto in ('tcp', 'udp'):
                    result = subprocess.run([binary, proto, '127.0.0.1', str(server.payload_port),
                                             '1200', '20', '0'], input='go\nclose\n', text=True,
                                            capture_output=True, check=True, timeout=5)
                    ready, measured = [json.loads(row) for row in result.stdout.splitlines()]
                    self.assertTrue(ready['connected'])
                    self.assertEqual(measured['bytes'], 24000)
                    self.assertEqual(measured['operations'], 20)
                for proto in ('edns', 'fallback'):
                    result = subprocess.run([binary, proto, '127.0.0.1', str(server.dns_port), '198.51.100.7', '0'],
                                            text=True, capture_output=True, check=True, timeout=5)
                    observed = json.loads(result.stdout)
                    self.assertGreater(observed['response_bytes'], 2048)
                    self.assertEqual(observed['tcp_fallback'], proto == 'fallback')
                rows = [json.loads(line) for line in server.ledger.read_text().splitlines()]
                self.assertEqual(sum(r.get('operations', 0) for r in rows), 40)
                self.assertEqual({r['protocol'] for r in rows if r['kind'] == 'dns'}, {'udp', 'tcp'})


if __name__ == '__main__':
    if sys.argv[1:] == ['--vm']:
        vm()
    else:
        unittest.main()
