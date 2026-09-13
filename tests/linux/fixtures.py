#!/usr/bin/env python3
"""Owned disposable-VM WireGuard peer and controlled DNS responders."""
import contextlib
import shutil
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def run(*args, **kwargs):
    kwargs.setdefault('timeout', 30)
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result


def respond(data, answer):
    end = 12
    while data[end]:
        end += data[end] + 1
    question = data[12:end + 5]
    qtype, qclass = struct.unpack('!HH', data[end + 1:end + 5])
    # NODATA for SOA/AAAA keeps real libc/mDNS behavior meaningful. A records
    # have a positive TTL so a daemon can demonstrably populate a warm cache.
    if (qtype, qclass) != (1, 1):
        return data[:2] + struct.pack('!HHHHH', 0x8180, 1, 0, 0, 0) + question
    return (data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question +
            b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(answer))


def serve(address, answer, ledger):
    def record(proto, peer, data):
        end, labels = 12, []
        while data[end]:
            length = data[end]
            labels.append(data[end + 1:end + 1 + length].decode('ascii', errors='replace'))
            end += length + 1
        qtype = struct.unpack('!H', data[end + 1:end + 3])[0]
        with open(ledger, 'a') as output:
            output.write(json.dumps({'protocol': proto, 'peer': peer,
                                     'name': '.'.join(labels), 'type': qtype}) + '\n')

    def tcp_loop():
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, 53))
            listener.listen()
            while True:
                conn, peer = listener.accept()
                with conn:
                    conn.settimeout(2)
                    header = conn.recv(2, socket.MSG_WAITALL)
                    if len(header) != 2:
                        continue
                    data = conn.recv(struct.unpack('!H', header)[0], socket.MSG_WAITALL)
                    response = respond(data, answer)
                    record('tcp', peer, data)
                    conn.sendall(struct.pack('!H', len(response)) + response)

    threading.Thread(target=tcp_loop, daemon=True).start()
    with socket.socket(type=socket.SOCK_DGRAM) as udp:
        udp.bind((address, 53))
        while True:
            data, peer = udp.recvfrom(4096)
            record('udp', peer, data)
            udp.sendto(respond(data, answer), peer)


QUERY = struct.pack('!HHHHHH', 42, 0x0100, 1, 0, 0, 0) + b'\x04wgps\x07invalid\x00\x00\x01\x00\x01'


def query(address, proto, mark, bind=None):
    started = time.monotonic_ns()
    with socket.socket(type=socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.7)
        if mark:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
        if bind:
            sock.bind((bind, 0))
        if proto in ('tcp', 'udp-connected'):
            sock.connect((address, 53))
            assert sock.getpeername() == (address, 53)
        if proto == 'tcp':
            sock.sendall(struct.pack('!H', len(QUERY)) + QUERY)
            header = sock.recv(2, socket.MSG_WAITALL)
            assert len(header) == 2
            data = sock.recv(struct.unpack('!H', header)[0], socket.MSG_WAITALL)
            peer = sock.getpeername()
        else:
            if proto == 'udp-connected':
                sock.send(QUERY)
            else:
                sock.sendto(QUERY, (address, 53))
            data, peer = sock.recvfrom(4096)
        assert peer == (address, 53), (peer, address)
        assert data[:2] == QUERY[:2]
        return socket.inet_ntoa(data[-4:]), (time.monotonic_ns() - started) / 1000


from wg_program_split.firewall import Firewall


def clear_owned_zone(zone):
    """Only call for zones proved empty and acquired by this fixture."""
    result = subprocess.run(['conntrack', '-D', '--zone', str(zone)],
                            text=True, capture_output=True, timeout=30)
    if result.returncode and not (result.returncode == 1 and
                                  '0 flow entries have been deleted' in result.stderr):
        raise RuntimeError('could not clear owned test conntrack zone')


def wait_ipv6_ready(device, *, namespace=None, timeout=5):
    """Wait only for this acquired veth's DAD and local-route publication."""
    prefix = ('ip', '-n', namespace) if namespace else ('ip',)
    command = ('ip', 'netns', 'exec', namespace) if namespace else ()
    disabled = run(*command, 'sysctl', '-n', f'net.ipv6.conf.{device}.disable_ipv6').stdout.strip()
    if disabled == '1': return  # Respect an existing disabled-IPv6 fixture default.
    assert disabled == '0', 'unexpected IPv6 interface configuration'
    birth = json.loads(run(*prefix, '-j', 'link', 'show', 'dev', device).stdout)[0]['ifindex']
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        links = json.loads(run(*prefix, '-j', '-6', 'address', 'show', 'dev', device).stdout)
        if links:
            assert len(links) == 1 and links[0]['ifindex'] == birth, 'owned IPv6 fixture link changed'
            addresses = [a for a in links[0]['addr_info'] if a['family'] == 'inet6']
            def flagged(address, flag): return address.get(flag) or flag in address.get('flags', [])
            if any(flagged(a, 'dadfailed') for a in addresses):
                raise RuntimeError('owned fixture IPv6 duplicate address detection failed')
            if addresses and not any(flagged(a, 'tentative') for a in addresses):
                routes = json.loads(run(*prefix, '-j', '-6', 'route', 'show', 'table', 'local', 'dev', device).stdout)
                local = {r.get('dst', '').split('/')[0] for r in routes if r.get('type') == 'local'}
                if all(a['local'] in local for a in addresses): return
        time.sleep(.02)
    raise RuntimeError('owned fixture IPv6 initialization did not finish')


@contextlib.contextmanager
def vpn_fixture(extra_zones=(), *, owned_host=True):
    assert os.geteuid() == 0
    assert os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert socket.gethostname() != 'TV' and 'microsoft' not in os.uname().release
    assert Path('/var/lib/wgps-vm-provisioned').is_file(), 'disposable VM marker missing'
    for resource in ('wgps0', 'wgps-underlay'):
        assert subprocess.run(['ip', 'link', 'show', resource], capture_output=True).returncode != 0
    assert subprocess.run(['ip', 'netns', 'exec', 'wgps-peer', 'true'], capture_output=True).returncode != 0
    assert subprocess.run(['nft', 'list', 'table', 'inet', 'wgps_dns_proof'], capture_output=True).returncode != 0
    assert not json.loads(run('ip', '-j', 'rule', 'show').stdout) or not any(rule.get('priority') == 5701 for rule in json.loads(run('ip', '-j', 'rule', 'show').stdout))
    routes = subprocess.run(['ip', '-j', 'route', 'show', 'table', '57001'], text=True, capture_output=True)
    assert not routes.stdout.strip() or json.loads(routes.stdout) == [], 'test route table is occupied'
    zones = (57001, *extra_zones) if owned_host else ()
    for zone in zones:
        assert type(zone) is int and 0 < zone < 65536
        assert not run('conntrack', '-L', '--zone', str(zone)).stdout.strip(), 'test conntrack zone is occupied'
    resources = []
    processes = []
    root = Path(tempfile.mkdtemp(prefix='wgps-dns-proof-', dir='/etc/wireguard'))
    try:
        for side in ('host', 'peer'):
            key = run('wg', 'genkey').stdout
            (root / (side + '.key')).write_text(key)
            (root / (side + '.key')).chmod(0o600)
            (root / (side + '.pub')).write_text(run('wg', 'pubkey', input=key).stdout.strip())
        run('ip', 'netns', 'add', 'wgps-peer')
        resources.append(('ip', 'netns', 'delete', 'wgps-peer'))
        run('ip', 'link', 'add', 'wgps-underlay', 'type', 'veth', 'peer', 'name', 'wgps-remote')
        resources.append(('ip', 'link', 'delete', 'wgps-underlay'))
        run('ip', 'link', 'set', 'wgps-remote', 'netns', 'wgps-peer')
        run('ip', 'addr', 'add', '192.0.2.1/30', 'dev', 'wgps-underlay')
        run('ip', 'link', 'set', 'wgps-underlay', 'up')
        run('ip', '-n', 'wgps-peer', 'addr', 'add', '192.0.2.2/30', 'dev', 'wgps-remote')
        run('ip', '-n', 'wgps-peer', 'link', 'set', 'wgps-remote', 'up')
        run('ip', '-n', 'wgps-peer', 'link', 'set', 'lo', 'up')
        if owned_host:
            run('ip', 'link', 'add', 'wgps0', 'type', 'wireguard')
            resources.append(('ip', 'link', 'delete', 'wgps0'))
        run('ip', '-n', 'wgps-peer', 'link', 'add', 'wgps-wgpeer', 'type', 'wireguard')
        if owned_host:
            run('wg', 'set', 'wgps0', 'private-key', str(root / 'host.key'), 'listen-port', '51821',
                'fwmark', '0x20000', 'peer', (root / 'peer.pub').read_text(),
                'allowed-ips', '0.0.0.0/0', 'endpoint', '192.0.2.2:51822')
        run('ip', 'netns', 'exec', 'wgps-peer', 'wg', 'set', 'wgps-wgpeer',
            'private-key', str(root / 'peer.key'), 'listen-port', '51822',
            'peer', (root / 'host.pub').read_text(), 'allowed-ips', '10.200.0.1/32',
            'endpoint', '192.0.2.1:51821')
        if owned_host:
            run('ip', 'addr', 'add', '10.200.0.1/32', 'dev', 'wgps0')
            run('ip', 'link', 'set', 'wgps0', 'up')
        run('ip', '-n', 'wgps-peer', 'addr', 'add', '10.200.0.2/32', 'dev', 'wgps-wgpeer')
        run('ip', '-n', 'wgps-peer', 'link', 'set', 'wgps-wgpeer', 'up')
        run('ip', '-n', 'wgps-peer', 'route', 'add', '10.200.0.1/32', 'dev', 'wgps-wgpeer')
        if owned_host:
            run('ip', 'route', 'add', 'table', '57001', 'unreachable', 'default', 'metric', '32760')
            resources.append(('ip', 'route', 'delete', 'table', '57001', 'unreachable', 'default', 'metric', '32760'))
            run('ip', 'route', 'add', 'table', '57001', 'default', 'dev', 'wgps0', 'metric', '10')
            resources.append(('ip', 'route', 'delete', 'table', '57001', 'default', 'dev', 'wgps0', 'metric', '10'))
            run('ip', 'rule', 'add', 'priority', '5701', 'fwmark', '0x10000/0xffff0000', 'table', '57001')
            resources.append(('ip', 'rule', 'delete', 'priority', '5701', 'fwmark', '0x10000/0xffff0000', 'table', '57001'))
            nft = Firewall('10.200.0.1', '10.200.0.2', table='wgps_dns_proof', mask=0xffff0000).render()
            run('nft', '-f', '-', input=nft)
            resources.append(('nft', 'delete', 'table', 'inet', 'wgps_dns_proof'))
        server_cmd = [sys.executable, str(Path(__file__).resolve()), 'server']
        processes.append(subprocess.Popen(['ip', 'netns', 'exec', 'wgps-peer', *server_cmd,
                                          '10.200.0.2', '198.51.100.7', str(root / 'vpn.jsonl')]))
        processes.append(subprocess.Popen([*server_cmd, '127.0.0.60', '203.0.113.7', str(root / 'direct.jsonl')]))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                if query('127.0.0.60', 'udp', 0)[0] == '203.0.113.7':
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise RuntimeError('controlled DNS responder did not start')
        wait_ipv6_ready('wgps-underlay')
        wait_ipv6_ready('wgps-remote', namespace='wgps-peer')
        yield root
    finally:
        cleanup_errors = []
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    cleanup_errors.append(f'owned responder PID {proc.pid} did not exit')
        for command in reversed(resources):
            try:
                # Kernel link-down handling can already remove the owned route.
                if command[:3] == ('ip', 'route', 'delete') and 'dev' in command:
                    routes = json.loads(run('ip', '-j', 'route', 'show', 'table', '57001').stdout)
                    device = command[command.index('dev') + 1]
                    metric = int(command[command.index('metric') + 1])
                    if not any(r.get('dst') == 'default' and r.get('dev') == device and
                               r.get('metric') == metric for r in routes):
                        continue
                result = subprocess.run(command, text=True, capture_output=True, timeout=30)
                if result.returncode:
                    cleanup_errors.append(f'{command}: {result.stderr}')
            except (subprocess.TimeoutExpired, RuntimeError, ValueError) as error:
                cleanup_errors.append(f'cleanup failed: {command}: {error}')
        for zone in zones:
            try:
                clear_owned_zone(zone)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(str(error))
        shutil.rmtree(root)
        if cleanup_errors:
            raise RuntimeError('Fixture cleanup failed: ' + '; '.join(cleanup_errors))


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == 'server':
        serve(*sys.argv[2:])
    else:
        raise SystemExit('fixture helper requires server arguments')
