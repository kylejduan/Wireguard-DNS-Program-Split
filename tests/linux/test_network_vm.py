# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit disposable-VM acceptance for the real network ownership adapter."""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid

from fixtures import vpn_fixture, run
from wg_program_split.config import Profile
from wg_program_split.network import Network, NetworkError, _legacy_mask, allocate, inspect, run_command
from wg_program_split import ownership as own


# The review's scenario: TCP/443 connections are tagged 0x01000000 in the
# conntrack mark, which a restore copies back with a narrow nfmask but every
# ctmask bit, so the XOR can set bits of the mask the controller would pick.
TAG = ['-p', 'tcp', '--dport', '443', '-j', 'CONNMARK', '--set-xmark', '0x1000000/0xffffffff']


def restore(ctmask, *shift):
    return ['-p', 'tcp', '--dport', '443', '-j', 'CONNMARK', '--restore-mark',
            '--nfmask', '0xff0000', '--ctmask', ctmask, *shift]


def ipset(command, name, **data):
    """Minimal ipset netlink client (the ipset tool is not installed): create a
    hash:ip set with skbinfo, add an address with an skbmark, or destroy."""
    def attribute(kind, payload, flags=0):
        size = 4 + len(payload)
        return struct.pack('=HH', size, kind | flags) + payload + bytes(-size % 4)
    nested, net = 1 << 15, 1 << 14
    attributes = attribute(1, b'\x07') + attribute(2, name.encode() + b'\0')
    if command == 'create':
        attributes += (attribute(3, b'hash:ip\0') + attribute(4, b'\x04') + attribute(5, b'\x02') +
                       attribute(7, attribute(8, struct.pack('>I', 1 << 6), net), nested))  # with skbinfo
    elif command == 'add':
        address = attribute(1, socket.inet_aton(data['address']), net)
        mark = attribute(27, struct.pack('>Q', data['mark'] << 32 | data['mask']), net)
        attributes += attribute(7, attribute(1, address, nested) + mark, nested)
    kind = 6 << 8 | {'create': 2, 'destroy': 3, 'add': 9}[command]
    body = struct.pack('=BBH', socket.AF_INET, 0, 0) + attributes
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as channel:
        channel.send(struct.pack('=IHHII', 16 + len(body), kind, 1 | 4, 1, 0) + body)  # REQUEST | ACK
        reply = channel.recv(65536)
    if struct.unpack_from('=H', reply, 4)[0] != 2 or struct.unpack_from('=i', reply, 16)[0] != 0:
        raise RuntimeError('ipset ' + command + ' failed: ' + str(struct.unpack_from('=i', reply, 16)[0]))


def rewrite(action):
    """The review's rule: before conntrack, move loopback DNS to port 5353 untracked."""
    if action == 'delete':
        run('nft', 'delete', 'table', 'inet', 'wgps_rewrite')
        return
    run('nft', '-f', '-', input='table inet wgps_rewrite {\n chain out {\n  type filter hook output priority -310; '
        'policy accept;\n  ip daddr 127.0.0.60 udp dport 53 udp dport set 5353 notrack\n }\n}\n')


def legacy(action, rules):
    for rule in rules:
        run('iptables-legacy', '-t', 'mangle', action, 'OUTPUT', *rule)


def main():
    if sys.argv[1:] != ['--vm']:
        raise SystemExit('privileged acceptance requires --vm on the marked disposable VM')
    assert os.geteuid() == 0 and os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert Path('/var/lib/wgps-vm-provisioned').is_file()
    repo = Path(__file__).resolve().parents[2]
    evidence = repo / 'local/validation' / ('network-' + uuid.uuid4().hex[:10])
    evidence.mkdir(parents=True)
    direct, included = evidence / 'direct', evidence / 'included'
    run('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
        str(repo / 'tests/linux/dns_client.c'), '-o', str(direct))
    shutil.copy2(direct, included)
    loader = str(repo / 'build/linux/bpf-loader')
    pins = '/sys/fs/bpf/' + evidence.name
    state = Path('/run') / evidence.name
    state.mkdir(mode=0o700)
    checks = []
    trace = []
    cleaned = False

    def runner(argv, *, input=None):
        # Input can contain private WireGuard material: never record it.
        trace.append(list(argv))
        return run_command(argv, input=input)

    def passed(name):
        checks.append(name)
        print('PASS', name, flush=True)

    before_routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'main').stdout)
    mangle_existed = subprocess.run(['nft', 'list', 'table', 'ip', 'mangle'], capture_output=True).returncode == 0
    before_rules = json.loads(run('ip', '-j', '-4', 'rule', 'show').stdout)
    try:
        with vpn_fixture(owned_host=False) as peer:
            profile = Profile(address='10.200.0.1/24', resolver='10.200.0.2',
                              endpoint_host='192.0.2.2', endpoint_port=51822,
                              private_key=(peer / 'host.key').read_text().strip(),
                              public_key=(peer / 'peer.pub').read_text().strip())
            # Legacy CONNMARK restores reserve nfmask and the shifted ctmask.
            for ctmask, shift, reserved in (('0xffffffff', (), 0xffffffff), ('0x3000000', (), 0x3ff0000),
                                            ('0x3', ('--left-shift-mark', '24'), 0x3ff0000)):
                rules = [TAG, restore(ctmask, *shift)]
                legacy('-A', rules)
                try:
                    assert _legacy_mask(run('iptables-legacy-save', '-t', 'mangle').stdout) == reserved
                    try:
                        candidate = allocate(inspect(profile, runner=runner))
                    except NetworkError:
                        assert reserved == 0xffffffff, 'refused although free mark bits remain'
                    else:
                        assert reserved != 0xffffffff and not candidate.mask & reserved, (hex(candidate.mask), hex(reserved))
                finally:
                    legacy('-D', rules)
            passed('legacy CONNMARK restores never yield an overlapping allocation')
            # An ipset entry's skbmark, applied by SET --map-mark, can overwrite
            # any bit and changes without an iptables edit: always refused.
            ipset('create', 'wgps_marks')
            try:
                ipset('add', 'wgps_marks', address='192.0.2.99', mark=0x3000000, mask=0xffffffff)
                for tool in ('iptables-legacy', 'iptables-nft'):
                    rule = ['-p', 'udp', '-j', 'SET', '--map-set', 'wgps_marks', 'dst', '--map-mark']
                    run(tool, '-t', 'mangle', '-A', 'OUTPUT', *rule)
                    try:
                        try:
                            allocate(inspect(profile, runner=runner))
                            raise AssertionError(tool + ' SET --map-mark was not refused')
                        except NetworkError:
                            pass
                    finally:
                        run(tool, '-t', 'mangle', '-D', 'OUTPUT', *rule)
                if not mangle_existed and subprocess.run(['nft', 'list', 'table', 'ip', 'mangle'],
                                                         capture_output=True).returncode == 0:
                    run('nft', 'delete', 'table', 'ip', 'mangle')
            finally:
                ipset('destroy', 'wgps_marks')
            passed('SET --map-mark from a real skbmark ipset is refused in both iptables flavours')
            # A stateless port rewrite before conntrack moves DNS past the owned guards.
            rewrite('add')
            try:
                try:
                    allocate(inspect(profile, runner=runner))
                    raise AssertionError('a foreign stateless port rewrite was not refused')
                except NetworkError as error:
                    assert 'udp dport' in str(error), str(error)
            finally:
                rewrite('delete')
            passed('a foreign stateless DNS port rewrite is refused at activation')
            allocation = allocate(inspect(profile, runner=runner))
            run(loader, 'load', str(repo / 'build/linux/classifier.bpf.o'), pins,
                '/sys/fs/cgroup', hex(allocation.mask), hex(allocation.mark), str(included))
            try:
                with own.locked_state(state) as fd:
                    network = Network(profile, fd, runner=runner, allocation=allocation)
                    try:
                        receipt = network.prepare(guard_blocked=True)
                        assert network.health().ready
                        passed('real owned acquisition and complete effective network readback')
                        main_routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'main').stdout)
                        assert not any(route.get('dev') == 'wgps0' for route in main_routes)
                        passed('profile prefix does not change unlisted main routes')
                        run(loader, 'state', pins, 'ready')
                        for proto in ('udp', 'udp-connected', 'tcp'):
                            run(str(included), proto, '127.0.0.60', '198.51.100.7', hex(allocation.mark), '1')
                            run(str(direct), proto, '127.0.0.60', '203.0.113.7', '0', '1')
                        assert network.health().ready
                        passed('automatic included VPN DNS and unlisted direct DNS survive real counters')
                        mismatch = Network(replace(profile, resolver='10.200.0.99'), fd,
                                           runner=runner, receipt=receipt)
                        assert not mismatch.health().ready
                        passed('changed resolver cannot adopt old firewall readiness')
                        rules = [TAG, restore('0xffffffff')]
                        legacy('-A', rules)
                        try:
                            assert 'allocation:foreign' in network.health().changed
                            assert not network.health().ready
                        finally:
                            legacy('-D', rules)
                        assert network.health().ready
                        passed('a legacy CONNMARK restore reaching the owned mask blocks readiness')
                        rewrite('add')
                        try:
                            try:
                                network.health()
                                raise AssertionError('health accepted a foreign stateless port rewrite')
                            except NetworkError as error:
                                assert 'udp dport' in str(error), str(error)
                        finally:
                            rewrite('delete')
                        assert network.health().ready
                        passed('a foreign stateless DNS port rewrite added while running fails health')
                        run('ip', 'link', 'set', 'wgps-underlay', 'down')
                        counts = [(peer / name).read_text() for name in ('vpn.jsonl', 'direct.jsonl')]
                        try:
                            run(str(included), 'udp', '127.0.0.60', '198.51.100.7', hex(allocation.mark), '1')
                            raise AssertionError('selected DNS unexpectedly succeeded with underlay down')
                        except RuntimeError:
                            pass
                        assert counts == [(peer / name).read_text() for name in ('vpn.jsonl', 'direct.jsonl')]
                        run(str(direct), 'udp', '127.0.0.60', '203.0.113.7', '0', '1')
                        run('ip', 'link', 'set', 'wgps-underlay', 'up')
                        run(str(included), 'udp', '127.0.0.60', '198.51.100.7', hex(allocation.mark), '1')
                        passed('underlay loss retains DNS separation and restored underlay recovers')
                        anchors = [r for r in network.receipt.resources if r.kind not in ('interface', 'sysctl')
                                   and not (r.kind == 'route' and r.name == 'preferred')]
                        for loss in ('route', 'interface'):
                            run(loader, 'state', pins, 'blocked')
                            if loss == 'route':
                                run('ip', 'route', 'delete', 'table', str(allocation.routing_table),
                                    'default', 'dev', 'wgps0', 'metric', '10', 'proto', 'static')
                            else:
                                run('ip', 'link', 'delete', 'wgps0')
                            assert network.health().missing
                            network.repair_missing(guard_blocked=True)
                            assert network.health().ready
                            assert all(r in network.receipt.resources for r in anchors)
                            run(loader, 'state', pins, 'ready')
                            deadline = time.monotonic() + 10
                            while True:
                                try:
                                    run(str(included), 'udp', '127.0.0.60', '198.51.100.7',
                                        hex(allocation.mark), '1')
                                    break
                                except RuntimeError:
                                    if time.monotonic() >= deadline:
                                        raise
                                    time.sleep(0.1)
                            run(str(direct), 'udp', '127.0.0.60', '203.0.113.7', '0', '1')
                            passed('missing owned ' + loss + ' repaired with intact safety anchors and DNS separation')
                    finally:
                        run(loader, 'state', pins, 'blocked')
                        remaining = network.disable(guard_blocked=True)
                        assert not remaining.resources, 'owned resources remain after explicit disable'
                        cleaned = True
                    passed('exact network disable removes owned resources and zone')
            finally:
                if cleaned:
                    run(loader, 'remove', pins)
        assert before_routes == json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'main').stdout)
        assert before_rules == json.loads(run('ip', '-j', '-4', 'rule', 'show').stdout)
        passed('fixture and adapter restore pre-test unlisted routes and rules')
        (evidence / 'results.json').write_text(json.dumps(checks, indent=2) + '\n')
    finally:
        (evidence / 'commands.json').write_text(json.dumps(trace, indent=2) + '\n')
        if (state / 'receipt.json').exists():
            shutil.copy2(state / 'receipt.json', evidence / 'receipt.json')
        if cleaned:
            shutil.rmtree(state)
        else:
            print('Retained failed-test state and any guard pins for ownership inspection:', state, pins)
        print('Evidence:', evidence, flush=True)


if __name__ == '__main__':
    main()
