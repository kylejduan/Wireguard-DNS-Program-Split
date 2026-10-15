# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged rule tests; --vm exercises real automatic selection and DNS."""
import unittest
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import socket
import statistics
import subprocess
import sys
import time
import uuid

from wg_program_split.firewall import Firewall


class FirewallTests(unittest.TestCase):
    def test_rejects_rule_injection(self):
        for value in ('bad; flush ruleset', '../wg', 'a"b', ''):
            with self.assertRaises(ValueError):
                Firewall('10.200.0.1', '10.200.0.2', interface=value)

    def test_rejects_unsafe_addresses_and_marks(self):
        for address in ('::1', '0.0.0.0', '127.0.0.53', '224.0.0.1'):
            with self.assertRaises(ValueError):
                Firewall('10.200.0.1', address)
        with self.assertRaises(ValueError):
            Firewall('10.200.0.1', '10.200.0.2', mask=0x10000, mark=0x20000)

    def test_rules_scope_translation_and_guard_to_selected_mark(self):
        rules = Firewall('10.200.0.1', '10.200.0.2').render()
        self.assertIn('hook postrouting priority filter', rules)
        self.assertIn('dnat ip to 10.200.0.2:53', rules)
        self.assertIn('snat ip to 10.200.0.1', rules)
        self.assertNotIn('flush ruleset', rules)
        self.assertNotIn('hook output priority filter', rules)

    def test_selected_dns_reaches_only_the_tunnel_resolver_after_any_nat(self):
        """Destination NAT happens once: an earlier foreign NAT chain can claim
        selected DNS. The egress chain (after all NAT) drops selected traffic to
        or originally to port 53 unless it goes to the tunnel resolver, before
        the loopback allowance, and selection is the packet mark."""
        rules = Firewall('10.200.0.1', '10.200.0.2', mask=0xff0000, mark=0x10000).render()
        egress = rules[rules.index('chain egress'):rules.index('chain loopback_input')]
        lines = [line.strip() for line in egress.splitlines()]
        guards = [index for index, line in enumerate(lines) if '10.200.0.2' in line]
        selected = 'meta nfproto ipv4 meta mark & 0xff0000 == 0x10000 meta l4proto { tcp, udp } '
        # Original-direction or untracked packets only: an enrolled DNS server's
        # replies to an unlisted client also carry the mark and original port 53.
        self.assertEqual([lines[index] for index in guards], [
            selected + 'th dport 53 ct direction original ip daddr != 10.200.0.2 counter drop',
            selected + 'th dport 53 ct state untracked ip daddr != 10.200.0.2 counter drop',
            selected + 'ct direction original ct original proto-dst 53 ip daddr != 10.200.0.2 counter drop'])
        loopback = next(index for index, line in enumerate(lines) if 'oifname "lo"' in line)
        tunnel = next(index for index, line in enumerate(lines) if 'oifname "wgps0" accept' in line)
        self.assertLess(max(guards), min(loopback, tunnel))


def enrolled_forwarder_replies(client, direct):
    """An enrolled (selected-mark) DNS server answering an unlisted loopback
    client: its replies carry the selected mark and an original port 53, and
    must still be delivered (the guard checks original-direction packets only)."""
    import struct
    import threading
    from fixtures import respond
    address, answer, mark = '127.0.0.61', '203.0.113.61', 0x10000
    udp = socket.socket(type=socket.SOCK_DGRAM)
    listener = socket.socket()
    for sock in (udp, listener):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, 53))
    listener.listen()
    stop = threading.Event()

    def serve_udp():
        udp.settimeout(0.2)
        while not stop.is_set():
            try:
                data, peer = udp.recvfrom(4096)
            except OSError:
                continue
            udp.sendto(respond(data, answer), peer)

    def serve_tcp():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            with conn:
                assert conn.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == mark
                conn.settimeout(2)
                size = struct.unpack('!H', conn.recv(2, socket.MSG_WAITALL))[0]
                response = respond(conn.recv(size, socket.MSG_WAITALL), answer)
                conn.sendall(struct.pack('!H', len(response)) + response)
    threads = [threading.Thread(target=serve_udp, daemon=True), threading.Thread(target=serve_tcp, daemon=True)]
    for thread in threads:
        thread.start()
    try:
        for proto in ('udp', 'udp-connected', 'tcp'):
            client(direct, proto, address, answer=answer)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
        udp.close()
        listener.close()


def foreign_nat_bypass(state, client, included, direct, repo):
    """A foreign nat output chain at priority -110 takes destination NAT for
    port 53 before ours. Selected queries must be dropped, never answered by
    the loopback stub or any other resolver; unlisted queries follow it."""
    from fixtures import run
    servers, ledgers = [], [state / 'vpn.jsonl', state / 'direct.jsonl']
    for address in ('127.0.0.1', '192.0.2.1'):  # A stub on loopback, and a local non-loopback resolver.
        ledger = state / ('foreign-' + address + '.jsonl')
        ledgers.append(ledger)
        servers.append(subprocess.Popen([sys.executable, str(repo / 'tests/linux/fixtures.py'), 'server',
                                         address, '203.0.113.7', str(ledger)]))
    try:
        def answered(address):
            try:
                return client(direct, 'udp', address) is not None
            except RuntimeError:
                return False
        deadline = time.monotonic() + 5
        while not all(answered(address) for address in ('127.0.0.1', '192.0.2.1')):
            assert time.monotonic() < deadline, 'foreign fixture resolvers did not start'
        def drops():
            listing = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'wgps_dns_proof', 'egress').stdout)
            return sum(expr['counter']['packets'] for item in listing['nftables'] if 'rule' in item
                       if '10.200.0.2' in json.dumps(item) for expr in item['rule']['expr'] if 'counter' in expr)
        nat = 'type nat hook output priority -110'
        for hook, action, local in ((nat, 'dnat ip to 127.0.0.60:53', True), (nat, 'dnat ip to 192.0.2.1:53', True),
                                    (nat, 'redirect', True), (nat, 'dnat ip to 203.0.113.99:53', False)):
            run('nft', '-f', '-', input='table inet wgps_foreign_nat {\n chain out {\n  ' + hook + '; policy accept;\n'
                '  meta l4proto { tcp, udp } th dport 53 ' + action + '\n }\n}\n')
            try:
                for proto in ('udp', 'tcp'):
                    before = [ledger.read_text() if ledger.exists() else '' for ledger in ledgers]
                    counted = drops()
                    try:
                        client(included, proto)
                        raise AssertionError('selected DNS was answered after foreign ' + action)
                    except RuntimeError:
                        pass
                    after = [ledger.read_text() if ledger.exists() else '' for ledger in ledgers]
                    assert before == after, 'selected DNS reached a resolver after foreign ' + action
                    assert drops() > counted, 'selected DNS was not dropped by the owned guard'
                    if local:
                        client(direct, proto)  # Unlisted DNS follows the foreign rule.
            finally:
                run('nft', 'delete', 'table', 'inet', 'wgps_foreign_nat')
        # NOTRACK cannot stop the DNS NAT: the owned raw chain gives selected DNS a
        # conntrack zone template first, and notrack leaves a template alone,
        # whether it runs before (-310) or after (-250) that chain.
        for priority in ('-310', '-250'):
            run('nft', '-f', '-', input='table inet wgps_foreign_nat {\n chain out {\n  type filter hook output '
                'priority ' + priority + '; policy accept;\n  meta l4proto { tcp, udp } th dport 53 notrack\n }\n}\n')
            try:
                for proto in ('udp', 'tcp'):
                    before = [ledger.read_text() if ledger.exists() else '' for ledger in ledgers]
                    client(included, proto)  # Answered by the tunnel resolver only.
                    after = [ledger.read_text() if ledger.exists() else '' for ledger in ledgers]
                    assert after[0] != before[0] and after[1:] == before[1:], 'NOTRACK changed selected DNS'
                    client(direct, proto)
            finally:
                run('nft', 'delete', 'table', 'inet', 'wgps_foreign_nat')
        client(included, 'udp')
        client(direct, 'udp')
    finally:
        for server in servers:
            server.kill()
            server.wait(timeout=5)
        # Unlisted flows the foreign rules translated keep their conntrack NAT
        # for up to two minutes; a later client reusing such a source port would
        # follow it to a stopped server. Remove every translated DNS flow.
        for proto in ('udp', 'tcp'):
            subprocess.run(['conntrack', '-D', '-p', proto, '--dst-nat'], capture_output=True)


def vm_tests():
    from fixtures import vpn_fixture, run
    repo = Path(__file__).resolve().parents[2]
    assert os.geteuid() == 0 and os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert Path('/var/lib/wgps-vm-provisioned').is_file()
    tag = 'wgps-dns-' + uuid.uuid4().hex[:8]
    evidence = repo / 'local' / 'validation' / tag
    evidence.mkdir(parents=True)
    evidence.chmod(0o755)
    direct, included = evidence / 'direct', evidence / 'included'
    run('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
        str(repo / 'tests/linux/dns_client.c'), '-o', str(direct))
    shutil.copy2(direct, included)
    loader = str(repo / 'build/linux/bpf-loader')
    pins = '/sys/fs/bpf/' + tag
    loaded = False
    checks = []

    def client(path, proto, destination='127.0.0.60', answer=None, count=1, source=None, prefix=()):
        selected = path == included
        args = [*prefix, str(path), proto, destination,
                answer or ('198.51.100.7' if selected else '203.0.113.7'),
                '0x10000' if selected else '0', str(count)]
        if source:
            args.append(source)
        return run(*args).stdout

    def passed(name):
        checks.append(name)
        print('PASS', name, flush=True)

    def blocked(state, proto):
        before = [(state / name).read_text().splitlines() if (state / name).exists() else []
                  for name in ('direct.jsonl', 'vpn.jsonl')]
        with unittest.TestCase().assertRaises(RuntimeError):
            client(included, proto)
        after = [(state / name).read_text().splitlines() if (state / name).exists() else []
                 for name in ('direct.jsonl', 'vpn.jsonl')]
        assert before == after, 'blocked selected lookup reached a DNS responder'

    try:
        attached = run(loader, 'load', str(repo / 'build/linux/classifier.bpf.o'), pins,
                       '/sys/fs/cgroup', '0xffff0000', '0x10000', str(included))
        loaded = True
        (evidence / 'verifier.txt').write_text(attached.stderr)
        with vpn_fixture() as state:
            run(loader, 'state', pins, 'ready')
            blocked(state, 'udp')
            passed('loopback-source DNS fails before owned-interface route_localnet')
            run('sysctl', '-w', 'net.ipv4.conf.wgps0.route_localnet=1')
            with socket.socket(type=socket.SOCK_DGRAM) as reservation:
                reservation.bind(('127.0.0.1', 0))
                source = '127.0.0.1:' + str(reservation.getsockname()[1])
            client(direct, 'udp', source=source)
            client(included, 'udp', source=source)
            client(direct, 'udp', source=source)
            passed('identical reused UDP tuples retain included/unlisted DNS separation')
            for proto in ('udp', 'udp-connected', 'tcp'):
                for address in ('127.0.0.60', '127.0.0.53', '203.0.113.53'):
                    client(included, proto, address)
                client(direct, proto)
                client(included, proto, source='127.0.0.1')
                client(included, proto, source='192.0.2.1')
            passed('automatic first-socket DNS, observed tuples, source binds, UDP and TCP')
            before_vpn = len((state / 'vpn.jsonl').read_text().splitlines())
            before_direct = len((state / 'direct.jsonl').read_text().splitlines())
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                tasks = [pool.submit(client, path, proto) for _ in range(10)
                         for path in (direct, included) for proto in ('udp', 'tcp')]
                for task in tasks:
                    task.result()
            assert len((state / 'vpn.jsonl').read_text().splitlines()) - before_vpn == 20
            assert len((state / 'direct.jsonl').read_text().splitlines()) - before_direct == 20
            passed('concurrent same-name included/unlisted queries have separate responder ledgers')
            enrolled_forwarder_replies(client, direct)
            passed('an enrolled DNS server answers an unlisted loopback client over UDP and TCP')
            foreign_nat_bypass(state, client, included, direct, repo)
            passed('an earlier foreign NAT of selected DNS (loopback stub, local or remote resolver, REDIRECT) '
                   'is dropped and NOTRACK cannot skip the owned NAT; unlisted DNS follows the foreign rules')

            # Mounts are private to each client subprocess; host resolver is unchanged.
            (state / 'resolv.conf').write_text('nameserver 127.0.0.60\noptions attempts:1 timeout:1\n')
            (state / 'nsswitch.conf').write_text('hosts: files dns\n')
            mount_script = ('mount --bind "$1" /etc/resolv.conf && '
                            'mount --bind "$2" /etc/nsswitch.conf && shift 2 && exec "$@"')
            for path, answer in ((direct, '203.0.113.7'), (included, '198.51.100.7')):
                run('unshare', '--mount', '--propagation', 'private', 'sh', '-c', mount_script,
                    'dns-fixture', str(state / 'resolv.conf'), str(state / 'nsswitch.conf'),
                    str(path), 'libc', 'wgps.invalid', answer)
            passed('actual glibc files/dns lookup separates same-name answers')

            timing = {}
            for path, name in ((direct, 'unlisted'), (included, 'kernel-dns')):
                values = [int(x) for x in client(path, 'udp', count=500).splitlines()]
                ordered = sorted(values)
                timing[name] = {'n': len(values), 'p50_ns': statistics.median(values),
                                'p95_ns': ordered[int(len(values) * .95)],
                                'p99_ns': ordered[int(len(values) * .99)]}
            (evidence / 'timing.json').write_text(json.dumps(timing, indent=2) + '\n')
            (evidence / 'nft.json').write_text(run('nft', '-j', 'list', 'table', 'inet', 'wgps_dns_proof').stdout)
            for ledger in ('vpn.jsonl', 'direct.jsonl'):
                shutil.copy2(state / ledger, evidence / ledger)
            run('ip', 'link', 'set', 'wgps0', 'down')
            for proto in ('udp', 'tcp'):
                blocked(state, proto)
                client(direct, proto)
            passed('tunnel loss stops selected DNS while unlisted DNS remains direct')
            run(loader, 'state', pins, 'blocked')
            blocked(state, 'udp')
            client(direct, 'udp')
            passed('pinned blocked state denies selected sockets and preserves unlisted DNS')
        (evidence / 'results.json').write_text(json.dumps(checks, indent=2) + '\n')
        print('Evidence:', evidence)
    finally:
        if loaded:
            run(loader, 'remove', pins)


if __name__ == '__main__':
    if sys.argv[1:] == ['--vm']:
        vm_tests()
    else:
        unittest.main()
