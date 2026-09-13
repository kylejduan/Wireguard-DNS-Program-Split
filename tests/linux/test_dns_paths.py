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
