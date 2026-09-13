"""Disposable VM measurements; results are observations, never an automatic SLO pass."""
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

from fixtures import clear_owned_zone, run, vpn_fixture
from wg_program_split.firewall import Firewall


def guest_cpu():
    values = [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
    return sum(values[i] for i in (0, 1, 2, 5, 6)) / os.sysconf('SC_CLK_TCK')


def measure(client, destination, answer, mark, count=2000, prefix=()):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_before = guest_cpu()
    begin = time.monotonic_ns()
    output = run(*prefix, str(client), 'udp', destination, answer, mark, str(count), timeout=30)
    elapsed = time.monotonic_ns() - begin
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_after = guest_cpu()
    samples = sorted(int(x) for x in output.stdout.splitlines())
    assert len(samples) == count
    return {'n': count, 'p50_ns': statistics.median(samples),
            'p95_ns': samples[int(.95 * count)], 'p99_ns': samples[int(.99 * count)],
            'client_cpu_ns_per_query': int(((after.ru_utime + after.ru_stime) -
                                          (before.ru_utime + before.ru_stime)) * 1e9 / count),
            'wall_ns_per_query': elapsed / count,
            'guest_active_cpu_ns_per_query': int((cpu_after - cpu_before) * 1e9 / count),
            'client_context_switches': (after.ru_nvcsw + after.ru_nivcsw) -
                                       (before.ru_nvcsw + before.ru_nivcsw)}


def main():
    assert os.geteuid() == 0 and os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert socket.gethostname() != 'TV' and Path('/var/lib/wgps-vm-provisioned').is_file()
    repo = Path(__file__).resolve().parents[2]
    output = repo / 'local/validation' / ('wgps-perf-' + uuid.uuid4().hex[:8])
    output.mkdir(parents=True)
    clients = Path(tempfile.mkdtemp(prefix='wgps-perf-', dir='/run'))
    try:
        clients.chmod(0o755)
        client = clients / 'dns_client'
        run('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
            str(repo / 'tests/linux/dns_client.c'), '-o', str(client))
        pins = '/sys/fs/bpf/' + clients.name
        loader = str(repo / 'build/linux/bpf-loader')
        obj = str(repo / 'build/linux/classifier.bpf.o')
        uid = '65534'
        assert subprocess.run(['pgrep', '-u', uid], capture_output=True).returncode == 1
        assert not any(r.get('priority') == 5702 for r in json.loads(run('ip', '-j', 'rule').stdout))
        prefix = ('setpriv', '--reuid', uid, '--regid', uid, '--clear-groups')
        rows = {name: [] for name in ('unlisted-baseline', 'unlisted-empty-policy',
                                      'plain-wireguard', 'kernel-dns', 'uncached-proxy-dns')}
        loaded = rule = False
        proxy = None
        with vpn_fixture(extra_zones=(57002,)) as fixture_state:
            # Test-only UID routing supplies a matched plain WireGuard baseline.
            # The product's automatic enrollment never uses this UID or launcher.
            normal = Firewall('10.200.0.1', '10.200.0.2', table='wgps_dns_proof', mask=0xffff0000).render()

            def replace(rules):
                clear_owned_zone(57001)
                clear_owned_zone(57002)
                run('nft', '-f', '-', input='delete table inet wgps_dns_proof\n' + rules)

            def attach():
                nonlocal loaded
                result = run(loader, 'load', obj, pins, '/sys/fs/cgroup', '0xffff0000', '0x10000')
                loaded = True
                (output / 'verifier.txt').write_text(result.stderr)
                run(loader, 'state', pins, 'ready')

            try:
                run('ip', 'rule', 'add', 'priority', '5702', 'uidrange', uid + '-' + uid, 'table', '57001')
                rule = True
                run('sysctl', '-w', 'net.ipv4.conf.wgps0.route_localnet=1')
                for repeat in range(5):
                    # Empty owned table de-registers NAT/conntrack hooks for the baseline.
                    replace('table inet wgps_dns_proof {}\n')
                    rows['unlisted-baseline'].append(measure(client, '127.0.0.60', '203.0.113.7', '0'))
                    rows['plain-wireguard'].append(measure(client, '10.200.0.2', '198.51.100.7', '0', prefix=prefix))
                    attach()
                    rows['unlisted-empty-policy'].append(measure(client, '127.0.0.60', '203.0.113.7', '0'))
                    run(loader, 'path-add', pins, str(client))
                    replace(normal)
                    rows['kernel-dns'].append(measure(client, '127.0.0.53', '198.51.100.7', '0x10000'))
                    run(loader, 'path-del', pins, str(client))
                    run(loader, 'remove', pins)
                    loaded = False
                    print('Completed baseline/kernel repetition', repeat + 1, flush=True)

                # dnsmasq has no cache, hosts, resolv.conf or default configuration.
                # The controlled upstream and query contents match the kernel candidate.
                with (output / 'proxy-stderr.txt').open('wb') as log:
                    proxy = subprocess.Popen([*prefix, 'dnsmasq', '--keep-in-foreground', '--conf-file=',
                        '--pid-file=', '--no-resolv', '--no-hosts', '--cache-size=0', '--bind-interfaces',
                        '--listen-address=127.0.0.61', '--port=53053', '--server=10.200.0.2'],
                        stdout=subprocess.DEVNULL, stderr=log)
                time.sleep(.1)
                assert proxy.poll() is None, 'controlled proxy did not start'
                attach()
                run(loader, 'path-add', pins, str(client))
                proxy_rules = normal.replace('dnat ip to 10.200.0.2:53', 'dnat ip to 127.0.0.61:53053')
                # The forwarder's upstream class needs its own conntrack zone,
                # otherwise a reused tuple can hit an application's DNAT record.
                extra = (f'  meta skuid {uid} ip daddr 10.200.0.2 ct zone set 57002\n'
                         f'  meta skuid {uid} udp sport 53053 ct zone set 57001\n'
                         f'  meta skuid {uid} tcp sport 53053 ct zone set 57001\n')
                marker = 'type filter hook output priority raw; policy accept;\n'
                proxy_rules = proxy_rules.replace(marker, marker + extra, 1)
                proxy_rules = proxy_rules.replace('iifname "wgps0" ct zone set 57001',
                                                  'iifname "wgps0" ct zone set 57002')
                proxy_rules = proxy_rules.rsplit('}', 1)[0] + ''' chain proxy_delivery {
 type filter hook input priority filter; policy accept;
 ip daddr 127.0.0.61 udp dport 53053 counter accept
 }
}
'''
                replace(proxy_rules)
                def proxy_count():
                    data = json.loads(run('nft', '-j', 'list', 'chain', 'inet',
                                          'wgps_dns_proof', 'proxy_delivery').stdout)
                    return sum(expr['counter']['packets'] for item in data['nftables']
                               for expr in item.get('rule', {}).get('expr', []) if 'counter' in expr)
                for _ in range(5):
                    before = proxy_count()
                    before_upstream = len((fixture_state / 'vpn.jsonl').read_text().splitlines())
                    rows['uncached-proxy-dns'].append(measure(client, '127.0.0.53', '198.51.100.7', '0x10000'))
                    assert proxy_count() - before == 2000, 'measured queries bypassed the proxy'
                    assert len((fixture_state / 'vpn.jsonl').read_text().splitlines()) - before_upstream == 2000
            finally:
                failures = []
                def cleanup(action):
                    try:
                        action()
                    except Exception as error:
                        failures.append(str(error))
                if proxy:
                    def stop_proxy():
                        if proxy.poll() is None:
                            proxy.terminate()
                        try:
                            proxy.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proxy.kill()
                            proxy.wait(timeout=3)
                    cleanup(stop_proxy)
                if loaded:
                    cleanup(lambda: run(loader, 'remove', pins))
                cleanup(lambda: replace(normal))
                if rule:
                    cleanup(lambda: run('ip', 'rule', 'delete', 'priority', '5702',
                                        'uidrange', uid + '-' + uid, 'table', '57001'))
                if failures:
                    raise RuntimeError('Performance fixture cleanup failed: ' + '; '.join(failures))
        result = {'kernel': os.uname().release,
                  'note': 'VM observations only. Client CPU excludes persistent responders; guest active CPU includes all guest work at scheduler-tick resolution. Sequential blocks, no accepted performance budget.',
                  'rows': rows}
        (output / 'measurements.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({name: {'median_p50_ns': statistics.median(r['p50_ns'] for r in values),
                                'median_p99_ns': statistics.median(r['p99_ns'] for r in values),
                                'median_client_cpu_ns_per_query': statistics.median(r['client_cpu_ns_per_query'] for r in values)}
                          for name, values in rows.items()}, indent=2))
        print('Evidence:', output)
    finally:
        shutil.rmtree(clients)


if __name__ == '__main__':
    if sys.argv[1:] != ['--vm']:
        raise SystemExit('explicit --vm is required')
    main()
