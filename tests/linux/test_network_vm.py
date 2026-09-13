"""Explicit disposable-VM acceptance for the real network ownership adapter."""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid

from fixtures import vpn_fixture, run
from wg_program_split.config import Profile
from wg_program_split.network import Network, allocate, inspect, run_command
from wg_program_split import ownership as own


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
    before_rules = json.loads(run('ip', '-j', '-4', 'rule', 'show').stdout)
    try:
        with vpn_fixture(owned_host=False) as peer:
            profile = Profile(address='10.200.0.1/24', resolver='10.200.0.2',
                              endpoint_host='192.0.2.2', endpoint_port=51822,
                              private_key=(peer / 'host.key').read_text().strip(),
                              public_key=(peer / 'peer.pub').read_text().strip())
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
