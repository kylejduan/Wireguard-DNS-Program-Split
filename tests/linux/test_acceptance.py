#!/usr/bin/env python3
"""Installed CLI/systemd acceptance; runs only in the marked disposable VM."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import stat
import subprocess
import sys
import time
import traceback
import uuid

UNITS = ('wg-program-split-guard.service', 'wg-program-split.service')
CLI = Path('/usr/bin/wg-program-split')
ARTIFACTS = Path('/usr/lib/wg-program-split')
CONFIG = Path('/etc/wg-program-split')
STATE = Path('/run/wg-program-split')
PINS = Path('/sys/fs/bpf/wg_program_split')
PAYLOADS = (CLI, *(ARTIFACTS / name for name in
             ('wg-program-split.pyz', 'bpf-loader', 'classifier.bpf.o')),
            *(Path('/usr/lib/systemd/system') / unit for unit in UNITS))
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def require_vm():
    if (os.geteuid() != 0 or os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') != '1' or
            not Path('/var/lib/wgps-vm-provisioned').is_file() or
            socket.gethostname() == 'TV' or 'microsoft' in os.uname().release.lower()):
        raise SystemExit('requires --vm, root, explicit disposable VM flag/marker and native non-TV host')


def execute(*args, okay=True, timeout=35, **kwargs):
    result = subprocess.run(tuple(map(str, args)), text=True, capture_output=True,
                            timeout=timeout, **kwargs)
    if okay and result.returncode:
        raise AssertionError(f'command failed: {args[0]} {args[1:3]} (exit {result.returncode})')
    return result


def identity(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1, f'unsafe file: {path}'
    return (info.st_dev, info.st_ino, info.st_ctime_ns, info.st_uid,
            stat.S_IMODE(info.st_mode), hashlib.sha256(path.read_bytes()).hexdigest())


def directory_identity(path):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)


def stable(value):
    if isinstance(value, list):
        return [stable(item) for item in value]
    if isinstance(value, dict):
        return {key: stable({k: v for k, v in item.items() if k not in ('packets', 'bytes')}
                            if key == 'counter' and isinstance(item, dict) else item)
                for key, item in value.items() if key not in ('expires',)}
    return value


def snapshot():
    def data(*args):
        value = stable(json.loads(execute(*args).stdout))
        return sorted(value, key=lambda item: json.dumps(item, sort_keys=True)) if isinstance(value, list) else value
    resolver = {}
    for name in ('/etc/resolv.conf', '/etc/nsswitch.conf'):
        path = Path(name)
        resolver[name] = {'link': os.readlink(path) if path.is_symlink() else None,
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    return {'routes4': data('ip', '-j', '-4', 'route', 'show', 'table', 'all'),
            'routes6': data('ip', '-j', '-6', 'route', 'show', 'table', 'all'),
            'rules4': data('ip', '-j', '-4', 'rule', 'show'),
            'rules6': data('ip', '-j', '-6', 'rule', 'show'),
            'nft': data('nft', '-j', 'list', 'ruleset'),
            'bpf': data('bpftool', '-j', 'link', 'show'), 'resolver': resolver,
            'listeners': sorted(re.sub(r'fd=\d+', 'fd=*', line).strip()
                                for line in execute('ss', '-H', '-lntup').stdout.splitlines()),
            'namespaces': sorted(execute('ip', 'netns', 'list').stdout.splitlines())}


def unit_state(unit):
    result = execute('systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState',
                     '-p', 'MainPID', '-p', 'FragmentPath', '-p', 'DropInPaths', okay=False)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def pristine():
    for path in (*PAYLOADS, ARTIFACTS, CONFIG, STATE, PINS):
        assert not os.path.lexists(path), f'pre-existing installation/ownership path: {path}'
    for root in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
        assert not list(Path(root).glob('**/*wg-program-split*')), f'pre-existing unit/override in {root}'
    for unit in UNITS:
        value = unit_state(unit)
        assert value.get('LoadState') == 'not-found' and not value.get('FragmentPath')
        assert not value.get('DropInPaths') and int(value.get('MainPID', '0')) == 0
    for link in ('wgps0', 'wgps-underlay'):
        assert execute('ip', 'link', 'show', link, okay=False).returncode != 0
    assert not os.path.lexists('/run/netns/wgps-peer')
    assert not list(Path('/etc/wireguard').glob('wgps-dns-proof-*')), 'pre-existing peer fixture files'
    listeners = {line.split()[4] for line in execute('ss', '-H', '-lnut').stdout.splitlines()}
    assert not listeners & {'127.0.0.60:53', '0.0.0.0:53', '*:53', '[::]:53'}, 'fixture DNS port occupied'
    nft = json.loads(execute('nft', '-j', 'list', 'ruleset').stdout)
    assert not any(entry.get('table', {}).get('name') in ('wg_program_split', 'wgps_dns_proof')
                   for entry in nft['nftables']), 'reserved nft table already exists'
    rules = json.loads(execute('ip', '-j', '-4', 'rule', 'show').stdout)
    assert not any(rule.get('priority') == 5701 for rule in rules), 'fixture policy priority occupied'
    routes = json.loads(execute('ip', '-j', '-4', 'route', 'show', 'table', 'all').stdout)
    assert not any(str(route.get('table')) == '57001' for route in routes), 'fixture route table occupied'


def wait_for(predicate, description, timeout=45):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate(): return
        time.sleep(0.15)
    raise AssertionError('timed out: ' + description)


def echo_server(ledger):
    require_vm()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('192.0.2.2', 0))
        print(server.getsockname()[1], flush=True)
        while True:
            data, peer = server.recvfrom(65535)
            with open(ledger, 'a') as output:
                output.write(json.dumps({'source': peer[0], 'port': peer[1]}) + '\n')
            server.sendto(data, peer)


class Acceptance:
    def __init__(self, repo, evidence):
        self.repo, self.evidence = repo, evidence
        self.checks, self.trace, self.files, self.dirs = [], [], {}, {}
        self.observations = []
        self.profile_hash = None
        self.installed = False

    def run(self, *args, **kwargs):
        self.trace.append(list(map(str, args)))
        okay = kwargs.pop('okay', True)
        result = execute(*args, okay=False, **kwargs)
        self.observations.append({'argv': self.trace[-1], 'exit': result.returncode,
                                  'stdout': result.stdout, 'stderr': result.stderr})
        assert not okay or result.returncode == 0, f'command failed: {args[:2]} (exit {result.returncode})'
        return result

    def cli(self, *args, **kwargs):
        assert self.installed and identity(CLI) == self.files[CLI], 'installed entrypoint replaced'
        return json.loads(self.run(CLI, *args, env=ENV, **kwargs).stdout)

    def passed(self, name):
        self.checks.append(name)
        print('PASS', name, flush=True)

    def service(self, *operation):
        for unit in UNITS:
            path = Path('/usr/lib/systemd/system') / unit
            assert identity(path) == self.files[path], 'installed service changed'
            observed = unit_state(unit)
            assert observed['FragmentPath'] == str(path) and not observed['DropInPaths']
        return self.run('systemctl', *operation, timeout=60, env=ENV)

    def native(self):
        return json.loads(self.run(ARTIFACTS / 'bpf-loader', 'snapshot', PINS, env=ENV).stdout)

    def remember_directories(self):
        for directory in (ARTIFACTS, CONFIG, STATE):
            if directory.exists() and directory not in self.dirs:
                self.dirs[directory] = directory_identity(directory)

    def ready(self):
        return self.cli('status').get('state') == 'ready'

    def retired_state(self):
        """Record a validated final journal only under the previously owned lock."""
        if not STATE.exists(): return
        assert STATE in self.dirs and directory_identity(STATE) == self.dirs[STATE]
        lock = STATE / '.lock'
        assert lock in self.files and identity(lock) == self.files[lock]
        fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == self.files[lock][:2]
            path = STATE / 'controller.json'; before = identity(path)
            journal = json.loads(path.read_text())
            assert journal['state'] == 'disabled' and journal['pins'] is None and journal['pending'] is None
            assert journal['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            assert journal['profile_digest'] == self.profile_hash
            assert sorted(journal['policy']) == sorted(json.loads((CONFIG / 'settings.json').read_text())['included_executables'])
            assert identity(path) == before
            self.files[path] = before
        finally:
            os.close(fd)

    def install(self, peer, selected):
        build = self.repo / 'build/linux'
        for name in ('wg-program-split.pyz', 'bpf-loader', 'classifier.bpf.o', *UNITS):
            assert (build / name).is_file(), 'build/package artifacts are required'
        profile = self.evidence / 'profile.conf'
        profile.write_text('[Interface]\nPrivateKey = ' + (peer / 'host.key').read_text().strip() +
                           '\nAddress = 10.200.0.1/32\nDNS = 10.200.0.2\n[Peer]\nPublicKey = ' +
                           (peer / 'peer.pub').read_text().strip() +
                           '\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.2:51822\n')
        profile.chmod(0o600)
        self.files[profile] = identity(profile)
        self.profile_hash = self.files[profile][-1]
        settings = self.evidence / 'settings.json'
        settings.write_text(json.dumps({'schema_version': 1, 'included_executables': list(map(str, selected))}))
        settings.chmod(0o600)
        before = snapshot()
        result = self.run('/usr/bin/python3', '-I', build / 'wg-program-split.pyz', 'install',
                          '--profile', profile, '--settings', settings, '--artifacts', build,
                          env=ENV, timeout=60, okay=False)
        # An error after the installer published its manifest can still leave a
        # complete installation. Establish its exact payload identity for cleanup.
        if (CONFIG / 'installation.json').is_file() and all(path.is_file() for path in PAYLOADS):
            expected = {CLI: (self.repo / 'scripts/wg-program-split').read_bytes()}
            expected.update({path: (build / path.name).read_bytes() for path in PAYLOADS if path != CLI})
            assert all(path.read_bytes() == content for path, content in expected.items()), 'unexpected installed payload'
            self.files.update({path: identity(path) for path in PAYLOADS})
            assert all(value[3] == 0 and value[4] == (0o755 if path in (CLI, ARTIFACTS / 'bpf-loader') else 0o644)
                       for path, value in self.files.items() if path in PAYLOADS)
            self.installed = True
        assert result.returncode == 0 and self.installed, 'installation failed; inspect owned manifest'
        assert json.loads(result.stdout)['activated'] is False
        self.remember_directories()
        for path in (CONFIG / 'profile.conf', CONFIG / 'settings.json'):
            self.files[path] = identity(path)
        after = snapshot()
        for name, value in (('install-before', before), ('install-after', after)):
            (self.evidence / (name + '.json')).write_text(json.dumps(value, indent=2))
        assert after == before, 'installation changed networking or listeners'
        assert not PINS.exists() and not STATE.exists()
        assert all(unit_state(unit)['ActiveState'] == 'inactive' for unit in UNITS)
        self.passed('install is inactive and leaves routing, resolver, hooks and listeners unchanged')
        poison = self.evidence / 'poison'; poison.mkdir()
        (poison / 'sitecustomize.py').write_text('raise RuntimeError("environment import executed")\n')
        (poison / 'wg_program_split.py').write_text('raise RuntimeError("cwd import executed")\n')
        result = self.run(CLI, 'status', cwd=poison, env={**ENV, 'PYTHONPATH': str(poison)})
        assert json.loads(result.stdout)['state'] == 'inactive'
        self.run('systemd-analyze', 'verify', *(Path('/usr/lib/systemd/system') / unit for unit in UNITS))
        self.passed('installed isolated entrypoint ignores import injection; installed units verify')

    def cleanup(self):
        errors = []
        if self.installed and CLI.exists():
            try:
                self.cli('disable', timeout=70)
                try:
                    self.retired_state()
                except Exception:
                    errors.append('disabled state identity was not established; retaining its files')
                result = self.cli('uninstall', timeout=70)
                assert not result['retained'] and not result.get('removal_deferred')
                self.installed = False
            except Exception as error:
                errors.append('verified CLI cleanup failed: ' + type(error).__name__)
        if not self.installed:
            try:
                assert not PINS.exists(), 'pinned protection remains; retain state/config evidence'
                allowed = {CONFIG: {'profile.conf', 'settings.json'}, STATE: {'controller.json', '.lock'}, ARTIFACTS: set()}
                for directory, names in allowed.items():
                    if not directory.exists(): continue
                    assert directory_identity(directory) == self.dirs[directory], 'owned directory replaced'
                    entries = list(directory.iterdir())
                    assert {p.name for p in entries} <= names, 'unexpected file retained for inspection'
                    for path in entries:
                        assert path in self.files, 'uncaptured file retained'
                        current = identity(path)
                        assert current == self.files[path], 'owned file changed'
                        assert current[3] == 0 and current[4] == 0o600
                        if path.name == 'profile.conf': assert current[-1] == self.profile_hash
                        if path.name == 'settings.json':
                            policy = json.loads(path.read_text())['included_executables']
                            assert set(policy) <= {str(self.evidence / 'selected-dns'), str(self.evidence / 'selected-ip')}
                    for path in entries:
                        assert identity(path) == self.files[path]
                        path.unlink()
                    directory.rmdir()
            except Exception as error:
                errors.append('owned fixture cleanup retained ambiguous state: ' + str(error))
        for path in (self.evidence / 'profile.conf',):
            if path.exists():
                try:
                    assert identity(path) == self.files[path]
                    path.unlink()
                except Exception:
                    errors.append('private input profile retained after identity mismatch')
        try:
            self.run('systemctl', 'daemon-reload')
            for unit in UNITS:
                self.run('systemctl', 'reset-failed', unit, okay=False)
        except Exception:
            errors.append('systemd cleanup readback/reload failed')
        return errors


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--vm', action='store_true')
    modes.add_argument('--echo', type=Path)
    args = parser.parse_args()
    require_vm()
    if args.echo: return echo_server(args.echo)
    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo / 'src/linux'))  # Peer fixture only; installed CLI uses -I.
    os.environ['PYTHONPATH'] = str(repo / 'src/linux')  # Fixture responder subprocesses.
    from fixtures import vpn_fixture
    pristine()
    baseline = snapshot()
    evidence = repo / 'local/validation' / ('acceptance-' + uuid.uuid4().hex[:10])
    evidence.mkdir(parents=True, mode=0o700)
    test = Acceptance(repo, evidence)
    for source, direct, selected, extra in (
            ('dns_client.c', 'direct-dns', 'selected-dns', []),
            ('probe_socket.c', 'direct-ip', 'selected-ip', ['-pthread'])):
        test.run('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', *extra,
                 repo / 'tests/linux' / source, '-o', evidence / direct)
        shutil.copy2(evidence / direct, evidence / selected)
    echo, failure, cleanup_errors = None, None, []
    try:
        with vpn_fixture(owned_host=False) as peer:
            try:
                ledger = evidence / 'ip-ledger.jsonl'
                echo = subprocess.Popen(['ip', 'netns', 'exec', 'wgps-peer', sys.executable,
                                         str(Path(__file__).resolve()), '--echo', str(ledger)],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                assert select.select([echo.stdout], [], [], 5)[0], 'echo responder did not start'
                port = int(echo.stdout.readline())
                def addresses_ready():
                    return all(not address.get('tentative') and 'tentative' not in address.get('flags', []) for command in
                               (('ip', '-j', '-6', 'addr'), ('ip', '-n', 'wgps-peer', '-j', '-6', 'addr'))
                               for link in json.loads(execute(*command).stdout) for address in link['addr_info'])
                wait_for(addresses_ready, 'fixture IPv6 address initialization', timeout=5)
                test.install(peer, (evidence / 'selected-dns', evidence / 'selected-ip'))
                result = test.cli('activate', timeout=90)
                assert result['state'] == 'ready', result
                test.remember_directories()
                test.files[STATE / '.lock'] = identity(STATE / '.lock')
                wait_for(lambda: unit_state(UNITS[1])['ActiveState'] == 'active' and test.ready(), 'daemon ready')
                first = test.native(); mark = first['mark']
                def counts():
                    return [sum(json.loads(line).get('name') == 'wgps.invalid' for line in
                                (peer / name).read_text().splitlines()) if (peer / name).exists() else 0
                            for name in ('vpn.jsonl', 'direct.jsonl')]
                def dns(selected=True, proto='udp', blocked=False):
                    before = counts()
                    path = evidence / ('selected-dns' if selected else 'direct-dns')
                    result = test.run(path, proto, '127.0.0.60', '198.51.100.7' if selected else '203.0.113.7',
                                      hex(mark) if selected else '0', '1', okay=False)
                    after = counts()
                    assert after[1 if selected else 0] == before[1 if selected else 0], 'cross-class DNS arrival'
                    if result.returncode:
                        assert selected and blocked and before == after, 'DNS failed or escaped classification'
                    else:
                        assert after[0 if selected else 1] == before[0 if selected else 1] + 1
                    return result.returncode == 0
                def ip_probe(selected=True, blocked=False):
                    before = ledger.read_text().splitlines() if ledger.exists() else []
                    result = test.run(evidence / ('selected-ip' if selected else 'direct-ip'),
                                      'udp', '192.0.2.2', port, okay=False)
                    after = ledger.read_text().splitlines() if ledger.exists() else []
                    if result.returncode:
                        assert selected and blocked and before == after
                    else:
                        assert f'mark=0x{mark if selected else 0:08x}' in result.stdout
                        assert len(after) == len(before) + 1
                        assert json.loads(after[-1])['source'] == ('10.200.0.1' if selected else '192.0.2.1')
                    return result.returncode == 0
                for proto in ('udp', 'udp-connected', 'tcp'):
                    dns(True, proto); dns(False, proto)
                ip_probe(); ip_probe(False)
                resolver = evidence / 'resolv.conf'; resolver.write_text('nameserver 127.0.0.60\noptions attempts:1 timeout:1\n')
                nss = evidence / 'nsswitch.conf'; nss.write_text('hosts: files dns\n')
                mount = 'mount --bind "$1" /etc/resolv.conf && mount --bind "$2" /etc/nsswitch.conf && shift 2 && exec "$@"'
                for name, answer in (('selected-dns', '198.51.100.7'), ('direct-dns', '203.0.113.7')):
                    test.run('unshare', '--mount', '--propagation', 'private', 'sh', '-c', mount,
                             'acceptance-libc', resolver, nss, evidence / name, 'libc', 'wgps.invalid', answer)
                test.passed('installed activation marks first sockets and separates actual DNS/IP traffic')
                def service_resources():
                    fields = execute('systemctl', 'show', UNITS[1], '-p', 'CPUUsageNSec', '-p', 'MemoryCurrent').stdout
                    return {k: int(v) for line in fields.splitlines() for k, v in [line.split('=', 1)]}
                resources = service_resources(); started = time.monotonic()
                time.sleep(11)  # At least two normal five-second health intervals.
                after = service_resources()
                (evidence / 'controller-resources.json').write_text(json.dumps({
                    'elapsed_seconds': time.monotonic() - started,
                    'service_cpu_ns': after['CPUUsageNSec'] - resources['CPUUsageNSec'],
                    'memory_current_bytes': after['MemoryCurrent'],
                    'note': 'VM observation including service children; no TV latency or CPU budget verdict.'}, indent=2))
                old_pid = int(unit_state(UNITS[1])['MainPID']); assert old_pid > 0, 'daemon exited before SIGKILL gate'
                test.service('kill', '--kill-whom=main', '--signal=SIGKILL', UNITS[1])
                assert test.native()['links'] == first['links'] and test.native()['maps'] == first['maps']
                dns(blocked=True); dns(False); ip_probe(blocked=True)
                wait_for(lambda: int(unit_state(UNITS[1]).get('MainPID', '0')) not in (0, old_pid) and test.ready(),
                         'systemd restarted killed controller')
                dns(); ip_probe()
                test.passed('SIGKILL retains pinned traffic protection and systemd restart recovers readiness')
                before_stop = snapshot()
                test.service('stop', UNITS[1])
                assert unit_state(UNITS[1])['ActiveState'] == 'inactive'
                assert test.native()['ready'] and test.native()['links'] == first['links']
                assert snapshot() == before_stop
                dns(); dns(False); ip_probe()
                test.passed('normal systemctl stop retains BPF, routes, firewall and working selected VPN traffic')
                test.run('ip', 'link', 'set', 'wgps-underlay', 'down')
                assert not dns(blocked=True); dns(False)
                assert not ip_probe(blocked=True)
                assert test.cli('check')['state'] == 'degraded'
                assert not test.native()['ready']
                test.run('ip', 'link', 'set', 'wgps-underlay', 'up')
                wait_for(lambda: test.cli('check')['state'] == 'ready', 'underlay recovery')
                dns(); dns(False); ip_probe()
                test.passed('underlay loss fails closed, unlisted DNS remains healthy, and recovery restores readiness')
                test.cli('include', 'remove', evidence / 'selected-dns')
                test.files[CONFIG / 'settings.json'] = identity(CONFIG / 'settings.json')
                result = test.run(evidence / 'selected-dns', 'udp', '127.0.0.60', '203.0.113.7', '0', '1')
                assert result.returncode == 0
                test.cli('include', 'add', evidence / 'selected-dns')
                test.files[CONFIG / 'settings.json'] = identity(CONFIG / 'settings.json')
                dns(); ip_probe()
                test.passed('include removal/addition changes the next native socket mark and DNS path')
                test.service('start', UNITS[1]); wait_for(test.ready, 'daemon final restart')
                test.cli('disable', timeout=70)
                test.retired_state()
                assert not PINS.exists() and execute('ip', 'link', 'show', 'wgps0', okay=False).returncode != 0
                assert all(unit_state(unit)['ActiveState'] == 'inactive' for unit in UNITS)
                test.run(evidence / 'selected-dns', 'udp', '127.0.0.60', '203.0.113.7', '0', '1')
                assert 'mark=0x00000000' in test.run(evidence / 'selected-ip', 'identity').stdout
                profile_before = identity(CONFIG / 'profile.conf')
                settings_before = identity(CONFIG / 'settings.json')
                result = test.cli('uninstall', timeout=70)
                assert not result['retained'] and not result.get('removal_deferred')
                test.installed = False
                assert all(not os.path.lexists(path) for path in PAYLOADS)
                assert identity(CONFIG / 'profile.conf') == profile_before
                assert identity(CONFIG / 'settings.json') == settings_before
                test.passed('explicit disable releases owned networking; uninstall retains unchanged private profiles')
            finally:
                try:
                    cleanup_errors.extend(test.cleanup())
                except Exception as error:
                    cleanup_errors.append('cleanup interrupted: ' + type(error).__name__)
                if echo and echo.poll() is None:
                    echo.terminate()
                    try: echo.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        echo.kill()
                        try: echo.wait(timeout=3)
                        except subprocess.TimeoutExpired: cleanup_errors.append(f'owned echo PID {echo.pid} remains')
                for name in ('vpn.jsonl', 'direct.jsonl'):
                    if (peer / name).exists(): shutil.copy2(peer / name, evidence / name)
    except Exception as error:
        failure = type(error).__name__ + ': ' + str(error)
        (evidence / 'failure-stack.txt').write_text(traceback.format_exc())
    finally:
        after = None
        try:
            after = snapshot()
        except Exception as error:
            cleanup_errors.append('final baseline inspection failed: ' + type(error).__name__)
        (evidence / 'before.json').write_text(json.dumps(baseline, indent=2))
        (evidence / 'after.json').write_text(json.dumps(after, indent=2))
        (evidence / 'commands.json').write_text(json.dumps(test.trace, indent=2))
        (evidence / 'observations.json').write_text(json.dumps(test.observations, indent=2))
        if after != baseline: cleanup_errors.append('baseline routes/resolver/BPF/listeners were not restored')
        if not failure and not cleanup_errors:
            try:
                pristine()
                test.passed('test-owned fixture files removed; baseline routes, resolver, BPF and listeners restored')
            except Exception as error:
                cleanup_errors.append('final pristine check failed: ' + str(error))
        (evidence / 'results.json').write_text(json.dumps({'checks': test.checks, 'failure': failure,
                                                       'cleanup_errors': cleanup_errors}, indent=2))
        print('Evidence:', evidence, flush=True)
    assert not failure and not cleanup_errors, (failure, cleanup_errors)


if __name__ == '__main__': main()
