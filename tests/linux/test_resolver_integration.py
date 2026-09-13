"""Real distro resolver integration; privileged work requires explicit --vm."""
import json
import hashlib
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


REPO = Path(__file__).resolve().parents[2]


def read_line(process, timeout=12):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError('owned resolver fixture timed out')
    line = process.stdout.readline()
    if not line:
        raise RuntimeError('owned resolver fixture exited without evidence')
    return json.loads(line)


def stop_process(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def cleanup_namespace(fd):
    """A held namespace FD prevents its inode being recycled during this scan."""
    if fd is None:
        raise RuntimeError('no verified namespace lifetime handle; residual cleanup is uncertain')
    identity = os.fstat(fd).st_ino
    if (not os.readlink(f'/proc/self/fd/{fd}').startswith('mnt:[') or
            identity == os.stat('/proc/self/ns/mnt').st_ino):
        raise RuntimeError('refusing cleanup outside the held private mount namespace')
    escalated, pending = [], []
    try:
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal():
                continue
            process_fd = None
            try:
                process_fd = os.pidfd_open(int(entry.name), 0)
                if (entry / 'ns/mnt').stat().st_ino == identity:
                    signal.pidfd_send_signal(process_fd, signal.SIGKILL)
                    escalated.append(entry.name)
                    pending.append(process_fd)
                    process_fd = None
            except (FileNotFoundError, ProcessLookupError):
                pass
            finally:
                if process_fd is not None:
                    os.close(process_fd)
        deadline = time.monotonic() + 3
        while pending:
            exited, _, _ = select.select(pending, [], [], max(0, deadline - time.monotonic()))
            if not exited:
                raise RuntimeError('owned namespace processes survived kill escalation')
            for process_fd in exited:
                pending.remove(process_fd)
                os.close(process_fd)
        return escalated
    finally:
        for process_fd in pending:
            os.close(process_fd)


def host_identity(path):
    p = Path(path)
    info = p.lstat()
    return (info.st_dev, info.st_ino, info.st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())


def configure(work, mdns):
    for directory in ('run/nscd', 'run/avahi-daemon', 'cache', 'lib', 'avahi/services'):
        (work / directory).mkdir(parents=True, mode=0o755)
    resolver = 'nameserver 127.0.0.60\noptions attempts:1 timeout:1\n'
    (work / 'resolv.conf').write_text(resolver)
    resolved = Path('/etc/resolv.conf').resolve()
    if str(resolved).startswith('/run/'):
        target = work / 'run' / resolved.relative_to('/run')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(resolver)
    hosts = 'files mdns4_minimal [NOTFOUND=return] dns' if mdns else 'files dns'
    (work / 'nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: ' + hosts + '\n')
    (work / 'hosts').write_text('127.0.0.1 localhost\n')
    (work / 'nscd.conf').write_text(
        'threads 4\nmax-threads 8\nparanoia no\nreload-count 0\n'
        'enable-cache passwd no\nenable-cache group no\nenable-cache services no\n'
        'enable-cache netgroup no\nenable-cache hosts yes\n'
        'positive-time-to-live hosts 600\nnegative-time-to-live hosts 1\n'
        'suggested-size hosts 211\ncheck-files hosts no\npersistent hosts yes\n'
        'shared hosts yes\nmax-db-size hosts 1048576\nlogfile ' + str(work / 'nscd.log') + '\n')
    (work / 'avahi/hosts').write_text('203.0.113.9 wgps-integration.local\n')
    (work / 'avahi/avahi-daemon.conf').write_text(
        '[server]\nhost-name=wgps-fixture\nuse-ipv4=yes\nuse-ipv6=no\n'
        'allow-interfaces=wgps-underlay\nenable-dbus=no\n'
        '[wide-area]\nenable-wide-area=no\n[publish]\npublish-addresses=no\n'
        'publish-hinfo=no\npublish-workstation=no\n[reflector]\nenable-reflector=no\n')


def run_variant(work, mdns, state, loader, obj):
    from fixtures import run
    configure(work, mdns)
    ordinary, included, session = work / 'ordinary', work / 'included', work / 'retained'
    run('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
        str(REPO / 'tests/linux/dns_client.c'), '-o', str(ordinary))
    shutil.copy2(ordinary, included)
    run('cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
        str(REPO / 'tests/linux/resolver_session.c'), '-o', str(session))
    pins = '/sys/fs/bpf/wgps-resolver-' + uuid.uuid4().hex[:8]
    loaded, processes, checks = False, [], []
    namespace = None
    namespace_fd = None
    stderr = open(work / 'namespace.log', 'wb')

    def counts():
        return tuple(len((state / name).read_text().splitlines()) if (state / name).exists() else 0
                     for name in ('direct.jsonl', 'vpn.jsonl'))

    def passed(label, **evidence):
        checks.append({'gate': label, **evidence})
        print('PASS', label, flush=True)
        (work / 'results.json').write_text(json.dumps(checks, indent=2) + '\n')

    def in_namespace(*args, trace=None):
        prefix = ['nsenter', '--mount=/proc/' + str(namespace.pid) + '/ns/mnt', '--']
        if trace:
            prefix += ['strace', '-qq', '-f', '-e', 'trace=connect,openat,mmap,recvmsg',
                       '-o', str(work / trace)]
        return run(*prefix, *map(str, args), input='quit\n')

    def lookup(binary, name, answer, *, trace=None):
        return in_namespace(binary, 'libc', name, answer, trace=trace)

    def message(child, command):
        child.stdin.write(command + '\n')
        child.stdin.flush()
        return read_line(child)

    try:
        namespace = subprocess.Popen(['unshare', '--mount', '--propagation', 'private',
                                      sys.executable, str(REPO / 'tests/linux/resolver_namespace.py'),
                                      str(work), 'mdns' if mdns else 'files'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=stderr, text=True)
        processes.append(namespace)
        announced = read_line(namespace)
        assert announced['phase'] == 'namespace' and announced['pid'] == namespace.pid
        candidate_fd = os.open(f'/proc/{namespace.pid}/ns/mnt', os.O_RDONLY | os.O_CLOEXEC)
        try:
            identity = os.fstat(candidate_fd).st_ino
            assert identity == announced['mount_namespace'] and identity != os.stat('/proc/self/ns/mnt').st_ino
            namespace_fd = candidate_fd
        finally:
            if namespace_fd is None:
                os.close(candidate_fd)
        namespace.stdin.write('continue\n')
        namespace.stdin.flush()
        started = read_line(namespace)
        assert started['pid'] == namespace.pid
        (work / 'namespace.json').write_text(json.dumps(started, indent=2))
        before_warm = counts()
        lookup(ordinary, 'wgps.invalid', '203.0.113.7')
        after_warm = counts()
        assert after_warm[0] > before_warm[0] and after_warm[1] == before_warm[1]
        retained = subprocess.Popen(['nsenter', '--mount=/proc/' + str(namespace.pid) + '/ns/mnt', '--',
                                     str(session), 'wgps.invalid'], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=stderr, text=True)
        processes.append(retained)
        first = read_line(retained)
        assert first['answer'] == '203.0.113.7' and first['consistent'] and first['mapped_hosts'], first
        (work / 'retained-before.maps').write_text(Path(f'/proc/{first["pid"]}/maps').read_text())
        before = counts()
        lookup(ordinary, 'wgps.invalid', '203.0.113.7')
        assert counts() == before, 'nscd warm-hit precondition did not hold'
        passed('real nscd shared hosts mapping and warm DNS cache hit', process=first,
               before_warm=before_warm, after_warm=after_warm, cached_counts=before)

        attached = run(loader, 'load', obj, pins, '/sys/fs/cgroup', '0xffff0000', '0x10000',
                       str(included), str(session))
        loaded = True
        (work / 'verifier.log').write_text(attached.stderr)
        # Private mount locations have the same objects at these visible aliases.
        # Default daemon/client API names inside the namespace are unchanged.
        for parent in (work / 'run', work / 'cache', work / 'lib'):
            run(loader, 'guard-slot', pins, 'nscd-parent' if parent.name == 'run' else 'cache-dir', str(parent))
        for directory in (work / 'run/nscd', work / 'cache', work / 'lib'):
            run(loader, 'guard-slot', pins, 'cache-dir', str(directory))
            for entry in directory.iterdir():
                if entry.is_file() and (entry.name == 'hosts' or entry.name.startswith('db')):
                    run(loader, 'guard-slot', pins, 'cache', str(entry))
        for slot in ('run/nscd/socket', 'run/avahi-daemon/socket'):
            run(loader, 'guard-slot', pins, 'socket', str(work / slot))
        run(loader, 'state', pins, 'ready')
        run('sysctl', '-w', 'net.ipv4.conf.wgps0.route_localnet=1')
        before = counts()
        lookup(included, 'wgps.invalid', '198.51.100.7', trace='selected-nscd.trace')
        after = counts()
        assert after[0] == before[0] and after[1] > before[1], (before, after)
        passed('fresh selected libc bypasses real warm nscd and reaches only VPN DNS', before=before, after=after)
        before = counts()
        lookup(ordinary, 'wgps.invalid', '203.0.113.7')
        assert counts() == before
        passed('unlisted libc retains genuine nscd cache without responder traffic')
        before = counts()
        for command in ('again', 'fork'):
            retained_result = message(retained, command)
            assert retained_result['answer'] == '203.0.113.7' and retained_result['mapped_hosts'], retained_result
            assert counts() == before
            passed('pre-enrollment real nscd mapping remains restart boundary: ' + command,
                   process=retained_result, protection_verified=False)
        before = counts()
        fresh = message(retained, 'exec')
        after = counts()
        assert fresh['pid'] == first['pid'] and fresh['answer'] == '198.51.100.7' and not fresh['mapped_hosts'], fresh
        assert after[0] == before[0] and after[1] > before[1], (before, after)
        passed('same-PID exec removes retained nscd mapping and restores selected VPN lookup',
               process=fresh, before=before, after=after)

        if mdns:
            before = counts()
            lookup(ordinary, 'wgps-integration.local', '203.0.113.9', trace='unlisted-mdns.trace')
            nscd_maps = Path(f'/proc/{started["daemons"][0]}/maps').read_text()
            assert 'libnss_mdns4_minimal.so' in nscd_maps, 'real nscd did not load the distro mDNS module'
            (work / 'nscd-mdns.maps').write_text(nscd_maps)
            passed('actual distro mDNS and Avahi supply distinct local-name answer', before=before, after=counts())
            before = counts()
            lookup(included, 'wgps-integration.local', '198.51.100.7', trace='selected-mdns.trace')
            after = counts()
            trace = (work / 'selected-mdns.trace').read_text()
            assert 'libnss_mdns4_minimal.so' in trace and 'avahi-daemon/socket' in trace
            assert after[0] == before[0] and after[1] > before[1], (before, after)
            passed('fresh selected actual mdns4_minimal falls through blocked Avahi to VPN DNS', before=before, after=after)
        assert message(namespace, 'status')['running']
        return checks
    finally:
        failures = []
        for child in reversed(processes):
            try:
                stop_process(child)
            except (OSError, subprocess.TimeoutExpired) as error:
                failures.append(str(error))
        # A daemon can setsid() in foreground mode; the open namespace handle
        # remains held until scanning finishes, even after its last process exits.
        try:
            if namespace is not None:
                escalated = cleanup_namespace(namespace_fd)
                if escalated:
                    (work / 'cleanup-escalation.json').write_text(json.dumps(escalated))
        except (OSError, RuntimeError) as error:
            failures.append(str(error))
        finally:
            if namespace_fd is not None:
                os.close(namespace_fd)
        if loaded:
            try:
                run(loader, 'remove', pins)
            except RuntimeError as error:
                failures.append(str(error))
        stderr.close()
        if failures:
            raise RuntimeError('resolver integration cleanup failed: ' + '; '.join(failures))


def vm_tests():
    from fixtures import run, vpn_fixture
    assert os.geteuid() == 0 and os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert socket.gethostname() != 'TV' and 'microsoft' not in os.uname().release
    assert Path('/var/lib/wgps-vm-provisioned').is_file()
    for command in ('nscd', 'avahi-daemon', 'strace', 'cc', 'nsenter', 'unshare'):
        assert shutil.which(command), 'disposable VM package prerequisite missing: ' + command
    before = {path: host_identity(path) for path in ('/etc/resolv.conf', '/etc/nsswitch.conf', '/etc/hosts')}
    evidence = REPO / 'local/validation' / ('wgps-resolver-integration-' + uuid.uuid4().hex[:8])
    evidence.mkdir(parents=True)
    versions = run('dpkg-query', '-W', '-f=${Package} ${Version}\n', 'libc6', 'nscd', 'libnss-mdns', 'avahi-daemon').stdout
    (evidence / 'packages.txt').write_text(versions)
    loader, obj = str(REPO / 'build/linux/bpf-loader'), str(REPO / 'build/linux/classifier.bpf.o')
    try:
        with vpn_fixture() as state:
            try:
                for mdns in (False, True):
                    work = evidence / ('mdns' if mdns else 'files-dns')
                    work.mkdir()
                    run_variant(work, mdns, state, loader, obj)
            finally:
                for ledger in ('direct.jsonl', 'vpn.jsonl'):
                    if (state / ledger).exists():
                        shutil.copy2(state / ledger, evidence / ledger)
    finally:
        assert {path: host_identity(path) for path in before} == before, 'host resolver/NSS files changed'
        print('Evidence:', evidence, flush=True)


class SessionHelperTests(unittest.TestCase):
    def test_cleanup_signals_a_process_lifetime_handle_instead_of_recycled_pid(self):
        class Entry:
            name = '123'
            def __truediv__(self, _):
                return self
            def stat(self):
                return SimpleNamespace(st_ino=77)
        with patch('os.fstat', return_value=SimpleNamespace(st_ino=77)), \
                patch('os.stat', return_value=SimpleNamespace(st_ino=88)), \
                patch('os.readlink', return_value='mnt:[77]'), \
                patch.object(Path, 'iterdir', return_value=[Entry()]), \
                patch('os.pidfd_open', return_value=22) as opened, \
                patch('signal.pidfd_send_signal') as sent, patch('os.close'), \
                patch('select.select', return_value=([22], [], [])), \
                patch('os.kill', side_effect=AssertionError('numeric PID signal is unsafe')):
            self.assertEqual(cleanup_namespace(11), ['123'])
            opened.assert_called_once_with(123, 0)
            sent.assert_called_once_with(22, signal.SIGKILL)

    def test_cleanup_refuses_missing_namespace_lease_and_callers_namespace(self):
        with patch('os.kill') as kill:
            with self.assertRaises(RuntimeError):
                cleanup_namespace(None)
            fd = os.open('/proc/self/ns/mnt', os.O_RDONLY | os.O_CLOEXEC)
            try:
                with self.assertRaises(RuntimeError):
                    cleanup_namespace(fd)
            finally:
                os.close(fd)
            kill.assert_not_called()

    def test_controlled_dns_has_negative_soa_and_cacheable_a_answers(self):
        from fixtures import QUERY, respond
        soa_query = QUERY[:-4] + struct.pack('!HH', 6, 1)
        soa = respond(soa_query, '203.0.113.7')
        self.assertEqual(struct.unpack('!HHHHHH', soa[:12])[2:], (1, 0, 0, 0))
        self.assertEqual(soa[12:], soa_query[12:])
        answer = respond(QUERY, '203.0.113.7')
        self.assertEqual(struct.unpack('!I', answer[len(QUERY) + 6:len(QUERY) + 10])[0], 60)

    def test_real_libc_session_and_fork_emit_observed_addresses(self):
        with tempfile.TemporaryDirectory(prefix='wgps-libc-', dir=Path.home()) as directory:
            binary = str(Path(directory) / 'session')
            subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(REPO / 'tests/linux/resolver_session.c'), '-o', binary],
                           capture_output=True, check=True, timeout=30)
            output = subprocess.run([binary, '127.0.0.9'], input='again\nfork\nexec\nquit\n',
                                    text=True, capture_output=True, check=True, timeout=5)
            rows = [json.loads(line) for line in output.stdout.splitlines()]
            self.assertEqual(len(rows), 4)
            self.assertTrue(all(row['answer'] == '127.0.0.9' and row['consistent'] for row in rows))
            self.assertEqual(rows[0]['pid'], rows[1]['pid'])
            self.assertNotEqual(rows[0]['pid'], rows[2]['pid'])
            self.assertEqual(rows[0]['pid'], rows[3]['pid'])


if __name__ == '__main__':
    if sys.argv[1:] == ['--vm']:
        vm_tests()
    else:
        unittest.main()
