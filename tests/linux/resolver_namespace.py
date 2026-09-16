# SPDX-License-Identifier: GPL-3.0-or-later
"""Private-mount supervisor for actual distro nscd and Avahi test processes."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


def run(*args):
    subprocess.run(args, check=True, capture_output=True, timeout=15)


def worker(work, mdns):
    work = Path(work)
    assert os.geteuid() == 0 and os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') == '1'
    assert os.stat('/proc/self/ns/mnt').st_ino != os.stat('/proc/1/ns/mnt').st_ino
    for component in ('root', 'ns/net', 'ns/user'):
        a, b = os.stat('/proc/self/' + component), os.stat('/proc/1/' + component)
        assert (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    (work / 'mount-namespace').write_text(str(os.stat('/proc/self/ns/mnt').st_ino))
    # No directory creation occurs at a host path: bind only existing targets.
    mounts = [(work / 'run', '/run'), (work / 'resolv.conf', '/etc/resolv.conf'),
              (work / 'nsswitch.conf', '/etc/nsswitch.conf'), (work / 'hosts', '/etc/hosts')]
    for label, target in [('cache', '/var/cache/nscd'), ('lib', '/var/lib/nscd')]:
        if Path(target).is_dir():
            mounts.append((work / label, target))
    assert any(target in ('/var/cache/nscd', '/var/lib/nscd') for _, target in mounts)
    if mdns:
        mounts.append((work / 'avahi', '/etc/avahi'))
    for source, target in mounts:
        run('mount', '--bind', str(source), target)
    processes, logs = [], []
    stopping = False

    def stop(*_args):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def start(argv, log):
        stream = open(work / log, 'wb')
        logs.append(stream)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream)
        processes.append(child)
        (work / 'daemon-pids.json').write_text(json.dumps([p.pid for p in processes]))
        return child

    def wait_socket(path, child):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError('real distro resolver daemon exited during startup')
            if Path(path).exists():
                return
            if stopping:
                raise RuntimeError('namespace supervisor interrupted')
            time.sleep(.05)
        raise RuntimeError('real distro resolver daemon did not publish its socket')

    try:
        # Parent must hold this namespace before any daemon can outlive us.
        print(json.dumps({'phase': 'namespace', 'pid': os.getpid(),
                          'mount_namespace': os.stat('/proc/self/ns/mnt').st_ino}), flush=True)
        if sys.stdin.readline().strip() != 'continue':
            raise RuntimeError('parent did not acquire namespace lifetime handle')
        nscd = start(['/usr/sbin/nscd', '--foreground', '--config-file', str(work / 'nscd.conf')], 'nscd-stderr.log')
        wait_socket('/run/nscd/socket', nscd)
        if mdns:
            avahi = start(['/usr/sbin/avahi-daemon', '--no-drop-root', '--no-chroot', '--no-rlimits',
                           '--debug', '--file', '/etc/avahi/avahi-daemon.conf'], 'avahi.log')
            wait_socket('/run/avahi-daemon/socket', avahi)
        from wg_program_split.preflight import check_host
        check_host()
        print(json.dumps({'pid': os.getpid(), 'daemons': [p.pid for p in processes],
                          'mount_namespace': os.stat('/proc/self/ns/mnt').st_ino}), flush=True)
        while not stopping:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('owned resolver daemon exited during proof')
            if select.select([sys.stdin], [], [], .25)[0]:
                if sys.stdin.readline().strip() != 'status':
                    break
                print(json.dumps({'running': True}), flush=True)
    finally:
        failures = []
        for child in reversed(processes):
            try:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired) as error:
                failures.append(str(error))
        for stream in logs:
            stream.close()
        if failures:
            raise RuntimeError('owned daemon cleanup failed: ' + '; '.join(failures))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('requires private work directory and files/mdns mode')
    worker(sys.argv[1], sys.argv[2] == 'mdns')
