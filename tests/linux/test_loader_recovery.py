#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Interrupted guard loads and pre-upgrade pins; privileged proof requires explicit VM mode."""
import argparse
import contextlib
import errno
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import uuid

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / 'build/linux'
MASK, MARK = '0x00ff0000', '0x00010000'
# Pin names in pin (attach) order, as src/linux/native/pin-set.h lists them.
PIN_SET = (REPO / 'src/linux/native/pin-set.h').read_text()
LINK_PINS = tuple(re.findall(r'^    \{"(link[a-z_]*)",', PIN_SET, re.M))
MAP_PINS = tuple(name for name in re.findall(r'^    \{"([a-z_]+)",', PIN_SET, re.M) if name not in LINK_PINS)
# Counts every AF_INET socket an included process manages to create, and how
# many of those lacked the selected mark, until SIGTERM.
WATCHER = r'''#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void finish(int signum) { (void)signum; stop = 1; }
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned mask = strtoul(argv[1], 0, 0), mark = strtoul(argv[2], 0, 0);
    unsigned long attempts = 0, denied = 0, marked = 0, unmarked = 0;
    signal(SIGTERM, finish);
    printf("ready\n"); fflush(stdout);
    while (!stop) {
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        attempts++;
        if (fd < 0) { denied++; continue; }
        unsigned value = 0; socklen_t size = sizeof(value);
        if (getsockopt(fd, SOL_SOCKET, SO_MARK, &value, &size) || (value & mask) != mark) unmarked++;
        else marked++;
        close(fd);
    }
    printf("attempts=%lu denied=%lu marked=%lu unmarked=%lu\n", attempts, denied, marked, unmarked);
    return 0;
}
'''

# A selected process changes an AF_UNIX stream's peer identity while an
# interrupted generation is attached: bind makes one end of a SAFE socketpair a
# standard Avahi endpoint; rename makes a connected listener's directory
# /run/avahi-daemon. Prints the errno of a send before and after the change.
CHECKER = r'''#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
static int sent(int fd) { return send(fd, "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL) == 1 ? 0 : errno; }
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int one, two, before, after;
    if (!strcmp(argv[1], "bind")) {
        int pair[2];
        if (mkdir("/run/avahi-daemon", 0755) || socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 3;
        one = pair[0]; two = pair[1];
        before = sent(two);
        snprintf(address.sun_path, sizeof(address.sun_path), "/run/avahi-daemon/socket");
        if (bind(one, (struct sockaddr *)&address, sizeof(address))) return 3;
        after = sent(two);
        unlink("/run/avahi-daemon/socket"); rmdir("/run/avahi-daemon");
    } else {
        if (mkdir(argv[2], 0755)) return 3;
        snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", argv[2]);
        one = socket(AF_UNIX, SOCK_STREAM, 0); two = socket(AF_UNIX, SOCK_STREAM, 0);
        if (bind(one, (struct sockaddr *)&address, sizeof(address)) || listen(one, 1) ||
            connect(two, (struct sockaddr *)&address, sizeof(address))) return 3;
        before = sent(two);
        if (rename(argv[2], "/run/avahi-daemon")) return 3;
        after = sent(two);
        unlink("/run/avahi-daemon/socket"); rmdir("/run/avahi-daemon");
    }
    printf("%d %d\n", before, after);
    return 0;
}
'''

# Parks a vfs_rename and a unix_bind inside the kernel across guard attachment:
# a write holding a file's inode lock waits on a userfaultfd page, a rename of
# that file (holding the directory lock) waits inside vfs_rename for it, and a
# bind of one end of a socketpair into that directory waits inside unix_bind.
# The directory is the root of a private tmpfs, where "bus" is a protected
# name, so the loader's own lookups of standard paths never wait on it.
# Commands on stdin: "send" prints the errno of a send on the other end;
# "release" resolves the fault and waits for all three to finish.
INFLIGHT = r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
static char file[200], moved[200], socket_path[108], *page;
static int pair[2];
static void *writer(void *unused) { (void)unused; int fd = open(file, O_WRONLY); if (write(fd, page, 4096) < 0) perror("write"); close(fd); return 0; }
static void *renamer(void *unused) { (void)unused; if (rename(file, moved)) perror("rename"); return 0; }
static void *binder(void *unused) {
    (void)unused;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (bind(pair[0], (struct sockaddr *)&address, sizeof(address))) perror("bind");
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    snprintf(file, sizeof(file), "%s/held", argv[1]);
    snprintf(moved, sizeof(moved), "%s/moved", argv[1]);
    snprintf(socket_path, sizeof(socket_path), "%s/bus", argv[1]);
    close(open(file, O_CREAT | O_WRONLY, 0600));
    int uffd = syscall(SYS_userfaultfd, O_CLOEXEC);
    struct uffdio_api api = {.api = UFFD_API};
    page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct uffdio_register area = {.range = {(unsigned long)page, 4096}, .mode = UFFDIO_REGISTER_MODE_MISSING};
    if (uffd < 0 || ioctl(uffd, UFFDIO_API, &api) || ioctl(uffd, UFFDIO_REGISTER, &area) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) { perror("setup"); return 3; }
    pthread_t threads[3];
    void *(*steps[3])(void *) = {writer, renamer, binder};
    for (int i = 0; i < 3; i++) { pthread_create(&threads[i], 0, steps[i], 0); usleep(200000); }
    printf("blocked\n"); fflush(stdout);
    char command[32];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strncmp(command, "send", 4)) {
            int result = send(pair[1], "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL) == 1 ? 0 : errno;
            printf("%d\n", result);
        } else if (!strncmp(command, "release", 7)) {
            struct uffdio_zeropage zero = {.range = {(unsigned long)page, 4096}};
            if (ioctl(uffd, UFFDIO_ZEROPAGE, &zero)) perror("zeropage");
            for (int i = 0; i < 3; i++) pthread_join(threads[i], 0);
            printf("released\n");
        } else break;
        fflush(stdout);
    }
    return 0;
}
'''


def run(args, okay=True, env=None, **kwargs):
    result = subprocess.run([str(x) for x in args], text=True, capture_output=True, timeout=60,
                            env=env, **kwargs)
    if okay and result.returncode:
        raise AssertionError(f'{args}: {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result


def hooked_loader(output):
    """Test-only build with named interruption points; production builds have none."""
    flags = run(['pkg-config', '--cflags', '--libs', 'libbpf']).stdout.split()
    run(['c++', '-O2', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-DWGPS_LOADER_TEST_HOOKS',
         REPO / 'src/linux/native/bpf-loader.cpp', '-o', output, *flags])
    return output


CLASSIFY = r'''#define main loader_main
#include LOADER_SOURCE
#undef main
int main() {
    KernelSymbols symbols;
    symbols.traced = {{0x1000, 0x1100}, {0x2000, 0x2100}};  // unix_bind, vfs_rename
    symbols.bottoms = {{0x9000, 0x9100}, {0xa000, 0xa040}};   // entry text, fork return
    const size_t cap = 127;
    DrainRecord quiet{7, 0, 1, 40, 40, 0};
    std::vector<uint64_t> complete{0x5000, 0x6000, 0x9010};
    int failures = 0;
    auto expect = [&](const char *name, DrainRecord record, std::vector<uint64_t> frames, Walk expected) {
        if (classify(record, frames, cap, symbols) != expected) { std::cerr << "FAIL " << name << '\n'; failures++; }
    };
    expect("complete off-CPU walk", quiet, complete, Walk::Clear);
    DrainRecord ran = quiet; ran.switches_after = 41;  // Ran during the walk and stopped again.
    expect("off-CPU, running, off-CPU during the walk", ran, complete, Walk::Unknown);
    DrainRecord running = quiet; running.flags = TASK_ON_CPU;
    expect("running at either read", running, complete, Walk::Unknown);
    for (size_t keep = 0; keep < complete.size(); keep++)  // Early-stopped unwinds of any length.
        expect("unwind stopped before the stack bottom",
               quiet, std::vector<uint64_t>(complete.begin(), complete.begin() + keep), Walk::Unknown);
    std::vector<uint64_t> deep(cap, 0x5000); deep.back() = 0x9010;
    expect("trace filling the depth cap", quiet, deep, Walk::Unknown);
    expect("kernel thread ending at the fork return", quiet, {0x5000, 0xa010}, Walk::Clear);
    expect("frame inside vfs_rename", quiet, {0x5000, 0x2050, 0x9010}, Walk::Inside);
    DrainRecord failed = quiet; failed.flags = TASK_WALK_ERROR;
    expect("walk error", failed, {}, Walk::Unknown);
    DrainRecord exited = quiet; exited.flags = TASK_EXITED;
    expect("exited task", exited, {}, Walk::Clear);
    if (failures) return 1;
    std::cout << "PASS: only a quiet, complete walk ending in entry text clears a task\n";
}
'''


def native():
    output = BUILD / 'bpf-loader-hooks'
    BUILD.mkdir(parents=True, exist_ok=True)
    hooked_loader(output)
    production = (REPO / 'src/linux/native/bpf-loader.cpp').read_text()
    assert production.count('#ifdef WGPS_LOADER_TEST_HOOKS') == 1
    print('PASS native interruption hooks compile only into an explicit test build')
    source, executable = BUILD / 'drain-classify.cpp', BUILD / 'drain-classify'
    source.write_text(CLASSIFY)
    flags = run(['pkg-config', '--cflags', '--libs', 'libbpf']).stdout.split()
    run(['c++', '-O2', '-std=c++17', '-Wall', '-Wextra', '-Werror',
         f'-DLOADER_SOURCE="{REPO / "src/linux/native/bpf-loader.cpp"}"', source, '-o', executable, *flags])
    print(run([executable]).stdout.strip())


class Recovery:
    def __init__(self, work):
        self.work = work
        tag = work.name
        self.group = Path('/sys/fs/cgroup') / tag
        self.pins = Path('/sys/fs/bpf') / tag
        self.names = (Path(str(self.pins) + '_new'), Path(str(self.pins) + '_next'))
        self.loader = BUILD / 'bpf-loader'
        self.hooked = hooked_loader(work / 'bpf-loader-hooks')
        self.object = BUILD / 'classifier.bpf.o'
        self.included = work / 'included-watch'
        self.direct = work / 'direct-probe'
        source = work / 'watch.c'; source.write_text(WATCHER)
        run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', source, '-o', self.included])
        self.inflight = work / 'included-inflight'
        source = work / 'inflight.c'; source.write_text(INFLIGHT)
        run(['cc', '-O2', '-std=c11', '-pthread', '-Wall', '-Wextra', '-Werror', source, '-o', self.inflight])
        self.checker = work / 'included-checker'
        source = work / 'checker.c'; source.write_text(CHECKER)
        run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', source, '-o', self.checker])
        self.checks = []
        shutil.copy2(BUILD / 'probe_socket', self.direct)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ('WG_CLASSIFIER_DISPOSABLE_VM', 'WGPS_TEST_KILL_AT', 'WGPS_TEST_FAIL_AT')}
        self.watchers = []
        self.results, self.counts = [], []

    def scoped(self, args):
        return ['sh', '-c', 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"', 'recovery', self.group, *args]

    def load(self, loader=None, *, kill=None, fail=None, scoped=False, okay=True, record=None):
        env = dict(self.env)
        if kill: env['WGPS_TEST_KILL_AT'] = kill
        if fail: env['WGPS_TEST_FAIL_AT'] = fail
        if record:
            args = [loader or self.loader, 'load-policy-stdin', self.object, self.pins, self.group, MASK, MARK, record]
            stdin = ''.join(str(path) + '\0' for path in (self.included, self.checker, self.inflight))
        else:
            args = [loader or self.loader, 'load', self.object, self.pins, self.group, MASK, MARK,
                    self.included, self.checker, self.inflight]
            stdin = None
        result = run(self.scoped(args) if scoped else args, okay=False, env=env, input=stdin)
        if kill:
            assert result.returncode == -signal.SIGKILL, (result.returncode, result.stderr[-2000:])
        elif okay:
            assert result.returncode == 0, result.stderr[-4000:]
        return result

    def staged(self):
        return [path for path in self.names if path.exists()]

    def classifiers(self):
        """Effective cgroup LSM program IDs on the test cgroup."""
        rows = json.loads(run(['bpftool', '-j', 'cgroup', 'show', self.group, 'effective']).stdout)
        return sorted(row['id'] for row in rows if row.get('attach_type') == 'lsm_cgroup')

    def program(self, directory, pin='link'):
        # bpftool 7.x exits nonzero after printing a pinned cgroup link it cannot
        # resolve to a path; the JSON object it printed is still complete.
        result = run(['bpftool', '-j', 'link', 'show', 'pinned', directory / pin], okay=False)
        return json.loads(result.stdout)['prog_id']

    def watch(self):
        process = subprocess.Popen([str(x) for x in self.scoped([self.included, MASK, MARK])],
                                   stdout=subprocess.PIPE, text=True)
        self.watchers.append(process)
        assert process.stdout.readline().strip() == 'ready'
        return process

    def stop(self, process):
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=10)
        counts = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', output)}
        assert counts['attempts'] > 0, output
        self.counts.append(counts)
        return counts

    def direct_mark(self, expected_success=True):
        result = run(self.scoped([self.direct, 'identity']), okay=False)
        if expected_success:
            assert result.returncode == 0 and 'mark=0x00000000 ' in result.stdout, result.stdout
        else:
            assert result.returncode == 1 and 'socket_error=1 ' in result.stdout, result.stdout

    def passed(self, name):
        self.results.append(name)
        print('PASS', name, flush=True)

    def published(self):
        snapshot = json.loads(run([self.loader, 'snapshot', self.pins]).stdout)
        assert snapshot['ready'] is False
        assert snapshot['paths'] == sorted(map(str, (self.included, self.checker, self.inflight)))
        assert not self.staged(), 'interrupted staging generation survived publication'
        self.settle([snapshot['links']['link']['program_id']])
        return snapshot

    def settle(self, expected):
        """Unpinning releases a link from a kernel work item, so a replaced
        classifier may stay attached (and blocking) for a moment afterwards.
        An expected classifier is never missing meanwhile."""
        expected, deadline = sorted(expected), time.monotonic() + 5
        while (observed := self.classifiers()) != expected and time.monotonic() < deadline:
            assert set(expected) <= set(observed), (expected, observed)
            time.sleep(.05)
        assert observed == expected, (expected, observed)

    def remove(self):
        if self.pins.exists():
            run([self.loader, 'remove', self.pins])
            if self.group.exists():
                self.settle([])  # The kernel releases unpinned links shortly afterwards.

    def cleanup(self):
        failures = []
        for process in self.watchers:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
        for action in (self.remove, *(lambda path=path: discard(path) for path in self.names)):
            try: action()
            except Exception as error: failures.append(str(error))
        if self.group.exists():
            try: self.group.rmdir()
            except OSError as error: failures.append(str(error))
        if failures: raise RuntimeError('recovery cleanup failed: ' + '; '.join(failures))

    def unix_changes(self, label):
        """While only an interrupted generation is attached: once it can cache a
        SAFE stream label it must also invalidate it after a bind or rename."""
        assert not Path('/run/avahi-daemon').exists(), 'the disposable VM must not run Avahi'
        caching = (self.names[0] / 'link_send').exists()
        for mode in ('bind', 'rename'):
            result = run([self.checker, mode, Path('/run') / (self.work.name + '-stage')])
            before, after = map(int, result.stdout.split())
            self.checks.append({'point': label, 'mode': mode, 'caching': caching, 'before': before, 'after': after})
            assert before == 0, (label, mode, result.stdout)
            if caching:
                assert after == errno.EACCES, (label, mode, result.stdout)

    def interrupted_then_recovered(self):
        for point in ('maps', 'link', 'link_bound', 'link_attr', 'link_rename', 'link_connect',
                      'link_send', 'link_bind', 'verified'):
            self.load(self.hooked, kill=point)
            assert not self.pins.exists() and self.staged() == [self.names[0]]
            self.unix_changes(point)
            if point == 'maps':
                # Nothing was attached yet: the retry is an ordinary first load.
                self.settle([])
                self.load()
            else:
                stale = self.program(self.names[0])
                self.settle([stale])
                watcher = self.watch(); time.sleep(.2)
                self.load()
                counts = self.stop(watcher)
                assert counts['unmarked'] == 0 and counts['marked'] == 0, (point, counts)
                assert counts['denied'] == counts['attempts'], (point, counts)
            self.published()
            self.direct_mark()
            self.remove()
        self.passed('a load killed after any staging step is replaced by the next load with '
                    'no unmarked included socket and no detached interval')

    def repeated_interruptions(self):
        self.load(self.hooked, kill='link')
        first = self.program(self.names[0])
        watcher = self.watch()
        self.load(self.hooked, kill='link_bind')
        assert self.staged() == list(self.names)
        second = self.program(self.names[1])
        self.settle((first, second))
        # Both names held: the classifier-only generation is covered by the full one.
        self.load(self.hooked, kill='verified')
        assert self.staged() == list(self.names) and self.program(self.names[1]) == second
        third = self.program(self.names[0])
        assert third not in (first, second)
        self.settle((second, third))
        # The equal full generation is freed first; the injected failure then
        # removes only its own attempt and leaves the other attached.
        failed = self.load(self.hooked, fail='verified', okay=False)
        assert failed.returncode and 'injected failure' in failed.stderr, failed.stderr
        assert self.staged() == [self.names[1]]
        self.settle([second])
        self.load()
        counts = self.stop(watcher)
        assert counts['unmarked'] == 0 and counts['marked'] == 0 and counts['denied'] == counts['attempts'], counts
        self.published()
        run([self.loader, 'state', self.pins, 'ready'])
        watcher = self.watch(); time.sleep(.2); counts = self.stop(watcher)
        assert counts['marked'] > 0 and counts['denied'] == 0 and counts['unmarked'] == 0, counts
        self.remove()
        self.passed('repeated kills and an injected failure keep an attached generation until one load publishes')

    def published_interruption(self):
        """Killed after publication: the birth record proves the published
        generation, and settle detaches the interrupted one beside it."""
        for leftover in (True, False):
            record = self.work / 'birth.json'
            if record.exists(): record.unlink()
            if leftover:
                self.load(self.hooked, kill='link_bind')
                stale = self.program(self.names[0])
                watcher = self.watch(); time.sleep(.2)
            self.load(self.hooked, kill='published', record=record)
            if not leftover:
                watcher = self.watch(); time.sleep(.2)
            assert self.pins.exists() and self.staged() == ([self.names[0]] if leftover else [])
            snapshot = json.loads(run([self.loader, 'snapshot', self.pins]).stdout)
            assert json.loads(record.read_text()) == {'maps': snapshot['maps'], 'links': snapshot['links']}
            published = snapshot['links']['link']['program_id']
            self.settle([stale, published] if leftover else [published])
            refused = self.load(okay=False)
            assert refused.returncode and ('competing' in refused.stderr or 'already exists' in refused.stderr)
            settled = run([self.loader, 'settle', self.pins, self.group]).stdout
            assert settled.strip() == f'settled={int(leftover)}', settled
            counts = self.stop(watcher)
            assert counts['unmarked'] == 0 and counts['marked'] == 0 and counts['denied'] == counts['attempts'], counts
            self.published()
            self.remove()
        self.passed('a load killed after publication is proved by its birth record and settled without a detached interval')

    def unpopulated_generation(self):
        self.load(self.hooked, kill='link_bind')
        stale = self.names[0]
        run(['bpftool', 'map', 'update', 'pinned', stale / 'policy_cfg', 'key', 'hex', '00', '00', '00', '00',
             'value', 'hex', *['00'] * 40])
        self.direct_mark(expected_success=False)  # An invalid configuration refuses every socket.
        watcher = self.watch()
        # Inside the cgroup the loader's own context probe must see a usable host.
        result = self.load(scoped=True)
        assert 'self-check skipped' not in result.stderr, result.stderr
        counts = self.stop(watcher)
        assert counts['unmarked'] == 0 and counts['marked'] == 0, counts
        self.published()
        self.direct_mark()
        self.remove()
        self.passed('an interrupted generation with an invalid configuration is held blocked, not blocking all, until replaced')

    def refusals(self):
        self.load(self.hooked, kill='link')
        foreign = self.names[0] / 'unexpected'
        paths = json.loads(run(['bpftool', '-j', 'map', 'show', 'pinned', self.names[0] / 'paths']).stdout)['id']
        run(['bpftool', 'map', 'pin', 'id', paths, foreign])
        refused = self.load(okay=False)
        assert refused.returncode and 'unknown' in refused.stderr, refused.stderr
        assert self.staged() == [self.names[0]]
        self.settle([self.program(self.names[0])])
        foreign.unlink()
        self.load()
        self.published()
        repeated = self.load(okay=False)
        assert repeated.returncode and ('competing' in repeated.stderr or 'already exists' in repeated.stderr)
        self.published()
        self.remove()
        self.passed('foreign staging entries and an existing published directory are still refused')

    @contextlib.contextmanager
    def blocked_calls(self, name):
        """A helper with threads held inside unix_bind and vfs_rename; yields a
        function sending it one command ('send' or 'release')."""
        directory = self.work / name
        directory.mkdir()
        run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', directory])
        helper = subprocess.Popen([str(self.inflight), str(directory)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
        self.watchers.append(helper)
        try:
            assert helper.stdout.readline().strip() == 'blocked'
            stacks = ''.join(path.read_text() for path in Path(f'/proc/{helper.pid}/task').glob('*/stack'))
            assert 'vfs_rename' in stacks and 'unix_bind' in stacks, stacks
            def command(text):
                helper.stdin.write(text + '\n'); helper.stdin.flush()
                return helper.stdout.readline().strip()
            yield directory, command
            helper.stdin.close(); helper.wait(timeout=10)
        finally:
            if helper.poll() is None:
                helper.kill(); helper.wait(timeout=10)
            run(['umount', directory])
            directory.rmdir()

    def inflight_across_attachment(self):
        """A bind and a rename that entered before the guard attached finish
        after it: the guard stays unsettled, deciding every call, until a drain
        scan proves neither is still running; nothing cached can outlive them."""
        with self.blocked_calls('inflight-tmpfs') as (directory, command):
            loaded = self.load()
            assert 'not settled' in loaded.stderr, loaded.stderr
            assert json.loads(run([self.loader, 'snapshot', self.pins]).stdout)['settled'] is False
            unsettled = run([self.loader, 'drain', self.pins, self.object]).stdout.strip()
            assert unsettled == 'settled=0', unsettled
            assert command('send') == '0'  # The bind has not happened yet.
            # A depth cap of one makes every walk possibly truncated: unknown.
            depth = Path('/proc/sys/kernel/perf_event_max_stack')
            original = depth.read_text()
            set_depth(depth, '1\n')
            try:
                shallow = run([self.loader, 'drain', self.pins, self.object]).stdout.strip()
                assert shallow == 'settled=0', shallow
                assert command('release') == 'released'
                shallow = run([self.loader, 'drain', self.pins, self.object]).stdout.strip()
                assert shallow == 'settled=0', shallow
            finally:
                set_depth(depth, original)
            assert (directory / 'bus').exists() and (directory / 'moved').exists()
            denied = command('send')
            assert denied == str(errno.EACCES), denied
            assert run([self.loader, 'drain', self.pins, self.object]).stdout.strip() == 'settled=1'
            assert json.loads(run([self.loader, 'snapshot', self.pins]).stdout)['settled'] is True
            assert command('send') == str(errno.EACCES)
        self.remove()
        self.passed('a bind and a rename in flight across attachment keep the guard unsettled until drained')

    def slow_scan_activation(self):
        """However slow the task scans, a load publishes before the controller's
        30-second command timeout: the drain stops at its deadline, even partway
        through a scan, and leaves the guard unsettled. A pending thread that
        exits during a drain is then noticed by rescanning just that thread."""
        import sys
        sys.path.insert(0, str(REPO / 'src/linux'))
        from wg_program_split.preflight import command as controller_command
        args = ['load', self.object, self.pins, self.group, MASK, MARK, self.included, self.checker, self.inflight]
        with self.blocked_calls('slow-scan-tmpfs') as (_, command):
            started = time.monotonic()  # The controller's own bounded command runner.
            controller_command('/usr/bin/env', 'WGPS_TEST_SCAN_DELAY_MS=1000', str(self.hooked), *map(str, args))
            slow = time.monotonic() - started
            assert slow < 10, slow
            assert json.loads(run([self.loader, 'snapshot', self.pins]).stdout)['settled'] is False
            self.remove()
            started = time.monotonic()
            cut = run([self.hooked, *args], env={**self.env, 'WGPS_TEST_SCAN_DELAY_MS': '4000'})
            partway = time.monotonic() - started
            assert 'drain deadline reached' in cut.stderr and partway < 10, (partway, cut.stderr[-500:])
            assert json.loads(run([self.loader, 'snapshot', self.pins]).stdout)['settled'] is False
            report = run([self.loader, 'drain-report', self.object]).stdout
            assert 'thread_filter=works' in report, report
            started = time.monotonic()
            drain = subprocess.Popen([str(self.loader), 'drain', str(self.pins), str(self.object)],
                                     stdout=subprocess.PIPE, text=True)
            time.sleep(.5)
            assert command('release') == 'released'
            output, _ = drain.communicate(timeout=30)
            released = time.monotonic() - started
            assert output.strip() == 'settled=1', output
        self.checks.append({'slow_scan_load_seconds': round(slow, 2), 'deadline_partway_seconds': round(partway, 2),
                            'drain_with_exiting_pending_threads_seconds': round(released, 2),
                            'drain_report': report.splitlines()[0]})
        self.remove()
        self.passed('a slow task scan publishes an unsettled guard well before the command timeout')

    def running_task_drain(self):
        """A task running on a CPU cannot be walked reliably; it clears only once
        it is observed off CPU (here, preempted by a competitor on that CPU)."""
        spin = 'import os; os.sched_setaffinity(0, {1})\nwhile True: pass'
        spinner = subprocess.Popen(['python3', '-c', spin])
        self.watchers.append(spinner)
        competitor = None
        try:
            time.sleep(.5)
            loaded = self.load()
            settled = json.loads(run([self.loader, 'snapshot', self.pins]).stdout)['settled']
            competitor = subprocess.Popen(['python3', '-c', spin])
            self.watchers.append(competitor)
            time.sleep(.5)
            result = run([self.loader, 'drain', self.pins, self.object]).stdout.strip()
            assert result == 'settled=1', (result, settled, loaded.stderr[-300:])
            self.checks.append({'running_task_settled_at_load': settled})
            # A task that keeps waking and sleeping: walks it overlaps are
            # unknown, but a quiet one soon clears it.
            flapping = subprocess.Popen(['python3', '-c', 'import time\nwhile True: time.sleep(0.0001)'])
            self.watchers.append(flapping)
            time.sleep(.3)
            result = run([self.loader, 'drain', self.pins, self.object]).stdout.strip()
            flapping.kill(); flapping.wait(timeout=10)
            assert result == 'settled=1', result
        finally:
            for process in (spinner, competitor):
                if process and process.poll() is None:
                    process.kill(); process.wait(timeout=10)
        self.remove()
        self.passed('a CPU-bound task keeps the guard unsettled until it is observed off CPU')

    def recorded(self, snapshot):
        lines = [f'map {name} {value}' for name, value in snapshot['maps'].items()]
        lines += [f'link {name} {value["id"]} {value["program_id"]}' for name, value in snapshot['links'].items()]
        return '\n'.join(lines) + '\n'

    def interrupted_removal(self):
        """A removal killed after any unpin is finished by discard, which checks
        each remaining pin against the identities recorded at load."""
        removal = [f'removed:{pin}' for pin in reversed(LINK_PINS)] + [f'removed:{name}' for name in reversed(MAP_PINS)]
        for index, point in enumerate(removal):
            self.load()
            snapshot = json.loads(run([self.loader, 'snapshot', self.pins]).stdout)
            killed = run([self.hooked, 'remove', self.pins], okay=False, env={**self.env, 'WGPS_TEST_KILL_AT': point})
            assert killed.returncode == -signal.SIGKILL, (point, killed.stderr)
            assert run([self.loader, 'snapshot', self.pins], okay=False).returncode  # No longer a whole set.
            if index % 5 == 0:  # The discard itself can be interrupted and resumed too.
                again = run([self.hooked, 'discard', self.pins], okay=False, input=self.recorded(snapshot),
                            env={**self.env, 'WGPS_TEST_KILL_AT': removal[min(index + 1, len(removal) - 1)]})
                assert again.returncode in (0, -signal.SIGKILL), again.stderr
            if self.pins.exists():
                run([self.loader, 'discard', self.pins], input=self.recorded(snapshot))
            assert not self.pins.exists()
            if self.group.exists():
                self.settle([])
        self.load()
        snapshot = json.loads(run([self.loader, 'snapshot', self.pins]).stdout)
        wrong = self.recorded(snapshot).replace(f'map paths {snapshot["maps"]["paths"]}', 'map paths 1')
        refused = run([self.loader, 'discard', self.pins], okay=False, input=wrong)
        assert refused.returncode and 'differs' in refused.stderr, refused.stderr
        # Map and link IDs are separate namespaces: a link pinned where a map
        # was, recorded under the link's own (equal) ID, is still refused.
        link_id = snapshot['links']['link']['id']
        (self.pins / 'stats').unlink()
        run(['bpftool', 'link', 'pin', 'id', str(link_id), self.pins / 'stats'])
        forged = re.sub(r'map stats \d+', f'map stats {link_id}', self.recorded(snapshot))
        refused = run([self.loader, 'discard', self.pins], okay=False, input=forged)
        assert refused.returncode and 'differs' in refused.stderr, refused.stderr
        assert (self.pins / 'link').exists()
        (self.pins / 'stats').unlink()
        stats_id = snapshot['maps']['stats']
        run(['bpftool', 'map', 'pin', 'id', str(stats_id), self.pins / 'stats'])
        # A link whose program differs from the recorded one is refused too.
        other = re.sub(r'(link link \d+) (\d+)', lambda m: f'{m[1]} {int(m[2]) + 1}', self.recorded(snapshot))
        refused = run([self.loader, 'discard', self.pins], okay=False, input=other)
        assert refused.returncode and 'differs' in refused.stderr, refused.stderr
        self.remove()
        self.passed('a removal killed after any unpin is finished from the recorded identities and object kinds')

    def legacy_capacity(self):
        """A 128-entry guard map build, as pinned before the capacity change."""
        legacy = self.work / 'legacy'
        shutil.copytree(REPO / 'src/linux/bpf', legacy)
        guard = legacy / 'resolver_guard.bpf.c'
        text = guard.read_text()
        for name in ('guard_slots', 'endpoint_names'):
            text = re.sub(r'max_entries, 1024\);(\n[^\n]*\n\} ' + name + ')', r'max_entries, 128);\1', text)
        guard.write_text(text)
        assert text.count('max_entries, 128)') == 2
        arch = {'x86_64': 'x86', 'aarch64': 'arm64'}[os.uname().machine]
        flags = run(['pkg-config', '--cflags', 'libbpf']).stdout.split()
        legacy_object = legacy / 'classifier.bpf.o'
        run(['clang', '-O2', '-g', '-target', 'bpf', f'-D__TARGET_ARCH_{arch}', '-I' + str(BUILD), *flags,
             '-c', legacy / 'classifier.bpf.c', '-o', legacy_object])
        self.object, current = legacy_object, self.object
        try:
            self.load()
        finally:
            self.object = current
        maps = json.loads(run([self.loader, 'snapshot', self.pins]).stdout)['maps']
        for name in ('guard_slots', 'endpoint_names'):
            info = json.loads(run(['bpftool', '-j', 'map', 'show', 'id', maps[name]]).stdout)
            assert info['max_entries'] == 128, info
        status = run([self.loader, 'status', self.pins]).stdout
        assert 'resolver_guards=active' in status
        run([self.loader, 'path-add-policy', self.pins, '/wgps-legacy-capacity'])
        run([self.loader, 'path-del', self.pins, '/wgps-legacy-capacity'])
        run([self.loader, 'guard-slot', self.pins, 'abstract', '@' + self.work.name])
        run([self.loader, 'state', self.pins, 'ready'])
        run([self.loader, 'state', self.pins, 'blocked'])
        full = None
        for index in range(200):
            result = run([self.loader, 'guard-slot', self.pins, 'abstract', f'@{self.work.name}-{index}'], okay=False)
            if result.returncode:
                full = result; break
        assert full is not None and 'enroll guard object' in full.stderr, 'legacy capacity was not reached'
        run([self.loader, 'state', self.pins, 'ready'])
        self.remove()
        self.passed('pins with the earlier 128-entry guard map capacity remain manageable until replaced')


def set_depth(path, value):
    """The kernel refuses a change while a program using stack walks is still
    being released (EBUSY); the loader's iterator is freed shortly after exit."""
    for attempt in range(100):
        try:
            path.write_text(value)
            return
        except OSError as error:
            if error.errno != errno.EBUSY or attempt == 99:
                raise
            time.sleep(.1)


def discard(path):
    if not path.exists(): return
    for entry in path.iterdir(): entry.unlink()
    path.rmdir()


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--native', action='store_true')
    modes.add_argument('--vm', action='store_true')
    args = parser.parse_args()
    if args.native: return native()
    if (os.geteuid() != 0 or os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM') != '1' or
            'microsoft' in os.uname().release.lower() or os.uname().nodename == 'TV' or
            not Path('/var/lib/wgps-vm-provisioned').is_file()):
        raise SystemExit('VM mode requires root, explicit disposable VM flag, marker, and native non-TV host')
    work = REPO / 'local/validation' / ('loader-recovery-' + uuid.uuid4().hex[:10])
    work.mkdir(parents=True)
    test = Recovery(work)
    try:
        test.group.mkdir()
        test.interrupted_then_recovered()
        test.repeated_interruptions()
        test.published_interruption()
        test.unpopulated_generation()
        test.refusals()
        test.interrupted_removal()
        test.inflight_across_attachment()
        test.slow_scan_activation()
        test.running_task_drain()
        test.legacy_capacity()
    finally:
        test.cleanup()
        (work / 'results.json').write_text(json.dumps({'checks': test.results, 'watchers': test.counts,
                                                       'unix_changes': test.checks}, indent=2))
        assert not test.pins.exists() and not test.staged() and not test.group.exists()
        print('Evidence:', work, flush=True)


if __name__ == '__main__': main()
