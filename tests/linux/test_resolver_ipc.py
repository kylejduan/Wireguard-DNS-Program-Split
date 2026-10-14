#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Disposable-VM resolver-object proof; subprocess clients use identical Python bytes."""
import argparse
import array
import ctypes
import errno
import json
import mmap
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid


def client(operation, target):
    try:
        if operation in ('stream', 'seqpacket', 'dgram'):
            kind = {'stream': socket.SOCK_STREAM, 'seqpacket': socket.SOCK_SEQPACKET,
                    'dgram': socket.SOCK_DGRAM}[operation]
            with socket.socket(socket.AF_UNIX, kind) as sock:
                if target.startswith('@'): target='\0'+target[1:]
                if operation == 'dgram': sock.sendto(b'fixture', target)
                else: sock.connect(target)
        elif operation == 'mapping':
            with open(target,'rb') as source, mmap.mmap(source.fileno(),4096,prot=mmap.PROT_READ) as memory:
                print(json.dumps({'mapped':True}),flush=True); sys.stdin.readline()
                child=os.fork()
                if child==0:
                    print(json.dumps({'inherited_byte':memory[0]}),flush=True); os._exit(0)
                os.waitpid(child,0)
                print(json.dumps({'retained_byte':memory[0]})); return
        elif operation == 'open':
            with open(target, 'rb') as stream: stream.read(1)
        elif operation in ('mmap', 'none', 'read'):
            fd = int(target)
            if operation == 'read': os.read(fd, 1)
            else:
                with mmap.mmap(fd, 4096, prot=0 if operation == 'none' else mmap.PROT_READ): pass
        elif operation == 'scm':
            with socket.socket(fileno=int(target)) as sock:
                _, messages, _, _ = sock.recvmsg(16,socket.CMSG_SPACE(4))
                descriptors=[]
                for level,kind,data in messages:
                    if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                        values=array.array('i'); values.frombytes(data); descriptors.extend(values)
                for fd in descriptors: os.close(fd)
                print(json.dumps({'fd_count':len(descriptors)})); return
        elif operation == 'ordinary':
            for _ in range(100):
                with open(target,'rb') as source:
                    with mmap.mmap(source.fileno(),4096,prot=mmap.PROT_READ): pass
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ip:
                ip.sendto(b'probe',('127.0.0.1',9))
        elif operation == 'splice':
            readfd,writefd=os.pipe()
            try:
                count=os.splice(int(target),writefd,7)
                assert os.read(readfd,count)
            finally: os.close(readfd); os.close(writefd)
        elif operation in ('sendfd', 'recvfd'):
            with socket.socket(fileno=int(target)) as sock:
                if operation == 'sendfd': sock.send(b'fixture')
                else: sock.recv(16)
        else: raise ValueError(operation)
    except OSError as error:
        print(json.dumps({'errno': error.errno}))
        return
    print(json.dumps({'errno': 0}))


def run(args, okay=True, **kwargs):
    result = subprocess.run([str(x) for x in args], text=True, capture_output=True,
                            timeout=30, **kwargs)
    if okay and result.returncode:
        raise AssertionError(f'{args}: {result.stdout}\n{result.stderr}')
    return result


def native_json_test(repo):
    # Private serializer tested without privileged BPF calls or a new public API.
    source=repo/'build/linux/json-path-test.cpp'
    source.write_text(r'''#define main hidden_loader_main
#include "../../src/linux/native/bpf-loader.cpp"
#undef main
int main() {
    std::cout<<json_string(std::string("/valid-\xc3\xa9-invalid-\xff-\xed\xa0\x80-\"-\\-\n"))<<'\n';
}
''')
    executable=source.with_suffix('')
    flags=run(['pkg-config','--cflags','--libs','libbpf']).stdout.split()
    run(['c++','-O2','-std=c++17','-Wall','-Wextra','-Werror',source,'-o',executable,*flags])
    value=json.loads(run([executable]).stdout)
    assert os.fsencode(value)==b'/valid-\xc3\xa9-invalid-\xff-\xed\xa0\x80-"-\\-\n'
    print('PASS native JSON preserves valid UTF-8 and surrogateescape filesystem bytes')


# Each round binds a fresh endpoint below a staging directory and connects one
# stream that several sender threads share, so concurrent relabels of the same
# stale socket race each other while the directory is renamed to a standard
# name. A send that starts and ends while the standard name is stable must be
# denied (any other result, even a full buffer, means the guard allowed it).
# The endpoint inode is new every round, so no earlier label can help.
RENAME_RACE = r'''#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define SENDERS 4
static atomic_ulong sequence, denied, allowed, racing;
static atomic_int at_final, client = -1, go, stop_request, stopped[SENDERS], done;
static void pause_us(long us) { struct timespec t = {0, us * 1000}; nanosleep(&t, 0); }
static void *sender(void *slot) {
    int index = (int)(long)slot;
    while (!atomic_load(&done)) {
        int request = atomic_load(&stop_request);
        if (!atomic_load(&go)) { atomic_store(&stopped[index], request); continue; }
        unsigned long before = atomic_load(&sequence);
        int standard = atomic_load(&at_final);
        long result = send(atomic_load(&client), "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        int error = errno;
        if (before != atomic_load(&sequence) || (before & 1)) { atomic_fetch_add(&racing, 1); continue; }
        if (!standard) continue;
        atomic_fetch_add(result < 0 && error == EACCES ? &denied : &allowed, 1);
    }
    return 0;
}
static void move(const char *from, const char *to, int destination) {
    atomic_fetch_add(&sequence, 1);
    if (rename(from, to)) { perror("rename"); exit(3); }
    atomic_store(&at_final, destination);
    atomic_fetch_add(&sequence, 1);
}
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    const char *stage = argv[1], *final = argv[2], *name = argv[3];
    long rounds = atol(argv[4]);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s/%s", stage, name);
    char moved[sizeof(address.sun_path)];
    snprintf(moved, sizeof(moved), "%s/%s", final, name);
    pthread_t threads[SENDERS];
    for (long i = 0; i < SENDERS; i++)
        if (pthread_create(&threads[i], 0, sender, (void *)i)) return 2;
    for (int round = 1; round <= rounds; round++) {
        int listener = socket(AF_UNIX, SOCK_STREAM, 0), stream = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listener < 0 || stream < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
            listen(listener, 1) || connect(stream, (struct sockaddr *)&address, sizeof(address))) { perror("setup"); return 3; }
        int peer = accept(listener, 0, 0);
        if (peer < 0) { perror("accept"); return 3; }
        atomic_store(&client, stream);
        atomic_store(&go, 1);
        pause_us(20);
        move(stage, final, 1);
        pause_us(100);
        atomic_store(&go, 0);
        atomic_store(&stop_request, round);
        for (int i = 0; i < SENDERS; i++) while (atomic_load(&stopped[i]) != round) {}
        close(peer); close(stream); close(listener);
        if (unlink(moved)) { perror("unlink"); return 3; }
        move(final, stage, 0);
    }
    atomic_store(&done, 1);
    for (int i = 0; i < SENDERS; i++) pthread_join(threads[i], 0);
    printf("{\"standard_denied\":%lu,\"standard_allowed\":%lu,\"racing\":%lu,\"rounds\":%ld,\"senders\":%d}\n",
           atomic_load(&denied), atomic_load(&allowed), atomic_load(&racing), rounds, SENDERS);
    return 0;
}
'''


# Each round several sender threads hammer one end of a fresh socketpair while
# the other end is bound to a protected slot. A send that starts after bind()
# returned must be denied (any other result means the guard allowed it).
BIND_RACE = r'''#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define SENDERS 4
static atomic_ulong denied, allowed;
static atomic_int target = -1, bound, go, stop_request, stopped[SENDERS], done;
static void pause_us(long us) { struct timespec t = {0, us * 1000}; nanosleep(&t, 0); }
static void *sender(void *slot) {
    int index = (int)(long)slot;
    while (!atomic_load(&done)) {
        int request = atomic_load(&stop_request);
        if (!atomic_load(&go)) { atomic_store(&stopped[index], request); continue; }
        int after = atomic_load(&bound);
        long result = send(atomic_load(&target), "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        int error = errno;
        if (after) atomic_fetch_add(result < 0 && error == EACCES ? &denied : &allowed, 1);
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[1]);
    long rounds = atol(argv[2]);
    pthread_t threads[SENDERS];
    for (long i = 0; i < SENDERS; i++)
        if (pthread_create(&threads[i], 0, sender, (void *)i)) return 2;
    for (int round = 1; round <= rounds; round++) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) { perror("socketpair"); return 3; }
        atomic_store(&target, pair[1]);
        atomic_store(&bound, 0);
        atomic_store(&go, 1);
        pause_us(20);
        if (bind(pair[0], (struct sockaddr *)&address, sizeof(address))) { perror("bind"); return 3; }
        atomic_store(&bound, 1);
        pause_us(50);
        atomic_store(&go, 0);
        atomic_store(&stop_request, round);
        for (int i = 0; i < SENDERS; i++) while (atomic_load(&stopped[i]) != round) {}
        close(pair[0]); close(pair[1]);
        if (unlink(address.sun_path)) { perror("unlink"); return 3; }
    }
    atomic_store(&done, 1);
    for (int i = 0; i < SENDERS; i++) pthread_join(threads[i], 0);
    printf("{\"after_bind_denied\":%lu,\"after_bind_allowed\":%lu,\"rounds\":%ld,\"senders\":%d}\n",
           atomic_load(&denied), atomic_load(&allowed), rounds, SENDERS);
    return 0;
}
'''


# The two interleavings that defeated pre-operation invalidation, under load.
# two-ended: senders hammer B while A binds an ordinary path, A then sends once,
# senders hammer A while B binds a protected slot; a send on A begun after that
# bind returned must be denied. ordinary: senders hammer B while A binds an
# ordinary path; afterwards one send on each end must succeed.
BIND_SEQUENCE = r'''#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define SENDERS 4
static atomic_ulong denied, allowed;
static atomic_int target = -1, judged, go, stop_request, stopped[SENDERS], done;
static void pause_us(long us) { struct timespec t = {0, us * 1000}; nanosleep(&t, 0); }
static void *sender(void *slot) {
    int index = (int)(long)slot;
    while (!atomic_load(&done)) {
        int request = atomic_load(&stop_request);
        if (!atomic_load(&go)) { atomic_store(&stopped[index], request); continue; }
        int judge = atomic_load(&judged);
        long result = send(atomic_load(&target), "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        int error = errno;
        if (judge) atomic_fetch_add(result < 0 && error == EACCES ? &denied : &allowed, 1);
    }
    return 0;
}
static int request;
static void hammer(int fd) { atomic_store(&target, fd); atomic_store(&judged, 0); atomic_store(&go, 1); pause_us(20); }
static void quiesce(void) {
    pause_us(50);
    atomic_store(&go, 0);
    atomic_store(&stop_request, ++request);
    for (int i = 0; i < SENDERS; i++) while (atomic_load(&stopped[i]) != request) {}
}
static void bind_to(int fd, const char *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) { perror("bind"); exit(3); }
}
static void drain(int fd) { char buffer[4096]; while (recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {} }
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int two_ended = !strcmp(argv[1], "two-ended");
    const char *ordinary = argv[2], *protected_slot = argv[3];
    long rounds = atol(argv[4]);
    unsigned long later_sent = 0, later_refused = 0;
    pthread_t threads[SENDERS];
    for (long i = 0; i < SENDERS; i++)
        if (pthread_create(&threads[i], 0, sender, (void *)i)) return 2;
    for (long round = 0; round < rounds; round++) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) { perror("socketpair"); return 3; }
        hammer(pair[1]);
        bind_to(pair[0], ordinary);
        quiesce();
        drain(pair[0]); drain(pair[1]);
        if (two_ended) {
            send(pair[0], "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
            hammer(pair[0]);
            bind_to(pair[1], protected_slot);
            atomic_store(&judged, 1);
            quiesce();
            unlink(protected_slot);
        } else {
            for (int end = 0; end < 2; end++) {
                if (send(pair[end], "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL) == 1) later_sent++;
                else later_refused++;
            }
        }
        close(pair[0]); close(pair[1]);
        unlink(ordinary);
    }
    atomic_store(&done, 1);
    for (int i = 0; i < SENDERS; i++) pthread_join(threads[i], 0);
    printf("{\"after_protected_bind_denied\":%lu,\"after_protected_bind_allowed\":%lu,"
           "\"later_sent\":%lu,\"later_refused\":%lu,\"rounds\":%ld}\n",
           atomic_load(&denied), atomic_load(&allowed), later_sent, later_refused, rounds);
    return 0;
}
'''


# A stream socket is shared by two processes, as an inherited or received file
# is: each round the connector process (unlisted) creates it, passes it to the
# sender process and connects it to a listener on a protected slot while the
# sender's threads hammer it. A send begun after connect() returned must be
# denied for a selected sender. State is shared through a mapped file.
CONNECT_RACE = r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define SENDERS 4
struct shared {
    atomic_int target, ready, go, connected, stop_request, stopped[SENDERS], done;
    atomic_ulong denied, allowed;
};
static struct shared *state;
static void pause_us(long us) { struct timespec t = {0, us * 1000}; nanosleep(&t, 0); }
static void *sender(void *slot) {
    int index = (int)(long)slot;
    while (!atomic_load(&state->done)) {
        int request = atomic_load(&state->stop_request);
        if (!atomic_load(&state->go)) { atomic_store(&state->stopped[index], request); continue; }
        int after = atomic_load(&state->connected);
        long result = send(atomic_load(&state->target), "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        int error = errno;
        if (after) atomic_fetch_add(result < 0 && error == EACCES ? &state->denied : &state->allowed, 1);
    }
    return 0;
}
/* Pathname binds advance the generation, so the senders relabel the shared
 * socket over and over instead of once per round. */
static char churn_path[108];
static atomic_int churning = 1;
static void *churn(void *unused) {
    (void)unused;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", churn_path);
    while (atomic_load(&churning)) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0 && !bind(fd, (struct sockaddr *)&address, sizeof(address))) unlink(address.sun_path);
        if (fd >= 0) close(fd);
    }
    return 0;
}
static int receive_fd(int channel) {
    char byte; char control[CMSG_SPACE(sizeof(int))];
    struct iovec io = {&byte, 1};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    if (recvmsg(channel, &message, 0) != 1) return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header) return -2;
    int fd; memcpy(&fd, CMSG_DATA(header), sizeof(fd)); return fd;
}
static void send_fd(int channel, int fd) {
    char byte = 'f'; char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec io = {&byte, 1};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1};
    if (fd >= 0) {
        message.msg_control = control; message.msg_controllen = sizeof(control);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    }
    if (sendmsg(channel, &message, 0) != 1) { perror("sendmsg"); exit(3); }
}
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    int file = open(argv[2], O_RDWR), channel = atoi(argv[3]);
    state = mmap(0, sizeof(*state), PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    if (file < 0 || state == MAP_FAILED) return 2;
    if (!strcmp(argv[1], "sender")) {
        pthread_t threads[SENDERS];
        for (long i = 0; i < SENDERS; i++) if (pthread_create(&threads[i], 0, sender, (void *)i)) return 2;
        for (int round = 1;; round++) {
            int fd = receive_fd(channel);
            if (fd < 0) break;
            int old = atomic_exchange(&state->target, fd);
            if (old > 0) close(old);
            atomic_store(&state->ready, round);
        }
        atomic_store(&state->done, 1);
        for (int i = 0; i < SENDERS; i++) pthread_join(threads[i], 0);
        return 0;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[4]);
    snprintf(churn_path, sizeof(churn_path), "%s-churn", argv[4]);
    long rounds = atol(argv[5]);
    pthread_t churner;
    if (pthread_create(&churner, 0, churn, 0)) return 2;
    for (int round = 1; round <= rounds; round++) {
        int listener = socket(AF_UNIX, SOCK_STREAM, 0), client = socket(AF_UNIX, SOCK_STREAM, 0);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 4)) { perror("listen"); return 3; }
        atomic_store(&state->connected, 0);
        send_fd(channel, client);
        while (atomic_load(&state->ready) != round) {}
        atomic_store(&state->go, 1);
        pause_us(20);
        if (connect(client, (struct sockaddr *)&address, sizeof(address))) { perror("connect"); return 3; }
        atomic_store(&state->connected, 1);
        pause_us(50);
        atomic_store(&state->go, 0);
        atomic_store(&state->stop_request, round);
        for (int i = 0; i < SENDERS; i++) while (atomic_load(&state->stopped[i]) != round) {}
        close(client); close(listener);
        if (unlink(address.sun_path)) { perror("unlink"); return 3; }
    }
    atomic_store(&churning, 0);
    pthread_join(churner, 0);
    send_fd(channel, -1);
    printf("{\"after_connect_denied\":%lu,\"after_connect_allowed\":%lu,\"rounds\":%ld,\"senders\":%d}\n",
           atomic_load(&state->denied), atomic_load(&state->allowed), rounds, SENDERS);
    return 0;
}
'''


def late_standard(repo, work, included):
    """Fresh standard parent objects, without changing package-owned directories."""
    assert os.stat('/proc/self/ns/mnt').st_ino != os.stat('/proc/1/ns/mnt').st_ino
    for component in ('root', 'ns/net', 'ns/user', 'ns/pid'):
        a, b = os.stat('/proc/self/' + component), os.stat('/proc/1/' + component)
        assert (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    run(['mount','--make-rprivate','/'])
    for path in ('/run', '/var/cache'):
        run(['mount','-t','tmpfs','-o','mode=0755','tmpfs',path])
    Path('/run/systemd').mkdir(); Path('/run/user').mkdir()
    directories=('/run/nscd','/run/avahi-daemon','/var/cache/nscd','/run/user/99996')
    assert all(not Path(path).exists() for path in directories)
    loader=repo/'build/linux/bpf-loader'; script=Path(__file__).resolve()
    pins=Path('/sys/fs/bpf')/(work.name+'-late'); group=Path('/sys/fs/cgroup')/(work.name+'-late')
    sockets=[]; descriptors=[]; loaded=False
    native_env={key:value for key,value in os.environ.items() if key!='WG_CLASSIFIER_DISPOSABLE_VM'}
    def control(*args): return run([loader,*args],env=native_env)
    def check(executable, operation, target, expected, pass_fds=()):
        result=run([executable,script,'--client',operation,target],pass_fds=pass_fds)
        assert json.loads(result.stdout).get('errno')==expected,result.stdout
    assert not pins.exists() and not group.exists()
    try:
        group.mkdir()
        result=control('load',repo/'build/linux/classifier.bpf.o',pins,group,'0x00ff0000','0x00010000',included)
        loaded=True; (work/'late-verifier.log').write_text(result.stderr)
        # Creation follows attachment; no custom guard-slot enrollment occurs.
        for directory in directories: Path(directory).mkdir()
        os.chown('/run/user/99996',99996,99996)
        run(['mount','-t','tmpfs','-o','mode=0700,uid=99996,gid=99996','tmpfs','/run/user/99996'])
        for path in ('/run/nscd/socket','/run/avahi-daemon/socket','/run/user/99996/bus'):
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sockets.append(sock)
            sock.bind(path); sock.listen(8)
            check(included,'stream',path,errno.EACCES)
            check(work/'direct-python','stream',path,0)
        dynamic=Path('/var/cache/nscd/dbXYZ123'); dynamic.write_bytes(b'd'*4096)
        fd=os.open(dynamic,os.O_RDONLY); descriptors.append(fd); dynamic.unlink()
        check(included,'mmap',fd,errno.EACCES,pass_fds=(fd,))
        check(work/'direct-python','mmap',fd,0,pass_fds=(fd,))
        # Renaming a directory to a standard parent name relabels the SAFE streams
        # already connected below it, although no socket was renamed.
        for stage,final,name in ((Path('/run/dbus-stage'),Path('/run/dbus'),'system_bus_socket'),
                                 (Path('/run/user/stage-99997'),Path('/run/user/99997'),'bus')):
            stage.mkdir()
            if final.parent==Path('/run/user'): os.chown(stage,99997,99997)
            server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sockets.append(server)
            server.bind(str(stage/name)); server.listen(8)
            client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sockets.append(client)
            client.connect(str(stage/name)); peer,_=server.accept(); sockets.append(peer)
            check(included,'sendfd',client.fileno(),0,pass_fds=(client.fileno(),))
            stage.rename(final)
            check(included,'sendfd',client.fileno(),errno.EACCES,pass_fds=(client.fileno(),))
            check(work/'direct-python','sendfd',client.fileno(),0,pass_fds=(client.fileno(),))
        # The rename hook runs before the move is visible; a relabel racing it
        # must still see the destination name.
        source=work/'rename-race.c'; source.write_text(RENAME_RACE)
        race=work/'rename-race'; run(['cc','-O2','-std=c11','-pthread','-Wall','-Wextra','-Werror',source,'-o',race])
        selected_race=work/'rename-race-selected'; shutil.copy2(race,selected_race)
        control('path-add',pins,selected_race)
        stage,final=Path('/run/systemd/resolve-stage'),Path('/run/systemd/resolve')
        stage.mkdir()
        races={label:json.loads(run([executable,stage,final,'io.systemd.Resolve',3000]).stdout)
               for label,executable in (('selected',selected_race),('unlisted',race))}
        (work/'rename-race.json').write_text(json.dumps(races,indent=2))
        selected,unlisted=races['selected'],races['unlisted']
        assert selected['standard_allowed']==0 and selected['standard_denied']>0,races
        assert unlisted['standard_denied']==0 and unlisted['standard_allowed']>0,races
        (work/'late-namespace.json').write_text(json.dumps({'mount_namespace':os.stat('/proc/self/ns/mnt').st_ino,
            'late_directories':directories,'created_after_attachment':True,'custom_slots':False}))
    finally:
        failures=[]
        for action in [*(lambda fd=fd: os.close(fd) for fd in descriptors),
                       *(sock.close for sock in sockets),
                       *([lambda: control('remove',pins)] if loaded else []),
                       *([group.rmdir] if group.exists() else [])]:
            try: action()
            except Exception as error: failures.append(str(error))
        # All mounts are private and disappear with this synchronous child.
        if failures: raise RuntimeError('late-standard cleanup failed: '+'; '.join(failures))


def main():
    parser = argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--client', nargs=2)
    modes.add_argument('--baseline', action='store_true')
    modes.add_argument('--native', action='store_true')
    modes.add_argument('--vm', action='store_true')
    modes.add_argument('--late-standard', nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.client: return client(*args.client)
    repo = Path(__file__).resolve().parents[2]
    if args.native: return native_json_test(repo)
    if (args.vm or args.late_standard) and (os.geteuid()!=0 or os.environ.get('WG_CLASSIFIER_DISPOSABLE_VM')!='1' or
                   'microsoft' in os.uname().release.lower() or os.uname().nodename=='TV' or
                   not Path('/var/lib/wgps-vm-provisioned').is_file()):
        raise SystemExit('VM mode requires root, explicit disposable VM flag, marker, and native non-TV host')
    if args.late_standard:
        return late_standard(repo,Path(args.late_standard[0]),Path(args.late_standard[1]))
    work = repo / 'local/validation' / ('resolver-' + uuid.uuid4().hex[:10])
    work.mkdir(parents=True)
    included, direct = work/'included-python', work/'direct-python'
    for path in (included,direct): shutil.copy2(sys.executable,path)
    server_path=work/'resolver.sock'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(server_path)); server.listen(8)
        output=run([included,__file__,'--client','stream',server_path])
        if args.baseline:
            assert json.loads(output.stdout)['errno']==errno.EACCES, 'RED: selected Unix resolver connect succeeds without guards'
            return
    loader=repo/'build/linux/bpf-loader'
    pins=Path('/sys/fs/bpf')/work.name
    group=Path('/sys/fs/cgroup')/work.name
    sockets=[]; descriptors=[]; mounts=[]; active=False; results=[]; mapped_client=None
    prior_pin=Path('/sys/fs/bpf')/(work.name+'-prior')
    script=Path(__file__).resolve()
    native_env={k:v for k,v in os.environ.items() if k!='WG_CLASSIFIER_DISPOSABLE_VM'}
    def control(*args): return run([loader,*args],env=native_env)
    def check(path,operation,target,expected=errno.EACCES,pass_fds=()):
        result=run([path,script,'--client',operation,target],pass_fds=pass_fds,cwd=work)
        observed=json.loads(result.stdout)
        assert observed.get('errno')==expected,(operation,target,observed,expected)
        return observed
    def passed(name): results.append(name); print('PASS',name,flush=True)
    def add(kind,path): control('guard-slot',pins,kind,path)
    def listen(path,kind=socket.SOCK_STREAM):
        sock=socket.socket(socket.AF_UNIX,kind); sock.settimeout(3)
        sock.bind(str(path))
        if kind!=socket.SOCK_DGRAM: sock.listen(128)
        sockets.append(sock); return sock
    def connect(path):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); sock.settimeout(3)
        sock.connect(str(path)); sockets.append(sock); return sock
    def transfer(fd,path,expected):
        left,right=socket.socketpair(); sockets.extend((left,right))
        left.sendmsg([b'fd'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        result=run([path,script,'--client','scm',right.fileno()],pass_fds=(right.fileno(),))
        assert json.loads(result.stdout)=={'fd_count':expected},result.stdout
    def stats():
        return dict(line.split('=',1) for line in control('status',pins).stdout.splitlines() if '=' in line)
    try:
        with tempfile.TemporaryDirectory(prefix=work.name+'-host-',dir='/run') as namespace_test:
            visible_loader=Path(namespace_test)/'loader'; shutil.copy2(loader,visible_loader)
            for namespace in (('--net',),('--user','--map-root-user'),('--pid','--fork','--mount-proc')):
                rejected=run(['unshare',*namespace,visible_loader,'path-add-policy',pins,'/missing-image'],okay=False,env=native_env)
                assert rejected.returncode and ('namespace' in rejected.stderr or 'enrollment context' in rejected.stderr),rejected.stderr
        passed('production host checks reject foreign net/user/PID namespaces before mutation')
        group.mkdir()
        server_path.unlink()
        server=listen(server_path)
        old_client=connect(server_path); old_peer,_=server.accept(); sockets.append(old_peer)
        old_peer.send(b'queued before guard')
        mapped_file=work/'preexisting-cache'; mapped_file.write_bytes(b'z'*4096)
        mapped_client=subprocess.Popen([str(included),str(script),'--client','mapping',str(mapped_file)],
                                       stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert mapped_client.stdout.readline().strip()=='{"mapped": true}'
        prior_file=work/'prior-denied'; prior_file.write_bytes(b'p'*4096)
        prior=prior_file.stat(); device=(os.major(prior.st_dev)<<20)|os.minor(prior.st_dev)
        prior_source=work/'prior.bpf.c'
        prior_source.write_text(f'''#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
SEC("lsm/file_open") int BPF_PROG(prior_deny,struct file *file,int ret) {{
 (void)ctx; if (ret) return ret;
 return BPF_CORE_READ(file,f_inode,i_ino)=={prior.st_ino}ULL &&
        BPF_CORE_READ(file,f_inode,i_sb,s_dev)=={device}U ? -1 : 0;
}}
char LICENSE[] SEC("license")="GPL";
''')
        run(['clang','-O2','-g','-target','bpf','-I'+str(repo/'build/linux'),
             '-c',prior_source,'-o',str(prior_source)+'.o'])
        run(['bpftool','prog','load',str(prior_source)+'.o',prior_pin,'autoattach'])
        future=work/'future-image'; redirected=work/'stored-symlink'; redirected.symlink_to(direct)
        result=control('load-policy',repo/'build/linux/classifier.bpf.o',pins,group,'0x00ff0000','0x00010000',included,future,redirected)
        active=True; (work/'verifier.log').write_text(result.stderr)
        interpreter=Path(sys.executable).resolve(); control('path-add',pins,interpreter)
        try: assert json.loads(control('probe-dns',pins).stdout)=={'dns':True}
        finally: control('path-del',pins,interpreter)
        passed('native marked DNS probe works while the Python interpreter is selected and policy blocked')
        check(included,'open',prior_file,errno.EPERM); check(direct,'open',prior_file,errno.EPERM)
        passed('preexisting global LSM denial is preserved for selected and unlisted access')
        add('socket',server_path)
        check(included,'stream',server_path); check(direct,'stream',server_path,0)
        passed('actual-peer stream deny for selected while blocked; unlisted allowed')
        expected=sorted(map(str,(included,future,redirected)))
        assert json.loads(control('policy',pins).stdout)==expected
        snapshot=json.loads(control('snapshot',pins).stdout)
        assert snapshot['paths']==expected, 'snapshot must include policy under the same ownership lock'
        assert snapshot['abi']==4 and snapshot['ready'] is False
        assert len(snapshot['maps'])==15 and len(snapshot['links'])==15
        assert snapshot['mask']==0x00ff0000 and snapshot['mark']==0x00010000
        foreign=pins/'unexpected'
        run(['bpftool','map','pin','id',snapshot['maps']['paths'],foreign])
        try:
            rejected=run([loader,'snapshot',pins],okay=False)
            assert rejected.returncode and 'unknown' in rejected.stderr
        finally: foreign.unlink()
        assert all(v['id']>0 and v['program_id']>0 for v in snapshot['links'].values())
        shutil.copy2(direct,future); check(future,'stream',server_path)
        redirected.unlink(); shutil.copy2(direct,redirected); check(redirected,'stream',server_path)
        control('path-del',pins,redirected)
        assert json.loads(control('policy',pins).stdout)==sorted(map(str,(included,future)))
        assert json.loads(control('snapshot',pins).stdout)['paths']==sorted(map(str,(included,future)))
        pending=work/'pending-image'
        control('path-add-policy',pins,pending)
        assert str(pending) in json.loads(control('policy',pins).stdout)
        shutil.copy2(direct,pending); check(pending,'stream',server_path)
        control('path-del',pins,pending)
        passed('stored policy survives missing/symlink images; JSON readback reports exact owned state')
        add('cache',mapped_file)
        output,errors=mapped_client.communicate('go\n',timeout=10)
        assert mapped_client.returncode==0,(output,errors)
        assert [json.loads(line) for line in output.splitlines()]==[{'inherited_byte':122},{'retained_byte':122}]
        passed('readiness boundary: pre-enrollment mapping and forked copy remain readable and require restart')
        # Exact peer resolution ignores caller aliases.
        aliases=[server_path,Path(str(server_path).replace(str(work),'.',1)),
                 Path('/proc/self/root')/str(server_path).lstrip('/')]
        symlink=work/'socket-link'; symlink.symlink_to(server_path); aliases.append(symlink)
        hardlink=work/'socket-hardlink'; os.link(server_path,hardlink); aliases.append(hardlink)
        bound=work/'socket-bind'; bound.touch(); run(['mount','--bind',server_path,bound]); mounts.append(bound); aliases.append(bound)
        for alias in aliases:
            check(included,'stream',alias); check(direct,'stream',alias,0)
        passed('absolute/relative/symlink/hard-link/bind/proc-root endpoint aliases')
        for kind,operation in ((socket.SOCK_SEQPACKET,'seqpacket'),(socket.SOCK_DGRAM,'dgram')):
            path=work/operation; listen(path,kind); add('socket',path)
            check(included,operation,path); check(direct,operation,path,0)
        passed('actual-peer seqpacket and unconnected datagram denial')
        # Missing endpoint and daemon unlink/rebind are covered by configured slot.
        late=work/'late.sock'; add('socket',late); late_server=listen(late)
        check(included,'stream',late); check(direct,'stream',late,0)
        renamed=work/'renamed.sock'; late.rename(renamed)
        check(included,'stream',renamed)
        late_server.close(); renamed.unlink(); listen(late)
        check(included,'stream',late)
        passed('missing-then-created, bound socket rename and daemon unlink/rebind')
        bind_dir=work/'bind-canonical'; bind_dir.mkdir()
        bind_alias=work/'bind-alias'; bind_alias.symlink_to(bind_dir,target_is_directory=True)
        add('socket',bind_dir/'socket')
        listen(bind_alias/'socket')
        (bind_dir/'socket').rename(bind_dir/'moved-before-connect')
        check(included,'stream',bind_dir/'moved-before-connect')
        passed('server binding through directory alias then renaming before first client remains protected')
        exchange=bind_dir/'exchange'; destination=bind_dir/'destination'; add('socket',exchange)
        listen(bind_alias/'exchange'); listen(destination)
        libc=ctypes.CDLL(None,use_errno=True)
        assert libc.renameat2(-100,os.fsencode(destination),-100,os.fsencode(exchange),2)==0,ctypes.get_errno()
        check(included,'stream',destination); check(included,'stream',exchange)
        passed('rename exchange keeps both moved protected endpoint objects guarded')
        check(included,'sendfd',old_client.fileno(),pass_fds=(old_client.fileno(),))
        check(included,'recvfd',old_client.fileno(),pass_fds=(old_client.fileno(),))
        check(direct,'sendfd',old_client.fileno(),0,pass_fds=(old_client.fileno(),))
        splice_path=work/'splice.sock'; splice_server=listen(splice_path); add('socket',splice_path)
        splice_client=connect(splice_path); splice_peer,_=splice_server.accept(); sockets.append(splice_peer)
        splice_peer.send(b'queued splice data')
        check(included,'splice',splice_client.fileno(),pass_fds=(splice_client.fileno(),))
        check(direct,'splice',splice_client.fileno(),0,pass_fds=(splice_client.fileno(),))
        passed('selected splice of queued protected stream is denied; unlisted splice allowed')
        passed('pre-guard inherited stream and queued reply denied for selected; unlisted preserved')
        connected=connect(server_path); peer,_=server.accept(); sockets.append(peer)
        check(included,'sendfd',connected.fileno(),pass_fds=(connected.fileno(),))
        transfer(connected.fileno(),included,0); transfer(connected.fileno(),direct,1)
        passed('post-guard protected stream survives exec/SCM transfer as protected role')
        other=work/'ordinary.sock'; ordinary_server=listen(other); ordinary=connect(other)
        check(included,'sendfd',ordinary.fileno(),0,pass_fds=(ordinary.fileno(),))
        passed('unrelated post-guard stream retains ordinary selected functionality')
        add('socket',other)
        check(included,'sendfd',ordinary.fileno(),pass_fds=(ordinary.fileno(),))
        passed('new protected endpoint enrollment invalidates older safe stream roles')
        failing=work/'failed-enrollment.sock'; failing_server=listen(failing)
        failing_client=connect(failing); failing_peer,_=failing_server.accept(); sockets.append(failing_peer)
        check(included,'sendfd',failing_client.fileno(),0,pass_fds=(failing_client.fileno(),))
        failing.unlink(); failing.touch()
        rejected=run([loader,'guard-slot',pins,'socket',failing],okay=False)
        assert rejected.returncode and 'wrong file type' in rejected.stderr
        check(included,'sendfd',failing_client.fileno(),pass_fds=(failing_client.fileno(),))
        check(direct,'sendfd',failing_client.fileno(),0,pass_fds=(failing_client.fileno(),))
        passed('partially failed guard enrollment invalidates earlier SAFE streams')

        target=work/'protected-destination'; add('socket',target)
        source=work/'unprotected-source'; listen(source); moving=connect(source)
        source.rename(target)
        check(included,'sendfd',moving.fileno(),pass_fds=(moving.fileno(),))
        passed('moving a safe endpoint into a protected slot invalidates old connected stream roles')
        pair_path=work/'named-pair'; add('socket',pair_path)
        one,two=socket.socketpair(); sockets.extend((one,two)); one.bind(str(pair_path))
        check(included,'sendfd',two.fileno(),pass_fds=(two.fileno(),))
        passed('binding a previously unnamed safe socketpair invalidates both endpoint roles')
        source=work/'bind-race.c'; source.write_text(BIND_RACE)
        race=work/'bind-race'; run(['cc','-O2','-std=c11','-pthread','-Wall','-Wextra','-Werror',source,'-o',race])
        selected_race=work/'bind-race-selected'; shutil.copy2(race,selected_race)
        control('path-add',pins,selected_race)
        race_path=work/'bind-race-slot'; add('socket',race_path)
        races={label:json.loads(run([executable,race_path,3000]).stdout)
               for label,executable in (('selected',selected_race),('unlisted',race))}
        (work/'bind-race.json').write_text(json.dumps(races,indent=2))
        assert races['selected']['after_bind_allowed']==0 and races['selected']['after_bind_denied']>0,races
        assert races['unlisted']['after_bind_denied']==0 and races['unlisted']['after_bind_allowed']>0,races
        control('path-del',pins,selected_race)
        passed('concurrent senders on a socketpair never pass after its peer is bound to a protected slot')
        source=work/'bind-sequence.c'; source.write_text(BIND_SEQUENCE)
        sequence=work/'bind-sequence'; run(['cc','-O2','-std=c11','-pthread','-Wall','-Wextra','-Werror',source,'-o',sequence])
        selected_sequence=work/'bind-sequence-selected'; shutil.copy2(sequence,selected_sequence)
        control('path-add',pins,selected_sequence)
        sequences={f'{mode}-{label}':json.loads(run([executable,mode,work/'bind-ordinary',race_path,2000]).stdout)
                   for mode in ('two-ended','ordinary')
                   for label,executable in (('selected',selected_sequence),('unlisted',sequence))}
        (work/'bind-sequence.json').write_text(json.dumps(sequences,indent=2))
        assert sequences['two-ended-selected']['after_protected_bind_allowed']==0,sequences
        assert sequences['two-ended-selected']['after_protected_bind_denied']>0,sequences
        assert sequences['two-ended-unlisted']['after_protected_bind_denied']==0,sequences
        for label in ('selected','unlisted'):
            assert sequences['ordinary-'+label]['later_refused']==0,sequences
        control('path-del',pins,selected_sequence)
        passed('two-ended bind never passes after the protected bind; an ordinary bind leaves the pair usable')
        source=work/'connect-race.c'; source.write_text(CONNECT_RACE)
        connector=work/'connect-race'; run(['cc','-O2','-std=c11','-pthread','-Wall','-Wextra','-Werror',source,'-o',connector])
        selected_connector=work/'connect-race-selected'; shutil.copy2(connector,selected_connector)
        control('path-add',pins,selected_connector)
        def shared_connect(sender_executable):
            shared=work/'connect-race.shm'; shared.write_bytes(bytes(4096)); shared.chmod(0o666)
            ours,theirs=socket.socketpair(); sockets.extend((ours,theirs))
            sending=subprocess.Popen([str(sender_executable),'sender',str(shared),str(theirs.fileno())],pass_fds=(theirs.fileno(),))
            try:
                result=run([connector,'connector',shared,ours.fileno(),race_path,3000],pass_fds=(ours.fileno(),))
            finally:
                if sending.wait(timeout=30): raise AssertionError('sender failed')
            return json.loads(result.stdout)
        connects={label:shared_connect(executable)
                  for label,executable in (('selected',selected_connector),('unlisted',connector))}
        (work/'connect-race.json').write_text(json.dumps(connects,indent=2))
        assert connects['selected']['after_connect_allowed']==0 and connects['selected']['after_connect_denied']>0,connects
        assert connects['unlisted']['after_connect_denied']==0,connects
        control('path-del',pins,selected_connector)
        passed('a relabel racing connect never leaves SAFE for a protected peer')
        # A rename into a slot that fails after the rename hook (the target is a
        # mount point) must not leave the moved socket protected.
        failing_slot=work/'failing-slot'; add('socket',failing_slot); failing_slot.write_bytes(b'')
        cover=work/'failing-cover'; cover.write_bytes(b'')
        run(['mount','--bind',cover,failing_slot]); mounts.append(failing_slot)
        movable=work/'movable.sock'; movable_server=listen(movable)
        movable_client=connect(movable); movable_peer,_=movable_server.accept(); sockets.append(movable_peer)
        check(included,'sendfd',movable_client.fileno(),0,pass_fds=(movable_client.fileno(),))
        try:
            movable.rename(failing_slot); raise AssertionError('rename onto a mount point succeeded')
        except OSError as error:
            assert error.errno==errno.EBUSY,error
        # Any later invalidation relabels the stream from the listener's inode.
        listen(work/'invalidating.sock')
        check(included,'sendfd',movable_client.fileno(),0,pass_fds=(movable_client.fileno(),))
        passed('a rename into a slot that fails after the hook leaves its socket unprotected')
        # Exchanging a slot's socket with an ordinary one, in both argument
        # orders: a failure (EBUSY after both hooks) leaves the ordinary socket
        # unprotected; a success protects a stream to the socket now in the slot.
        for order in ('slot-first','ordinary-first'):
            for fails in (True,False):
                tag=f'{order}-{"failing" if fails else "working"}'
                slot=work/('exchange-slot-'+tag); add('socket',slot); listen(slot)
                plain=work/('exchange-plain-'+tag); plain_server=listen(plain)
                stream=connect(plain); peer,_=plain_server.accept(); sockets.append(peer)
                check(included,'sendfd',stream.fileno(),0,pass_fds=(stream.fileno(),))
                if fails:
                    cover=work/('exchange-cover-'+tag); cover.write_bytes(b'')
                    run(['mount','--bind',cover,slot]); mounts.append(slot)
                first,second=(slot,plain) if order=='slot-first' else (plain,slot)
                result=libc.renameat2(-100,os.fsencode(first),-100,os.fsencode(second),2)
                if fails:
                    assert result!=0 and ctypes.get_errno()==errno.EBUSY,(tag,result,ctypes.get_errno())
                    # Immediately (the hook already advanced the generation) and
                    # after a later invalidation.
                    check(included,'sendfd',stream.fileno(),0,pass_fds=(stream.fileno(),))
                    listen(work/('exchange-invalidate-'+tag))
                    check(included,'sendfd',stream.fileno(),0,pass_fds=(stream.fileno(),))
                else:
                    assert result==0,(tag,ctypes.get_errno())
                    check(included,'sendfd',stream.fileno(),pass_fds=(stream.fileno(),))
                check(direct,'sendfd',stream.fileno(),0,pass_fds=(stream.fileno(),))
        passed('slot exchanges in both orders: a failed one protects nothing, a successful one protects the moved socket')
        cache=work/'hosts-cache'; cache.write_bytes(b'h'*4096)
        cachefd=os.open(cache,os.O_RDONLY); descriptors.append(cachefd); add('cache',cache)
        aliases=[cache,Path('/proc/self/root')/str(cache).lstrip('/')]
        link=work/'cache-hardlink'; os.link(cache,link); aliases.append(link)
        link=work/'cache-symlink'; link.symlink_to(cache); aliases.append(link)
        for path in aliases:
            check(included,'open',path); check(direct,'open',path,0)
        cache.rename(work/'cache-renamed'); check(included,'open',work/'cache-renamed')
        for op in ('mmap','none','read'):
            check(included,op,cachefd,pass_fds=(cachefd,)); check(direct,op,cachefd,0,pass_fds=(cachefd,))
        transfer(cachefd,included,0); transfer(cachefd,direct,1)
        passed('cache inode aliases/rename, inherited read/mmap/PROT_NONE and SCM_RIGHTS guarded')
        # The negative-role cache: a file proved roleless must not stay allowed
        # after enrollment, a rename into a slot, or a second link into a slot.
        plain=work/'plain-file'; plain.write_bytes(b'q'*4096)
        check(included,'open',plain,0); check(included,'open',plain,0)
        add('cache',plain); check(included,'open',plain); check(direct,'open',plain,0)
        moving=work/'moving-file'; moving.write_bytes(b'm'*4096); slot=work/'future-cache-slot'; add('cache',slot)
        check(included,'open',moving,0); check(included,'open',moving,0)
        moving.rename(slot); check(included,'open',slot); check(direct,'open',slot,0)
        linked=work/'linked-file'; linked.write_bytes(b'l'*4096); link_slot=work/'future-link-slot'; add('cache',link_slot)
        check(included,'open',linked,0); check(included,'open',linked,0)
        os.link(linked,link_slot); check(included,'open',link_slot); check(direct,'open',link_slot,0)
        passed('cached no-role files are rechecked after enrollment, rename into a slot and a second link')
        private=work/'nscd-private'; private.mkdir(); add('cache-dir',private)
        temporary=private/'dbABC123'; temporary.write_bytes(b't'*4096)
        fd=os.open(temporary,os.O_RDONLY); descriptors.append(fd); temporary.unlink()
        for op in ('read','mmap','none'): check(included,op,fd,pass_fds=(fd,))
        transfer(fd,included,0)
        passed('newly created then unlinked nscd-style temporary database retains inode label')
        # Native standard slots: no custom guard-slot enrollment for these.
        for path in ('/run/systemd/resolve/io.systemd.Resolve','/run/dbus/system_bus_socket',
                     '/run/user/1000/bus'):
            assert Path(path).exists(),f'reference VM endpoint absent: {path}'
            check(included,'stream',path); check(direct,'stream',path,0)
        passed('real resolved Varlink, system bus and user bus connects selected-denied/unlisted-allowed')
        abstract='@'+work.name
        abstract_server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        abstract_server.bind('\0'+abstract[1:]); abstract_server.listen(8); sockets.append(abstract_server)
        add('abstract',abstract)
        check(included,'stream',abstract); check(direct,'stream',abstract,0)
        passed('abstract namespace endpoint matches exact byte length and name')
        plain=work/'plain'; plain.write_bytes(b'p'*4096)
        before=int(stats()['guard_path_lookups'])
        check(included,'ordinary',plain,0)
        after=int(stats()['guard_path_lookups'])
        assert before==after,(before,after)
        passed('100 ordinary open/mmap operations and IP payload send perform zero guard executable lookups')
        # Fault-injected crash epoch: no SAFE classification can survive an
        # incomplete update; direct clients retain working unrelated IPC.
        crash=work/'during-update.sock'; listen(crash)
        raw=run(['bpftool','-j','map','lookup','pinned',pins/'guard_config','key','hex','00','00','00','00']).stdout
        epoch=int.from_bytes(bytes(int(v,16) for v in json.loads(raw)['value']),'little')
        def set_epoch(value):
            run(['bpftool','map','update','pinned',pins/'guard_config','key','hex','00','00','00','00',
                 'value','hex',*(f'{x:02x}' for x in value.to_bytes(8,'little'))])
        set_epoch(epoch+1)
        check(included,'stream',crash); check(direct,'stream',crash,0)
        interrupted=run([loader,'state',pins,'ready'],okay=False)
        assert interrupted.returncode and 'incomplete' in interrupted.stderr
        set_epoch(epoch+2)
        check(included,'stream',crash,0)
        passed('interrupted odd guard epoch denies selected SAFE use and readiness; unlisted IPC stays healthy')
        # Protection is active independently of socket/network ready flag.
        control('state',pins,'ready'); check(included,'stream',server_path)
        changed=run([loader,'guard-slot',pins,'socket',other],okay=False)
        assert changed.returncode and 'blocked' in changed.stderr
        passed('guard link verification gates ready; guard changes require blocked state')
        (work/'status.txt').write_text(control('status',pins).stdout)
        (work/'links.json').write_text(run(['bpftool','-j','link','show']).stdout)
    finally:
        if mapped_client and mapped_client.poll() is None:
            mapped_client.kill(); mapped_client.communicate(timeout=10)
        for fd in descriptors: os.close(fd)
        for sock in sockets: sock.close()
        for mount in reversed(mounts): run(['umount',mount])
        if active: control('remove',pins)
        if prior_pin.exists(): prior_pin.unlink()
        if group.exists(): group.rmdir()
        (work/'results.json').write_text(json.dumps(results,indent=2))
        (work/'links-after.json').write_text(run(['bpftool','-j','link','show']).stdout)
        print('Evidence:',work,flush=True)
    # Existing real endpoints were tested above in their original host view.
    # A separate namespace permits genuine late creation even after apt/nscd.
    def directory_identity():
        result={}
        for name in ('/run/nscd','/run/avahi-daemon','/var/cache/nscd','/run/user/99996'):
            path=Path(name)
            if path.exists():
                st=path.stat()
                result[name]=[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_mtime_ns,
                              sorted(item.name for item in path.iterdir())]
            else: result[name]=None
        return result
    before=directory_identity()
    late_pins=Path('/sys/fs/bpf')/(work.name+'-late')
    late_group=Path('/sys/fs/cgroup')/(work.name+'-late')
    assert not late_pins.exists() and not late_group.exists()
    try:
        run(['unshare','--mount','--propagation','private',sys.executable,script,
             '--late-standard',work,included])
    finally:
        failures=[]
        # The child normally removes these. Also fence a killed/timed-out child;
        # native removal verifies map/link ownership before removing any pins.
        for action in [*([lambda: control('remove',late_pins)] if late_pins.exists() else []),
                       *([late_group.rmdir] if late_group.exists() else [])]:
            try: action()
            except Exception as error: failures.append(str(error))
        if directory_identity()!=before: failures.append('host package/runtime directories changed')
        (work/'host-directories.json').write_text(json.dumps(before,indent=2))
        if failures: raise RuntimeError('late-standard supervisor cleanup failed: '+'; '.join(failures))
    passed('late standard nscd/Avahi/user bus directories, directory renames into standard names and unlinked cache covered by ancestor rules')
    (work/'results.json').write_text(json.dumps(results,indent=2))
    (work/'links-after.json').write_text(run(['bpftool','-j','link','show']).stdout)


if __name__ == '__main__': main()
