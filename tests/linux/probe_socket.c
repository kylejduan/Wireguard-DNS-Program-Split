// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Deliberately no resolver/library networking before socket(). Numeric peers only. */
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int mark(int fd)
{
    unsigned value = 0;
    socklen_t len = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_MARK, &value, &len)) {
        perror("getsockopt SO_MARK");
        exit(2);
    }
    return (int)value;
}

static int open_socket(int domain, int type, uint64_t *elapsed)
{
    uint64_t begin = now_ns();
    int fd = socket(domain, type | SOCK_CLOEXEC, type == SOCK_RAW ? IPPROTO_RAW : 0);
    int error = errno;
    *elapsed = now_ns() - begin;
    if (fd < 0)
        printf("socket_error=%d socket_ns=%llu\n", error,
               (unsigned long long)*elapsed);
    return fd;
}

static int identity(int domain, int type)
{
    uint64_t elapsed;
    int fd = open_socket(domain, type, &elapsed);
    if (fd < 0) return 1;
    char exe[4096] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) { perror("readlink"); close(fd); return 2; }
    struct stat net, mnt, root;
    if (stat("/proc/self/ns/net", &net) || stat("/proc/self/ns/mnt", &mnt) ||
        stat("/", &root)) { perror("stat"); close(fd); return 2; }
    printf("mark=0x%08x socket_ns=%llu uid=%u netns=%llu mntns=%llu "
           "root_ino=%llu exe=%s\n", (unsigned)mark(fd),
           (unsigned long long)elapsed, getuid(), (unsigned long long)net.st_ino,
           (unsigned long long)mnt.st_ino, (unsigned long long)root.st_ino, exe);
    close(fd);
    return 0;
}

static int exchange(const char *mode, const char *host, const char *port)
{
    struct sockaddr_in peer = {.sin_family = AF_INET};
    char *end;
    long number = strtol(port, &end, 10);
    if (*end || number < 1 || number > 65535 ||
        inet_pton(AF_INET, host, &peer.sin_addr) != 1) return 2;
    peer.sin_port = htons((unsigned short)number);
    int tcp = !strcmp(mode, "tcp"), connected = strcmp(mode, "udp") != 0;
    uint64_t elapsed, begin = now_ns();
    int fd = open_socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, &elapsed);
    if (fd < 0) return 1;
    /* Read immediately, before connect/send and before any user mark update. */
    unsigned observed = (unsigned)mark(fd);
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto error;
    if (connected && connect(fd, (void *)&peer, sizeof(peer)) < 0) {
        if (errno != EINPROGRESS) goto error;
        struct pollfd p = {.fd = fd, .events = POLLOUT};
        int result = 0;
        socklen_t len = sizeof(result);
        if (poll(&p, 1, 2000) != 1 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &result, &len) || result) goto error;
    }
    const char payload[] = "wg-classifier-first-packet";
    ssize_t sent = connected ? send(fd, payload, sizeof(payload), MSG_NOSIGNAL) :
        sendto(fd, payload, sizeof(payload), MSG_NOSIGNAL, (void *)&peer, sizeof(peer));
    if (sent != sizeof(payload)) goto error;
    struct pollfd p = {.fd = fd, .events = POLLIN};
    char reply[sizeof(payload)];
    struct sockaddr_in observed_peer;
    socklen_t peer_len = sizeof(observed_peer);
    ssize_t got = 0;
    uint64_t deadline = now_ns() + 2000000000ULL;
    do {
        uint64_t current = now_ns();
        if (current >= deadline || poll(&p, 1, (int)((deadline-current)/1000000)+1) != 1)
            goto error;
        ssize_t part = tcp ? recv(fd, reply+got, sizeof(reply)-(size_t)got, 0) :
            recvfrom(fd, reply, sizeof(reply), 0, (void *)&observed_peer, &peer_len);
        if (part < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (part <= 0) goto error;
        got += part;
        if (!tcp) break;
    } while ((size_t)got < sizeof(reply));
    if (got != sizeof(reply) || memcmp(reply, payload, sizeof(reply))) goto error;
    if (tcp && getpeername(fd, (void *)&observed_peer, &peer_len)) goto error;
    char observed_host[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &observed_peer.sin_addr, observed_host, sizeof(observed_host))) goto error;
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(fd, (void *)&local, &len)) goto error;
    printf("mode=%s mark=0x%08x socket_ns=%llu response_ns=%llu "
           "local_port=%u peer=%s:%u bytes=%zd\n", mode, observed,
           (unsigned long long)elapsed, (unsigned long long)(now_ns() - begin),
           ntohs(local.sin_port), observed_host, ntohs(observed_peer.sin_port), got);
    close(fd);
    return 0;
error:
    fprintf(stderr, "exchange failed: errno=%d (%s)\n", errno, strerror(errno));
    close(fd);
    return 1;
}

/* FIFO/stdin control keeps an old executable image alive across rename/unlink.
 * 's': new socket; 'o': hold socket; 'm': held socket mark; 'q': quit. */
static int control(void)
{
    int held = -1, c;
    puts("ready");
    while ((c = getchar()) != EOF && c != 'q') {
        if (c == 's') (void)identity(AF_INET, SOCK_DGRAM);
        if (c == 'o') {
            if (held >= 0) close(held);
            uint64_t elapsed;
            held = open_socket(AF_INET, SOCK_DGRAM, &elapsed);
            if (held >= 0) printf("held_mark=0x%08x\n", (unsigned)mark(held));
        }
        if (c == 'm' && held >= 0) printf("held_mark=0x%08x\n", (unsigned)mark(held));
    }
    if (held >= 0) close(held);
    return 0;
}

static void *thread_probe(void *arg)
{
    long count = (long)arg;
    for (long i = 0; i < count; i++)
        if (identity(AF_INET, SOCK_DGRAM)) return (void *)1;
    return NULL;
}

static int benchmark(const char *argument)
{
    long count = strtol(argument, NULL, 10);
    if (count < 1 || count > 1000000) return 2;
    uint64_t *samples = calloc((size_t)count, sizeof(*samples));
    if (!samples) return 2;
    struct timespec cpu0, cpu1;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu0);
    uint64_t start = now_ns();
    unsigned first = 0;
    for (long i = 0; i < count; i++) {
        int fd = open_socket(AF_INET, SOCK_DGRAM, &samples[i]);
        if (fd < 0) { free(samples); return 1; }
        unsigned observed = (unsigned)mark(fd);
        if (i == 0) first = observed;
        if (observed != first) { close(fd); free(samples); return 1; }
        close(fd);
    }
    uint64_t wall = now_ns() - start;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu1);
    uint64_t cpu = (uint64_t)(cpu1.tv_sec - cpu0.tv_sec) * 1000000000ULL +
                   cpu1.tv_nsec - cpu0.tv_nsec;
    for (long i = 0; i < count; i++)
        printf("mark=0x%08x socket_ns=%llu\n", first, (unsigned long long)samples[i]);
    printf("count=%ld wall_ns=%llu cpu_ns=%llu\n", count,
           (unsigned long long)wall, (unsigned long long)cpu);
    free(samples);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2 && !strcmp(argv[1], "identity")) return identity(AF_INET, SOCK_DGRAM);
    if (argc == 2 && !strcmp(argv[1], "ipv6")) return identity(AF_INET6, SOCK_DGRAM);
    if (argc == 2 && !strcmp(argv[1], "raw")) return identity(AF_INET, SOCK_RAW);
    if (argc == 2 && !strcmp(argv[1], "packet")) return identity(AF_PACKET, SOCK_DGRAM);
    if (argc == 2 && !strcmp(argv[1], "control")) return control();
    if (argc == 3 && !strcmp(argv[1], "bench")) return benchmark(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "threads")) {
        long count = strtol(argv[2], NULL, 10);
        if (count < 1 || count > 100000) return 2;
        pthread_t threads[4];
        for (int i = 0; i < 4; i++)
            if (pthread_create(&threads[i], NULL, thread_probe, (void *)count)) return 2;
        int result = 0;
        for (int i = 0; i < 4; i++) {
            void *ret;
            if (pthread_join(threads[i], &ret) || ret) result = 1;
        }
        return result;
    }
    if (argc == 4 && (!strcmp(argv[1], "tcp") || !strcmp(argv[1], "udp") ||
                      !strcmp(argv[1], "udp-connected")))
        return exchange(argv[1], argv[2], argv[3]);
    fprintf(stderr, "usage: %s identity|ipv6|raw|packet|control|bench COUNT|threads COUNT|"
            "tcp|udp|udp-connected HOST PORT\n", argv[0]);
    return 2;
}
