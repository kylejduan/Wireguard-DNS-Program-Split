#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Test-only native peer and paced clients. Never writes SO_MARK. All timing
 * records stay in memory until the measured work has ended. */
#define CAPACITY 16400
#define CONNECTIONS 64
static volatile sig_atomic_t stopping;
static uint64_t stamp(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) exit(2);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
static unsigned number(const char *text, unsigned maximum) {
    char *end; errno = 0;
    unsigned long value = strtoul(text, &end, 0);
    if (errno || !*text || *end || value > maximum) exit(2);
    return (unsigned)value;
}
static unsigned u16(const unsigned char *p) { return (p[0] << 8) | p[1]; }
static unsigned u32(const unsigned char *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void put16(unsigned char *p, unsigned n) { p[0] = n >> 8; p[1] = n; }
static void put32(unsigned char *p, unsigned n) { p[0] = n >> 24; p[1] = n >> 16; p[2] = n >> 8; p[3] = n; }
static int transfer(int fd, void *buffer, size_t bytes, int writing) {
    size_t done = 0;
    while (done < bytes) {
        ssize_t n = writing ? send(fd, (char *)buffer + done, bytes - done, MSG_NOSIGNAL) :
                              recv(fd, (char *)buffer + done, bytes - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return errno ? errno : EIO;
        done += (size_t)n;
    }
    return 0;
}
static int marked(int fd, unsigned expected) {
    unsigned observed = 0; socklen_t size = sizeof(observed);
    if (getsockopt(fd, SOL_SOCKET, SO_MARK, &observed, &size)) {
        int error = errno;
        fprintf(stderr, "mark read errno=%d expected=%u\n", error, expected);
        return error;
    }
    if (size != sizeof(observed) || observed != expected) {
        fprintf(stderr, "mark mismatch expected=%u observed=%u bytes=%u\n", expected, observed, size);
        return EPROTO;
    }
    return 0;
}
static int connection(int tcp, const char *host, unsigned port, unsigned mark) {
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) { int error = errno; fprintf(stderr, "connection socket errno=%d\n", error); errno = error; return -1; }
    int error = marked(fd, mark);
    if (error) { fprintf(stderr, "connection mark errno=%d expected=%u\n", error, mark); close(fd); errno = error; return -1; }
    int no_delay = 1;
    struct timeval timeout = {.tv_sec = 1};
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (error || inet_pton(AF_INET, host, &address.sin_addr) != 1 ||
        (tcp && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay))) ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        connect(fd, (void *)&address, sizeof(address))) {
        if (!error) error = errno ? errno : EINVAL;
        fprintf(stderr, "connection options/connect errno=%d\n", error);
        close(fd); errno = error; return -1;
    }
    return fd;
}
static int dns_response(unsigned char *data, size_t length) {
    size_t end = 12;
    if (length < 17 || u16(data + 4) != 1) return -1;
    while (end < length && data[end]) {
        unsigned size = data[end];
        if (size > 63 || end + size + 1 >= length) return -1;
        end += size + 1;
    }
    if (end + 5 > length || u16(data + end + 1) != 1 || u16(data + end + 3) != 1) return -1;
    end += 5;
    put16(data + 2, 0x8180); put16(data + 4, 1); put16(data + 6, 1);
    put16(data + 8, 0); put16(data + 10, 0);
    static const unsigned char answer[] = {0xc0,12,0,1,0,1,0,0,0,60,0,4,198,51,100,7};
    if (end + sizeof(answer) > CAPACITY) return -1;
    memcpy(data + end, answer, sizeof(answer));
    return (int)(end + sizeof(answer));
}
static void stopped(int signal_number) { (void)signal_number; stopping = 1; }
struct peer_client { int fd, dns; size_t used, sending, sent; unsigned char data[CAPACITY + 2]; };
static int bind_socket(const char *host, unsigned port, int tcp, unsigned *actual) {
    int fd = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK, 0), yes = 1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    socklen_t size = sizeof(address);
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) ||
        inet_pton(AF_INET, host, &address.sin_addr) != 1 || bind(fd, (void *)&address, size) ||
        (tcp && listen(fd, 32)) || getsockname(fd, (void *)&address, &size)) exit(2);
    *actual = ntohs(address.sin_port); return fd;
}
static int peer(const char *host, unsigned dns_port, unsigned payload_port, const char *source) {
    int sockets[4]; unsigned ignored;
    sockets[0] = bind_socket(host, dns_port, 1, &dns_port);
    sockets[1] = bind_socket(host, dns_port, 0, &ignored);
    sockets[2] = bind_socket(host, payload_port, 1, &payload_port);
    sockets[3] = bind_socket(host, payload_port, 0, &ignored);
    struct in_addr expected;
    if (inet_pton(AF_INET, source, &expected) != 1) return 2;
    struct peer_client *clients = calloc(CONNECTIONS, sizeof(*clients));
    if (!clients) return 2;
    for (int i = 0; i < CONNECTIONS; i++) clients[i].fd = -1;
    signal(SIGTERM, stopped); signal(SIGINT, stopped); signal(SIGPIPE, SIG_IGN);
    unsigned long long dns = 0, payload = 0;
    printf("{\"ready\":true,\"dns_port\":%u,\"payload_port\":%u}\n", dns_port, payload_port); fflush(stdout);
    int error = 0;
    while (!stopping && !error) {
        struct pollfd pollers[CONNECTIONS + 5];
        for (int i = 0; i < 4; i++) pollers[i] = (struct pollfd){.fd = sockets[i], .events = POLLIN};
        pollers[4] = (struct pollfd){.fd = STDIN_FILENO, .events = POLLIN};
        for (int i = 0; i < CONNECTIONS; i++) pollers[i + 5] = (struct pollfd){.fd = clients[i].fd,
            .events = clients[i].sending ? POLLOUT : POLLIN};
        if (poll(pollers, CONNECTIONS + 5, 200) < 0) { if (errno == EINTR) continue; error = 1; break; }
        if (pollers[4].revents & (POLLIN | POLLHUP)) {
            char command[32]; ssize_t n = read(STDIN_FILENO, command, sizeof(command));
            if (n <= 0 || (n >= 4 && !memcmp(command, "quit", 4))) stopping = 1;
            else { printf("{\"dns\":%llu,\"payload\":%llu}\n", dns, payload); fflush(stdout); }
        }
        for (int i = 0; i < 4; i++) if (pollers[i].revents & POLLIN) {
            struct sockaddr_in address; socklen_t size = sizeof(address);
            if (!(i & 1)) {
                int fd = accept4(sockets[i], (void *)&address, &size, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0) continue;
                int no_delay = 1;
                if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay))) { close(fd); error = 1; break; }
                if (address.sin_addr.s_addr != expected.s_addr) { close(fd); error = 1; break; }
                int index;
                for (index = 0; index < CONNECTIONS && clients[index].fd >= 0; index++) {}
                if (index == CONNECTIONS) { close(fd); error = 1; break; }
                clients[index].fd = fd; clients[index].dns = i == 0;
                clients[index].used = clients[index].sent = clients[index].sending = 0;
            } else {
                unsigned char data[CAPACITY];
                ssize_t n = recvfrom(sockets[i], data, sizeof(data), 0, (void *)&address, &size);
                if (n < 0) continue;
                if (address.sin_addr.s_addr != expected.s_addr) { error = 1; break; }
                if (i == 1) { n = dns_response(data, (size_t)n); dns++; }
                else {
                    if (n < 16 || memcmp(data, "WGPS", 4) || u32(data + 8) + 16 != (unsigned)n) { error = 1; break; }
                    payload++;
                }
                if (n < 0 || sendto(sockets[i], data, (size_t)n, 0, (void *)&address, size) != n) { error = 1; break; }
            }
        }
        for (int i = 0; i < CONNECTIONS; i++) {
            struct peer_client *client = &clients[i];
            short events = pollers[i + 5].revents;
            if (client->fd < 0 || !events) continue;
            if (client->sending && (events & POLLOUT)) {
                ssize_t n = send(client->fd, client->data + client->sent, client->sending - client->sent, MSG_NOSIGNAL);
                if (n > 0) client->sent += (size_t)n;
                else if (errno != EAGAIN && errno != EINTR) { error = 1; break; }
                if (client->sent == client->sending) client->used = client->sent = client->sending = 0;
            } else if (!client->sending && (events & (POLLIN | POLLHUP | POLLERR))) {
                ssize_t n = recv(client->fd, client->data + client->used, sizeof(client->data) - client->used, 0);
                if (!n) { close(client->fd); client->fd = -1; continue; }
                if (n < 0) { if (errno != EAGAIN && errno != EINTR) error = 1; continue; }
                client->used += (size_t)n;
                size_t needed = 0;
                if (client->dns && client->used >= 2) needed = u16(client->data) + 2;
                if (!client->dns && client->used >= 16) needed = u32(client->data + 8) + 16;
                if (needed > sizeof(client->data)) { error = 1; break; }
                if (needed && client->used == needed) {
                    if (client->dns) {
                        int length = dns_response(client->data + 2, needed - 2);
                        if (length < 0) { error = 1; break; }
                        put16(client->data, (unsigned)length); client->sending = (size_t)length + 2; dns++;
                    } else {
                        if (memcmp(client->data, "WGPS", 4)) { error = 1; break; }
                        client->sending = needed; payload++;
                    }
                }
            }
        }
    }
    for (int i = 0; i < 4; i++) close(sockets[i]);
    for (int i = 0; i < CONNECTIONS; i++) if (clients[i].fd >= 0) close(clients[i].fd);
    free(clients); return error;
}

struct sample { uint64_t latency, lateness; unsigned error, bytes; };
static int query(const char *host, unsigned port, unsigned mark, unsigned sequence, int tcp) {
    int fd = connection(tcp, host, port, mark);
    if (fd < 0) return errno;
    unsigned char data[512] = {0,0,1,0,0,1,0,0,0,0,0,0,4,'w','g','p','s',7,'i','n','v','a','l','i','d',0,0,1,0,1};
    put16(data, sequence); unsigned char length[2]; put16(length, 30);
    int error = tcp ? transfer(fd, length, 2, 1) : 0;
    if (!error) error = transfer(fd, data, 30, 1);
    ssize_t size = 0;
    if (!error && tcp) {
        error = transfer(fd, length, 2, 0); size = u16(length);
        if (size > (ssize_t)sizeof(data)) error = EPROTO;
        if (!error) error = transfer(fd, data, (size_t)size, 0);
    } else if (!error) size = recv(fd, data, sizeof(data), 0);
    static const unsigned char answer[] = {198,51,100,7};
    if (!error && (size < 16 || u16(data) != (sequence & 65535) || u16(data + 6) != 1 ||
                   memcmp(data + size - 4, answer, 4))) error = EPROTO;
    close(fd); return error;
}
static int client(int argc, char **argv) {
    if (argc != 10) return 2;
    signal(SIGTERM, stopped); signal(SIGINT, stopped); signal(SIGPIPE, SIG_IGN);
    const char *mode = argv[2], *host = argv[3], *file = argv[9];
    unsigned dns_port = number(argv[4], 65535), payload_port = number(argv[5], 65535);
    unsigned milliseconds = number(argv[6], 30000), rate = number(argv[7], 20000), mark = number(argv[8], UINT32_MAX);
    unsigned count = (unsigned)((uint64_t)milliseconds * rate / 1000);
    if (!milliseconds || !rate || !count || count > 100000) return 2;
    int socket_case = !strcmp(mode, "socket_udp") || !strcmp(mode, "socket_tcp");
    int dns_case = !strcmp(mode, "dns_udp") || !strcmp(mode, "dns_tcp");
    int payload_case = !strcmp(mode, "tcp") || !strcmp(mode, "udp");
    int ipc_case = !strcmp(mode, "ipc_fresh") || !strcmp(mode, "ipc_old");
    int mmap_case = !strcmp(mode, "mmap"), file_case = !strcmp(mode, "file");
    if (!socket_case && !dns_case && !payload_case && !ipc_case && !mmap_case && !file_case) return 2;
    struct sample *samples = calloc(count, sizeof(*samples));
    if (!samples) return 2;
    int fd = -1, pair[2] = {-1, -1}, tcp = !strcmp(mode, "tcp") || !strcmp(mode, "dns_tcp") || !strcmp(mode, "socket_tcp");
    if (payload_case) fd = connection(tcp, host, payload_port, mark);
    if ((payload_case && fd < 0) || (ipc_case && socketpair(AF_UNIX, SOCK_STREAM, 0, pair))) { free(samples); return 2; }
    unsigned nonce;
    if (getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce)) { free(samples); return 2; }
    puts("{\"ready\":true}"); fflush(stdout);
    char command[96]; unsigned long long start;
    if (!fgets(command, sizeof(command), stdin) || sscanf(command, "go %llu", &start) != 1) { free(samples); return 2; }
    uint64_t period = 1000000000ULL / rate;
    struct rusage usage0, usage1;
    struct timespec initial = {.tv_sec = (time_t)(start / 1000000000ULL), .tv_nsec = (long)(start % 1000000000ULL)};
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &initial, NULL) == EINTR) {}
    getrusage(RUSAGE_SELF, &usage0); uint64_t cpu = stamp(CLOCK_PROCESS_CPUTIME_ID), began = stamp(CLOCK_MONOTONIC);
    unsigned completed = 0, failed = 0;
    for (unsigned i = 0; i < count && !stopping; i++) {
        uint64_t due = start + period * i;
        struct timespec wait = {.tv_sec = (time_t)(due / 1000000000ULL), .tv_nsec = (long)(due % 1000000000ULL)};
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wait, NULL) == EINTR) {}
        struct sample *sample = &samples[i];
        uint64_t begin = stamp(CLOCK_MONOTONIC);
        sample->lateness = begin > due ? begin - due : 0;
        if (socket_case) {
            int opened = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
            int error = opened < 0 ? errno : 0;
            sample->latency = stamp(CLOCK_MONOTONIC) - begin;
            sample->error = opened < 0 ? (unsigned)error : (unsigned)marked(opened, mark);
            if (opened < 0) fprintf(stderr, "socket errno=%d\n", error);
            if (opened >= 0) close(opened);
        } else if (dns_case) sample->error = (unsigned)query(host, dns_port, mark, nonce + i, tcp);
        else if (payload_case || ipc_case) {
            unsigned char sent[CAPACITY], reply[CAPACITY];
            unsigned size = ipc_case ? 64 : tcp ? 16384 : 1200;
            memcpy(sent, "WGPS", 4); put32(sent + 4, i); put32(sent + 8, size); put32(sent + 12, nonce);
            for (unsigned j = 0; j < size; j++) sent[j + 16] = (unsigned char)(j ^ i ^ nonce);
            int output = ipc_case ? pair[0] : fd, input = ipc_case ? pair[1] : fd;
            sample->error = (unsigned)transfer(output, sent, size + 16, 1);
            if (!sample->error) sample->error = (unsigned)transfer(input, reply, size + 16, 0);
            if (!sample->error && memcmp(sent, reply, size + 16)) sample->error = EPROTO;
            if (!sample->error) sample->bytes = size;
        } else {
            int input = open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (input < 0) sample->error = (unsigned)errno;
            else if (mmap_case) {
                void *mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, input, 0);
                if (mapping == MAP_FAILED) sample->error = (unsigned)errno;
                else { if (*(volatile unsigned char *)mapping != 'Z') sample->error = EPROTO; munmap(mapping, 4096); }
            } else {
                unsigned char data[64];
                if (read(input, data, sizeof(data)) != sizeof(data)) sample->error = EIO;
                else for (unsigned j = 0; j < sizeof(data); j++) if (data[j] != 'Z') sample->error = EPROTO;
            }
            if (input >= 0) close(input);
        }
        if (!socket_case) sample->latency = stamp(CLOCK_MONOTONIC) - begin;
        completed++;
        if (sample->error) { failed = 1; break; }
    }
    uint64_t elapsed = stamp(CLOCK_MONOTONIC) - began; cpu = stamp(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    getrusage(RUSAGE_SELF, &usage1);
    if (fd >= 0) close(fd);
    if (pair[0] >= 0) { close(pair[0]); close(pair[1]); }
    printf("{\"case\":\"%s\",\"planned\":%u,\"start_ns\":%llu,\"period_ns\":%llu,\"elapsed_ns\":%llu,"
           "\"cpu_ns\":%llu,\"context_switches\":%ld,\"samples\":[", mode, count, start,
           (unsigned long long)period, (unsigned long long)elapsed, (unsigned long long)cpu,
           (usage1.ru_nvcsw + usage1.ru_nivcsw) - (usage0.ru_nvcsw + usage0.ru_nivcsw));
    for (unsigned i = 0; i < completed; i++) printf("%s[%llu,%llu,%u,%u]", i ? "," : "",
        (unsigned long long)samples[i].latency, (unsigned long long)samples[i].lateness, samples[i].error, samples[i].bytes);
    puts("]}"); free(samples); return (int)(failed || completed != count);
}
int main(int argc, char **argv) {
    if (argc == 6 && !strcmp(argv[1], "peer")) return peer(argv[2], number(argv[3], 65535), number(argv[4], 65535), argv[5]);
    if (argc >= 2 && !strcmp(argv[1], "client")) return client(argc, argv);
    return 2;
}
