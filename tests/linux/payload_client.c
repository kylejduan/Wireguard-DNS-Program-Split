// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Real native ELF. Only reads SO_MARK; enrollment performs all mark writes. */
static void require(int okay, const char *what) {
    if (!okay) { fprintf(stderr, "%s: %s\n", what, strerror(errno)); exit(1); }
}
static uint64_t now(clockid_t clock) {
    struct timespec value;
    require(!clock_gettime(clock, &value), "clock");
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}
static uint16_t u16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void p16(unsigned char *p, unsigned value) { p[0] = value >> 8; p[1] = value; }
static void p32(unsigned char *p, unsigned value) {
    p[0] = value >> 24; p[1] = value >> 16; p[2] = value >> 8; p[3] = value;
}
static void send_all(int fd, const void *data, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t n = send(fd, (const char *)data + done, length - done, MSG_NOSIGNAL);
        require(n > 0, "send"); done += (size_t)n;
    }
}
static void read_all(int fd, void *data, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t n = recv(fd, (char *)data + done, length - done, 0);
        require(n > 0, "recv"); done += (size_t)n;
    }
}
static int connect_socket(int tcp, const char *address, unsigned port, unsigned expected) {
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    require(fd >= 0, "socket");
    unsigned mark = 0;
    socklen_t len = sizeof(mark);
    require(!getsockopt(fd, SOL_SOCKET, SO_MARK, &mark, &len) && mark == expected, "automatic socket mark");
    struct timeval timeout = {.tv_sec = 3};
    require(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "receive timeout");
    require(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)), "send timeout");
    if (tcp) {
        int yes = 1;
        require(!setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)), "TCP_NODELAY");
    }
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    require(inet_pton(AF_INET, address, &peer.sin_addr) == 1 && port > 0 && port <= 65535, "destination");
    require(!connect(fd, (void *)&peer, sizeof(peer)), "connect");
    struct sockaddr_in observed;
    len = sizeof(observed);
    require(!getpeername(fd, (void *)&observed, &len) && observed.sin_port == peer.sin_port &&
            observed.sin_addr.s_addr == peer.sin_addr.s_addr, "observed connected peer");
    return fd;
}
static ssize_t receive_udp(int fd, void *data, size_t length) {
    struct sockaddr_in peer, observed;
    socklen_t len = sizeof(peer), observed_len = sizeof(observed);
    require(!getpeername(fd, (void *)&peer, &len), "peer");
    ssize_t n = recvfrom(fd, data, length, 0, (void *)&observed, &observed_len);
    require(n > 0 && observed.sin_port == peer.sin_port &&
            observed.sin_addr.s_addr == peer.sin_addr.s_addr, "observed datagram peer");
    return n;
}
static int compare(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static void payload(int tcp, const char *address, unsigned port, unsigned size, unsigned count, unsigned mark) {
    require(size && size <= 32768 && count && count <= 100000, "payload limits");
    unsigned char *sent = malloc(size + 16), *reply = malloc(size + 16);
    uint64_t *samples = calloc(count, sizeof(*samples));
    require(sent && reply && samples, "allocation");
    int fd = connect_socket(tcp, address, port, mark);
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    require(!getsockname(fd, (void *)&local, &len), "source");
    char source[INET_ADDRSTRLEN], command[32];
    require(inet_ntop(AF_INET, &local.sin_addr, source, sizeof(source)) != NULL, "source address");
    printf("{\"connected\":true,\"source\":\"%s\",\"source_port\":%u}\n", source, ntohs(local.sin_port));
    fflush(stdout);
    require(fgets(command, sizeof(command), stdin) && !strcmp(command, "go\n"), "payload start");
    uint64_t cpu = now(CLOCK_PROCESS_CPUTIME_ID), started = now(CLOCK_MONOTONIC);
    for (unsigned i = 0; i < count; i++) {
        memcpy(sent, "WGPS", 4); p32(sent + 4, i); p32(sent + 8, count); p32(sent + 12, size);
        for (unsigned j = 0; j < size; j++) sent[j + 16] = (unsigned char)(j ^ i ^ 0x5a);
        uint64_t before = now(CLOCK_MONOTONIC);
        if (tcp) {
            send_all(fd, sent, size + 16);
            read_all(fd, reply, size + 16);
        } else {
            require(send(fd, sent, size + 16, MSG_NOSIGNAL) == (ssize_t)size + 16, "datagram send");
            require(receive_udp(fd, reply, size + 16) == (ssize_t)size + 16, "datagram length");
        }
        require(!memcmp(sent, reply, size + 16), "persistent transfer integrity");
        samples[i] = now(CLOCK_MONOTONIC) - before;
    }
    uint64_t elapsed = now(CLOCK_MONOTONIC) - started;
    cpu = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    qsort(samples, count, sizeof(*samples), compare);
    printf("{\"operations\":%u,\"bytes\":%llu,\"p50_ns\":%llu,\"p95_ns\":%llu,\"p99_ns\":%llu,"
           "\"elapsed_ns\":%llu,\"client_cpu_ns\":%llu,\"peer\":\"%s\",\"peer_port\":%u}\n",
           count, (unsigned long long)count * size, (unsigned long long)samples[count / 2],
           (unsigned long long)samples[(size_t)count * 95 / 100], (unsigned long long)samples[(size_t)count * 99 / 100],
           (unsigned long long)elapsed, (unsigned long long)cpu, address, port);
    fflush(stdout);
    require(fgets(command, sizeof(command), stdin) && !strcmp(command, "close\n"), "payload close");
    close(fd); free(sent); free(reply); free(samples);
}
static size_t name_end(const unsigned char *data, size_t length, size_t offset) {
    while (offset < length) {
        unsigned size = data[offset++];
        if (!size) return offset;
        if ((size & 0xc0) == 0xc0) { require(offset < length, "DNS pointer"); return offset + 1; }
        require(size <= 63 && offset + size <= length, "DNS label");
        offset += size;
    }
    require(0, "DNS name bounds"); return 0;
}
static void dns(const char *mode, const char *address, unsigned port, const char *answer, unsigned mark) {
    int fallback = !strcmp(mode, "fallback");
    unsigned char query[512] = {0}, response[65535];
    unsigned transaction = (unsigned)getpid() & 0xffff;
    p16(query, transaction); p16(query + 2, 0x100); p16(query + 4, 1); p16(query + 10, 1);
    const char *name = fallback ? "fallback" : "large";
    size_t offset = 12, size = strlen(name);
    query[offset++] = (unsigned char)size; memcpy(query + offset, name, size); offset += size;
    query[offset++] = 4; memcpy(query + offset, "test", 4); offset += 4; query[offset++] = 0;
    p16(query + offset, 1); p16(query + offset + 2, 1); offset += 4;
    size_t question_end = offset;
    query[offset++] = 0; p16(query + offset, 41); p16(query + offset + 2, 4096); offset += 10;
    int fd = connect_socket(0, address, port, mark);
    require(send(fd, query, offset, MSG_NOSIGNAL) == (ssize_t)offset, "EDNS query");
    ssize_t received = receive_udp(fd, response, sizeof(response));
    require(received >= 12 && u16(response) == transaction && (u16(response + 2) & 0x8000), "DNS transaction");
    int truncated = !!(u16(response + 2) & 0x200);
    require(truncated == fallback, "DNS expected UDP truncation behavior");
    close(fd);
    if (truncated) {
        fd = connect_socket(1, address, port, mark);
        unsigned char length[2]; p16(length, (unsigned)offset);
        send_all(fd, length, 2); send_all(fd, query, offset);
        read_all(fd, length, 2); received = u16(length);
        require(received >= 12, "DNS TCP frame length");
        read_all(fd, response, (size_t)received); close(fd);
    }
    size_t response_size = (size_t)received;
    require(response_size > 2048 && response_size <= 4096 && u16(response) == transaction &&
            (u16(response + 2) & 0x820f) == 0x8000 && u16(response + 4) == 1 &&
            u16(response + 6) == 1 && !memcmp(response + 12, query + 12, question_end - 12), "large DNS header/question");
    unsigned records = u16(response + 6) + u16(response + 8) + u16(response + 10);
    offset = question_end;
    struct in_addr expected;
    require(inet_pton(AF_INET, answer, &expected) == 1, "DNS expected address");
    for (unsigned i = 0; i < records; i++) {
        offset = name_end(response, response_size, offset);
        require(offset + 10 <= response_size, "DNS record header");
        unsigned type = u16(response + offset), bytes = u16(response + offset + 8);
        offset += 10;
        require(offset + bytes <= response_size, "DNS record data");
        if (i == 0) require(type == 1 && bytes == 4 && !memcmp(response + offset, &expected, 4), "DNS observed answer");
        if (type == 16) {
            size_t end = offset + bytes, cursor = offset;
            while (cursor < end) { unsigned n = response[cursor++]; require(cursor + n <= end, "DNS TXT bounds"); cursor += n; }
        }
        offset += bytes;
    }
    require(offset == response_size, "complete large DNS response");
    printf("{\"response_bytes\":%zu,\"tcp_fallback\":%s,\"answer\":\"%s\"}\n",
           response_size, truncated ? "true" : "false", answer);
}
int main(int argc, char **argv) {
    if (argc == 7 && (!strcmp(argv[1], "tcp") || !strcmp(argv[1], "udp"))) {
        payload(!strcmp(argv[1], "tcp"), argv[2], (unsigned)strtoul(argv[3], NULL, 0),
                (unsigned)strtoul(argv[4], NULL, 0), (unsigned)strtoul(argv[5], NULL, 0),
                (unsigned)strtoul(argv[6], NULL, 0));
    } else if (argc == 6 && (!strcmp(argv[1], "edns") || !strcmp(argv[1], "fallback"))) {
        dns(argv[1], argv[2], (unsigned)strtoul(argv[3], NULL, 0), argv[4], (unsigned)strtoul(argv[5], NULL, 0));
    } else { fprintf(stderr, "invalid packet fixture arguments\n"); return 2; }
    return 0;
}
