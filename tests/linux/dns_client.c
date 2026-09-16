// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Native ELF fixture: no setsockopt(SO_MARK), proxy, or launcher. */
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(2);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static int read_all(int fd, void *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t got = recv(fd, (char *)buf + done, len - done, 0);
        if (got <= 0) return -1;
        done += (size_t)got;
    }
    return 0;
}
static int lookup(const char *proto, const char *address, const char *answer,
                  unsigned expected, const char *source) {
    int tcp = !strcmp(proto, "tcp"), connected = tcp || !strcmp(proto, "udp-connected");
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int result = 1;
    unsigned mark = 0;
    socklen_t size = sizeof(mark);
    struct timeval timeout = {.tv_sec = 1};
    if (getsockopt(fd, SOL_SOCKET, SO_MARK, &mark, &size) || mark != expected) {
        fprintf(stderr, "unexpected mark 0x%x expected 0x%x\n", mark, expected); goto end;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) goto end;
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(53)};
    if (inet_pton(AF_INET, address, &peer.sin_addr) != 1) goto end;
    if (source) {
        struct sockaddr_in local = {.sin_family = AF_INET};
        char source_address[64];
        if (strlen(source) >= sizeof(source_address)) goto end;
        strcpy(source_address, source);
        char *port = strchr(source_address, ':');
        if (port) {
            *port++ = 0;
            char *endptr;
            unsigned long value = strtoul(port, &endptr, 10);
            if (!*port || *endptr || !value || value > 65535) goto end;
            local.sin_port = htons((uint16_t)value);
        }
        if (inet_pton(AF_INET, source_address, &local.sin_addr) != 1 ||
            bind(fd, (void *)&local, sizeof(local))) goto end;
    }
    const unsigned char query[] = {
        0,42,1,0,0,1,0,0,0,0,0,0,4,'w','g','p','s',7,'i','n','v','a','l','i','d',0,0,1,0,1
    };
    if (connected && connect(fd, (void *)&peer, sizeof(peer))) goto end;
    unsigned char reply[65535];
    ssize_t length;
    struct sockaddr_in observed = {0};
    socklen_t observed_size = sizeof(observed);
    if (tcp) {
        uint16_t count = htons(sizeof(query));
        if (send(fd, &count, 2, MSG_NOSIGNAL) != 2 ||
            send(fd, query, sizeof(query), MSG_NOSIGNAL) != sizeof(query) ||
            read_all(fd, &count, 2)) goto end;
        length = ntohs(count);
        if (read_all(fd, reply, (size_t)length)) goto end;
        if (getpeername(fd, (void *)&observed, &observed_size)) goto end;
    } else {
        ssize_t sent = connected ? send(fd, query, sizeof(query), 0) :
            sendto(fd, query, sizeof(query), 0, (void *)&peer, sizeof(peer));
        if (sent != sizeof(query)) goto end;
        length = recvfrom(fd, reply, sizeof(reply), 0, (void *)&observed, &observed_size);
    }
    if (length < 16 || reply[0] != 0 || reply[1] != 42 ||
        observed.sin_addr.s_addr != peer.sin_addr.s_addr || observed.sin_port != peer.sin_port) goto end;
    struct in_addr expected_answer;
    if (inet_pton(AF_INET, answer, &expected_answer) != 1 ||
        memcmp(reply + length - 4, &expected_answer, 4)) goto end;
    result = 0;
end:
    if (result) fprintf(stderr, "DNS query failed: %s (%d)\n", strerror(errno), errno);
    close(fd);
    return result;
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "libc")) {
        struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *result;
        int error = getaddrinfo(argv[2], NULL, &hints, &result);
        if (error) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error)); return 1; }
        struct in_addr expected;
        int okay = inet_pton(AF_INET, argv[3], &expected) == 1;
        for (struct addrinfo *item = result; item; item = item->ai_next)
            okay &= ((struct sockaddr_in *)item->ai_addr)->sin_addr.s_addr == expected.s_addr;
        freeaddrinfo(result);
        return okay ? 0 : 1;
    }
    if (argc < 5 || argc > 7) {
        fprintf(stderr, "dns_client udp|udp-connected|tcp DEST ANSWER EXPECTED_MARK [COUNT [SOURCE]]\n");
        return 2;
    }
    unsigned count = argc >= 6 ? (unsigned)strtoul(argv[5], NULL, 10) : 1;
    if (!count || count > 1000000) return 2;
    uint64_t *samples = calloc(count, sizeof(*samples));
    if (!samples) return 2;
    for (unsigned i = 0; i < count; i++) {
        uint64_t begin = now();
        if (lookup(argv[1], argv[2], argv[3], (unsigned)strtoul(argv[4], NULL, 0), argc == 7 ? argv[6] : NULL)) {
            free(samples); return 1;
        }
        samples[i] = now() - begin;
    }
    for (unsigned i = 0; i < count; i++) printf("%llu\n", (unsigned long long)samples[i]);
    free(samples);
    return 0;
}
