// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Test-only: periodic FIFO wakeups preempt another copy on the same CPU.
 * Neither executable sets SO_MARK. All observations are buffered until exit. */
static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) exit(2);
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}
static void until(uint64_t target) {
    struct timespec value = {.tv_sec = target / 1000000000,
                            .tv_nsec = target % 1000000000};
    int error;
    do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &value, NULL); }
    while (error == EINTR);
    if (error) exit(2);
}
int main(int argc, char **argv) {
    if (argc != 8) return 2;
    int cpu = atoi(argv[1]), paced = atoi(argv[2]);
    unsigned expected = (unsigned)strtoul(argv[3], NULL, 0);
    uint64_t start = strtoull(argv[4], NULL, 10);
    unsigned seconds = (unsigned)strtoul(argv[5], NULL, 10);
    int guarded = atoi(argv[7]);
    if (cpu < 0 || cpu >= CPU_SETSIZE || seconds < 1 || seconds > 60) return 2;
    cpu_set_t cpus; CPU_ZERO(&cpus); CPU_SET(cpu, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus)) { perror("affinity"); return 2; }
    struct sched_param scheduling = {.sched_priority = paced ? 1 : 0};
    if (sched_setscheduler(0, paced ? SCHED_FIFO : SCHED_OTHER, &scheduling)) {
        perror("scheduler"); return 2;
    }
    uint64_t sockets = 0, socket_errors = 0, wrong_marks = 0, cache_errors = 0, ipc_errors = 0;
    unsigned first_mark = 0; int first_socket_errno = 0;
    until(start);
    uint64_t end = start + (uint64_t)seconds * 1000000000;
    while (now() < end) {
        for (int batch = 0; batch < 4; batch++) {
            int fd = socket(AF_INET, sockets & 1 ? SOCK_STREAM : SOCK_DGRAM, 0);
            sockets++;
            if (fd < 0) {
                socket_errors++; if (!first_socket_errno) first_socket_errno = errno;
            } else {
                unsigned observed = 0; socklen_t size = sizeof(observed);
                if (getsockopt(fd, SOL_SOCKET, SO_MARK, &observed, &size) || size != sizeof(observed)) {
                    socket_errors++; if (!first_socket_errno) first_socket_errno = errno ? errno : EIO;
                } else if (observed != expected) {
                    if (!wrong_marks) first_mark = observed;
                    wrong_marks++;
                }
                close(fd);
            }
            /* This registered cache path also invokes shared policy_select. */
            fd = open(argv[6], O_RDONLY | O_CLOEXEC);
            if (guarded && expected) {
                if (fd >= 0 || errno != EACCES) cache_errors++;
            } else if (fd < 0) cache_errors++;
            if (fd >= 0) { char byte; if (read(fd, &byte, 1) != 1) cache_errors++; close(fd); }
        }
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) ipc_errors++;
        else {
            char byte = 'x';
            if (write(pair[0], &byte, 1) != 1 || read(pair[1], &byte, 1) != 1) ipc_errors++;
            close(pair[0]); close(pair[1]);
        }
        /* Relative pacing avoids a delayed FIFO worker monopolizing its CPU. */
        if (paced) until(now() + 50000);
    }
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage)) return 2;
    printf("{\"cpu\":%d,\"paced\":%d,\"sockets\":%llu,\"socket_errors\":%llu,"
           "\"wrong_marks\":%llu,\"first_mark\":%u,\"first_socket_errno\":%d,"
           "\"cache_errors\":%llu,\"ipc_errors\":%llu,\"voluntary\":%ld,\"involuntary\":%ld}\n",
           sched_getcpu(), paced, (unsigned long long)sockets, (unsigned long long)socket_errors,
           (unsigned long long)wrong_marks, first_mark, first_socket_errno,
           (unsigned long long)cache_errors, (unsigned long long)ipc_errors,
           usage.ru_nvcsw, usage.ru_nivcsw);
    return (socket_errors || wrong_marks || cache_errors || ipc_errors) ? 1 : 0;
}
