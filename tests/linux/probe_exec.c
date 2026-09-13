// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* A real native parent and independently execed helper. Never set SO_MARK. */
static int observe(int fd, const char *stage)
{
    unsigned value = 0;
    socklen_t size = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_MARK, &value, &size)) return 2;
    printf("launcher_%s pid=%ld mark=0x%08x\n", stage, (long)getpid(), value);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1][0] != '/') return 2;
    alarm(10);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("launcher socket"); return 1; }
    if (observe(fd, "before")) { close(fd); return 2; }
    pid_t parent = getpid(), child = fork();
    if (child == 0) {
        /* A timed-out parent must not leave its fixture helper running. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(2);
        execl(argv[1], argv[1], "identity", (char *)NULL);
        _exit(2);
    }
    if (child < 0) { close(fd); return 2; }
    int status;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    int result = observe(fd, "after");
    close(fd);
    if (waited != child || !WIFEXITED(status)) return 2;
    return result ? result : WEXITSTATUS(status);
}
