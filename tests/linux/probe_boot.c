// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* No resolver calls or networking precedes this process's first socket(). */
int main(int argc, char **argv)
{
    if (argc != 3 || strspn(argv[2], "0123456789abcdef") != 12 || strlen(argv[2]) != 12) return 2;
    char boot[40] = {0};
    int source = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (source < 0 || read(source, boot, 36) != 36) return 2;
    close(source);
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int error = sock < 0 ? errno : 0;
    unsigned mark = 0; socklen_t size = sizeof(mark);
    char mark_text[16] = "null";
    if (sock >= 0) {
        if (getsockopt(sock, SOL_SOCKET, SO_MARK, &mark, &size)) return 2;
        snprintf(mark_text, sizeof(mark_text), "%u", mark);
        close(sock);
    }
    int output = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) return 2;
    if (dprintf(output, "{\"boot_id\":\"%s\",\"nonce\":\"%s\",\"socket_errno\":%d,\"mark\":%s}\n",
                boot, argv[2], error, mark_text) < 0 || fsync(output)) return 2;
    close(output);
    return error == EPERM ? 0 : 1;
}
