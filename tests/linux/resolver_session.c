#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Calls only real libc. Retains libc's actual nscd mappings between requests. */
static int lookup(const char *name) {
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    int result = getaddrinfo(name, NULL, &hints, &addresses);
    if (result || !addresses) {
        printf("{\"pid\":%ld,\"error\":%d}\n", (long)getpid(), result);
        fflush(stdout);
        return 1;
    }
    struct in_addr first = ((struct sockaddr_in *)addresses->ai_addr)->sin_addr;
    int consistent = 1;
    for (struct addrinfo *item = addresses; item; item = item->ai_next)
        consistent &= ((struct sockaddr_in *)item->ai_addr)->sin_addr.s_addr == first.s_addr;
    char answer[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &first, answer, sizeof(answer))) return 1;
    freeaddrinfo(addresses);
    int mapped = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    char *line = NULL;
    size_t capacity = 0;
    if (!maps) return 1;
    while (getline(&line, &capacity, maps) != -1)
        mapped |= strstr(line, "/nscd/hosts") != NULL;
    free(line);
    fclose(maps);
    printf("{\"pid\":%ld,\"answer\":\"%s\",\"consistent\":%s,\"mapped_hosts\":%s}\n",
           (long)getpid(), answer, consistent ? "true" : "false", mapped ? "true" : "false");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || lookup(argv[1])) return 1;
    char command[32];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "quit\n")) return 0;
        if (!strcmp(command, "exec\n")) {
            execl(argv[0], argv[0], argv[1], (char *)NULL);
            perror("execl");
            return 1;
        }
        if (!strcmp(command, "again\n")) {
            if (lookup(argv[1])) return 1;
        } else if (!strcmp(command, "fork\n")) {
            pid_t child = fork();
            if (child < 0) return 1;
            if (!child) _exit(lookup(argv[1]));
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
        } else return 2;
    }
    return 0;
}
