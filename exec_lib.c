#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <string.h>

#include "exec_lib.h"
#include "mbuf.h"

static int exec_proc_sync(int fd, sync_cb_t sync_cb)
{
    int read_bytes;
    static char read_buffer[2048];
    struct mbuf buffer;
    int ret;

    mbuf_init(&buffer, 0);

    do {
        read_bytes = read(fd, read_buffer, sizeof(read_buffer) - 1);
        read_buffer[read_bytes] = '\0';
        if (read_bytes < 0) {
            perror("read operaion failed");
        } else if (read_bytes > 0) {
            mbuf_append(&buffer, read_buffer, read_bytes);
        }
    } while (read_bytes > 0);

    close(fd);
    wait(NULL);
    ret = sync_cb(&buffer);
    if (ret < 0) {
        printf("callback failed\n");
    }
    mbuf_free(&buffer);
    return ret;
}

int exec_proccess(char **cmd, sync_cb_t sync_cb)
{
    int fork_pid;
    int stdout_pipe[2];

    if (pipe(stdout_pipe)) {
        perror("couldn't create pipe");
        return -1;
    }

    fork_pid = fork();

    if (fork_pid < 0) {
        perror("fork failed");
        return -1;
    }

    if (fork_pid == 0) {
        close(stdout_pipe[0]);
        close(STDOUT_FILENO);

        //redirect stdout
        if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0) {
            perror("couldn't redirect stdout to pipe");
            return -1;
        }

        //redirect stderr
        close(STDERR_FILENO);
        if (dup2(stdout_pipe[1], STDERR_FILENO) < 0) {
            perror("couldn't redirect stderr to pipe");
            return -1;
        }

        execvp(cmd[0], cmd);
        close(stdout_pipe[1]);

    } else {
        close(stdout_pipe[1]);
        return exec_proc_sync(stdout_pipe[0], sync_cb);
    }

    return 0;
}
