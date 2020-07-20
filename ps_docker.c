#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "parser.h"
#include "exec_lib.h"

#define MAX_BUFFER_SIZE 2048
#define MAX_CONTINER_ID_LEN 1024
#define MAX_CMDLINE_LEN 1024
#define SHA256_SIZE 65

#define STATIC_ASSERT(cond) do {char _tmp[-!!!(cond)]; (void)_tmp;} while (0)

static char sha256_current[SHA256_SIZE];

static int sha256sum_cb(struct mbuf *buffer)
{
    //upone error in sha256sum stderr will start with sha256sum
    if (!buffer || !buffer->buf || strstr(buffer->buf, "sha256sum:")) {
        memcpy(sha256_current, "None", sizeof("None"));
        return 0;
    }

    memcpy(sha256_current, buffer->buf, sizeof(sha256_current));
    sha256_current[sizeof(sha256_current) - 1] = '0';
    return 0;
}

static bool get_sha256(pid_t pid,
                       char *buffer,
                       size_t buffer_size,
                       char *path,
                       size_t path_size) {

    int bytes = snprintf(path, path_size, "/proc/%d/exe", pid);
    char *sha256[] ={"sha256sum", "path-to-exec", NULL};

    if (bytes < 0 || (size_t)bytes == path_size) {
        printf("sprintf error");
        return false;
    }

    sha256[1] = path;

    if (readlink(path, buffer, buffer_size - 1) == -1) {
        memcpy(sha256_current, "Deleted", sizeof("Deleted"));
    } else {
        exec_proccess(sha256, sha256sum_cb);
    }

    return true;
}

static char* get_starttime(pid_t pid, char *path, size_t path_size, char *buffer, size_t buffer_size)
{
    int bytes;
    char *starttime_str;
    unsigned long long starttime_offset;
    double uptime;
    time_t now;
    time_t starttime;
    char *tmp;

    now = time(NULL);

    bytes = snprintf(path, path_size, "/proc/%d/stat", pid);
    if (bytes < 0 || (size_t)bytes == path_size) {
        printf("error parsing %d status\n", pid);
        return NULL;
    }

    if (!read_file(path, buffer, buffer_size)) {
        printf ("couldn't parse stat\n");
        return NULL;
    }

    starttime_str = get_nth_word(buffer, 22);
    if (!starttime_str) {
        printf("couldn't parse stat\n");
        return NULL;
    }

    starttime_offset = strtoull(starttime_str, NULL, 10);
    if (starttime_offset == ULONG_MAX && errno == ERANGE) {
        printf("couldn't convert start-time\n");
        return NULL;
    }

    if (!read_file("/proc/uptime", buffer, buffer_size)) {
        printf ("couldn't parse stat\n");
        return NULL;
    }

    uptime = strtod(buffer, NULL);

    starttime = starttime_offset / sysconf(_SC_CLK_TCK);
    starttime =  (now - (time_t)uptime) + starttime;
    tmp = ctime(&starttime);
    tmp[strlen(tmp) - 1] = 0;
    return tmp;
}

static bool get_cmdline(char *cmd_line, size_t cmd_line_size, char *path, size_t path_size, pid_t pid)
{
    int bytes = snprintf(path, path_size, "/proc/%d/cmdline", pid);
    if (bytes < 0 || (size_t)bytes == path_size) {
        printf("sprintf error\n");
        return false;
    }

    if (!read_file(path, cmd_line,cmd_line_size)) {
        printf ("couldn't print cmdline\n");
        return false;
    }

    if (cmd_line[0] == '\0') {
        bytes = snprintf(path, path_size, "/proc/%d/comm", pid);
        if (bytes < 0 || (size_t)bytes == path_size) {
            printf("sprintf error\n");
            return false;
        }

        //in case cmdline is empty use comm
        if (!read_file(path, cmd_line, cmd_line_size)) {
            printf ("couldn't print cmdline\n");
            return false;
        }
    }

    return true;
}

/**
 * @brief this functions get all the data we need from prcess
 *
 * @param[in] status_buffer       contains the data from /proc/<pid>/status
 * @param[in] pid                 pid of the desired process
 * @param[in] desired_docker_pid  if we want to check proccess only against docker namespace pid
 * desired_docker_pid will be initialized with the docker pid
 *
 * @returns true for success, else false
*/
static bool get_data(char *status_buffer, pid_t pid, pid_t desired_docker_pid)
{
    int bytes;
    char *container_id;
    bool container_exists;
    pid_t ppid;
    char *runner = status_buffer;
    pid_t docker_pid;
    pid_t docker_ppid;
    int euid;
    static char cmd_line[MAX_CMDLINE_LEN];
    static char container_id_buffer[MAX_CONTINER_ID_LEN];
    static char buffer[MAX_BUFFER_SIZE];
    static char path[PATH_MAX];

    bytes = snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    if (bytes < 0 || bytes == sizeof(path)) {
        printf("error parsing cgroup\n");
    }

    if (!read_file(path, buffer, sizeof(buffer))) {
        printf("error reading file\n");
        return false;
    }

    container_id = strstr(buffer, "docker/");
    container_exists = (container_id != NULL);

    //ppid
    ppid = get_field(runner, "PPid:", sizeof("PPid:"), 1, NUMERIC);

    euid = get_field(runner, "Uid:", sizeof("Uid:"), 3, NUMERIC);

    if (!container_id) {
        container_id_buffer[0] = '\0';

    } else {
        //assuming the only namespace we are interested in is docker
        container_id += sizeof("docker/") - 1;
        bytes = sscanf(container_id, "%[^\n]", container_id_buffer); //read all characters until \n or EOF

        docker_pid = get_field(runner, "NSpid:", sizeof("NSpid:"), 2, NUMERIC);
        if (pid == -1) {
            printf ("get_field failed\n");
            return false;
        }

        //this is a special case, when we check if the namespace pid is
        //equal to the desired pid
        if (desired_docker_pid != 0 && desired_docker_pid != docker_pid) {
            return false;
        }

        // 1 is the first proccess, the parent is outside the container
        if (pid != 1) {
            bytes = snprintf(path, sizeof(path), "/proc/%d/status", ppid);
            if (bytes < 0 || bytes == sizeof(path)) {
                printf("error parsing %d status\n", ppid);
                return false;
            }

            if (!read_file(path, buffer, sizeof(buffer))) {
                printf("error parsing %d status\n", ppid);
                return false;
            }

            docker_ppid = get_field(buffer, "NSpid:", sizeof("NSpid:"), 2, NUMERIC);
            if (ppid == -1) {
                printf("get field failed\n");
                return -1;
            }
        }
    }

    if (!get_cmdline(cmd_line, sizeof(cmd_line), path, sizeof(path), pid)) {
        printf("coudn't get cmdline\n");
        return false;
    }

    if (!get_sha256(pid, buffer, sizeof(buffer), path, sizeof(path))) {
        printf("couln't get sha256\n");
        return false;
    }

    //formated print
    printf("%d\t%d\t%d\t%s\t%s\t%.*s\t%.*s\n",
            euid,
            container_exists ? docker_pid : pid,
            container_exists ? docker_ppid : ppid,
            get_starttime(pid, path, sizeof(path), buffer, sizeof(buffer)),
            sha256_current,
            12, //comaptible with docker ps
            container_exists ? container_id_buffer : "None",
            30, //must be cut so we can see each process in line
            cmd_line);

     return true;
}

static int grep_single_processes(char *pid, pid_t desired_docker_pid) {
    int bytes;
    static char path_status[PATH_MAX];
    static char status_buffer[MAX_BUFFER_SIZE];
    int cur_pid;
    char status;

    if (!is_numeric_str(pid)) {
        return -1;
    }

    bytes = snprintf(path_status, sizeof(path_status), "/proc/%s/status", pid);
    if (bytes < 0 || bytes == sizeof(path_status)) {
        printf("error parsing status for %s\n", pid);
        return -1;
    }

    if (!read_file(path_status, status_buffer, sizeof(status_buffer))) {
        printf("error reading proc\n");
        return -1;
    }

    //print only active processes Z - zombie, X - killed (man proc)
    status = get_field(status_buffer, "State:", sizeof("State:"), 1, ALPHA);
    if (status == -1 || status == 'Z' || status == 'X') {
        return -1;
    }

    cur_pid = atoi(pid);

    if (!get_data(status_buffer, cur_pid, desired_docker_pid)) {
        return -1;
    }

    return 0;
}

/**
 * @brief this functions gets all pids which equal to "pid" (containers included)
 * it will look into their processes and will try to extract their NSpid
 * there might be more than one answer
 *
 * @param[in] pid the process to be found
 *
 * @returns 0 for success
*/
static int standalone_ps(char *pid)
{
    DIR *dockers_dir;
    struct dirent *entry;
    int bytes;
    static char path[PATH_MAX];
    static char buffer[MAX_BUFFER_SIZE];
    char *token;

    //try to find pid in the host
    grep_single_processes(pid, 0);

    //if in standalone mode we need to search in all the dockers namespaces
    dockers_dir = opendir("/sys/fs/cgroup/devices/docker");
    while((entry = readdir(dockers_dir))) {
        if (entry->d_type != DT_DIR ||
            strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        bytes = snprintf(path, sizeof(path), "/sys/fs/cgroup/devices/docker/%s/tasks", entry->d_name);
        if (bytes < 0 || bytes == sizeof(path)) {
            printf("error snprintf %s\n", pid);
            continue;
        }

        if (!read_file(path, buffer, sizeof(buffer))) {
            printf("couln't read docker file\n");
            continue;
        }

        token = strtok(buffer, "\n");
        while (token) {
            grep_single_processes(token, atoi(pid));
            token = strtok(NULL, "\n");
        }
    }
    closedir(dockers_dir);
    return 0;
}

/**
 * @brief loop over all processes in /prod evntually prints process data
*/
static void grep_all_processes()
{
    DIR *proc;
    struct dirent *entry;

    //I extract pid from status using %d (man proc)
    STATIC_ASSERT(sizeof(pid_t) <= sizeof(int));

    proc = opendir("/proc");
    if (!proc) {
        printf("couldn't open proc\n");
        return;
    }

    while((entry = readdir(proc))) {
        if (grep_single_processes(entry->d_name, 0) == -1) {
            continue;
        }
    }
    closedir(proc);
}

int main(int argc, char *argv[])
{
    int opt;

    printf("EUID\tPID\tPPID\tSTARTTIME\t\t\tSHA256\t\t\t\t\t\t\t\t\tCONTAINER_ID\tCMDLINE\n");

    if (argc == 1) {
        grep_all_processes();
    } else {
        while ((opt = getopt(argc, argv, "p:")) != -1) {
            switch (opt) {
            case 'p':
                return standalone_ps(optarg);
                break;
            default:
                fprintf(stderr, "usage: %s [-p] <pid>",
                        argv[0]);
                return -1;
            }
        }
    }
    return 0;
}