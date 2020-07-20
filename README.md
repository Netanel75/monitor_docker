# monitor_docker
create ps which will also include dockers.
The ps should be implemented based on the host point of view.

For each running process the tool will output:
- euid (effective user id)
- pid (process id)
- ppid (parent process id)
- Command line arguments
- Process start time (in human readable form)
- sha256 hash of the process executable
- container_id (if running inside a docker container)
The data which I use in this assignment is mostly based of /proc file system.

# Notes
if the process is running in container, the command will show the ​ namespace​ pid
and the ​ namespace​ ppid of the process.
ps will print only active processes, meaning it won’t print zombie or killed.-

when using ps -p <pid>, ps will try to find the pid in the host and in the dockers
namespace, it will print all the findings.
I used mostly static allocated buffers to limit the memory used, and to speed up
runtime (the files are small).
  
# Build system
I used meson build system: https://mesonbuild.com/
