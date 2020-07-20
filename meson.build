project('ps_dockers', 'c')
ps_docker_cflags = ['-Wextra', '-Wno-unused-parameter', '-Wall','-Werror', '-D_GNU_SOURCE']
ps_docker_includes = include_directories('include')
cc = meson.get_compiler('c')

srcs = [
    'parser.c',
    'ps_docker.c',
    'exec_lib.c',
    'mbuf.c'
]

ps_docker = executable('ps_docker',
                        srcs,
                        c_args: ps_docker_cflags,
                        include_directories: ps_docker_includes)