"""x86_64 syscall number table (subset used by seccomp deny-lists)."""

# name -> number on x86_64 (Linux). Common subset; extend as needed.
X86_64 = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
    "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
    "ioctl": 16, "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
    "access": 21, "pipe": 22, "select": 23, "sched_yield": 24, "mremap": 25,
    "dup": 32, "dup2": 33, "nanosleep": 35, "getpid": 39, "socket": 41,
    "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45, "sendmsg": 46,
    "recvmsg": 47, "shutdown": 48, "bind": 49, "listen": 50, "getsockname": 51,
    "setsockopt": 54, "getsockopt": 55, "clone": 56, "fork": 57, "vfork": 58,
    "execve": 59, "exit": 60, "wait4": 61, "kill": 62, "uname": 63,
    "fcntl": 72, "fsync": 74, "fdatasync": 75, "truncate": 76,
    "ftruncate": 77, "getdents": 78, "getcwd": 79, "chdir": 80, "rename": 82,
    "mkdir": 83, "rmdir": 84, "creat": 85, "link": 86, "unlink": 87,
    "symlink": 88, "readlink": 89, "chmod": 90, "fchmod": 91, "chown": 92,
    "umask": 95, "gettimeofday": 96, "getrlimit": 97, "getuid": 102,
    "getgid": 104, "setuid": 105, "setgid": 106, "ptrace": 101,
    "socketpair": 53, "setsid": 112, "setpgid": 109, "getppid": 110,
    "setrlimit": 160, "mount": 165, "umount2": 166, "ptrace": 101,
    "reboot": 169, "openat": 257, "mkdirat": 258, "mknodat": 259,
    "fchownat": 260, "futimesat": 261, "newfstatat": 262, "unlinkat": 263,
    "renameat": 264, "linkat": 265, "symlinkat": 266, "readlinkat": 267,
    "fchmodat": 268, "faccessat": 269, "pselect6": 270, "splice": 275,
    "tee": 276, "sync_file_range": 277, "vmsplice": 278, "utimensat": 280,
    "epoll_wait": 232, "epoll_ctl": 233, "timerfd_settime": 286,
    "eventfd2": 290, "fallocate": 285, "dup3": 292, "pipe2": 293,
    "inotify_init1": 294, "preadv": 295, "pwritev": 296, "accept4": 288,
    "recvmmsg": 299, "sendmmsg": 307, "prctl": 157, "seccomp": 317,
    "getrandom": 318, "memfd_create": 319, "bpf": 321, "execveat": 322,
    "userfaultfd": 323, "statx": 332, "io_uring_setup": 425,
    "io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428,
    "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
    "fspick": 433, "pidfd_open": 434, "clone3": 435, "close_range": 436,
    "openat2": 437, "pidfd_getfd": 438, "faccessat2": 439,
    "process_madvise": 440, "epoll_pwait2": 441, "mount_setattr": 442,
}

# alias groups
GROUPS = {
    "network": ["socket", "connect", "accept", "accept4", "bind", "listen",
                "sendto", "sendmsg", "recvfrom", "recvmsg", "socketpair",
                "getsockname", "shutdown", "setsockopt", "getsockopt"],
    "spawn": ["execve", "execveat", "fork", "vfork", "clone", "clone3"],
    "fs_write": ["open", "openat", "openat2", "creat", "write", "writev",
                 "pwrite64", "pwritev", "truncate", "ftruncate", "rename",
                 "renameat", "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir",
                 "chmod", "fchmod", "chown", "fchownat", "link", "linkat",
                 "symlink", "symlinkat", "mount", "umount2"],
}


def resolve_syscall(name: str) -> list:
    """Resolve a syscall name (or group alias) to a list of numbers."""
    name = name.strip()
    if name == "*":
        return []
    if name in GROUPS:
        return [X86_64[n] for n in GROUPS[name] if n in X86_64]
    if name in X86_64:
        return [X86_64[name]]
    # unknown syscall -> cannot map, return empty (validator/hint downstream)
    return []
