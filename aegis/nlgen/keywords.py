"""Intent lexicon used by the deterministic NL parser."""

ACTION_BLOCK = {"block", "deny", "forbid", "禁止", "阻止", "拦截", "封禁", "屏蔽"}
ACTION_ALLOW = {"allow", "permit", "except", "whitelist", "放行", "允许", "白名单", "除了"}

SCOPE_NETWORK = {"network", "traffic", "outbound", "inbound", "dns", "http", "https",
                 "网络", "出站", "入站", "流量"}
SCOPE_SYSCALL = {"syscall", "syscalls", "exec", "execve", "fork", "clone", "系统调用"}
SCOPE_FILES = {"file", "files", "filesystem", "readonly", "write", "文件", "只读", "写"}
SCOPE_SPAWN = {"spawn", "child", "process", "子进程", "进程"}

# dns / common service -> port
PORT_HINTS = {
    "dns": 53, "http": 80, "https": 443, "ssh": 22, "telnet": 23,
    "ldap": 389, "ldaps": 636, "rmi": 1099, "mysql": 3306, "postgres": 5432,
    "redis": 6379, "kafka": 9092, "smb": 445, "ftp": 21, "smtp": 25,
}

SYSNAME_HINTS = {
    "exec": "execve", "execve": "execve", "fork": "fork", "vfork": "vfork",
    "clone": "clone", "connect": "connect", "socket": "socket", "open": "open",
    "write": "write", "unlink": "unlink",
}

_PRIVATE = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
