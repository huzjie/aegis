"""Built-in shield profiles (ready-to-use policy dicts)."""

from aegis.policy.types import (
    Enforcement, FileRule, NetworkRule, Policy, SpawnRule, SyscallRule, Target,
)

NETWORK_ONLY = Policy(
    name="network-only",
    description="Block all outbound network except loopback and private ranges.",
    target=Target(process="*"),
    network=NetworkRule(deny=["*"], allow=["127.0.0.0/8", "10.0.0.0/8",
                                            "172.16.0.0/12", "192.168.0.0/16"]),
    enforcement=Enforcement(backend="nftables"),
)

FILESYSTEM_LOCKDOWN = Policy(
    name="filesystem-lockdown",
    description="Read-only filesystem except /tmp; block writes to /etc and /var/log.",
    target=Target(process="*"),
    files=FileRule(deny_write=["/etc/**", "/var/log/**", "/usr/**", "/bin/**"],
                   allow=["/tmp/**"]),
    enforcement=Enforcement(backend="apparmor"),
)

NO_SPAWN = Policy(
    name="no-spawn",
    description="Forbid the process from spawning child processes.",
    target=Target(process="*"),
    spawn=SpawnRule(deny=["*"]),
    syscalls=SyscallRule(deny=["execve", "execveat", "fork", "vfork", "clone",
                                "clone3"]),
    enforcement=Enforcement(backend="seccomp"),
)

FULL_LOCKDOWN = Policy(
    name="full-lockdown",
    description="Temporary full lockdown: no network, no spawn, read-only FS.",
    target=Target(process="*"),
    network=NetworkRule(deny=["*"], allow=["127.0.0.0/8"]),
    syscalls=SyscallRule(deny=["execve", "execveat", "fork", "vfork", "clone",
                                "clone3", "connect", "socket"]),
    files=FileRule(deny_write=["/etc/**", "/var/**", "/usr/**", "/bin/**"]),
    spawn=SpawnRule(deny=["*"]),
    enforcement=Enforcement(backend="auto", mode="enforce", duration="7d"),
)

BUILTIN_PROFILES = {
    "network-only": NETWORK_ONLY,
    "filesystem-lockdown": FILESYSTEM_LOCKDOWN,
    "no-spawn": NO_SPAWN,
    "full-lockdown": FULL_LOCKDOWN,
}


def builtin(name: str) -> Policy:
    if name not in BUILTIN_PROFILES:
        raise KeyError(f"unknown builtin profile {name!r}; "
                       f"available: {sorted(BUILTIN_PROFILES)}")
    return BUILTIN_PROFILES[name]


def builtin_names() -> list:
    return sorted(BUILTIN_PROFILES)
