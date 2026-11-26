"""Compile a raw policy dict into a typed Policy + normalized IR."""

from aegis.policy.loader import _coerce  # reuse coercion for inline lists
from aegis.policy.types import (
    Enforcement, FileRule, NetworkRule, Policy, SpawnRule, SyscallRule, Target,
)


def _list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, str):
        return [_coerce(x) for x in [v]]
    return [str(v)]


class PolicyCompiler:
    """Turns a raw policy dict into a typed :class:`Policy` and a flat IR."""

    def compile(self, policy: dict) -> Policy:
        from aegis.policy.validator import validate_policy
        validate_policy(policy)
        t = policy.get("target", {}) or {}
        target = Target(
            process=t.get("process"), user=t.get("user"), pid=t.get("pid"),
            container=t.get("container"), cgroup=t.get("cgroup"),
        )
        net = sysc = files = spawn = None
        for r in policy.get("rules", []):
            rt = r.get("type")
            if rt == "network":
                net = NetworkRule(
                    allow=_list(r.get("allow")), deny=_list(r.get("deny")),
                    ports_allow=[int(x) for x in _list(r.get("ports_allow"))],
                    ports_deny=[int(x) for x in _list(r.get("ports_deny"))],
                )
            elif rt == "syscalls":
                sysc = SyscallRule(deny=_list(r.get("deny")),
                                   allow=_list(r.get("allow")))
            elif rt == "files":
                files = FileRule(
                    deny_read=_list(r.get("deny_read")),
                    deny_write=_list(r.get("deny_write")),
                    allow=_list(r.get("allow")),
                )
            elif rt == "spawn":
                spawn = SpawnRule(deny=_list(r.get("deny")),
                                  allow=_list(r.get("allow")))
        e = policy.get("enforcement", {}) or {}
        enf = Enforcement(
            backend=e.get("backend", "auto"),
            fallback=_list(e.get("fallback")) or ["seccomp", "nftables", "audit"],
            mode=e.get("mode", "enforce"),
            duration=e.get("duration"),
        )
        return Policy(
            name=policy["name"],
            version=str(policy.get("version", "1")),
            description=policy.get("description", ""),
            target=target, network=net, syscalls=sysc, files=files, spawn=spawn,
            enforcement=enf, metadata=policy.get("metadata", {}) or {},
        )

    def to_ir(self, policy: Policy) -> dict:
        """Flatten a typed Policy into a backend-agnostic intermediate rep."""
        ir = {
            "name": policy.name,
            "version": policy.version,
            "description": policy.description,
            "target": {
                "process": policy.target.process,
                "user": policy.target.user,
                "pid": policy.target.pid,
                "container": policy.target.container,
                "cgroup": policy.target.cgroup,
            },
            "enforcement": {
                "backend": policy.enforcement.backend,
                "fallback": policy.enforcement.fallback,
                "mode": policy.enforcement.mode,
                "duration": policy.enforcement.duration,
            },
            "network": None, "syscalls": None, "files": None, "spawn": None,
        }
        if policy.network:
            ir["network"] = {
                "allow": policy.network.allow, "deny": policy.network.deny,
                "ports_allow": policy.network.ports_allow,
                "ports_deny": policy.network.ports_deny,
            }
        if policy.syscalls:
            ir["syscalls"] = {
                "allow": policy.syscalls.allow, "deny": policy.syscalls.deny,
            }
        if policy.files:
            ir["files"] = {
                "deny_read": policy.files.deny_read,
                "deny_write": policy.files.deny_write,
                "allow": policy.files.allow,
            }
        if policy.spawn:
            ir["spawn"] = {"allow": policy.spawn.allow, "deny": policy.spawn.deny}
        return ir
