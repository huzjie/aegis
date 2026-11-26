"""Typed (dataclass) policy model shared across the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Target:
    process: str | None = None
    user: str | None = None
    pid: int | None = None
    container: str | None = None
    cgroup: str | None = None


@dataclass
class NetworkRule:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    ports_allow: list[int] = field(default_factory=list)
    ports_deny: list[int] = field(default_factory=list)


@dataclass
class SyscallRule:
    deny: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)


@dataclass
class FileRule:
    deny_read: list[str] = field(default_factory=list)
    deny_write: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)


@dataclass
class SpawnRule:
    deny: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)


@dataclass
class Enforcement:
    backend: str = "auto"          # auto | seccomp | ebpf | apparmor | nftables | audit
    fallback: list[str] = field(default_factory=lambda: ["seccomp", "nftables", "audit"])
    mode: str = "enforce"          # enforce | audit
    duration: str | None = None    # e.g. "7d" -> temporary shield


@dataclass
class Policy:
    name: str
    version: str = "1"
    description: str = ""
    target: Target = field(default_factory=Target)
    network: NetworkRule | None = None
    syscalls: SyscallRule | None = None
    files: FileRule | None = None
    spawn: SpawnRule | None = None
    enforcement: Enforcement = field(default_factory=Enforcement)
    metadata: dict[str, Any] = field(default_factory=dict)

    def rule_categories(self) -> list[str]:
        cats = []
        if self.network is not None:
            cats.append("network")
        if self.syscalls is not None:
            cats.append("syscalls")
        if self.files is not None:
            cats.append("files")
        if self.spawn is not None:
            cats.append("spawn")
        return cats
