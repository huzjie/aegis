"""Backend registry and auto-dispatch compilation."""

from __future__ import annotations

from aegis.backend.base import Artifact
from aegis.errors import BackendError

_REGISTRY = {}


def register(cls):
    _REGISTRY[cls.name] = cls
    return cls


class BackendFactory:
    @staticmethod
    def create(name: str):
        from aegis.backend import audit, seccomp, ebpf, apparmor, nftables, iptables  # noqa: F401
        if name not in _REGISTRY:
            raise BackendError(f"unknown backend {name!r}; "
                               f"available: {sorted(_REGISTRY)}")
        return _REGISTRY[name]()

    @staticmethod
    def available() -> list:
        from aegis.backend import audit, seccomp, ebpf, apparmor, nftables, iptables  # noqa: F401
        return sorted(_REGISTRY)


# Category -> preferred backend (used by "auto")
CATEGORY_BACKEND = {
    "syscalls": "seccomp",
    "spawn": "seccomp",
    "network": "nftables",
    "files": "apparmor",
}


def compile_policy(ir: dict, policy: dict | None = None) -> dict:
    """Compile each rule category to its preferred backend; returns name->Artifact.

    ``auto`` backend dispatches per-category so a single policy may fan out to
    seccomp (syscalls/spawn) + nftables (network) + apparmor (files).
    """
    factory = BackendFactory
    artifacts = {}
    categories = [c for c in ("network", "syscalls", "files", "spawn")
                  if ir.get(c) is not None]
    if not categories:
        raise BackendError("policy has no compilable rule categories")
    for cat in categories:
        name = CATEGORY_BACKEND[cat]
        backend = factory.create(name)
        artifacts[name] = backend.compile(ir, policy)
    # always attach an audit plan as a human-readable dry-run view
    audit_backend = factory.create("audit")
    artifacts["audit"] = audit_backend.compile(ir, policy)
    return artifacts
