"""Backend abstract base and the Artifact container."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Artifact:
    """A concrete, applyable product of compiling a policy against a backend."""

    backend: str
    kind: str                       # "text" | "bpf" | "script" | "profile" | "plan"
    content: Any = None             # str, or list of bpf instructions, etc.
    files: dict[str, str] = field(default_factory=dict)  # filename -> text (ebpf)
    meta: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        if self.kind == "text" and isinstance(self.content, str):
            return f"{self.backend}: {len(self.content.splitlines())} lines"
        if self.kind == "bpf":
            return f"{self.backend}: {len(self.content or [])} bpf instructions"
        if self.kind == "plan":
            return f"{self.backend}: {len(self.content or [])} decisions"
        if self.files:
            return f"{self.backend}: {len(self.files)} files"
        return f"{self.backend}: {self.kind}"


class Backend:
    """Base class for enforcement backends."""

    name = "base"

    def supports(self, ir: dict) -> bool:
        """Return True if this backend can enforce at least one rule category."""
        return False

    def compile(self, ir: dict, policy: dict | None = None) -> Artifact:
        raise NotImplementedError

    def apply(self, artifact: Artifact) -> dict:
        """Best-effort apply; returns a status dict. Dry-run safe default."""
        return {"backend": self.name, "applied": False,
                "reason": "apply requires root on a Linux host (see docs)"}

    def remove(self, artifact: Artifact) -> dict:
        return {"backend": self.name, "removed": False,
                "reason": "remove requires root on a Linux host (see docs)"}
