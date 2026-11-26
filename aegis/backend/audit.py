"""Audit / dry-run backend: never enforces, only explains decisions."""

from aegis.backend.base import Artifact, Backend
from aegis.backend.factory import register


@register
class AuditBackend(Backend):
    name = "audit"

    def supports(self, ir: dict) -> bool:
        return any(ir.get(c) for c in ("network", "syscalls", "files", "spawn"))

    def compile(self, ir: dict, policy: dict | None = None) -> Artifact:
        decisions = []
        t = ir.get("target", {}) or {}
        target_desc = " and ".join(f"{k}={v}" for k, v in t.items() if v) or "any process"
        if ir.get("network"):
            n = ir["network"]
            decisions.append(f"[network] on {target_desc}: "
                             f"deny {n.get('deny') or '()'} / allow {n.get('allow') or '()'}")
            if n.get("ports_deny"):
                decisions.append(f"[network] deny ports {n['ports_deny']}")
            if n.get("ports_allow"):
                decisions.append(f"[network] allow ports {n['ports_allow']}")
        if ir.get("syscalls"):
            s = ir["syscalls"]
            decisions.append(f"[syscalls] on {target_desc}: deny {s.get('deny') or '()'}")
        if ir.get("files"):
            f = ir["files"]
            if f.get("deny_write"):
                decisions.append(f"[files] deny write {f['deny_write']}")
            if f.get("deny_read"):
                decisions.append(f"[files] deny read {f['deny_read']}")
            if f.get("allow"):
                decisions.append(f"[files] allow {f['allow']}")
        if ir.get("spawn"):
            sp = ir["spawn"]
            decisions.append(f"[spawn] on {target_desc}: deny {sp.get('deny') or '()'}")
        mode = (ir.get("enforcement") or {}).get("mode", "enforce")
        duration = (ir.get("enforcement") or {}).get("duration")
        if duration:
            decisions.append(f"[meta] temporary shield, auto-remove after {duration}")
        decisions.append(f"[meta] mode={mode}")
        return Artifact(backend=self.name, kind="plan", content=decisions,
                        meta={"target": target_desc})

    def apply(self, artifact: Artifact) -> dict:
        return {"backend": self.name, "applied": True, "mode": "dry-run",
                "decisions": artifact.content}
