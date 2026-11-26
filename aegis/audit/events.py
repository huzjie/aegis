"""Audit event model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AuditEvent:
    action: str
    shield: str
    decision: str
    target: str = ""
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    result: str = "allow"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp, "action": self.action,
            "shield": self.shield, "decision": self.decision,
            "target": self.target, "detail": self.detail, "result": self.result,
        }
