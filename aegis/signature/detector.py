"""SignatureDetector: scan snapshots, produce ranked Detections."""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.signature.cve import load_signatures

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Detection:
    signature_id: str
    cve: str
    name: str
    severity: str
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.0

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.name} ({self.cve}) " \
               f"confidence={self.confidence:.2f}"


class SignatureDetector:
    def __init__(self, signatures: list | None = None):
        self._sigs = signatures if signatures is not None else load_signatures()

    @property
    def signatures(self):
        return list(self._sigs)

    def scan(self, snapshot: dict) -> list[Detection]:
        dets = []
        for sig in self._sigs:
            hits = sig.matches(snapshot)
            if not hits:
                continue
            # confidence: 1.0 if a hard indicator (argv/cmdline/port) fired,
            # else scaled by how many soft indicators matched.
            hard = bool(hits.get("argv") or hits.get("cmdline") or hits.get("ports"))
            conf = 0.95 if hard else 0.5 + 0.1 * len(hits)
            dets.append(Detection(
                signature_id=sig.id, cve=sig.cve, name=sig.name,
                severity=sig.severity, evidence=hits, confidence=min(conf, 1.0),
            ))
        dets.sort(key=lambda d: (_SEVERITY_RANK.get(d.severity, 0), d.confidence),
                  reverse=True)
        return dets
