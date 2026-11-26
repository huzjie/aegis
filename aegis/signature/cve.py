"""Signature data model and knowledge-base loading."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db")


@dataclass
class Signature:
    id: str
    name: str
    cve: str
    description: str = ""
    severity: str = "medium"
    process: list[str] = field(default_factory=list)
    argv_patterns: list[str] = field(default_factory=list)
    cmdline_patterns: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    kernel_lt: str | None = None
    recommended_shield: dict = field(default_factory=dict)

    def matches(self, snapshot: dict) -> dict:
        """Return a dict of matched indicator -> evidence, or {} if no match."""
        hits = {}
        proc = (snapshot.get("process") or "").lower()
        cmdline = (snapshot.get("cmdline") or "").lower()
        argv = [str(a).lower() for a in (snapshot.get("argv") or [])]
        argv_text = " ".join(argv)

        if self.process:
            if proc in self.process or any(p in proc for p in self.process):
                hits["process"] = proc
        for pat in self.argv_patterns:
            if re.search(pat, argv_text, re.IGNORECASE):
                hits.setdefault("argv", []).append(pat)
        for pat in self.cmdline_patterns:
            if re.search(pat, cmdline, re.IGNORECASE):
                hits.setdefault("cmdline", []).append(pat)
        # ports: match if snapshot lists any observed outbound port
        snap_ports = snapshot.get("ports") or snapshot.get("dst_ports") or []
        if self.ports and snap_ports:
            overlap = sorted(set(self.ports) & set(snap_ports))
            if overlap:
                hits["ports"] = overlap
        if self.kernel_lt:
            kv = snapshot.get("kernel") or ""
            if kv and _lt_version(kv, self.kernel_lt):
                hits["kernel"] = kv
        return hits


def _lt_version(a: str, b: str) -> bool:
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)][:3]
    return parts(a) < parts(b)


def load_signatures() -> list[Signature]:
    """Load all signature YAML files from the db/ directory."""
    from aegis.policy.loader import _parse_yaml
    sigs = []
    if not os.path.isdir(_DB_DIR):
        return sigs
    for fn in sorted(os.listdir(_DB_DIR)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(_DB_DIR, fn), "r", encoding="utf-8") as f:
            raw = _parse_yaml(f.read())
        if not raw.get("id"):
            continue
        sigs.append(Signature(
            id=raw["id"], name=raw.get("name", raw["id"]),
            cve=raw.get("cve", ""), description=raw.get("description", ""),
            severity=raw.get("severity", "medium"),
            process=list(raw.get("process") or []),
            argv_patterns=list(raw.get("argv_patterns") or []),
            cmdline_patterns=list(raw.get("cmdline_patterns") or []),
            ports=[int(p) for p in (raw.get("ports") or [])],
            kernel_lt=raw.get("kernel_lt"),
            recommended_shield=raw.get("recommended_shield") or {},
        ))
    return sigs
