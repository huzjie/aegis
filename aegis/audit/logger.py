"""In-memory audit logger with JSONL / SQLite sinks."""

from __future__ import annotations

import json
import os
import sqlite3

from aegis.audit.events import AuditEvent


class AuditLogger:
    def __init__(self):
        self._events: list[AuditEvent] = []

    def log(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def clear(self):
        self._events.clear()

    def to_jsonl(self, path: str) -> str:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            for e in self._events:
                f.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
        return path

    def to_sqlite(self, path: str) -> str:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        conn = sqlite3.connect(path)
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, action TEXT, shield TEXT, decision TEXT,
            target TEXT, detail TEXT, result TEXT)""")
        for e in self._events:
            conn.execute(
                "INSERT INTO audit_events(timestamp,action,shield,decision,target,detail,result) "
                "VALUES(?,?,?,?,?,?,?)",
                (e.timestamp, e.action, e.shield, e.decision, e.target, e.detail, e.result))
        conn.commit()
        conn.close()
        return path
