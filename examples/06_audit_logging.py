import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：把编译/扫描动作写入审计日志（JSONL + SQLite）。"""
from aegis.audit.events import AuditEvent
from aegis.audit.logger import AuditLogger
from aegis.api import Aegis

engine = Aegis()
logger = AuditLogger()

policy = engine.load("config.example.yaml")
logger.log(AuditEvent(action="compile", shield=policy["name"],
                      decision="compiled", target="java"))

dets = engine.scan({"argv": ["${jndi:ldap://x}"]})
for d in dets:
    logger.log(AuditEvent(action="scan", shield="signature:" + d.signature_id,
                          decision=d.severity, target=d.name))

logger.to_jsonl("artifacts/audit.jsonl")
logger.to_sqlite("artifacts/audit.db")
print("已写入 artifacts/audit.jsonl 与 artifacts/audit.db，共", len(logger.events), "条")
