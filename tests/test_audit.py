import os
import sqlite3
import tempfile
import unittest

from aegis.audit.events import AuditEvent
from aegis.audit.logger import AuditLogger


class TestAuditEvent(unittest.TestCase):
    def test_to_dict(self):
        e = AuditEvent(action="compile", shield="t", decision="deny")
        d = e.to_dict()
        self.assertEqual(d["action"], "compile")
        self.assertIn("timestamp", d)


class TestAuditLogger(unittest.TestCase):
    def test_log_and_jsonl(self):
        logger = AuditLogger()
        logger.log(AuditEvent(action="x", shield="s", decision="allow"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            logger.to_jsonl(path)
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 1)

    def test_log_and_sqlite(self):
        logger = AuditLogger()
        logger.log(AuditEvent(action="x", shield="s", decision="allow"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.db")
            logger.to_sqlite(path)
            conn = sqlite3.connect(path)
            n = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            conn.close()
            self.assertEqual(n, 1)

    def test_clear(self):
        logger = AuditLogger()
        logger.log(AuditEvent(action="x", shield="s", decision="allow"))
        logger.clear()
        self.assertEqual(logger.events, [])


if __name__ == "__main__":
    unittest.main()
