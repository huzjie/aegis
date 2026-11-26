import unittest

from aegis.backend.apparmor import AppArmorBackend
from aegis.backend.audit import AuditBackend
from aegis.backend.factory import BackendFactory, compile_policy
from aegis.errors import BackendError


class TestAppArmor(unittest.TestCase):
    def test_compile_files(self):
        ir = {"name": "t", "files": {"deny_write": ["/etc/**"],
                                     "allow": ["/tmp/**"]}}
        art = AppArmorBackend().compile(ir)
        self.assertIn("profile aegis/t", art.content)
        self.assertIn("deny w /etc/**", art.content)


class TestAudit(unittest.TestCase):
    def test_compile_plan(self):
        ir = {"name": "t", "network": {"deny": ["*"]},
              "enforcement": {"mode": "enforce", "duration": "7d"}}
        art = AuditBackend().compile(ir)
        self.assertIsInstance(art.content, list)
        self.assertTrue(any("network" in d for d in art.content))
        self.assertTrue(any("7d" in d for d in art.content))

    def test_apply_is_dry_run(self):
        art = AuditBackend().compile({"name": "t", "network": {"deny": ["*"]}})
        status = AuditBackend().apply(art)
        self.assertTrue(status["applied"])
        self.assertEqual(status["mode"], "dry-run")


class TestFactory(unittest.TestCase):
    def test_available(self):
        avail = BackendFactory.available()
        for b in ("seccomp", "nftables", "iptables", "apparmor", "ebpf", "audit"):
            self.assertIn(b, avail)

    def test_unknown_backend(self):
        with self.assertRaises(BackendError):
            BackendFactory.create("bogus")

    def test_compile_policy_auto(self):
        ir = {"name": "t", "network": {"deny": ["*"]},
              "syscalls": {"deny": ["execve"]}}
        arts = compile_policy(ir)
        self.assertIn("nftables", arts)
        self.assertIn("seccomp", arts)
        self.assertIn("audit", arts)


if __name__ == "__main__":
    unittest.main()
