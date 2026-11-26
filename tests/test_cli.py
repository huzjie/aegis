import unittest

from aegis.cli import main


class TestCLI(unittest.TestCase):
    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_doctor(self):
        self.assertEqual(main(["doctor"]), 0)

    def test_list(self):
        self.assertEqual(main(["list"]), 0)

    def test_gen(self):
        self.assertEqual(main(["gen", "block outbound dns"]), 0)

    def test_signatures(self):
        self.assertEqual(main(["signatures"]), 0)

    def test_diff(self):
        self.assertEqual(main(["diff", "--old", "config.example.yaml",
                               "--new", "config/policies/no-spawn.yaml"]), 0)

    def test_compile_policy(self):
        self.assertEqual(main(["compile", "--policy",
                               "config/policies/log4shell-shield.yaml"]), 0)

    def test_apply_audit(self):
        self.assertEqual(main(["apply", "--policy",
                               "config/policies/network-isolate.yaml",
                               "--backend", "audit"]), 0)

    def test_scan(self):
        self.assertEqual(main(["scan", "--cmdline", "java",
                               "--argv", "java", "${jndi:ldap://x}"]), 0)


if __name__ == "__main__":
    unittest.main()
