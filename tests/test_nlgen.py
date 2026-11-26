import unittest

from aegis.nlgen.compiler import compile_intent
from aegis.nlgen.keywords import ACTION_BLOCK, ACTION_ALLOW
from aegis.nlgen.mock_llm import MockLLM
from aegis.nlgen.parser import NlParser


class TestParser(unittest.TestCase):
    def setUp(self):
        self.p = NlParser()

    def test_block_network(self):
        intent = self.p.parse("block outbound dns")
        self.assertEqual(intent["scope"], "network")
        self.assertEqual(intent["action"], "block")

    def test_ip_not_misread_as_port(self):
        intent = self.p.parse("block outbound dns except to 10.0.0.53")
        self.assertEqual(intent["allow"], ["10.0.0.53"])
        # octets 10/0/0 must not leak into ports
        self.assertNotIn(10, intent["ports_deny"])
        self.assertNotIn(0, intent["ports_deny"])

    def test_syscalls_scope(self):
        intent = self.p.parse("deny execve and fork")
        self.assertEqual(intent["scope"], "syscalls")

    def test_files_scope(self):
        intent = self.p.parse("make the filesystem read-only")
        self.assertEqual(intent["scope"], "files")

    def test_spawn_scope(self):
        intent = self.p.parse("forbid child processes")
        self.assertEqual(intent["scope"], "spawn")

    def test_chinese(self):
        intent = self.p.parse("\u7981\u6b62\u51fa\u7ad9\u6d41\u91cf")  # 禁止出站流量
        self.assertEqual(intent["scope"], "network")


class TestCompiler(unittest.TestCase):
    def test_compile_network(self):
        policy = compile_intent({"scope": "network", "action": "block",
                                 "deny": ["*"], "allow": ["127.0.0.0/8"]})
        self.assertEqual(policy["rules"][0]["type"], "network")
        self.assertEqual(policy["enforcement"]["mode"], "enforce")

    def test_compile_syscalls(self):
        policy = compile_intent({"scope": "syscalls", "action": "block",
                                 "syscalls": ["execve"]})
        self.assertEqual(policy["rules"][0]["deny"], ["execve"])

    def test_compile_files(self):
        policy = compile_intent({"scope": "files", "action": "block",
                                 "files": {"deny_write": ["/etc/**"]}})
        self.assertEqual(policy["rules"][0]["type"], "files")

    def test_compile_spawn(self):
        policy = compile_intent({"scope": "spawn", "action": "block", "spawn": True})
        self.assertEqual(policy["rules"][0]["deny"], ["*"])


class TestKeywords(unittest.TestCase):
    def test_disjoint(self):
        self.assertTrue(ACTION_BLOCK.isdisjoint(ACTION_ALLOW))


class TestMockLLM(unittest.TestCase):
    def test_deterministic(self):
        a = MockLLM().generate("p")
        b = MockLLM().generate("p")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
