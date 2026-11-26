import unittest

from aegis.errors import PolicyError
from aegis.policy.compiler import PolicyCompiler
from aegis.policy.defaults import builtin, builtin_names, BUILTIN_PROFILES
from aegis.policy.diff import diff_policies
from aegis.policy.loader import load_policy
from aegis.policy.schema import structural_errors
from aegis.policy.types import NetworkRule, Policy, Target
from aegis.policy.validator import validate_policy


class TestSchema(unittest.TestCase):
    def test_missing_name(self):
        errs = structural_errors({"rules": []})
        self.assertTrue(any("name" in e for e in errs))

    def test_bad_rule_type(self):
        errs = structural_errors({"name": "x", "rules": [{"type": "bogus"}]})
        self.assertTrue(any("bogus" in e or "type" in e for e in errs))

    def test_valid(self):
        self.assertEqual(structural_errors(
            {"name": "x", "rules": [{"type": "network", "deny": ["*"]}]}), [])


class TestValidator(unittest.TestCase):
    def test_empty_rules(self):
        with self.assertRaises(PolicyError):
            validate_policy({"name": "x", "rules": []})

    def test_bad_mode(self):
        with self.assertRaises(PolicyError):
            validate_policy({"name": "x", "rules": [{"type": "network", "deny": ["*"]}],
                             "enforcement": {"mode": "bogus"}})

    def test_network_needs_deny_or_allow(self):
        with self.assertRaises(PolicyError):
            validate_policy({"name": "x", "rules": [{"type": "network"}]})


class TestLoader(unittest.TestCase):
    def test_load_dict(self):
        p = load_policy({"name": "x", "rules": [{"type": "network", "deny": ["*"]}]})
        self.assertEqual(p["name"], "x")

    def test_load_yaml_file(self):
        p = load_policy("config/policies/no-spawn.yaml")
        self.assertEqual(p["name"], "no-spawn")

    def test_load_missing(self):
        from aegis.errors import ConfigError
        with self.assertRaises(ConfigError):
            load_policy("does-not-exist.yaml")


class TestCompiler(unittest.TestCase):
    def test_compile_typed(self):
        c = PolicyCompiler()
        typed = c.compile({"name": "x", "rules": [
            {"type": "network", "deny": ["*"], "ports_deny": [53]}]})
        self.assertIsInstance(typed, Policy)
        self.assertIsNotNone(typed.network)
        self.assertEqual(typed.network.ports_deny, [53])

    def test_to_ir(self):
        c = PolicyCompiler()
        typed = c.compile({"name": "x", "rules": [
            {"type": "syscalls", "deny": ["execve"]}]})
        ir = c.to_ir(typed)
        self.assertEqual(ir["syscalls"]["deny"], ["execve"])

    def test_rule_categories(self):
        c = PolicyCompiler()
        typed = c.compile({"name": "x", "rules": [
            {"type": "network", "deny": ["*"]},
            {"type": "spawn", "deny": ["*"]}]})
        self.assertEqual(sorted(typed.rule_categories()), ["network", "spawn"])


class TestDefaults(unittest.TestCase):
    def test_builtin_names(self):
        self.assertEqual(builtin_names(), sorted(BUILTIN_PROFILES))

    def test_builtin(self):
        self.assertEqual(builtin("full-lockdown").name, "full-lockdown")

    def test_builtin_unknown(self):
        with self.assertRaises(KeyError):
            builtin("nope")


class TestDiff(unittest.TestCase):
    def test_diff_network(self):
        a = {"name": "a", "rules": [{"type": "network", "deny": ["*"]}]}
        b = {"name": "a", "rules": [{"type": "network", "deny": ["*"],
                                     "allow": ["10.0.0.0/8"]}]}
        out = diff_policies(a, b)
        self.assertEqual(len(out), 1)
        self.assertIn("allow", out[0])

    def test_diff_empty(self):
        a = {"name": "a", "rules": [{"type": "network", "deny": ["*"]}]}
        self.assertEqual(diff_policies(a, a), [])


if __name__ == "__main__":
    unittest.main()
