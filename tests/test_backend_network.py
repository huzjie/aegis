import unittest

from aegis.backend.iptables import IptablesBackend
from aegis.backend.nftables import NftablesBackend


class TestNftables(unittest.TestCase):
    def test_compile_deny_cidr(self):
        ir = {"name": "t", "network": {"deny": ["10.9.9.0/24"]}}
        art = NftablesBackend().compile(ir)
        self.assertIn("10.9.9.0/24", art.content)
        self.assertIn("drop", art.content)

    def test_compile_deny_all(self):
        ir = {"name": "t", "network": {"deny": ["*"]}}
        art = NftablesBackend().compile(ir)
        self.assertIn("drop", art.content)

    def test_compile_ports(self):
        ir = {"name": "t", "network": {"ports_deny": [53], "ports_allow": [443]}}
        art = NftablesBackend().compile(ir)
        self.assertIn("dport 53", art.content)
        self.assertIn("dport 443", art.content)


class TestIptables(unittest.TestCase):
    def test_compile_deny(self):
        ir = {"name": "t", "network": {"deny": ["10.9.9.0/24"]}}
        art = IptablesBackend().compile(ir)
        self.assertIn("10.9.9.0/24", art.content)
        self.assertIn("-j DROP", art.content)


if __name__ == "__main__":
    unittest.main()
