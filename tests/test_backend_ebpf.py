import unittest

from aegis.backend.ebpf import EbpfBackend
from aegis.ebpf.generator import generate_ebpf_program, generate_loader, _ipv4_hex


class TestEbpfGenerator(unittest.TestCase):
    def test_generate_program_no_deny(self):
        src = generate_ebpf_program({"name": "t"})
        self.assertIn('SEC("tc")', src)
        self.assertIn("BPF_OK", src)

    def test_generate_program_deny(self):
        src = generate_ebpf_program({"name": "t", "network": {"deny": ["10.0.0.0/8"]}})
        self.assertIn("BPF_DROP", src)

    def test_ipv4_hex(self):
        self.assertEqual(_ipv4_hex("10.0.0.1"), "0a000001")

    def test_loader(self):
        loader = generate_loader({"name": "t"})
        self.assertIn("clang", loader)
        self.assertIn("tc", loader)


class TestEbpfBackend(unittest.TestCase):
    def test_compile_files(self):
        art = EbpfBackend().compile({"name": "t", "network": {"deny": ["*"]}})
        self.assertIn("t.bpf.c", art.files)
        self.assertIn("loader.sh", art.files)


if __name__ == "__main__":
    unittest.main()
