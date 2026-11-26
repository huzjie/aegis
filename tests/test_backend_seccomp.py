import unittest

from aegis.backend.seccomp import SeccompBackend, build_denylist_filter


class TestBuildDenylistFilter(unittest.TestCase):
    def test_arch_check_first(self):
        insns = build_denylist_filter([59])
        # first insn loads arch, second checks x86_64, then per-syscall pairs
        self.assertGreaterEqual(len(insns), 4)

    def test_sorted_unique(self):
        insns = build_denylist_filter([59, 57, 59])
        # arch ld + arch jeq + arch-mismatch kill + 2 syscalls * 3 + allow
        self.assertEqual(len(insns), 3 + 2 * 3 + 1)


class TestSeccompBackend(unittest.TestCase):
    def test_compile_deny(self):
        ir = {"name": "t", "syscalls": {"deny": ["execve", "fork"]}}
        art = SeccompBackend().compile(ir)
        self.assertEqual(art.kind, "bpf")
        self.assertIn(59, art.meta["syscall_numbers"])
        self.assertIn(57, art.meta["syscall_numbers"])

    def test_compile_group_alias(self):
        ir = {"name": "t", "syscalls": {"deny": ["spawn"]}}
        art = SeccompBackend().compile(ir)
        self.assertIn(59, art.meta["syscall_numbers"])  # execve
        self.assertIn(57, art.meta["syscall_numbers"])  # fork

    def test_unknown_syscall_unresolved(self):
        ir = {"name": "t", "syscalls": {"deny": ["not-a-syscall"]}}
        art = SeccompBackend().compile(ir)
        self.assertIn("not-a-syscall", art.meta["unresolved"])


if __name__ == "__main__":
    unittest.main()
