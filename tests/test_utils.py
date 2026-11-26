import unittest

from aegis.utils.fs import ensure_dir, write_text
from aegis.utils.hashing import sha256_hex, stable_hash
from aegis.utils.json_util import dumps, loads
from aegis.utils.net import ip_in_cidr, parse_cidr
from aegis.utils.rng import DeterministicRNG
from aegis.utils.text import normalize, slugify, tokenize_cn
from aegis.utils.time_util import format_duration, parse_duration
import tempfile, os


class TestHashing(unittest.TestCase):
    def test_stable(self):
        self.assertEqual(stable_hash("foo"), stable_hash("foo"))
        self.assertNotEqual(stable_hash("foo"), stable_hash("bar"))

    def test_sha256(self):
        self.assertEqual(len(sha256_hex("x")), 64)


class TestRng(unittest.TestCase):
    def test_deterministic(self):
        a, b = DeterministicRNG("k"), DeterministicRNG("k")
        self.assertEqual([a.randint(1, 100) for _ in range(10)],
                         [b.randint(1, 100) for _ in range(10)])

    def test_coin(self):
        self.assertIn(DeterministicRNG("k").coin(), (True, False))


class TestText(unittest.TestCase):
    def test_slugify(self):
        self.assertEqual(slugify("Hello, World!"), "hello-world")

    def test_tokenize_cn(self):
        toks = tokenize_cn("\u5b89\u5168\u9632\u62a4")  # 安全防护
        self.assertIn("\u5b89\u5168", toks)

    def test_normalize(self):
        self.assertEqual(normalize("  a   b  "), "a b")


class TestNet(unittest.TestCase):
    def test_ip_in_cidr(self):
        self.assertTrue(ip_in_cidr("10.0.0.5", "10.0.0.0/8"))
        self.assertFalse(ip_in_cidr("11.0.0.5", "10.0.0.0/8"))

    def test_parse_cidr(self):
        self.assertEqual(str(parse_cidr("10.0.0.0/8")), "10.0.0.0/8")


class TestTimeUtil(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_duration("7d"), 604800)
        self.assertEqual(parse_duration("4h"), 14400)
        self.assertEqual(parse_duration("30s"), 30)

    def test_format(self):
        self.assertEqual(format_duration(604800), "1w")
        self.assertEqual(format_duration(86400), "1d")

    def test_invalid(self):
        with self.assertRaises(ValueError):
            parse_duration("abc")


class TestJsonUtil(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(loads(dumps({"b": 1, "a": 2})), {"a": 2, "b": 1})


class TestFs(unittest.TestCase):
    def test_write_and_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = write_text(os.path.join(d, "sub", "f.txt"), "hello")
            self.assertTrue(os.path.exists(p))
            ensure_dir(os.path.join(d, "x"))
            self.assertTrue(os.path.isdir(os.path.join(d, "x")))


if __name__ == "__main__":
    unittest.main()
