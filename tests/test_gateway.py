import json
import threading
import unittest
from http.server import HTTPServer
from urllib.request import urlopen

from aegis.api import Aegis
from aegis.gateway.handlers import make_handler


class TestGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Aegis()
        cls.httpd = HTTPServer(("127.0.0.1", 0), make_handler(cls.engine))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _get(self, path):
        import urllib.error
        try:
            with urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def _post(self, path, body):
        req = json.dumps(body).encode("utf-8")
        import urllib.request
        r = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=req,
            headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_health(self):
        status, body = self._get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_profiles(self):
        status, body = self._get("/v1/shields")
        self.assertEqual(status, 200)
        self.assertIn("profiles", body)

    def test_signatures(self):
        status, body = self._get("/v1/signatures")
        self.assertEqual(status, 200)
        self.assertTrue(body["signatures"])

    def test_backends(self):
        status, body = self._get("/v1/backends")
        self.assertEqual(status, 200)
        self.assertIn("seccomp", body["backends"])

    def test_compile(self):
        status, body = self._post("/v1/compile", {
            "name": "t", "target": {"process": "*"},
            "rules": [{"type": "network", "deny": ["*"], "allow": ["127.0.0.0/8"]}]})
        self.assertEqual(status, 200)
        self.assertIn("nftables", body["backend"])

    def test_scan(self):
        status, body = self._post("/v1/scan", {
            "cmdline": "java", "argv": ["${jndi:ldap://x}"]})
        self.assertEqual(status, 200)
        self.assertTrue(body["detections"])

    def test_gen(self):
        status, body = self._post("/v1/gen", {"text": "block outbound dns"})
        self.assertEqual(status, 200)
        self.assertIn("policy", body)

    def test_404(self):
        status, _ = self._get("/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
