"""HTTP request handlers for the aegis control plane."""

from http.server import BaseHTTPRequestHandler

from aegis import __version__
from aegis.api import Aegis
from aegis.gateway.schemas import json_response, read_json
from aegis.policy.defaults import builtin_names


def make_handler(engine: Aegis):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # silence default logging
            pass

        def do_GET(self):
            path = self.path.split("?")[0].rstrip("/")
            if path == "/health":
                return json_response(self, {"status": "ok", "version": __version__})
            if path == "/v1/shields" or path == "/v1/profiles":
                return json_response(self, {"profiles": builtin_names()})
            if path == "/v1/signatures":
                return json_response(self, {"signatures": [
                    {"id": s.id, "cve": s.cve, "name": s.name,
                     "severity": s.severity} for s in engine._detector.signatures]})
            if path == "/v1/backends":
                from aegis.backend.factory import BackendFactory
                return json_response(self, {"backends": BackendFactory.available()})
            return json_response(self, {"error": "not found"}, 404)

        def do_POST(self):
            path = self.path.split("?")[0].rstrip("/")
            try:
                if path == "/v1/compile":
                    policy = read_json(self)
                    artifacts = engine.compile(policy)
                    return json_response(self, {
                        "artifacts": {k: v.summary() for k, v in artifacts.items()},
                        "backend": sorted(artifacts.keys()),
                    })
                if path == "/v1/apply":
                    policy = read_json(self)
                    artifacts = engine.compile(policy)
                    out = {}
                    for name, art in artifacts.items():
                        from aegis.backend.factory import BackendFactory
                        out[name] = BackendFactory.create(name).apply(art)
                    return json_response(self, {"applied": out})
                if path == "/v1/scan":
                    snapshot = read_json(self)
                    dets = engine.scan(snapshot)
                    return json_response(self, {"detections": [
                        {"id": d.signature_id, "cve": d.cve, "name": d.name,
                         "severity": d.severity, "confidence": d.confidence,
                         "evidence": d.evidence} for d in dets]})
                if path == "/v1/gen":
                    body = read_json(self)
                    from aegis.nlgen.parser import NlParser
                    from aegis.nlgen.compiler import compile_intent
                    intent = NlParser().parse(body.get("text", ""))
                    return json_response(self, {
                        "intent": intent, "policy": compile_intent(intent)})
                return json_response(self, {"error": "not found"}, 404)
            except Exception as e:  # noqa: BLE001
                return json_response(self, {"error": str(e)}, 400)

    return Handler
