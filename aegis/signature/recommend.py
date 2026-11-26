"""Turn a Detection into a ready-to-apply shield policy dict."""

from aegis.signature.cve import load_signatures
from aegis.signature.detector import Detection


def recommend_shield(detection: Detection) -> dict:
    """Return a policy dict built from the detection's recommended shield."""
    sig = _find(detection.signature_id)
    base = sig.recommended_shield if sig else {}
    policy = {
        "name": f"shield-{detection.signature_id}",
        "version": "1",
        "description": f"Auto-generated shield for {detection.name} ({detection.cve}).",
        "target": {"process": base.get("process") or detection.evidence.get("process")},
        "rules": base.get("rules") or [],
        "enforcement": base.get("enforcement") or {"backend": "auto", "duration": "7d"},
    }
    if not policy["rules"]:
        policy["rules"] = [{"type": "network",
                            "deny": base.get("network", {}).get("deny", ["*"]),
                            "allow": base.get("network", {}).get("allow", ["127.0.0.0/8"])}]
    return policy


def _find(sig_id: str):
    for s in load_signatures():
        if s.id == sig_id:
            return s
    return None
