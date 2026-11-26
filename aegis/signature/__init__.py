"""Exploit signature knowledge base, matching and shield recommendation."""

from aegis.signature.detector import SignatureDetector, Detection
from aegis.signature.recommend import recommend_shield

__all__ = ["SignatureDetector", "Detection", "recommend_shield"]
