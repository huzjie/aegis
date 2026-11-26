"""Matcher: run all signatures against a single snapshot."""

from aegis.signature.cve import load_signatures


class Matcher:
    def __init__(self, signatures: list | None = None):
        self.signatures = signatures if signatures is not None else load_signatures()

    def match(self, snapshot: dict) -> list:
        """Return [(signature, hits), ...] for every signature that fires."""
        out = []
        for sig in self.signatures:
            hits = sig.matches(snapshot)
            if hits:
                out.append((sig, hits))
        return out
