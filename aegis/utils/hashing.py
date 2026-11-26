"""Deterministic, dependency-free hashing helpers."""

import hashlib


def stable_hash(data: str, n_bytes: int = 8) -> int:
    """Return a stable unsigned integer hash of *data* (md5, big-endian).

    Used everywhere a reproducible pseudo-random value is needed (seeds,
    fingerprinting, cache keys). Same input -> same output, every process,
    every platform.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    digest = hashlib.md5(data).digest()
    return int.from_bytes(digest[:n_bytes], "big")


def sha256_hex(data: str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
