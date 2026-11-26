"""Deterministic RNG derived from an md5 seed (fully reproducible)."""

import random

from aegis.utils.hashing import stable_hash


class DeterministicRNG:
    """A `random.Random` seeded deterministically from a string key.

    Two processes constructing ``DeterministicRNG("foo")`` will produce the
    exact same sequence of numbers. Used to make mocks and benchmarks
    bit-for-bit reproducible.
    """

    def __init__(self, seed: str):
        self._key = seed
        self._rng = random.Random(stable_hash(seed))

    def randint(self, a: int, b: int) -> int:
        return self._rng.randint(a, b)

    def random(self) -> float:
        return self._rng.random()

    def choice(self, seq):
        return self._rng.choice(seq)

    def coin(self, p: float = 0.5) -> bool:
        return self._rng.random() < p

    def shuffle(self, seq):
        self._rng.shuffle(seq)
        return seq

    @property
    def seed(self) -> str:
        return self._key
