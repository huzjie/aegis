"""A simple fixed-bucket histogram."""

from collections import defaultdict


class Histogram:
    def __init__(self, name: str, buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                                            0.5, 1, 2.5, 5, 10)):
        self.name = name
        self.buckets = tuple(sorted(buckets))
        self._counts = defaultdict(int)
        self._sum = 0.0
        self._count = 0

    def observe(self, value: float):
        self._sum += value
        self._count += 1
        for b in self.buckets:
            if value <= b:
                self._counts[b] += 1

    def snapshot(self) -> dict:
        return {"count": self._count, "sum": self._sum,
                "buckets": {str(b): self._counts[b] for b in self.buckets}}
