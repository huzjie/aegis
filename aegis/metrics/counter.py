"""A monotonic counter with labels."""

from collections import defaultdict


class Counter:
    def __init__(self, name: str, help_: str = ""):
        self.name = name
        self.help = help_
        self._vals = defaultdict(int)

    def inc(self, labels: tuple = (), value: int = 1):
        self._vals[labels] += value

    def get(self, labels: tuple = ()) -> int:
        return self._vals.get(labels, 0)

    def all(self) -> dict:
        return dict(self._vals)
