"""Time helpers (parse durations like ``7d``, ``4h``)."""

import re

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_PAT = re.compile(r"(\d+(?:\.\d+)?)([smhdw])")


def parse_duration(text: str) -> int:
    """Parse a human duration string into seconds.

    Examples: "30s" -> 30, "4h" -> 14400, "7d" -> 604800, "1w" -> 604800.
    """
    text = (text or "").strip().lower()
    total = 0
    pos = 0
    for m in _PAT.finditer(text):
        total += float(m.group(1)) * _UNITS[m.group(2)]
        pos = m.end()
    if total == 0 and text.isdigit():
        return int(text)
    if total == 0 or pos != len(text):
        raise ValueError(f"invalid duration: {text!r}")
    return int(total)


def format_duration(seconds: int) -> str:
    if seconds >= 604800 and seconds % 604800 == 0:
        return f"{seconds // 604800}w"
    if seconds >= 86400 and seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"
