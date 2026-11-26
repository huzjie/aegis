"""Filesystem helpers used by audit / apparmor backends."""

import os


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def write_text(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path
