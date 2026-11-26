"""Load a policy from YAML / JSON / dict (minimal YAML fallback included)."""

from __future__ import annotations

import json
import os

from aegis.errors import ConfigError
from aegis.policy.validator import validate_policy

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


def _parse_yaml(text: str) -> dict:
    if yaml is not None:
        return yaml.safe_load(text) or {}
    # minimal flat-ish YAML fallback (enough for our config files)
    out: dict = {}
    stack = [(out, -1)]
    for raw in text.splitlines():
        if raw.strip().startswith("#") or not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip().rstrip()
        while stack and indent <= stack[-1][1]:
            stack.pop()
        parent, _ = stack[-1]
        if line.endswith(":"):
            key = line[:-1].strip()
            child = {}
            parent[key] = child
            stack.append((child, indent))
        elif ":" in line:
            k, v = line.split(":", 1)
            parent[k.strip()] = _coerce(v.strip())
        else:
            if isinstance(parent, list):
                parent.append(_coerce(line))
    return out


def _coerce(v: str):
    if v == "":
        return ""
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    if v in ("null", "None", "~"):
        return None
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [_coerce(x.strip().strip("'\"")) for x in inner.split(",")] if inner else []
    if (v.startswith("'") and v.endswith("'")) or (v.startswith('"') and v.endswith('"')):
        return v[1:-1]
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        return v


def load_policy(path_or_obj) -> dict:
    """Load and validate a policy. Accepts a path or an already-parsed dict."""
    if isinstance(path_or_obj, dict):
        policy = path_or_obj
    else:
        if not os.path.exists(path_or_obj):
            raise ConfigError(f"policy file not found: {path_or_obj}")
        with open(path_or_obj, "r", encoding="utf-8") as f:
            text = f.read()
        if str(path_or_obj).endswith(".json"):
            policy = json.loads(text)
        else:
            policy = _parse_yaml(text)
    validate_policy(policy)
    return policy
