"""JSON helpers with deterministic output."""

import json


def dumps(obj, indent: int = 2) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=indent, sort_keys=True)


def loads(text: str):
    return json.loads(text)
