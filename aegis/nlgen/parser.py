"""Deterministic natural-language -> intent parser (no model required)."""

from __future__ import annotations

import re

from aegis.nlgen.keywords import (
    ACTION_ALLOW, ACTION_BLOCK, PORT_HINTS, SCOPE_FILES, SCOPE_NETWORK,
    SCOPE_SPAWN, SCOPE_SYSCALL, SYSNAME_HINTS,
)

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_PORT = re.compile(r"\b(?:port\s+)?(\d{1,5})\b")


class NlParser:
    """Parse a short English/Chinese instruction into a structured intent.

    Deterministic and offline; a real LLM can augment this via the
    ``aegis.nlgen.mock_llm``-style adapter and the prompt templates under
    ``prompts/``.
    """

    def parse(self, text: str) -> dict:
        t = (text or "").lower()
        intent = {
            "action": "block" if _any(t, ACTION_BLOCK) else "allow",
            "scope": self._scope(t),
            "allow": [], "deny": [],
            "ports_deny": [], "ports_allow": [],
            "syscalls": [], "files": {"deny_write": [], "deny_read": []},
            "spawn": False,
        }
        ips = _IP.findall(t)
        # strip IPs before port extraction so octets (e.g. "10.0.0.53") are
        # not misread as port numbers; keep only valid 1..65535 ports.
        t_noip = _IP.sub(" ", t)
        ports = [int(x) for x in _PORT.findall(t_noip) if 0 < int(x) <= 65535]

        # negation split: everything after "except"/"allow" -> allowlist
        if _any(t, ACTION_ALLOW):
            intent["allow"] = list(ips)
        else:
            intent["deny"] = list(ips)

        # service -> port hints
        for word, port in PORT_HINTS.items():
            if word in t.split() or word in t:
                if _any(t, ACTION_ALLOW):
                    intent["ports_allow"].append(port)
                else:
                    intent["ports_deny"].append(port)
        intent["ports_deny"] += [p for p in ports if p not in intent["ports_allow"]]

        if intent["scope"] == "network":
            if "all" in t or "everything" in t or "全部" in t:
                intent["deny"] = ["*"] if not _any(t, ACTION_ALLOW) else intent["deny"]
        elif intent["scope"] == "syscalls":
            for word, name in SYSNAME_HINTS.items():
                if word in t:
                    intent["syscalls"].append(name)
            if not intent["syscalls"]:
                intent["syscalls"] = ["execve", "fork", "clone"]
        elif intent["scope"] == "files":
            intent["files"]["deny_write"] = ["/etc/**", "/usr/**", "/var/**"]
        elif intent["scope"] == "spawn":
            intent["spawn"] = True
        return intent

    def _scope(self, t: str) -> str:
        if _any(t, SCOPE_SYSCALL):
            return "syscalls"
        if _any(t, SCOPE_FILES):
            return "files"
        if _any(t, SCOPE_SPAWN):
            return "spawn"
        if _any(t, SCOPE_NETWORK):
            return "network"
        return "network"


def _any(text: str, words) -> bool:
    for w in words:
        if w in text:
            return True
    return False
