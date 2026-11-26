"""Semantic validation of a shield policy."""

from aegis.errors import PolicyError
from aegis.policy.schema import structural_errors


def validate_policy(policy: dict) -> None:
    """Raise PolicyError if *policy* is structurally or semantically invalid."""
    errs = structural_errors(policy)
    if errs:
        raise PolicyError("; ".join(errs))
    _validate_semantics(policy)


def _validate_semantics(policy: dict) -> None:
    target = policy.get("target", {}) or {}
    if not any(target.get(k) for k in ("process", "user", "pid", "container", "cgroup")):
        # target may be omitted -> implicit "*"
        pass
    rules = policy.get("rules", [])
    if not rules:
        raise PolicyError("policy must declare at least one rule (rules: [])")
    seen_types = set()
    for i, r in enumerate(rules):
        t = r.get("type")
        seen_types.add(t)
        if t == "network":
            if "deny" not in r and "allow" not in r:
                raise PolicyError(f"rules[{i}] network rule needs deny or allow")
        elif t == "syscalls":
            if "deny" not in r and "allow" not in r:
                raise PolicyError(f"rules[{i}] syscalls rule needs deny or allow")
        elif t == "files":
            if not any(k in r for k in ("deny_read", "deny_write", "allow")):
                raise PolicyError(f"rules[{i}] files rule needs deny_read/deny_write/allow")
        elif t == "spawn":
            if "deny" not in r and "allow" not in r:
                raise PolicyError(f"rules[{i}] spawn rule needs deny or allow")
    enforcement = policy.get("enforcement", {}) or {}
    mode = enforcement.get("mode", "enforce")
    if mode not in ("enforce", "audit"):
        raise PolicyError(f"enforcement.mode must be enforce|audit, got {mode!r}")
