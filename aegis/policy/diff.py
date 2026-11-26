"""Compute a human-readable diff between two policy dicts."""

from aegis.policy.types import Policy


def diff_policies(old, new) -> list:
    """Return a list of ``"rule.attr: old -> new"`` strings."""
    o = old if isinstance(old, Policy) else _to_policy(old)
    n = new if isinstance(new, Policy) else _to_policy(new)
    out = []
    for cat in ("network", "syscalls", "files", "spawn"):
        ov = _flat(getattr(o, cat)) if getattr(o, cat) else {}
        nv = _flat(getattr(n, cat)) if getattr(n, cat) else {}
        keys = set(ov) | set(nv)
        for k in sorted(keys):
            if ov.get(k) != nv.get(k):
                out.append(f"{cat}.{k}: {ov.get(k)} -> {nv.get(k)}")
    return out


def _to_policy(policy: dict) -> Policy:
    from aegis.policy.compiler import PolicyCompiler
    return PolicyCompiler().compile(policy)


def _flat(rule) -> dict:
    d = {}
    for k, v in vars(rule).items():
        if v:
            d[k] = v
    return d
