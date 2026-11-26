"""JSON-schema-like structural validation rules for a policy dict."""

_REQUIRED = ["name"]
_RULE_TYPES = {"network", "syscalls", "files", "spawn"}
_ENFORCEMENT_KEYS = {"backend", "fallback", "mode", "duration"}


def structural_errors(policy: dict) -> list:
    errs = []
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]
    for k in _REQUIRED:
        if not policy.get(k):
            errs.append(f"missing required field: {k}")
    target = policy.get("target", {})
    if target is not None and not isinstance(target, dict):
        errs.append("target must be a mapping")
    rules = policy.get("rules")
    if rules is not None:
        if not isinstance(rules, list):
            errs.append("rules must be a list")
            return errs
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                errs.append(f"rules[{i}] must be a mapping")
                continue
            if r.get("type") not in _RULE_TYPES:
                errs.append(f"rules[{i}].type must be one of {sorted(_RULE_TYPES)}")
    enforcement = policy.get("enforcement", {})
    if enforcement is not None and not isinstance(enforcement, dict):
        errs.append("enforcement must be a mapping")
    return errs
