"""Compile a parsed intent into a valid shield policy dict."""


def compile_intent(intent: dict, name: str = "nl-shield") -> dict:
    """Turn a parser intent into a policy dict ready for load/compile."""
    rules = []
    scope = intent.get("scope", "network")
    action = intent.get("action", "block")
    if scope == "network":
        rule = {"type": "network"}
        if action == "block":
            rule["deny"] = intent.get("deny") or ["*"]
        if intent.get("allow"):
            rule["allow"] = intent["allow"]
        if intent.get("ports_deny"):
            rule["ports_deny"] = intent["ports_deny"]
        if intent.get("ports_allow"):
            rule["ports_allow"] = intent["ports_allow"]
        rules.append(rule)
    elif scope == "syscalls":
        rules.append({"type": "syscalls", "deny": intent.get("syscalls") or ["execve"]})
    elif scope == "files":
        f = intent.get("files") or {}
        rule = {"type": "files"}
        if f.get("deny_write"):
            rule["deny_write"] = f["deny_write"]
        if f.get("deny_read"):
            rule["deny_read"] = f["deny_read"]
        rules.append(rule)
    elif scope == "spawn":
        rules.append({"type": "spawn", "deny": ["*"]})
    return {
        "name": name,
        "version": "1",
        "description": "Generated from natural-language instruction.",
        "target": {"process": "*"},
        "rules": rules,
        "enforcement": {"backend": "auto", "mode": "enforce", "duration": "7d"},
    }
