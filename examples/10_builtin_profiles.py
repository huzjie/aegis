import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：使用内置配置（network-only / fs-lockdown / no-spawn / full-lockdown）。"""
from aegis.policy.compiler import PolicyCompiler
from aegis.policy.defaults import builtin, builtin_names
from aegis.backend.factory import compile_policy

for name in builtin_names():
    p = builtin(name)
    ir = PolicyCompiler().to_ir(p)
    arts = compile_policy(ir)
    print(f"{name:<20} -> backends: {sorted(arts)} | {p.description}")
