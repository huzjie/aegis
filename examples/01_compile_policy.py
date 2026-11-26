import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：编译一份护盾策略到所有后端，打印产物概览。"""
from aegis.api import Aegis

engine = Aegis()
policy = engine.load("config/policies/log4shell-shield.yaml")
artifacts = engine.compile(policy)

print("策略:", policy["name"], "->", policy["description"])
for backend, art in artifacts.items():
    print(f"  [{backend}] {art.summary()}")

# 打印 audit 决策清单（dry-run 视角，永远安全）
audit = artifacts.get("audit")
if audit:
    print("\naudit 决策清单:")
    for line in audit.content:
        print(f"  - {line}")
