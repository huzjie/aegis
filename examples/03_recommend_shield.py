import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：从检测结果自动生成护盾策略。"""
import json

from aegis.api import Aegis

engine = Aegis()
dets = engine.scan({"cmdline": "java", "argv": ["java", "${jndi:ldap://x}"]})
for d in dets:
    policy = engine.recommend(d)
    print(f"检测: {d}")
    print("推荐护盾:")
    print(json.dumps(policy, ensure_ascii=False, indent=2))
    break
