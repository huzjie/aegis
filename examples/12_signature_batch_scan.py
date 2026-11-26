import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：批量扫描多份快照并汇总统计。"""
from collections import Counter

from aegis.api import Aegis

engine = Aegis()
samples = [
    {"argv": ["java", "${jndi:ldap://x}"]},
    {"argv": ["bash", "-i"], "ports": [4444]},
    {"cmdline": "python3", "argv": ["python3", "-c", "import socket;"]},
    {"argv": ["java", "-jar", "app.jar"]},
    {"cmdline": "nginx", "argv": ["nginx"]},
]
tally = Counter()
for s in samples:
    for d in engine.scan(s):
        tally[d.signature_id] += 1
print("特征命中统计:")
for sid, n in tally.most_common():
    print(f"  {sid:<16} {n}")
