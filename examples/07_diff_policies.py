import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：对比两份策略的差异。"""
from aegis.api import Aegis

engine = Aegis()
a = engine.load("config/policies/network-isolate.yaml")
b = engine.load("config/policies/log4shell-shield.yaml")
for line in engine.diff(a, b):
    print(" ", line)
