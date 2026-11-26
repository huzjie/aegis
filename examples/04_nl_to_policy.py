import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：一句话自然语言 -> 可编译护盾策略。"""
from aegis.nlgen.compiler import compile_intent
from aegis.nlgen.parser import NlParser

parser = NlParser()
for text in [
    "block outbound dns except to 10.0.0.53",
    "deny execve and fork",
    "make the filesystem read-only",
    "\u7981\u6b62\u51fa\u7ad9\u6d41\u91cf",  # 禁止出站流量
]:
    intent = parser.parse(text)
    policy = compile_intent(intent)
    print(f"\n输入: {text}")
    print(f"  意图: {intent['scope']} / {intent['action']}")
    print(f"  规则: {policy['rules']}")
