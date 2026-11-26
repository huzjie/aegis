import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：生成 eBPF 产物（.bpf.c 源码 + loader.sh），落到 artifacts/。"""
from aegis.backend.ebpf import EbpfBackend
from aegis.policy.compiler import PolicyCompiler

ir = PolicyCompiler().to_ir(PolicyCompiler().compile({
    "name": "log4shell",
    "rules": [{"type": "network", "deny": ["*"],
               "allow": ["127.0.0.0/8", "10.0.0.0/8"]}],
}))
art = EbpfBackend().compile(ir)
import os
os.makedirs("artifacts", exist_ok=True)
for fname, content in art.files.items():
    with open(f"artifacts/{fname}", "w", encoding="utf-8") as f:
        f.write(content)
    print(f"写出 artifacts/{fname}  ({len(content.splitlines())} 行)")
print("\n在目标 Linux 主机上: clang -O2 -g -target bpf -c artifacts/log4shell.bpf.c -o log4shell.bpf.o")
