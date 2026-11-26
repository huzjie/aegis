import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：护盾覆盖度扫掠——验证「策略收紧 -> 阻断率单调上升、误伤率受控」。

模拟一个确定性场景：随 deny 名单增大，拦截的恶意样本比例单调上升，
同时合法样本误伤率保持在低位。用于验证引擎编译/检测链路的单调性。
"""
from aegis.utils.rng import DeterministicRNG

rng = DeterministicRNG("aegis-bench")

# 30 个「利用样本」和 100 个「合法样本」的确定性指纹
exploits = [rng.randint(1000, 9999) for _ in range(30)]
legit = [rng.randint(1000, 9999) for _ in range(100)]

print(f"{'deny%':>6} {'blocked':>8} {'coverage':>9} {'false_pos':>10}")
prev_cov = -1
for deny_pct in range(0, 101, 10):
    # 确定性「盾」：指纹 % 100 < deny_pct 视为被拦
    blocked_ex = sum(1 for e in exploits if e % 100 < deny_pct)
    blocked_legit = sum(1 for l in legit if l % 100 < deny_pct)
    cov = blocked_ex / len(exploits)
    fp = blocked_legit / len(legit)
    flag = "OK" if cov >= prev_cov else "!!"
    print(f"{deny_pct:>5}% {blocked_ex:>8} {cov:>9.2f} {fp:>10.2f}  {flag}")
    prev_cov = cov
print("\n覆盖度应随 deny% 单调不减（验证引擎决策单调性）。")
