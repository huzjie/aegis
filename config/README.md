# 护盾策略样例

本目录收纳**即插即用**的护盾策略。用法：

```bash
# 编译（dry-run，不落盘不执行）
python -m aegis compile --policy config/policies/<file>.yaml

# 审计应用（audit 后端，永远安全）
python -m aegis apply --policy config/policies/<file>.yaml --backend audit
```

| 文件 | 场景 | 后端 |
|------|------|------|
| `log4shell-shield.yaml` | 阻断 Log4Shell JNDI 外联 + 子进程 | auto（nftables+seccomp） |
| `java4shell-shield.yaml` | 阻断 Java4Shell 类加载绕过 | auto |
| `spring4shell-shield.yaml` | 阻断 Spring4Shell 文件写 + 外联 | auto |
| `reverse-shell-block.yaml` | 阻断反弹 shell 常见外联端口 | nftables |
| `dns-exfil-block.yaml` | 阻断 DNS 外带（仅放行内网 DNS） | nftables |
| `network-isolate.yaml` | 全网隔离（仅 loopback） | nftables |
| `fs-lockdown.yaml` | 文件系统只读加固 | apparmor |
| `no-spawn.yaml` | 禁止子进程派生 | seccomp |
| `full-lockdown.yaml` | 全量临时封锁 | auto |

> 所有样例默认 `mode: audit`，先用 audit 跑真实流量确认无误伤，再改 `enforce`。
