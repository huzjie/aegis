# Changelog

## [1.0.0] - 2026-11-26

### 新增
- 声明式护盾策略引擎：loader / validator / compiler / 类型化 Policy / IR
- 六大后端：seccomp / eBPF / AppArmor / nftables / iptables / audit（dry-run）
- CVE 特征库（14 条）与进程快照扫描、护盾推荐
- 自然语言 -> 策略（离线确定性解析 + mock LLM 适配）
- HTTP 控制平面（compile / apply / scan / gen / health）
- Prometheus 指标、审计日志（JSONL / SQLite）
- 内置配置（network-only / fs-lockdown / no-spawn / full-lockdown）
- 完整测试套件、示例、文档、Docker / K8s / Helm / systemd 部署、CI/CD

### 修复
- eBPF 生成器的字符串转义
- `Aegis.compile` 的 IR 传递（Policy -> to_ir）
- 自然语言解析器端口提取误读 IP 八位组
