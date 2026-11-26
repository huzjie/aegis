# 技术篇｜补丁落地前，怎么用 AI + eBPF 给跑着的服务「套盾」？—— 一个可复用的运行时防护控制平面拆解

> 一句话背景：2026-11-23 OpenAI 与 Cisco（Isovalent）开源了运行时防护项目 **Shirudo**（日语「盾」）。
> 它的核心命题是——**漏洞被发现的速度已经快过打补丁的速度**，与其等官方二进制补丁铺到生产（数周），
> 不如让 AI 先给运行中的服务写一层临时的 eBPF「盾」，在**不重启、不中断**的前提下阻断漏洞利用路径。
> 本仓库（aegis）是把这个思路**降维成一个纯 Python 控制平面**的完整实现。下面把技术原理、可复用的工程思路、以及能直接抄的提示词与配置模板一次讲透。

---

## 一、先搞懂：为什么 eBPF 能做到「不重启就堵住漏洞」？

普通安全软件堵漏洞靠的是「改代码 + 重启」或「改配置 + 重载」。eBPF 不一样——它是 Linux 内核里一台**沙箱虚拟机**：
你把一小段经过**内核 verifier 静态校验**的程序，挂到内核的固定执行点（kprobe / tracepoint / LSM hook / tc），
它就能在**不重新编译内核、不加载驱动、不重启进程**的前提下，观察甚至改写进程的行为。

这就是「盾」的全部秘密：

- **漏洞还在二进制里**，盾并没有修 bug；
- 盾只做一件事——**掐断「利用这条漏洞所依赖的那条代码路径」**。比如 Java4Shell 依赖 JNDI 外联 LDAP/RMI 端口、或依赖 fork 出子进程执行命令，那就把这两条路径在系统调用/网络层拦掉；
- 因为拦的是「路径」而不是「进程」，所以 **PID 不变、TCP 长连接不断、客户端吞吐不打折**。

把这个认知翻译成工程语言，就是三句话：

1. 攻击行为与合法请求往往**共用同一个底层 Linux 操作**（connect、execve、write……），所以盾必须**精准到「特定条件」**，而不是整进程一刀切；
2. 因此盾需要「**先观察、后拦截**」——先用 monitor/audit 模式跑一段真实流量，看「它会拦到什么」再决定是否 enforce；
3. 盾是**临时资产**——它买来的是「测试并部署正式补丁」的时间，补丁一落地就该退役。

---

## 二、我把这个问题降维成了什么

直接在 eBPF 上编程有门槛：要装 clang + 内核头文件、要懂 BPF 指令或写 C、要处理不同内核版本的兼容。
于是我做了个取舍：**aegis 不直接操作内核，而是做一个「声明式策略 → 多后端加固产物」的控制平面**。

核心数据流就一条：

```
策略 YAML ──validate──▶ 类型化 Policy ──compile──▶ IR ──分发──▶ 后端产物
                                                          ├─ seccomp   （经典 BPF 指令，拦 syscall/spawn）
                                                          ├─ nftables  （nft 规则文本，拦网络）
                                                          ├─ iptables  （legacy 兜底）
                                                          ├─ apparmor  （profile 文本，拦文件写）
                                                          ├─ ebpf      （生成 .bpf.c + loader.sh，全类别）
                                                          └─ audit     （决策清单，永远不强制，dry-run）
```

三个关键设计决策（可以直接抄去你自己的项目）：

**① 策略声明式、后端可插拔。** 用户只写「要拦什么」，不写「怎么拦」。`enforcement.backend: auto` 时按**规则类别**自动分发：

```python
CATEGORY_BACKEND = {
    "syscalls": "seccomp",   # 系统调用 -> seccomp 最稳
    "spawn":    "seccomp",   # 进程派生 -> seccomp
    "network":  "nftables",  # 网络 -> nftables
    "files":    "apparmor",  # 文件 -> apparmor
}
```

**② deny-all（`*`）必须诚实建模。** 「允许出站只有私网段」本质上是个「默认拒绝 + 白名单」策略，
如果后端实现写错了，会把合法流量一起砍了。所以每个后端的编译逻辑都**显式处理 `*`**，并且 `audit` 后端会把「deny-all」这条决策明文打印出来，逼操作员看见风险再点确认。

**③ 永远提供一个不会伤人的 `audit` 后端。** 它只产出「我会对目标进程做什么」的决策清单，`apply` 返回 `mode: dry-run`。
这让「先审计、后强制」从口号变成**代码里的一条硬路径**，而不是靠操作员的自觉。

---

## 三、能直接抄的干货块

### 干货块 1：一份即插即用的护盾策略模板

```yaml
name: my-temporary-shield
version: "1"
description: 补丁落地前，临时阻断 java 进程的非私网外联与子进程派生
target:
  process: java                # 或 user / pid / container / cgroup
rules:
  - type: network
    deny: ["*"]                # 默认拒绝所有出站
    allow: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ports_deny: [389, 636, 1099, 1389]   # 额外点名 JNDI 常走端口
  - type: spawn
    deny: ["*"]                # 禁止 fork 子进程执行命令
enforcement:
  backend: auto
  mode: audit                  # 先 audit 跑一天，无业务误伤再改 enforce
  duration: 7d                 # 临时盾，7 天后退役
```

### 干货块 2：给真实 LLM 的「盾生成」提示词模板

```
你是 Linux 运行时防护专家。基于下面的漏洞信息，产出一份 aegis 护盾策略 YAML。

漏洞信息：{cve_id} {affected_process} {exploit_requires}
目标进程：{target_process}
业务红线：必须放行的地址/端口/路径 —— {allowlist}

要求：
1. 只输出 YAML，不要解释。
2. 用最少的规则阻断漏洞利用所依赖的路径，不要整进程一刀切。
3. 网络规则必须显式写出 allow 白名单（deny: ["*"] 时必须给出 allow）。
4. enforcement.mode 一律先写 audit，enforcement.duration 写 7d。
5. 若利用需要 fork 子进程，追加 type: spawn 规则。
```

（完整版见仓库 `prompts/shield_generation.system.md`，配套还有「利用复现」「检测分诊」「报告简报」三套模板。）

### 干货块 3：一条 8 步的「临时护盾」落地路径

1. **观察**：`python -m aegis scan --cmdline "java -jar app.jar" --argv ...` 命中了哪条 CVE 特征；
2. **定位路径**：这条利用靠的是网络外联、syscall、文件写、还是子进程派生？
3. **写策略**：按上面的模板写 YAML（或 `python -m aegis gen "..."` 一句话生成草稿）；
4. **编译**：`python -m aegis compile --policy x.yaml`，看各后端产物长什么样；
5. **审计**：`mode: audit` 跑真实流量，对比 `audit` 后端决策清单，确认没有误伤；
6. **审批**：人工确认后 `mode: enforce`；
7. **强制**：在目标 Linux 主机执行对应后端产物（`nft -f` / 加载 seccomp / `apparmor_parser -r`）；
8. **退役**：正式补丁上线后移除护盾，`duration` 到期自动提示退役。

### 干货块 4：两个踩过的坑（直接抄可省半天）

- **坑 1：本机没有 eBPF 工具链怎么办？** 编译 eBPF 需要 `clang -target bpf` + 内核头文件，很多环境装不齐。
  解法：`backend: auto` 会优先走 seccomp/nftables（不需要任何编译工具链），eBPF 只作为「能生成源码、到目标机再编译」的产物。
- **坑 2：seccomp 的经典 BPF 只能按「系统调用号」匹配。** 你没法用一条规则拦「带 JNDI 字符串的 connect」，
  只能拦「connect 这个 syscall 本身」。所以**网络层的条件拦截交给 nftables（能按目标端口/地址）**，seccomp 只负责「禁 fork/exec」这类无条件拦截。别指望一层做完所有事。

---

## 四、可复用思路清单（一句话版）

- **把「防护」建模成「策略编译到多后端」，而不是写死一种内核机制** —— 后端可插拔，按类别分发；
- **deny-all 与 audit 是两件必须显式处理的事** —— 危险操作要能被看见、能被 dry-run；
- **「正确性」和「置信度」分开建模** —— 特征命中给置信度、不直接给结论，留给人复核；
- **离线确定性 mock 打通端到端验证** —— 不依赖任何 LLM 密钥也能跑完整条链路，接入真模型只替换一个 `generate()`。

---

*本仓库为教学/研究用途的独立实现，不包含 Shirudo 任何代码；eBPF 产物遵循内核 GPL 兼容声明。*
