# prompts/

可直接复用的大模型提示词模板。喂给任意模型（或 aegis 的 LLM 适配器）即可：

- `shield_generation.system.md` — 自然语言 → 盾策略 YAML
- `detection_triage.system.md` — 检测结果 → 要不要上盾的分诊
- `exploit_reverse.system.md` — CVE → 最小拦截面反推
- `report_briefing.system.md` — 盾策略 → 运维简报
