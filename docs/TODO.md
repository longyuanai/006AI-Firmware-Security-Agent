# 006 AI-Firmware-Security-Agent · v0.1 TODO

> **项目状态**: PoC ✅ (23/23 tests passing)
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) (已冻结)
> **派活模板**: [CODEX_INSTRUCTIONS.md](../../CODEX_INSTRUCTIONS.md)

---

## P0 · 本项目 v0.1 任务清单

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| CVE-001 | 接真实 NVD API 替换 mock | done | 2026-07-24 | 2026-07-24 | NVD 2.0 + mock fallback |
| CVE-002 | 接 EPSS API | done | 2026-07-24 | 2026-07-24 | FIRST EPSS v1 + 0.0 fallback |
| CVE-003 | 接 CISA KEV | done | 2026-07-24 | 2026-07-24 | CISA JSON feed + false fallback |
| FW-001 | 真实固件解包 (binwalk + squashfs) | done | 2026-07-24 | 2026-07-24 | 真实 SquashFS demo + Windows-safe runner |
| FW-002 | PRisk 加权公式 v0.1 | done | 2026-07-24 | 2026-07-24 | 归一化 0-1 + analyzer 排序 |
| RPT-001 | Markdown 报告加图表 (matplotlib PNG) | done | 2026-07-24 | 2026-07-24 | Agg 饼图 + Markdown 相对路径 |
| DOCKER-001 | Dockerfile + docker-compose.yml | done | 2026-07-24 | 2026-07-24 | 非 root slim 镜像 167.3 MB |
| CI-001 | GitHub Actions: lint + pytest + type check | pending | | | |

---

## 派活模板（复制即可）

发给 Codex 时,把这个模板 + 上面 issue 表里挑的一行 ID 拼起来:

```
[{ISSUE_ID}] 006 AI-Firmware-Security-Agent · {一句话}

## 背景
- 项目: 006 AI-Firmware-Security-Agent
- 路径: E:\001项目\000开发\003AI+网络安全\006AI-Firmware-Security-Agent
- 接口契约: 000shared-llm-core/docs/v0.1-contract.md (已冻结)

## 必须做的事
1. <具体动作 1,含文件路径>
2. <具体动作 2>
3. <具体动作 3>

## 验收
- [ ] pytest 全绿
- [ ] 新增测试 ≥ N 个
- [ ] CLI smoke test 通过 (粘贴输出)
- [ ] 改动文件清单 (git diff --stat)

## 回报格式
**ID**: <ISSUE-ID>
**Files changed**: <列表>
**Tests**: X/X passed
**CLI smoke**: <输出片段>
**Deviations**: <如有,说明原因>
```

---

## 复盘节奏

- 每周一 09:00: 跑 `pytest` 全量,状态写到本表
- 每周五 17:00: review 完成的 issue,标 done
- 每月 1 号: 检查 shared-llm-core 是否有 breaking change
