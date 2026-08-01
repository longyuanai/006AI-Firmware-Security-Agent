# 006 AI Firmware Security Agent · 商业化实施方案

> 状态：执行中
> 基线：390 passed / 2 skipped（2026-08-01）
> 目标：先交付单租户、离线优先的 on-prem Beta，再演进为企业版。

## 1. 产品边界

首个可收费版本不是云端多租户平台，而是部署在客户自有 Windows/Linux
环境中的 Docker 静态分析 Worker。默认不执行固件内容，不把固件上传到外部服务；
NVD、EPSS、KEV 同步和 LLM 富化均可关闭。

首版面向以下场景：

- 固件发布前的组件、CVE、KEV 和 PRisk 检查
- CycloneDX 1.5 SBOM/VEX 交付
- 两个固件版本之间的组件和漏洞差分
- Markdown、HTML 和 IntegrationGateway JSON 报告
- 在隔离网络中使用本地 SQLite CVE 缓存完成扫描

0-day 候选和攻击链叙述只作为人工研判辅助，不作为已确认漏洞、可利用性证明
或自动阻断发布的依据。QEMU/FirmAE 动态分析保持显式 opt-in，不进入默认产品路径。

## 2. 商业发布门槛

只有同时满足以下门槛，版本才可标记为 commercial beta：

| 门槛 | 验收标准 |
|------|----------|
| 构建 | Windows/Linux CI 全绿；依赖审计无未处置高危项 |
| 契约 | v0.5 Finding 与 envelope 契约测试全绿 |
| 安全 | 只读、无网络、非 root Worker；输入/解包/SSRF 限制有回归测试 |
| 可复现 | 锁定 Python 依赖、基础镜像和外部工具版本；生成发布 SBOM |
| 准确率 | 至少 5 个独立真实固件家族；组件 precision/recall 和 CVE recall 有报告 |
| 性能 | 10 MiB、50 MiB、100 MiB 样本有端到端耗时与资源峰值基线 |
| 运营 | 扫描任务、状态、结果、错误和固件哈希可持久化；支持备份和清理 |
| 交付 | 版本号、变更日志、升级/回滚说明、已知限制和许可证清单齐全 |

未测量的准确率、召回率或风险排序一致性不得作为销售承诺。

## 3. 分阶段路线

### Phase C0 · 发布阻断项

| ID | 工作 | 完成定义 |
|----|------|----------|
| COMM-SEC-001 | 修复 Starlette/上游依赖审计失败 | Linux/Windows CI 与 pip-audit 全绿 |
| COMM-WIN-001 | 修复原生 PowerShell JSON stdin 编码 | 中文绝对路径通过真实 subprocess smoke |
| COMM-REL-001 | 统一版本与可复现构建 | 版本来源唯一、依赖锁定、创建首个预发布版本 |
| ARCH-001 | 收敛产品解包入口 | CLI、Gateway、Scanner 使用同一编排语义 |

### Phase C1 · 可收费 on-prem Beta

| ID | 工作 | 完成定义 |
|----|------|----------|
| FUSION-006 | VEX triage | 支持 affected/not_affected/fixed/under_investigation，保留原始证据 |
| FUSION-007 | 固件 Registry | SQLite 持久化扫描、组件、漏洞、工具版本和固件哈希 |
| COMM-JOB-001 | 作业生命周期 | queued/running/succeeded/failed/cancelled、超时和幂等键 |
| COMM-OBS-001 | 可观测性 | 结构化阶段日志、耗时、降级原因和健康状态；不记录固件内容 |
| COMM-PKG-001 | 交付包 | 固定 digest 的镜像、发布 SBOM、许可证清单、升级/回滚文档 |

### Phase C2 · 准确率与试点

| ID | 工作 | 完成定义 |
|----|------|----------|
| COMM-EVAL-001 | 独立真实语料 | 至少 5 个厂商/固件家族，人工标注 ground truth |
| COMM-CVE-001 | CVE 召回评测 | 与固定日期 NVD/KEV 快照对比并发布误报/漏报清单 |
| COMM-RISK-001 | PRisk 校准 | 由安全人员标注 Top-N，记录排序一致率和权重版本 |
| COMM-PERF-001 | 性能容量 | 测量解包、识别、匹配、报告各阶段耗时和资源峰值 |
| COMM-PILOT-001 | 客户试点 | 授权样本、验收报告、问题闭环和回滚演练 |

### Phase C3 · 企业版

- IntegrationGateway 身份认证、RBAC 和单租户到多租户隔离
- 审计日志、数据保留、删除、备份恢复和密钥管理
- Worker 队列、并发配额、失败重试、节点隔离和水平扩展
- 镜像签名、来源证明、漏洞响应 SLA 和发布审批
- 可选 FUSION-008 FirmAE/QEMU Lab Worker，独立网络与授权边界

## 4. 执行顺序

严格按以下顺序推进，每个 ID 独立 commit 并推送到 GitHub：

1. COMM-WIN-001（当前仓库可独立完成）
2. COMM-SEC-001（需要共享 integration 依赖升级配合）
3. COMM-REL-001
4. ARCH-001
5. FUSION-006
6. FUSION-007 + COMM-JOB-001
7. COMM-OBS-001 + COMM-PKG-001
8. Phase C2 真实评测与试点
9. Phase C3 企业能力

任何阶段若安全门槛或回归测试未通过，不进入下一发布等级；fail-open 只用于
保持扫描返回合法结果，不得把降级结果伪装成完整扫描。

## 5. 当前已知阻断项

- GitHub Linux CI 的 pip-audit 因共享 IntegrationGateway 依赖的 Starlette 0.46.2 失败。
- 本机未安装 Binwalk、Unblob、Syft、CVE Binary Tool，真实工具链尚未在本机联调。
- PowerShell 通过 stdin 传递带中文绝对路径的 JSON 时存在 BOM/编码兼容问题。
- CVE 召回率、PRisk 人工一致率和真实解包性能仍未独立测量。
- 当前包版本仍为 `0.1.0`，且没有正式 Git tag/GitHub Release。
