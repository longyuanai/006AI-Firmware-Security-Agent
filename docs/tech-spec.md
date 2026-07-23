# 006 AI-Firmware-Security-Agent · 技术方案

## 1. 业务问题

IoT 厂商出货百万台路由器/摄像头/智能门锁,固件里塞了 BusyBox / OpenSSL / lighttpd / xz 等几十个开源组件。一旦某个组件爆 CVE:

- **不知道影响范围**: 出货的固件里到底有没有这个组件?哪个版本?
- **来不及修**: 重新打固件 + 工厂烧录 + 升级推送 = 几个月
- **用户投诉**: 等用户被黑了才知道
- **合规压力**: 欧盟 CRA / 美国 Cyber Trust Mark 要求 SBOM

需要一个 **AI 助手**自动:
- 解包固件(.bin) → 提取组件清单(SBOM)
- 查 CVE/NVD/EPSS/KEV → 命中已知漏洞
- **PRisk 排序**: 综合 CVSS + EPSS + KEV + 可利用性 + 暴露面
- LLM 富化 Top N → 业务影响 + 修复方案
- 输出可执行的 Markdown 报告(含 SBOM)

## 2. 产品定位

**AI 固件安全分析平台**,接固件二进制,输出 SBOM + CVE 命中 + PRisk 排序报告。

- 输入: 固件 .bin (TP-Link / 小米 / Hikvision 等常见格式)
- 输出: Markdown 报告(SBOM + Top CVE 富化 + PRisk 排序)

**不是** 在线扫描器,是 **出厂前 / 出厂后定期** 的离线分析工具。

## 3. 关键能力（MoSCoW）

| 优先级 | 能力 | 说明 |
|--------|------|------|
| Must | 组件清单提取 | SBOM (CycloneDX 格式) |
| Must | CVE 匹配 | mock DB (PoC), NVD (v0.1) |
| Must | PRisk 排序 | 0.25·CVSS + 0.25·EPSS + 0.20·KEV + 0.15·Exploit + 0.15·Exposure |
| Must | LLM 富化 Top N | 业务影响 + 修复 |
| Must | Markdown 报告 | CLI 输出 |
| Should | 真实固件解包 | binwalk + squashfs |
| Should | EPSS / KEV | 真实威胁情报 |
| Should | HTML 报告 | jinja2 + CSS |
| Should | 报告图表 | matplotlib PNG |
| Should | Dockerfile | CI/CD |
| Could | CycloneDX 输出 | 标准化 SBOM |
| Could | 厂商指纹识别 | 自动识别 OEM |
| Could | 差分分析 | 对比两个版本固件 |
| Won't | 在线升级 | 推外部 OTA 系统 |

## 4. 总体架构

```
┌──────────────┐
│ firmware.bin │ ──▶ Unpack (binwalk/squashfs) ──▶ Filesystem
└──────────────┘                                        │
                                                        ▼
                                              ┌────────────────────┐
                                              │ Component Detector │
                                              │ (busybox/openssl/  │
                                              │  openssh/xz/...)   │
                                              └─────────┬──────────┘
                                                        ▼
                                              ┌────────────────────┐
                                              │ Component (SBOM)   │
                                              └─────────┬──────────┘
                                                        ▼
                                              ┌────────────────────┐
                                              │ CVE Lookup         │ ◀─ NVD/EPSS/KEV
                                              │ match_components   │
                                              └─────────┬──────────┘
                                                        ▼
                                              ┌────────────────────┐
                                              │ PRisk Ranking      │
                                              └─────────┬──────────┘
                                                        ▼
                                              ┌────────────────────┐
                                              │ LLM Enricher       │ ◀─ shared_llm_core (STANDARD)
                                              │ Top-N              │
                                              └─────────┬──────────┘
                                                        ▼
                                              ┌────────────────────┐
                                              │ Markdown Reporter  │
                                              │ SBOM + Top + table │
                                              └────────────────────┘
```

## 5. 模块设计

### 5.1 Component (`normalizer.py`)

```python
@dataclass
class Component:
    name: str          # busybox / openssl / openssh / xz
    version: str
    vendor: str
    category: str
    path: str          # 在固件中的路径
    extra: dict
```

### 5.2 Unpack (`unpack.py`,Stage 2)

```python
def unpack_firmware(bin_path: str) -> list[Component]:
    """binwalk → extract → parse package list → Component list"""
```

PoC 阶段用 tar.gz + manifest.yml 模拟,真实固件解包 Stage 2 实现。

### 5.3 CVE DB (`cve_db.py`)

```python
@dataclass
class CveRecord:
    cve: str
    cvss: float
    summary: str

def mock_lookup(c: Component) -> list[CveRecord]: ...
def nvd_lookup(c: Component, api_key=None) -> list[CveRecord]: ...   # Stage 1
def epss_lookup(cve: str) -> float: ...                                # Stage 1
def kev_lookup(cve: str) -> bool: ...                                  # Stage 1
```

### 5.4 Analyzer (`analyzer.py`)

```python
@dataclass
class ComponentMatch:
    component: Component
    cves: list[CveRecord]

def match_components(components, lookup_fn=None) -> list[ComponentMatch]: ...
def enrich_top_components(matches, n=5) -> list[ComponentNarrative]: ...
```

### 5.5 PRisk (`scoring.py`,Stage 2)

```python
@dataclass
class PRiskScore:
    component: ComponentMatch
    score: float          # 0-4
    cvss_term: float
    epss_term: float
    kev_term: float
    exploit_term: float
    exposure_term: float
```

公式: `PRisk = 0.25·(CVSS/10) + 0.25·EPSS + 0.20·KEV + 0.15·Exploit + 0.15·Exposure`

### 5.6 Reporter (`reporter.py`)

```python
def render_markdown(components, matches, narratives) -> str: ...
```

CLI 命令 `firmware-agent scan -i firmware.bin -o report.md`,带 `--demo` 用 mock 数据。

## 6. 数据与模型

无业务数据持久化。固件在内存解包,处理完丢弃。

## 7. 安全与合规

- 固件可能含厂商机密,本地处理,**不上云**
- LLM 调用走共享内核,审计留痕
- 报告脱敏: 默认不含固件 hash / vendor 明细

## 8. 部署

- CLI: `firmware-agent scan -i fw.bin -o report.md`
- `--demo` 模式用内置 mock 组件
- Docker: 镜像 < 500 MB
- 接 NVD: 环境变量 `NVD_API_KEY`

## 9. 评估指标

| 指标 | 目标 |
|------|------|
| 组件识别准确率 | ≥ 95% (主流组件) |
| CVE 匹配召回率 | ≥ 90% (mock DB) |
| PRisk 排序与人工一致 | ≥ 80% (Top 10) |
| 报告生成时间 | < 30s (10MB 固件) |

## 10. 路线图

| 阶段 | 内容 |
|------|------|
| **PoC (当前)** | mock 固件 + mock CVE + 富化, 23/23 测试 |
| **v0.1 S1** | 接 NVD/EPSS/KEV 真实 API |
| **v0.1 S2** | 真实固件解包 + PRisk 公式 |
| **v0.1 S3** | 报告图表 + Docker + CI |
| **v0.5** | CycloneDX SBOM 输出 |
| **v1.0** | 厂商指纹 + 差分分析 |

## 11. 接口契约

依赖 `shared-llm-core` v0.1。所有 LLM 调用通过 `LLMRouter`。

## 12. 风险

- **真实固件格式碎片**: 每家厂商不同 → 先覆盖 binwalk 主流格式
- **CVE 数据膨胀**: NVD 30万条 → 加本地缓存
- **PRisk 公式**: 权重是经验值,需实战调优

## 13. 关键文件

- `src/ai_firmware_agent/parsers.py` — 固件解包
- `src/ai_firmware_agent/cve_db.py` — CVE 查询
- `src/ai_firmware_agent/analyzer.py` — 匹配 + 富化
- `src/ai_firmware_agent/reporter.py` — 报告
- `samples/firmware_demo/` — PoC demo 固件
- `docs/TODO.md` — v0.1 issue 清单