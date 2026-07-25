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

## 14. Phase-2 实施(v0.6+ 改造指令)

> **本文是 Codex 实施 Phase-2 的入口**。路线图 v0.6 之后所有改动以此为准。

### 14.1 Hook A · 真实 binwalk 集成(v0.6)

**目标**:替换 mock 解包为 `binwalk -e` 调用,**真**提取文件系统 + 内核 + 应用。

**新增文件**:

```
src/ai_firmware_agent/binwalk_runner.py    # BinwalkRunner:asyncio subprocess 调 binwalk
src/ai_firmware_agent/parsers/
├── __init__.py
├── mock.py             # 现有 mock,搬过来
└── binwalk.py          # BinwalkRunner 包装,ExtractResult dataclass
```

**API 形状**:

```python
@dataclass
class ExtractResult:
    firmware_path: Path
    output_dir: Path
    files: list[Path]            # 提取出来的文件清单
    signatures: list[str]        # binwalk 识别到的 magic
    error: str | None


class BinwalkRunner:
    def __init__(self, binwalk_path: str = "binwalk", timeout: int = 120):
        self._binwalk = binwalk_path
        self._timeout = timeout

    async def extract(self, firmware_path: Path, *, output_dir: Path) -> ExtractResult:
        """asyncio.create_subprocess_exec('binwalk', '-e', '--directory', ..., firmware_path)"""
        ...

    async def is_available(self) -> bool:
        """shutil.which('binwalk') or PATH check"""
        ...
```

**集成方式**:

- `src/ai_firmware_agent/scanner.py` —— 如果 `binwalk` 在 PATH,用 BinwalkRunner;否则 fallback mock
- 不在 fixture 上强依赖 binwalk(测试用 mock,生产环境用户装)

**测试要求**:

- `tests/test_binwalk_runner.py` —— 用 `unittest.mock` mock asyncio subprocess
- `tests/test_binwalk_availability.py` —— mock `shutil.which` 返回 None / "C:\\binwalk.exe"
- `tests/test_scanner_fallback.py` —— binwalk 不可用时,scanner 自动 fallback 到 mock
- 真集成测试标记 `@pytest.mark.integration`,**默认 skip**,本地有 binwalk 时才跑

**commit 计划**(2 commit):

1. `feat(binwalk): add BinwalkRunner async subprocess + ExtractResult schema`
2. `feat(scanner): add binwalk availability check + fallback to mock parser`

### 14.2 Hook B · 嵌入式 CVE 数据库(v0.7)

**目标**:frequently-embedded 软件(openssh / busybox / dnsmasq 等)的 CVE 本地查询,离线可用。

**新增文件**:

```
src/ai_firmware_agent/cve_db/
├── __init__.py
├── schema.sql               # SQLite schema(cpe_id, cve_id, cvss_v3, description)
├── sync.py                  # 启动时下载一次 NVD CPE match,写入 SQLite
├── query.py                 # 按 component + version 查 CVE
├── embedded_components.json # frequently-embedded 名单(openssh / busybox / dnsmasq / dropbear / ...)
└── data/
    └── cve_cache.db         # SQLite 文件,gitignore
```

**Schema**:

```sql
CREATE TABLE cve_entries (
    cve_id TEXT PRIMARY KEY,
    cpe_id TEXT NOT NULL,         -- "cpe:2.3:a:openbsd:openssh:8.5p1:*:*:*:*:*:*"
    cvss_v3 REAL,
    description TEXT,
    in_known_exploited BOOLEAN DEFAULT 0,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_cpe ON cve_entries(cpe_id);
```

**API**:

```python
class EmbeddedCVEDatabase:
    def __init__(self, db_path: Path = Path("data/cve_cache.db")):
        self._db = db_path

    async def sync(self) -> int:
        """下载 NVD CPE match,upsert。返回写入条数"""

    async def lookup(self, component: str, version: str) -> list[CVEEntry]:
        """按 (component, version) 模糊匹配 CPE"""
```

**集成方式**:

- `src/ai_firmware_agent/scanner.py` —— 扫描出组件 + 版本后调 `db.lookup(...)`,命中 CVE 时产 Finding
- CLI 首次启动会触发 sync,**用 NVD_API_KEY** 时 50 req/30s,没有时 5 req/30s

**测试要求**:

- `tests/test_cve_db_schema.py` —— schema 合法,索引在
- `tests/test_cve_db_sync.py` —— mock NVD response,验证 upsert 行为
- `tests/test_cve_db_query.py` —— 用预填 SQLite fixture,验证 lookup
- `tests/test_cve_db_offline.py` —— 数据库已同步后,断网仍可查

**commit 计划**(3 commit):

1. `feat(cve_db): add SQLite schema + embedded_components.json + DB class`
2. `feat(cve_db): add NVD CPE match sync + rate limit handling`
3. `feat(scanner): integrate CVE lookup into scan pipeline + Finding emission`

### 14.3 Hook C · SBOM CycloneDX 导出(v0.7)

**目标**:导出 CycloneDX 1.5 SBOM,从 firmware extract 出 component + version + license。

**新增文件**:

```
src/ai_firmware_agent/sbom/
├── __init__.py
├── cyclonedx.py             # CycloneDX 1.5 BOM 生成
└── template.json            # CycloneDX BOM 模板
```

**CycloneDX 1.5 BOM 形状**:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "openssh",
      "version": "8.5p1",
      "licenses": [{"license": {"name": "BSD-2-Clause"}}],
      "purl": "pkg:generic/openssh@8.5p1"
    }
  ]
}
```

**CLI 增量**:

```bash
ai-firmware-agent scan --input '{...}' --sbom output/sbom.json
```

**测试要求**:

- `tests/test_cyclonedx_bom.py` —— 用 jsonschema 验证(需 `jsonschema` 依赖)
- `tests/test_sbom_components.py` —— fixture firmware → 已知 components
- `tests/test_cli_sbom_output.py` —— `--sbom` 路径正确生成

**commit 计划**(1 commit):

- `feat(sbom): add CycloneDX 1.5 exporter + --sbom CLI flag`

### 14.4 不要做的事

- ❌ **不**真跑 firmware(可能含漏洞代码)—— sandbox 内或 dry-run
- ❌ **不**把 firmware 内容写日志(隐私 + 体积)
- ❌ **不**破坏 v0.5 §15 envelope 的 `source="006"` 注入(集成层靠这个分流)
- ❌ **不**改 `Finding` schema(共享契约,改了就破 v0.5 冻结)
- ❌ **不**动 `tests/test_cli_envelope.py`(§15 契约测试是冻结基线)
- ❌ **不**强依赖 binwalk PATH(测试用 mock,fail-open fallback)

### 14.5 验收清单

Codex 完工后跑:

```powershell
& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m pytest tests/ `
  --basetemp=C:/pytest-tmp/006-phase2 `
  -o addopts= `
  -q --tb=short

& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m ai_firmware_agent scan --input '{"firmware_path":"tests/fixtures/sample.bin"}' --json
```

预期:≥ 130 passed(原 116 + Phase-2 新增 14);CLI envelope 仍是 `{"findings": [...], "summary": {...}}`。

---

**最近修订**: 2026-07-25 · Claude 把 PHASE-2.md 合并进 §14
**下次回看触发**: v0.6 启动 / Hook A 启动 / CVE DB 同步