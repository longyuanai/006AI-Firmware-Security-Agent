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
| Must | 组件清单提取 | SBOM (CycloneDX 格式) ✅ |
| Must | CVE 匹配 | mock DB (PoC), NVD (v0.1) |
| Must | PRisk 排序 | 0.25·CVSS + 0.25·EPSS + 0.20·KEV + 0.15·Exploit + 0.15·Exposure |
| Must | LLM 富化 Top N | 业务影响 + 修复 |
| Must | Markdown 报告 | CLI 输出 |
| Should | 真实固件解包 | binwalk + squashfs ✅ |
| Should | EPSS / KEV | 真实威胁情报 |
| Should | HTML 报告 | jinja2 + CSS ✅ 已完成(`html_report.py`,自动转义 + 图表内联) |
| Should | 报告图表 | matplotlib PNG |
| Should | Dockerfile | CI/CD |
| Could | CycloneDX 输出 | 标准化 SBOM ✅ 已完成(含 VEX) |
| Could | 厂商指纹识别 | 自动识别 OEM |
| Could | 差分分析 | 对比两个版本固件 ✅ 已完成(不含厂商指纹) |
| Won't | 在线升级 | 推外部 OTA 系统 |

## 4. 总体架构

```
┌──────────────┐
│ firmware.bin │ ──▶ Unpack (binwalk/squashfs) ──▶ Filesystem
└──────────────┘                                        │
                                                        ▼
                                              ┌────────────────────┐
                                              │ Component Detector │
                                              │ opkg/dpkg status   │
                                              │ /etc/os-release    │
                                              │ ELF version banner │
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

### 5.2 Unpack (`unpack.py` + `extraction.py`)

```python
def unpack_firmware(bin_path, *, runner=subprocess.run,
                    max_bytes=MAX_EXTRACTED_BYTES,
                    max_files=MAX_EXTRACTED_FILES) -> list[Component]:
    """binwalk -Me → (必要时) unsquashfs → 组件检测 → Component list"""
```

固件是不可信输入且 `binwalk -Me` 递归解包,构造的镜像可以无限膨胀。解包输出
上限在 `extraction.py`,**两条解包路径共用**(同步 `unpack.py` 与异步
`parsers/binwalk.py`);只给其中一条加防护等于留了绕行口。上限约束的是本进程
拿解包结果做什么,不等于给 binwalk 本身套了磁盘配额。

### 5.2a 组件检测 (`detectors/`)

`manifest.yml` 是**测试夹具格式,真实固件没有**。检测器按证据强度读真实 rootfs:

| 模块 | 来源 | 强度 |
|---|---|---|
| `detectors/packages.py` | opkg / dpkg status(Debian control 格式,共用解析器) | 最强 |
| `detectors/osrelease.py` | `/etc/os-release`,识别发行版 | 中 |
| `detectors/binary.py` | ELF 里编译进去的版本 banner | 启发式 |
| `detectors/python_packages.py` | `*.dist-info/METADATA` / `*.egg-info/PKG-INFO` | 强(结构化元数据) |
| `detectors/node_packages.py` | `package.json`(含 `node_modules/` 下的依赖) | 强(结构化元数据) |

```python
def detect_components(rootfs: Path) -> list[Component]:   # 单个 rootfs
def detect_in_tree(root: Path) -> list[Component]:        # 解包树,内含嵌套 rootfs
```

要点:

- 包版本要剥掉 epoch 和打包 revision:`1:1.36.1-r2` → `1.36.1`,否则 CPE 全查不中
- 同名组件按 `DETECTOR_PRIORITY` 取最强证据,分歧写进 `extra["also_detected_by"]`,
  不静默丢弃
- binwalk 把内容 carve 进 `_image.bin.extracted/squashfs-root/`,解包树根**不是**
  rootfs,要先找嵌套的候选根
- 只读不执行,所有读取有上限
- `Component.extra` 带 `detector` / `evidence`,报告和 SBOM 能透出来源
- 二进制 banner 只收录**编译期字面量拼接**能保证的模式(如 `"name v" VERSION_STR`),
  运行时 `sprintf` 拼出来的横幅(如 libcurl)版本号和前缀分开存放,静态扫描本来就
  找不到,不收录
- **RPM 数据库检测器暂缓**:RPM header 是自定义二进制格式,在没有真实 rpmdb
  文件可供校验的情况下实现,风险是产出一个看似合理、实际解析错误的解析器——
  比不检测更糟。需要真实样本才能补上

### 5.3 CVE DB (`cve_db/` package)

```python
@dataclass
class CveRecord:
    cve: str
    cvss: float
    summary: str

def mock_lookup(c: Component) -> list[CveRecord]: ...       # 冻结的离线兜底
def local_db_lookup(db=None) -> Callable[[Component], list[CveRecord]]
def epss_lookup(cve: str) -> float: ...
def kev_lookup(cve: str) -> bool: ...

class NvdClient:
    """活满整次扫描:按 NVD 限速排队 + 按 (name, version) 缓存 + 复用连接。

    扫描要查清单里每个组件。无 API key 时限 5 req/30s,逐个新建客户端并连打
    会收 403,然后**静默降级**到 mock 数据却仍报扫描成功。
    """
    def lookup(self, component: Component) -> list[CveRecord]: ...

def nvd_lookup(c: Component, api_key=None) -> list[CveRecord]:
    """单次查询的便捷包装;扫描整个清单请用 NvdClient"""
```

CLI 用 `--cve-source {nvd,local,mock}` 选 provider。

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
    score: float          # 0.0-1.0(各项归一化后加权,权重和为 1)
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

### 5.6a HTML 报告 (`html_report.py` + `templates/report.html.j2`)

`--format {markdown,html}`,默认 markdown。HTML 是单文件自包含产物——
图表内联成 base64 data URI,不额外产出文件。

**转义是硬约束,不是可选项**:组件名、版本、CVE 描述全部来自不可信固件。
Jinja2 environment 开启 autoescape,模板**禁止**对扫描数据用 `|safe`。
`tests/test_html_report.py` 有多条用例验证脚本标签、属性逃逸、事件处理器
都被转义,不能作为回归红线放松。

### 5.7 v0.5 共享契约边界 (`v05_compat.py` / `adapter.py` / `gateway_envelope.py`)

`v05_compat.py` 是**唯一**碰 shared-llm-core §9 类型的地方。它先试顶层导出、
再试 `shared_llm_core.finding` 子模块,都没有才落到本地冻结 schema——共享类型
明明能导入却用了本地副本,会产生不同的枚举对象,静默破坏对它们的 `is` 比较。

- 全产品的 Finding 一律经 `v05_compat.new_finding()` 构造(UUID4 自动生成)
- `adapter.py` 是唯一需要 §10 gateway 层的模块,因此在包顶层**懒加载**;
  eager import 会让 gateway 层成为整个包(含根本不用它的 CLI)的硬依赖
- `gateway_envelope.py` 实现 §15 CLI envelope:`{"findings": [...], "errors": [...], "summary": {...}}`
- `tests/test_v05_boundary.py` 会遍历源码树,任何模块在边界外 import
  `shared_llm_core` 就失败

### 5.8 报告图表 (`charts.py`)

matplotlib Agg 后端(无 GUI)渲染 CVSS 严重度分布饼图,`--output` 时随报告落盘。

### 5.9 固件仿真 (`emulator.py`)

Docker 托管的 QEMU user-mode 跑固件 init,产出进程 / 监听端口 / §9 Finding。
容器硬化:`--network none`、`--read-only`、`--cap-drop ALL`、
`no-new-privileges`、非 root、pids/memory/cpu 上限、固件只读挂载。
测试注入 runner,**从不真跑 QEMU**。

### 5.10 0-day 候选预测 (`zeroday.py`)

比对清单版本与已知 CVE 证据里的版本串,相邻 release line 成为待审候选,带
置信度、类比 CVE、弱点信号。**这是排序启发式,不声称可利用性,也不分配新 CVE 编号。**

### 5.11 多智能体攻击链 (`attack_chain.py`)

向 §7 的 SCOUT / EXPLOITER / REVIEWER 发一次防御性 mission,产出
背景/攻击/后果叙述 + §9 Finding。EXPLOITER 只被要求模拟逻辑路径,
不执行固件命令、不产出可部署 exploit。

### 5.12 固件差分 (`diff.py` + `reporter.render_diff_markdown`)

```python
def diff_components(old, new) -> FirmwareDiff:
    """按名称(大小写不敏感)比对两份清单:added/removed/upgraded/
    downgraded/changed(版本排序不明确)/unchanged"""

def diff_vulnerabilities(old_matches, new_matches) -> tuple[PersistentVulnerability, ...]:
    """两次 CVE 匹配结果的交集:同一组件在新旧版本里都命中的 CVE。
    不做 CVE 查询,调用方要用同一个 lookup_fn 分别跑过两次 match_components"""
```

CLI:`firmware-agent diff --old OLD --new NEW [--cve-source ...] -o report.md`。
和 `--sbom` 一样,`diff` 要把两份清单各查一遍 CVE,所以 `--cve-source`
**默认 mock**,不是 `nvd`——避免默认情况下悄悄打两倍的限速请求。

版本排序复用 `cve_db/version.py` 的 `version_key()`,那是给嵌入式包版本用的
实用比较器,不是完整 semver 实现。OpenWrt 这类"日期+git-hash"版本号
(`2023-09-01-598d9fbb`)仍然会得到一个排序结果,但那个顺序**不代表**真实的
新旧关系——只有真正没有任何数字/字母的版本串(纯符号或空串)才会落到
`changed`(排序不明确),两个都是字母/哈希的版本串会被排出一个顺序,
即使那个顺序没有实际意义。这一点在 `diff.py` 模块文档和 README 里都写了,
不要只看 CLI 输出的 upgraded/downgraded 标签就下结论。

## 6. 数据与模型

无业务数据持久化——固件解包在临时目录,处理完删除。

**一个例外**:`cve_db/data/cve_cache.db` 是持久化的 NVD 子集缓存(gitignore),
位置可用 `AI_FIRMWARE_CVE_DB` 覆盖。它是可重新下载的派生数据,不含固件内容。

## 7. 安全与合规

- 固件可能含厂商机密,本地处理,**不上云**
- LLM 调用走共享内核,审计留痕
- 报告脱敏: 默认不含固件 hash / vendor 明细

### 7.1 处理不可信输入

固件本身是不可信输入,以下防护不可退化:

| 面 | 防护 | 位置 |
|---|---|---|
| 解压炸弹 | 解包输出的字节数 / 文件数上限,每步解包后检查 | `extraction.py` |
| 执行风险 | 只读取,**从不执行**固件内任何文件;仿真必须在 §5.9 沙箱里 | `detectors/`、`parsers/` |
| SSRF | `firmware_url` 下载:解析出的**每个** IP 都要校验非私网 | `gateway_envelope.py` |
| SSRF(重定向) | 手动逐跳跟随并重新校验,跳数有上限。**不可**用 `follow_redirects=True` | `gateway_envelope.py` |
| 下载体积 | 流式写盘时超过 `MAX_FIRMWARE_BYTES` 立即中止 | `gateway_envelope.py` |

已知残留风险:DNS rebinding 未完全关闭——校验之后连接会再解析一次。下载物
一律按不可信输入对待。

### 7.2 依赖自身安全

CI 跑 `pip-audit --strict`。报告别人组件漏洞的工具不该带着自己的漏洞出货。

## 8. 部署

- CLI: `firmware-agent scan -i fw.bin -o report.md`
- `--demo` 模式用内置 mock 组件
- Docker: 镜像 < 500 MB
- 接 NVD: 环境变量 `NVD_API_KEY`

## 9. 评估指标

评测基线见 `benchmarks/`(EVAL-001)。**读 `benchmarks/README.md` 里"测量范围"
那张表再看下面的数字**——每一条现状都有明确的适用边界,不要脱离边界引用。

| 指标 | 目标 | 现状 |
|------|------|------|
| 组件识别准确率 | ≥ 95% (主流组件) | **部分测量**。`detectors/packages.py`(opkg/dpkg 解析 + `upstream_version()`)对着 135 包的真实 OpenWrt 官方 manifest 跑,name-level 与 name+version-level precision/recall/F1 均为 1.000——这证明解析器在 135 条真实、格式各异的版本串(git-hash 日期、多段 revision、裸整数)上不会解析错或漏解析,但**不是**独立标注下的准确率:该语料的 rootfs 是从同一份 manifest 生成的,expected.yml 天然不会包含 manifest 之外的内容,结构上不可能出现误报。`detectors/binary.py` / `detectors/osrelease.py` 仍未有真实语料验证,只在自检夹具(`benchmarks/corpus/harness-selfcheck/`)里跑过——那份夹具是为了验证跑分脚本本身算得对,不是准确率语料。 |
| CVE 匹配召回率 | ≥ 90% | **未测量**——需要真实 NVD 数据核对,而这个环境 `services.nvd.nist.gov` 被出网策略挡了(403),本地缓存 `cve-db sync` 依赖同一条网络。 |
| PRisk 排序与人工一致 | ≥ 80% (Top 10) | **未测量**——需要人工标注的优先级排序基线,目前没有。 |
| 报告生成时间 | < 30s (10MB 固件) | **部分测量**。`benchmarks/run.py --time-scan` 实测:135 组件的 `detect_components` + mock CVE 匹配 + PRisk 打分,全流程约 2ms(见下方实测输出)。**不包含** binwalk/unsquashfs 解包耗时——这个环境没装 binwalk(`BinwalkRunner().is_available()` 返回 `False`),这一步完全没法测。真实固件的端到端耗时瓶颈几乎必然在解包和 `--cve-source nvd` 的网络请求(无 key 时 5 req/30s,135 包约 13 分钟),不在检测/打分本身。 |

```
$ poetry run python benchmarks/run.py --time-scan

=== harness-selfcheck ===
  expected: 3   detected: 3
  name-level    precision=0.667 recall=0.667 f1=0.667
  name+version  precision=0.333 recall=0.333 f1=0.333

=== openwrt-23.05.5-ath79-tiny ===
  expected: 135   detected: 135
  name-level    precision=1.000 recall=1.000 f1=1.000
  name+version  precision=1.000 recall=1.000 f1=1.000

=== timing: rootfs (135 components) ===
  detect_components:           1.8 ms
  match_components (mock):     0.1 ms
  score_and_rank_matches:      0.1 ms
  total:                       1.9 ms
```

`harness-selfcheck` 的 0.667/0.333 不是"检测器表现差"——那份夹具是刻意构造成
每种结果各占一例(命中/版本错/漏检/误报),用来验证跑分脚本的算术本身是对的,
在 `tests/test_benchmark_harness.py` 里有对应的手算断言。

仍然是那句话:**未测量的部分不要在文档或对外材料里说成已达成**,已测量的
部分也要带着上面写明的适用边界一起引用,不要只截取数字。

## 10. 路线图

| 阶段 | 内容 |
|------|------|
| PoC | mock 固件 + mock CVE + 富化 |
| **v0.1 S1** | 接 NVD/EPSS/KEV 真实 API |
| **v0.1 S2** | 真实固件解包 + PRisk 公式 |
| **v0.1 S3** | 报告图表 + Docker + CI |
| **v0.5** | CycloneDX SBOM 输出 ✅ |
| v0.7 (当前) | 本地 CVE 缓存 + VEX + 真实组件检测,278 passed |
| **v1.0** | 厂商指纹(差分分析、评测基线已在 v0.7 完成) |

## 11. 接口契约

依赖 `shared-llm-core`。所有 LLM 调用通过 `LLMRouter`。
v0.5 的 §7 / §9 / §10 / §15 契约面见 §5.7——所有共享类型只经 `v05_compat.py`。

## 12. 风险

- **真实固件格式碎片**: 每家厂商不同 → 先覆盖 binwalk 主流格式
- **CVE 数据膨胀**: NVD 30万条 → 本地缓存(已做,只同步 embedded_components.json 名单)
- **PRisk 公式**: 权重是经验值,需实战调优(目前无评测基线可验证,见 §9)
- **两套解包栈并存**: 同步 `unpack.py` 与异步 `binwalk_runner.py`,能力互补;
  安全防护已拉平,但收敛主线是待决策项(见 docs/TODO.md ARCH-001)

## 13. 关键文件

解包与检测:

- `unpack.py` — 同步解包(binwalk -Me + unsquashfs 回退),CLI / envelope 走这条
- `extraction.py` — 解包体积上限,两条解包路径共用
- `binwalk_runner.py` + `parsers/binwalk.py` — 异步解包,`scanner.py` 走这条
- `detectors/` — 真实 rootfs 组件检测(packages / osrelease / binary)
- `parsers/mock.py` — manifest.yml 夹具解析

CVE 与评分:

- `cve_db/` — 本地 SQLite 缓存(`schema.sql` / `sync.py` / `query.py` / `version.py`)
- `cve_db/mock.py` — 冻结的离线兜底数据
- `nvd.py` — `NvdClient`,限速 + 缓存 + 连接复用
- `eps.py` / `kev.py` — FIRST EPSS / CISA KEV
- `scoring.py` — PRisk

输出:

- `analyzer.py` — 匹配 + LLM 富化
- `reporter.py` — Markdown 报告
- `charts.py` — 分布饼图
- `sbom/cyclonedx.py` — CycloneDX 1.5 + VEX

契约与集成:

- `v05_compat.py` — v0.5 §9 类型的唯一边界
- `adapter.py` — §10 in-process 适配器(懒加载)
- `gateway_envelope.py` — §15 CLI envelope + 下载防护
- `scanner.py` — 异步扫描编排

扩展能力:

- `emulator.py` / `zeroday.py` / `attack_chain.py`

其他:

- `_version.py` — 版本单一来源(User-Agent、SBOM metadata 都从这里取)
- `samples/firmware_demo/` — PoC demo 固件
- `tests/fixtures/rootfs/` — **无 manifest** 的真实形态 rootfs 夹具
- `docs/TODO.md` — issue 清单

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

**Schema**(实际实现,`cve_db/schema.sql`):

```sql
-- 主键必须是 (cve_id, cpe_id) 复合键:一个 CVE 影响多条 CPE。
-- 早期版本用单列 cve_id 主键,导致同一 CVE 的其余 CPE 被最后写入的那条覆盖,
-- 绝大多数版本因此查不出来。不要改回单列。
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id TEXT NOT NULL,
    cpe_id TEXT NOT NULL,         -- "cpe:2.3:a:openbsd:openssh:8.5p1:*:*:*:*:*:*:*"
    cvss_v3 REAL,
    description TEXT,
    in_known_exploited BOOLEAN DEFAULT 0,
    product TEXT,                 -- 从 CPE 解析出的 product,查询走索引
    version_start_including TEXT, -- NVD 的版本区间,必须入库
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cve_id, cpe_id)
);
CREATE INDEX IF NOT EXISTS idx_cpe ON cve_entries(cpe_id);
CREATE INDEX IF NOT EXISTS idx_product ON cve_entries(product);
```

schema 变更通过 `PRAGMA user_version` 版本化(`query.py:SCHEMA_VERSION`)。
缓存是可重新下载的派生数据,版本不匹配时**重建**而非原地迁移。

**版本匹配**:NVD 用两种方式表达"受影响"——字面 CPE 版本,以及通配 CPE +
`versionStartIncluding` / `versionEndExcluding` 区间。两种都要支持,只认字面
版本会丢掉大部分记录。无任何边界的通配 CPE **不算命中**("影响所有版本"不可行动)。
比较逻辑在 `cve_db/version.py`。

**API**:

```python
class EmbeddedCVEDatabase:
    def __init__(self, db_path: Path | None = None):
        """默认位置可用 AI_FIRMWARE_CVE_DB 覆盖(只读安装 / 容器场景)"""

    async def sync(self, *, client=None, sleep=asyncio.sleep) -> int:
        """下载 NVD 记录 upsert。返回**实际落库**行数(不是尝试写入数)"""

    async def lookup(self, component: str, version: str) -> list[CVEEntry]:
        """按 product + 版本(字面或区间)查,每个 CVE 返回一条"""

    def lookup_sync(self, component: str, version: str) -> list[CVEEntry]: ...
    async def stats(self) -> dict[str, int]: ...
```

**集成方式**:

- `scanner.py` —— 扫描出组件 + 版本后调 `db.lookup(...)`,命中 CVE 时产 Finding
- CLI:`cve-db sync` / `cve-db status` 显式命令;`scan --cve-source local` 用缓存查
- **不做**首次启动自动 sync:扫描要能离线、可预测地跑,后台下载会让首次扫描
  静默变成几分钟的网络操作
- 限速:有 `NVD_API_KEY` 时 50 req/30s,没有时 5 req/30s

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

**CycloneDX 1.5 BOM 形状**(实际实现):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {"tools": [{"vendor": "longyuanai", "name": "ai-firmware-agent", "version": "0.1.0"}]},
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:generic/openssh@8.5p1",
      "name": "openssh",
      "version": "8.5p1",
      "licenses": [{"license": {"name": "BSD-2-Clause"}}],
      "purl": "pkg:generic/openssh@8.5p1"
    }
  ],
  "vulnerabilities": [
    {
      "bom-ref": "vuln:CVE-2018-15473",
      "id": "CVE-2018-15473",
      "source": {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473"},
      "ratings": [{"source": {"name": "NVD"}, "severity": "medium", "method": "CVSSv3", "score": 5.3}],
      "affects": [{"ref": "pkg:generic/openssh@8.5p1"}],
      "properties": [
        {"name": "ai-firmware-agent:epss", "value": "0.012300"},
        {"name": "ai-firmware-agent:kev", "value": "false"}
      ]
    }
  ]
}
```

约束:

- 输出**确定性**——无时间戳、无随机 `serialNumber`,SBOM 要能跨构建 diff
- 一个 CVE 影响多个组件时合并成一条,多个 `affects` ref
- EPSS / KEV 无 CycloneDX 原生字段,走 `ai-firmware-agent:*` properties

**CLI 增量**:

```bash
ai-firmware-agent scan --input '{...}' --sbom output/sbom.json
```

SBOM 是全清单批量导出,而 NVD provider 每组件一次请求(自带的 OpenWrt 样本
135 个包)。因此未显式传 `--cve-source` 时,VEX 段留在离线源。

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

预期:≥ 278 passed;CLI envelope 仍是 `{"findings": [...], "summary": {...}}`。

注意:CI 只测 **Python 3.11**(`pyproject` 是 `^3.11`)。用其他版本本地验证前,
先确认它也在 CI 矩阵里,否则本地绿、CI 红。

---

**最近修订**: 2026-07-25 · Claude 把 PHASE-2.md 合并进 §14
**下次回看触发**: v0.6 启动 / Hook A 启动 / CVE DB 同步