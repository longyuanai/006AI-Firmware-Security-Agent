# 006 AI Firmware Security Agent · 开源能力融合实施方案

> 状态：实施中（静态 Provider 第一阶段已完成）
> 日期：2026-07-29
> 范围：方案设计，不代表功能已经实现
> 契约：保持 v0.5 `Finding` schema、`source="006"` 与 §15 envelope 不变

## 0. 实施进度

截至 2026-07-29：

- [x] Provider capability 与 inventory 基础协议
- [x] Binwalk 提取文件数、体积、symlink 和越界保护
- [x] Unblob 可选 CLI adapter
- [x] Syft 可选 filesystem inventory adapter
- [x] CVE Binary Tool 离线 component adapter
- [x] 多源组件、PURL、license、evidence、confidence 合并
- [x] Scanner 的 Binwalk → Unblob → mock fail-open 链
- [x] `capabilities --json` 工具发现命令
- [x] CycloneDX evidence/properties 与原子写入
- [x] Docker static worker 与固定镜像 digest
- [ ] OpenVEX/CycloneDX VEX triage
- [x] 跨版本组件和漏洞 diff
- [ ] 持久化固件 registry
- [ ] FirmAE/QEMU 独立 lab worker

当前完成项只声明适配和测试已实现，不表示本机已安装 Binwalk、Unblob、Syft 或 CVE Binary Tool。

## 1. 目标

本方案融合以下开源项目的核心特点，同时保持 006 为轻量、可测试、可降级的 Python Agent：

- Binwalk v3：固件签名识别、提取和熵分析
- Unblob：精确 chunk 边界、递归解包、未知区块 carving 和插件机制
- EMBA：静态分析、动态分析、SBOM、漏洞报告的完整流水线
- FACT_core：多分析器编排、插件隔离、结果浏览、搜索和样本比较
- FirmAE：QEMU 全系统仿真、启动修复、网络识别和动态验证
- CVE Binary Tool：二进制组件/version Checker、多源漏洞数据和离线扫描
- Syft：文件系统组件清单、PURL 和 CycloneDX/SPDX SBOM
- Grype：SBOM 驱动的漏洞匹配、EPSS、KEV、VEX 和风险排序
- CycloneDX Python Library：标准 BOM 数据模型、序列化和校验

融合不等于复制所有代码。006 只维护统一编排、契约转换、证据融合、PRisk 和安全策略；成熟能力通过 CLI、Docker 或可选 Python Provider 复用。

## 2. 设计原则

1. **静态分析优先**：默认不执行固件中的二进制、脚本或 init。
2. **能力可发现**：每个外部工具先执行 availability/capability check。
3. **失败开放**：单个工具失败只降低结果完整度，不让扫描和 envelope 崩溃。
4. **证据优先**：Finding 必须能够追溯到组件、版本、文件路径和识别引擎。
5. **多源交叉验证**：包数据库、字符串特征、SBOM 和漏洞数据库结果合并去重。
6. **契约冻结**：不修改共享 `Finding` schema，不改变 v0.5 §15 envelope。
7. **隔离 GPL 工具**：EMBA、FACT 等以独立进程或容器使用，不复制或链接其代码。
8. **Windows 兼容**：Windows 负责 CLI、编排和测试；真实固件工具运行在 Linux Docker Worker。
9. **可复现**：记录工具名称、版本、配置、数据库时间和固件哈希，不记录固件内容。
10. **渐进增强**：没有 Docker、Binwalk、Syft 或网络时，仍可使用内置 mock/SQLite 完成基础扫描。

## 3. 能力融合矩阵

| 能力 | 首选实现 | 补充实现 | 006 自研部分 | 降级路径 |
|---|---|---|---|---|
| 固件识别与解包 | Binwalk v3 | Unblob | Runner、超时、沙箱、结果归一化 | MockExtractor |
| 递归提取与 carving | Unblob | Binwalk matryoshka/carve | 深度、体积、文件数策略 | 只扫描输入文件 |
| 文件系统组件识别 | Syft | 原生 dpkg/opkg/apk/parser | 组件归一化、PURL/CPE 映射 | embedded_components 字符串匹配 |
| 二进制组件识别 | CVE Binary Tool Checker | `strings`/正则解析器 | 证据评分和去重 | 内置版本规则 |
| 已知漏洞查询 | EmbeddedCVEDatabase | CVE Binary Tool/Grype | NVD、EPSS、KEV 合并 | mock_lookup |
| 风险排序 | 现有 PRisk | Grype risk 作为参考信号 | 固件 Exposure/Exploit 权重 | CVSS-only |
| SBOM | CycloneDX Python Library | Syft CycloneDX 输出 | 固件元数据、证据属性 | 最小合法 BOM |
| VEX/误报抑制 | Grype/OpenVEX | CVE Binary Tool VEX | triage 状态映射 | 不过滤，仅标记 |
| 静态规则分析 | EMBA 模块思想 | 内置规则 Provider | 硬编码密码、危险配置等 Finding | 跳过不可用规则 |
| 结果编排与比较 | FACT 插件思想 | SQLite/JSON registry | Provider 生命周期、缓存、diff | 单次报告 |
| 动态仿真 | FirmAE Docker Worker | QEMU user-mode | 作业管理、输出归一化 | 静态分析结果 |
| 报告 | 现有 Markdown/PNG | EMBA 风格 Web 报告 | Finding/envelope/PRisk narrative | JSON envelope |

## 4. 总体架构

```text
CLI / IntegrationGateway
           │
           ▼
┌──────────────────────────────────────────────┐
│ ScanOrchestrator                             │
│ 输入校验、策略、超时、缓存、事件与降级状态  │
└──────────────┬───────────────────────────────┘
               │
     ┌─────────▼─────────┐
     │ AcquisitionPolicy │
     │ path/url/hash/size │
     └─────────┬─────────┘
               │
     ┌─────────▼───────────────────────────────┐
     │ Extractor Providers                     │
     │ Binwalk → Unblob → Mock                 │
     └─────────┬───────────────────────────────┘
               │ ExtractResult
     ┌─────────▼───────────────────────────────┐
     │ Inventory Providers                     │
     │ Native Parser + Syft + CVE Binary Tool  │
     └─────────┬───────────────────────────────┘
               │ NormalizedComponent[]
     ┌─────────▼───────────────────────────────┐
     │ Vulnerability Providers                 │
     │ SQLite/NVD + EPSS + KEV + optional Grype│
     └─────────┬───────────────────────────────┘
               │ VulnerabilityEvidence[]
     ┌─────────▼───────────────────────────────┐
     │ Correlation + PRisk + Finding Adapter   │
     └──────┬──────────────────┬───────────────┘
            │                  │
   Finding envelope      CycloneDX 1.5 SBOM
            │
            └──────► Report / Registry / Diff

可选隔离分支：
ExtractResult → DynamicAnalysisQueue → FirmAE/QEMU Docker Worker
```

## 5. 核心内部模型

内部模型不属于共享契约，可独立演进；最终由 Adapter 转成冻结的 `Finding`。

### 5.1 ToolCapability

- `name`
- `version`
- `available`
- `mode`: local / docker / mock
- `reason`
- `features`

### 5.2 ExtractResult

沿用 `tech-spec.md` §14 的字段，并允许向后兼容地增加内部元数据：

- firmware_path
- output_dir
- files
- signatures
- error
- extractor
- extractor_version
- warnings
- truncated
- duration_ms

### 5.3 NormalizedComponent

- name
- version
- vendor
- type
- purl
- cpes
- licenses
- evidence_paths
- detection_sources
- confidence

### 5.4 VulnerabilityEvidence

- cve
- component
- version
- cvss
- epss
- kev
- exploit_signal
- exposure_signal
- affected_match
- providers
- database_updated_at
- confidence

## 6. Provider 选择策略

### 6.1 解包

1. 本地 Binwalk v3 可用时调用 Binwalk。
2. 本地不可用但 Docker profile 启用时，调用固定版本 Binwalk 镜像。
3. Binwalk 不支持或输出异常时，可选调用 Unblob。
4. 所有真实解包器不可用或失败时，使用 MockExtractor。
5. fallback 必须写入 warning/summary，但不改变合法 envelope。

Binwalk 和 Unblob 不应同时无条件运行。默认只运行首选解包器；只有识别为空、关键格式未提取或用户启用交叉验证时才运行第二解包器。

### 6.2 组件识别

组件识别采用并集合并，而非单选：

1. 原生解析器读取 dpkg/opkg/apk 等包元数据。
2. Syft 扫描提取后的 rootfs，提供标准组件和 PURL。
3. CVE Binary Tool Checker 扫描二进制版本字符串。
4. 内置 embedded component 规则补充 BusyBox、OpenSSL、Dropbear、dnsmasq 等常见组件。
5. 使用规范化名称、版本和 PURL/CPE 合并结果。

置信度建议：

- 包管理数据库精确记录：0.95
- Syft 包识别：0.90
- 多个二进制特征同时命中：0.85
- 单一版本字符串：0.65
- 文件名推断：0.40

### 6.3 漏洞匹配

1. `EmbeddedCVEDatabase` 保持为稳定公共门面。
2. 本地 SQLite 是默认离线后端。
3. NVD、OSV 等同步过程独立于扫描过程，避免每次扫描联网。
4. EPSS 和 KEV 作为 enrichment，不决定 CVE 是否命中。
5. Grype/CVE Binary Tool 可作为第二意见；冲突时保留各方证据。
6. 版本仅字符串命中时降低 confidence，不直接标记为已确认可利用。

## 7. PRisk 融合

保持现有公式不变：

```text
PRisk =
0.25 × CVSS
+ 0.25 × EPSS
+ 0.20 × KEV
+ 0.15 × Exploit
+ 0.15 × Exposure
```

新增工具只提供输入信号：

- CVSS：SQLite/NVD/CVE Binary Tool/Grype
- EPSS：FIRST EPSS 或已缓存 enrichment
- KEV：CISA KEV 或 Grype enrichment
- Exploit：公开 exploit、EMBA 静态信号、可选动态验证
- Exposure：监听端口、Web 服务、默认配置、组件可达性

Grype 的 risk score 只作为证据，不替换 PRisk，避免破坏项目既有评分语义。

## 8. SBOM 与 VEX

### 8.1 CycloneDX 1.5

使用 CycloneDX Python Library 创建和校验 BOM，至少输出：

- firmware metadata 和 SHA-256
- components
- version
- licenses
- PURL/CPE
- hashes
- evidence
- detection provider/confidence properties
- dependency graph（能够推断时）

Syft 生成的 CycloneDX 可以作为输入，但最终由 006 归一化后重新输出，保证字段和固件元数据一致。

### 8.2 VEX

后续可读取 OpenVEX/CycloneDX VEX：

- `affected`
- `not_affected`
- `fixed`
- `under_investigation`

VEX 只能调整 triage 和展示，不删除原始漏洞证据。

## 9. 动态分析隔离

FirmAE/QEMU 能力不进入默认扫描流程，独立为 `DynamicAnalysisWorker`：

- 仅在用户显式启用后运行
- 仅处理自有、授权、靶场或公开测试固件
- Linux 专用 Worker
- 独立 Docker 网络和临时目录
- 不使用宿主机网络
- CPU、内存、PID、磁盘和运行时间限制
- 只收集进程、监听端口、启动状态和服务 banner
- 不执行主动 exploit

动态结果用于提高或降低 Exposure/Exploit confidence，而不是直接宣称漏洞已成功利用。

## 10. 安全控制

### 10.1 解包安全

- 校验输入是普通文件
- 固件输入只读挂载
- 拒绝绝对路径和 `..` 越界
- 拒绝逃逸输出目录的 symlink
- 限制最大递归深度
- 限制提取文件数、单文件大小和总大小
- 超过限制时标记 `truncated`，保留已获得结果
- 超时后终止整个子进程树

### 10.2 数据与日志

- 不记录固件字节、配置内容、密码或私钥
- 默认只记录哈希、大小、工具版本、阶段状态和错误类型
- evidence 使用相对路径
- 报告输出前进行敏感信息过滤
- API Key 只从环境变量或参数传入，不写入配置、日志和数据库

### 10.3 容器

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `no-new-privileges`
- 非 root 用户
- 临时输出卷
- 固定镜像 digest
- 资源与超时限制

## 11. Windows 与部署

支持三种 profile：

### portable

- Windows 原生 Python
- MockExtractor
- 内置组件规则
- SQLite 离线 CVE
- 适合单元测试和无 Docker 环境

### standard

- Windows Python 编排
- Docker 中运行 Binwalk/Unblob/Syft
- 本地 SQLite、NVD/EPSS/KEV enrichment
- 推荐的开发和生产模式

### lab

- Linux Worker
- standard 全部能力
- EMBA/FirmAE/QEMU 动态分析
- 只用于授权实验环境

## 12. 实施阶段

### Phase A：Provider 基础设施

- 定义 capability、extractor、inventory、vulnerability provider 协议
- 增加统一 timeout/error/warning 结果
- 保持 scanner、Finding 和 envelope 外部接口不变

### Phase B：真实解包

- Binwalk v3 adapter
- JSON/文本结果解析
- Unblob 可选 adapter
- Mock fallback
- 解包安全限制

### Phase C：组件融合

- 原生包数据库解析
- Syft 可选 adapter
- CVE Binary Tool 可选 adapter
- 名称、版本、PURL/CPE、证据和置信度合并

### Phase D：漏洞融合

- 保持 EmbeddedCVEDatabase API
- SQLite 离线查询和独立同步
- NVD/EPSS/KEV enrichment
- Grype 可选交叉验证
- 误报和冲突证据保留

### Phase E：标准输出

- CycloneDX Python Library
- CycloneDX 1.5 schema validation
- SBOM 原子写入
- envelope、Markdown、PNG 报告保持兼容

### Phase F：平台能力

- Provider 执行记录
- 固件扫描 registry
- 同一型号/版本间组件和漏洞 diff
- 可选 REST/Web 查询，不照搬 FACT UI

### Phase G：动态实验

- 独立 FirmAE/QEMU Docker Worker
- 进程和监听端口采集
- 动态证据反馈到 PRisk
- 默认关闭

## 13. 测试策略

### 单元测试

- Provider availability
- subprocess 参数、超时和异常
- parser 和结果归一化
- 组件合并、冲突和 confidence
- CVE offline lookup
- CycloneDX schema
- Finding/envelope 冻结契约

### 契约测试

- 缺少全部外部工具仍返回合法 envelope
- 任一 Provider 崩溃不影响其他 Provider
- `source="006"` 保持不变
- Finding schema 不增加或删除字段
- `--sbom` 失败不破坏 JSON 扫描结果

### 集成测试

- 使用公开、无执行的小型固件 fixture
- Binwalk、Unblob、Syft、CVE Binary Tool 测试标记 `integration`
- 默认测试不要求外部工具和网络
- 真实工具结果使用范围断言，不依赖不稳定的完整输出

### 差分测试

对同一 fixture 比较：

- Binwalk 与 Unblob 的提取文件集合
- 原生解析器、Syft 和 CVE Binary Tool 的组件集合
- SQLite、CVE Binary Tool 和 Grype 的 CVE 集合

差分用于发现覆盖缺口，不要求不同工具结果完全一致。

## 14. 不纳入当前实现的内容

- 不复制 EMBA 或 FACT 的完整代码和 UI
- 不在默认扫描中启动 FirmAE/QEMU
- 不主动执行 exploit
- 不把所有外部工具变成强制生产依赖
- 不为支持新工具修改共享 Finding schema
- 不让在线 API 成为离线扫描的必要条件
- 不因为某个工具报告 CVE 就宣称漏洞可利用

## 15. 推荐决策

建议按以下配置开工：

1. 采用轻量 Provider 架构。
2. Binwalk v3 为主解包器，Unblob 为可选补充。
3. 原生解析器、Syft、CVE Binary Tool 联合识别组件。
4. 现有 SQLite/NVD/EPSS/KEV/PRisk 保持核心地位。
5. Grype作为可选交叉验证器。
6. CycloneDX Python Library 负责标准输出。
7. EMBA/FACT 仅借鉴流水线、插件和比较能力。
8. FirmAE/QEMU 延后做独立 lab profile。

## 16. 参考项目

- https://github.com/ReFirmLabs/binwalk
- https://github.com/onekey-sec/unblob
- https://github.com/e-m-b-a/emba
- https://github.com/fkie-cad/FACT_core
- https://github.com/pr0v3rbs/FirmAE
- https://github.com/ossf/cve-bin-tool
- https://github.com/anchore/syft
- https://github.com/anchore/grype
- https://github.com/CycloneDX/cyclonedx-python-lib
