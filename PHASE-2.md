# 006AI-Firmware-Security-Agent · Phase-2 计划

> **本仓角色**: AI 固件扫描 Agent。`binwalk` 提取 + 已知 CVE 匹配 + SBOM 关联,产出 firmware finding。
> **当前状态**: v0.6 §15 CLI Envelope 已实现,S5 worker 4 件套全绿,F 绿。
> **下一阶段**: v0.7+ 真 binwalk + 持久化 FindingRegistry + 嵌入式 CVE 数据库。

---

## 现状摘要(2026-07-25)

| 项 | 状态 |
|----|------|
| v0.1 LLM 集成 | ✅ |
| v0.5 Finding schema | ✅ |
| 1 种 firmware path 输入 | ✅ |
| `tests/fixtures/sample.bin` fixture | ✅ |
| CLI 子命令 `scan --input '<json>' --json` | ✅ |
| S5 worker 4 件套 | ✅ PASS |

---

## Phase-2 hooks

### Hook A · 真实 binwalk 集成(派活 026-FW-BINWALK)

**目标**:替换 mock 解包为 `binwalk -e` 调用,**真**提取文件系统 + 内核 + 应用。

**派活文档**:`026-FW-BINWALK.md`(待起草)

```python
# src/ai_firmware_agent/binwalk_runner.py
class BinwalkRunner:
    async def extract(self, firmware_path: Path, *, output_dir: Path) -> ExtractResult:
        proc = await asyncio.create_subprocess_exec(
            "binwalk", "-e", "--directory", str(output_dir), str(firmware_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        ...
```

- 测试:用 `tests/fixtures/sample.bin`(已有)
- 真集成测试要装 `binwalk`(Extras 依赖,**不强求**;mock 也行)

**为什么 Phase-2**:
- 现在 fixture 是 mock
- 真固件(路由器 / IoT)必须真解包

### Hook B · 嵌入式 CVE 数据库(本地 NVD 子集)

**目标**:frequently-embedded 软件(openssh / busybox / dnsmasq 等)的 CVE 本地查询。

**派活文档**:`027-FW-CVE-DB.md`(待起草)

- 启动时下载一次 NVD CPE match,本地 SQlite
- 离线可用,无 API 限速

**为什么 Phase-2**:
- 嵌入式扫描常在隔离环境跑
- 不在线就要有本地 DB

### Hook C · SBOM 输出(CycloneDX)

**目标**:导出 CycloneDX 1.5 SBOM,从 firmware extract 出 component + version + license。

**派活文档**:`028-FW-SBOM.md`(待起草)

- 复用 Hook A 的 extract 结果
- 与 002 VULN 的 SBOM 集成对齐

---

## v1.0 路线图

```
v0.5 已冻结:CLI envelope + binary ID
v0.6: Hook A (真 binwalk)
v0.7: Hook B (本地 CVE DB) + Hook C (SBOM)
v1.0: 与 NVD CPE 实时同步 + 与 002 VULN 双向关联
```

---

## 不要做的事

- ❌ 不要真跑 firmware(可能含漏洞代码)— sandbox 内或 dry-run
- ❌ 不要把 firmware 内容写日志(隐私 / 体积)
- ❌ 不要破坏 v0.5 §15 envelope 的 source=`006` 注入

---

**最近修订**: 2026-07-25 · Claude 起草 Phase-2 计划
**下次回看触发**: v0.6 启动 / Hook A 启动
