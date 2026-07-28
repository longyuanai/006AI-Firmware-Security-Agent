# 006 AI-Firmware-Security-Agent · v0.1 TODO

> **项目状态**: v0.7 ✅ (278 passed / 4 skipped)
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
| CI-001 | GitHub Actions: lint + pytest + type check | done | 2026-07-24 | 2026-07-24 | Windows/Linux matrix + Ruff + mypy |
| EMULATE-001-A | Docker 隔离 QEMU user-mode 固件 emulation | done | 2026-07-24 | 2026-07-24 | mipsel/arm + 进程/监听端口 Finding |
| ZERODAY-001-A | 组件版本 + 已知 CVE 模式 0-day 候选 | done | 2026-07-24 | 2026-07-24 | 相邻 release line + 置信度/理由 Finding |
| ATTACKCHAIN-001-A | firmware 漏洞到 root shell 攻击链还原 | done | 2026-07-24 | 2026-07-24 | §7 SCOUT/EXPLOITER/REVIEWER + §9 Finding |
| FW-CLI-001 | IntegrationGateway FirmwareAdapter JSON CLI 契约 | done | 2026-07-24 | 2026-07-24 | path/url payload + Finding envelope |
| FW-LIVE-001 | 公开固件样本 + IntegrationGateway 联调 | done | 2026-07-24 | 2026-07-24 | OpenWrt 23.05.5 + official manifest + registry E2E |
| CVEDB-FIX-001 | CVE 缓存复合主键 + NVD 版本区间 | done | 2026-07-27 | 2026-07-27 | 单列主键会覆盖同 CVE 其余 CPE |
| CVEDB-CLI-001 | `cve-db sync/status` + `--cve-source local` | done | 2026-07-27 | 2026-07-27 | 本地缓存原先无产品入口 |
| SEC-001 | SSRF 全解析地址校验 + 逐跳重定向 + 解包体积上限 | done | 2026-07-27 | 2026-07-27 | |
| V05-BOUND-001 | Finding 统一经 v05_compat + adapter 懒加载 | done | 2026-07-27 | 2026-07-27 | 源码树扫描测试守护 |
| SBOM-VEX-001 | CycloneDX vulnerabilities (VEX) 段 | done | 2026-07-27 | 2026-07-27 | 确定性输出,含 EPSS/KEV properties |
| NVD-PERF-001 | NvdClient 限速 + 缓存 + 连接复用 | done | 2026-07-27 | 2026-07-27 | 原先每组件新建客户端且不限速 |
| FW-DETECT-001 | 真实固件组件检测器 (opkg/dpkg/os-release/ELF) | done | 2026-07-27 | 2026-07-27 | 此前真实固件一律返回空清单 |
| SPEC-001 | tech-spec 与代码同步 | done | 2026-07-27 | 2026-07-27 | 原 §14.2 仍写着已修复的单列主键 |

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

---

## 待派 Codex 的任务(按优先级)

> 卡片格式见 [CODEX_INSTRUCTIONS.md](CODEX_INSTRUCTIONS.md)。
> 当前基线:**278 passed / 4 skipped**,ruff + mypy 全绿。

| ID | 任务 | 优先级 | 阻塞点 |
|----|------|--------|--------|
| ARCH-001 | 收敛两套解包栈 | P1 | **需先决策主线** |
| EVAL-001 | §9 指标的评测基线 | P1 | 无 |
| ~~RPT-HTML-001~~ | ~~HTML 报告~~ | done | — |
| ~~DETECT-002~~ | ~~扩充检测器覆盖面~~ | done(部分) | RPM 暂缓,见下 |
| DETECT-002 | 扩充检测器覆盖面 | P2 | 无 |
| DIFF-001 | 固件差分分析 | P3 | 无 |
| FINGERPRINT-001 | 厂商/OEM 指纹识别 | P3 | 无 |
| ENG-001 | poetry.lock + ruff format 决策 | P3 | 需先定风格 |

---

### ARCH-001 · 收敛两套解包栈(P1,**待决策**)

现状:两条解包路径并存,能力互补,谁都不能直接删。

| | 栈 A(产品路径) | 栈 B(仅 scanner.py) |
|---|---|---|
| 实现 | `unpack.py`,同步,runner 可注入 | `binwalk_runner.py`,异步 |
| 命令 | `binwalk -Me` + `unsquashfs` 回退 | `binwalk -e` |
| 调用方 | `cli.py` / `gateway_envelope.py` | `scanner.py` |

体积上限已抽到 `extraction.py` 两边共用,安全防护是平的。但收敛必然丢一边:
要么丢 `unsquashfs` 回退和可注入 runner(测试全靠它),要么丢异步设计。

**派活前需要你先回答**:主线选同步还是异步?`scanner.py` 是要接进 CLI,
还是只作为 §10 适配器的内部实现?定了我再写卡。

---

### EVAL-001 · 建立 §9 指标的评测基线(P1)

```
[EVAL-001] 006 AI-Firmware-Security-Agent · 评测基线与跑分脚本

## 背景
- tech-spec §9 定了 4 个指标,目前**一个都无法测量**,没有语料也没有跑分脚本
- FW-DETECT-001 已让真实固件能出组件,现在具备了可测量的前提

## 必须做的事
1. 新建 benchmarks/corpus/,每个样本一个目录:
   firmware 或 rootfs + expected.yml(人工标注的组件清单 + 版本)
   先放 3-5 个公开固件(OpenWrt / DD-WRT 等,记录来源 URL + SHA-256)
2. 新建 benchmarks/run.py:
   - 对每个样本跑 detect_components,与 expected.yml 比对
   - 输出 precision / recall / F1,以及漏检、误检、版本错三类明细
   - 组件识别耗时与端到端报告耗时
3. 新建 tests/test_benchmark_harness.py:用小夹具验证跑分脚本本身算得对
   (不跑真语料,真语料标 @pytest.mark.integration 默认 skip)
4. 结果写回 tech-spec §9 的"现状"列,**如实填**,不达标就写不达标

## 必须满足的约束
- 语料里的固件如体积大,只提交 rootfs 摘要或下载脚本,不要把大二进制入库
- 跑分脚本不得联网(CVE 相关指标用 --cve-source mock/local)
- Windows 兼容

## 不要做的事
- 不要为了让数字好看去调标注
- 不要把未达标的指标在 README 里写成已达成

## 验收
- [ ] pytest 全绿(基线 278 passed)
- [ ] 新增测试 ≥ 6 个
- [ ] benchmarks/run.py 能跑出一份报告,粘贴输出
- [ ] tech-spec §9 现状列已按真实结果更新
```

---

### RPT-HTML-001 · HTML 报告(P2)

```
[RPT-HTML-001] 006 AI-Firmware-Security-Agent · HTML 报告输出

## 背景
- tech-spec §3 把 HTML 报告列为 Should,至今未做
- jinja2 已在 pyproject 依赖里,但全仓**零引用**——要么用起来,要么摘掉

## 必须做的事
1. 新建 src/ai_firmware_agent/report/html.py,用 jinja2 渲染
2. 模板放 src/ai_firmware_agent/report/templates/report.html.j2
   内容对齐 Markdown 报告:摘要、图表、Top-N 富化、完整清单表
   清单表要透出 FW-DETECT-001 的 extra["detector"] / ["evidence"]
3. CLI:--format {markdown,html},默认 markdown 保持现状不变
4. CSS 内联进模板(报告要能单文件分发,不依赖外部资源)
5. 加 tests/test_report_html.py

## 必须满足的约束
- 输出确定性(除生成时间戳外),便于 diff
- **必须转义**组件名/版本/CVE 描述——这些字符串来自不可信固件,
  未转义就是把固件内容变成报告里的 HTML 注入
- 不联网:不引 CDN 字体/JS
- Windows 兼容

## 不要做的事
- 不要改 render_markdown 的输出(现有测试锁着)
- 不要装新依赖(jinja2 已有)

## 验收
- [ ] pytest 全绿(基线 278 passed)
- [ ] 新增测试 ≥ 8 个,含一条 HTML 转义的注入用例
- [ ] CLI smoke: --format html 生成的文件能在浏览器打开,粘贴片段
```

---

### DETECT-002 · 扩充检测器覆盖面(P2)

```
[DETECT-002] 006 AI-Firmware-Security-Agent · 扩充组件检测覆盖

## 背景
- FW-DETECT-001 已建 detectors/ 框架(packages / osrelease / binary)
- binary.py 目前只认 9 个组件的 banner,包管理器只覆盖 opkg / dpkg

## 必须做的事
1. binary.py 扩充 banner 模式:zlib / libcurl / wpa_supplicant / hostapd /
   uhttpd / nginx / sqlite / expat / libupnp 等嵌入式常见组件
2. 新增 detectors/rpm.py:读 RPM 数据库(部分工业设备用)
3. 新增 detectors/python.py:site-packages 下的 *.dist-info/METADATA
4. 新增 detectors/node.py:package.json(name + version)
5. 每个新检测器配 tests/fixtures/rootfs 下的夹具

## 必须满足的约束
- 沿用 DETECTOR_PRIORITY 与 merge_components 的合并语义
- 只读不执行,读取有上限
- 新 banner 必须有夹具佐证,不要凭记忆写正则
- 误报比漏报更糟:宁可不认,不要认错版本

## 不要做的事
- 不要装 pyelftools 等新依赖(标准库够用),确需再单独批准
- 不要改 Component dataclass 已有字段

## 验收
- [ ] pytest 全绿(基线 278 passed)
- [ ] 新增测试 ≥ 15 个
- [ ] 每个新检测器至少 1 个真实形态夹具
```

---

### DETECT-002 补记:RPM 检测器为什么没做

卡片原计划包含 `detectors/rpm.py`。没做,原因不是工作量,是**没有可信的验证手段**:
RPM header 是自定义的 tag-based 二进制格式(magic + index + data area),这个环境里
没有真实 `rpmdb.sqlite` / `Packages` 文件能跑通验证。写一个看起来合理但实际解析
错误的解析器,比干脆不检测更糟——错误的版本号会污染 CVE 匹配还不容易被发现。

重新捡起来的前提:先搞到至少一个真实的 RPM 数据库文件(或者认可基于 `rpm2cpio` /
系统 `rpm` 命令做验证测试),再实现,而不是凭格式文档硬写。

已完成的部分:`detectors/binary.py` 加了 zlib / wpa_supplicant / hostapd / mbedtls /
nginx 五个新 banner(全部是编译期字面量,不是猜的);新增 `detectors/python_packages.py`
(dist-info/egg-info)和 `detectors/node_packages.py`(package.json,含 node_modules 依赖)。

---

### DIFF-001 / FINGERPRINT-001 / ENG-001(P3)

- **DIFF-001**:对比两个固件版本的组件清单,输出新增/删除/升级/降级,
  并标出"升级后仍受同一 CVE 影响"的情况。依赖 EVAL-001 的语料。
- **FINGERPRINT-001**:从 rootfs 特征(目录布局、默认配置、厂商字符串)
  推断 OEM 与设备型号。误报代价高,先定准确率门槛再做。
- **ENG-001**:`poetry.lock` 目前**生成不了**——pyproject 用
  `path = "../000shared-llm-core"` 依赖 sibling,需要先决定共享内核的分发方式
  (私有 index / wheel / git 依赖)。`ruff format --check` 要先重排 19 个文件,
  是风格决策不是 bug 修复,需你拍板。
