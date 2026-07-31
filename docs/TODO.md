# 006 AI-Firmware-Security-Agent · v0.1 TODO

> **项目状态**: v0.7 静态融合实施中（386 passed / 2 skipped，2026-07-29）
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

## v0.6 · 开源能力融合

详细设计见 [`open-source-fusion-plan.md`](open-source-fusion-plan.md)。

| ID | 任务 | 状态 | 完成日 | 备注 |
|----|------|------|--------|------|
| FUSION-001 | Provider capability/inventory 协议 | done | 2026-07-29 | 可选工具、无硬依赖 |
| FUSION-002 | Unblob 后备解包 adapter | done | 2026-07-29 | Binwalk → Unblob → mock |
| FUSION-003 | Syft + CVE Binary Tool inventory | done | 2026-07-29 | PURL/evidence/confidence 合并 |
| FUSION-004 | CycloneDX evidence + 原子写入 | done | 2026-07-29 | 保持 1.5 输出兼容 |
| FUSION-005 | Docker static worker | pending | — | 固定 digest、只读、无网络 |
| FUSION-006 | VEX triage | pending | — | OpenVEX/CycloneDX VEX |
| FUSION-007 | Registry + firmware diff | partial | — | diff 已完成；持久 registry 待实现 |
| FUSION-008 | FirmAE/QEMU lab worker | pending | — | 显式 opt-in，不进默认 scan |

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
> 当前基线:**354 passed / 4 skipped**,ruff + mypy 全绿。

| ID | 任务 | 优先级 | 阻塞点 |
|----|------|--------|--------|
| ARCH-001 | 收敛两套解包栈 | P1 | **需先决策主线** |
| ~~RPT-HTML-001~~ | ~~HTML 报告~~ | done | — |
| ~~DETECT-002~~ | ~~扩充检测器覆盖面~~ | done(部分) | RPM 暂缓,见下 |
| ~~EVAL-001~~ | ~~评测基线与跑分脚本~~ | done(部分) | 见 `benchmarks/`,4 个指标中 2 个部分测量、2 个仍无法测 |
| ~~DIFF-001~~ | ~~固件差分分析~~ | done | — |
| FINGERPRINT-001 | 厂商/OEM 指纹识别 | P3 | 误报代价高,需先定准确率门槛 |
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

### EVAL-001 · 建立 §9 指标的评测基线 — ✅ 部分完成

`benchmarks/run.py` + `benchmarks/corpus/` 已实现,`benchmarks/README.md` 有
完整的"测量范围"表,tech-spec §9 已按实测结果更新。

**做了什么**:
- `benchmarks/corpus/openwrt-23.05.5-ath79-tiny/`:从仓库自带的真实 OpenWrt
  官方 manifest(135 包)生成 opkg status 文件 + expected.yml,测的是
  `detectors/packages.py` 的解析器在 135 条真实、格式各异的版本串上不出错——
  但这不是独立标注的准确率(rootfs 和 expected.yml 同源,结构上不会有误报)
- `benchmarks/corpus/harness-selfcheck/`:4 组件手写夹具,四种结果各一例
  (命中/版本错/漏检/误报),只用来验证跑分脚本算术本身是对的
- `--time-scan` 实测了检测+mock CVE 匹配+PRisk 打分的端到端耗时

**为什么还是"部分完成",没做原计划的"3-5 个公开固件"**:
- 这个环境没有出网权限,无法下载新固件语料
- 仓库里唯一的真实 `.bin` 样本需要 binwalk 提取到 rootfs,而这个环境没装
  binwalk(`BinwalkRunner().is_available()` 返回 `False`)
- CVE 匹配召回率、PRisk 排序一致性两项仍完全无法测:前者需要真 NVD 数据
  (被出网策略挡了),后者需要人工标注的优先级基线,目前没有

**继续这项工作的前提**:找到一个能出网、或者能装 binwalk 的环境,把真实
`.bin` 提取出来跑,再补充人工标注的组件清单作为独立 ground truth——而不是
像 `openwrt-23.05.5-ath79-tiny` 这条一样从 manifest 反推。RPM 检测器和
CVE 匹配召回率都在等同一件事:一个能验证的真实环境。

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

### DIFF-001 · 固件差分分析 — ✅ 已完成

`diff.py`(`diff_components` / `diff_vulnerabilities`)+
`reporter.render_diff_markdown` + `firmware-agent diff --old --new` 已实现。

- 按组件名(大小写不敏感)对比两份清单:added / removed / upgraded /
  downgraded / changed(版本排序不明确)/ unchanged
- `diff_vulnerabilities` 标出"同一组件在新旧版本里都命中的 CVE"——
  只对比调用方已经算好的两次 `match_components` 结果,不自己发起 CVE 查询
- 和 `--sbom` 一样,`diff` 默认 `--cve-source mock`,不是 `nvd`:
  会把两份清单各查一遍,默认打两倍限速请求不合理
- 版本排序复用 `cve_db/version.py` 的 `version_key()`,对"日期+git-hash"
  风格的版本号(OpenWrt 常见)只是给出某种排序,不保证对应真实新旧关系——
  这一点在 `diff.py` 模块文档、README、tech-spec §5.12 都写了,不要只看
  upgraded/downgraded 标签下结论
- CLI 的 `scan` 输入解析逻辑抽成了 `_parse_input_file` 共享辅助函数,
  行为与原来逐字一致(含"非 `.bin` 的损坏归档不会被 `FirmwareUnpackError`
  捕获"这条边界情况),新增测试专门锁住这个不变量

### FINGERPRINT-001 / ENG-001(P3)

- **FINGERPRINT-001**:从 rootfs 特征(目录布局、默认配置、厂商字符串)
  推断 OEM 与设备型号。误报代价高,先定准确率门槛再做。
- **ENG-001**:`poetry.lock` 目前**生成不了**——pyproject 用
  `path = "../000shared-llm-core"` 依赖 sibling,需要先决定共享内核的分发方式
  (私有 index / wheel / git 依赖)。`ruff format --check` 要先重排 19 个文件,
  是风格决策不是 bug 修复,需你拍板。
