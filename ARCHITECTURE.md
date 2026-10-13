# 006AI-Firmware-Security-Agent · 架构导览

> 2026-10-12 根据本地目录、已有文档和构建清单建立的工程文档入口；本轮未运行项目业务验收或完整安全审计。

- Project ID：`006AI-Firmware-Security-Agent`
- GitHub：[longyuanai/006AI-Firmware-Security-Agent](https://github.com/longyuanai/006AI-Firmware-Security-Agent)
- Obsidian：Vault `龙渊` 内的 `03_Projects/AI-Network-Security/006AI-Firmware-Security-Agent - Git关联.md`（记录原理、实验、漏洞分析与复盘）。

## 已核实的工程入口

```text
006AI-Firmware-Security-Agent/
├── AUDIT/
├── benchmarks/
├── CAPABILITIES.md
├── docker-compose.yml
├── Dockerfile
├── Dockerfile.emulator
├── docs/
├── evals/
├── LICENSE
├── modules/
├── PHASE-2.md
├── pyproject.toml
├── samples/
├── src/
├── tests/
```

## 构建与技术栈依据

- [pyproject.toml](pyproject.toml)：[tool.poetry]；name = "ai-firmware-agent"；[tool.poetry.dependencies]；python = "^3.11"；[tool.poetry.group.dev.dependencies]；[tool.poetry.scripts]；[build-system]；[tool.pytest.ini_options]。

能力模块保留独立 Git 历史，提交/克隆须分别核对；目录编号与 API 来源编号不可混用，详见 CAPABILITIES。

## 边界与待补充

- 组件职责、数据流、数据模型与部署边界以现行技术规范为准。
- [ ] 在真实代码反馈后补充仍缺少的数据流或设计取舍；当前不把拟议能力标为已实现。

## 现行依据

- [README.md](README.md)
- [CAPABILITIES.md](CAPABILITIES.md)
- [docs/tech-spec.md](docs/tech-spec.md)
- [docs/TODO.md](docs/TODO.md)
