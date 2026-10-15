# 006AI-Firmware-Security-Agent · ARCHITECTURE

核实日期：2026-10-15。依据本地README、构建清单和实际入口；本文件不把文档计划当成运行时验收。

## 目标与范围

在授权边界内分析固件，静态分析与受限模拟/工作进程能力分别验收。

GitHub：[longyuanai/006AI-Firmware-Security-Agent](https://github.com/longyuanai/006AI-Firmware-Security-Agent)。知识笔记：Vault内 `03_Projects/AI-Network-Security/006AI-Firmware-Security-Agent - Git关联.md`。

## 组件与代码入口

| 实际路径 | 责任边界 |
| --- | --- |
| [src](src) | 主要实现 |
| [modules](modules) | 独立能力Git仓 |
| [tests](tests) | 测试 |
| [docs](docs) | 工程规范与说明 |

## 数据与控制流

以下链路对应README/规范描述；实现覆盖以代码入口和适用验证为准。

```mermaid
flowchart LR
    N0["授权样本"]
    N1["格式与能力选择"]
    N2["静态分析或受限工作进程"]
    N3["发现"]
    N4["报告"]
    N0 --> N1
    N1 --> N2
    N2 --> N3
    N3 --> N4
```

## 构建与依赖依据

- [pyproject.toml](pyproject.toml)：`Python`。

## 验证边界

验证未授权、异常退出、超时和不支持样本的处理；不执行未知样本或实体烧录。

## 现行依据

- [README.md](README.md)
- [CAPABILITIES.md](CAPABILITIES.md)
- [docs/tech-spec.md](docs/tech-spec.md)
- [docs/TODO.md](docs/TODO.md)
