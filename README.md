# Ensou DSH Launcher

**An Ensou Studio engineering project exploring managed Windows deployment for DeepSeek Harness.**

一个由 **ensou** 发起、以 **Ensou Studio** 名义维护的 Windows 桌面启动与更新项目。项目围绕 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)，探索如何让不熟悉命令行的用户安装、启动和维护本地 AI Agent。

> **项目展示 / 非商业学习用途。** 这是第三方工程项目，不是 DeepSeek 官方客户端，也不代表官方背书。源码、测试和实验性分支不等于已经通过生产验收的安装包。

## 为什么做这个项目

本地 Agent 的使用不应以掌握 Git、FNM、Node.js 或包管理器为前提。本项目尝试把运行环境管理、后台进程、版本更新和故障恢复收敛为普通 Windows 用户可以理解的桌面操作，同时保留对话历史与工作区在本机的边界。

它也是一份持续积累的工程实践：如何把“开发机上可以运行”推进到“能够安装、验证更新、失败后恢复”的产品交付流程。

## 工程主题

- **桌面入口：** C# / WPF 界面、托盘操作、状态提示和本地 WebUI 入口。
- **本地运行时：** Launcher 管理自己启动的 DSH 进程，探索随包运行环境与程序版本隔离。
- **受控更新：** 签名清单、下载校验、不可变制品，以及 Launcher 与 DSH 分组件发布的设计。
- **失败恢复：** 健康检查、版本切换、回退及本地用户数据保护。
- **管理能力的边界：** 在客户端设计中区分用户身份、设备授权和本地 Agent 运行，不把管理界面误当成模型本身。

这些是本仓库的研究与实现方向，不是对每个分支、安装包或真实设备的功能保证。本仓库是一份脱敏的源码快照；不包含原始提交历史、开发分支、PR 讨论或 Actions 日志，也不包含本机未提交的工作文件。

## 架构概览

```text
Windows 用户
    │
    ▼
Bootstrapper ── 启动入口与版本恢复
    │
    ▼
Launcher ────── 界面、托盘、状态与更新协调
    │
    ▼
Local Host ──── 管理本项目启动的后台进程
    │
    ▼
DSH Runtime ─── 本地 WebUI、对话与工作区

更新源 ── 签名清单与版本制品 ──► Launcher
用户数据 ── 保存在程序版本目录之外
```

Personal 与 Enterprise 的开发探索共享部分进程托管、合同和校验能力，但具有不同的产品策略和验证链路。**企业服务端不在本次公开范围内**；仓库中的客户端协议与历史设计文档不提供生产服务、客户配置或访问凭据。

## 当前状态与上游关系

截至 **2026-09-15**，项目开发保持暂停，现有成果保留用于展示、学习和后续评估；这不是已经完成的生产发行，也没有在此承诺正式安装包或维护时限。

DeepSeek 官方仓库已经加入 [Desktop 实现](https://github.com/deepseek-ai/deepseek-harness/tree/master/apps/desktop)。本项目正在重新评估独立桌面壳的必要性，优先考虑复用官方桌面能力，并把真正有差异的管理与部署支持单独保留。这不代表已经完成迁移，也不代表官方桌面安装包或更新流程已经由本项目验收。

设计文档保留了不同阶段的网络、身份和发布方案，仅供学习，不应直接作为当前部署指南。设备标识、个人路径与客户称谓已替换为示例；自动发布工作流未包含在公开副本中。脱敏后的内容与原始签名、哈希和验收记录不能互相替代，需要重新构建、校验与独立验收，不能据此操作真实设备或发布通道。

## 从哪里开始阅读

| 路径 | 内容 |
| --- | --- |
| [`src/`](src/) | Launcher、Host、更新及客户端组件 |
| [`tests/`](tests/) | 合同校验与隔离测试 |
| [`docs/adr/`](docs/adr/) | 架构决策与取舍 |
| [`release/`](release/) | 清单、版本与制品设计 |
| [`installer/`](installer/) | 安装布局及数据保留边界 |
| [`security/`](security/) | 威胁模型与信任设计 |
| [`versions/locked.json`](versions/locked.json) | 所在分支锁定的上游版本 |

本仓库不是面向普通用户的一键安装入口。需要研究构建时，请先阅读所在分支的 `global.json`、项目文件及构建脚本，并使用隔离测试环境；不要直接把示例域名、测试身份或测试密钥用于真实部署。

## 许可证与非商业使用

本项目中由 ensou / Ensou Studio 有权授权的原创代码与文档采用 **[PolyForm Noncommercial License 1.0.0](LICENSE.md)**。允许的非商业目的、修改、分发和声明保留要求以许可证原文为准。

- 欢迎在许可证允许的范围内阅读、学习、实验、修改和分享。
- 商业用途不由此许可证授权；需要另行取得权利人的书面许可。申请入口为本仓库的 Issue 或 Pull Request，申请本身不构成授权，请勿提交客户信息或秘密。
- 这是 **source-available（源码可见）** 项目，不标榜为允许任意商用的 OSI 标准开源项目。
- DeepSeek Harness、第三方依赖及其既有代码继续适用各自的许可证；本项目不撤销上游 MIT 等许可已经授予的权利。详见 [NOTICE.md](NOTICE.md)。

许可证约束使用与分发权利，不是技术防拷贝机制，也不是 Windows 代码签名证书。

## 反馈与安全

欢迎通过 Issue 讨论工程设计与学习问题。安全问题请遵循 [SECURITY.md](SECURITY.md)，不要公开上传 API Key、签名材料、员工信息、对话或工作区数据。

**作者：ensou · 项目品牌：Ensou Studio**

---

### English summary

Ensou DSH Launcher is an independent Ensou Studio project exploring Windows desktop delivery for local DeepSeek Harness agents: a WPF launcher, owned background processes, managed runtime packages, signed update manifests, and recovery boundaries. It is shared as an engineering portfolio and for noncommercial study, not as an official DeepSeek product or a production-certified distribution. Development is paused while the upstream Desktop implementation is evaluated. The enterprise server remains private. Original licensable contributions are offered under PolyForm Noncommercial 1.0.0; third-party licenses remain unchanged.
