<div align="center">

# 🦠 病毒拦截

### 安装事件拦截 · ClamAV 级特征引擎 · VirusTotal 云查询 · 全盘扫描与处置 · 独立 Shizuku 授权

[![Plugin CI](https://github.com/abyss-tool/abyss-plugin-virus-guard/actions/workflows/plugin-ci.yml/badge.svg?branch=main)](https://github.com/abyss-tool/abyss-plugin-virus-guard/actions/workflows/plugin-ci.yml)
![Version](https://img.shields.io/badge/version-0.1.0-7EC8FF)
![Category](https://img.shields.io/badge/分类-系统工具-4FD8EB)
![Status](https://img.shields.io/badge/状态-框架预览-1A222D)

</div>

---

> 深渊工具（[abyss-tool/Abyss-Tools](https://github.com/abyss-tool/Abyss-Tools)）的**引擎级大插件**（v0.8.0 插件矩阵新成员）—— 在手机上拦截安装事件、扫描已装应用、处置威胁。本仓库为**插件框架期骨架**：manifest（含独立 Shizuku 授权声明）/ 补丁通道 / CI 门禁已就绪，特征引擎按路线图实现。

## 为什么是插件？

病毒拦截是**自带完整引擎**的能力：ClamAV 级签名库（数十万特征，本体即百 MB 级）+ 云查询调度 + 实时拦截守护 —— 这是 v0.8.0 大内置化后「只有引擎级能力才插件化」分界线的三个代表之一（另两个：应用构建器 / 虚拟机）。

## 插件信息

| 字段 | 值 |
| --- | --- |
| 插件 ID | `abyss-plugin-virus-guard` |
| 分类 | 系统工具（system） |
| 版本 | v0.1.0（框架预览） |
| 最低宿主 | App v0.8.0 / HOST_API v1 |
| 仓库 | [abyss-tool/abyss-plugin-virus-guard](https://github.com/abyss-tool/abyss-plugin-virus-guard) |
| 补丁通道 | [`patches/index.json`](patches/index.json) |

## 权限需求

- `INTERNET`（VirusTotal 云查询）
- `FOREGROUND_SERVICE`（安装监听守护前台保活）
- `RECEIVE_BOOT_COMPLETED`（开机恢复监听）

## Shizuku 独立授权（重要）

安装事件拦截与静默处置经 Shizuku（ADB shell 上下文）挂接
`pm install-session` 监听并执行静默卸载 —— 免 Shizuku 时降级为普通
安装广播监听（只能提示，不能拦截）。本插件为独立 APK，按 Shizuku
per-app 授权机制需单独授权一次。

## 路线图

- [ ] v0.2 拦截骨架：安装广播 + 会话监听 + 信任判定管线
- [ ] v0.3 本地特征引擎：ClamAV 签名库移植 + 哈希黑名单
- [ ] v0.4 VirusTotal 云查询（限额调度 + 结果缓存）
- [ ] v0.5 全盘扫描与处置面板（隔离 / 卸载引导 / 白名单）

详见 [ROADMAP.md](ROADMAP.md)。
