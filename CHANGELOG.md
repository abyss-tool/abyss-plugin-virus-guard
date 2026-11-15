# 更新日志

本文件遵循「一版一条」纪律：每个发布版本一个 `## v*` 条目；发布时由
插件 CI 校验当前版本必须有对应条目。

## v0.1.0

- 插件框架期骨架：plugin.json manifest（含 Shizuku 独立授权声明）/
  patches/index.json 补丁通道 / CI 清单门禁（validate_plugin.py，含
  shizuku 声明强制校验）全部就绪
- v0.8.0 大内置化后的插件矩阵新成员：病毒拦截与虚拟机一道接替归档的
  六个重型插件位次，成为「引擎级能力」插件化的代表
- 技术方案定稿：安装事件拦截 + ClamAV 级本地特征引擎 + VirusTotal 云
  查询 + 全盘扫描处置面板，完整排期见 ROADMAP.md
- 插件本体按 ROADMAP.md 排期实现（APK 资产自 v0.2 发布流水线起发布）
