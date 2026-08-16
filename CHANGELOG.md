# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 和 [SemVer](https://semver.org/lang/zh-CN/) 约定。

## [Unreleased]

### Added

- 开源协作基础设施：贡献指南、Issue/PR 模板、CI。
- 节点表单按协议动态显隐字段，参考 3x-ui 对齐各协议配置。
- Shadowsocks 支持选择加密方式和 TCP/UDP 网络；VMess 客户端支持选择加密方式。
- Reality 仅对 VLESS 开放，VMess 与 WS 组合不可用。

### Fixed

- Trojan 节点不再允许选择 Reality：此前 Trojan 分享链接缺少 Reality 参数，导入客户端不完整。

## [0.1.0] - 2026-08-16

### Added

- 服务器管理：SSH 密码 / 私钥认证、保存连接、测试连接、系统信息。
- 服务器快速添加：支持粘贴多种常见连接格式并自动识别。
- 节点管理：VMess、VLESS、Trojan、Shadowsocks；TCP / WebSocket / gRPC / HTTPUpgrade；无加密 / TLS / Reality。
- 客户端管理：每个节点配置多个客户端，自动生成 UUID / 密码。
- 一键部署：自动检测架构、安装 Xray、写入 systemd 服务、生成配置并重启。
- 远程状态与日志：Xray 版本、运行状态、监听端口、最近日志。
- 分享链接：生成 VMess / VLESS / Trojan / Shadowsocks 客户端链接。
- Reality 密钥对本地生成与伪装站点预设。
- Docker 运行方式，数据目录挂载到宿主机。
