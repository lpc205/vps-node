# VPS-Node · Sing-box 节点控制台

在本地或 Docker 中运行的中文 VPS 管理面板。通过 SSH 远程部署与维护 **Sing-box**，提供免自有域名的节点组合、Web 终端、动态订阅、路由以及近实时状态面板。

> 此分支为 Xray → Sing-box 的破坏性内核迁移。**升级容器不等于迁移远端节点；切勿未经备份直接覆盖生产部署。**

## 核心架构

- 面板安装在你自己的 Docker / NAS / PC 中；VPS 上只安装 Sing-box 本体，只有选择 Argo 临时隧道时才额外安装 Nginx、cloudflared。
- SSH 密码、私钥与 sudo 凭据由面板加密保存在本机数据目录；Web 前端不获取这些凭据。
- 不要求准备自有域名。直连方案使用 IP + Reality 或自动生成自签证书；WebSocket 隧道使用 Cloudflare Quick Tunnel 提供的随机 `trycloudflare.com` 域名。
- **面板仍没有内置登录鉴权。** 只允许可信局域网、VPN 或具有独立认证的 HTTPS 反向代理访问，不要直接暴露公网。

## 可创建的部署组合

| 组合 | 连接方式 | 证书 / 域名要求 |
| --- | --- | --- |
| VLESS + Reality Vision | TCP 直连 | 无需自有域名；使用伪装目标的 SNI |
| VLESS + gRPC + Reality | gRPC 直连 | 无需自有域名 |
| VLESS + HTTP + Reality | HTTP 传输 | 无需自有域名 |
| Hysteria2 | UDP 直连 | 自动自签证书 |
| TUIC V5 | UDP 直连 | 自动自签证书 |
| AnyTLS | TLS 直连 | 自动自签证书 |
| Trojan Direct | TLS 直连 | 自动自签证书 |
| Shadowsocks | TCP / UDP | 无需证书；支持 2022 加密方法 |
| VLESS + WebSocket + Argo | Quick Tunnel | 隧道自动分配临时域名 |
| VMess + WebSocket + Argo | Quick Tunnel | 隧道自动分配临时域名 |
| SOCKS5 | 仅用作出站 | 不作为公网入站 |

不支持旧 Xray 专属的 XHTTP / HTTPUpgrade 组合。需要自己准备 DNS 解析、正式域名证书或 Cloudflare 固定隧道认证信息的方案也不出现在部署预设中。

**自签证书安全：** 部署时自动读取服务器证书的 SHA-256 整体指纹与 SPKI 公钥指纹。用于 Sing-box 出站路由时要求验证 SPKI 指纹，不再默认设置 `insecure: true`；部分 URI 分享链接附带供 Shadowrocket 等兼容客户端使用的 `hpkp` 指纹字段。**不同客户端对证书指纹 URI 参数的支持并不统一**，不支持时需另行配置证书或公钥指纹；不能将未完成验证的客户端视为安全或可用。

**Quick Tunnel 限制：** 临时隧道适合体验和轻量用途，不保证永久稳定；服务重启后临时域名可能更换，订阅会随重新部署更新。

## 近实时状态监控

监控运行在面板进程中，不在 VPS 上安装常驻 Agent。

| 类型 | 策略 |
| --- | --- |
| 快速检查 | 默认每 5 秒，每台 VPS 复用 SSH 连接 |
| 完整巡检 | 约每 60 秒检查 Sing-box 二进制、配置文件一致性、端口、隧道状态 |
| 资源监控 | 5 秒周期采样 CPU、内存、负载、网卡字节数与网络速率 |
| 前端更新 | SSE 推送变更；15 秒轮询兜底，重新打开页面立即同步 |
| 失败退避 | 最高约 30 秒，避免离线 VPS 长时间无法恢复显示 |
| 并发 | 默认 5，最大 10，可配置 |

状态区分 SSH 可达、Sing-box 服务运行、配置一致性和 TCP/UDP 端口监听。**绿色状态不等于协议握手成功或端到端代理可用**；真实外部协议拨测仍需要额外的验证能力，不能凭监听端口断言节点完全正常。

## 本地 / Docker 启动

需要 Node.js >=22.5。

```bash
npm ci
npm start
# 或开发模式：npm run dev
```

打开 http://127.0.0.1:3000。

Docker：

```bash
docker compose up -d --build
```

默认仅映射本机 `127.0.0.1:3000:3000`。数据在 `./data`，含 SQLite 数据库和加密密钥文件，容器重建必须保留整个目录。

运行单元测试：`npm test`。GitHub Actions 另外使用 Sing-box 官方二进制校验部署预设，并构建 Docker 镜像检查健康接口。

### 配置项

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | Web 面板端口 |
| `DATA_DIR` | `./data` | SQLite 与加密密钥 |
| `PANEL_STATUS_INTERVAL` | `5` | 快速巡检间隔，秒，最小 5 |
| `PANEL_STATUS_CONCURRENCY` | `5` | 巡检并发量，1～10 |
| `PANEL_SINGBOX_VERSION` | `1.14.3` | 首次安装时使用已通过 CI 验证的 Sing-box 版本 |

## 从 Xray 版本升级

1. 备份旧容器的 `data/`，并记录当前 VPS 节点配置、端口和 Xray 服务状态。
2. 单独在测试 Docker / 数据目录中验证此分支。**不要把当前运行的 Xray 自动卸载或覆盖。**
3. 查看原有节点配置：Sing-box 与 Xray JSON 格式不同；旧的 XHTTP / HTTPUpgrade 等节点需要手动改为支持的组合。面板仍保留旧节点数据以供迁移，但不会假装旧配置可以直接运行。
4. 在测试 VPS 上安装 Sing-box、生成配置并测试客户端实际连接；确认端口没有与旧 Xray 服务冲突。
5. 确认全部新节点正常后，才自行安排停止 / 卸载旧 Xray（本项目不会在升级过程中自动删除旧内核）。

写入配置时，会先在远端执行 `sing-box check -c` 校验暂存文件，校验不通过不替换线上配置。systemd 启动失败时会尝试恢复最近的 `config.json.bak`。

## 核心代码

- `src/singbox.js`：Sing-box 入站、出站、路由与节点分享链接
- `src/remote.js`：SSH 探测、安装、配置校验与远程服务管理
- `src/ssh.js`：SSH 执行与轻量探测专用连接池
- `src/status.js`：快慢双周期巡检、资源采样、退避和状态推送
- `src/status-events.js`：进程内事件总线
- `src/argo.js`：Nginx、Cloudflared、临时隧道和自签证书
- `src/db.js`：SQLite、节点 / 服务器管理与兼容旧数据
- `src/app.js`：HTTP API、SSE 和路由
- `public/`：中文界面
- `test/`：自动化测试

技术参考：[fscarmen/sing-box](https://github.com/fscarmen/sing-box)，配置规范以 [Sing-box 官方文档](https://sing-box.sagernet.org/configuration/) 为准。本项目没有直接在 VPS 上执行第三方一键脚本，而是独立生成配置并通过 SSH 管理。
