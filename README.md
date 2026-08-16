# VPS 节点控制台

一个运行在本地或 Docker 中的可视化 VPS 管理面板：通过 SSH 连接你的 VPS，在网页上部署、编辑、检查和维护 Xray 节点，并生成客户端分享链接和动态订阅。

## 为什么这样设计

- 面板只运行在本地，VPS 上不安装任何常驻控制端，只安装 Xray 本身。
- 所有远程操作都是“面板发起 SSH 命令”，适合轻量 VPS，也方便迁移和审计。
- 服务器密码、私钥、sudo 密码保存在本机 SQLite 外的密钥文件中，使用 AES-256-GCM 加密后再落盘。
- 支持 Docker 运行，数据目录挂载到宿主机，删除容器不会丢配置。
- 节点配置统一由面板生成 `config.json`，避免手工 SSH 修改容易出错。
- 面板默认没有登录鉴权，只适合本机、可信局域网、VPN 或受保护的反向代理环境。

## 已实现

### 服务器和终端

- SSH 密码或私钥认证，支持 sudo 密码。
- 粘贴 `root@IP:端口 密码`、`IP:端口:用户名:密码`、`IP 端口 用户名 密码` 等格式快速添加服务器。
- 服务器状态检查：SSH 连通性、Xray 二进制、服务状态、配置文件、端口监听和最近检查时间。
- WebSocket + xterm.js SSH 终端，支持输入、窗口调整、关闭、全屏和重新连接。
- 服务器日志查看和危险操作确认。

### 节点和路由

- 支持 VMess、VLESS、Trojan、Shadowsocks 和 SOCKS5。
- 支持入站 / 出站角色，按角色查看节点。
- 支持 TCP、WebSocket、gRPC 和 HTTPUpgrade，以及 TLS、Reality 和无加密。
- 节点支持多个客户端，自动生成 UUID 或密码。
- Reality X25519 密钥对在面板本地生成，不依赖 VPS。
- 内置常见 Reality 伪装目标，可随机轮换 `dest`、`serverNames` 和 SNI。
- 路由页面可以把入站节点连接到出站节点，并在入站服务器上生成对应 Xray 出口和路由规则。
- 支持部署全部节点、分享链接和 v2rayN 等客户端导入。

### 状态巡检和修复

- 后台按固定间隔自动巡检服务器，默认 60 秒，可通过 `PANEL_STATUS_INTERVAL` 调整。
- 通过 `PANEL_STATUS_CONCURRENCY` 限制 SSH 并发，失败时指数退避。
- 状态缓存区分运行中、服务停止、配置不一致、配置缺失、二进制缺失、端口异常、离线和未知。
- 本地生成期望配置并与 VPS 上的 `config.json` 做 SHA-256 一致性比较。
- 一键修复按漂移类型选择恢复服务、恢复配置或重新部署，并写入审计日志。
- 自动修复默认关闭；巡检和状态检查本身都是只读操作。

### 订阅

- 订阅功能集成在总览页，不单独占用导航页面。
- 自动包含所有 `role = inbound` 且 `enabled = 1` 的节点，不需要手动选择节点。
- 新增、编辑、启用或禁用入口节点后，订阅内容自动变化。
- Token 使用密码学安全随机值生成，数据库只保存 Token 哈希，支持禁用、过期和重新生成。
- 支持 Base64 和原始 URI 两种格式，以及 VMess、VLESS、Trojan、Shadowsocks 和 SOCKS5。

### 前端体验

- 中文界面和 lucide 图标。
- 亮色 / 暗色 / 跟随系统主题切换，并记住用户选择。
- 卡片、弹窗、Toast 和页面切换使用克制的过渡动画。
- 适配桌面、中等宽度和手机屏幕，避免横向滚动与内容截断。

## 快速开始

要求 Node.js `>= 22.5`。

本地 Node.js 运行：

```bash
npm install
npm start
```

打开 <http://127.0.0.1:3000>。

Docker 运行：

```bash
docker compose up -d --build
```

默认映射为 `127.0.0.1:3000:3000`，打开 <http://127.0.0.1:3000>。数据保存在 `./data`，包含 `panel.db` 和加密密钥 `.secret`。

### 飞牛 NAS 部署

飞牛部署目录使用用户 Docker 目录，例如：

```text
/vol1/1000/Docker/vps-node-console
```

NAS 部署时建议：

- 将项目源码和 Compose 配置放在用户 Docker 目录下。
- 将面板数据绑定到项目目录内的 `data` 子目录。
- 设置 `restart: unless-stopped`，让 NAS 重启后自动恢复。
- ARM64 NAS 且无法访问 Docker Hub 时，提前准备匹配架构的 Node.js 运行时和 npm 依赖进行离线构建。

本项目已在 ARM64 飞牛 NAS 上验证运行，局域网访问地址可以是 `http://NAS_IP:3000`。默认 Docker Compose 只绑定 `127.0.0.1`；如果需要局域网访问，应明确绑定到 NAS 局域网地址或 `0.0.0.0`，并确认 NAS 防火墙和访问网络可信。

## 开发与贡献

```bash
npm install
npm run dev   # 打开 http://127.0.0.1:3000
npm test
```

项目遵循 Issue → 讨论 → 分支开发 → Pull Request → CI → Review → 合并 → 发版的迭代流程。详细约定见 [CONTRIBUTING.md](CONTRIBUTING.md)，变更记录见 [CHANGELOG.md](CHANGELOG.md)，安全报告方式见 [SECURITY.md](SECURITY.md)。

## 使用流程

1. 在“服务器”页添加 VPS：填写主机、SSH 端口、用户名，密码或私钥任选。
   - 也可以在“快速粘贴服务器信息”里粘贴连接信息，点击“识别并保存”直接添加。
2. 非 root 用户需要填写 sudo 密码；root 用户不需要。
3. 在“节点”页选择服务器，添加入站或出站节点和客户端。
4. 点击“部署全部节点”完成 Xray 安装、配置写入和启动。
5. 在节点卡片中点击“状态”查看实际运行情况，点击“分享”复制客户端链接。
6. 在“路由”页选择入站和出站节点，连接后为入站服务器配置远程出口。
7. 在总览页创建订阅，订阅会自动包含所有启用的入口节点。

## 目录结构

```text
public/             前端静态面板
src/
  index.js          服务启动和 WebSocket 终端
  app.js            Express 路由和静态资源
  db.js             SQLite 表结构和 CRUD
  crypto.js         AES-256-GCM 加解密
  paths.js          数据目录解析
  ssh.js            ssh2 连接和远程命令执行
  remote.js         VPS 探测、安装、配置、重启、日志和状态
  xray.js           Xray 配置、分享链接和 Reality 密钥对
  status.js         自动状态巡检、状态派生和配置校验
  repair.js         漂移修复和审计日志
  subscriptions.js  动态订阅查询和格式转换
test/               状态、Xray、路由和订阅测试
Dockerfile
docker-compose.yml
```

## API 摘要

服务器和节点：

- `GET /api/servers`、`POST /api/servers`、`PUT/DELETE /api/servers/:id`
- `GET /api/servers/:id/status`、`POST /api/servers/:id/deploy`
- `GET /api/servers/:id/logs`、`POST /api/servers/:id/x25519`
- `GET /api/nodes`、`POST /api/servers/:id/nodes`、`PUT/DELETE /api/nodes/:id`

状态和修复：

- `GET /api/status`
- `POST /api/servers/:id/repair`
- `GET /api/repair-logs`

路由、订阅和终端：

- `GET/POST /api/routes`、`DELETE /api/routes/:id`
- `GET /api/subscriptions`、`POST /api/subscriptions`
- `GET/PUT/DELETE /api/subscriptions/:id`
- `POST /api/subscriptions/:id/rotate|enable|disable`
- `GET /api/subscriptions/:id/preview`
- `GET /sub/:token`、`GET /sub/:token?format=base64|uri`
- `WS /ws/terminal?serverId=...`

## 配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | HTTP 服务端口 |
| `DATA_DIR` | `./data` | SQLite 和加密密钥目录 |
| `PANEL_STATUS_INTERVAL` | `60` | 状态巡检间隔，单位秒，最小 5 秒 |
| `PANEL_STATUS_CONCURRENCY` | `3` | 同时巡检的 SSH 数量，范围 1-10 |

## 测试

```bash
npm test
```

测试覆盖状态派生、配置一致性、漂移修复、Reality 密钥对、节点分享链接、路由配置和订阅 Token 生命周期。

## 安全注意

- 默认 Docker 映射绑定到 `127.0.0.1`，避免局域网暴露；如果改为局域网绑定，必须限制访问范围。
- 不要把 `data/.secret`、服务器密码、私钥、sudo 密码、订阅完整 Token 或本地数据库提交到 Git。
- 面板自身目前没有登录鉴权，适合只在本机、可信局域网、VPN 或受保护的 HTTPS 反向代理后运行。
- 订阅地址包含访问凭据；重新生成 Token 后旧地址立即失效。
- 状态巡检和订阅接口不会自动连接 VPS；部署、路由连接和漂移修复才会执行远程操作。
- 远程安装脚本需要服务器能访问 GitHub Release；如果网络受限，可后续增加自定义下载地址。

## 后续路线

- 面板登录与操作审计日志
- 单个节点单独部署 / 热更新，而不是始终整机重写配置
- 多服务器批量状态巡检
- 支持 3x-ui 既有配置迁移 / 兼容导入
- 流量统计、在线客户端、二维码分享
- Cloudflare 或自定义二进制下载源
