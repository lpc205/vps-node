# VPS 节点控制台

一个运行在本地的可视化 VPS 管理面板：通过 SSH 连接你的 VPS，在网页上部署、编辑和重启 Xray 节点，并生成客户端分享链接。

## 为什么这样设计

- 面板只运行在本地，VPS 上不安装任何常驻控制端，只安装 Xray 本身。
- 所有远程操作都是“面板发起 SSH 命令”，适合轻量 VPS，也方便迁移和审计。
- 服务器密码、私钥、sudo 密码保存在本机 SQLite 外的密钥文件中，使用 AES-256-GCM 加密后再落盘。
- 支持 Docker 运行，数据目录挂载到宿主机，删除容器不会丢配置。
- 节点配置统一由面板生成 `config.json`，避免手工 SSH 修改容易出错。

## 已实现

- 服务器管理：SSH 密码 / 私钥认证，保存连接信息，测试连接，查看系统信息。
- 服务器快速添加：粘贴 `root@IP:端口 密码`、`IP:端口:用户名:密码` 或 `IP 端口 用户名 密码` 等格式，一键识别并保存。
- 节点管理：VMess、VLESS、Trojan、Shadowsocks，TCP / WebSocket / gRPC / HTTPUpgrade，无加密 / TLS / Reality。
- 客户端管理：每个节点可配置多个客户端，自动生成 UUID / 密码。
- 一键部署：自动检测架构、安装 Xray、写入 systemd 服务、生成配置并重启。
- 远程状态与日志：查看 Xray 版本、运行状态、监听端口和最近日志。
- 分享链接：生成 VMess / VLESS / Trojan / Shadowsocks 客户端链接。
- Reality 密钥对：在节点编辑页本地生成 X25519 公私钥，不依赖 VPS 连接或 Xray 安装。
- Reality 伪装站点预设：内置常见目标站点，可下拉选择或点击“随机”轮换 `dest`、`serverNames` 和 `SNI`。

## 快速开始

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

打开 <http://127.0.0.1:3000>。数据保存在 `./data`，包含 `panel.db` 和加密密钥 `.secret`。

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
3. 点击“测试”确认 SSH 连通。
4. 在“节点”页选择服务器，添加节点和客户端。
5. 点击“部署全部节点”完成安装和启动。
6. 在节点卡片中点击“分享”复制客户端链接。

## 目录结构

```text
public/             前端静态面板
src/
  app.js            HTTP 路由与静态资源
  db.js             SQLite 数据层
  crypto.js         本地密钥加密
  ssh.js            SSH 执行层
  remote.js         远程探测、安装、配置、重启、日志
  xray.js           Xray 配置生成与分享链接
test/               单元测试
Dockerfile
docker-compose.yml
```

## API 摘要

- `GET /api/servers`、`POST/PUT/DELETE /api/servers/:id`
- `POST /api/servers/:id/test`：SSH 连通与系统信息
- `POST /api/servers/:id/deploy`：安装 + 写入配置 + 重启
- `POST /api/servers/:id/x25519`：生成 Reality 密钥对
- `GET /api/servers/:id/status|logs`
- `GET/POST /api/servers/:id/nodes`、`PUT/DELETE /api/nodes/:id`

## 安全注意

- 默认只监听容器内 3000，Docker 映射绑定到 `127.0.0.1`，避免局域网暴露。
- 不要把 `data/.secret` 和私钥内容提交到 Git。
- 面板自身目前没有登录鉴权，适合只在本机或受控网络运行。后续可加 `PANEL_TOKEN` 或登录页。
- 远程安装脚本需要服务器能访问 GitHub Release；如果网络受限，可后续增加自定义下载地址。

## 后续路线

- 面板登录与操作审计日志
- 单个节点单独部署 / 热更新，而不是始终整机重写配置
- 多服务器批量状态巡检
- 支持 3x-ui 既有配置迁移 / 兼容导入
- 流量统计、在线客户端、二维码分享
- Cloudflare 或自定义二进制下载源
