# AGENTS.md

本文档面向后续开发/维护本项目的 Agent 和开发者，汇总项目背景、当前功能、架构、数据模型、关键流程与开发注意事项。它优先反映当前代码状态；如果与旧版 README 描述不一致，以本文档和代码为准。

## 项目定位

一个运行在本地（也可 Docker 运行）的可视化 VPS 管理面板，通过 SSH 远程操作服务器，用于部署、编辑和重启 Xray 节点，并生成客户端分享链接。产品形态上类似 3x-ui 的节点管理体验，但面板本身不常驻 VPS，所有远程操作都是“面板主动发起 SSH 命令”。

核心原则：

- VPS 上只安装 Xray 本身，不安装面板控制端。
- 服务器密码、私钥、sudo 密码在本机用 AES-256-GCM 加密后落盘。
- Xray `config.json` 统一由面板生成并写入，避免手工 SSH 改配置。
- 本地面板默认只监听本机或 Docker 绑定 `127.0.0.1:3000`。

## 开发历程摘要

按用户实际提出需求的顺序，已完成以下内容：

1. 初始方案：本地运行 + Docker 支持，SSH 远程管理 VPS，面板参考 3x-ui 的部署/编辑节点体验。
2. 服务器快速添加：在“添加服务器”弹窗支持粘贴连接信息，一键解析并填入主机、端口、用户名、密码，支持“识别并保存”直接添加。
3. SSH 连通与状态能力：补充 `probeServer`、`xrayStatus` 等后端能力；用户曾反馈按钮报错，后续统一把服务器卡片上的 `测试 / 状态 / 部署` 按钮移除，避免入口与 API 状态不一致。
4. Reality 密钥对：确认并实现为纯本地生成 X25519 密钥对，不依赖 VPS 连接或 Xray 安装。
5. Reality 伪装站点预设：内置 Microsoft、Apple、Cloudflare、Google、Amazon、Mozilla、Bing、GitHub 等目标站点，支持下拉选择与“随机”轮换 `dest`、`serverNames`、`SNI`。
6. 节点部署与客户端导入：一键部署 Xray、写入配置、重启；节点分享链接可导入 v2rayN 等客户端。
7. SOCKS5 节点：节点协议新增 `socks`，编辑弹窗选择 SOCKS5 后只保留必要字段，不再显示 SNI、加密方式等无关选项。
8. 路由页面：新增“路由”页，分为“入站 / 出站”两个板块；节点添加时可选择作为入站或出站，路由页按角色展示，点击节点可选中，点击“连接所选节点”建立链路。
9. 路由生效逻辑：连接后，在入站节点所在服务器上修改 Xray 配置，使该入站使用所选出站节点作为出口。
10. 进度/结果弹窗：节点部署和路由连接等操作增加“正在执行”弹窗，完成后弹窗展示结果。
11. SSH 终端：服务器卡片去掉 `测试 / 状态 / 部署`，新增“终端”按钮，点击后直接打开 xterm.js SSH 交互窗口；通过 WebSocket 连接真实 shell，支持输入和 resize。
12. 只读状态检查：服务器卡片恢复“状态”按钮，节点卡片新增“检查状态”入口，展示 SSH 连通、Xray 安装/运行、配置存在与有效、端口监听、节点配置匹配等实际状态；所有检查只读，不修改 VPS 文件或服务。
13. 自动状态巡检：后台按 60 秒间隔（`PANEL_STATUS_INTERVAL` 可调）错峰巡检每台服务器，写入 `server_status` 缓存；前端每 20 秒轮询 `GET /api/status`，在总览/服务器/节点页持续展示在线运行、离线、配置不一致、未安装等状态点。
14. 漂移修复：状态区分服务停止/配置缺失/配置不一致/二进制缺失；服务器与节点卡片显示“已漂移”标签和原因，提供“一键修复”确认后执行，全部写入 `repair_logs` 审计；自动修复开关默认关闭，开启后仅自动提示服务停止类漂移。

## 当前页面与入口

| 页面 | 用途 | 主要操作 |
| --- | --- | --- |
| 总览 | 服务器/节点/启用节点统计，最近节点列表 | 查看状态点、点击最近节点查看分享链接 |
| 服务器 | 管理 SSH 目标 | 添加、粘贴识别保存、状态、一键修复、编辑、删除、日志、终端 |
| 节点 | 管理指定服务器上的节点 | 添加/编辑/删除节点、检查状态、一键修复、分享链接、部署全部节点 |
| 路由 | 管理入站到出站的转发链路 | 选择入站/出站节点、连接所选节点、断开链路 |

服务器卡片当前按钮为：`一键修复（漂移时）/ 状态 / 终端 / 日志 / 编辑 / 删除`。漂移时卡片显示“已漂移”标签和原因；节点卡片同样展示漂移标签与一键修复。服务器页工具栏有默认关闭的“自动修复”开关。

## 架构

```text
浏览器 (public/)
  -> Express HTTP API (src/app.js)
  -> SQLite 数据层 (src/db.js)
  -> SSH 执行层 (src/ssh.js)
  -> 远程脚本 (src/remote.js)
  -> Xray 配置生成 (src/xray.js)
  -> VPS 上的 Xray
```

WebSocket 终端：

```text
浏览器 xterm.js
  -> ws://<host>/ws/terminal?serverId=...
  -> src/index.js 中的 WebSocketServer
  -> ssh2 Client.shell()
  -> VPS 交互 shell
```

## 目录结构

```text
public/
  index.html        单页结构：总览/服务器/节点/路由
  app.js            前端状态、渲染、弹窗、事件、终端
  styles.css        样式
src/
  index.js          启动入口；WebSocket SSH 终端服务
  app.js            Express 路由、静态资源、xterm vendor 路由
  db.js             SQLite 表结构与 CRUD
  crypto.js         AES-256-GCM 加解密
  paths.js          数据目录解析（支持 DATA_DIR 环境变量）
  ssh.js            ssh2 连接、脚本执行、sudo 封装
  remote.js         VPS 探测、Xray 安装、配置写入、重启、状态、日志
  xray.js           Xray config 生成、分享链接、Reality 密钥对
  status.js         自动状态巡检调度、状态派生、配置 sha256 一致性
  repair.js         漂移修复执行、动作映射、审计日志写入
test/
  xray.test.js      配置生成与链接测试
  status.test.js    状态派生与缓存记录测试
data/               运行数据（不提交）：panel.db、.secret
Dockerfile
docker-compose.yml
```

## 数据模型

### servers

- `id`：UUID
- `name / host / port / username / notes`
- `auth_type`：`password` 或 `key`
- `password / private_key / passphrase / sudo_password`：均为加密存储
- 对外 API 返回 `has_password / has_private_key / has_passphrase / has_sudo_password`，不返回明文或密文内容

### nodes

- `id / server_id / name`
- `protocol`：`vmess / vless / trojan / shadowsocks / socks`
- `role`：`inbound / outbound`
- `port / network / security`
- `network`：`tcp / ws / grpc / httpupgrade`
- `security`：`none / tls / reality`
- `sni / path / cert_file / key_file / dest / server_names / private_key / public_key / short_ids`
- `method`：Shadowsocks 加密方式，如 `aes-256-gcm`、`chacha20-ietf-poly1305`、`2022-blake3-aes-256-gcm`
- `ss_network`：Shadowsocks 网络，`tcp / udp / tcp,udp`
- `clients_json`：客户端数组，`email / secret / flow / security`（`security` 用于 VMess，如 `auto`、`aes-128-gcm`、`chacha20-poly1305`）
- `enabled`：`1/0`

### routes

- `id`
- `inbound_node_id`：唯一，一个入站只能连接一个出站
- `outbound_node_id`
- `enabled / created_at / updated_at`

### server_status

- `server_id`：主键，对应 servers.id
- `ssh_reachable / xray_installed / xray_bin_present / service_active / config_present / config_match / ports_listening`：`1/0`
- `last_checked_at / last_error / node_status_json / failure_count / next_check_at / updated_at`
- `node_status_json`：每次巡检的快照，含每个节点的 `in_config / listening_tcp / listening_udp / listening`
- `failure_count` 用于指数退避；`next_check_at` 记录下次可巡检时间

### repair_logs

- `id / server_id / server_name`
- `drift_type`：`service_stopped / config_missing / config_mismatch / binary_missing`
- `action`：`restart / write_config_restart / redeploy`
- `result / success / created_at`：执行结果、成败标记、审计时间

### 本地文件

- `data/panel.db`：SQLite
- `data/.secret`：加密密钥文件，不可提交
- Docker 中挂载 `./data:/app/data`

## 核心流程

### 添加服务器

1. 点击“添加服务器”。
2. 可手动填写，或粘贴 `root@IP:端口 密码`、`IP:端口:用户名:密码`、`IP 端口 用户名 密码` 等格式。
3. 点击“识别并填入”只填表单；点击“识别并保存”直接创建。
4. 密码/私钥二选一；非 root 用户可填 sudo 密码。

### 添加并部署节点

1. “节点”页选择目标服务器。
2. 添加节点：选择协议、角色、端口、传输、安全等字段。
   - 表单会按协议显示对应字段：VMess 显示客户端加密方式；VLESS / Trojan + Reality 显示 flow（仅 VLESS）；Shadowsocks 显示加密方式和 TCP/UDP 网络；SOCKS5 只保留用户名/密码。
3. 节点可配置多个客户端，客户端 secret 自动生成。
4. 点击“部署全部节点”：调用 `/api/servers/:id/deploy`，流程为安装 Xray → 写入 config → 重启 → 查询状态。
5. 部署期间显示进度弹窗，完成后显示结果弹窗。

### 路由连接

1. “路由”页选择入站节点和出站节点。
2. 点击“连接所选节点”保存 route，并在入站节点所在服务器上重新部署配置。
3. Xray 配置会为入站生成对应 `outbound`，并添加 `inboundTag -> outboundTag` 的 routing rule。
4. 出站节点如果不在同一服务器且未运行，会先部署出站服务器。
5. 断开链路会删除 route 并重新部署入站服务器。

### 只读状态检查

1. 服务器卡片点击“状态”或节点卡片点击“检查状态”。
2. 后端执行只读脚本：SSH 连通、Xray 二进制与版本、systemd/OpenRC 服务状态、配置文件存在性及内容（base64 读取后本地解析）、TCP/UDP 监听端口。
3. 状态弹窗展示 SSH、Xray 服务、配置文件、监听端口四个摘要项，并列出该服务器下每个节点的“配置已写入 / TCP / UDP / 监听”明细。
4. SSH 失败时返回分类错误（认证失败、连接超时、连接被拒绝、无法解析地址、不可达、连接中断、缺少 sudo 密码），前端明确展示。
5. 非 root 用户读取 600 权限配置失败时，会自动尝试用 sudo 只读读取。

### 自动状态巡检

1. `src/index.js` 启动时调用 `startStatusSweeper()`，默认每 60 秒巡检一轮（`PANEL_STATUS_INTERVAL` 秒）。
2. 每台服务器错峰入队，并发上限默认 3（`PANEL_STATUS_CONCURRENCY`），单次 SSH 超时 15 秒。
3. 巡检失败按指数退避：失败次数 n 时下次间隔为 `interval * 2^(n-1)`，上限 30 分钟；成功后恢复固定间隔。
4. 配置一致性：本地用 `buildXrayConfig` 生成期望配置并计算 sha256，与 VPS 实际 `config.json` sha256 比对，结果写入 `config_match`。
5. `GET /api/status` 聚合返回每台服务器的派生状态与节点快照；前端每 20 秒轮询并刷新状态点。
6. 派生状态：`running / service_stopped / offline / config_mismatch / config_missing / binary_missing / ports_down / unknown`。

### 漂移修复

1. 漂移类型与动作映射：`service_stopped -> restart`、`config_missing/config_mismatch -> write_config_restart`、`binary_missing -> redeploy`。
2. `POST /api/servers/:id/repair` 先校验缓存：无缓存、离线、无漂移或漂移已变化时拒绝执行。
3. 修复复用 `restartXray / writeXrayConfig / deployServer`，不新增远程脚本；不修改 Xray 以外的内容。
4. 每次修复写入 `repair_logs`（时间、服务器、漂移类型、动作、结果、成败）。
5. 前端“一键修复”先弹确认框展示操作摘要；自动修复开关默认关闭，开启后仅对可达且 `service_stopped` 的服务器自动弹出确认框，不自动执行，离线不排队。

### SSH 终端

1. 服务器卡片点击“终端”。
2. 前端打开 modal，加载 xterm.js + FitAddon。
3. 通过 WebSocket 建立 SSH shell，输入和 resize 实时双向同步。
4. 关闭弹窗时断开 WebSocket 并释放 SSH 连接。

## API 摘要

- `GET /api/health`、`GET /api/stats`
- `GET /api/status`：聚合状态接口，返回 `interval_seconds` 与每台服务器的 `server / state / status / nodes`
- `POST /api/servers/:id/repair`：按缓存漂移类型执行修复，返回动作与审计记录
- `GET /api/repair-logs?limit=N`：最近修复审计日志
- `GET /api/servers`
- `POST /api/servers`
- `PUT /api/servers/:id`
- `DELETE /api/servers/:id`
- `POST /api/servers/:id/test`：SSH 连通与系统信息（UI 已不展示按钮，API 保留）
- `GET /api/servers/:id/status`：只读状态检查，返回 `ssh / xray / config / ports / nodes / checked_at`；SSH 失败时 `ok=false` 并带分类错误
- `POST /api/servers/:id/install`
- `POST /api/servers/:id/restart`
- `POST /api/servers/:id/x25519`：本地生成 Reality 密钥对
- `POST /api/servers/:id/deploy`：安装 + 配置 + 重启 + 状态
- `GET /api/servers/:id/logs?lines=N`
- `GET /api/servers/:id/nodes`
- `POST /api/servers/:id/nodes`
- `PUT /api/nodes/:id`
- `DELETE /api/nodes/:id`
- `GET /api/nodes`
- `GET /api/routes`
- `POST /api/routes`
- `DELETE /api/routes/:id`
- `WS /ws/terminal?serverId=...`

## 开发与验证

```bash
npm install
npm run dev       # 打开 http://127.0.0.1:3000
npm start
npm test          # 当前 15 个 node:test 用例
```

Docker：

```bash
docker compose up -d --build
```

要求 Node.js >= 22.5。

环境变量：

- `PANEL_STATUS_INTERVAL`：巡检间隔秒数，默认 `60`，最小 `5`
- `PANEL_STATUS_CONCURRENCY`：同时巡检的 SSH 并发数，默认 `3`，范围 `1-10`

## 重要实现细节与坑

- `@xterm/addon-fit` 的浏览器 UMD 全局是 `window.FitAddon`（一个命名空间对象），不是构造函数。当前代码使用 `typeof FitAddon === 'function' ? FitAddon : FitAddon.FitAddon` 来兼容。
- WebSocket 终端协议：状态消息是 JSON 字符串（如 `{"type":"ready"}`），终端原始输出作为二进制数据发送；前端通过 `typeof event.data === 'string'` 区分协议消息与终端输出。
- 终端初始尺寸来自 xterm `fit()` 后的 `cols/rows`，resize 消息在 shell 就绪后发送。
- 服务器凭据只在服务端 SSH 连接时解密，API 永远不返回明文/密文凭据。
- 非 root 服务器通过 `sudo -S` 执行部署脚本，需要 sudo 密码。
- Xray 安装脚本支持 systemd、OpenRC，以及无服务管理器的 `nohup/setsid` 兜底。
- 自动巡检写入 `server_status` 缓存；`GET /api/status` 只读缓存，不触发新的 SSH 检查。
- 配置一致性用 sha256 比对：本地 `JSON.stringify(buildXrayConfig(...), null, 2)` 与 VPS 原始文件字节一致才算匹配。
- 巡检失败会把 `failure_count` 递增并指数退避，成功时清零；`next_check_at` 控制错峰与重试节奏。
- 漂移状态与修复动作一一映射，服务停止只 `restartXray`，配置类漂移才重写配置，二进制缺失走 `deployServer` 整机重部署。
- 修复必须先确认：前端确认弹窗展示服务器、漂移类型和远程操作摘要；后端拒绝离线/无漂移请求。
- “自动修复”开关默认关闭（localStorage 持久化），开启后仅自动弹出服务停止类确认框，绝不绕过确认执行。
- 所有修复写入 `repair_logs`，可在 `GET /api/repair-logs` 查看。
- 部署使用 base64 传输 `config.json`，避免 SSH 脚本转义问题。
- 路由配置在 `buildXrayConfig` 中按 `routes` 生成 `outbound` 与 routing rule；同一入站只能有一条 route。
- 节点表单按协议动态显隐字段：Shadowsocks 不显示传输/安全/SNI/路径，改用 `method` 与 `ss_network`；VMess 客户端有 `security`；VLESS 只在 Reality 时显示 flow。
- Reality 仅对 VLESS 且传输不为 WS 可用；Trojan、VMess 与 WS 组合会被表单禁用并在后端拒绝。

## 安全与边界
## GitHub 同步

- 远程仓库：`https://github.com/lpc205/vps-node.git`，默认分支 `main`。
- `core.hooksPath=.githooks`，`post-commit` hook 会把当前分支提交自动推送到已配置 upstream。
- `.github/workflows/ci.yml` 在 push 到 `main/master` 时运行 `npm test`。
- 新功能完成后在 `main` 上执行 `git add -A && git commit` 即可自动同步；若 hook 未触发则手动 `git push origin main`。
- `data/`、`node_modules/`、`.env` 已在 `.gitignore` 中，禁止提交面板凭据和本地数据。

- 面板目前没有登录鉴权，默认只在本机或 Docker `127.0.0.1` 暴露。
- `data/.secret`、私钥、密码、UUID 等不要提交或外传。
- 远程安装需要服务器能访问 GitHub Release；网络受限时可后续增加自定义下载源。
- 后续可能方向：面板登录/操作审计、单节点单独热更新、批量状态巡检、3x-ui 配置迁移、流量统计、二维码分享。
