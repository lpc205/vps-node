# 贡献指南

欢迎任何形式的贡献：提 Issue、修 Bug、加功能、补文档、做 Code Review 都可以。项目遵循下面的开源迭代流程：

1. 在 Issue 中描述需求或 Bug，维护者确认方向和优先级。
2. 功能类改动先讨论方案，避免做完才发现方向不对。
3. 从主干拉分支开发，提交 Pull Request。
4. CI 自动跑测试，维护者 Review 后合并。
5. 变更进入 `CHANGELOG.md`，随新版本发布。

## 开发环境

要求 Node.js >= 22.5。

```bash
npm install
npm run dev
```

打开 <http://127.0.0.1:3000>。测试用：

```bash
npm test
```

## 提 Issue

- Bug：使用 Bug 模板，说明运行环境、复现步骤、实际行为和期望行为，尽量附上日志。
- 新功能：使用功能模板，说明要解决的问题和使用场景，而不是只给一个功能名。
- 不要在任何 Issue 中粘贴服务器密码、私钥、sudo 密码、UUID 等敏感信息。

## 提 Pull Request

### 分支命名

建议按变更类型命名：

- `feat/xxx`：新功能
- `fix/xxx`：修复
- `docs/xxx`：文档
- `refactor/xxx`：重构
- `test/xxx`：测试

### 提交信息

使用 Conventional Commits 风格，主题尽量简短：

```text
feat: 支持单个节点单独部署
fix: 修复 WebSocket 终端断开后资源未释放
```

### 合并前检查

- 改动范围保持聚焦，不要夹带无关重构。
- `npm test` 全部通过；涉及新行为时补充测试。
- 功能或行为变化同步更新 `README.md`。
- 在 `CHANGELOG.md` 的 `[Unreleased]` 下追加一条变更说明。
- 不提交 `data/`、`.secret`、私钥、日志等敏感或本地文件。

## 发布流程

维护者负责发版，节奏建议是：

1. 确认 `[Unreleased]` 中的变更已整理。
2. 按 SemVer 提升 `package.json` 的 `version`。
3. 把 `[Unreleased]` 重命名成版本号并补充日期。
4. 打 tag，例如 `v0.2.0`，推送到 GitHub。
5. 创建 GitHub Release，附上对应版本的变更记录。

## 代码风格

- 前端和后端都保持现有风格，不做大规模格式化噪音。
- 注释只解释“为什么”，不解释“做了什么”。
- 新抽象只在能明显减少重复时才引入。
