# Session Bridge

Session Bridge 是一个纯浏览器端的 ChatGPT 凭证转换工具，使用 Bun、TypeScript 和
Vite 构建，可直接部署到 Cloudflare Pages。

所有解析、转换、预览与打包均在当前浏览器内完成，凭证不会上传到服务器。

## 支持格式

| 输入 | 可导出 |
| --- | --- |
| ChatGPT Web Session | sub2api、CPA |
| CPA（CLIProxyAPI Codex auth JSON） | sub2api |
| sub2api OpenAI OAuth 账号包 | CPA |

CPA 与 sub2api 可以双向转换，并尽可能保留原格式中的专属字段。

## 核心功能

- 自动识别 Session、CPA 和 sub2api JSON。
- 支持粘贴、连续 JSON、JSON 数组、多文件、目录和拖拽导入。
- 从 access token JWT claims 补齐邮箱、账号 ID、用户 ID、套餐和过期时间。
- sub2api 多账号合并导出。
- CPA 单账号 JSON 与多账号 ZIP 导出。
- 默认脱敏 token、password、client_secret 等敏感字段。
- 预览使用脱敏数据，复制和下载使用完整 JSON。
- 无服务端 API，无数据库，页面运行时零第三方依赖。

## 隐私与安全

- 不上传凭证。
- 不写入 localStorage、sessionStorage、IndexedDB 或 Cookie。
- 页面 CSP 禁止运行时网络连接：`connect-src 'none'`。
- Cloudflare Pages 通过 `public/_headers` 应用安全响应头和静态资源缓存规则。

Session 和认证 JSON 包含等同登录权限的敏感 token，只应在可信设备上处理。

## 本地开发

需要 Bun 1.3.14：

```bash
bun install --frozen-lockfile
bun run dev
```

默认访问地址：

```text
http://127.0.0.1:5173
```

生产构建与本地预览：

```bash
bun run build
bun run preview
```

构建产物位于 `dist/`。

## Cloudflare Pages 部署

### Git 自动部署

在 Cloudflare Dashboard 中创建 Pages 项目并连接 GitHub 仓库，使用以下配置：

| 配置项 | 值 |
| --- | --- |
| Framework preset | `None` |
| Production branch | `main` |
| Build command | `bun run build` |
| Build output directory | `dist` |
| Root directory | `/` |
| Deploy command | 不填写 |

配置完成后：

- 推送到 `main` 分支会自动更新生产环境。
- 其他分支和 Pull Request 可生成独立预览环境。
- 不需要环境变量、数据库或 Cloudflare 服务端密钥。

### 命令行手动部署

```bash
bun install --frozen-lockfile
bunx --bun wrangler login
bun run deploy
```

## 项目结构

```text
index.html                 Vite 页面入口
src/app.ts                 页面状态、导入、预览、复制与下载
src/styles.css             响应式界面样式
src/core/index.ts          核心模块公共入口
src/core/types.ts          核心数据结构与导出类型
src/core/credentials.ts    凭证解析、归一化和双向转换
src/core/redaction.ts      预览敏感字段脱敏
src/core/zip.ts            无依赖 ZIP 打包
public/_headers            Cloudflare Pages 安全响应头
scripts/check-build.ts     生产构建完整性与隐私边界检查
```

## License

MIT
