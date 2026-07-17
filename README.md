# Session Bridge

Session Bridge 是一个使用 Bun、TypeScript 和 Vite 构建的 ChatGPT 凭证转换工具，
可直接部署到 Cloudflare Pages。

JSON 的解析、转换、预览和打包均在本地浏览器内完成。AT 与 RT 通过同源
Cloudflare Pages Function 从当前边缘节点访问 OpenAI。

在线预览：[Session Bridge](https://elysiaya.xyz)

## 支持格式

| 输入 | 可导出 |
| --- | --- |
| ChatGPT Web Session | Sub2API、CPA |
| CPA（CLIProxyAPI Codex auth JSON） | Sub2API |
| Sub2API OpenAI OAuth 账号包 | CPA |
| Access Token（`at-`） | Sub2API、CPA |
| Refresh Token | Sub2API、CPA |

CPA 与 Sub2API 可以双向转换，并尽可能保留原格式中的专属字段。

## 核心功能

- 自动识别 Session、CPA 和 Sub2API JSON。
- 支持逐行粘贴 `at-` AT 或 RT，严格校验格式后自动联网验证。
- AT 会联网验证有效性并获取邮箱、账号 ID、用户 ID、套餐和 FedRAMP 状态，token 本身不会被替换。
- RT 通过当前 Cloudflare 节点向 OpenAI 换取 Access Token、ID Token 和新 Refresh Token，再生成可用的 Sub2API 或 CPA 凭证。
- 自动尝试 Codex CLI 与 Mobile OAuth `client_id`，无需手动选择 RT 类型。
- 支持粘贴、连续 JSON、JSON 数组、多文件、目录和拖拽导入；单次最多处理 500 个 JSON、总计 50 MB。
- 导入 JSON 时，可从其中的 access token JWT claims 补齐邮箱、账号 ID、用户 ID、套餐和过期时间。
- Sub2API 多账号合并导出。
- CPA 单账号 JSON 与多账号 ZIP 导出。
- 默认脱敏 token、password、client_secret 等敏感字段。
- 预览使用脱敏数据，复制和下载使用完整 JSON。
- AT 与 RT 仅能访问固定的 OpenAI 认证路径，不会将服务暴露为通用代理。

## 隐私与安全

- JSON 文件不离开浏览器；手动输入的 AT 与 RT 通过本站 Pages Function 转发至 OpenAI。
- Pages Function 不记录、不缓存、不持久化 AT、RT 或 OpenAI 返回的凭证。
- 不写入 localStorage、sessionStorage、IndexedDB 或 Cookie。
- 页面 CSP 仅允许访问同源接口：`connect-src 'self'`。
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

需要测试 AT / RT 联网验证时，使用 Pages Functions 本地环境：

```bash
bun run dev:pages
```

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
- `wrangler.jsonc` 已为 Pages Functions 启用 `nodejs_compat`，无需在 Dashboard 重复配置。

AT / RT 验证依赖当前 Cloudflare 边缘节点所在地区。若提示地区不受支持，
请将访问本站的网络节点切换至日本、新加坡、美国等 OpenAI 支持地区后重试。

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
src/core/openai-oauth.ts   OpenAI OAuth 客户端与响应类型
src/core/token-format.ts   AT / RT 输入格式校验
src/openai-refresh.ts      同源 AT / RT 验证客户端及双 client_id 回退
src/server/openai-upstream.ts 固定 OpenAI 目标、超时与网络错误处理
src/server/pages-api.ts    Pages API 请求校验与安全响应
src/core/redaction.ts      预览敏感字段脱敏
src/core/zip.ts            无依赖 ZIP 打包
functions/api/openai/      Cloudflare Pages AT / RT 验证接口
public/_headers            Cloudflare Pages 安全响应头
wrangler.jsonc             Pages 输出目录与运行时兼容配置
scripts/check-build.ts     生产构建完整性与隐私边界检查
tests/core.test.ts         解析、互转、脱敏与 ZIP 回归测试
tests/openai-refresh.test.ts  AT / RT 接口与客户端回退测试
tests/openai-upstream.test.ts 固定目标与超时安全边界测试
```

## License

MIT
