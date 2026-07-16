# Session Bridge

一个使用 Bun + TypeScript + Vite 构建的浏览器端凭证转换工具，可直接部署到
Cloudflare Pages。当前实现：

- ChatGPT Web Session → sub2api
- ChatGPT Web Session → CPA（CLIProxyAPI Codex auth JSON）
- CPA → sub2api
- sub2api → CPA

## 特性

- 自动识别 ChatGPT Session、CPA 和 sub2api JSON
- 支持粘贴单个对象、数组、嵌套对象、连续 JSON 和 JSONL 风格输入
- 支持拖拽、多个 JSON 文件和目录导入
- 从 access token JWT claims 补齐邮箱、账号 ID、用户 ID、套餐与过期时间
- CPA token 字段与普通元数据分离写入 sub2api credentials / extra
- sub2api 转 CPA 时保留 token、扩展 credentials、extra、账号配置和文档级元数据
- sub2api 多账号合并导出
- CPA 单账号 JSON 与多账号 ZIP 导出
- 默认脱敏 token、password、client_secret 等敏感字段，复制和下载仍使用完整 JSON
- 不上传凭证、不写入 localStorage / IndexedDB / Cookie
- 严格 TypeScript，使用 Bun 安装、测试和运行脚本
- Vite 生产构建，页面运行时零第三方依赖
- 内置 Cloudflare Pages CSP、安全响应头和静态资源缓存规则

## 本地使用

安装 Bun 1.3.14 后：

    bun install
    bun run dev

Vite 会输出本地访问地址，默认是：

    http://127.0.0.1:5173

登录 ChatGPT 后，可从下面的地址获取 Session JSON：

    https://chatgpt.com/api/auth/session

Session 中包含等同登录凭证的敏感 token。只应在可信设备上处理，不要发送给其他人。

检查生产构建：

    bun run build
    bun run preview

构建产物位于 dist/。

## 部署到 Cloudflare Pages

在 Cloudflare Dashboard 连接 Git 仓库后使用以下配置：

- Framework preset：None
- Build command：bun run build
- Build output directory：dist
- Root directory：仓库根目录

仓库包含 bun.lock、packageManager 和 .bun-version，Cloudflare 构建环境可据此使用
Bun 1.3.14。

也可以通过命令行发布到 Pages：

    bun install
    bunx --bun wrangler login
    bun run deploy

这个项目不需要环境变量、数据库、KV、D1 或任何服务端密钥。public/_headers 会被
Vite 复制到 dist，并在 Cloudflare 上启用严格 CSP，明确禁止页面脚本发起网络连接。

## 输出约定

输入 CPA 时会自动选择 sub2api 作为目标格式；输入 sub2api 时会自动选择 CPA。
也可以随时通过页面上的导出格式开关手动切换。

### sub2api

输出为以下批量导入结构：

    {
      "exported_at": "...",
      "proxies": [],
      "accounts": []
    }

每个 OpenAI OAuth account 默认包含 concurrency 10、priority 1、rate_multiplier 1
和 credentials。
没有 refresh token 时，账号级 expires_at 使用 access token JWT 的 exp 秒级时间戳，
并设置 auto_pause_on_expired。存在 refresh token 时不设置账号暂停到期时间。

CPA 转换时，access_token、refresh_token、id_token、session_token 写入 credentials；
CPA 的其他字段写入 extra。这样再次转回 CPA 时可以恢复账号名、source、自定义元数据
和过期时间。若输入本身是 sub2api，concurrency、priority、rate_multiplier、
auto_pause_on_expired 和 expires_at 会被保留。

### CPA

每个账号生成一个 type 为 codex 的认证 JSON。输入缺少真实 id_token 时，会根据
Session 和 access token claims 构造带 session_bridge_synthetic 标记的占位 JWT，
用于满足 CPA 的解析结构；它不是真实签发的 OAuth id token。

sub2api 转出的 CPA 会附带 session_bridge 元数据。该字段不改变 CPA 的标准
认证字段，仅用于再次转回 sub2api 时还原扩展 credentials、空对象配置、extra、
账号级设置以及 type、version、proxies 等文档级字段。原文件不存在的合成
id_token 不会被写回 sub2api credentials。

sub2api 转换时，从 credentials 恢复 token、邮箱、account_id 和套餐；从 extra 恢复
CPA 元数据。账号级或 credentials 中的数字时间戳会转换为 UTC ISO 时间，根级
exported_at 在缺少 last_refresh 时作为回退值。当前只转换 platform=openai 且
type=oauth 的 sub2api 账号，其他平台或账号类型会安全跳过并显示提示。

ChatGPT Web Session 通常没有 refresh_token，因此 access token 到期后无法自动刷新。
格式转换也不能绕过 OpenAI 的手机验证、账号权限或模型权限限制。

## 项目结构

    index.html                Vite 页面入口
    src/core/credentials.ts   三种格式解析、统一账号模型和双向导出器
    src/core/redaction.ts     预览敏感字段脱敏
    src/core/types.ts         核心数据结构与导出类型
    src/core/zip.ts           无依赖 ZIP 打包
    src/core/index.ts         核心模块公共入口
    src/app.ts                页面状态、导入、预览、复制与下载
    src/styles.css            响应式界面样式
    public/_headers           Cloudflare 安全头与缓存规则
    vite.config.ts            Vite 生产构建配置
    scripts/check-build.ts    Cloudflare Pages 构建完整性检查
    dist/                     生产构建产物（不提交）

credentials.ts 将 Session、CPA 和 sub2api 账号统一归一化后，再交给 CPA 或 sub2api 导出器。
双向转换共用同一套字段解析、JWT claims 补全、去重和安全提示逻辑。

## 构建检查

运行严格类型检查：

    bun run typecheck

完整发布前检查：

    bun run build

## License

MIT
