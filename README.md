# Session Bridge

ChatGPT Web Session、Sub2API、CPA、Agent Identity 与 Grok 凭证转换工具。JSON 在浏览器内完成转换，RT、AT 与 SSO 由同一 Rust 服务联网验证。

浏览器端使用 WebAssembly memory64，请使用较新的 Chrome、Edge、Brave 或其他支持 memory64 的浏览器。

预览：<https://elysiaya.xyz>

| 输入 | 可导出格式 |
| --- | --- |
| ChatGPT Web Session | Sub2API、CPA |
| CPA Codex JSON | Sub2API、CPA |
| Sub2API OpenAI OAuth JSON | CPA、Sub2API |
| RT（OpenAI Codex、OpenAI Mobile、Grok） | Sub2API、CPA |
| AT（`at-` Access Token） | Sub2API、CPA |
| AI（Agent Identity JSON） | Sub2API、CPA |
| SSO（Grok Web） | Sub2API、CPA |
| CPA xAI JSON | Sub2API、CPA |
| Sub2API Grok OAuth JSON | CPA、Sub2API |

## Docker 部署

### 方案一：Docker Compose

```bash
git clone https://github.com/imengying/GptSession.git
cd GptSession
docker compose up -d
```

### 方案二：Docker 命令

```bash
docker run -d --name gptsession --restart unless-stopped \
  -p 127.0.0.1:3000:3000 \
  ghcr.io/imengying/gptsession:latest
```

## 二进制部署

Releases 提供 Linux amd64 和 arm64 二进制文件。以 amd64 为例：

```bash
curl -fLO https://github.com/imengying/GptSession/releases/latest/download/session-bridge-linux-amd64.tar.gz
tar -xzf session-bridge-linux-amd64.tar.gz
sudo install -m 755 session-bridge /usr/local/bin/session-bridge
session-bridge
```

arm64 服务器将文件名中的 `amd64` 改为 `arm64`。服务固定监听 `0.0.0.0:3000`。

## License

MIT
