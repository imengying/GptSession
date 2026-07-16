import { OPENAI_PAT_WHOAMI_URL } from "../../../src/core/openai-oauth";

type Fetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

interface PagesContext {
  request: Request;
}

interface JsonRecord {
  [key: string]: unknown;
}

const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_ACCESS_TOKEN_LENGTH = 8 * 1024;

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store, max-age=0",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function safeUpstreamMessage(payload: unknown, status: number): string {
  if (payload && typeof payload === "object") {
    const record = payload as JsonRecord;
    const nested = record.error && typeof record.error === "object"
      ? record.error as JsonRecord
      : undefined;
    return readString(nested?.message)
      ?? readString(record.message)
      ?? "OpenAI AT 验证失败（HTTP " + status + "）";
  }
  return "OpenAI AT 验证失败（HTTP " + status + "）";
}

export async function handleOpenAiWhoami(
  request: Request,
  fetcher: Fetcher = fetch,
): Promise<Response> {
  if (request.method !== "POST") {
    return jsonResponse({ error: { code: "METHOD_NOT_ALLOWED", message: "仅支持 POST" } }, 405);
  }

  const requestUrl = new URL(request.url);
  const origin = request.headers.get("Origin");
  if (origin && origin !== requestUrl.origin) {
    return jsonResponse({ error: { code: "ORIGIN_NOT_ALLOWED", message: "请求来源不受信任" } }, 403);
  }

  const contentLength = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BYTES) {
    return jsonResponse({ error: { code: "REQUEST_TOO_LARGE", message: "请求内容过大" } }, 413);
  }

  let rawBody: string;
  try {
    rawBody = await request.text();
  } catch {
    return jsonResponse({ error: { code: "INVALID_BODY", message: "无法读取请求内容" } }, 400);
  }
  if (new TextEncoder().encode(rawBody).byteLength > MAX_REQUEST_BYTES) {
    return jsonResponse({ error: { code: "REQUEST_TOO_LARGE", message: "请求内容过大" } }, 413);
  }

  let body: JsonRecord;
  try {
    const parsed = JSON.parse(rawBody) as unknown;
    if (!parsed || typeof parsed !== "object") {
      throw new Error("not an object");
    }
    body = parsed as JsonRecord;
  } catch {
    return jsonResponse({ error: { code: "INVALID_JSON", message: "请求 JSON 无效" } }, 400);
  }

  const accessToken = readString(body.access_token);
  if (
    !accessToken
    || !accessToken.startsWith("at-")
    || accessToken.length <= 3
    || accessToken.length > MAX_ACCESS_TOKEN_LENGTH
  ) {
    return jsonResponse({
      error: {
        code: "OPENAI_CODEX_PAT_INVALID_PREFIX",
        message: "Personal Access Token 必须以 at- 开头",
      },
    }, 400);
  }

  let upstream: Response;
  try {
    upstream = await fetcher(OPENAI_PAT_WHOAMI_URL, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Authorization": "Bearer " + accessToken,
        "Originator": "codex_cli_rs",
        "User-Agent": "codex-cli/0.91.0",
      },
      redirect: "error",
    });
  } catch {
    return jsonResponse({
      error: {
        code: "OPENAI_CODEX_PAT_NETWORK_ERROR",
        message: "Cloudflare 无法连接 OpenAI AT 验证服务",
      },
    }, 502);
  }

  const text = await upstream.text();
  let payload: JsonRecord = {};
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === "object") {
      payload = parsed as JsonRecord;
    }
  } catch {
    payload = {};
  }

  if (upstream.status === 401 || upstream.status === 403) {
    return jsonResponse({
      error: {
        code: "OPENAI_CODEX_PAT_INVALID",
        message: "Personal Access Token 无效或已过期",
      },
    }, 400);
  }
  if (!upstream.ok) {
    return jsonResponse({
      error: {
        code: "OPENAI_CODEX_PAT_VALIDATE_FAILED",
        message: safeUpstreamMessage(payload, upstream.status),
      },
    }, 502);
  }

  const output = {
    email: readString(payload.email),
    chatgpt_user_id: readString(payload.chatgpt_user_id),
    chatgpt_account_id: readString(payload.chatgpt_account_id),
    chatgpt_plan_type: readString(payload.chatgpt_plan_type),
    chatgpt_account_is_fedramp: payload.chatgpt_account_is_fedramp,
  };
  const missing = Object.entries(output).find(([, value]) => (
    value === undefined || value === null
  ))?.[0];
  if (missing || typeof output.chatgpt_account_is_fedramp !== "boolean") {
    return jsonResponse({
      error: {
        code: "OPENAI_CODEX_PAT_RESPONSE_INVALID",
        message: "OpenAI AT 验证结果缺少必要字段" + (missing ? "：" + missing : ""),
      },
    }, 502);
  }

  return jsonResponse(output);
}

export function onRequest(context: PagesContext): Promise<Response> {
  return handleOpenAiWhoami(context.request);
}
