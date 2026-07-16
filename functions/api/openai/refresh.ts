import {
  OPENAI_OAUTH_SCOPE,
  OPENAI_OAUTH_TOKEN_URL,
  isOpenAiOAuthClientId,
} from "../../../src/core/openai-oauth";

type Fetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

interface PagesContext {
  request: Request;
}

interface RefreshRequestBody {
  refresh_token?: unknown;
  client_id?: unknown;
}

interface JsonRecord {
  [key: string]: unknown;
}

const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_REFRESH_TOKEN_LENGTH = 8 * 1024;

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

function safeOAuthError(payload: unknown, status: number): JsonRecord {
  const record = payload && typeof payload === "object"
    ? payload as JsonRecord
    : {};
  const nested = record.error && typeof record.error === "object"
    ? record.error as JsonRecord
    : undefined;
  const stringError = readString(record.error);
  const code = readString(nested?.code)
    ?? stringError
    ?? readString(record.code)
    ?? "OPENAI_OAUTH_REQUEST_FAILED";
  const message = readString(nested?.message)
    ?? readString(record.error_description)
    ?? readString(record.message)
    ?? "OpenAI OAuth 请求失败（HTTP " + status + "）";
  return { error: { code, message } };
}

function selectTokenFields(payload: JsonRecord): JsonRecord {
  const output: JsonRecord = {};
  for (const key of [
    "access_token",
    "refresh_token",
    "id_token",
    "token_type",
    "expires_in",
    "scope",
  ]) {
    if (payload[key] !== undefined) {
      output[key] = payload[key];
    }
  }
  return output;
}

export async function handleOpenAiRefresh(
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

  let body: RefreshRequestBody;
  try {
    body = JSON.parse(rawBody) as RefreshRequestBody;
  } catch {
    return jsonResponse({ error: { code: "INVALID_JSON", message: "请求 JSON 无效" } }, 400);
  }
  if (!body || typeof body !== "object") {
    return jsonResponse({ error: { code: "INVALID_JSON", message: "请求 JSON 必须是对象" } }, 400);
  }

  const refreshToken = readString(body.refresh_token);
  if (!refreshToken || refreshToken.length > MAX_REFRESH_TOKEN_LENGTH) {
    return jsonResponse({ error: { code: "INVALID_REFRESH_TOKEN", message: "Refresh Token 格式无效" } }, 400);
  }
  if (!isOpenAiOAuthClientId(body.client_id)) {
    return jsonResponse({ error: { code: "INVALID_CLIENT_ID", message: "OAuth client_id 不受支持" } }, 400);
  }

  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: body.client_id,
    scope: OPENAI_OAUTH_SCOPE,
  });

  let upstream: Response;
  try {
    upstream = await fetcher(OPENAI_OAUTH_TOKEN_URL, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "codex-cli/0.91.0",
      },
      body: form,
      redirect: "error",
    });
  } catch {
    return jsonResponse({
      error: {
        code: "OPENAI_OAUTH_NETWORK_ERROR",
        message: "Cloudflare 无法连接 OpenAI OAuth 服务",
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

  if (!upstream.ok) {
    return jsonResponse(safeOAuthError(payload, upstream.status), upstream.status);
  }
  if (!readString(payload.access_token)) {
    return jsonResponse({
      error: {
        code: "OPENAI_OAUTH_ACCESS_TOKEN_MISSING",
        message: "OpenAI 返回结果中缺少 access_token",
      },
    }, 502);
  }

  return jsonResponse(selectTokenFields(payload));
}

export function onRequest(context: PagesContext): Promise<Response> {
  return handleOpenAiRefresh(context.request);
}
