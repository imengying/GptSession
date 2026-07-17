import {
  isOpenAiOAuthClientId,
  OPENAI_OAUTH_SCOPE,
  OPENAI_OAUTH_TOKEN_URL,
} from "../../../src/core/openai-oauth";
import {
  OpenAiProxyError,
  requestOpenAiViaSingaporeProxy,
  type OpenAiUpstreamRequester,
} from "../../../src/server/openai-proxy";
import {
  assertSameOriginPost,
  jsonResponse,
  pagesApiErrorResponse,
  readJsonObject,
  readString,
  type JsonRecord,
} from "../../../src/server/pages-api";

interface PagesEnvironment {
  OPENAI_PROXY_HOSTS?: string;
}

interface PagesContext {
  env?: PagesEnvironment;
  request: Request;
}

const MAX_REFRESH_TOKEN_LENGTH = 16 * 1024;
const OAUTH_TOKEN_PATH = new URL(OPENAI_OAUTH_TOKEN_URL).pathname;

function safeOAuthErrorPayload(payload: JsonRecord, status: number): JsonRecord {
  const nested = payload.error && typeof payload.error === "object"
    ? payload.error as JsonRecord
    : undefined;
  const code = readString(nested?.code)
    ?? readString(payload.code)
    ?? readString(payload.error)
    ?? "OPENAI_OAUTH_REQUEST_FAILED";
  const message = readString(nested?.message)
    ?? readString(payload.error_description)
    ?? readString(payload.message)
    ?? "OpenAI OAuth 验证失败（HTTP " + status + "）";
  if (nested) {
    return {
      error: {
        code,
        message,
        type: readString(nested.type),
      },
    };
  }
  return {
    error: code,
    error_description: message,
  };
}

export async function handleOpenAiRefresh(
  request: Request,
  requester: OpenAiUpstreamRequester = requestOpenAiViaSingaporeProxy,
): Promise<Response> {
  let body: JsonRecord;
  try {
    assertSameOriginPost(request);
    body = await readJsonObject(request, 24 * 1024);
  } catch (error) {
    return pagesApiErrorResponse(error);
  }

  const refreshToken = readString(body.refresh_token);
  const clientId = readString(body.client_id);
  if (!refreshToken || refreshToken.length > MAX_REFRESH_TOKEN_LENGTH) {
    return jsonResponse({
      error: {
        code: "OPENAI_OAUTH_REFRESH_TOKEN_INVALID",
        message: "Refresh Token 无效",
      },
    }, 400);
  }
  if (!isOpenAiOAuthClientId(clientId)) {
    return jsonResponse({
      error: {
        code: "OPENAI_OAUTH_CLIENT_ID_INVALID",
        message: "OpenAI OAuth client_id 不受支持",
      },
    }, 400);
  }

  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId,
    scope: OPENAI_OAUTH_SCOPE,
  });

  let upstream: Response;
  try {
    upstream = await requester({
      method: "POST",
      path: OAUTH_TOKEN_PATH,
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "session-bridge/0.1.0",
      },
      body: form.toString(),
      signal: request.signal,
    });
  } catch (error) {
    const proxyError = error instanceof OpenAiProxyError ? error : undefined;
    return jsonResponse({
      error: {
        code: proxyError?.code ?? "OPENAI_OAUTH_REQUEST_FAILED",
        message: proxyError?.message ?? "无法通过新加坡线路连接 OpenAI OAuth",
      },
    }, 502);
  }

  let payload: JsonRecord;
  try {
    const parsed = JSON.parse(await upstream.text()) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    payload = parsed as JsonRecord;
  } catch {
    return jsonResponse({
      error: {
        code: "OPENAI_OAUTH_RESPONSE_INVALID",
        message: "OpenAI OAuth 返回了无效响应（HTTP " + upstream.status + "）",
      },
    }, 502);
  }

  return jsonResponse(
    upstream.ok ? payload : safeOAuthErrorPayload(payload, upstream.status),
    upstream.status,
  );
}

export function onRequest(context: PagesContext): Promise<Response> {
  return handleOpenAiRefresh(context.request, (upstreamRequest) => (
    requestOpenAiViaSingaporeProxy(upstreamRequest, {
      proxyHosts: context.env?.OPENAI_PROXY_HOSTS,
    })
  ));
}
