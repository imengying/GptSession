import {
  isOpenAiOAuthClientId,
  OPENAI_OAUTH_SCOPE,
  OPENAI_OAUTH_TOKEN_URL,
} from "../../../src/core/openai-oauth";
import {
  manualTokenValidationError,
} from "../../../src/core/token-format";
import {
  OPENAI_UNSUPPORTED_REGION_MESSAGE,
  OpenAiUpstreamError,
  requestOpenAiUpstream,
  type OpenAiUpstreamRequester,
} from "../../../src/server/openai-upstream";
import {
  assertSameOriginPost,
  jsonResponse,
  pagesApiErrorResponse,
  readJsonObject,
  readString,
  type JsonRecord,
} from "../../../src/server/pages-api";

interface PagesContext {
  request: Request;
}

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
  const safeMessage = code === "unsupported_country_region_territory"
    ? OPENAI_UNSUPPORTED_REGION_MESSAGE
    : message;
  if (nested) {
    return {
      error: {
        code,
        message: safeMessage,
        type: readString(nested.type),
      },
    };
  }
  return {
    error: code,
    error_description: safeMessage,
  };
}

export async function handleOpenAiRefresh(
  request: Request,
  requester: OpenAiUpstreamRequester = requestOpenAiUpstream,
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
  const refreshTokenError = refreshToken
    ? manualTokenValidationError(refreshToken, "rt")
    : "Refresh Token 无效";
  if (!refreshToken || refreshTokenError) {
    return jsonResponse({
      error: {
        code: "OPENAI_OAUTH_REFRESH_TOKEN_INVALID",
        message: refreshTokenError ?? "Refresh Token 无效",
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
    const upstreamError = error instanceof OpenAiUpstreamError ? error : undefined;
    return jsonResponse({
      error: {
        code: upstreamError?.code ?? "OPENAI_OAUTH_REQUEST_FAILED",
        message: upstreamError?.message ?? "无法连接 OpenAI OAuth",
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
  return handleOpenAiRefresh(context.request, requestOpenAiUpstream);
}
