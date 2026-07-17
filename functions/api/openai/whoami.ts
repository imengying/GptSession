import { OPENAI_PAT_WHOAMI_URL } from "../../../src/core/openai-oauth";
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

const MAX_ACCESS_TOKEN_LENGTH = 8 * 1024;
const WHOAMI_PATH = new URL(OPENAI_PAT_WHOAMI_URL).pathname;

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

function upstreamErrorCode(payload: JsonRecord): string | undefined {
  const nested = payload.error && typeof payload.error === "object"
    ? payload.error as JsonRecord
    : undefined;
  return readString(nested?.code) ?? readString(payload.code);
}

export async function handleOpenAiWhoami(
  request: Request,
  requester: OpenAiUpstreamRequester = requestOpenAiViaSingaporeProxy,
): Promise<Response> {
  let body: JsonRecord;
  try {
    assertSameOriginPost(request);
    body = await readJsonObject(request);
  } catch (error) {
    return pagesApiErrorResponse(error);
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
    upstream = await requester({
      method: "GET",
      path: WHOAMI_PATH,
      headers: {
        "Accept": "application/json",
        "Authorization": "Bearer " + accessToken,
        "Originator": "codex_cli_rs",
        "User-Agent": "codex-cli/0.91.0",
      },
      signal: request.signal,
    });
  } catch (error) {
    const proxyError = error instanceof OpenAiProxyError ? error : undefined;
    return jsonResponse({
      error: {
        code: proxyError?.code ?? "OPENAI_CODEX_PAT_NETWORK_ERROR",
        message: proxyError?.message ?? "无法通过新加坡线路连接 OpenAI AT 验证服务",
      },
    }, 502);
  }

  let text: string;
  try {
    text = await upstream.text();
  } catch {
    return jsonResponse({
      error: {
        code: "OPENAI_CODEX_PAT_RESPONSE_READ_FAILED",
        message: "OpenAI AT 验证响应读取失败（HTTP " + upstream.status + "）",
      },
    }, 502);
  }
  let payload: JsonRecord = {};
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      payload = parsed as JsonRecord;
    }
  } catch {
    payload = {};
  }

  const errorCode = upstreamErrorCode(payload);
  if (errorCode === "unsupported_country_region_territory") {
    return jsonResponse({
      error: {
        code: errorCode,
        message: safeUpstreamMessage(payload, upstream.status),
      },
    }, 502);
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
        code: errorCode ?? "OPENAI_CODEX_PAT_VALIDATE_FAILED",
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
  return handleOpenAiWhoami(context.request, (upstreamRequest) => (
    requestOpenAiViaSingaporeProxy(upstreamRequest, {
      proxyHosts: context.env?.OPENAI_PROXY_HOSTS,
    })
  ));
}
