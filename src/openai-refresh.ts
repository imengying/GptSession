import {
  OPENAI_CODEX_CLIENT_ID,
  OPENAI_MOBILE_CLIENT_ID,
  type OpenAiOAuthClientId,
  type OpenAiOAuthTokenInfo,
  type OpenAiPersonalAccessTokenInfo,
} from "./core";

interface RefreshErrorPayload {
  error?: {
    code?: unknown;
    message?: unknown;
  };
}

interface ParsedResponse<T> {
  payload: RefreshErrorPayload & Partial<T>;
  plainText?: string;
}

export class OpenAiRefreshError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(message: string, status = 0, code = "OPENAI_OAUTH_REQUEST_FAILED") {
    super(message);
    this.name = "OpenAiRefreshError";
    this.code = code;
    this.status = status;
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

async function parseResponse<T>(response: Response): Promise<ParsedResponse<T>> {
  const text = await response.text().catch(() => "");
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === "object") {
      return {
        payload: parsed as RefreshErrorPayload & Partial<T>,
      };
    }
  } catch {
    // A platform-level Cloudflare error can be plain text rather than JSON.
  }
  return {
    payload: {},
    plainText: stringValue(text),
  };
}

function httpErrorMessage(
  label: "RT" | "AT",
  response: Response,
  plainText?: string,
): string {
  const platformError = plainText?.toLowerCase() === "error code: " + response.status;
  if (plainText && !platformError && plainText.length <= 200) {
    return label + " 联网验证失败（HTTP " + response.status + "）：" + plainText;
  }
  return label + " 联网验证接口返回 HTTP " + response.status;
}

async function requestRefreshToken(
  refreshToken: string,
  clientId: OpenAiOAuthClientId,
  signal?: AbortSignal,
): Promise<OpenAiOAuthTokenInfo> {
  let response: Response;
  try {
    response = await fetch("/api/openai/refresh", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        refresh_token: refreshToken,
        client_id: clientId,
      }),
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new OpenAiRefreshError("无法连接 RT 联网验证接口，请稍后重试");
  }

  const { payload, plainText } = await parseResponse<OpenAiOAuthTokenInfo>(response);
  if (!response.ok) {
    if (response.status === 404) {
      throw new OpenAiRefreshError(
        "RT 联网验证接口不可用，请通过 Cloudflare Pages Functions 运行项目",
        response.status,
        "PAGES_FUNCTION_NOT_FOUND",
      );
    }
    const code = stringValue(payload.error?.code) ?? "OPENAI_OAUTH_REQUEST_FAILED";
    const message = stringValue(payload.error?.message)
      ?? httpErrorMessage("RT", response, plainText);
    throw new OpenAiRefreshError(message, response.status, code);
  }

  const accessToken = stringValue(payload.access_token);
  if (!accessToken) {
    throw new OpenAiRefreshError(
      "OpenAI 返回结果中缺少 access_token",
      502,
      "OPENAI_OAUTH_ACCESS_TOKEN_MISSING",
    );
  }

  return {
    ...payload,
    access_token: accessToken,
    client_id: clientId,
  } as OpenAiOAuthTokenInfo;
}

function shouldTryMobileClient(error: unknown): boolean {
  if (!(error instanceof OpenAiRefreshError)) {
    return false;
  }
  if (error.code.toLowerCase().includes("reused")) {
    return false;
  }
  return error.status === 400 || error.status === 401;
}

export async function refreshOpenAiToken(
  refreshToken: string,
  signal?: AbortSignal,
): Promise<OpenAiOAuthTokenInfo> {
  try {
    return await requestRefreshToken(
      refreshToken,
      OPENAI_CODEX_CLIENT_ID,
      signal,
    );
  } catch (error) {
    if (!shouldTryMobileClient(error)) {
      throw error;
    }
  }

  return requestRefreshToken(refreshToken, OPENAI_MOBILE_CLIENT_ID, signal);
}

export async function validateOpenAiPersonalAccessToken(
  accessToken: string,
  signal?: AbortSignal,
): Promise<OpenAiPersonalAccessTokenInfo> {
  let response: Response;
  try {
    response = await fetch("/api/openai/whoami", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ access_token: accessToken }),
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new OpenAiRefreshError("无法连接 AT 联网验证接口，请稍后重试");
  }

  const { payload, plainText } = await parseResponse<OpenAiPersonalAccessTokenInfo>(response);
  if (!response.ok) {
    if (response.status === 404) {
      throw new OpenAiRefreshError(
        "AT 联网验证接口不可用，请通过 Cloudflare Pages Functions 运行项目",
        response.status,
        "PAGES_FUNCTION_NOT_FOUND",
      );
    }
    const code = stringValue(payload.error?.code) ?? "OPENAI_CODEX_PAT_VALIDATE_FAILED";
    const message = stringValue(payload.error?.message)
      ?? httpErrorMessage("AT", response, plainText);
    throw new OpenAiRefreshError(message, response.status, code);
  }

  const required = {
    email: stringValue(payload.email),
    chatgpt_user_id: stringValue(payload.chatgpt_user_id),
    chatgpt_account_id: stringValue(payload.chatgpt_account_id),
    chatgpt_plan_type: stringValue(payload.chatgpt_plan_type),
  };
  const missing = Object.entries(required).find(([, value]) => !value)?.[0];
  if (missing || typeof payload.chatgpt_account_is_fedramp !== "boolean") {
    throw new OpenAiRefreshError(
      "OpenAI AT 验证结果缺少必要账号字段",
      502,
      "OPENAI_CODEX_PAT_RESPONSE_INVALID",
    );
  }

  return {
    email: required.email ?? "",
    chatgpt_user_id: required.chatgpt_user_id ?? "",
    chatgpt_account_id: required.chatgpt_account_id ?? "",
    chatgpt_plan_type: required.chatgpt_plan_type ?? "",
    chatgpt_account_is_fedramp: payload.chatgpt_account_is_fedramp,
  };
}
