import { describe, expect, test } from "bun:test";

import { handleOpenAiWhoami } from "../functions/api/openai/whoami";
import {
  OPENAI_CODEX_CLIENT_ID,
  OPENAI_MOBILE_CLIENT_ID,
  OPENAI_OAUTH_TOKEN_URL,
  OPENAI_PAT_WHOAMI_URL,
} from "../src/core";
import {
  refreshOpenAiToken,
  validateOpenAiPersonalAccessToken,
} from "../src/openai-refresh";

describe("Cloudflare OpenAI AT function", () => {
  test("validates at- tokens through the fixed OpenAI whoami endpoint", async () => {
    let forwardedUrl = "";
    let authorization = "";
    let originator = "";
    const response = await handleOpenAiWhoami(new Request(
      "https://session.example/api/openai/whoami",
      {
        method: "POST",
        headers: { "Origin": "https://session.example" },
        body: JSON.stringify({ access_token: "at-input-token" }),
      },
    ), async (input, init) => {
      forwardedUrl = String(input);
      const headers = new Headers(init?.headers);
      authorization = headers.get("Authorization") ?? "";
      originator = headers.get("Originator") ?? "";
      return Response.json({
        email: "pat@example.com",
        chatgpt_user_id: "pat-user",
        chatgpt_account_id: "pat-account",
        chatgpt_plan_type: "pro",
        chatgpt_account_is_fedramp: false,
        ignored_field: "do-not-forward",
      });
    });
    const payload = await response.json() as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(forwardedUrl).toBe(OPENAI_PAT_WHOAMI_URL);
    expect(authorization).toBe("Bearer at-input-token");
    expect(originator).toBe("codex_cli_rs");
    expect(payload).toMatchObject({
      email: "pat@example.com",
      chatgpt_user_id: "pat-user",
      chatgpt_account_id: "pat-account",
      chatgpt_plan_type: "pro",
      chatgpt_account_is_fedramp: false,
    });
    expect(payload.ignored_field).toBeUndefined();
  });

  test("returns JSON when the AT response body cannot be read", async () => {
    const upstream = new Response(null, { status: 502 });
    upstream.text = async () => {
      throw new Error("upstream body terminated");
    };
    const response = await handleOpenAiWhoami(new Request(
      "https://session.example/api/openai/whoami",
      {
        method: "POST",
        body: JSON.stringify({ access_token: "at-input-token" }),
      },
    ), async () => upstream);

    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({
      error: {
        code: "OPENAI_CODEX_PAT_RESPONSE_READ_FAILED",
        message: "OpenAI AT 验证响应读取失败（HTTP 502）",
      },
    });
  });
});

describe("browser RT refresh client", () => {
  test("refreshes directly in the browser and falls back to Mobile client_id", async () => {
    const originalFetch = globalThis.fetch;
    const clientIds: string[] = [];
    const requestedUrls: string[] = [];
    const requestOptions: RequestInit[] = [];
    globalThis.fetch = (async (input, init) => {
      requestedUrls.push(String(input));
      requestOptions.push(init ?? {});
      const form = new URLSearchParams(String(init?.body));
      const clientId = form.get("client_id") ?? "";
      clientIds.push(clientId);
      expect(form.get("grant_type")).toBe("refresh_token");
      expect(form.get("refresh_token")).toBe("input-refresh-token");
      expect(form.get("scope")).toBe("openid profile email");
      if (clientId === OPENAI_CODEX_CLIENT_ID) {
        return Response.json({
          error: "invalid_grant",
          error_description: "client mismatch",
        }, { status: 400 });
      }
      return Response.json({
        access_token: "mobile-access-token",
        refresh_token: "mobile-refresh-token",
        expires_in: 3600,
      });
    }) as typeof fetch;

    try {
      const result = await refreshOpenAiToken("input-refresh-token");
      expect(clientIds).toEqual([
        OPENAI_CODEX_CLIENT_ID,
        OPENAI_MOBILE_CLIENT_ID,
      ]);
      expect(requestedUrls).toEqual([
        OPENAI_OAUTH_TOKEN_URL,
        OPENAI_OAUTH_TOKEN_URL,
      ]);
      expect(requestOptions.every((init) => (
        new Headers(init.headers).get("Content-Type")
          === "application/x-www-form-urlencoded"
        && init.credentials === "omit"
        && init.redirect === "error"
        && init.referrerPolicy === "no-referrer"
      ))).toBe(true);
      expect(result).toMatchObject({
        access_token: "mobile-access-token",
        refresh_token: "mobile-refresh-token",
        client_id: OPENAI_MOBILE_CLIENT_ID,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("does not retry a rotating RT after a browser network or CORS failure", async () => {
    const originalFetch = globalThis.fetch;
    let requests = 0;
    globalThis.fetch = (async (_input, _init): Promise<Response> => {
      requests += 1;
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;

    try {
      await expect(refreshOpenAiToken("input-refresh-token")).rejects.toMatchObject({
        message: "浏览器无法连接 OpenAI OAuth，请切换至 OpenAI 支持地区的网络节点后重试",
        status: 0,
        code: "OPENAI_OAUTH_REQUEST_FAILED",
      });
      expect(requests).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("reads validated account fields without replacing the at- token", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input, _init) => Response.json({
      email: "pat@example.com",
      chatgpt_user_id: "pat-user",
      chatgpt_account_id: "pat-account",
      chatgpt_plan_type: "plus",
      chatgpt_account_is_fedramp: false,
    })) as typeof fetch;

    try {
      const result = await validateOpenAiPersonalAccessToken("at-input-token");
      expect(result).toEqual({
        email: "pat@example.com",
        chatgpt_user_id: "pat-user",
        chatgpt_account_id: "pat-account",
        chatgpt_plan_type: "plus",
        chatgpt_account_is_fedramp: false,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("reports a platform-level plain-text HTTP error", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input, _init) => new Response("error code: 502", {
      status: 502,
      headers: { "Content-Type": "text/plain" },
    })) as typeof fetch;

    try {
      await expect(refreshOpenAiToken("input-refresh-token")).rejects.toMatchObject({
        message: "RT 联网验证接口返回 HTTP 502",
        status: 502,
        code: "OPENAI_OAUTH_REQUEST_FAILED",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("reports a platform-level plain-text AT error", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input, _init) => new Response("error code: 502", {
      status: 502,
      headers: { "Content-Type": "text/plain" },
    })) as typeof fetch;

    try {
      await expect(validateOpenAiPersonalAccessToken("at-input-token"))
        .rejects.toMatchObject({
          message: "AT 联网验证接口返回 HTTP 502",
          status: 502,
          code: "OPENAI_CODEX_PAT_VALIDATE_FAILED",
        });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
