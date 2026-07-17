import { describe, expect, test } from "bun:test";

import { handleOpenAiRefresh } from "../functions/api/openai/refresh";
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
    let forwardedPath = "";
    let authorization = "";
    let originator = "";
    const response = await handleOpenAiWhoami(new Request(
      "https://session.example/api/openai/whoami",
      {
        method: "POST",
        headers: { "Origin": "https://session.example" },
        body: JSON.stringify({ access_token: "at-input-token-value" }),
      },
    ), async (upstream) => {
      forwardedPath = upstream.path;
      authorization = upstream.headers?.Authorization ?? "";
      originator = upstream.headers?.Originator ?? "";
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
    expect(forwardedPath).toBe(new URL(OPENAI_PAT_WHOAMI_URL).pathname);
    expect(authorization).toBe("Bearer at-input-token-value");
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
        body: JSON.stringify({ access_token: "at-input-token-value" }),
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

describe("Cloudflare OpenAI RT function", () => {
  test("forwards only the fixed OAuth form and returns rotated credentials", async () => {
    let forwardedMethod = "";
    let forwardedPath = "";
    let forwardedForm = new URLSearchParams();
    const response = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        headers: { "Origin": "https://session.example" },
        body: JSON.stringify({
          refresh_token: "input-refresh-token",
          client_id: OPENAI_CODEX_CLIENT_ID,
        }),
      },
    ), async (upstream) => {
      forwardedMethod = upstream.method;
      forwardedPath = upstream.path;
      forwardedForm = new URLSearchParams(upstream.body);
      return Response.json({
        access_token: "rotated-access-token",
        refresh_token: "rotated-refresh-token",
        expires_in: 3600,
      });
    });

    expect(response.status).toBe(200);
    expect(forwardedMethod).toBe("POST");
    expect(forwardedPath).toBe(new URL(OPENAI_OAUTH_TOKEN_URL).pathname);
    expect(forwardedForm.get("grant_type")).toBe("refresh_token");
    expect(forwardedForm.get("refresh_token")).toBe("input-refresh-token");
    expect(forwardedForm.get("client_id")).toBe(OPENAI_CODEX_CLIENT_ID);
    expect(forwardedForm.get("scope")).toBe("openid profile email");
    expect(await response.json()).toMatchObject({
      access_token: "rotated-access-token",
      refresh_token: "rotated-refresh-token",
    });
  });

  test("rejects cross-origin credential submission", async () => {
    const response = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        headers: { "Origin": "https://untrusted.example" },
        body: JSON.stringify({
          refresh_token: "input-refresh-token",
          client_id: OPENAI_CODEX_CLIENT_ID,
        }),
      },
    ));

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      error: { code: "ORIGIN_NOT_ALLOWED" },
    });
  });

  test("rejects malformed RT input before making an upstream request", async () => {
    let requested = false;
    const response = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        body: JSON.stringify({
          refresh_token: "<!DOCTYPE html><title>502 Bad gateway</title>",
          client_id: OPENAI_CODEX_CLIENT_ID,
        }),
      },
    ), async () => {
      requested = true;
      return Response.json({});
    });

    expect(response.status).toBe(400);
    expect(requested).toBe(false);
    expect(await response.json()).toMatchObject({
      error: { code: "OPENAI_OAUTH_REFRESH_TOKEN_INVALID" },
    });
  });

  test("returns a clear supported-region message", async () => {
    const response = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        body: JSON.stringify({
          refresh_token: "input-refresh-token",
          client_id: OPENAI_CODEX_CLIENT_ID,
        }),
      },
    ), async () => Response.json({
      error: {
        code: "unsupported_country_region_territory",
        message: "Country, region, or territory not supported",
      },
    }, { status: 403 }));

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: {
        code: "unsupported_country_region_territory",
        message: "当前 Cloudflare 节点不受 OpenAI 支持，请切换至日本、新加坡或美国等支持地区的网络节点后重试",
      },
    });
  });

  test("does not echo unexpected fields from OAuth errors", async () => {
    const response = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        body: JSON.stringify({
          refresh_token: "input-refresh-token",
          client_id: OPENAI_CODEX_CLIENT_ID,
        }),
      },
    ), async () => Response.json({
      error: {
        code: "token_expired",
        message: "Token expired",
        debug_token: "must-not-leak",
      },
      refresh_token: "must-not-leak",
    }, { status: 401 }));
    const payload = await response.json() as Record<string, unknown>;

    expect(response.status).toBe(401);
    expect(payload).toEqual({
      error: {
        code: "token_expired",
        message: "Token expired",
      },
    });
  });
});

describe("browser OpenAI validation client", () => {
  test("refreshes through Pages and falls back to Mobile client_id", async () => {
    const originalFetch = globalThis.fetch;
    const clientIds: string[] = [];
    const requestedUrls: string[] = [];
    const requestOptions: RequestInit[] = [];
    globalThis.fetch = (async (input, init) => {
      requestedUrls.push(String(input));
      requestOptions.push(init ?? {});
      const body = JSON.parse(String(init?.body)) as Record<string, string>;
      const clientId = body.client_id ?? "";
      clientIds.push(clientId);
      expect(body.refresh_token).toBe("input-refresh-token");
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
        "/api/openai/refresh",
        "/api/openai/refresh",
      ]);
      expect(requestOptions.every((init) => (
        new Headers(init.headers).get("Content-Type") === "application/json"
        && init.credentials === "same-origin"
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

  test("does not retry a rotating RT after a Pages network failure", async () => {
    const originalFetch = globalThis.fetch;
    let requests = 0;
    globalThis.fetch = (async (_input, _init): Promise<Response> => {
      requests += 1;
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;

    try {
      await expect(refreshOpenAiToken("input-refresh-token")).rejects.toMatchObject({
        message: "无法连接 RT 联网验证接口，请稍后重试",
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
