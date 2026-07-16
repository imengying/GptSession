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

describe("Cloudflare OpenAI refresh function", () => {
  test("forwards only the supported OAuth refresh request", async () => {
    let forwardedUrl = "";
    let forwardedForm = "";
    let forwardedUserAgent = "";
    const response = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Origin": "https://session.example",
        },
        body: JSON.stringify({
          refresh_token: "input-refresh-token",
          client_id: OPENAI_CODEX_CLIENT_ID,
        }),
      },
    ), async (input, init) => {
      forwardedUrl = String(input);
      forwardedForm = String(init?.body ?? "");
      forwardedUserAgent = new Headers(init?.headers).get("User-Agent") ?? "";
      return Response.json({
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        id_token: "new-id-token",
        expires_in: 3600,
        ignored_field: "do-not-forward",
      });
    });
    const payload = await response.json() as Record<string, unknown>;
    const form = new URLSearchParams(forwardedForm);

    expect(response.status).toBe(200);
    expect(forwardedUrl).toBe(OPENAI_OAUTH_TOKEN_URL);
    expect(forwardedUserAgent).toBe("codex-cli/0.91.0");
    expect(form.get("grant_type")).toBe("refresh_token");
    expect(form.get("refresh_token")).toBe("input-refresh-token");
    expect(form.get("client_id")).toBe(OPENAI_CODEX_CLIENT_ID);
    expect(form.get("scope")).toBe("openid profile email");
    expect(payload).toMatchObject({
      access_token: "new-access-token",
      refresh_token: "new-refresh-token",
      id_token: "new-id-token",
      expires_in: 3600,
    });
    expect(payload.ignored_field).toBeUndefined();
  });

  test("rejects cross-origin and unsupported client requests", async () => {
    let forwarded = false;
    const fetcher = async (): Promise<Response> => {
      forwarded = true;
      return Response.json({ access_token: "unexpected" });
    };
    const crossOrigin = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        headers: { "Origin": "https://attacker.example" },
        body: JSON.stringify({
          refresh_token: "input-refresh-token",
          client_id: OPENAI_CODEX_CLIENT_ID,
        }),
      },
    ), fetcher);
    const unsupportedClient = await handleOpenAiRefresh(new Request(
      "https://session.example/api/openai/refresh",
      {
        method: "POST",
        body: JSON.stringify({
          refresh_token: "input-refresh-token",
          client_id: "untrusted-client-id",
        }),
      },
    ), fetcher);

    expect(crossOrigin.status).toBe(403);
    expect(unsupportedClient.status).toBe(400);
    expect(forwarded).toBe(false);
  });

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
});

describe("browser RT refresh client", () => {
  test("automatically falls back from Codex CLI to Mobile client_id", async () => {
    const originalFetch = globalThis.fetch;
    const clientIds: string[] = [];
    globalThis.fetch = (async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { client_id: string };
      clientIds.push(body.client_id);
      if (body.client_id === OPENAI_CODEX_CLIENT_ID) {
        return Response.json({
          error: { code: "invalid_grant", message: "client mismatch" },
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
      expect(result).toMatchObject({
        access_token: "mobile-access-token",
        refresh_token: "mobile-refresh-token",
        client_id: OPENAI_MOBILE_CLIENT_ID,
      });
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
});
