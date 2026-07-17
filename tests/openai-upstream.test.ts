import { describe, expect, test } from "bun:test";

import {
  OPENAI_OAUTH_TOKEN_URL,
  OPENAI_PAT_WHOAMI_URL,
} from "../src/core";
import {
  OpenAiUpstreamError,
  requestOpenAiUpstream,
} from "../src/server/openai-upstream";

describe("OpenAI upstream transport", () => {
  test("forwards only fixed OpenAI authentication targets", async () => {
    const requests: Array<{ init?: RequestInit; url: string }> = [];
    const fetcher = (async (input, init) => {
      requests.push({ init, url: String(input) });
      return Response.json({ ok: true });
    }) as typeof fetch;

    await requestOpenAiUpstream({
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "refresh_token=test",
    }, { fetcher });
    await requestOpenAiUpstream({
      method: "GET",
      path: "/api/accounts/v1/user-auth-credential/whoami",
      headers: { "Authorization": "Bearer at-test" },
    }, { fetcher });

    expect(requests.map((request) => request.url)).toEqual([
      OPENAI_OAUTH_TOKEN_URL,
      OPENAI_PAT_WHOAMI_URL,
    ]);
    expect(requests.every((request) => (
      request.init?.cache === "no-store"
      && request.init?.redirect === "error"
    ))).toBe(true);
    await expect(requestOpenAiUpstream({
      method: "GET",
      path: "/untrusted",
    }, { fetcher })).rejects.toBeInstanceOf(OpenAiUpstreamError);
    expect(requests).toHaveLength(2);
  });

  test("returns a controlled error when the upstream request stalls", async () => {
    const fetcher = (() => (
      new Promise<Response>(() => undefined)
    )) as unknown as typeof fetch;

    await expect(requestOpenAiUpstream({
      method: "POST",
      path: "/oauth/token",
      body: "refresh_token=test",
    }, {
      fetcher,
      timeoutMilliseconds: 5,
    })).rejects.toMatchObject({ code: "OPENAI_UPSTREAM_TIMEOUT" });
  });
});
