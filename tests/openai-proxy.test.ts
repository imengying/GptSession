import { describe, expect, test } from "bun:test";

import {
  buildOpenAiHttpRequest,
  decodeChunkedHttpBody,
  OpenAiProxyError,
  parseOpenAiHttpResponse,
  parseOpenAiProxyHosts,
  resolveOpenAiProxyCandidates,
} from "../src/server/openai-proxy";

describe("OpenAI Singapore proxy transport", () => {
  test("parses explicit proxy endpoints without accepting URLs", () => {
    expect(parseOpenAiProxyHosts(
      "1.2.3.4:443, Proxy.Example:8443;proxy.example:8443 https://bad.example",
    )).toEqual([
      { host: "1.2.3.4", port: 443 },
      { host: "proxy.example", port: 8443 },
    ]);
  });

  test("resolves a proxy pool to independent TCP candidates", async () => {
    const candidates = await resolveOpenAiProxyCandidates(
      "pool.session-bridge.test:443",
      (async () => Response.json({
        Answer: [
          { type: 5, data: "target.example" },
          { type: 1, data: "203.0.113.10" },
          { type: 1, data: "203.0.113.11" },
        ],
      })) as unknown as typeof fetch,
    );

    expect(candidates).toContainEqual({ host: "203.0.113.10", port: 443 });
    expect(candidates).toContainEqual({ host: "203.0.113.11", port: 443 });
  });

  test("builds only fixed auth.openai.com requests", () => {
    const request = new TextDecoder().decode(buildOpenAiHttpRequest({
      method: "POST",
      path: "/oauth/token",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "refresh_token=secret&client_id=client",
    }));

    expect(request).toContain("POST /oauth/token HTTP/1.1\r\n");
    expect(request).toContain("Host: auth.openai.com\r\n");
    expect(request).toContain("Accept-Encoding: identity\r\n");
    expect(request).toContain("Content-Length: 37\r\n");
    expect(request.endsWith("refresh_token=secret&client_id=client")).toBe(true);
    expect(() => buildOpenAiHttpRequest({
      method: "GET",
      path: "/untrusted",
    })).toThrow(OpenAiProxyError);
  });

  test("rejects request header injection", () => {
    expect(() => buildOpenAiHttpRequest({
      method: "GET",
      path: "/api/accounts/v1/user-auth-credential/whoami",
      headers: { "Authorization": "Bearer safe\r\nHost: attacker.example" },
    })).toThrow("OpenAI 验证请求无效");
  });

  test("parses content-length OpenAI responses and keeps safe diagnostics", async () => {
    const response = parseOpenAiHttpResponse(new TextEncoder().encode(
      "HTTP/1.1 401 Unauthorized\r\n"
      + "Content-Type: application/json\r\n"
      + "Content-Length: 15\r\n"
      + "CF-Ray: test-SIN\r\n"
      + "Set-Cookie: private=value\r\n\r\n"
      + "{\"error\":\"bad\"}",
    ));

    expect(response.status).toBe(401);
    expect(response.headers.get("cf-ray")).toBe("test-SIN");
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(await response.json()).toEqual({ error: "bad" });
  });

  test("decodes chunked HTTP response bodies", async () => {
    expect(new TextDecoder().decode(decodeChunkedHttpBody(new TextEncoder().encode(
      "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
    )))).toBe("Wikipedia");

    const response = parseOpenAiHttpResponse(new TextEncoder().encode(
      "HTTP/1.1 200 OK\r\n"
      + "Content-Type: application/json\r\n"
      + "Transfer-Encoding: chunked\r\n\r\n"
      + "7\r\n{\"ok\":1\r\n1\r\n}\r\n0\r\n\r\n",
    ));
    expect(await response.json()).toEqual({ ok: 1 });
  });

  test("fails closed on malformed HTTP framing", () => {
    expect(() => decodeChunkedHttpBody(new TextEncoder().encode(
      "invalid\r\ndata\r\n",
    ))).toThrow("OpenAI 验证响应无效");
    expect(() => parseOpenAiHttpResponse(new TextEncoder().encode(
      "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
    ))).toThrow("OpenAI 验证响应无效");
  });
});
