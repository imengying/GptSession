import type {
  connect as connectCloudflareSocket,
  Socket as CloudflareSocket,
} from "cloudflare:sockets";

import {
  OPENAI_OAUTH_TOKEN_URL,
  OPENAI_PAT_WHOAMI_URL,
} from "../core/openai-oauth";

export interface OpenAiProxyRequest {
  method: "GET" | "POST";
  path: string;
  headers?: Readonly<Record<string, string>>;
  body?: string;
  signal?: AbortSignal;
}

export interface OpenAiProxyOptions {
  proxyHosts?: string;
  fetcher?: typeof fetch;
  socketConnector?: OpenAiSocketConnector;
  connectTimeoutMilliseconds?: number;
  responseTimeoutMilliseconds?: number;
}

export interface OpenAiProxyCandidate {
  host: string;
  port: number;
}

export type OpenAiUpstreamRequester = (
  request: OpenAiProxyRequest,
) => Promise<Response>;

export type OpenAiSocketConnector = typeof connectCloudflareSocket;

export class OpenAiProxyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "OpenAiProxyError";
    this.code = code;
  }
}

const OPENAI_AUTH_HOST = "auth.openai.com";
// A verified member reduces cold-start latency; the DNS pool remains the fallback.
const PREFERRED_SINGAPORE_PROXY = "128.199.255.242:443";
const DEFAULT_PROXY_POOL = PREFERRED_SINGAPORE_PROXY + ",sin.proxyip.cmliussss.net:443";
const DNS_JSON_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const DNS_CACHE_MILLISECONDS = 5 * 60 * 1000;
const DNS_TIMEOUT_MILLISECONDS = 3_000;
const TLS_TIMEOUT_MILLISECONDS = 5_000;
const RESPONSE_TIMEOUT_MILLISECONDS = 10_000;
const CONNECT_BATCH_SIZE = 3;
const MAX_PROXY_CANDIDATES = 6;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const OAUTH_TOKEN_PATH = new URL(OPENAI_OAUTH_TOKEN_URL).pathname;
const PAT_WHOAMI_PATH = new URL(OPENAI_PAT_WHOAMI_URL).pathname;
const ALLOWED_REQUESTS = new Set([
  "POST " + OAUTH_TOKEN_PATH,
  "GET " + PAT_WHOAMI_PATH,
]);

interface DnsJsonAnswer {
  data?: unknown;
  type?: unknown;
}

interface DnsJsonResponse {
  Answer?: DnsJsonAnswer[];
}

interface CachedDnsResult {
  expiresAt: number;
  hosts: string[];
}

interface TlsAttempt {
  close: () => void;
  promise: Promise<CloudflareSocket>;
}

const dnsCache = new Map<string, CachedDnsResult>();
let lastSuccessfulProxy = PREFERRED_SINGAPORE_PROXY;

function candidateKey(candidate: OpenAiProxyCandidate): string {
  return candidate.host + ":" + candidate.port;
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => (
    /^\d{1,3}$/u.test(part) && Number(part) >= 0 && Number(part) <= 255
  ));
}

function isValidHostname(value: string): boolean {
  return value.length <= 253
    && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(value);
}

export function parseOpenAiProxyHosts(value: string): OpenAiProxyCandidate[] {
  const unique = new Map<string, OpenAiProxyCandidate>();
  for (const entry of value.split(/[\s,;]+/u)) {
    const input = entry.trim();
    if (!input || input.includes("://")) {
      continue;
    }

    let host = input;
    let port = 443;
    const portMatch = /^(.*):(\d{1,5})$/u.exec(input);
    if (portMatch && !portMatch[1]?.includes(":")) {
      host = portMatch[1] ?? "";
      port = Number(portMatch[2]);
    }
    host = host.trim().toLowerCase();
    if (
      !host
      || (!isIpv4(host) && !isValidHostname(host))
      || !Number.isInteger(port)
      || port < 1
      || port > 65_535
    ) {
      continue;
    }

    const candidate = { host, port };
    unique.set(candidateKey(candidate), candidate);
    if (unique.size >= MAX_PROXY_CANDIDATES) {
      break;
    }
  }
  return [...unique.values()];
}

async function resolveIpv4Hosts(
  host: string,
  fetcher: typeof fetch,
): Promise<string[]> {
  if (isIpv4(host)) {
    return [host];
  }

  const cached = dnsCache.get(host);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.hosts;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DNS_TIMEOUT_MILLISECONDS);
  try {
    const url = new URL(DNS_JSON_ENDPOINT);
    url.searchParams.set("name", host);
    url.searchParams.set("type", "A");
    const response = await fetcher(url, {
      cache: "no-store",
      headers: { "Accept": "application/dns-json" },
      signal: controller.signal,
    });
    if (!response.ok) {
      return [];
    }
    const payload = await response.json() as DnsJsonResponse;
    const hosts = [...new Set((payload.Answer ?? []).flatMap((answer) => (
      answer.type === 1 && typeof answer.data === "string" && isIpv4(answer.data)
        ? [answer.data]
        : []
    )))];
    if (hosts.length) {
      dnsCache.set(host, {
        expiresAt: Date.now() + DNS_CACHE_MILLISECONDS,
        hosts,
      });
    }
    return hosts;
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

function shuffleCandidates(
  candidates: OpenAiProxyCandidate[],
): OpenAiProxyCandidate[] {
  const output = [...candidates];
  for (let index = output.length - 1; index > 0; index -= 1) {
    const random = crypto.getRandomValues(new Uint32Array(1))[0] ?? 0;
    const target = random % (index + 1);
    [output[index], output[target]] = [output[target]!, output[index]!];
  }
  if (lastSuccessfulProxy) {
    const index = output.findIndex((candidate) => (
      candidateKey(candidate) === lastSuccessfulProxy
    ));
    if (index > 0) {
      output.unshift(...output.splice(index, 1));
    }
  }
  return output;
}

export async function resolveOpenAiProxyCandidates(
  proxyHosts = DEFAULT_PROXY_POOL,
  fetcher: typeof fetch = fetch,
): Promise<OpenAiProxyCandidate[]> {
  const configured = parseOpenAiProxyHosts(proxyHosts);
  if (!configured.length) {
    throw new OpenAiProxyError(
      "OPENAI_PROXY_CONFIGURATION_INVALID",
      "新加坡验证线路配置无效",
    );
  }

  const resolvedCandidates = await Promise.all(configured.map(async (candidate) => ({
    candidate,
    hosts: await resolveIpv4Hosts(candidate.host, fetcher),
  })));
  const expanded = new Map<string, OpenAiProxyCandidate>();
  for (const { candidate, hosts } of resolvedCandidates) {
    const resolvedHosts = hosts.length ? hosts : [candidate.host];
    for (const host of resolvedHosts) {
      const resolved = { host, port: candidate.port };
      expanded.set(candidateKey(resolved), resolved);
      if (expanded.size >= MAX_PROXY_CANDIDATES) {
        break;
      }
    }
    if (expanded.size >= MAX_PROXY_CANDIDATES) {
      break;
    }
  }
  return shuffleCandidates([...expanded.values()].slice(0, MAX_PROXY_CANDIDATES));
}

let defaultSocketConnectorPromise: Promise<OpenAiSocketConnector> | undefined;

function loadDefaultSocketConnector(): Promise<OpenAiSocketConnector> {
  defaultSocketConnectorPromise ??= import("cloudflare:sockets").then((module) => (
    module.connect
  ));
  return defaultSocketConnectorPromise;
}

function closeSocket(socket: CloudflareSocket | undefined): void {
  try {
    if (socket) {
      void socket.close().catch(() => undefined);
    }
  } catch {
    // The socket may already have been invalidated by startTls().
  }
}

function observeSocketClose(socket: CloudflareSocket): void {
  void socket.closed.catch(() => undefined);
}

function startTlsAttempt(
  candidate: OpenAiProxyCandidate,
  connector: OpenAiSocketConnector,
  timeoutMilliseconds: number,
): TlsAttempt {
  let transport: CloudflareSocket | undefined;
  let socket: CloudflareSocket | undefined;
  let settled = false;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let rejectPromise: ((error: Error) => void) | undefined;

  const clearAttemptTimeout = (): void => {
    if (timeout) {
      clearTimeout(timeout);
      timeout = undefined;
    }
  };

  const close = (): void => {
    clearAttemptTimeout();
    closeSocket(socket);
    closeSocket(transport);
    if (!settled) {
      settled = true;
      rejectPromise?.(new Error("TLS connection cancelled"));
    }
  };

  const fail = (error: unknown): void => {
    if (settled) {
      return;
    }
    settled = true;
    clearAttemptTimeout();
    closeSocket(socket);
    closeSocket(transport);
    rejectPromise?.(
      error instanceof Error ? error : new Error("TLS connection failed"),
    );
  };

  const promise = new Promise<CloudflareSocket>((resolve, reject) => {
    rejectPromise = reject;
    try {
      transport = connector({
        hostname: candidate.host,
        port: candidate.port,
      }, {
        allowHalfOpen: false,
        secureTransport: "starttls",
      });
      observeSocketClose(transport);
      socket = transport.startTls({ expectedServerHostname: OPENAI_AUTH_HOST });
      observeSocketClose(socket);
      timeout = setTimeout(() => {
        fail(new Error("TLS connection timed out"));
      }, timeoutMilliseconds);
      socket.opened.then(() => {
        if (settled || !socket) {
          return;
        }
        settled = true;
        clearAttemptTimeout();
        resolve(socket);
      }, fail);
    } catch (error) {
      fail(error);
    }
  });

  return { close, promise };
}

async function openAuthorizedTlsSocket(
  candidates: OpenAiProxyCandidate[],
  connector: OpenAiSocketConnector,
  timeoutMilliseconds: number,
): Promise<CloudflareSocket> {
  for (let offset = 0; offset < candidates.length; offset += CONNECT_BATCH_SIZE) {
    const batch = candidates.slice(offset, offset + CONNECT_BATCH_SIZE);
    const attempts = batch.map((candidate) => (
      startTlsAttempt(candidate, connector, timeoutMilliseconds)
    ));
    try {
      const winner = await Promise.any(attempts.map(async (attempt, index) => ({
        index,
        socket: await attempt.promise,
      })));
      attempts.forEach((attempt, index) => {
        if (index !== winner.index) {
          attempt.close();
        }
      });
      lastSuccessfulProxy = candidateKey(batch[winner.index]!);
      return winner.socket;
    } catch {
      attempts.forEach((attempt) => attempt.close());
    }
  }
  throw new OpenAiProxyError(
    "OPENAI_PROXY_CONNECT_FAILED",
    "新加坡验证线路暂时不可用，请稍后重试",
  );
}

function assertSafeHeader(name: string, value: string): void {
  if (!/^[A-Za-z0-9-]+$/u.test(name) || /[\r\n]/u.test(value)) {
    throw new OpenAiProxyError(
      "OPENAI_PROXY_REQUEST_INVALID",
      "OpenAI 验证请求无效",
    );
  }
}

export function buildOpenAiHttpRequest(request: OpenAiProxyRequest): Uint8Array {
  if (!ALLOWED_REQUESTS.has(request.method + " " + request.path)) {
    throw new OpenAiProxyError(
      "OPENAI_PROXY_TARGET_NOT_ALLOWED",
      "OpenAI 验证目标不受支持",
    );
  }

  const body = Buffer.from(request.body ?? "", "utf8");
  const headers = new Map<string, string>([
    ["Host", OPENAI_AUTH_HOST],
    ["Accept", "application/json"],
    ["Accept-Encoding", "identity"],
    ["Connection", "close"],
  ]);
  const forbiddenHeaders = new Set([
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "transfer-encoding",
  ]);
  for (const [name, value] of Object.entries(request.headers ?? {})) {
    assertSafeHeader(name, value);
    if (!forbiddenHeaders.has(name.toLowerCase())) {
      headers.set(name, value);
    }
  }
  if (body.byteLength || request.method === "POST") {
    headers.set("Content-Length", String(body.byteLength));
  }

  const head = request.method + " " + request.path + " HTTP/1.1\r\n"
    + [...headers].map(([name, value]) => name + ": " + value).join("\r\n")
    + "\r\n\r\n";
  return Buffer.concat([Buffer.from(head, "utf8"), body]);
}

function findCrlf(buffer: Buffer, offset: number): number {
  return buffer.indexOf("\r\n", offset, "latin1");
}

export function decodeChunkedHttpBody(input: Uint8Array): Uint8Array {
  const buffer = Buffer.from(input);
  const chunks: Buffer[] = [];
  let offset = 0;
  let totalBytes = 0;

  while (offset < buffer.byteLength) {
    const lineEnd = findCrlf(buffer, offset);
    if (lineEnd < 0) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
    }
    const sizeText = buffer.toString("latin1", offset, lineEnd).split(";", 1)[0]?.trim() ?? "";
    if (!/^[0-9a-f]+$/iu.test(sizeText)) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
    }
    const size = Number.parseInt(sizeText, 16);
    offset = lineEnd + 2;
    if (size === 0) {
      return Buffer.concat(chunks, totalBytes);
    }
    if (size > MAX_RESPONSE_BYTES || offset + size + 2 > buffer.byteLength) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
    }
    chunks.push(buffer.subarray(offset, offset + size));
    totalBytes += size;
    if (totalBytes > MAX_RESPONSE_BYTES) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_TOO_LARGE", "OpenAI 验证响应过大");
    }
    offset += size;
    if (buffer[offset] !== 0x0d || buffer[offset + 1] !== 0x0a) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
    }
    offset += 2;
  }
  throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
}

export function parseOpenAiHttpResponse(input: Uint8Array): Response {
  const buffer = Buffer.from(input);
  let responseOffset = 0;

  while (true) {
    const headerEnd = buffer.indexOf("\r\n\r\n", responseOffset, "latin1");
    if (headerEnd < 0 || headerEnd - responseOffset > MAX_HEADER_BYTES) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
    }
    const headerText = buffer.toString("latin1", responseOffset, headerEnd);
    const lines = headerText.split("\r\n");
    const statusMatch = /^HTTP\/1\.[01] (\d{3})(?: |$)/u.exec(lines.shift() ?? "");
    const status = Number(statusMatch?.[1]);
    if (!Number.isInteger(status) || status < 100 || status > 599) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
    }
    responseOffset = headerEnd + 4;
    if (status >= 100 && status < 200) {
      continue;
    }

    const headers = new Map<string, string>();
    for (const line of lines) {
      const colon = line.indexOf(":");
      if (colon <= 0) {
        throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
      }
      const name = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      headers.set(name, headers.has(name) ? headers.get(name) + ", " + value : value);
    }

    let body = buffer.subarray(responseOffset);
    if (headers.get("transfer-encoding")?.toLowerCase().includes("chunked")) {
      body = Buffer.from(decodeChunkedHttpBody(body));
    } else if (headers.has("content-length")) {
      const contentLength = Number(headers.get("content-length"));
      if (
        !Number.isInteger(contentLength)
        || contentLength < 0
        || contentLength > MAX_RESPONSE_BYTES
        || body.byteLength < contentLength
      ) {
        throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_INVALID", "OpenAI 验证响应无效");
      }
      body = body.subarray(0, contentLength);
    }
    if (body.byteLength > MAX_RESPONSE_BYTES) {
      throw new OpenAiProxyError("OPENAI_PROXY_RESPONSE_TOO_LARGE", "OpenAI 验证响应过大");
    }

    const responseHeaders = new Headers();
    for (const name of ["content-type", "cf-ray", "x-request-id"]) {
      const value = headers.get(name);
      if (value) {
        responseHeaders.set(name, value);
      }
    }
    return new Response(status === 204 || status === 304 ? null : body, {
      status,
      headers: responseHeaders,
    });
  }
}

async function exchangeHttpRequest(
  socket: CloudflareSocket,
  requestBytes: Uint8Array,
  signal?: AbortSignal,
  timeoutMilliseconds = RESPONSE_TIMEOUT_MILLISECONDS,
): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      closeSocket(socket);
      fail(new Error("OpenAI response timed out"));
    }, timeoutMilliseconds);

    const cleanup = (): void => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", onAbort);
    };
    const finish = (response: Buffer): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve(response);
    };
    function fail(error: unknown): void {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(error instanceof Error ? error : new Error("OpenAI request failed"));
    }
    function onAbort(): void {
      fail(new DOMException("The operation was aborted", "AbortError"));
      closeSocket(socket);
    }

    if (signal?.aborted) {
      onAbort();
      return;
    }
    signal?.addEventListener("abort", onAbort, { once: true });

    const exchange = async (): Promise<Buffer> => {
      const writer = socket.writable.getWriter();
      try {
        await writer.write(requestBytes);
      } finally {
        writer.releaseLock();
      }

      const reader = socket.readable.getReader();
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            return Buffer.concat(chunks, totalBytes);
          }
          totalBytes += value.byteLength;
          if (totalBytes > MAX_RESPONSE_BYTES + MAX_HEADER_BYTES) {
            throw new Error("OpenAI response is too large");
          }
          chunks.push(Buffer.from(value));
        }
      } finally {
        reader.releaseLock();
      }
    };
    void exchange().then(finish, fail);
  });
}

export async function requestOpenAiViaSingaporeProxy(
  request: OpenAiProxyRequest,
  options: OpenAiProxyOptions = {},
): Promise<Response> {
  const requestBytes = buildOpenAiHttpRequest(request);
  const candidates = await resolveOpenAiProxyCandidates(
    options.proxyHosts ?? DEFAULT_PROXY_POOL,
    options.fetcher ?? fetch,
  );
  const connector = options.socketConnector ?? await loadDefaultSocketConnector();
  const socket = await openAuthorizedTlsSocket(
    candidates,
    connector,
    options.connectTimeoutMilliseconds ?? TLS_TIMEOUT_MILLISECONDS,
  );
  try {
    const rawResponse = await exchangeHttpRequest(
      socket,
      requestBytes,
      request.signal,
      options.responseTimeoutMilliseconds ?? RESPONSE_TIMEOUT_MILLISECONDS,
    );
    return parseOpenAiHttpResponse(rawResponse);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    if (error instanceof OpenAiProxyError) {
      throw error;
    }
    throw new OpenAiProxyError(
      "OPENAI_PROXY_REQUEST_FAILED",
      "新加坡验证线路请求失败，请稍后重试",
    );
  } finally {
    closeSocket(socket);
  }
}
