import {
  OPENAI_OAUTH_TOKEN_URL,
  OPENAI_PAT_WHOAMI_URL,
} from "../core/openai-oauth";

export interface OpenAiUpstreamRequest {
  method: "GET" | "POST";
  path: string;
  headers?: Readonly<Record<string, string>>;
  body?: string;
  signal?: AbortSignal;
}

export interface OpenAiUpstreamOptions {
  fetcher?: typeof fetch;
  timeoutMilliseconds?: number;
}

export type OpenAiUpstreamRequester = (
  request: OpenAiUpstreamRequest,
) => Promise<Response>;

export class OpenAiUpstreamError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "OpenAiUpstreamError";
    this.code = code;
  }
}

export const OPENAI_UNSUPPORTED_REGION_MESSAGE =
  "当前 Cloudflare 节点不受 OpenAI 支持，请切换至日本、新加坡或美国等支持地区的网络节点后重试";

const REQUEST_TIMEOUT_MILLISECONDS = 12_000;
const ALLOWED_TARGETS = new Map<string, string>([
  ["POST " + new URL(OPENAI_OAUTH_TOKEN_URL).pathname, OPENAI_OAUTH_TOKEN_URL],
  ["GET " + new URL(OPENAI_PAT_WHOAMI_URL).pathname, OPENAI_PAT_WHOAMI_URL],
]);

export async function requestOpenAiUpstream(
  request: OpenAiUpstreamRequest,
  options: OpenAiUpstreamOptions = {},
): Promise<Response> {
  const target = ALLOWED_TARGETS.get(request.method + " " + request.path);
  if (!target) {
    throw new OpenAiUpstreamError(
      "OPENAI_UPSTREAM_TARGET_NOT_ALLOWED",
      "OpenAI 验证目标不受支持",
    );
  }

  if (request.signal?.aborted) {
    throw new DOMException("The operation was aborted", "AbortError");
  }

  const controller = new AbortController();
  let rejectGuard: ((error: Error) => void) | undefined;
  const guard = new Promise<never>((_resolve, reject) => {
    rejectGuard = reject;
  });
  const timeout = setTimeout(() => {
    rejectGuard?.(new OpenAiUpstreamError(
      "OPENAI_UPSTREAM_TIMEOUT",
      "连接 OpenAI 超时，请稍后重试或更换网络节点",
    ));
    controller.abort();
  }, options.timeoutMilliseconds ?? REQUEST_TIMEOUT_MILLISECONDS);
  const onAbort = (): void => {
    rejectGuard?.(new DOMException("The operation was aborted", "AbortError"));
    controller.abort();
  };
  request.signal?.addEventListener("abort", onAbort, { once: true });

  try {
    return await Promise.race([
      (options.fetcher ?? fetch)(target, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
      }),
      guard,
    ]);
  } catch (error) {
    if (error instanceof OpenAiUpstreamError) {
      throw error;
    }
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new OpenAiUpstreamError(
      "OPENAI_UPSTREAM_NETWORK_ERROR",
      "当前 Cloudflare 节点无法连接 OpenAI，请稍后重试或更换网络节点",
    );
  } finally {
    clearTimeout(timeout);
    request.signal?.removeEventListener("abort", onAbort);
  }
}
