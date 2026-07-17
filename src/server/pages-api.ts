export interface JsonRecord {
  [key: string]: unknown;
}

export class PagesApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "PagesApiError";
    this.code = code;
    this.status = status;
  }
}

export function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store, max-age=0",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export function pagesApiErrorResponse(error: unknown): Response {
  if (error instanceof PagesApiError) {
    return jsonResponse({
      error: {
        code: error.code,
        message: error.message,
      },
    }, error.status);
  }
  return jsonResponse({
    error: {
      code: "INVALID_BODY",
      message: "无法读取请求内容",
    },
  }, 400);
}

export function assertSameOriginPost(request: Request): void {
  if (request.method !== "POST") {
    throw new PagesApiError("METHOD_NOT_ALLOWED", "仅支持 POST", 405);
  }

  const requestUrl = new URL(request.url);
  const origin = request.headers.get("Origin");
  if (origin && origin !== requestUrl.origin) {
    throw new PagesApiError("ORIGIN_NOT_ALLOWED", "请求来源不受信任", 403);
  }
}

export async function readJsonObject(
  request: Request,
  maxBytes = 16 * 1024,
): Promise<JsonRecord> {
  const contentLength = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new PagesApiError("REQUEST_TOO_LARGE", "请求内容过大", 413);
  }

  let rawBody: string;
  try {
    rawBody = await request.text();
  } catch {
    throw new PagesApiError("INVALID_BODY", "无法读取请求内容", 400);
  }
  if (new TextEncoder().encode(rawBody).byteLength > maxBytes) {
    throw new PagesApiError("REQUEST_TOO_LARGE", "请求内容过大", 413);
  }

  try {
    const parsed = JSON.parse(rawBody) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed as JsonRecord;
  } catch {
    throw new PagesApiError("INVALID_JSON", "请求 JSON 无效", 400);
  }
}

export function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
