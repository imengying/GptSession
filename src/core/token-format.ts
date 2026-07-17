import type { ManualTokenType } from "./types";

export const MAX_ACCESS_TOKEN_LENGTH = 8 * 1024;
export const MAX_REFRESH_TOKEN_LENGTH = 16 * 1024;

const MIN_MANUAL_TOKEN_LENGTH = 16;
const TOKEN_CHARACTERS = /^[A-Za-z0-9._~+/=-]+$/u;

export function detectNonTokenDocument(text: string): string | undefined {
  const trimmed = text.trim();
  if (
    /^(?:<!doctype\s+html|<html(?:\s|>))/iu.test(trimmed)
    || /<\/html>\s*$/iu.test(trimmed)
  ) {
    return "检测到 HTML 页面，请粘贴 token 本身，不要粘贴报错页面";
  }
  if (/^(?:\{|\[)/u.test(trimmed)) {
    return "检测到 JSON 内容，请切换到 JSON 输入";
  }
  return undefined;
}

export function manualTokenValidationError(
  token: string,
  tokenType: ManualTokenType,
): string | undefined {
  const label = tokenType === "at" ? "AT" : "RT";
  const maxLength = tokenType === "at"
    ? MAX_ACCESS_TOKEN_LENGTH
    : MAX_REFRESH_TOKEN_LENGTH;

  if (tokenType === "at" && !token.startsWith("at-")) {
    return "AT 仅支持 at- 开头的 Personal Access Token";
  }
  if (token.length < MIN_MANUAL_TOKEN_LENGTH) {
    return label + " 长度过短，请检查是否粘贴完整";
  }
  if (token.length > maxLength) {
    return label + " 长度超过限制";
  }
  if (!TOKEN_CHARACTERS.test(token)) {
    return label + " 含有空格或非法字符；每行只能填写一个完整 token";
  }
  if (tokenType === "rt" && token.startsWith("at-")) {
    return "检测到 AT，请切换到 AT 输入";
  }
  return undefined;
}
