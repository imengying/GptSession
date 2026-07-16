import type { JsonRecord } from "./types";

const SENSITIVE_KEYS = new Set([
  "accesstoken",
  "refreshtoken",
  "sessiontoken",
  "idtoken",
  "oauthtoken",
  "bearertoken",
  "csrftoken",
  "password",
  "passwd",
  "passphrase",
  "clientsecret",
  "apikey",
  "authorization",
  "accesskey",
  "secretkey",
  "privatekey",
  "cookie",
]);

function isPlainObject(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  return SENSITIVE_KEYS.has(normalized)
    || /(?:token|password|passwd|secret|apikey|privatekey)$/u.test(normalized);
}

export function redactSensitiveDocument<T>(value: T, currentKey?: string): T {
  if (currentKey && isSensitiveKey(currentKey)) {
    if (typeof value === "string") {
      return (value === ""
        ? "[empty]"
        : "[hidden · " + value.length + " chars]") as T;
    }
    if (value !== undefined && value !== null) {
      return "[hidden]" as T;
    }
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveDocument(item)) as T;
  }
  if (isPlainObject(value)) {
    const output: JsonRecord = {};
    for (const [key, item] of Object.entries(value)) {
      output[key] = redactSensitiveDocument(item, key);
    }
    return output as T;
  }
  return value;
}
