import type {
  AccountSourceType,
  ArchiveEntry,
  CpaRecord,
  DownloadDescriptor,
  JsonRecord,
  ManualTokenType,
  NormalizedAccount,
  OutputDocument,
  OutputFormat,
  ParseCredentialResult,
  ParseIssue,
  Sub2ApiAccount,
  Sub2ApiDocument,
  Sub2ApiSettings,
} from "./types";

export const OPENAI_AUTH_CLAIM = "https://api.openai.com/auth";
export const OPENAI_PROFILE_CLAIM = "https://api.openai.com/profile";

interface CredentialCandidate {
  value: JsonRecord;
  sourceName: string;
  sourcePath: string;
  sourceType: AccountSourceType;
  exportedAt?: string;
  sub2ApiSettings?: Sub2ApiSettings;
}

interface ConvertOptions {
  now?: Date;
}

interface ParseOptions extends ConvertOptions {
  sourceName?: string;
  sourcePath?: string;
  sourceType?: AccountSourceType;
  lastRefreshFallback?: unknown;
  preservedCpaFields?: JsonRecord;
  sub2ApiSettings?: Sub2ApiSettings;
}

interface ManualTokenParseOptions extends ConvertOptions {
  maxTokens?: number;
  sourceName?: string;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const ACCESS_TOKEN_PATHS = [
  "accessToken",
  "access_token",
  "tokens.accessToken",
  "tokens.access_token",
  "token.accessToken",
  "token.access_token",
  "credentials.accessToken",
  "credentials.access_token",
];

const SESSION_TOKEN_PATHS = [
  "sessionToken",
  "session_token",
  "tokens.sessionToken",
  "tokens.session_token",
  "token.sessionToken",
  "token.session_token",
  "credentials.sessionToken",
  "credentials.session_token",
];

const REFRESH_TOKEN_PATHS = [
  "refreshToken",
  "refresh_token",
  "tokens.refreshToken",
  "tokens.refresh_token",
  "token.refreshToken",
  "token.refresh_token",
  "credentials.refreshToken",
  "credentials.refresh_token",
];

const ID_TOKEN_PATHS = [
  "idToken",
  "id_token",
  "tokens.idToken",
  "tokens.id_token",
  "token.idToken",
  "token.id_token",
  "credentials.idToken",
  "credentials.id_token",
];

const SESSION_BRIDGE_KEY = "session_bridge";
const SESSION_BRIDGE_SCHEMA = 1;
const MAX_CPA_FILE_TOKEN_BYTES = 240;

function isPlainObject(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function firstNonEmpty(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim() !== "") {
      return value.trim();
    }
  }
  return undefined;
}

function toFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : undefined;
  }
  return undefined;
}

function getAtPath(record: JsonRecord, path: string): unknown {
  let current: unknown = record;
  for (const part of path.split(".")) {
    if (!isPlainObject(current)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function readFirstString(record: JsonRecord, paths: string[]): string | undefined {
  return firstNonEmpty(...paths.map((path) => getAtPath(record, path)));
}

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return textDecoder.decode(bytes);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function encodeBase64UrlJson(value: unknown): string {
  return bytesToBase64Url(textEncoder.encode(JSON.stringify(value)));
}

export function parseJwtPayload(token?: string): JsonRecord | undefined {
  if (!token?.trim()) {
    return undefined;
  }
  const segments = token.split(".");
  if (segments.length < 2 || !segments[1]) {
    return undefined;
  }
  try {
    const payload: unknown = JSON.parse(decodeBase64Url(segments[1]));
    return isPlainObject(payload) ? payload : undefined;
  } catch {
    return undefined;
  }
}

function getClaimObject(payload: JsonRecord | undefined, claimName: string): JsonRecord {
  const section = payload?.[claimName];
  return isPlainObject(section) ? section : {};
}

function normalizeTimestamp(value: unknown): string | undefined {
  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return value.toISOString();
  }

  const numeric = toFiniteNumber(value);
  if (numeric !== undefined) {
    const milliseconds = numeric > 1e11 ? numeric : numeric * 1000;
    const date = new Date(milliseconds);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }

  if (typeof value !== "string" || !value.trim()) {
    return undefined;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function timestampFromUnixSeconds(value: unknown): string | undefined {
  const numeric = toFiniteNumber(value);
  if (numeric === undefined || numeric <= 0) {
    return undefined;
  }
  const date = new Date(numeric * 1000);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function unixSecondsFromValue(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  const numeric = toFiniteNumber(value);
  if (numeric !== undefined) {
    return Math.trunc(numeric > 1e11 ? numeric / 1000 : numeric);
  }
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? Math.trunc(parsed / 1000) : undefined;
}

function unixSecondsFromJwtExp(value: unknown): number | undefined {
  const numeric = toFiniteNumber(value);
  return numeric !== undefined && numeric > 0 ? Math.trunc(numeric) : undefined;
}

function getExpiresIn(expiresAt: string | undefined, now: Date): number | undefined {
  if (!expiresAt) {
    return undefined;
  }
  const expiresMs = new Date(expiresAt).getTime();
  if (Number.isNaN(expiresMs) || Number.isNaN(now.getTime())) {
    return undefined;
  }
  return Math.max(0, Math.floor((expiresMs - now.getTime()) / 1000));
}

function compactObject(value: JsonRecord): JsonRecord {
  return Object.fromEntries(
    Object.entries(value).filter(([, item]) => item !== undefined && item !== null),
  );
}

function toEmailKey(email?: string): string | undefined {
  return email
    ?.trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "") || undefined;
}

function truncateUtf8(value: string, maxBytes: number): string {
  const bytes = textEncoder.encode(value);
  if (bytes.length <= maxBytes) {
    return value;
  }
  let end = maxBytes;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) {
    end -= 1;
  }
  return textDecoder.decode(bytes.subarray(0, end));
}

function fitFileToken(value: string, maxBytes: number): string {
  if (textEncoder.encode(value).length <= maxBytes) {
    return value;
  }
  const atIndex = value.lastIndexOf("@");
  if (atIndex > 0) {
    const domain = value.slice(atIndex);
    const domainBytes = textEncoder.encode(domain).length;
    if (domainBytes < maxBytes) {
      return truncateUtf8(value.slice(0, atIndex), maxBytes - domainBytes)
        + domain;
    }
  }
  return truncateUtf8(value, maxBytes);
}

function sanitizeFileToken(value: unknown, fallback = "chatgpt-account"): string {
  const base = firstNonEmpty(value, fallback) ?? fallback;
  const sanitized = base
    .replace(/[\\/:*?"<>|]+/g, "-")
    .replace(/[\u0000-\u001f\u007f]+/g, "-")
    .replace(/[. ]+$/g, "") || fallback;
  return fitFileToken(sanitized, MAX_CPA_FILE_TOKEN_BYTES) || fallback;
}

function getTimestampToken(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("-") + "_" + [
    pad(date.getHours()),
    pad(date.getMinutes()),
    pad(date.getSeconds()),
  ].join("-");
}

function deriveOrganizationId(...sources: JsonRecord[]): string | undefined {
  for (const source of sources) {
    const organizations = source.organizations;
    if (!Array.isArray(organizations)) {
      continue;
    }
    const normalized = organizations.filter(isPlainObject);
    const preferred = normalized.find((organization) => (
      organization.is_default && organization.id
    ));
    const selected = preferred ?? normalized.find((organization) => organization.id);
    if (selected?.id) {
      return String(selected.id);
    }
  }
  return undefined;
}

function buildSyntheticCodexIdToken(
  account: Pick<NormalizedAccount, "accountId" | "email" | "planType" | "userId" | "tokenExpiresAt">,
  now: Date,
): string | undefined {
  if (!account.accountId) {
    return undefined;
  }

  const issuedAt = Math.trunc(now.getTime() / 1000);
  const expiresAt = unixSecondsFromValue(account.tokenExpiresAt)
    ?? issuedAt + (90 * 24 * 60 * 60);
  const authInfo: JsonRecord = {
    chatgpt_account_id: account.accountId,
  };
  if (account.planType) {
    authInfo.chatgpt_plan_type = account.planType;
  }
  if (account.userId) {
    authInfo.chatgpt_user_id = account.userId;
    authInfo.user_id = account.userId;
  }

  const payload: JsonRecord = {
    iat: issuedAt,
    exp: expiresAt,
    [OPENAI_AUTH_CLAIM]: authInfo,
  };
  if (account.email) {
    payload.email = account.email;
  }

  const header = {
    alg: "none",
    typ: "JWT",
    session_bridge_synthetic: true,
  };
  return encodeBase64UrlJson(header) + "." + encodeBase64UrlJson(payload) + ".synthetic";
}

function getAccessToken(record: JsonRecord): string | undefined {
  return readFirstString(record, ACCESS_TOKEN_PATHS);
}

function getSessionToken(record: JsonRecord): string | undefined {
  return readFirstString(record, SESSION_TOKEN_PATHS);
}

function getRefreshToken(record: JsonRecord): string | undefined {
  return readFirstString(record, REFRESH_TOKEN_PATHS);
}

function getIdToken(record: JsonRecord): string | undefined {
  return readFirstString(record, ID_TOKEN_PATHS);
}

const CREDENTIAL_FIELD_NAMES = new Set([
  "access_token",
  "accessToken",
  "refresh_token",
  "refreshToken",
  "id_token",
  "idToken",
  "session_token",
  "sessionToken",
]);

function withoutFields(record: JsonRecord, fieldNames: Set<string>): JsonRecord {
  return Object.fromEntries(
    Object.entries(record).filter(([key]) => !fieldNames.has(key)),
  );
}

function withoutCredentialFields(record: JsonRecord): JsonRecord {
  return withoutFields(record, CREDENTIAL_FIELD_NAMES);
}

function withoutSessionBridge(record: JsonRecord): JsonRecord {
  return Object.fromEntries(
    Object.entries(record).filter(([key]) => key !== SESSION_BRIDGE_KEY),
  );
}

function readBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  if (value === "true" || value === 1 || value === "1") {
    return true;
  }
  if (value === "false" || value === 0 || value === "0") {
    return false;
  }
  return undefined;
}

function isLikelyCpaRecord(record: JsonRecord): boolean {
  if (record.type === "codex") {
    return true;
  }
  return typeof record.access_token === "string" && Boolean(
    record.account_id
    || record.chatgpt_account_id
    || record.last_refresh
    || record.expired,
  );
}

function isLikelySub2ApiAccount(record: JsonRecord): boolean {
  if (!isPlainObject(record.credentials)) {
    return false;
  }
  return Boolean(
    record.platform
    || record.type === "oauth"
    || record.concurrency !== undefined
    || record.priority !== undefined,
  );
}

function isLikelySub2ApiDocument(record: JsonRecord): boolean {
  if (!Array.isArray(record.accounts)) {
    return false;
  }
  return Boolean(
    record.exported_at
    || Array.isArray(record.proxies)
    || record.accounts.some((account) => (
      isPlainObject(account) && isLikelySub2ApiAccount(account)
    )),
  );
}

function emailFromSub2ApiName(value: unknown): string | undefined {
  const name = firstNonEmpty(value);
  if (!name) {
    return undefined;
  }
  const candidate = name.split("--")[0]?.trim();
  return candidate?.includes("@") ? candidate : undefined;
}

function buildSub2ApiSettings(
  record: JsonRecord,
  documentFields?: JsonRecord,
  restoredFromBridge = false,
  credentialKeys?: string[],
): Sub2ApiSettings {
  const credentials = isPlainObject(record.credentials)
    ? { ...record.credentials }
    : {};
  const extra = isPlainObject(record.extra) ? { ...record.extra } : {};
  const accountFields = Object.fromEntries(
    Object.entries(record).filter(([key]) => key !== "credentials" && key !== "extra"),
  );
  return {
    name: firstNonEmpty(record.name),
    platform: firstNonEmpty(record.platform),
    accountType: firstNonEmpty(record.type),
    concurrency: toFiniteNumber(record.concurrency),
    priority: toFiniteNumber(record.priority),
    rateMultiplier: toFiniteNumber(record.rate_multiplier),
    autoPauseOnExpired: readBoolean(record.auto_pause_on_expired),
    expiresAt: unixSecondsFromValue(record.expires_at),
    disabled: readBoolean(record.disabled),
    credentials,
    extra,
    accountFields,
    originalCredentialKeys: credentialKeys ?? Object.keys(credentials),
    documentFields,
    restoredFromBridge,
  };
}

function buildSub2ApiBridgeMetadata(settings: Sub2ApiSettings): JsonRecord {
  return {
    schema: SESSION_BRIDGE_SCHEMA,
    source: "sub2api",
    sub2api: {
      document: settings.documentFields ?? {},
      account: settings.accountFields,
      credentials: withoutCredentialFields(settings.credentials),
      credential_keys: settings.originalCredentialKeys,
      extra: settings.extra,
    },
  };
}

function readSub2ApiBridgeSettings(record: JsonRecord): Sub2ApiSettings | undefined {
  const bridge = record[SESSION_BRIDGE_KEY];
  if (!isPlainObject(bridge)) {
    return undefined;
  }
  if (bridge.schema !== SESSION_BRIDGE_SCHEMA || bridge.source !== "sub2api") {
    return undefined;
  }
  const sub2api = bridge.sub2api;
  if (!isPlainObject(sub2api)) {
    return undefined;
  }

  const accountFields = isPlainObject(sub2api.account)
    ? { ...sub2api.account }
    : {};
  const credentials = isPlainObject(sub2api.credentials)
    ? { ...sub2api.credentials }
    : {};
  const extra = isPlainObject(sub2api.extra) ? { ...sub2api.extra } : {};
  const documentFields = isPlainObject(sub2api.document)
    ? { ...sub2api.document }
    : undefined;
  const credentialKeys = Array.isArray(sub2api.credential_keys)
    ? sub2api.credential_keys.filter(
      (key): key is string => typeof key === "string" && Boolean(key),
    )
    : Object.keys(credentials);

  return buildSub2ApiSettings(
    {
      ...accountFields,
      credentials,
      extra,
    },
    documentFields,
    true,
    credentialKeys,
  );
}

function buildSub2ApiNormalizationRecord(
  record: JsonRecord,
  exportedAt?: string,
): JsonRecord {
  const settings = buildSub2ApiSettings(record);
  const credentials = settings.credentials;
  const extra = settings.extra;
  return {
    ...extra,
    ...credentials,
    name: firstNonEmpty(extra.name, record.name),
    email: firstNonEmpty(
      credentials.email,
      extra.email,
      emailFromSub2ApiName(record.name),
    ),
    account_id: firstNonEmpty(
      credentials.chatgpt_account_id,
      extra.account_id,
      extra.chatgpt_account_id,
    ),
    plan_type: firstNonEmpty(
      credentials.plan_type,
      extra.plan_type,
      extra.chatgpt_plan_type,
    ),
    expires_at: firstNonEmpty(
      credentials.expires_at,
      record.expires_at,
      extra.expired,
    ) ?? credentials.expires_at ?? record.expires_at ?? extra.expired,
    last_refresh: firstNonEmpty(
      extra.last_refresh,
      extra.lastRefresh,
      exportedAt,
    ),
    disabled: readBoolean(record.disabled) ?? readBoolean(extra.disabled),
    auth_provider: firstNonEmpty(extra.auth_provider, "openai"),
  };
}

function isLikelySessionObject(record: JsonRecord, token: string): boolean {
  const payload = parseJwtPayload(token);
  const auth = getClaimObject(payload, OPENAI_AUTH_CLAIM);
  const profile = getClaimObject(payload, OPENAI_PROFILE_CLAIM);
  const hasIdentity = Boolean(
    isPlainObject(record.user)
    || isPlainObject(record.account)
    || firstNonEmpty(
      record.email,
      record.name,
      record.label,
      getAtPath(record, "meta.label"),
      record.account_id,
      record.accountId,
      auth.chatgpt_account_id,
      profile.email,
      payload?.email,
    ),
  );

  return Boolean(
    hasIdentity
    || getSessionToken(record)
    || getRefreshToken(record)
    || getIdToken(record)
    || (payload && (payload.exp || Object.keys(auth).length || Object.keys(profile).length)),
  );
}

function collectCredentialCandidates(
  value: unknown,
  sourceName = "粘贴内容",
): CredentialCandidate[] {
  const found: CredentialCandidate[] = [];
  const visited = new WeakSet<object>();

  const visit = (item: unknown, path: string): void => {
    if (!isPlainObject(item) && !Array.isArray(item)) {
      return;
    }
    if (visited.has(item)) {
      return;
    }
    visited.add(item);

    if (Array.isArray(item)) {
      item.forEach((child, index) => visit(child, path + "[" + index + "]"));
      return;
    }

    if (isLikelySub2ApiDocument(item)) {
      const exportedAt = normalizeTimestamp(item.exported_at);
      const accounts = Array.isArray(item.accounts) ? item.accounts : [];
      const documentFields = Object.fromEntries(
        Object.entries(item).filter(([key]) => key !== "accounts"),
      );
      accounts.forEach((account, index) => {
        if (!isPlainObject(account)) {
          found.push({
            value: { raw_value: account },
            sourceName,
            sourcePath: path + ".accounts[" + index + "]",
            sourceType: "sub2api",
            exportedAt,
          });
          return;
        }
        found.push({
          value: buildSub2ApiNormalizationRecord(account, exportedAt),
          sourceName,
          sourcePath: path + ".accounts[" + index + "]",
          sourceType: "sub2api",
          exportedAt,
          sub2ApiSettings: buildSub2ApiSettings(account, documentFields),
        });
      });
      return;
    }

    if (isLikelySub2ApiAccount(item)) {
      found.push({
        value: buildSub2ApiNormalizationRecord(item),
        sourceName,
        sourcePath: path,
        sourceType: "sub2api",
        sub2ApiSettings: buildSub2ApiSettings(item),
      });
      return;
    }

    if (isLikelyCpaRecord(item)) {
      found.push({
        value: item,
        sourceName,
        sourcePath: path,
        sourceType: "cpa",
        sub2ApiSettings: readSub2ApiBridgeSettings(item),
      });
      return;
    }

    const token = getAccessToken(item);
    if (token && isLikelySessionObject(item, token)) {
      found.push({
        value: item,
        sourceName,
        sourcePath: path,
        sourceType: "chatgpt_web_session",
      });
      return;
    }

    for (const [key, child] of Object.entries(item)) {
      if (/^(accessToken|access_token|sessionToken|session_token)$/u.test(key)) {
        continue;
      }
      visit(child, path + "." + key);
    }
  };

  visit(value, "$");
  return found;
}

function safeJsonError(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  const location = message.match(
    /(?:position\s+\d+|line\s+\d+(?:\s+column\s+\d+)?)/iu,
  );
  return location ? "JSON 解析失败（" + location[0] + "）" : "JSON 解析失败";
}

function parsePastedJsonDocuments(text: string): {
  documents: unknown[];
  issues: ParseIssue[];
} {
  const input = String(text || "");
  const documents: unknown[] = [];
  const issues: ParseIssue[] = [];
  let stack: string[] = [];
  let startIndex = -1;
  let inString = false;
  let escaped = false;
  let documentIndex = 0;
  const label = (index: number) => "粘贴内容 #" + (index + 1);

  const parseCandidate = (candidate: string): void => {
    try {
      documents.push(JSON.parse(candidate) as unknown);
    } catch (error) {
      issues.push({
        sourceName: label(documentIndex),
        reason: safeJsonError(error),
      });
    }
    documentIndex += 1;
  };

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (startIndex === -1) {
      if (/\s/u.test(character)) {
        continue;
      }
      if (character !== "{" && character !== "[") {
        issues.push({
          sourceName: label(documentIndex),
          reason: "发现非 JSON 内容；文档必须以 { 或 [ 开始",
        });
        break;
      }
      startIndex = index;
      stack = [character === "{" ? "}" : "]"];
      inString = false;
      escaped = false;
      continue;
    }

    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "\"") {
        inString = false;
      }
      continue;
    }

    if (character === "\"") {
      inString = true;
      continue;
    }
    if (character === "{" || character === "[") {
      stack.push(character === "{" ? "}" : "]");
      continue;
    }
    if (character === "}" || character === "]") {
      if (stack.at(-1) !== character) {
        issues.push({
          sourceName: label(documentIndex),
          reason: "JSON 括号不匹配",
        });
        documentIndex += 1;
        startIndex = -1;
        stack = [];
        continue;
      }
      stack.pop();
      if (!stack.length) {
        parseCandidate(input.slice(startIndex, index + 1));
        startIndex = -1;
      }
    }
  }

  if (startIndex !== -1) {
    issues.push({
      sourceName: label(documentIndex),
      reason: "JSON 不完整：缺少顶层闭合括号",
    });
  }
  if (!documents.length && !issues.length && input.trim()) {
    issues.push({
      sourceName: label(0),
      reason: "没有找到可解析的 JSON 文档",
    });
  }
  return { documents, issues };
}

export function normalizeSessionRecord(
  record: JsonRecord,
  options: ParseOptions = {},
): NormalizedAccount {
  const sourceType = options.sourceType ?? "chatgpt_web_session";
  const sub2ApiSettings = options.sub2ApiSettings;
  const usesSub2ApiSettings = sourceType === "sub2api"
    || sourceType === "manual_at"
    || sourceType === "manual_rt";
  if (
    usesSub2ApiSettings
    && sub2ApiSettings?.platform
    && sub2ApiSettings.platform.toLowerCase() !== "openai"
  ) {
    throw new Error("仅支持转换 Sub2API 中 platform=openai 的账号");
  }
  if (
    usesSub2ApiSettings
    && sub2ApiSettings?.accountType
    && sub2ApiSettings.accountType.toLowerCase() !== "oauth"
  ) {
    throw new Error("仅支持转换 Sub2API 中 type=oauth 的账号");
  }

  const accessToken = getAccessToken(record) ?? "";
  const refreshToken = getRefreshToken(record);
  const supportsRefreshOnly = sourceType === "sub2api"
    || sourceType === "cpa"
    || sourceType === "manual_rt";
  if (!accessToken && !(supportsRefreshOnly && refreshToken)) {
    throw new Error("缺少 access_token / accessToken 或 refresh_token");
  }

  const now = options.now ?? new Date();
  const sessionToken = getSessionToken(record);
  const inputIdToken = getIdToken(record);
  const accessPayload = parseJwtPayload(accessToken);
  const idPayload = parseJwtPayload(inputIdToken);
  const accessAuth = getClaimObject(accessPayload, OPENAI_AUTH_CLAIM);
  const idAuth = getClaimObject(idPayload, OPENAI_AUTH_CLAIM);
  const accessProfile = getClaimObject(accessPayload, OPENAI_PROFILE_CLAIM);
  const idProfile = getClaimObject(idPayload, OPENAI_PROFILE_CLAIM);
  const declaredExpiresAt = firstNonEmpty(
    normalizeTimestamp(record.expires),
    normalizeTimestamp(record.expiresAt),
    normalizeTimestamp(record.expires_at),
    normalizeTimestamp(record.expired),
  );
  const jwtExpiresAt = timestampFromUnixSeconds(accessPayload?.exp);
  const prefersJwtExpiry = sourceType === "chatgpt_web_session"
    || sourceType === "manual_at";
  const tokenExpiresAt = prefersJwtExpiry
    ? firstNonEmpty(jwtExpiresAt, declaredExpiresAt)
    : firstNonEmpty(declaredExpiresAt, jwtExpiresAt);
  const accessTokenExpiresAt = prefersJwtExpiry
    ? unixSecondsFromJwtExp(accessPayload?.exp)
      ?? unixSecondsFromValue(tokenExpiresAt)
    : unixSecondsFromValue(tokenExpiresAt)
      ?? unixSecondsFromJwtExp(accessPayload?.exp);
  const email = firstNonEmpty(
    getAtPath(record, "user.email"),
    record.email,
    getAtPath(record, "meta.label"),
    record.label,
    getAtPath(record, "credentials.email"),
    getAtPath(record, "providerSpecificData.email"),
    accessProfile.email,
    idProfile.email,
    idPayload?.email,
    accessPayload?.email,
  );
  const accountId = firstNonEmpty(
    getAtPath(record, "account.id"),
    record.account_id,
    record.accountId,
    getAtPath(record, "tokens.account_id"),
    getAtPath(record, "tokens.accountId"),
    record.chatgpt_account_id,
    record.chatgptAccountId,
    getAtPath(record, "meta.chatgpt_account_id"),
    getAtPath(record, "meta.chatgptAccountId"),
    getAtPath(record, "providerSpecificData.chatgpt_account_id"),
    getAtPath(record, "providerSpecificData.chatgptAccountId"),
    getAtPath(record, "credentials.chatgpt_account_id"),
    accessAuth.chatgpt_account_id,
    idAuth.chatgpt_account_id,
  );
  const userId = firstNonEmpty(
    getAtPath(record, "user.id"),
    record.user_id,
    record.chatgpt_user_id,
    record.chatgptUserId,
    getAtPath(record, "providerSpecificData.chatgpt_user_id"),
    getAtPath(record, "providerSpecificData.chatgptUserId"),
    accessAuth.chatgpt_user_id,
    accessAuth.user_id,
    idAuth.chatgpt_user_id,
    idAuth.user_id,
  );
  const planType = firstNonEmpty(
    getAtPath(record, "account.planType"),
    getAtPath(record, "account.plan_type"),
    record.planType,
    record.plan_type,
    getAtPath(record, "providerSpecificData.chatgptPlanType"),
    getAtPath(record, "providerSpecificData.chatgpt_plan_type"),
    getAtPath(record, "credentials.plan_type"),
    accessAuth.chatgpt_plan_type,
    idAuth.chatgpt_plan_type,
  );
  const organizationId = firstNonEmpty(
    record.organization_id,
    record.organizationId,
    getAtPath(record, "credentials.organization_id"),
    deriveOrganizationId(idAuth, accessAuth),
  );
  const sourceName = firstNonEmpty(options.sourceName, "粘贴内容") ?? "粘贴内容";
  const sourcePath = firstNonEmpty(options.sourcePath, "$") ?? "$";
  const sourceBase = sourceName.split(/[\\/]/u).pop();
  const name = (prefersJwtExpiry
    ? firstNonEmpty(
      email,
      record.name,
      record.label,
      sourceBase,
      accountId,
      "ChatGPT Account",
    )
    : firstNonEmpty(
      record.name,
      email,
      record.label,
      sourceBase,
      accountId,
      "ChatGPT Account",
    )) ?? "ChatGPT Account";
  const exportedAt = normalizeTimestamp(now) ?? now.toISOString();
  const lastRefresh = firstNonEmpty(
    normalizeTimestamp(record.last_refresh),
    normalizeTimestamp(record.lastRefresh),
    normalizeTimestamp(options.lastRefreshFallback),
    exportedAt,
  ) ?? exportedAt;
  const partial = {
    accountId,
    email,
    planType,
    userId,
    tokenExpiresAt,
  };
  const syntheticIdToken = inputIdToken
    ? undefined
    : buildSyntheticCodexIdToken(partial, now);
  const inputIdTokenSynthetic = readBoolean(record.id_token_synthetic) === true;
  const isExpired = Boolean(
    tokenExpiresAt && new Date(tokenExpiresAt).getTime() <= now.getTime(),
  );
  const warnings: string[] = [];

  const isPersonalAccessToken = sourceType === "manual_at"
    && accessToken.startsWith("at-");
  if (!refreshToken && !isPersonalAccessToken) {
    warnings.push("缺少 refresh_token，access token 到期后无法自动刷新。");
  }
  if (syntheticIdToken) {
    warnings.push("缺少真实 id_token，CPA 将使用仅供解析的合成 JWT。");
  } else if (inputIdTokenSynthetic) {
    warnings.push("输入中的 id_token 已标记为合成 JWT，不是真实 OAuth id token。");
  }
  if (!accountId) {
    warnings.push("未解析到 account_id，目标系统可能无法完整识别账号。");
  }
  if (!email) {
    warnings.push("未解析到邮箱，已使用来源名称作为账号名。");
  }
  if (isExpired) {
    warnings.push("access token 已过期。");
  }

  return {
    sourceName,
    sourcePath,
    sourceType,
    name,
    email,
    accountId,
    userId,
    planType,
    organizationId,
    authProvider: firstNonEmpty(record.authProvider, record.auth_provider, "openai") ?? "openai",
    accessToken,
    sessionToken,
    refreshToken,
    inputIdToken,
    syntheticIdToken,
    idToken: firstNonEmpty(inputIdToken, syntheticIdToken),
    idTokenSynthetic: inputIdTokenSynthetic || Boolean(syntheticIdToken),
    tokenExpiresAt,
    accessTokenExpiresAt,
    exportExpiresAt: sourceType === "chatgpt_web_session" && refreshToken
      ? undefined
      : tokenExpiresAt,
    lastRefresh,
    disabled: readBoolean(record.disabled) ?? false,
    isRefreshable: Boolean(refreshToken),
    isExpired,
    warnings,
    preservedCpaFields: options.preservedCpaFields,
    sub2ApiSettings,
  };
}

export function getAccountCredentialKeys(account: NormalizedAccount): string[] {
  const keys: string[] = [];
  if (account.accessToken) {
    keys.push("at:" + account.accessToken);
  }
  if (account.refreshToken) {
    keys.push("rt:" + account.refreshToken);
  }
  return keys.length
    ? keys
    : ["source:" + account.sourceName + ":" + account.sourcePath];
}

export function parseCredentialText(
  text: string,
  options: ParseOptions = {},
): ParseCredentialResult {
  const parsed = parsePastedJsonDocuments(text);
  const accounts: NormalizedAccount[] = [];
  const issues = [...parsed.issues];
  const seenCredentials = new Set<string>();
  const baseName = firstNonEmpty(options.sourceName, "粘贴内容") ?? "粘贴内容";
  const now = options.now ?? new Date();

  parsed.documents.forEach((document, documentIndex) => {
    const documentLabel = parsed.documents.length > 1
      ? baseName + " · #" + (documentIndex + 1)
      : baseName;
    const candidates = collectCredentialCandidates(document, documentLabel);
    if (!candidates.length) {
      issues.push({
        sourceName: documentLabel,
        reason: "未找到可识别的 Session、CPA 或 Sub2API 账号",
      });
      return;
    }

    for (const candidate of candidates) {
      try {
        const account = normalizeSessionRecord(candidate.value, {
          sourceName: candidate.sourceName,
          sourcePath: candidate.sourcePath,
          sourceType: candidate.sourceType,
          lastRefreshFallback: candidate.exportedAt,
          preservedCpaFields: candidate.sourceType === "cpa"
            ? (candidate.sub2ApiSettings?.restoredFromBridge
              ? withoutSessionBridge(withoutCredentialFields(candidate.value))
              : withoutCredentialFields(candidate.value))
            : candidate.sourceType === "sub2api"
            ? withoutCredentialFields(candidate.sub2ApiSettings?.extra ?? {})
            : undefined,
          sub2ApiSettings: candidate.sub2ApiSettings,
          now,
        });
        const credentialKeys = getAccountCredentialKeys(account);
        if (credentialKeys.some((key) => seenCredentials.has(key))) {
          issues.push({
            sourceName: candidate.sourceName,
            sourcePath: candidate.sourcePath,
            reason: "检测到重复凭证，已忽略",
          });
          continue;
        }
        credentialKeys.forEach((key) => seenCredentials.add(key));
        accounts.push(account);
      } catch (error) {
        issues.push({
          sourceName: candidate.sourceName,
          sourcePath: candidate.sourcePath,
          reason: error instanceof Error ? error.message : "无法解析账号凭证",
        });
      }
    }
  });

  return { accounts, issues };
}

function createManualSub2ApiSettings(
  credentials: JsonRecord,
  extra: JsonRecord,
  defaults: { concurrency: number; priority: number; autoPause?: boolean },
): Sub2ApiSettings {
  return {
    platform: "openai",
    accountType: "oauth",
    concurrency: defaults.concurrency,
    priority: defaults.priority,
    rateMultiplier: 1,
    autoPauseOnExpired: defaults.autoPause,
    disabled: false,
    credentials,
    extra,
    accountFields: {},
    originalCredentialKeys: Object.keys(credentials),
  };
}

function normalizeManualAccessToken(
  token: string,
  index: number,
  options: ManualTokenParseOptions,
): NormalizedAccount {
  if (!token.startsWith("at-") || token.length <= 3) {
    throw new Error("AT 仅支持 at- 开头的 Personal Access Token");
  }
  const sourceName = options.sourceName ?? "手动 AT";
  const account = normalizeSessionRecord({
    access_token: token,
    name: "OpenAI AT " + (index + 1),
    auth_provider: "codex_personal_access_token",
  }, {
    sourceName,
    sourcePath: "$[" + index + "]",
    sourceType: "manual_at",
    now: options.now,
  });

  const settings = createManualSub2ApiSettings({
    access_token: token,
    auth_mode: "personal_access_token",
    openai_auth_mode: "personal_access_token",
    token_type: "Bearer",
  }, {
    import_source: "codex_personal_access_token",
    auth_provider: "codex_personal_access_token",
  }, {
    concurrency: 3,
    priority: 50,
    autoPause: false,
  });
  settings.name = account.email ?? account.name;
  account.sub2ApiSettings = settings;

  return account;
}

function normalizeManualRefreshToken(
  token: string,
  index: number,
  options: ManualTokenParseOptions,
): NormalizedAccount {
  const credentials = { refresh_token: token };
  const settings = createManualSub2ApiSettings(credentials, {
    auth_provider: "openai",
    source: "manual_refresh_token",
  }, {
    concurrency: 10,
    priority: 1,
  });
  const sourceName = options.sourceName ?? "手动 RT";
  const account = normalizeSessionRecord({
    refresh_token: token,
    name: "OpenAI RT " + (index + 1),
    auth_provider: "openai",
  }, {
    sourceName,
    sourcePath: "$[" + index + "]",
    sourceType: "manual_rt",
    sub2ApiSettings: settings,
    now: options.now,
  });
  settings.name = account.name;
  account.warnings = [];
  return account;
}

export function parseManualTokenText(
  text: string,
  tokenType: ManualTokenType,
  options: ManualTokenParseOptions = {},
): ParseCredentialResult {
  const rawTokens = String(text || "").split(/\s+/u).filter(Boolean);
  const maxTokens = Math.max(1, options.maxTokens ?? 500);
  const accounts: NormalizedAccount[] = [];
  const issues: ParseIssue[] = [];
  const seen = new Set<string>();

  if (rawTokens.length > maxTokens) {
    issues.push({
      sourceName: options.sourceName ?? "手动凭证",
      reason: "一次最多处理 " + maxTokens + " 个 token，其余内容已跳过",
    });
  }

  rawTokens.slice(0, maxTokens).forEach((token, index) => {
    const credentialKey = tokenType + ":" + token;
    if (seen.has(credentialKey)) {
      issues.push({
        sourceName: options.sourceName ?? "手动凭证",
        sourcePath: "$[" + index + "]",
        reason: "检测到重复凭证，已忽略",
      });
      return;
    }
    seen.add(credentialKey);
    try {
      accounts.push(tokenType === "at"
        ? normalizeManualAccessToken(token, index, options)
        : normalizeManualRefreshToken(token, index, options));
    } catch (error) {
      issues.push({
        sourceName: options.sourceName ?? "手动凭证",
        sourcePath: "$[" + index + "]",
        reason: error instanceof Error ? error.message : "无法解析 token",
      });
    }
  });

  return { accounts, issues };
}

export function toCpaRecord(
  account: NormalizedAccount,
  options: ConvertOptions = {},
): CpaRecord {
  const now = options.now ?? new Date();
  const preserved = account.preservedCpaFields ?? {};
  const bridgeMetadata = account.sub2ApiSettings
    ? buildSub2ApiBridgeMetadata(account.sub2ApiSettings)
    : undefined;
  const generatedName = (
    account.sourceType === "sub2api"
    || account.sourceType === "manual_at"
    || account.sourceType === "manual_rt"
  ) && account.email
    ? account.email + "_" + (account.accountId?.slice(0, 8) || "unknown")
    : undefined;
  const planType = firstNonEmpty(
    account.planType,
    preserved.plan_type,
    preserved.chatgpt_plan_type,
  );
  const accountId = firstNonEmpty(
    account.accountId,
    preserved.account_id,
    preserved.chatgpt_account_id,
  );
  const idToken = firstNonEmpty(account.idToken, preserved.id_token) ?? "";
  const idTokenSynthetic = account.idTokenSynthetic
    || readBoolean(preserved.id_token_synthetic) === true;
  return compactObject({
    ...preserved,
    type: "codex",
    account_id: accountId,
    chatgpt_account_id: accountId,
    email: firstNonEmpty(account.email, preserved.email),
    name: firstNonEmpty(preserved.name, generatedName, account.name),
    plan_type: planType,
    chatgpt_plan_type: planType,
    id_token: idToken,
    id_token_synthetic: idTokenSynthetic,
    access_token: account.accessToken,
    refresh_token: firstNonEmpty(account.refreshToken, preserved.refresh_token) ?? "",
    session_token: firstNonEmpty(account.sessionToken, preserved.session_token) ?? "",
    last_refresh: account.lastRefresh || normalizeTimestamp(now),
    expired: account.exportExpiresAt ?? normalizeTimestamp(preserved.expired),
    disabled: account.disabled || readBoolean(preserved.disabled) || undefined,
    source: firstNonEmpty(
      preserved.source,
      planType ? "gpt-" + planType + "-all-ws" : undefined,
    ),
    [SESSION_BRIDGE_KEY]: bridgeMetadata,
  }) as CpaRecord;
}

export function toSub2ApiAccount(
  account: NormalizedAccount,
  options: ConvertOptions = {},
): Sub2ApiAccount {
  const now = options.now ?? new Date();
  const settings = account.sub2ApiSettings;
  const preservedCredentials = settings?.credentials ?? {};
  const originalCredentialKeys = new Set(settings?.originalCredentialKeys ?? []);
  const hadCredential = (...keys: string[]): boolean => (
    !settings || keys.some((key) => originalCredentialKeys.has(key))
  );
  const preservedExtra = settings
    ? { ...settings.extra }
    : withoutCredentialFields(
      account.sourceType === "cpa" ? account.preservedCpaFields ?? {} : {},
    );
  const pauseExpiry = settings?.expiresAt !== undefined
    ? settings.expiresAt
    : account.isRefreshable
    ? undefined
    : account.accessTokenExpiresAt;
  const candidateIdToken = firstNonEmpty(
    account.inputIdToken,
    preservedCredentials.id_token,
    preservedCredentials.idToken,
  );
  const credentials = compactObject({
    ...preservedCredentials,
    access_token: account.accessToken || preservedCredentials.access_token,
    chatgpt_account_id: hadCredential("chatgpt_account_id", "chatgptAccountId")
      ? account.accountId ?? preservedCredentials.chatgpt_account_id
      : undefined,
    chatgpt_user_id: hadCredential("chatgpt_user_id", "chatgptUserId")
      ? account.userId ?? preservedCredentials.chatgpt_user_id
      : undefined,
    email: hadCredential("email")
      ? account.email ?? preservedCredentials.email
      : undefined,
    expires_at: hadCredential("expires_at", "expiresAt")
      ? (account.isRefreshable
        ? preservedCredentials.expires_at
        : account.tokenExpiresAt ?? preservedCredentials.expires_at)
      : undefined,
    expires_in: hadCredential("expires_in", "expiresIn")
      ? (account.isRefreshable
        ? preservedCredentials.expires_in
        : getExpiresIn(account.tokenExpiresAt, now))
      : undefined,
    id_token: hadCredential("id_token", "idToken") || !account.idTokenSynthetic
      ? candidateIdToken
      : undefined,
    organization_id: hadCredential("organization_id", "organizationId")
      ? account.organizationId ?? preservedCredentials.organization_id
      : undefined,
    plan_type: hadCredential("plan_type", "planType")
      ? account.planType ?? preservedCredentials.plan_type
      : undefined,
    refresh_token: account.refreshToken ?? preservedCredentials.refresh_token,
    session_token: account.sessionToken ?? preservedCredentials.session_token,
  }) as JsonRecord;
  const extra = settings
    ? preservedExtra
    : compactObject({
      ...preservedExtra,
      email: account.email ?? preservedExtra.email,
      email_key: toEmailKey(account.email) ?? preservedExtra.email_key,
      name: firstNonEmpty(preservedExtra.name, account.name),
      auth_provider: firstNonEmpty(
        preservedExtra.auth_provider,
        account.authProvider,
      ),
      source: firstNonEmpty(preservedExtra.source, account.sourceType),
      last_refresh: firstNonEmpty(
        preservedExtra.last_refresh,
        account.lastRefresh,
        normalizeTimestamp(now),
      ),
    });

  const concurrency = settings?.concurrency !== undefined
    && settings.concurrency >= 0 ? settings.concurrency : 10;
  const priority = settings?.priority !== undefined && settings.priority >= 0
    ? settings.priority
    : 1;
  const rateMultiplier = settings?.rateMultiplier !== undefined
    && settings.rateMultiplier >= 0 ? settings.rateMultiplier : 1;
  const autoPauseOnExpired = settings?.autoPauseOnExpired
    ?? (account.sourceType === "cpa" ? true : pauseExpiry ? true : undefined);

  return compactObject({
    ...(settings?.accountFields ?? {}),
    name: firstNonEmpty(
      settings?.name,
      account.name,
      account.email,
      "ChatGPT Account",
    ),
    platform: "openai",
    type: "oauth",
    expires_at: pauseExpiry,
    auto_pause_on_expired: autoPauseOnExpired,
    concurrency,
    priority,
    rate_multiplier: rateMultiplier,
    disabled: settings?.disabled ?? (account.disabled || undefined),
    credentials,
    extra,
  }) as unknown as Sub2ApiAccount;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  }
  if (isPlainObject(value)) {
    return "{" + Object.keys(value).sort().map((key) => (
      JSON.stringify(key) + ":" + canonicalJson(value[key])
    )).join(",") + "}";
  }
  return JSON.stringify(value) ?? String(value);
}

function getDistinctSub2ApiDocumentFields(
  accounts: NormalizedAccount[],
): JsonRecord[] {
  const documents: JsonRecord[] = [];
  const seen = new Set<string>();
  for (const account of accounts) {
    const document = account.sub2ApiSettings?.documentFields;
    if (!document) {
      continue;
    }
    const signature = canonicalJson(document);
    if (!seen.has(signature)) {
      seen.add(signature);
      documents.push(document);
    }
  }
  return documents;
}

export function getSub2ApiDocumentConflicts(
  accounts: NormalizedAccount[],
): string[] {
  const documents = getDistinctSub2ApiDocumentFields(accounts);
  const keys = new Set(documents.flatMap((document) => Object.keys(document)));
  keys.delete("exported_at");
  keys.delete("proxies");
  return [...keys].filter((key) => {
    const values = documents
      .filter((document) => document[key] !== undefined)
      .map((document) => canonicalJson(document[key]));
    return new Set(values).size > 1;
  }).sort();
}

function mergeSub2ApiDocumentFields(documents: JsonRecord[]): JsonRecord {
  const merged: JsonRecord = {};
  const keys = new Set(documents.flatMap((document) => Object.keys(document)));
  keys.delete("accounts");
  keys.delete("exported_at");
  keys.delete("proxies");

  for (const key of keys) {
    const values = documents
      .filter((document) => document[key] !== undefined)
      .map((document) => document[key]);
    if (!values.length) {
      continue;
    }
    const signatures = new Set(values.map((value) => canonicalJson(value)));
    if (signatures.size === 1) {
      merged[key] = values[0];
    }
  }

  const proxies: unknown[] = [];
  const seenProxies = new Set<string>();
  for (const document of documents) {
    if (!Array.isArray(document.proxies)) {
      continue;
    }
    for (const proxy of document.proxies) {
      const signature = canonicalJson(proxy);
      if (!seenProxies.has(signature)) {
        seenProxies.add(signature);
        proxies.push(proxy);
      }
    }
  }
  merged.proxies = proxies;
  return merged;
}

export function buildSub2ApiDocument(
  accounts: NormalizedAccount[],
  options: ConvertOptions = {},
): Sub2ApiDocument {
  const now = options.now ?? new Date();
  const documents = getDistinctSub2ApiDocumentFields(accounts);
  const documentFields = mergeSub2ApiDocumentFields(documents);
  const preservedExportedAt = documents.length === 1
    ? firstNonEmpty(documents[0].exported_at)
    : undefined;
  return {
    ...documentFields,
    exported_at: preservedExportedAt
      ?? normalizeTimestamp(now)
      ?? now.toISOString(),
    proxies: documentFields.proxies as unknown[],
    accounts: accounts.map((account) => toSub2ApiAccount(account, { now })),
  };
}

export function buildCpaDocument(
  accounts: NormalizedAccount[],
  options: ConvertOptions = {},
): CpaRecord | CpaRecord[] {
  const records = accounts.map((account) => toCpaRecord(account, options));
  return records.length === 1 ? records[0] : records;
}

export function buildOutputDocument(
  accounts: NormalizedAccount[],
  format: OutputFormat,
  options: ConvertOptions = {},
): OutputDocument {
  return format === "cpa"
    ? buildCpaDocument(accounts, options)
    : buildSub2ApiDocument(accounts, options);
}

function buildCpaFileName(account: NormalizedAccount, index: number): string {
  const fallback = account.accountId ?? "chatgpt-account-" + (index + 1);
  const fileToken = sanitizeFileToken(
    account.email ?? account.name ?? fallback,
    fallback,
  ).replace(/\.json$/iu, "");
  return fileToken + ".json";
}

function buildCpaArchiveEntries(
  accounts: NormalizedAccount[],
  options: ConvertOptions = {},
): ArchiveEntry[] {
  return accounts.map((account, index) => ({
    fileName: buildCpaFileName(account, index),
    text: JSON.stringify(toCpaRecord(account, options), null, 2) + "\n",
  }));
}

export function getDownloadDescriptor(
  accounts: NormalizedAccount[],
  format: OutputFormat,
  options: ConvertOptions = {},
): DownloadDescriptor {
  if (!accounts.length) {
    throw new Error("没有可导出的账号");
  }
  const now = options.now ?? new Date();
  const timestamp = getTimestampToken(now);
  if (format === "cpa" && accounts.length > 1) {
    return {
      kind: "zip",
      fileName: "cpa-" + timestamp + ".zip",
      entries: buildCpaArchiveEntries(accounts, { now }),
    };
  }
  if (format === "cpa") {
    return {
      kind: "json",
      fileName: buildCpaFileName(accounts[0], 0),
      document: toCpaRecord(accounts[0], { now }),
    };
  }
  return {
    kind: "json",
    fileName: "sub2api-" + timestamp + ".json",
    document: buildSub2ApiDocument(accounts, { now }),
  };
}
