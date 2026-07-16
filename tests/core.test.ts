import { describe, expect, test } from "bun:test";

import {
  OPENAI_AUTH_CLAIM,
  OPENAI_PROFILE_CLAIM,
  buildZipArchive,
  buildCpaDocument,
  buildSub2ApiDocument,
  getDownloadDescriptor,
  getSub2ApiDocumentConflicts,
  normalizeSessionRecord,
  parseCredentialText,
  parseJwtPayload,
  parseManualTokenText,
  redactSensitiveDocument,
  toCpaRecord,
  toSub2ApiAccount,
  type JsonRecord,
} from "../src/core";

const NOW = new Date("2026-07-16T04:00:00.000Z");
const EXPIRY = 4_102_444_800;

function jwt(payload: JsonRecord): string {
  const encode = (value: unknown) => (
    Buffer.from(JSON.stringify(value)).toString("base64url")
  );
  return encode({ alg: "none", typ: "JWT" })
    + "." + encode(payload) + ".signature";
}

function createSession(
  email: string,
  accountId: string,
  exp = EXPIRY,
): JsonRecord {
  return {
    user: {
      id: "user-" + accountId,
      email,
    },
    account: {
      id: accountId,
      planType: "plus",
    },
    accessToken: jwt({
      exp,
      email,
      [OPENAI_PROFILE_CLAIM]: {
        email,
      },
      [OPENAI_AUTH_CLAIM]: {
        chatgpt_account_id: accountId,
        chatgpt_plan_type: "plus",
        chatgpt_user_id: "user-" + accountId,
      },
    }),
    sessionToken: "session-" + accountId,
  };
}

function readZipFileNames(bytes: Uint8Array): string[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const decoder = new TextDecoder();
  const names: string[] = [];
  let offset = 0;
  while (offset + 30 <= bytes.length) {
    if (view.getUint32(offset, true) !== 0x04034b50) {
      break;
    }
    const compressedSize = view.getUint32(offset + 18, true);
    const fileNameLength = view.getUint16(offset + 26, true);
    const extraLength = view.getUint16(offset + 28, true);
    const nameStart = offset + 30;
    names.push(decoder.decode(bytes.subarray(
      nameStart,
      nameStart + fileNameLength,
    )));
    offset = nameStart + fileNameLength + extraLength + compressedSize;
  }
  return names;
}

describe("Session normalization", () => {
  test("normalizes a standard ChatGPT Web Session", () => {
    const parsed = parseCredentialText(
      JSON.stringify(createSession("mark@example.com", "account-1")),
      { sourceName: "session.json", now: NOW },
    );

    expect(parsed.accounts).toHaveLength(1);
    expect(parsed.issues).toHaveLength(0);
    expect(parsed.accounts[0]).toMatchObject({
      email: "mark@example.com",
      accountId: "account-1",
      planType: "plus",
      accessTokenExpiresAt: EXPIRY,
      isRefreshable: false,
    });
  });

  test("parses nested arrays and consecutive JSON documents", () => {
    const first = createSession("nested@example.com", "nested-1");
    const second = createSession("next@example.com", "nested-2");
    const text = JSON.stringify({ data: { sessions: [first] } })
      + "\n" + JSON.stringify(second);
    const result = parseCredentialText(text, {
      sourceName: "batch",
      now: NOW,
    });

    expect(result.accounts.map((account) => account.email)).toEqual([
      "nested@example.com",
      "next@example.com",
    ]);
  });

  test("ignores duplicate Sessions without exposing token text", () => {
    const session = createSession("duplicate@example.com", "duplicate-1");
    const result = parseCredentialText(JSON.stringify([session, session]), {
      sourceName: "duplicates.json",
      now: NOW,
    });

    expect(result.accounts).toHaveLength(1);
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].reason).toContain("重复");
    expect(result.issues[0].reason).not.toContain(String(session.accessToken));
  });

  test("returns a safe issue for invalid JSON", () => {
    const result = parseCredentialText('{"accessToken":"secret-value"', {
      sourceName: "broken.json",
      now: NOW,
    });

    expect(result.accounts).toHaveLength(0);
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].reason).not.toContain("secret-value");
  });
});

describe("Sub2API export", () => {
  test("uses each access token JWT expiry", () => {
    const first = normalizeSessionRecord(
      createSession("one@example.com", "account-one"),
      { sourceName: "one.json", now: NOW },
    );
    const second = normalizeSessionRecord(
      createSession("two@example.com", "account-two", EXPIRY - 1000),
      { sourceName: "two.json", now: NOW },
    );
    const document = buildSub2ApiDocument([first, second], { now: NOW });

    expect(document.exported_at).toBe(NOW.toISOString());
    expect(document.proxies).toEqual([]);
    expect(document.accounts).toHaveLength(2);
    expect(document.accounts[0]).toMatchObject({
      platform: "openai",
      type: "oauth",
      expires_at: EXPIRY,
      auto_pause_on_expired: true,
    });
    expect(document.accounts[1].expires_at).toBe(EXPIRY - 1000);
    expect(document.accounts[0].credentials.chatgpt_account_id)
      .toBe("account-one");
  });

  test("preserves real OAuth tokens and omits pause expiry", () => {
    const session = createSession(
      "refresh@example.com",
      "account-refresh",
    );
    const idToken = jwt({ email: "refresh@example.com" });
    session.refreshToken = "real-refresh-token";
    session.idToken = idToken;
    const account = normalizeSessionRecord(session, {
      sourceName: "refresh.json",
      now: NOW,
    });
    const sub2api = toSub2ApiAccount(account, { now: NOW });
    const cpa = toCpaRecord(account, { now: NOW });

    expect(account.isRefreshable).toBe(true);
    expect(sub2api.expires_at).toBeUndefined();
    expect(sub2api.auto_pause_on_expired).toBeUndefined();
    expect(sub2api.credentials.expires_at).toBeUndefined();
    expect(sub2api.credentials.expires_in).toBeUndefined();
    expect(sub2api.credentials.refresh_token).toBe("real-refresh-token");
    expect(cpa.refresh_token).toBe("real-refresh-token");
    expect(cpa.id_token).toBe(idToken);
    expect(cpa.expired).toBeUndefined();
  });
});

describe("CPA export", () => {
  test("creates a parseable marked synthetic id_token", () => {
    const account = normalizeSessionRecord(
      createSession("cpa@example.com", "account-cpa"),
      { sourceName: "cpa.json", now: NOW },
    );
    const cpa = toCpaRecord(account, { now: NOW });
    const download = getDownloadDescriptor([account], "cpa", { now: NOW });
    const idToken = String(cpa.id_token);
    const payload = parseJwtPayload(idToken);

    expect(cpa.id_token_synthetic).toBe(true);
    expect(idToken.split(".")).toHaveLength(3);
    expect(idToken.split(".").every(Boolean)).toBe(true);
    expect(payload?.email).toBe("cpa@example.com");
    expect(
      (payload?.[OPENAI_AUTH_CLAIM] as JsonRecord).chatgpt_account_id,
    ).toBe("account-cpa");
    expect(cpa.refresh_token).toBe("");
    expect(download.kind).toBe("json");
    expect(download.fileName).toBe("cpa@example.com.json");
  });

  test("redacts every secret while retaining valid JSON", () => {
    const account = normalizeSessionRecord(
      createSession("hidden@example.com", "hidden-1"),
      { sourceName: "hidden.json", now: NOW },
    );
    const full = buildCpaDocument([account], { now: NOW });
    const redacted = redactSensitiveDocument(full);
    const text = JSON.stringify(redacted);

    expect(text).not.toContain(account.accessToken);
    expect(text).not.toContain(account.sessionToken);
    expect(text).toContain("[hidden");
    expect((redacted as JsonRecord).id_token_synthetic).toBe(true);
  });

  test("redacts CPA passwords and secret aliases without changing the export", () => {
    const password = "correct-horse-battery-staple";
    const clientSecret = "private-client-secret";
    const cpa = {
      type: "codex",
      account_id: "password-account",
      email: "password@example.com",
      access_token: "opaque-password-access-token",
      refresh_token: "",
      password,
      client_secret: clientSecret,
    };
    const parsed = parseCredentialText(JSON.stringify(cpa), {
      sourceName: "password.cpa.json",
      now: NOW,
    });
    const full = buildSub2ApiDocument(parsed.accounts, { now: NOW });
    const redactedText = JSON.stringify(redactSensitiveDocument(full));
    const fullText = JSON.stringify(full);

    expect(parsed.issues).toHaveLength(0);
    expect(full.accounts[0].extra?.password).toBe(password);
    expect(fullText).toContain(password);
    expect(fullText).toContain(clientSecret);
    expect(redactedText).not.toContain(password);
    expect(redactedText).not.toContain(clientSecret);
    expect(redactedText).toContain("[hidden");
  });

  test("builds a valid multi-account ZIP descriptor", async () => {
    const first = normalizeSessionRecord(
      createSession("same@example.com", "zip-1"),
      { sourceName: "zip-1.json", now: NOW },
    );
    const second = normalizeSessionRecord(
      createSession("same@example.com", "zip-2"),
      { sourceName: "zip-2.json", now: NOW },
    );
    const descriptor = getDownloadDescriptor(
      [first, second],
      "cpa",
      { now: NOW },
    );

    expect(descriptor.kind).toBe("zip");
    if (descriptor.kind !== "zip") {
      throw new Error("Expected ZIP descriptor");
    }
    expect(descriptor.entries).toHaveLength(2);
    expect(descriptor.fileName).toEndWith(".zip");

    const archive = buildZipArchive(descriptor.entries, { modifiedAt: NOW });
    const bytes = new Uint8Array(await archive.arrayBuffer());
    const archiveText = Buffer.from(bytes).toString("utf8");
    expect(Array.from(bytes.slice(0, 4))).toEqual([0x50, 0x4b, 0x03, 0x04]);
    expect(archiveText).toContain("same@example.com.json");
    expect(archiveText).toContain("same@example.com-2.json");
    expect(bytes.length).toBeGreaterThan(100);
  });

  test("keeps ZIP entry names unique when a generated suffix already exists", async () => {
    const archive = buildZipArchive([
      { fileName: "account.json", text: "one" },
      { fileName: "account-2.json", text: "two" },
      { fileName: "account.json", text: "three" },
    ], { modifiedAt: NOW });
    const names = readZipFileNames(new Uint8Array(await archive.arrayBuffer()));

    expect(names).toEqual([
      "account.json",
      "account-2.json",
      "account-3.json",
    ]);
  });

  test("keeps a long email intact in the CPA JSON file name", () => {
    const email = "a".repeat(100) + "@example.com";
    const account = normalizeSessionRecord(
      createSession(email, "long-email-account"),
      { sourceName: "long-email.json", now: NOW },
    );
    const download = getDownloadDescriptor([account], "cpa", { now: NOW });

    expect(download.fileName).toBe(email + ".json");
  });
});

describe("Manual AT and RT input", () => {
  test("rejects JWT and other non-at manual access tokens", () => {
    const jwtAccessToken = jwt({
      exp: EXPIRY,
      email: "manual-at@example.com",
      [OPENAI_AUTH_CLAIM]: {
        chatgpt_account_id: "manual-at-account",
        chatgpt_plan_type: "plus",
        chatgpt_user_id: "manual-at-user",
      },
    });
    const parsed = parseManualTokenText(jwtAccessToken + "\nat-\nsk-other", "at", {
      now: NOW,
    });

    expect(parsed.accounts).toHaveLength(0);
    expect(parsed.issues).toHaveLength(3);
    parsed.issues.forEach((issue) => {
      expect(issue.reason).toContain("仅支持 at- 开头");
    });
  });

  test("marks at- tokens as Sub2API personal access tokens", () => {
    const token = "at-personal-access-token";
    const parsed = parseManualTokenText(token + "\n" + token, "at", { now: NOW });
    const sub2api = toSub2ApiAccount(parsed.accounts[0], { now: NOW });
    const cpa = toCpaRecord(parsed.accounts[0], { now: NOW });

    expect(parsed.accounts).toHaveLength(1);
    expect(parsed.issues).toHaveLength(1);
    expect(parsed.issues[0].reason).toContain("重复");
    expect(sub2api).toMatchObject({
      platform: "openai",
      type: "oauth",
      concurrency: 3,
      priority: 50,
      auto_pause_on_expired: false,
      credentials: {
        access_token: token,
        auth_mode: "personal_access_token",
        openai_auth_mode: "personal_access_token",
        token_type: "Bearer",
      },
    });
    expect(parsed.accounts[0].warnings.join(" ")).not.toContain("refresh_token");
    expect(cpa.access_token).toBe(token);
    expect(cpa.refresh_token).toBe("");
  });

  test("exports RT to both Sub2API and CPA", () => {
    const parsed = parseManualTokenText("rt-refresh-token", "rt", {
      now: NOW,
    });
    const sub2Api = toSub2ApiAccount(parsed.accounts[0], { now: NOW });
    const cpa = toCpaRecord(parsed.accounts[0], { now: NOW });

    expect(parsed.accounts[0]).toMatchObject({
      sourceType: "manual_rt",
      accessToken: "",
      refreshToken: "rt-refresh-token",
      isRefreshable: true,
      warnings: [],
    });
    expect(sub2Api.credentials).toEqual({
      refresh_token: "rt-refresh-token",
    });
    expect(cpa).toMatchObject({
      type: "codex",
      access_token: "",
      refresh_token: "rt-refresh-token",
      id_token: "",
      id_token_synthetic: false,
      expired: "2026-07-16T03:59:00.000Z",
    });

    const sub2ApiRoundTrip = parseCredentialText(JSON.stringify(
      buildSub2ApiDocument(parsed.accounts, { now: NOW }),
    ), { now: NOW });
    expect(sub2ApiRoundTrip.issues).toHaveLength(0);
    expect(sub2ApiRoundTrip.accounts[0]).toMatchObject({
      accessToken: "",
      refreshToken: "rt-refresh-token",
      isRefreshable: true,
    });

    const restored = parseCredentialText(JSON.stringify(cpa), { now: NOW });
    const restoredSub2Api = buildSub2ApiDocument(restored.accounts, { now: NOW });
    expect(restored.issues).toHaveLength(0);
    expect(restoredSub2Api.accounts[0].credentials).toEqual({
      refresh_token: "rt-refresh-token",
    });
  });

  test("limits manual token batches to 500 entries", () => {
    const input = Array.from(
      { length: 501 },
      (_, index) => "rt-batch-" + index,
    ).join("\n");
    const parsed = parseManualTokenText(input, "rt", {
      maxTokens: 500,
      now: NOW,
    });

    expect(parsed.accounts).toHaveLength(500);
    expect(parsed.issues).toHaveLength(1);
    expect(parsed.issues[0].reason).toContain("500");
  });
});

describe("CPA and Sub2API exchange", () => {
  test("converts a CPA auth record to Sub2API without mixing secrets into extra", () => {
    const idToken = jwt({
      email: "cpa-source@example.com",
      [OPENAI_AUTH_CLAIM]: {
        chatgpt_account_id: "cpa-source-account",
        chatgpt_plan_type: "team",
      },
    });
    const cpa = {
      type: "codex",
      account_id: "cpa-source-account",
      chatgpt_account_id: "cpa-source-account",
      email: "cpa-source@example.com",
      name: "CPA Source",
      plan_type: "team",
      chatgpt_plan_type: "team",
      id_token: idToken,
      id_token_synthetic: false,
      access_token: jwt({ exp: EXPIRY, email: "cpa-source@example.com" }),
      refresh_token: "cpa-refresh-token",
      session_token: "cpa-session-token",
      last_refresh: "2026-07-15T10:00:00.000Z",
      expired: "2100-01-01T00:00:00.000Z",
      source: "gpt-team-all-ws",
      custom_label: "preserve-me",
    };

    const parsed = parseCredentialText(JSON.stringify(cpa), {
      sourceName: "cpa.json",
      now: NOW,
    });
    const output = buildSub2ApiDocument(parsed.accounts, { now: NOW });
    const account = output.accounts[0];

    expect(parsed.issues).toHaveLength(0);
    expect(parsed.accounts[0].sourceType).toBe("cpa");
    expect(account).toMatchObject({
      name: "CPA Source",
      platform: "openai",
      type: "oauth",
      concurrency: 10,
      priority: 1,
      rate_multiplier: 1,
      auto_pause_on_expired: true,
    });
    expect(account.credentials).toMatchObject({
      access_token: cpa.access_token,
      refresh_token: "cpa-refresh-token",
      session_token: "cpa-session-token",
      id_token: idToken,
      chatgpt_account_id: "cpa-source-account",
    });
    expect(account.extra).toMatchObject({
      type: "codex",
      account_id: "cpa-source-account",
      email: "cpa-source@example.com",
      custom_label: "preserve-me",
      source: "gpt-team-all-ws",
    });
    expect(account.extra?.access_token).toBeUndefined();
    expect(account.extra?.refresh_token).toBeUndefined();
  });

  test("converts a Sub2API package to CPA and preserves account settings", () => {
    const accessToken = jwt({
      exp: EXPIRY,
      email: "sub-source@example.com",
      [OPENAI_AUTH_CLAIM]: {
        chatgpt_account_id: "sub-source-account",
        chatgpt_plan_type: "plus",
      },
    });
    const idToken = jwt({ email: "sub-source@example.com" });
    const sub2api = {
      exported_at: "2026-07-14T08:30:00Z",
      proxies: [],
      accounts: [{
        name: "sub-source@example.com--primary",
        platform: "openai",
        type: "oauth",
        expires_at: EXPIRY,
        auto_pause_on_expired: true,
        concurrency: 7,
        priority: 4,
        rate_multiplier: 1.5,
        credentials: {
          access_token: accessToken,
          refresh_token: "sub-refresh-token",
          session_token: "sub-session-token",
          id_token: idToken,
          chatgpt_account_id: "sub-source-account",
          email: "sub-source@example.com",
          plan_type: "plus",
        },
        extra: {
          auth_provider: "codex",
          source: "legacy-cpa",
          custom_label: "keep-this-too",
        },
      }],
    };

    const parsed = parseCredentialText(JSON.stringify(sub2api), {
      sourceName: "sub2api.json",
      now: NOW,
    });
    const cpa = toCpaRecord(parsed.accounts[0], { now: NOW });
    const rebuilt = toSub2ApiAccount(parsed.accounts[0], { now: NOW });

    expect(parsed.issues).toHaveLength(0);
    expect(parsed.accounts[0].sourceType).toBe("sub2api");
    expect(cpa).toMatchObject({
      type: "codex",
      account_id: "sub-source-account",
      email: "sub-source@example.com",
      name: "sub-source@example.com_sub-sour",
      plan_type: "plus",
      access_token: accessToken,
      refresh_token: "sub-refresh-token",
      session_token: "sub-session-token",
      id_token: idToken,
      expired: "2100-01-01T00:00:00.000Z",
      last_refresh: "2026-07-14T08:30:00.000Z",
      source: "legacy-cpa",
      custom_label: "keep-this-too",
    });
    expect(rebuilt).toMatchObject({
      concurrency: 7,
      priority: 4,
      rate_multiplier: 1.5,
      auto_pause_on_expired: true,
      expires_at: EXPIRY,
    });
  });

  test("preserves an imported optional client_id without classifying the RT", () => {
    const original = {
      exported_at: NOW.toISOString(),
      proxies: [],
      accounts: [{
        name: "refresh-token-account",
        platform: "openai",
        type: "oauth",
        concurrency: 10,
        priority: 1,
        credentials: {
          refresh_token: "existing-refresh-token",
          client_id: "existing-client-id",
        },
        extra: {},
      }],
    };
    const first = parseCredentialText(JSON.stringify(original), { now: NOW });
    const cpa = toCpaRecord(first.accounts[0], { now: NOW });
    const second = parseCredentialText(JSON.stringify(cpa), { now: NOW });
    const restored = toSub2ApiAccount(second.accounts[0], { now: NOW });

    expect(first.issues).toHaveLength(0);
    expect(second.issues).toHaveLength(0);
    expect(restored.credentials).toMatchObject({
      refresh_token: "existing-refresh-token",
      client_id: "existing-client-id",
    });
  });

  test("round-trips CPA metadata and all four token fields through Sub2API", () => {
    const original = {
      type: "codex",
      account_id: "roundtrip-account",
      email: "roundtrip@example.com",
      name: "Roundtrip Account",
      plan_type: "pro",
      id_token: jwt({ email: "roundtrip@example.com" }),
      id_token_synthetic: false,
      access_token: jwt({ exp: EXPIRY, email: "roundtrip@example.com" }),
      refresh_token: "roundtrip-refresh",
      session_token: "roundtrip-session",
      last_refresh: "2026-07-13T00:00:00.000Z",
      expired: "2099-12-31T00:00:00.000Z",
      custom_metadata: { region: "test" },
    };
    const first = parseCredentialText(JSON.stringify(original), {
      sourceName: "original.cpa.json",
      now: NOW,
    });
    const sub2api = buildSub2ApiDocument(first.accounts, { now: NOW });
    const second = parseCredentialText(JSON.stringify(sub2api), {
      sourceName: "converted.sub2api.json",
      now: NOW,
    });
    const restored = toCpaRecord(second.accounts[0], { now: NOW });

    expect(restored).toMatchObject({
      type: "codex",
      account_id: original.account_id,
      email: original.email,
      name: original.name,
      plan_type: original.plan_type,
      id_token: original.id_token,
      access_token: original.access_token,
      refresh_token: original.refresh_token,
      session_token: original.session_token,
      expired: original.expired,
      custom_metadata: original.custom_metadata,
    });
  });

  test("reports unsupported Sub2API account types without exposing tokens", () => {
    const input = {
      exported_at: NOW.toISOString(),
      proxies: [],
      accounts: [{
        name: "unsupported",
        platform: "anthropic",
        type: "api_key",
        credentials: { access_token: "do-not-leak-this-token" },
        concurrency: 1,
        priority: 1,
      }],
    };
    const parsed = parseCredentialText(JSON.stringify(input), { now: NOW });

    expect(parsed.accounts).toHaveLength(0);
    expect(parsed.issues).toHaveLength(1);
    expect(parsed.issues[0].reason).toContain("platform=openai");
    expect(parsed.issues[0].reason).not.toContain("do-not-leak-this-token");
  });

  test("round-trips a multi-account Sub2API package without losing extensions", () => {
    const accounts = Array.from({ length: 3 }, (_, index) => ({
      name: `multi-${index + 1}@example.com`,
      platform: "openai",
      type: "oauth",
      auto_pause_on_expired: true,
      concurrency: 10,
      priority: 1,
      rate_multiplier: 1,
      credentials: {
        access_token: `opaque-access-token-${index + 1}`,
        auth_mode: "oauth",
        chatgpt_account_id: `multi-account-${index + 1}`,
        chatgpt_account_is_fedramp: false,
        chatgpt_user_id: `multi-user-${index + 1}`,
        email: `multi-${index + 1}@example.com`,
        model_mapping: {},
        openai_auth_mode: "chatgpt",
        plan_type: "plus",
        token_type: "Bearer",
      },
      extra: {
        access_token_sha256: `hash-${index + 1}`,
        auth_provider: "openai",
        codex_5h_used_percent: index * 10,
        codex_5h_window_minutes: 300,
        privacy_mode: false,
      },
    }));
    const original = {
      type: "sub2api-data",
      version: 1,
      exported_at: "2026-07-16T14:02:55Z",
      proxies: [],
      accounts,
    };

    const first = parseCredentialText(JSON.stringify(original), {
      sourceName: "1.json",
      now: NOW,
    });
    const cpa = buildCpaDocument(first.accounts, { now: NOW });
    const cpaRecords = Array.isArray(cpa) ? cpa : [cpa];
    const second = parseCredentialText(JSON.stringify(cpaRecords), {
      sourceName: "cpa-directory",
      now: NOW,
    });
    const restored = buildSub2ApiDocument(second.accounts, { now: NOW });

    expect(first.issues).toHaveLength(0);
    expect(first.accounts).toHaveLength(3);
    expect(cpaRecords).toHaveLength(3);
    expect(second.issues).toHaveLength(0);
    expect(second.accounts).toHaveLength(3);
    expect(restored).toMatchObject({
      type: original.type,
      version: original.version,
      exported_at: original.exported_at,
      proxies: original.proxies,
    });

    cpaRecords.forEach((record) => {
      const bridge = record.session_bridge as JsonRecord;
      const sub2api = bridge.sub2api as JsonRecord;
      const credentials = sub2api.credentials as JsonRecord;
      expect(bridge).toMatchObject({ schema: 1, source: "sub2api" });
      expect(credentials.access_token).toBeUndefined();
    });

    restored.accounts.forEach((account, index) => {
      const source = accounts[index];
      expect(account.name).toBe(source.name);
      expect(account.concurrency).toBe(source.concurrency);
      expect(account.priority).toBe(source.priority);
      expect(account.rate_multiplier).toBe(source.rate_multiplier);
      expect(Object.keys(account.credentials).sort()).toEqual(
        Object.keys(source.credentials).sort(),
      );
      expect(account.credentials).toEqual(source.credentials);
      expect(account.credentials.model_mapping).toEqual({});
      expect(account.credentials.id_token).toBeUndefined();
      expect(account.extra).toEqual(source.extra);
    });
  });

  test("merges metadata from multiple Sub2API packages and reports conflicts", () => {
    const makePackage = (label: string, version: number) => ({
      type: "sub2api-data-" + label,
      version,
      shared_extension: { enabled: true },
      exported_at: version === 1
        ? "2026-07-15T00:00:00.000Z"
        : "2026-07-16T00:00:00.000Z",
      proxies: [{ name: "proxy-" + label }],
      accounts: [{
        name: label + "@example.com",
        platform: "openai",
        type: "oauth",
        concurrency: 1,
        priority: 1,
        rate_multiplier: 1,
        credentials: {
          access_token: "opaque-token-" + label,
          email: label + "@example.com",
        },
      }],
    });
    const first = parseCredentialText(JSON.stringify(makePackage("first", 1)), {
      sourceName: "first.json",
      now: NOW,
    });
    const second = parseCredentialText(JSON.stringify(makePackage("second", 2)), {
      sourceName: "second.json",
      now: NOW,
    });
    const accounts = [...first.accounts, ...second.accounts];
    const output = buildSub2ApiDocument(accounts, { now: NOW });

    expect(getSub2ApiDocumentConflicts(accounts)).toEqual(["type", "version"]);
    expect(output.type).toBeUndefined();
    expect(output.version).toBeUndefined();
    expect(output.shared_extension).toEqual({ enabled: true });
    expect(output.exported_at).toBe(NOW.toISOString());
    expect(output.proxies).toEqual([
      { name: "proxy-first" },
      { name: "proxy-second" },
    ]);
    expect(output.accounts).toHaveLength(2);
  });
});
