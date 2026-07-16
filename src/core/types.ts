export type OutputFormat = "sub2api" | "cpa";
export type AccountSourceType = "chatgpt_web_session" | "cpa" | "sub2api";
export type JsonRecord = Record<string, unknown>;

export interface Sub2ApiSettings {
  name?: string;
  platform?: string;
  accountType?: string;
  concurrency?: number;
  priority?: number;
  rateMultiplier?: number;
  autoPauseOnExpired?: boolean;
  expiresAt?: number;
  disabled?: boolean;
  credentials: JsonRecord;
  extra: JsonRecord;
  accountFields: JsonRecord;
  originalCredentialKeys: string[];
  documentFields?: JsonRecord;
  restoredFromBridge?: boolean;
}

export interface ParseIssue {
  sourceName: string;
  sourcePath?: string;
  reason: string;
}

export interface NormalizedAccount {
  sourceName: string;
  sourcePath: string;
  sourceType: AccountSourceType;
  name: string;
  email?: string;
  accountId?: string;
  userId?: string;
  planType?: string;
  organizationId?: string;
  authProvider: string;
  accessToken: string;
  sessionToken?: string;
  refreshToken?: string;
  inputIdToken?: string;
  syntheticIdToken?: string;
  idToken?: string;
  idTokenSynthetic: boolean;
  tokenExpiresAt?: string;
  accessTokenExpiresAt?: number;
  exportExpiresAt?: string;
  lastRefresh: string;
  disabled: boolean;
  isRefreshable: boolean;
  isExpired: boolean;
  warnings: string[];
  preservedCpaFields?: JsonRecord;
  sub2ApiSettings?: Sub2ApiSettings;
}

export interface ParseCredentialResult {
  accounts: NormalizedAccount[];
  issues: ParseIssue[];
}

export interface CpaRecord extends JsonRecord {
  type: "codex";
  access_token: string;
  refresh_token: string;
}

export interface Sub2ApiAccount {
  name: string;
  platform: "openai";
  type: "oauth";
  expires_at?: number;
  auto_pause_on_expired?: boolean;
  concurrency: number;
  priority: number;
  rate_multiplier: number;
  disabled?: boolean;
  credentials: JsonRecord;
  extra?: JsonRecord;
}

export interface Sub2ApiDocument extends JsonRecord {
  exported_at: string;
  proxies: unknown[];
  accounts: Sub2ApiAccount[];
}

export type OutputDocument = Sub2ApiDocument | CpaRecord | CpaRecord[];

export interface ArchiveEntry {
  fileName: string;
  text: string;
}

export type DownloadDescriptor =
  | {
      kind: "zip";
      fileName: string;
      entries: ArchiveEntry[];
    }
  | {
      kind: "json";
      fileName: string;
      document: CpaRecord | Sub2ApiDocument;
    };
