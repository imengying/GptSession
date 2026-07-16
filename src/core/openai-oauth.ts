import type { JsonRecord } from "./types";

export const OPENAI_CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
export const OPENAI_MOBILE_CLIENT_ID = "app_LlGpXReQgckcGGUo2JrYvtJK";
export const OPENAI_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token";
export const OPENAI_PAT_WHOAMI_URL =
  "https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami";
export const OPENAI_OAUTH_SCOPE = "openid profile email";

export const OPENAI_OAUTH_CLIENT_IDS = [
  OPENAI_CODEX_CLIENT_ID,
  OPENAI_MOBILE_CLIENT_ID,
] as const;

export type OpenAiOAuthClientId = typeof OPENAI_OAUTH_CLIENT_IDS[number];

export interface OpenAiOAuthTokenInfo extends JsonRecord {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
  expires_at?: number;
  scope?: string;
  client_id: OpenAiOAuthClientId;
  email?: string;
  name?: string;
  chatgpt_account_id?: string;
  chatgpt_user_id?: string;
  organization_id?: string;
  plan_type?: string;
  subscription_expires_at?: string;
  privacy_mode?: string;
}

export interface OpenAiPersonalAccessTokenInfo extends JsonRecord {
  email: string;
  chatgpt_user_id: string;
  chatgpt_account_id: string;
  chatgpt_plan_type: string;
  chatgpt_account_is_fedramp: boolean;
}

export function isOpenAiOAuthClientId(
  value: unknown,
): value is OpenAiOAuthClientId {
  return typeof value === "string"
    && OPENAI_OAUTH_CLIENT_IDS.some((clientId) => clientId === value);
}
