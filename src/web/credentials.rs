use std::collections::{BTreeSet, HashSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::Date;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::model::{
    ArchiveEntry, DownloadDescriptor, InputMode, JsonMap, NormalizedAccount, OAuthTokenInfo,
    OutputFormat, ParseIssue, ParseResult, PersonalAccessTokenInfo, SourceType, Sub2ApiSettings,
};

pub const OPENAI_AUTH_CLAIM: &str = "https://api.openai.com/auth";
pub const OPENAI_PROFILE_CLAIM: &str = "https://api.openai.com/profile";
pub const OPENAI_CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const OPENAI_MOBILE_CLIENT_ID: &str = "app_LlGpXReQgckcGGUo2JrYvtJK";

const SESSION_BRIDGE_KEY: &str = "session_bridge";
const SESSION_BRIDGE_SCHEMA: i64 = 1;
const MAX_CPA_FILE_TOKEN_BYTES: usize = 240;
const MAX_ACCESS_TOKEN_LENGTH: usize = 8 * 1024;
const MAX_REFRESH_TOKEN_LENGTH: usize = 16 * 1024;
const OPENAI_PAT_AUTH_MODE: &str = "personalAccessToken";
const OPENAI_PAT_LEGACY_AUTH_MODE: &str = "personal_access_token";

const ACCESS_TOKEN_PATHS: &[&str] = &[
    "accessToken",
    "access_token",
    "tokens.accessToken",
    "tokens.access_token",
    "token.accessToken",
    "token.access_token",
    "credentials.accessToken",
    "credentials.access_token",
];
const SESSION_TOKEN_PATHS: &[&str] = &[
    "sessionToken",
    "session_token",
    "tokens.sessionToken",
    "tokens.session_token",
    "token.sessionToken",
    "token.session_token",
    "credentials.sessionToken",
    "credentials.session_token",
];
const REFRESH_TOKEN_PATHS: &[&str] = &[
    "refreshToken",
    "refresh_token",
    "tokens.refreshToken",
    "tokens.refresh_token",
    "token.refreshToken",
    "token.refresh_token",
    "credentials.refreshToken",
    "credentials.refresh_token",
];
const ID_TOKEN_PATHS: &[&str] = &[
    "idToken",
    "id_token",
    "tokens.idToken",
    "tokens.id_token",
    "token.idToken",
    "token.id_token",
    "credentials.idToken",
    "credentials.id_token",
];
const CREDENTIAL_FIELD_NAMES: &[&str] = &[
    "access_token",
    "accessToken",
    "refresh_token",
    "refreshToken",
    "id_token",
    "idToken",
    "session_token",
    "sessionToken",
];

#[derive(Clone)]
struct CredentialCandidate {
    value: JsonMap,
    source_name: String,
    source_path: String,
    source_type: SourceType,
    exported_at: Option<String>,
    sub2api_settings: Option<Sub2ApiSettings>,
}

fn non_empty(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn first_non_empty(values: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    values.into_iter().flatten().find(|value| !value.is_empty())
}

fn at_path<'a>(record: &'a JsonMap, path: &str) -> Option<&'a Value> {
    let mut current = record;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        let value = current.get(part)?;
        if parts.peek().is_none() {
            return Some(value);
        }
        current = value.as_object()?;
    }
    None
}

fn read_string(record: &JsonMap, path: &str) -> Option<String> {
    at_path(record, path).and_then(non_empty)
}

fn read_first_string(record: &JsonMap, paths: &[&str]) -> Option<String> {
    first_non_empty(paths.iter().map(|path| read_string(record, path)))
}

fn number(value: &Value) -> Option<f64> {
    value.as_f64().or_else(|| {
        value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite())
    })
}

fn bool_value(value: &Value) -> Option<bool> {
    value.as_bool().or_else(|| match value {
        Value::String(value) if value == "true" || value == "1" => Some(true),
        Value::String(value) if value == "false" || value == "0" => Some(false),
        Value::Number(value) if value.as_i64() == Some(1) => Some(true),
        Value::Number(value) if value.as_i64() == Some(0) => Some(false),
        _ => None,
    })
}

fn to_i64(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        number(value).and_then(|value| {
            if value.is_finite() && value >= i64::MIN as f64 && value <= i64::MAX as f64 {
                Some(value.trunc() as i64)
            } else {
                None
            }
        })
    })
}

fn date_to_iso(milliseconds: f64) -> Option<String> {
    if !milliseconds.is_finite() {
        return None;
    }
    let date = Date::new(&milliseconds.into());
    if date.get_time().is_nan() {
        None
    } else {
        date.to_iso_string().as_string()
    }
}

fn normalize_timestamp(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if let Some(numeric) = number(value) {
        let milliseconds = if numeric > 1e11 {
            numeric
        } else {
            numeric * 1000.0
        };
        return date_to_iso(milliseconds);
    }
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    date_to_iso(Date::parse(text))
}

fn timestamp_from_unix_seconds(value: Option<&Value>) -> Option<String> {
    let numeric = value.and_then(number).filter(|value| *value > 0.0)?;
    date_to_iso(numeric * 1000.0)
}

fn unix_seconds(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if value.is_null() || value.as_str() == Some("") {
        return None;
    }
    if let Some(numeric) = number(value) {
        return Some(
            (if numeric > 1e11 {
                numeric / 1000.0
            } else {
                numeric
            })
            .trunc() as i64,
        );
    }
    let parsed = Date::parse(value.as_str()?);
    parsed.is_finite().then(|| (parsed / 1000.0).trunc() as i64)
}

fn now_iso(now_ms: f64) -> String {
    date_to_iso(now_ms).unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_owned())
}

fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_jwt_payload(token: Option<&str>) -> Option<JsonMap> {
    let token = token?.trim();
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()
        .cloned()
}

fn claim(payload: Option<&JsonMap>, name: &str) -> JsonMap {
    payload
        .and_then(|payload| payload.get(name))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn encode_json_base64(value: &Value) -> Option<String> {
    serde_json::to_vec(value)
        .ok()
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

fn build_synthetic_id_token(
    account_id: Option<&str>,
    email: Option<&str>,
    plan_type: Option<&str>,
    user_id: Option<&str>,
    token_expires_at: Option<&str>,
    now_ms: f64,
) -> Option<String> {
    let account_id = account_id?;
    let issued_at = (now_ms / 1000.0).trunc() as i64;
    let expires_at = token_expires_at
        .map(|value| Value::String(value.to_owned()))
        .as_ref()
        .and_then(|value| unix_seconds(Some(value)))
        .unwrap_or(issued_at + 90 * 24 * 60 * 60);
    let mut auth = JsonMap::new();
    auth.insert("chatgpt_account_id".to_owned(), json!(account_id));
    if let Some(plan_type) = plan_type {
        auth.insert("chatgpt_plan_type".to_owned(), json!(plan_type));
    }
    if let Some(user_id) = user_id {
        auth.insert("chatgpt_user_id".to_owned(), json!(user_id));
        auth.insert("user_id".to_owned(), json!(user_id));
    }
    let mut payload = JsonMap::new();
    payload.insert("iat".to_owned(), json!(issued_at));
    payload.insert("exp".to_owned(), json!(expires_at));
    payload.insert(OPENAI_AUTH_CLAIM.to_owned(), Value::Object(auth));
    if let Some(email) = email {
        payload.insert("email".to_owned(), json!(email));
    }
    let header = json!({
        "alg": "none",
        "typ": "JWT",
        "session_bridge_synthetic": true,
    });
    Some(format!(
        "{}.{}.synthetic",
        encode_json_base64(&header)?,
        encode_json_base64(&Value::Object(payload))?
    ))
}

fn without_fields(record: &JsonMap, field_names: &[&str]) -> JsonMap {
    record
        .iter()
        .filter(|(key, _)| !field_names.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn without_credential_fields(record: &JsonMap) -> JsonMap {
    without_fields(record, CREDENTIAL_FIELD_NAMES)
}

fn is_likely_cpa(record: &JsonMap) -> bool {
    record.get("type").and_then(Value::as_str) == Some("codex")
        || (record.get("access_token").is_some_and(Value::is_string)
            && [
                "account_id",
                "chatgpt_account_id",
                "last_refresh",
                "expired",
            ]
            .iter()
            .any(|key| record.contains_key(*key)))
}

fn is_likely_sub2api_account(record: &JsonMap) -> bool {
    record.get("credentials").is_some_and(Value::is_object)
        && (record.contains_key("platform")
            || record.get("type").and_then(Value::as_str) == Some("oauth")
            || record.contains_key("concurrency")
            || record.contains_key("priority"))
}

fn is_likely_sub2api_document(record: &JsonMap) -> bool {
    let Some(accounts) = record.get("accounts").and_then(Value::as_array) else {
        return false;
    };
    record.contains_key("exported_at")
        || record.get("proxies").is_some_and(Value::is_array)
        || accounts
            .iter()
            .filter_map(Value::as_object)
            .any(is_likely_sub2api_account)
}

fn email_from_name(value: Option<&Value>) -> Option<String> {
    let name = value.and_then(non_empty)?;
    let candidate = name.split("--").next()?.trim();
    candidate.contains('@').then(|| candidate.to_owned())
}

fn build_sub2api_settings(
    record: &JsonMap,
    document_fields: Option<JsonMap>,
    restored_from_bridge: bool,
    credential_keys: Option<Vec<String>>,
) -> Sub2ApiSettings {
    let credentials = record
        .get("credentials")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let extra = record
        .get("extra")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let account_fields = record
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "credentials" | "extra"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let original_credential_keys =
        credential_keys.unwrap_or_else(|| credentials.keys().cloned().collect());
    Sub2ApiSettings {
        name: record.get("name").and_then(non_empty),
        platform: record.get("platform").and_then(non_empty),
        account_type: record.get("type").and_then(non_empty),
        concurrency: record.get("concurrency").and_then(number),
        priority: record.get("priority").and_then(number),
        rate_multiplier: record.get("rate_multiplier").and_then(number),
        auto_pause_on_expired: record.get("auto_pause_on_expired").and_then(bool_value),
        expires_at: unix_seconds(record.get("expires_at")),
        disabled: record.get("disabled").and_then(bool_value),
        credentials,
        extra,
        account_fields,
        original_credential_keys,
        document_fields,
        restored_from_bridge,
    }
}

fn read_bridge_settings(record: &JsonMap) -> Option<Sub2ApiSettings> {
    let bridge = record.get(SESSION_BRIDGE_KEY)?.as_object()?;
    if bridge.get("schema").and_then(Value::as_i64) != Some(SESSION_BRIDGE_SCHEMA)
        || bridge.get("source").and_then(Value::as_str) != Some("sub2api")
    {
        return None;
    }
    let sub2api = bridge.get("sub2api")?.as_object()?;
    let account = sub2api
        .get("account")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let credentials = sub2api
        .get("credentials")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let extra = sub2api
        .get("extra")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let document = sub2api.get("document").and_then(Value::as_object).cloned();
    let keys = sub2api
        .get("credential_keys")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(non_empty).collect::<Vec<String>>())
        .unwrap_or_else(|| credentials.keys().cloned().collect());
    let mut rebuilt = account;
    rebuilt.insert("credentials".to_owned(), Value::Object(credentials));
    rebuilt.insert("extra".to_owned(), Value::Object(extra));
    Some(build_sub2api_settings(&rebuilt, document, true, Some(keys)))
}

fn build_sub2api_normalization_record(record: &JsonMap, exported_at: Option<&str>) -> JsonMap {
    let settings = build_sub2api_settings(record, None, false, None);
    let credentials = &settings.credentials;
    let extra = &settings.extra;
    let mut normalized = extra.clone();
    normalized.extend(credentials.clone());
    let pairs: [(&str, Option<String>); 8] = [
        (
            "name",
            first_non_empty([
                extra.get("name").and_then(non_empty),
                record.get("name").and_then(non_empty),
            ]),
        ),
        (
            "email",
            first_non_empty([
                credentials.get("email").and_then(non_empty),
                extra.get("email").and_then(non_empty),
                email_from_name(record.get("name")),
            ]),
        ),
        (
            "account_id",
            first_non_empty([
                credentials.get("chatgpt_account_id").and_then(non_empty),
                extra.get("account_id").and_then(non_empty),
                extra.get("chatgpt_account_id").and_then(non_empty),
            ]),
        ),
        (
            "plan_type",
            first_non_empty([
                credentials.get("plan_type").and_then(non_empty),
                extra.get("plan_type").and_then(non_empty),
                extra.get("chatgpt_plan_type").and_then(non_empty),
            ]),
        ),
        (
            "last_refresh",
            first_non_empty([
                extra.get("last_refresh").and_then(non_empty),
                extra.get("lastRefresh").and_then(non_empty),
                exported_at.map(ToOwned::to_owned),
            ]),
        ),
        (
            "auth_provider",
            first_non_empty([
                extra.get("auth_provider").and_then(non_empty),
                Some("openai".to_owned()),
            ]),
        ),
        (
            "organization_id",
            credentials.get("organization_id").and_then(non_empty),
        ),
        (
            "user_id",
            credentials.get("chatgpt_user_id").and_then(non_empty),
        ),
    ];
    for (key, value) in pairs {
        if let Some(value) = value {
            normalized.insert(key.to_owned(), Value::String(value));
        }
    }
    let expires = credentials
        .get("expires_at")
        .or_else(|| record.get("expires_at"))
        .or_else(|| extra.get("expired"))
        .cloned();
    if let Some(expires) = expires {
        normalized.insert("expires_at".to_owned(), expires);
    }
    if let Some(disabled) = record
        .get("disabled")
        .and_then(bool_value)
        .or_else(|| extra.get("disabled").and_then(bool_value))
    {
        normalized.insert("disabled".to_owned(), Value::Bool(disabled));
    }
    normalized
}

fn is_likely_session(record: &JsonMap, token: &str) -> bool {
    let payload = parse_jwt_payload(Some(token));
    let auth = claim(payload.as_ref(), OPENAI_AUTH_CLAIM);
    let profile = claim(payload.as_ref(), OPENAI_PROFILE_CLAIM);
    record.get("user").is_some_and(Value::is_object)
        || record.get("account").is_some_and(Value::is_object)
        || ["email", "name", "label", "account_id", "accountId"]
            .iter()
            .any(|path| read_string(record, path).is_some())
        || read_string(record, "meta.label").is_some()
        || auth.get("chatgpt_account_id").and_then(non_empty).is_some()
        || profile.get("email").and_then(non_empty).is_some()
        || payload
            .as_ref()
            .and_then(|value| value.get("email"))
            .and_then(non_empty)
            .is_some()
        || read_first_string(record, SESSION_TOKEN_PATHS).is_some()
        || read_first_string(record, REFRESH_TOKEN_PATHS).is_some()
        || read_first_string(record, ID_TOKEN_PATHS).is_some()
        || payload.as_ref().is_some_and(|payload| {
            payload.contains_key("exp") || !auth.is_empty() || !profile.is_empty()
        })
}

fn collect_candidates(value: &Value, source_name: &str) -> Vec<CredentialCandidate> {
    fn visit(value: &Value, source_name: &str, path: &str, found: &mut Vec<CredentialCandidate>) {
        if let Some(values) = value.as_array() {
            for (index, item) in values.iter().enumerate() {
                visit(item, source_name, &format!("{path}[{index}]"), found);
            }
            return;
        }
        let Some(record) = value.as_object() else {
            return;
        };
        if is_likely_sub2api_document(record) {
            let exported_at = normalize_timestamp(record.get("exported_at"));
            let document_fields = record
                .iter()
                .filter(|(key, _)| key.as_str() != "accounts")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<JsonMap>();
            if let Some(accounts) = record.get("accounts").and_then(Value::as_array) {
                for (index, account) in accounts.iter().enumerate() {
                    let source_path = format!("{path}.accounts[{index}]");
                    if let Some(account) = account.as_object() {
                        found.push(CredentialCandidate {
                            value: build_sub2api_normalization_record(
                                account,
                                exported_at.as_deref(),
                            ),
                            source_name: source_name.to_owned(),
                            source_path,
                            source_type: SourceType::Sub2Api,
                            exported_at: exported_at.clone(),
                            sub2api_settings: Some(build_sub2api_settings(
                                account,
                                Some(document_fields.clone()),
                                false,
                                None,
                            )),
                        });
                    } else {
                        found.push(CredentialCandidate {
                            value: Map::from_iter([("raw_value".to_owned(), account.clone())]),
                            source_name: source_name.to_owned(),
                            source_path,
                            source_type: SourceType::Sub2Api,
                            exported_at: exported_at.clone(),
                            sub2api_settings: None,
                        });
                    }
                }
            }
            return;
        }
        if is_likely_sub2api_account(record) {
            found.push(CredentialCandidate {
                value: build_sub2api_normalization_record(record, None),
                source_name: source_name.to_owned(),
                source_path: path.to_owned(),
                source_type: SourceType::Sub2Api,
                exported_at: None,
                sub2api_settings: Some(build_sub2api_settings(record, None, false, None)),
            });
            return;
        }
        if is_likely_cpa(record) {
            found.push(CredentialCandidate {
                value: record.clone(),
                source_name: source_name.to_owned(),
                source_path: path.to_owned(),
                source_type: SourceType::Cpa,
                exported_at: None,
                sub2api_settings: read_bridge_settings(record),
            });
            return;
        }
        if let Some(token) = read_first_string(record, ACCESS_TOKEN_PATHS) {
            if is_likely_session(record, &token) {
                found.push(CredentialCandidate {
                    value: record.clone(),
                    source_name: source_name.to_owned(),
                    source_path: path.to_owned(),
                    source_type: SourceType::ChatGptWebSession,
                    exported_at: None,
                    sub2api_settings: None,
                });
                return;
            }
        }
        for (key, child) in record {
            if matches!(
                key.as_str(),
                "accessToken" | "access_token" | "sessionToken" | "session_token"
            ) {
                continue;
            }
            visit(child, source_name, &format!("{path}.{key}"), found);
        }
    }

    let mut found = Vec::new();
    visit(value, source_name, "$", &mut found);
    found
}

fn parse_json_documents(text: &str) -> (Vec<Value>, Vec<ParseIssue>) {
    let mut documents = Vec::new();
    let mut issues = Vec::new();
    let mut stack = Vec::new();
    let mut start = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut document_index = 0;

    for (index, character) in text.char_indices() {
        if start.is_none() {
            if character.is_whitespace() {
                continue;
            }
            if !matches!(character, '{' | '[') {
                issues.push(ParseIssue::new(
                    format!("粘贴内容 #{}", document_index + 1),
                    "发现非 JSON 内容；文档必须以 { 或 [ 开始",
                ));
                break;
            }
            start = Some(index);
            stack.push(if character == '{' { '}' } else { ']' });
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
        } else if matches!(character, '{' | '[') {
            stack.push(if character == '{' { '}' } else { ']' });
        } else if matches!(character, '}' | ']') {
            if stack.last().copied() != Some(character) {
                issues.push(ParseIssue::new(
                    format!("粘贴内容 #{}", document_index + 1),
                    "JSON 括号不匹配",
                ));
                document_index += 1;
                start = None;
                stack.clear();
                continue;
            }
            stack.pop();
            if stack.is_empty() {
                let begin = start.take().unwrap_or_default();
                let end = index + character.len_utf8();
                match serde_json::from_str(&text[begin..end]) {
                    Ok(value) => documents.push(value),
                    Err(_) => issues.push(ParseIssue::new(
                        format!("粘贴内容 #{}", document_index + 1),
                        "JSON 解析失败",
                    )),
                }
                document_index += 1;
            }
        }
    }
    if start.is_some() {
        issues.push(ParseIssue::new(
            format!("粘贴内容 #{}", document_index + 1),
            "JSON 不完整：缺少顶层闭合括号",
        ));
    }
    if documents.is_empty() && issues.is_empty() && !text.trim().is_empty() {
        issues.push(ParseIssue::new("粘贴内容 #1", "没有找到可解析的 JSON 文档"));
    }
    (documents, issues)
}

fn derive_organization_id(sources: &[&JsonMap]) -> Option<String> {
    for source in sources {
        let Some(organizations) = source.get("organizations").and_then(Value::as_array) else {
            continue;
        };
        let selected = organizations
            .iter()
            .filter_map(Value::as_object)
            .find(|organization| {
                organization.get("is_default").and_then(Value::as_bool) == Some(true)
                    && organization.contains_key("id")
            })
            .or_else(|| {
                organizations
                    .iter()
                    .filter_map(Value::as_object)
                    .find(|organization| organization.contains_key("id"))
            });
        if let Some(id) = selected
            .and_then(|value| value.get("id"))
            .and_then(non_empty)
        {
            return Some(id);
        }
    }
    None
}

struct NormalizeOptions<'a> {
    source_name: &'a str,
    source_path: &'a str,
    source_type: SourceType,
    last_refresh_fallback: Option<&'a str>,
    preserved_cpa_fields: Option<JsonMap>,
    sub2api_settings: Option<Sub2ApiSettings>,
    now_ms: f64,
}

fn normalize_record(
    record: &JsonMap,
    options: NormalizeOptions<'_>,
) -> Result<NormalizedAccount, String> {
    let NormalizeOptions {
        source_name,
        source_path,
        source_type,
        last_refresh_fallback,
        preserved_cpa_fields,
        sub2api_settings,
        now_ms,
    } = options;
    let uses_settings = matches!(
        source_type,
        SourceType::Sub2Api
            | SourceType::ManualAt
            | SourceType::ManualRt
            | SourceType::ManualMobileRt
    );
    if uses_settings
        && sub2api_settings
            .as_ref()
            .and_then(|settings| settings.platform.as_deref())
            .is_some_and(|platform| !platform.eq_ignore_ascii_case("openai"))
    {
        return Err("仅支持转换 Sub2API 中 platform=openai 的账号".to_owned());
    }
    if uses_settings
        && sub2api_settings
            .as_ref()
            .and_then(|settings| settings.account_type.as_deref())
            .is_some_and(|kind| !kind.eq_ignore_ascii_case("oauth"))
    {
        return Err("仅支持转换 Sub2API 中 type=oauth 的账号".to_owned());
    }

    let access_token = read_first_string(record, ACCESS_TOKEN_PATHS).unwrap_or_default();
    let refresh_token = read_first_string(record, REFRESH_TOKEN_PATHS);
    let supports_refresh_only = matches!(
        source_type,
        SourceType::Sub2Api | SourceType::Cpa | SourceType::ManualRt | SourceType::ManualMobileRt
    );
    if access_token.is_empty() && !(supports_refresh_only && refresh_token.is_some()) {
        return Err("缺少 access_token / accessToken 或 refresh_token".to_owned());
    }

    let session_token = read_first_string(record, SESSION_TOKEN_PATHS);
    let input_id_token = read_first_string(record, ID_TOKEN_PATHS);
    let access_payload = parse_jwt_payload(Some(&access_token));
    let id_payload = parse_jwt_payload(input_id_token.as_deref());
    let access_auth = claim(access_payload.as_ref(), OPENAI_AUTH_CLAIM);
    let id_auth = claim(id_payload.as_ref(), OPENAI_AUTH_CLAIM);
    let access_profile = claim(access_payload.as_ref(), OPENAI_PROFILE_CLAIM);
    let id_profile = claim(id_payload.as_ref(), OPENAI_PROFILE_CLAIM);

    let declared_expires_at = first_non_empty([
        normalize_timestamp(record.get("expires")),
        normalize_timestamp(record.get("expiresAt")),
        normalize_timestamp(record.get("expires_at")),
        normalize_timestamp(record.get("expired")),
    ]);
    let jwt_expires_at = timestamp_from_unix_seconds(
        access_payload
            .as_ref()
            .and_then(|payload| payload.get("exp")),
    );
    let prefers_jwt = matches!(
        source_type,
        SourceType::ChatGptWebSession | SourceType::ManualAt
    );
    let token_expires_at = if prefers_jwt {
        first_non_empty([jwt_expires_at.clone(), declared_expires_at.clone()])
    } else {
        first_non_empty([declared_expires_at.clone(), jwt_expires_at.clone()])
    };
    let token_value = token_expires_at.clone().map(Value::String);
    let jwt_exp = access_payload
        .as_ref()
        .and_then(|payload| payload.get("exp"));
    let access_token_expires_at = if prefers_jwt {
        jwt_exp
            .and_then(to_i64)
            .filter(|value| *value > 0)
            .or_else(|| unix_seconds(token_value.as_ref()))
    } else {
        unix_seconds(token_value.as_ref()).or_else(|| jwt_exp.and_then(to_i64))
    };

    let email = first_non_empty([
        read_string(record, "user.email"),
        read_string(record, "email"),
        read_string(record, "meta.label"),
        read_string(record, "label"),
        read_string(record, "credentials.email"),
        read_string(record, "providerSpecificData.email"),
        access_profile.get("email").and_then(non_empty),
        id_profile.get("email").and_then(non_empty),
        id_payload
            .as_ref()
            .and_then(|payload| payload.get("email"))
            .and_then(non_empty),
        access_payload
            .as_ref()
            .and_then(|payload| payload.get("email"))
            .and_then(non_empty),
    ]);
    let account_id = first_non_empty([
        read_string(record, "account.id"),
        read_string(record, "account_id"),
        read_string(record, "accountId"),
        read_string(record, "tokens.account_id"),
        read_string(record, "tokens.accountId"),
        read_string(record, "chatgpt_account_id"),
        read_string(record, "chatgptAccountId"),
        read_string(record, "meta.chatgpt_account_id"),
        read_string(record, "meta.chatgptAccountId"),
        read_string(record, "providerSpecificData.chatgpt_account_id"),
        read_string(record, "providerSpecificData.chatgptAccountId"),
        read_string(record, "credentials.chatgpt_account_id"),
        access_auth.get("chatgpt_account_id").and_then(non_empty),
        id_auth.get("chatgpt_account_id").and_then(non_empty),
    ]);
    let user_id = first_non_empty([
        read_string(record, "user.id"),
        read_string(record, "user_id"),
        read_string(record, "chatgpt_user_id"),
        read_string(record, "chatgptUserId"),
        read_string(record, "providerSpecificData.chatgpt_user_id"),
        read_string(record, "providerSpecificData.chatgptUserId"),
        access_auth.get("chatgpt_user_id").and_then(non_empty),
        access_auth.get("user_id").and_then(non_empty),
        id_auth.get("chatgpt_user_id").and_then(non_empty),
        id_auth.get("user_id").and_then(non_empty),
    ]);
    let plan_type = first_non_empty([
        read_string(record, "account.planType"),
        read_string(record, "account.plan_type"),
        read_string(record, "planType"),
        read_string(record, "plan_type"),
        read_string(record, "providerSpecificData.chatgptPlanType"),
        read_string(record, "providerSpecificData.chatgpt_plan_type"),
        read_string(record, "credentials.plan_type"),
        access_auth.get("chatgpt_plan_type").and_then(non_empty),
        id_auth.get("chatgpt_plan_type").and_then(non_empty),
    ]);
    let organization_id = first_non_empty([
        read_string(record, "organization_id"),
        read_string(record, "organizationId"),
        read_string(record, "credentials.organization_id"),
        derive_organization_id(&[&id_auth, &access_auth]),
    ]);
    let source_base = source_name
        .rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.is_empty());
    let name = if prefers_jwt {
        first_non_empty([
            email.clone(),
            read_string(record, "name"),
            read_string(record, "label"),
            source_base.map(ToOwned::to_owned),
            account_id.clone(),
            Some("ChatGPT Account".to_owned()),
        ])
    } else {
        first_non_empty([
            read_string(record, "name"),
            email.clone(),
            read_string(record, "label"),
            source_base.map(ToOwned::to_owned),
            account_id.clone(),
            Some("ChatGPT Account".to_owned()),
        ])
    }
    .unwrap_or_else(|| "ChatGPT Account".to_owned());
    let exported_at = now_iso(now_ms);
    let last_refresh = first_non_empty([
        normalize_timestamp(record.get("last_refresh")),
        normalize_timestamp(record.get("lastRefresh")),
        last_refresh_fallback
            .and_then(|value| normalize_timestamp(Some(&Value::String(value.to_owned())))),
        Some(exported_at.clone()),
    ])
    .unwrap_or(exported_at);
    let synthetic_id_token = input_id_token
        .as_ref()
        .is_none()
        .then(|| {
            build_synthetic_id_token(
                account_id.as_deref(),
                email.as_deref(),
                plan_type.as_deref(),
                user_id.as_deref(),
                token_expires_at.as_deref(),
                now_ms,
            )
        })
        .flatten();
    let input_id_token_synthetic = record
        .get("id_token_synthetic")
        .and_then(bool_value)
        .unwrap_or(false);
    let is_expired = token_expires_at
        .as_deref()
        .map(Date::parse)
        .is_some_and(|expires| expires.is_finite() && expires <= now_ms);
    let personal_access_token = access_token.starts_with("at-");
    let mut warnings = Vec::new();
    if refresh_token.is_none() && !personal_access_token {
        warnings.push("缺少 refresh_token，access token 到期后无法自动刷新。".to_owned());
    }
    if synthetic_id_token.is_some() {
        warnings.push("缺少真实 id_token，CPA 将使用仅供解析的合成 JWT。".to_owned());
    } else if input_id_token_synthetic {
        warnings.push("输入中的 id_token 已标记为合成 JWT，不是真实 OAuth id token。".to_owned());
    }
    if account_id.is_none() {
        warnings.push("未解析到 account_id，目标系统可能无法完整识别账号。".to_owned());
    }
    if email.is_none() {
        warnings.push("未解析到邮箱，已使用来源名称作为账号名。".to_owned());
    }
    if is_expired {
        warnings.push("access token 已过期。".to_owned());
    }
    let id_token = first_non_empty([input_id_token.clone(), synthetic_id_token.clone()]);

    Ok(NormalizedAccount {
        source_name: source_name.to_owned(),
        source_path: source_path.to_owned(),
        source_type,
        name,
        email,
        account_id,
        user_id,
        plan_type,
        organization_id,
        auth_provider: first_non_empty([
            read_string(record, "authProvider"),
            read_string(record, "auth_provider"),
            Some("openai".to_owned()),
        ])
        .unwrap_or_else(|| "openai".to_owned()),
        access_token,
        session_token,
        refresh_token: refresh_token.clone(),
        input_id_token,
        id_token,
        id_token_synthetic: input_id_token_synthetic || synthetic_id_token.is_some(),
        token_expires_at: token_expires_at.clone(),
        access_token_expires_at,
        export_expires_at: if source_type == SourceType::ChatGptWebSession
            && refresh_token.is_some()
        {
            None
        } else {
            token_expires_at
        },
        last_refresh,
        disabled: record.get("disabled").and_then(bool_value).unwrap_or(false),
        is_refreshable: refresh_token.is_some(),
        is_expired,
        warnings,
        preserved_cpa_fields,
        sub2api_settings,
    })
}

pub fn credential_keys(account: &NormalizedAccount) -> Vec<String> {
    let mut keys = Vec::new();
    if !account.access_token.is_empty() {
        keys.push(format!("at:{}", account.access_token));
    }
    if let Some(refresh_token) = &account.refresh_token {
        keys.push(format!("rt:{refresh_token}"));
    }
    if keys.is_empty() {
        keys.push(format!(
            "source:{}:{}",
            account.source_name, account.source_path
        ));
    }
    keys
}

pub fn parse_credential_text(text: &str, source_name: &str, now_ms: f64) -> ParseResult {
    let (documents, mut issues) = parse_json_documents(text);
    let mut accounts = Vec::new();
    let mut seen = HashSet::new();
    for (document_index, document) in documents.iter().enumerate() {
        let label = if documents.len() > 1 {
            format!("{source_name} · #{}", document_index + 1)
        } else {
            source_name.to_owned()
        };
        let candidates = collect_candidates(document, &label);
        if candidates.is_empty() {
            issues.push(ParseIssue::new(
                label,
                "未找到可识别的 Session、CPA 或 Sub2API 账号",
            ));
            continue;
        }
        for candidate in candidates {
            let preserved = if candidate.source_type == SourceType::Cpa {
                let mut fields = without_credential_fields(&candidate.value);
                if candidate
                    .sub2api_settings
                    .as_ref()
                    .is_some_and(|settings| settings.restored_from_bridge)
                {
                    fields.remove(SESSION_BRIDGE_KEY);
                }
                Some(fields)
            } else if candidate.source_type == SourceType::Sub2Api {
                Some(without_credential_fields(
                    &candidate
                        .sub2api_settings
                        .as_ref()
                        .map(|settings| &settings.extra)
                        .cloned()
                        .unwrap_or_default(),
                ))
            } else {
                None
            };
            match normalize_record(
                &candidate.value,
                NormalizeOptions {
                    source_name: &candidate.source_name,
                    source_path: &candidate.source_path,
                    source_type: candidate.source_type,
                    last_refresh_fallback: candidate.exported_at.as_deref(),
                    preserved_cpa_fields: preserved,
                    sub2api_settings: candidate.sub2api_settings,
                    now_ms,
                },
            ) {
                Ok(account) => {
                    let keys = credential_keys(&account);
                    if keys.iter().any(|key| seen.contains(key)) {
                        issues.push(
                            ParseIssue::new(&candidate.source_name, "检测到重复凭证，已忽略")
                                .at_path(&candidate.source_path),
                        );
                    } else {
                        seen.extend(keys);
                        accounts.push(account);
                    }
                }
                Err(reason) => issues.push(
                    ParseIssue::new(&candidate.source_name, reason).at_path(&candidate.source_path),
                ),
            }
        }
    }
    ParseResult { accounts, issues }
}

fn detect_non_token_document(text: &str) -> Option<&'static str> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("<!doctype html")
        || lower.starts_with("<html")
        || lower.trim_end().ends_with("</html>")
    {
        return Some("检测到 HTML 页面，请粘贴 token 本身，不要粘贴报错页面");
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Some("检测到 JSON 内容，请切换到 JSON 输入");
    }
    None
}

fn manual_token_error(token: &str, mode: InputMode) -> Option<&'static str> {
    let max_length = match mode {
        InputMode::At => MAX_ACCESS_TOKEN_LENGTH,
        InputMode::Rt | InputMode::MobileRt => MAX_REFRESH_TOKEN_LENGTH,
        InputMode::Json => return Some("请选择 RT、Mobile RT 或 AT 输入"),
    };
    if mode == InputMode::At && !token.starts_with("at-") {
        return Some("AT 仅支持 at- 开头的 Personal Access Token");
    }
    if token.len() > max_length {
        return Some(match mode {
            InputMode::At => "AT 长度超过限制",
            InputMode::MobileRt => "Mobile RT 长度超过限制",
            InputMode::Rt => "RT 长度超过限制",
            InputMode::Json => "Token 长度超过限制",
        });
    }
    if !token
        .chars()
        .all(|character| !character.is_whitespace() && !character.is_control())
    {
        return Some(match mode {
            InputMode::At => "AT 含有空白或控制字符；每行只能填写一个完整 token",
            InputMode::MobileRt => "Mobile RT 含有空白或控制字符；每行只能填写一个完整 token",
            InputMode::Rt => "RT 含有空白或控制字符；每行只能填写一个完整 token",
            InputMode::Json => "Token 含有空白或控制字符",
        });
    }
    if matches!(mode, InputMode::Rt | InputMode::MobileRt) && token.starts_with("at-") {
        return Some("检测到 AT，请切换到 AT 输入");
    }
    None
}

fn manual_settings(
    credentials: JsonMap,
    extra: JsonMap,
    concurrency: f64,
    priority: f64,
    auto_pause: Option<bool>,
) -> Sub2ApiSettings {
    Sub2ApiSettings {
        platform: Some("openai".to_owned()),
        account_type: Some("oauth".to_owned()),
        concurrency: Some(concurrency),
        priority: Some(priority),
        rate_multiplier: Some(1.0),
        auto_pause_on_expired: auto_pause,
        disabled: Some(false),
        original_credential_keys: credentials.keys().cloned().collect(),
        credentials,
        extra,
        ..Sub2ApiSettings::default()
    }
}

fn normalize_manual_token(
    token: &str,
    mode: InputMode,
    index: usize,
    source_name: &str,
    now_ms: f64,
) -> Result<NormalizedAccount, String> {
    let source_path = format!("$[{index}]");
    match mode {
        InputMode::At => {
            let mut record = JsonMap::new();
            record.insert("access_token".to_owned(), json!(token));
            record.insert("name".to_owned(), json!(format!("OpenAI AT {}", index + 1)));
            record.insert(
                "auth_provider".to_owned(),
                json!("codex_personal_access_token"),
            );
            let mut account = normalize_record(
                &record,
                NormalizeOptions {
                    source_name,
                    source_path: &source_path,
                    source_type: SourceType::ManualAt,
                    last_refresh_fallback: None,
                    preserved_cpa_fields: None,
                    sub2api_settings: None,
                    now_ms,
                },
            )?;
            let credentials = Map::from_iter([
                ("access_token".to_owned(), json!(token)),
                ("auth_mode".to_owned(), json!(OPENAI_PAT_AUTH_MODE)),
                (
                    "openai_auth_mode".to_owned(),
                    json!(OPENAI_PAT_LEGACY_AUTH_MODE),
                ),
                ("token_type".to_owned(), json!("Bearer")),
            ]);
            let extra = Map::from_iter([
                (
                    "import_source".to_owned(),
                    json!("codex_personal_access_token"),
                ),
                (
                    "auth_provider".to_owned(),
                    json!("codex_personal_access_token"),
                ),
                ("imported_at".to_owned(), json!(now_iso(now_ms))),
                ("access_token_sha256".to_owned(), json!(sha256_hex(token))),
            ]);
            let mut settings = manual_settings(credentials, extra, 3.0, 50.0, Some(false));
            settings.name = Some(
                account
                    .email
                    .clone()
                    .unwrap_or_else(|| account.name.clone()),
            );
            account.sub2api_settings = Some(settings);
            Ok(account)
        }
        InputMode::Rt | InputMode::MobileRt => {
            let mobile = mode == InputMode::MobileRt;
            let source_type = if mobile {
                SourceType::ManualMobileRt
            } else {
                SourceType::ManualRt
            };
            let token_label = if mobile { "Mobile RT" } else { "RT" };
            let import_source = if mobile {
                "manual_mobile_refresh_token"
            } else {
                "manual_refresh_token"
            };
            let credentials = Map::from_iter([("refresh_token".to_owned(), json!(token))]);
            let extra = Map::from_iter([
                ("auth_provider".to_owned(), json!("openai")),
                ("source".to_owned(), json!(import_source)),
            ]);
            let mut settings = manual_settings(credentials, extra, 10.0, 1.0, None);
            let record = Map::from_iter([
                ("refresh_token".to_owned(), json!(token)),
                (
                    "name".to_owned(),
                    json!(format!("OpenAI {token_label} {}", index + 1)),
                ),
                ("auth_provider".to_owned(), json!("openai")),
            ]);
            let mut account = normalize_record(
                &record,
                NormalizeOptions {
                    source_name,
                    source_path: &source_path,
                    source_type,
                    last_refresh_fallback: None,
                    preserved_cpa_fields: None,
                    sub2api_settings: Some(settings.clone()),
                    now_ms,
                },
            )?;
            settings.name = Some(account.name.clone());
            account.sub2api_settings = Some(settings);
            account.warnings.clear();
            Ok(account)
        }
        InputMode::Json => Err("请选择 RT、Mobile RT 或 AT 输入".to_owned()),
    }
}

pub fn parse_manual_tokens(
    text: &str,
    mode: InputMode,
    source_name: &str,
    now_ms: f64,
) -> ParseResult {
    if let Some(reason) = detect_non_token_document(text) {
        return ParseResult {
            accounts: Vec::new(),
            issues: vec![ParseIssue::new(source_name, reason)],
        };
    }
    let tokens = text
        .lines()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let mut accounts = Vec::new();
    let mut issues = Vec::new();
    let mut seen = HashSet::new();
    if tokens.len() > 500 {
        issues.push(ParseIssue::new(
            source_name,
            "一次最多处理 500 个 token，其余内容已跳过",
        ));
    }
    for (index, token) in tokens.into_iter().take(500).enumerate() {
        if let Some(reason) = manual_token_error(token, mode) {
            issues.push(ParseIssue::new(source_name, reason).at_path(format!("$[{index}]")));
            continue;
        }
        let token_kind = match mode {
            InputMode::At => "at",
            InputMode::Rt => "rt",
            InputMode::MobileRt => "mobile_rt",
            InputMode::Json => "json",
        };
        let key = format!("{token_kind}:{token}");
        if !seen.insert(key) {
            issues.push(
                ParseIssue::new(source_name, "检测到重复凭证，已忽略")
                    .at_path(format!("$[{index}]")),
            );
            continue;
        }
        match normalize_manual_token(token, mode, index, source_name, now_ms) {
            Ok(account) => accounts.push(account),
            Err(reason) => {
                issues.push(ParseIssue::new(source_name, reason).at_path(format!("$[{index}]")))
            }
        }
    }
    ParseResult { accounts, issues }
}

pub fn normalize_validated_at(
    token: &str,
    info: &PersonalAccessTokenInfo,
    index: usize,
    now_ms: f64,
) -> Result<NormalizedAccount, String> {
    if !token.starts_with("at-") {
        return Err("AT 仅支持 at- 开头的 Personal Access Token".to_owned());
    }
    let credentials = Map::from_iter([
        ("access_token".to_owned(), json!(token)),
        ("auth_mode".to_owned(), json!(OPENAI_PAT_AUTH_MODE)),
        (
            "openai_auth_mode".to_owned(),
            json!(OPENAI_PAT_LEGACY_AUTH_MODE),
        ),
        ("token_type".to_owned(), json!("Bearer")),
        ("email".to_owned(), json!(info.email)),
        ("chatgpt_account_id".to_owned(), json!(info.account_id)),
        ("chatgpt_user_id".to_owned(), json!(info.user_id)),
        ("plan_type".to_owned(), json!(info.plan_type)),
        (
            "chatgpt_account_is_fedramp".to_owned(),
            json!(info.is_fedramp),
        ),
    ]);
    let extra = Map::from_iter([
        (
            "import_source".to_owned(),
            json!("codex_personal_access_token"),
        ),
        (
            "auth_provider".to_owned(),
            json!("codex_personal_access_token"),
        ),
        ("imported_at".to_owned(), json!(now_iso(now_ms))),
        ("access_token_sha256".to_owned(), json!(sha256_hex(token))),
        ("email".to_owned(), json!(info.email)),
    ]);
    let settings = manual_settings(credentials.clone(), extra, 3.0, 50.0, Some(false));
    let mut record = credentials;
    record.insert("name".to_owned(), json!(info.email));
    record.insert(
        "auth_provider".to_owned(),
        json!("codex_personal_access_token"),
    );
    record.insert("last_refresh".to_owned(), json!(now_iso(now_ms)));
    let source_path = format!("$[{index}]");
    let mut account = normalize_record(
        &record,
        NormalizeOptions {
            source_name: "手动 AT",
            source_path: &source_path,
            source_type: SourceType::ManualAt,
            last_refresh_fallback: None,
            preserved_cpa_fields: None,
            sub2api_settings: Some(settings),
            now_ms,
        },
    )?;
    if let Some(settings) = &mut account.sub2api_settings {
        settings.name = Some(
            account
                .email
                .clone()
                .unwrap_or_else(|| account.name.clone()),
        );
    }
    Ok(account)
}

pub fn normalize_refreshed_rt(
    original_refresh_token: &str,
    info: &OAuthTokenInfo,
    mode: InputMode,
    index: usize,
    now_ms: f64,
) -> Result<NormalizedAccount, String> {
    let mobile = mode == InputMode::MobileRt;
    let source_name = if mobile {
        "手动 Mobile RT"
    } else {
        "手动 RT"
    };
    let source_type = if mobile {
        SourceType::ManualMobileRt
    } else {
        SourceType::ManualRt
    };
    let import_source = if mobile {
        "manual_mobile_refresh_token"
    } else {
        "manual_refresh_token"
    };
    let token_label = if mobile { "Mobile RT" } else { "RT" };
    let access_token = info
        .fields
        .get("access_token")
        .and_then(non_empty)
        .ok_or_else(|| "OpenAI 返回结果中缺少 access_token".to_owned())?;
    let refresh_token = first_non_empty([
        info.fields.get("refresh_token").and_then(non_empty),
        Some(original_refresh_token.to_owned()),
    ])
    .unwrap_or_else(|| original_refresh_token.to_owned());
    let expires_at = unix_seconds(info.fields.get("expires_at")).or_else(|| {
        info.fields
            .get("expires_in")
            .and_then(number)
            .filter(|value| *value > 0.0)
            .map(|value| (now_ms / 1000.0).floor() as i64 + value.floor() as i64)
    });
    let mut credentials = JsonMap::new();
    credentials.insert("access_token".to_owned(), json!(access_token));
    credentials.insert("refresh_token".to_owned(), json!(refresh_token));
    credentials.insert("client_id".to_owned(), json!(info.client_id));
    let optional = [
        ("id_token", "id_token"),
        ("email", "email"),
        ("chatgpt_account_id", "chatgpt_account_id"),
        ("chatgpt_user_id", "chatgpt_user_id"),
        ("organization_id", "organization_id"),
        ("plan_type", "plan_type"),
        ("subscription_expires_at", "subscription_expires_at"),
    ];
    for (target, source) in optional {
        if let Some(value) = info.fields.get(source).and_then(non_empty) {
            credentials.insert(target.to_owned(), Value::String(value));
        }
    }
    if let Some(expires_at) = expires_at {
        credentials.insert("expires_at".to_owned(), json!(expires_at));
    }
    let mut extra = Map::from_iter([
        ("auth_provider".to_owned(), json!("openai")),
        ("source".to_owned(), json!(import_source)),
    ]);
    for key in ["email", "name", "privacy_mode"] {
        if let Some(value) = info.fields.get(key).and_then(non_empty) {
            extra.insert(key.to_owned(), Value::String(value));
        }
    }
    let settings = manual_settings(credentials.clone(), extra, 10.0, 1.0, None);
    let mut record = credentials;
    record.insert(
        "name".to_owned(),
        json!(
            first_non_empty([
                info.fields.get("name").and_then(non_empty),
                info.fields.get("email").and_then(non_empty),
                Some(format!("OpenAI {token_label} {}", index + 1)),
            ])
            .unwrap_or_else(|| format!("OpenAI {token_label} {}", index + 1))
        ),
    );
    record.insert("auth_provider".to_owned(), json!("openai"));
    record.insert("last_refresh".to_owned(), json!(now_iso(now_ms)));
    let source_path = format!("$[{index}]");
    let mut account = normalize_record(
        &record,
        NormalizeOptions {
            source_name,
            source_path: &source_path,
            source_type,
            last_refresh_fallback: None,
            preserved_cpa_fields: None,
            sub2api_settings: Some(settings),
            now_ms,
        },
    )?;
    if let Some(settings) = &mut account.sub2api_settings {
        settings.name = Some(
            account
                .email
                .clone()
                .unwrap_or_else(|| account.name.clone()),
        );
    }
    Ok(account)
}

fn insert_optional(map: &mut JsonMap, key: &str, value: Option<Value>) {
    if let Some(value) = value.filter(|value| !value.is_null()) {
        map.insert(key.to_owned(), value);
    } else {
        map.remove(key);
    }
}

fn bridge_metadata(settings: &Sub2ApiSettings) -> Value {
    json!({
        "schema": SESSION_BRIDGE_SCHEMA,
        "source": "sub2api",
        "sub2api": {
            "document": settings.document_fields.clone().unwrap_or_default(),
            "account": settings.account_fields,
            "credentials": without_credential_fields(&settings.credentials),
            "credential_keys": settings.original_credential_keys,
            "extra": settings.extra,
        },
    })
}

pub fn to_cpa_record(account: &NormalizedAccount, now_ms: f64) -> Value {
    let mut output = account.preserved_cpa_fields.clone().unwrap_or_default();
    let preserved = output.clone();
    let account_id = first_non_empty([
        account.account_id.clone(),
        preserved.get("account_id").and_then(non_empty),
        preserved.get("chatgpt_account_id").and_then(non_empty),
    ]);
    let plan_type = first_non_empty([
        account.plan_type.clone(),
        preserved.get("plan_type").and_then(non_empty),
        preserved.get("chatgpt_plan_type").and_then(non_empty),
    ]);
    let generated_name = matches!(
        account.source_type,
        SourceType::Sub2Api
            | SourceType::ManualAt
            | SourceType::ManualRt
            | SourceType::ManualMobileRt
    )
    .then(|| {
        account.email.as_ref().map(|email| {
            format!(
                "{email}_{}",
                account
                    .account_id
                    .as_deref()
                    .unwrap_or("unknown")
                    .chars()
                    .take(8)
                    .collect::<String>()
            )
        })
    })
    .flatten();
    let expired = if account.access_token.is_empty() && account.refresh_token.is_some() {
        date_to_iso(now_ms - 60_000.0)
    } else {
        account
            .export_expires_at
            .clone()
            .or_else(|| normalize_timestamp(preserved.get("expired")))
    };

    output.insert("type".to_owned(), json!("codex"));
    insert_optional(
        &mut output,
        "account_id",
        account_id.clone().map(Value::String),
    );
    insert_optional(
        &mut output,
        "chatgpt_account_id",
        account_id.map(Value::String),
    );
    insert_optional(
        &mut output,
        "email",
        first_non_empty([
            account.email.clone(),
            preserved.get("email").and_then(non_empty),
        ])
        .map(Value::String),
    );
    insert_optional(
        &mut output,
        "name",
        first_non_empty([
            preserved.get("name").and_then(non_empty),
            generated_name,
            Some(account.name.clone()),
        ])
        .map(Value::String),
    );
    insert_optional(
        &mut output,
        "plan_type",
        plan_type.clone().map(Value::String),
    );
    insert_optional(
        &mut output,
        "chatgpt_plan_type",
        plan_type.clone().map(Value::String),
    );
    output.insert(
        "id_token".to_owned(),
        json!(
            first_non_empty([
                account.id_token.clone(),
                preserved.get("id_token").and_then(non_empty),
            ])
            .unwrap_or_default()
        ),
    );
    output.insert(
        "id_token_synthetic".to_owned(),
        Value::Bool(
            account.id_token_synthetic
                || preserved
                    .get("id_token_synthetic")
                    .and_then(bool_value)
                    .unwrap_or(false),
        ),
    );
    output.insert("access_token".to_owned(), json!(account.access_token));
    output.insert(
        "refresh_token".to_owned(),
        json!(
            first_non_empty([
                account.refresh_token.clone(),
                preserved.get("refresh_token").and_then(non_empty),
            ])
            .unwrap_or_default()
        ),
    );
    output.insert(
        "session_token".to_owned(),
        json!(
            first_non_empty([
                account.session_token.clone(),
                preserved.get("session_token").and_then(non_empty),
            ])
            .unwrap_or_default()
        ),
    );
    output.insert("last_refresh".to_owned(), json!(account.last_refresh));
    insert_optional(&mut output, "expired", expired.map(Value::String));
    if account.disabled
        || preserved
            .get("disabled")
            .and_then(bool_value)
            .unwrap_or(false)
    {
        output.insert("disabled".to_owned(), Value::Bool(true));
    } else {
        output.remove("disabled");
    }
    let source = first_non_empty([
        preserved.get("source").and_then(non_empty),
        plan_type.map(|plan| format!("gpt-{plan}-all-ws")),
    ]);
    insert_optional(&mut output, "source", source.map(Value::String));
    if let Some(settings) = &account.sub2api_settings {
        output.insert(SESSION_BRIDGE_KEY.to_owned(), bridge_metadata(settings));
    } else {
        output.remove(SESSION_BRIDGE_KEY);
    }
    Value::Object(output)
}

fn to_email_key(email: Option<&str>) -> Option<String> {
    let mut output = String::new();
    let mut previous_separator = false;
    for character in email?.trim().to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character);
            previous_separator = false;
        } else if !previous_separator && !output.is_empty() {
            output.push('_');
            previous_separator = true;
        }
    }
    while output.ends_with('_') {
        output.pop();
    }
    (!output.is_empty()).then_some(output)
}

fn get_expires_in(expires_at: Option<&str>, now_ms: f64) -> Option<i64> {
    let expires = Date::parse(expires_at?);
    (expires.is_finite() && now_ms.is_finite())
        .then(|| ((expires - now_ms) / 1000.0).floor().max(0.0) as i64)
}

pub fn to_sub2api_account(account: &NormalizedAccount, now_ms: f64) -> Value {
    let settings = account.sub2api_settings.as_ref();
    let mut credentials = settings
        .map(|settings| settings.credentials.clone())
        .unwrap_or_default();
    let original_keys = settings.map(|settings| {
        settings
            .original_credential_keys
            .iter()
            .collect::<HashSet<_>>()
    });
    let had_credential = |keys: &[&str]| {
        original_keys
            .as_ref()
            .is_none_or(|original| keys.iter().any(|key| original.contains(&key.to_string())))
    };
    let mut extra = settings.map_or_else(
        || {
            if account.source_type == SourceType::Cpa {
                without_credential_fields(&account.preserved_cpa_fields.clone().unwrap_or_default())
            } else {
                JsonMap::new()
            }
        },
        |settings| settings.extra.clone(),
    );
    let pause_expiry = settings
        .and_then(|settings| settings.expires_at)
        .or_else(|| {
            (!account.is_refreshable)
                .then_some(account.access_token_expires_at)
                .flatten()
        });

    credentials.insert("access_token".to_owned(), json!(account.access_token));
    let fields = [
        (
            "chatgpt_account_id",
            &["chatgpt_account_id", "chatgptAccountId"][..],
            account.account_id.clone(),
        ),
        (
            "chatgpt_user_id",
            &["chatgpt_user_id", "chatgptUserId"][..],
            account.user_id.clone(),
        ),
        ("email", &["email"][..], account.email.clone()),
        (
            "organization_id",
            &["organization_id", "organizationId"][..],
            account.organization_id.clone(),
        ),
        (
            "plan_type",
            &["plan_type", "planType"][..],
            account.plan_type.clone(),
        ),
    ];
    for (target, keys, value) in fields {
        if had_credential(keys) {
            let preserved = credentials.get(target).and_then(non_empty);
            insert_optional(
                &mut credentials,
                target,
                value.or(preserved).map(Value::String),
            );
        } else {
            credentials.remove(target);
        }
    }
    if had_credential(&["expires_at", "expiresAt"]) {
        if !account.is_refreshable {
            let preserved = credentials.get("expires_at").cloned();
            insert_optional(
                &mut credentials,
                "expires_at",
                account
                    .token_expires_at
                    .clone()
                    .map(Value::String)
                    .or(preserved),
            );
        }
    } else {
        credentials.remove("expires_at");
    }
    if had_credential(&["expires_in", "expiresIn"]) {
        if !account.is_refreshable {
            insert_optional(
                &mut credentials,
                "expires_in",
                get_expires_in(account.token_expires_at.as_deref(), now_ms)
                    .map(|value| json!(value)),
            );
        }
    } else {
        credentials.remove("expires_in");
    }
    let candidate_id_token = first_non_empty([
        account.input_id_token.clone(),
        credentials.get("id_token").and_then(non_empty),
        credentials.get("idToken").and_then(non_empty),
    ]);
    if had_credential(&["id_token", "idToken"]) || !account.id_token_synthetic {
        insert_optional(
            &mut credentials,
            "id_token",
            candidate_id_token.map(Value::String),
        );
    } else {
        credentials.remove("id_token");
    }
    let preserved_refresh_token = credentials.get("refresh_token").cloned();
    insert_optional(
        &mut credentials,
        "refresh_token",
        account
            .refresh_token
            .clone()
            .map(Value::String)
            .or(preserved_refresh_token),
    );
    let preserved_session_token = credentials.get("session_token").cloned();
    insert_optional(
        &mut credentials,
        "session_token",
        account
            .session_token
            .clone()
            .map(Value::String)
            .or(preserved_session_token),
    );

    if settings.is_none() {
        insert_optional(
            &mut extra,
            "email",
            account.email.clone().map(Value::String),
        );
        insert_optional(
            &mut extra,
            "email_key",
            to_email_key(account.email.as_deref()).map(Value::String),
        );
        insert_optional(&mut extra, "name", Some(json!(account.name)));
        insert_optional(
            &mut extra,
            "auth_provider",
            Some(json!(account.auth_provider)),
        );
        insert_optional(&mut extra, "source", Some(json!(account.source_type.key())));
        insert_optional(
            &mut extra,
            "last_refresh",
            Some(json!(account.last_refresh)),
        );
    }

    let non_negative =
        |value: Option<f64>, fallback: f64| value.filter(|value| *value >= 0.0).unwrap_or(fallback);
    let concurrency = non_negative(settings.and_then(|value| value.concurrency), 10.0);
    let priority = non_negative(settings.and_then(|value| value.priority), 1.0);
    let rate_multiplier = non_negative(settings.and_then(|value| value.rate_multiplier), 1.0);
    let auto_pause = settings
        .and_then(|value| value.auto_pause_on_expired)
        .or_else(|| {
            if account.source_type == SourceType::Cpa || pause_expiry.is_some() {
                Some(true)
            } else {
                None
            }
        });
    let mut output = settings
        .map(|settings| settings.account_fields.clone())
        .unwrap_or_default();
    output.insert(
        "name".to_owned(),
        json!(
            first_non_empty([
                settings.and_then(|value| value.name.clone()),
                Some(account.name.clone()),
                account.email.clone(),
                Some("ChatGPT Account".to_owned()),
            ])
            .unwrap_or_else(|| "ChatGPT Account".to_owned())
        ),
    );
    output.insert("platform".to_owned(), json!("openai"));
    output.insert("type".to_owned(), json!("oauth"));
    insert_optional(
        &mut output,
        "expires_at",
        pause_expiry.map(|value| json!(value)),
    );
    insert_optional(
        &mut output,
        "auto_pause_on_expired",
        auto_pause.map(Value::Bool),
    );
    output.insert("concurrency".to_owned(), json!(concurrency));
    output.insert("priority".to_owned(), json!(priority));
    output.insert("rate_multiplier".to_owned(), json!(rate_multiplier));
    let disabled = settings
        .and_then(|value| value.disabled)
        .unwrap_or(account.disabled);
    if disabled {
        output.insert("disabled".to_owned(), Value::Bool(true));
    } else {
        output.remove("disabled");
    }
    output.insert("credentials".to_owned(), Value::Object(credentials));
    if extra.is_empty() {
        output.remove("extra");
    } else {
        output.insert("extra".to_owned(), Value::Object(extra));
    }
    Value::Object(output)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(record) => {
            let mut keys = record.keys().collect::<Vec<_>>();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(&record[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn distinct_documents(accounts: &[NormalizedAccount]) -> Vec<JsonMap> {
    let mut seen = HashSet::new();
    accounts
        .iter()
        .filter_map(|account| account.sub2api_settings.as_ref()?.document_fields.clone())
        .filter(|document| seen.insert(canonical_json(&Value::Object(document.clone()))))
        .collect()
}

pub fn sub2api_document_conflicts(accounts: &[NormalizedAccount]) -> Vec<String> {
    let documents = distinct_documents(accounts);
    let keys = documents
        .iter()
        .flat_map(|document| document.keys().cloned())
        .filter(|key| !matches!(key.as_str(), "exported_at" | "proxies"))
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter(|key| {
            documents
                .iter()
                .filter_map(|document| document.get(key))
                .map(canonical_json)
                .collect::<HashSet<_>>()
                .len()
                > 1
        })
        .collect()
}

pub fn build_sub2api_document(accounts: &[NormalizedAccount], now_ms: f64) -> Value {
    let documents = distinct_documents(accounts);
    let mut merged = JsonMap::new();
    let keys = documents
        .iter()
        .flat_map(|document| document.keys().cloned())
        .filter(|key| !matches!(key.as_str(), "accounts" | "exported_at" | "proxies"))
        .collect::<BTreeSet<_>>();
    for key in keys {
        let values = documents
            .iter()
            .filter_map(|document| document.get(&key))
            .collect::<Vec<_>>();
        if !values.is_empty()
            && values
                .iter()
                .map(|value| canonical_json(value))
                .collect::<HashSet<_>>()
                .len()
                == 1
        {
            merged.insert(key, values[0].clone());
        }
    }
    let mut seen_proxies = HashSet::new();
    let proxies = documents
        .iter()
        .filter_map(|document| document.get("proxies")?.as_array())
        .flatten()
        .filter(|proxy| seen_proxies.insert(canonical_json(proxy)))
        .cloned()
        .collect::<Vec<_>>();
    let preserved_exported_at = (documents.len() == 1)
        .then(|| documents[0].get("exported_at").and_then(non_empty))
        .flatten();
    merged.insert(
        "exported_at".to_owned(),
        json!(preserved_exported_at.unwrap_or_else(|| now_iso(now_ms))),
    );
    merged.insert("proxies".to_owned(), Value::Array(proxies));
    merged.insert(
        "accounts".to_owned(),
        Value::Array(
            accounts
                .iter()
                .map(|account| to_sub2api_account(account, now_ms))
                .collect(),
        ),
    );
    Value::Object(merged)
}

pub fn build_output_document(
    accounts: &[NormalizedAccount],
    format: OutputFormat,
    now_ms: f64,
) -> Value {
    match format {
        OutputFormat::Sub2Api => build_sub2api_document(accounts, now_ms),
        OutputFormat::Cpa if accounts.len() == 1 => to_cpa_record(&accounts[0], now_ms),
        OutputFormat::Cpa => Value::Array(
            accounts
                .iter()
                .map(|account| to_cpa_record(account, now_ms))
                .collect(),
        ),
    }
}

fn sanitize_file_token(value: &str, fallback: &str) -> String {
    let mut output = String::new();
    for character in value.trim().chars() {
        if matches!(
            character,
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
        ) || character.is_control()
        {
            if !output.ends_with('-') {
                output.push('-');
            }
        } else {
            output.push(character);
        }
    }
    while output.ends_with(['.', ' ']) {
        output.pop();
    }
    if output.is_empty() {
        output.push_str(fallback);
    }
    if output.len() <= MAX_CPA_FILE_TOKEN_BYTES {
        return output;
    }
    let mut boundary = MAX_CPA_FILE_TOKEN_BYTES;
    while !output.is_char_boundary(boundary) {
        boundary -= 1;
    }
    output.truncate(boundary);
    output
}

fn cpa_file_name(account: &NormalizedAccount, index: usize) -> String {
    let fallback = account
        .account_id
        .clone()
        .unwrap_or_else(|| format!("chatgpt-account-{}", index + 1));
    let source = account.email.as_deref().unwrap_or(account.name.as_str());
    let token = sanitize_file_token(source, &fallback);
    let token = token.strip_suffix(".json").unwrap_or(&token);
    format!("{token}.json")
}

fn timestamp_token(now_ms: f64) -> String {
    let date = Date::new(&now_ms.into());
    format!(
        "{:04}-{:02}-{:02}_{:02}-{:02}-{:02}",
        date.get_full_year(),
        date.get_month() + 1,
        date.get_date(),
        date.get_hours(),
        date.get_minutes(),
        date.get_seconds()
    )
}

pub fn download_descriptor(
    accounts: &[NormalizedAccount],
    format: OutputFormat,
    now_ms: f64,
) -> Result<DownloadDescriptor, String> {
    if accounts.is_empty() {
        return Err("没有可导出的账号".to_owned());
    }
    if format == OutputFormat::Cpa && accounts.len() > 1 {
        let entries = accounts
            .iter()
            .enumerate()
            .map(|(index, account)| ArchiveEntry {
                file_name: cpa_file_name(account, index),
                text: format!(
                    "{}\n",
                    serde_json::to_string_pretty(&to_cpa_record(account, now_ms))
                        .unwrap_or_default()
                ),
            })
            .collect();
        return Ok(DownloadDescriptor::Zip {
            file_name: format!("cpa-{}.zip", timestamp_token(now_ms)),
            entries,
        });
    }
    if format == OutputFormat::Cpa {
        return Ok(DownloadDescriptor::Json {
            file_name: cpa_file_name(&accounts[0], 0),
            document: to_cpa_record(&accounts[0], now_ms),
        });
    }
    Ok(DownloadDescriptor::Json {
        file_name: format!("sub2api-{}.json", timestamp_token(now_ms)),
        document: build_sub2api_document(accounts, now_ms),
    })
}

fn normalized_sensitive_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn sensitive_key(key: &str) -> bool {
    let normalized = normalized_sensitive_key(key);
    [
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
    ]
    .contains(&normalized.as_str())
        || [
            "token",
            "password",
            "passwd",
            "secret",
            "apikey",
            "privatekey",
        ]
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
}

pub fn redact(value: &Value, current_key: Option<&str>) -> Value {
    if current_key.is_some_and(sensitive_key) {
        return match value {
            Value::String(text) if text.is_empty() => json!("[empty]"),
            Value::String(text) => json!(format!("[hidden · {} chars]", text.chars().count())),
            Value::Null => Value::Null,
            _ => json!("[hidden]"),
        };
    }
    match value {
        Value::Array(values) => {
            Value::Array(values.iter().map(|value| redact(value, None)).collect())
        }
        Value::Object(record) => Value::Object(
            record
                .iter()
                .map(|(key, value)| (key.clone(), redact(value, Some(key))))
                .collect(),
        ),
        _ => value.clone(),
    }
}
