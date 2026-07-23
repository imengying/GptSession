use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use reqwest::{
    Client, Method, StatusCode, Url,
    header::{self, HeaderMap},
};
use serde_json::{Map, Value, json};

const GROK_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
const GROK_ACCOUNTS_URL: &str = "https://accounts.x.ai/";
const GROK_DEVICE_URL: &str = "https://auth.x.ai/oauth2/device/code";
const GROK_VERIFY_URL: &str = "https://auth.x.ai/oauth2/device/verify";
const GROK_APPROVE_URL: &str = "https://auth.x.ai/oauth2/device/approve";
const GROK_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const GROK_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";
const GROK_SSO_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write";
const GROK_BASE_URL: &str = "https://cli-chat-proxy.grok.com/v1";
const GROK_OAUTH_USER_AGENT: &str = "sub2api-grok-oauth/1.0";
const GROK_SSO_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const GROK_DEFAULT_TOKEN_TTL_SECONDS: i64 = 6 * 60 * 60;
const GROK_SSO_TIMEOUT: Duration = Duration::from_secs(90);
const GROK_TOKEN_POLL_TIMEOUT: Duration = Duration::from_secs(75);
const GROK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GROK_MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const GROK_MAX_REDIRECTS: usize = 8;

#[derive(Clone)]
pub(super) struct ReqwestGrokGateway {
    client: Client,
}

impl ReqwestGrokGateway {
    pub(super) fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .connect_timeout(GROK_CONNECT_TIMEOUT)
            .timeout(GROK_SSO_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()?;
        Ok(Self { client })
    }

    async fn send(
        &self,
        method: Method,
        url: &Url,
        form: Option<&[(String, String)]>,
        cookies: &BTreeMap<String, String>,
        user_agent: &'static str,
    ) -> Result<RawResponse, GrokError> {
        let mut request = self
            .client
            .request(method, url.clone())
            .header(
                header::ACCEPT,
                "application/json, text/html;q=0.9, */*;q=0.8",
            )
            .header(header::ACCEPT_LANGUAGE, "zh-CN,zh;q=0.9,en;q=0.8")
            .header(header::USER_AGENT, user_agent);
        if !cookies.is_empty() {
            let cookie = cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header(header::COOKIE, cookie);
        }
        if let Some(form) = form {
            request = request.form(form);
        }
        let response = request.send().await.map_err(GrokError::from_reqwest)?;
        read_response(response).await
    }

    async fn follow_xai_flow(
        &self,
        method: Method,
        endpoint: &str,
        form: Option<Vec<(String, String)>>,
        cookies: &mut BTreeMap<String, String>,
    ) -> Result<FlowResponse, GrokError> {
        let mut url = trusted_xai_url(endpoint)?;
        let mut method = method;
        let mut form = form;

        for redirect_count in 0..=GROK_MAX_REDIRECTS {
            let response = self
                .send(
                    method.clone(),
                    &url,
                    form.as_deref(),
                    cookies,
                    GROK_SSO_USER_AGENT,
                )
                .await?;
            capture_cookies(cookies, &response.headers);
            if !response.status.is_redirection() {
                return Ok(FlowResponse {
                    status: response.status,
                    final_url: url,
                    body: response.body,
                });
            }
            if redirect_count == GROK_MAX_REDIRECTS {
                return Err(GrokError::bad_gateway(
                    "GROK_SSO_REDIRECT_LIMIT",
                    "xAI SSO 重定向次数超过限制",
                ));
            }
            let location = response
                .headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    GrokError::bad_gateway(
                        "GROK_SSO_REDIRECT_INVALID",
                        "xAI SSO 重定向缺少目标地址",
                    )
                })?;
            let next = url.join(location).map_err(|_| {
                GrokError::bad_gateway("GROK_SSO_REDIRECT_INVALID", "xAI SSO 返回了无效重定向地址")
            })?;
            url = trusted_xai_url(next.as_str())?;
            if response.status == StatusCode::SEE_OTHER
                || (matches!(
                    response.status,
                    StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND
                ) && method != Method::GET
                    && method != Method::HEAD)
            {
                method = Method::GET;
                form = None;
            }
        }
        unreachable!("redirect loop always returns")
    }

    pub(super) async fn sso(&self, sso_token: &str) -> Result<Map<String, Value>, GrokError> {
        let mut cookies = BTreeMap::from([
            ("sso".to_owned(), sso_token.to_owned()),
            ("sso-rw".to_owned(), sso_token.to_owned()),
        ]);
        let account = self
            .follow_xai_flow(Method::GET, GROK_ACCOUNTS_URL, None, &mut cookies)
            .await?;
        let final_url = account.final_url.as_str();
        if account.status == StatusCode::UNAUTHORIZED
            || final_url.contains("sign-in")
            || final_url.contains("sign-up")
        {
            return Err(GrokError::unauthorized(
                "GROK_SSO_UNAUTHORIZED",
                "SSO 无效或已过期",
            ));
        }
        if !(StatusCode::OK..StatusCode::BAD_REQUEST).contains(&account.status) {
            return Err(GrokError::bad_gateway(
                "GROK_SSO_VALIDATE_FAILED",
                format!("xAI 无法验证 SSO（HTTP {}）", account.status),
            ));
        }

        let device = self
            .follow_xai_flow(
                Method::POST,
                GROK_DEVICE_URL,
                Some(form(&[
                    ("client_id", GROK_CLIENT_ID),
                    ("scope", GROK_SSO_SCOPE),
                ])),
                &mut cookies,
            )
            .await?;
        if !device.status.is_success() {
            return Err(GrokError::bad_gateway(
                "GROK_SSO_DEVICE_CODE_FAILED",
                format!("xAI Device Flow 启动失败（HTTP {}）", device.status),
            ));
        }
        let payload = json_object(&device.body).ok_or_else(|| {
            GrokError::bad_gateway(
                "GROK_SSO_DEVICE_RESPONSE_INVALID",
                "xAI Device Flow 返回内容无效",
            )
        })?;
        let device_code = required_string(&payload, "device_code", "device_code")?;
        let user_code = required_string(&payload, "user_code", "user_code")?;
        let verification_url = required_string(
            &payload,
            "verification_uri_complete",
            "verification_uri_complete",
        )?;
        trusted_xai_url(&verification_url)?;
        let interval = positive_seconds(payload.get("interval"), 5);
        let expires_in = positive_seconds(payload.get("expires_in"), 1_800);

        let verification = self
            .follow_xai_flow(Method::GET, &verification_url, None, &mut cookies)
            .await?;
        if !(StatusCode::OK..StatusCode::BAD_REQUEST).contains(&verification.status) {
            return Err(GrokError::bad_gateway(
                "GROK_SSO_VERIFICATION_PAGE_FAILED",
                format!(
                    "xAI Device Flow 验证页打开失败（HTTP {}）",
                    verification.status
                ),
            ));
        }

        let verified = self
            .follow_xai_flow(
                Method::POST,
                GROK_VERIFY_URL,
                Some(form(&[("user_code", &user_code)])),
                &mut cookies,
            )
            .await?;
        if !(StatusCode::OK..StatusCode::BAD_REQUEST).contains(&verified.status)
            || !verified.final_url.as_str().contains("consent")
        {
            return Err(GrokError::bad_gateway(
                "GROK_SSO_DEVICE_VERIFY_FAILED",
                "xAI Device Flow 未进入授权确认页",
            ));
        }

        let approved = self
            .follow_xai_flow(
                Method::POST,
                GROK_APPROVE_URL,
                Some(form(&[
                    ("user_code", &user_code),
                    ("action", "allow"),
                    ("principal_type", "User"),
                    ("principal_id", ""),
                ])),
                &mut cookies,
            )
            .await?;
        if !(StatusCode::OK..StatusCode::BAD_REQUEST).contains(&approved.status)
            || !approved.final_url.as_str().contains("done")
        {
            return Err(GrokError::bad_gateway(
                "GROK_SSO_DEVICE_APPROVE_FAILED",
                "xAI Device Flow 授权失败",
            ));
        }

        let deadline = Instant::now()
            + Duration::from_secs(u64::try_from(expires_in).unwrap_or_default())
                .min(GROK_TOKEN_POLL_TIMEOUT);
        let mut interval = Duration::from_secs(u64::try_from(interval).unwrap_or(5).max(1));
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(interval.min(remaining)).await;
            if Instant::now() >= deadline {
                break;
            }
            let token = self
                .follow_xai_flow(
                    Method::POST,
                    GROK_TOKEN_URL,
                    Some(form(&[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                        ("client_id", GROK_CLIENT_ID),
                        ("device_code", &device_code),
                    ])),
                    &mut cookies,
                )
                .await?;
            let payload = json_object(&token.body).ok_or_else(|| {
                GrokError::bad_gateway(
                    "GROK_SSO_TOKEN_RESPONSE_INVALID",
                    "xAI Device Flow token 返回内容无效",
                )
            })?;
            if token.status.is_success() && string_field(&payload, "access_token").is_some() {
                return normalized_token_response(payload, None, GROK_SSO_SCOPE);
            }
            match string_field(&payload, "error").as_deref() {
                Some("authorization_pending") => continue,
                Some("slow_down") => {
                    interval += Duration::from_secs(5);
                    continue;
                }
                Some("access_denied" | "expired_token") => {
                    return Err(GrokError::forbidden(
                        "GROK_SSO_AUTHORIZATION_DENIED",
                        "SSO 授权被拒绝或已过期",
                    ));
                }
                _ => {
                    return Err(GrokError::bad_gateway(
                        "GROK_SSO_TOKEN_FAILED",
                        format!("xAI Device Flow token 获取失败（HTTP {}）", token.status),
                    ));
                }
            }
        }
        Err(GrokError::gateway_timeout(
            "GROK_SSO_TIMEOUT",
            "SSO 转换超时，请重试",
        ))
    }

    pub(super) async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<Map<String, Value>, GrokError> {
        let url = trusted_xai_url(GROK_TOKEN_URL)?;
        let response = self
            .send(
                Method::POST,
                &url,
                Some(&form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", GROK_CLIENT_ID),
                    ("refresh_token", refresh_token),
                ])),
                &BTreeMap::new(),
                GROK_OAUTH_USER_AGENT,
            )
            .await?;
        let payload = json_object(&response.body).ok_or_else(|| {
            GrokError::bad_gateway(
                "GROK_OAUTH_RESPONSE_INVALID",
                format!("xAI OAuth 返回内容无效（HTTP {}）", response.status),
            )
        })?;
        if response.status.is_success() {
            return normalized_token_response(payload, Some(refresh_token), GROK_SCOPE);
        }
        if matches!(
            response.status,
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED
        ) {
            return Err(GrokError::bad_request(
                "GROK_OAUTH_REFRESH_TOKEN_INVALID",
                "Grok RT 无效或已过期",
            ));
        }
        if response.status == StatusCode::FORBIDDEN
            && has_explicit_entitlement_denial(&response.body)
        {
            return Err(GrokError::forbidden(
                "GROK_OAUTH_ENTITLEMENT_DENIED",
                "当前 Grok 账号没有可用订阅权限",
            ));
        }
        Err(GrokError::bad_gateway(
            "GROK_OAUTH_REQUEST_FAILED",
            format!("xAI OAuth 请求失败（HTTP {}）", response.status),
        ))
    }
}

struct RawResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct FlowResponse {
    status: StatusCode,
    final_url: Url,
    body: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct GrokError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl GrokError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    fn bad_gateway(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, code, message)
    }

    fn gateway_timeout(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, code, message)
    }

    fn from_reqwest(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            return Self::gateway_timeout("GROK_UPSTREAM_TIMEOUT", "连接 xAI 超时，请稍后重试");
        }
        Self::bad_gateway(
            "GROK_UPSTREAM_NETWORK_ERROR",
            "服务器无法连接 xAI，请检查部署地区和网络",
        )
    }
}

pub(super) fn normalize_sso_token(value: &str) -> String {
    let mut value = value.trim();
    if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("cookie:"))
    {
        value = value.get(7..).unwrap_or_default().trim();
    }
    for part in value.split(';') {
        let Some((name, token)) = part.trim().split_once('=') else {
            continue;
        };
        if matches!(name.trim().to_ascii_lowercase().as_str(), "sso" | "sso-rw") {
            return sanitize_sso_token(token);
        }
    }
    sanitize_sso_token(value.split(';').next().unwrap_or_default())
}

fn sanitize_sso_token(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n' | '\0'))
        .collect()
}

fn form(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn trusted_xai_url(value: &str) -> Result<Url, GrokError> {
    let url = Url::parse(value)
        .map_err(|_| GrokError::bad_gateway("GROK_SSO_URL_INVALID", "xAI OAuth 地址无效"))?;
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let trusted = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && (host == "x.ai" || host.ends_with(".x.ai"));
    if !trusted {
        return Err(GrokError::bad_gateway(
            "GROK_SSO_UNTRUSTED_REDIRECT",
            "xAI OAuth 重定向到了不受信任的地址",
        ));
    }
    Ok(url)
}

async fn read_response(mut response: reqwest::Response) -> Result<RawResponse, GrokError> {
    if response
        .content_length()
        .is_some_and(|length| length > GROK_MAX_RESPONSE_BYTES)
    {
        return Err(GrokError::bad_gateway(
            "GROK_UPSTREAM_RESPONSE_TOO_LARGE",
            "xAI 返回内容超过限制",
        ));
    }
    let status = response.status();
    let headers = response.headers().clone();
    let capacity = response
        .content_length()
        .unwrap_or_default()
        .min(GROK_MAX_RESPONSE_BYTES) as usize;
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        GrokError::bad_gateway("GROK_UPSTREAM_RESPONSE_READ_FAILED", "无法读取 xAI 响应")
    })? {
        if body.len().saturating_add(chunk.len()) > GROK_MAX_RESPONSE_BYTES as usize {
            return Err(GrokError::bad_gateway(
                "GROK_UPSTREAM_RESPONSE_TOO_LARGE",
                "xAI 返回内容超过限制",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(RawResponse {
        status,
        headers,
        body,
    })
}

fn capture_cookies(cookies: &mut BTreeMap<String, String>, headers: &HeaderMap) {
    for header in headers.get_all(header::SET_COOKIE) {
        let Ok(raw) = header.to_str() else {
            continue;
        };
        let pair = raw.split(';').next().unwrap_or_default();
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty()
            || name.len() > 128
            || value.len() > 16 * 1024
            || name
                .chars()
                .chain(value.chars())
                .any(|character| matches!(character, '\r' | '\n' | '\0'))
        {
            continue;
        }
        let deleted = raw.split(';').skip(1).any(|attribute| {
            attribute
                .trim()
                .to_ascii_lowercase()
                .starts_with("max-age=0")
        });
        if deleted {
            cookies.remove(name);
        } else {
            cookies.insert(name.to_owned(), value.to_owned());
        }
    }
}

fn json_object(body: &[u8]) -> Option<Map<String, Value>> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .as_object()
        .cloned()
}

fn string_field(payload: &Map<String, Value>, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_string(
    payload: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, GrokError> {
    string_field(payload, key).ok_or_else(|| {
        GrokError::bad_gateway(
            "GROK_SSO_DEVICE_RESPONSE_INVALID",
            format!("xAI Device Flow 返回结果缺少 {label}"),
        )
    })
}

fn positive_seconds(value: Option<&Value>, fallback: i64) -> i64 {
    value
        .and_then(|value| value.as_i64().or_else(|| value.as_f64().map(|v| v as i64)))
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn normalized_token_response(
    payload: Map<String, Value>,
    original_refresh_token: Option<&str>,
    default_scope: &str,
) -> Result<Map<String, Value>, GrokError> {
    let access_token = string_field(&payload, "access_token").ok_or_else(|| {
        GrokError::bad_gateway(
            "GROK_OAUTH_ACCESS_TOKEN_MISSING",
            "xAI OAuth 返回结果缺少 access_token",
        )
    })?;
    let refresh_token = string_field(&payload, "refresh_token")
        .or_else(|| original_refresh_token.map(ToOwned::to_owned));
    let expires_in = positive_seconds(payload.get("expires_in"), GROK_DEFAULT_TOKEN_TTL_SECONDS);
    let mut output = Map::from_iter([
        ("access_token".to_owned(), Value::String(access_token)),
        (
            "token_type".to_owned(),
            Value::String(
                string_field(&payload, "token_type").unwrap_or_else(|| "Bearer".to_owned()),
            ),
        ),
        ("expires_in".to_owned(), json!(expires_in)),
        ("client_id".to_owned(), json!(GROK_CLIENT_ID)),
        (
            "scope".to_owned(),
            json!(string_field(&payload, "scope").unwrap_or_else(|| default_scope.to_owned())),
        ),
        ("base_url".to_owned(), json!(GROK_BASE_URL)),
    ]);
    if let Some(refresh_token) = refresh_token {
        output.insert("refresh_token".to_owned(), Value::String(refresh_token));
    }
    if let Some(id_token) = string_field(&payload, "id_token") {
        output.insert("id_token".to_owned(), Value::String(id_token));
    }
    Ok(output)
}

fn has_explicit_entitlement_denial(body: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(body).to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    [
        "access_denied",
        "entitlement_denied",
        "subscription_required",
        "no_active_subscription",
    ]
    .iter()
    .any(|value| {
        ["error", "code", "reason"]
            .iter()
            .any(|field| compact.contains(&format!("\"{field}\":\"{value}\"")))
    }) || lower.contains("entitlement denied")
        || lower.contains("subscription required")
        || lower.contains("no active grok subscription")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};
    use serde_json::json;

    use super::{
        GROK_BASE_URL, GROK_CLIENT_ID, GROK_DEFAULT_TOKEN_TTL_SECONDS, capture_cookies,
        has_explicit_entitlement_denial, normalize_sso_token, normalized_token_response,
        trusted_xai_url,
    };

    #[test]
    fn normalizes_supported_sso_inputs() {
        assert_eq!(normalize_sso_token("raw-token"), "raw-token");
        assert_eq!(normalize_sso_token("sso=one; foo=bar"), "one");
        assert_eq!(normalize_sso_token("Cookie: foo=bar; sso-rw=two"), "two");
    }

    #[test]
    fn only_allows_xai_https_redirects() {
        assert!(trusted_xai_url("https://auth.x.ai/oauth2/token").is_ok());
        assert!(trusted_xai_url("https://x.ai/").is_ok());
        assert!(trusted_xai_url("http://auth.x.ai/oauth2/token").is_err());
        assert!(trusted_xai_url("https://user@auth.x.ai/oauth2/token").is_err());
        assert!(trusted_xai_url("https://x.ai.example.com/").is_err());
    }

    #[test]
    fn normalizes_oauth_response_and_preserves_refresh_token() {
        let payload = json!({
            "access_token": "access",
            "refresh_token": "rotated",
            "id_token": "id",
            "expires_in": 3600,
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        let output = normalized_token_response(payload, Some("original"), "scope")
            .expect("valid OAuth response");

        assert_eq!(output.get("refresh_token"), Some(&json!("rotated")));
        assert_eq!(output.get("client_id"), Some(&json!(GROK_CLIENT_ID)));
        assert_eq!(output.get("base_url"), Some(&json!(GROK_BASE_URL)));
        assert_eq!(output.get("token_type"), Some(&json!("Bearer")));
        assert_eq!(output.get("scope"), Some(&json!("scope")));
    }

    #[test]
    fn applies_safe_oauth_defaults() {
        let payload = json!({ "access_token": "access" })
            .as_object()
            .cloned()
            .unwrap_or_default();
        let output = normalized_token_response(payload, Some("original"), "scope")
            .expect("valid OAuth response");

        assert_eq!(output.get("refresh_token"), Some(&json!("original")));
        assert_eq!(
            output.get("expires_in"),
            Some(&json!(GROK_DEFAULT_TOKEN_TTL_SECONDS))
        );
    }

    #[test]
    fn carries_flow_cookies_and_honors_deletion() {
        let mut cookies = BTreeMap::from([("old".to_owned(), "value".to_owned())]);
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("session=active; Path=/; Secure"),
        );
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("old=gone; Max-Age=0; Path=/"),
        );

        capture_cookies(&mut cookies, &headers);

        assert_eq!(cookies.get("session").map(String::as_str), Some("active"));
        assert!(!cookies.contains_key("old"));
    }

    #[test]
    fn detects_only_explicit_entitlement_denials() {
        assert!(has_explicit_entitlement_denial(
            br#"{"error":"subscription_required"}"#
        ));
        assert!(!has_explicit_entitlement_denial(
            br#"{"message":"temporary upstream failure"}"#
        ));
    }
}
