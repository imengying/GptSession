use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Request, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, post},
};
use reqwest::redirect::Policy;
use rust_embed::Embed;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tower::limit::ConcurrencyLimitLayer;

const OPENAI_OAUTH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_PAT_WHOAMI_URL: &str =
    "https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami";
const OPENAI_OAUTH_SCOPE: &str = "openid profile email";
const OPENAI_CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_MOBILE_CLIENT_ID: &str = "app_LlGpXReQgckcGGUo2JrYvtJK";
const OPENAI_UNSUPPORTED_REGION_MESSAGE: &str =
    "当前服务器出口地区不受 OpenAI 支持，请检查服务器部署地区或出口代理";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 24 * 1024;
const MAX_UPSTREAM_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ACCESS_TOKEN_LENGTH: usize = 8 * 1024;
const MAX_REFRESH_TOKEN_LENGTH: usize = 16 * 1024;
const MIN_TOKEN_LENGTH: usize = 16;
const MAX_CONCURRENT_REQUESTS: usize = 64;
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'none'; frame-ancestors 'none'; frame-src 'none'; img-src 'self' data:; media-src 'none'; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; worker-src 'none'";

#[derive(Embed)]
#[folder = "src/static/"]
struct WebAssets;

#[derive(Clone)]
pub struct AppState {
    gateway: Arc<dyn OpenAiGateway>,
}

impl AppState {
    pub fn new(gateway: ReqwestOpenAiGateway) -> Self {
        Self {
            gateway: Arc::new(gateway),
        }
    }
}

#[derive(Clone)]
pub struct ReqwestOpenAiGateway {
    client: reqwest::Client,
}

impl ReqwestOpenAiGateway {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::none())
            .https_only(true)
            .user_agent("session-bridge/0.2.0")
            .build()?;
        Ok(Self { client })
    }

    async fn read_response(
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<UpstreamResponse, GatewayError> {
        let mut response = response.map_err(GatewayError::from_reqwest)?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_UPSTREAM_RESPONSE_BYTES)
        {
            return Err(GatewayError::new(
                "OPENAI_UPSTREAM_RESPONSE_TOO_LARGE",
                "OpenAI 返回内容超过限制",
            ));
        }
        let capacity = response
            .content_length()
            .unwrap_or_default()
            .min(MAX_UPSTREAM_RESPONSE_BYTES) as usize;
        let mut body = Vec::with_capacity(capacity);
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            GatewayError::new(
                "OPENAI_UPSTREAM_RESPONSE_READ_FAILED",
                "无法读取 OpenAI 响应",
            )
        })? {
            if body.len().saturating_add(chunk.len()) > MAX_UPSTREAM_RESPONSE_BYTES as usize {
                return Err(GatewayError::new(
                    "OPENAI_UPSTREAM_RESPONSE_TOO_LARGE",
                    "OpenAI 返回内容超过限制",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(UpstreamResponse { status, body })
    }
}

#[async_trait]
trait OpenAiGateway: Send + Sync {
    async fn refresh(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<UpstreamResponse, GatewayError>;

    async fn whoami(&self, access_token: &str) -> Result<UpstreamResponse, GatewayError>;
}

#[async_trait]
impl OpenAiGateway for ReqwestOpenAiGateway {
    async fn refresh(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<UpstreamResponse, GatewayError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("scope", OPENAI_OAUTH_SCOPE),
        ];
        Self::read_response(
            self.client
                .post(OPENAI_OAUTH_TOKEN_URL)
                .header(reqwest::header::ACCEPT, "application/json")
                .form(&form)
                .send()
                .await,
        )
        .await
    }

    async fn whoami(&self, access_token: &str) -> Result<UpstreamResponse, GatewayError> {
        Self::read_response(
            self.client
                .get(OPENAI_PAT_WHOAMI_URL)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {access_token}"),
                )
                .header("Originator", "codex_cli_rs")
                .header(reqwest::header::USER_AGENT, "codex-cli/0.91.0")
                .send()
                .await,
        )
        .await
    }
}

#[derive(Clone)]
struct UpstreamResponse {
    status: StatusCode,
    body: Vec<u8>,
}

#[derive(Clone)]
struct GatewayError {
    code: &'static str,
    message: &'static str,
}

impl GatewayError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    fn from_reqwest(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            return Self::new("OPENAI_UPSTREAM_TIMEOUT", "连接 OpenAI 超时，请稍后重试");
        }
        Self::new(
            "OPENAI_UPSTREAM_NETWORK_ERROR",
            "服务器无法连接 OpenAI，请检查部署地区和网络",
        )
    }
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: Option<String>,
    client_id: Option<String>,
}

#[derive(Deserialize)]
struct WhoamiRequest {
    access_token: Option<String>,
}

#[derive(Clone, Copy)]
enum TokenType {
    Access,
    Refresh,
}

pub fn build_app(state: AppState) -> Router {
    let api = Router::new()
        .route(
            "/refresh",
            post(refresh_handler).fallback(method_not_allowed),
        )
        .route("/whoami", post(whoami_handler).fallback(method_not_allowed))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS));
    let api = Router::new().nest("/openai", api).fallback(api_not_found);

    Router::new()
        .route("/api/", any(api_not_found))
        .nest("/api", api)
        .fallback(embedded_asset)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn embedded_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    let resolved = WebAssets::get(path).map(|asset| (path, asset)).or_else(|| {
        (!path.contains('.'))
            .then(|| WebAssets::get("index.html").map(|asset| ("index.html", asset)))
            .flatten()
    });
    let Some((asset_path, asset)) = resolved else {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    };
    let content_type = mime_guess::from_path(asset_path)
        .first_or_octet_stream()
        .as_ref()
        .to_owned();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(asset.data.into_owned()))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        })
}

async fn method_not_allowed() -> Response {
    api_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
        "仅支持 POST",
    )
}

async fn api_not_found() -> Response {
    api_error(StatusCode::NOT_FOUND, "API_NOT_FOUND", "接口不存在")
}

async fn security_headers(request: Request, next: Next) -> Response {
    let request_path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let response_is_success = response.status().is_success();
    let headers = response.headers_mut();

    insert_header_if_absent(headers, "content-security-policy", CONTENT_SECURITY_POLICY);
    insert_header_if_absent(headers, "cross-origin-opener-policy", "same-origin");
    insert_header_if_absent(headers, "cross-origin-resource-policy", "same-origin");
    insert_header_if_absent(
        headers,
        "permissions-policy",
        "camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()",
    );
    insert_header_if_absent(headers, "referrer-policy", "no-referrer");
    insert_header_if_absent(headers, "strict-transport-security", "max-age=31536000");
    insert_header_if_absent(headers, "x-content-type-options", "nosniff");
    insert_header_if_absent(headers, "x-frame-options", "DENY");

    if !headers.contains_key(header::CACHE_CONTROL) {
        let cache_control = if !response_is_success {
            "no-cache"
        } else if request_path.starts_with("/assets/") {
            "public, max-age=3600, must-revalidate"
        } else if request_path == "/theme.css" {
            "public, max-age=3600"
        } else {
            "no-cache"
        };
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control),
        );
    }

    response
}

fn insert_header_if_absent(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers
        .entry(HeaderName::from_static(name))
        .or_insert(HeaderValue::from_static(value));
}

async fn refresh_handler(
    State(state): State<AppState>,
    request: Result<Json<RefreshRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(rejection) => return json_rejection(rejection),
    };
    let refresh_token = request
        .refresh_token
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if let Some(message) = token_validation_error(refresh_token, TokenType::Refresh) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "OPENAI_OAUTH_REFRESH_TOKEN_INVALID",
            message,
        );
    }
    let client_id = request
        .client_id
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !matches!(client_id, OPENAI_CODEX_CLIENT_ID | OPENAI_MOBILE_CLIENT_ID) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "OPENAI_OAUTH_CLIENT_ID_INVALID",
            "OpenAI OAuth client_id 不受支持",
        );
    }

    let upstream = match state.gateway.refresh(refresh_token, client_id).await {
        Ok(response) => response,
        Err(error) => return gateway_error(error),
    };
    let Some(payload) = parse_json_object(&upstream.body) else {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "OPENAI_OAUTH_RESPONSE_INVALID",
            &format!("OpenAI OAuth 返回了无效响应（HTTP {}）", upstream.status),
        );
    };
    if upstream.status.is_success() {
        return api_json(upstream.status, Value::Object(payload));
    }
    let safe_payload = safe_oauth_error(&payload, upstream.status, refresh_token);
    api_json(upstream.status, safe_payload)
}

async fn whoami_handler(
    State(state): State<AppState>,
    request: Result<Json<WhoamiRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(rejection) => return json_rejection(rejection),
    };
    let access_token = request
        .access_token
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if let Some(message) = token_validation_error(access_token, TokenType::Access) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "OPENAI_CODEX_PAT_INVALID_PREFIX",
            message,
        );
    }

    let upstream = match state.gateway.whoami(access_token).await {
        Ok(response) => response,
        Err(error) => return gateway_error(error),
    };
    let Some(payload) = parse_json_object(&upstream.body) else {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "OPENAI_CODEX_PAT_RESPONSE_INVALID",
            &format!("OpenAI AT 验证返回了无效响应（HTTP {}）", upstream.status),
        );
    };

    let error_code = upstream_error_code(&payload);
    if error_code.as_deref() == Some("unsupported_country_region_territory") {
        return api_error(
            StatusCode::FORBIDDEN,
            "unsupported_country_region_territory",
            OPENAI_UNSUPPORTED_REGION_MESSAGE,
        );
    }
    if matches!(
        upstream.status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "OPENAI_CODEX_PAT_INVALID",
            "Personal Access Token 无效或已过期",
        );
    }
    if !upstream.status.is_success() {
        let code = error_code.unwrap_or_else(|| "OPENAI_CODEX_PAT_VALIDATE_FAILED".to_owned());
        let message = safe_upstream_message(&payload, upstream.status, access_token);
        return api_error(StatusCode::BAD_GATEWAY, &code, &message);
    }

    let required = [
        "email",
        "chatgpt_user_id",
        "chatgpt_account_id",
        "chatgpt_plan_type",
    ];
    let missing = required
        .iter()
        .find(|field| string_field(&payload, field).is_none());
    let fedramp = payload
        .get("chatgpt_account_is_fedramp")
        .and_then(Value::as_bool);
    if missing.is_some() || fedramp.is_none() {
        let suffix = missing.map_or_else(String::new, |field| format!("：{field}"));
        return api_error(
            StatusCode::BAD_GATEWAY,
            "OPENAI_CODEX_PAT_RESPONSE_INVALID",
            &format!("OpenAI AT 验证结果缺少必要字段{suffix}"),
        );
    }

    api_json(
        StatusCode::OK,
        json!({
            "email": string_field(&payload, "email"),
            "chatgpt_user_id": string_field(&payload, "chatgpt_user_id"),
            "chatgpt_account_id": string_field(&payload, "chatgpt_account_id"),
            "chatgpt_plan_type": string_field(&payload, "chatgpt_plan_type"),
            "chatgpt_account_is_fedramp": fedramp,
        }),
    )
}

fn json_rejection(rejection: JsonRejection) -> Response {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "REQUEST_TOO_LARGE",
            "请求内容过大",
        );
    }
    api_error(StatusCode::BAD_REQUEST, "INVALID_JSON", "请求 JSON 无效")
}

fn gateway_error(error: GatewayError) -> Response {
    api_error(StatusCode::BAD_GATEWAY, error.code, error.message)
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    api_json(
        status,
        json!({
            "error": {
                "code": code,
                "message": message,
            },
        }),
    )
}

fn api_json(status: StatusCode, payload: Value) -> Response {
    let mut response = (status, Json(payload)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn token_validation_error(token: &str, token_type: TokenType) -> Option<&'static str> {
    if matches!(token_type, TokenType::Access) && !token.starts_with("at-") {
        return Some("AT 仅支持 at- 开头的 Personal Access Token");
    }
    if token.len() < MIN_TOKEN_LENGTH {
        return Some(match token_type {
            TokenType::Access => "AT 长度过短，请检查是否粘贴完整",
            TokenType::Refresh => "RT 长度过短，请检查是否粘贴完整",
        });
    }
    let max_length = match token_type {
        TokenType::Access => MAX_ACCESS_TOKEN_LENGTH,
        TokenType::Refresh => MAX_REFRESH_TOKEN_LENGTH,
    };
    if token.len() > max_length {
        return Some(match token_type {
            TokenType::Access => "AT 长度超过限制",
            TokenType::Refresh => "RT 长度超过限制",
        });
    }
    if !token.bytes().all(is_token_character) {
        return Some(match token_type {
            TokenType::Access => "AT 含有空格或非法字符；每次只能提交一个完整 token",
            TokenType::Refresh => "RT 含有空格或非法字符；每次只能提交一个完整 token",
        });
    }
    if matches!(token_type, TokenType::Refresh) && token.starts_with("at-") {
        return Some("检测到 AT，请切换到 AT 输入");
    }
    None
}

const fn is_token_character(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

fn parse_json_object(body: &[u8]) -> Option<Map<String, Value>> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .as_object()
        .cloned()
}

fn string_field<'a>(payload: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn nested_error(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    payload.get("error").and_then(Value::as_object)
}

fn upstream_error_code(payload: &Map<String, Value>) -> Option<String> {
    let candidate = nested_error(payload)
        .and_then(|error| string_field(error, "code"))
        .or_else(|| string_field(payload, "code"))
        .or_else(|| payload.get("error").and_then(Value::as_str));
    candidate.and_then(safe_code)
}

fn safe_code(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 100
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return None;
    }
    Some(value.to_owned())
}

fn sanitized_message(value: &str, secret: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let redacted = value.replace(secret, "[redacted]");
    Some(redacted.chars().take(500).collect())
}

fn safe_oauth_error(
    payload: &Map<String, Value>,
    status: StatusCode,
    refresh_token: &str,
) -> Value {
    let nested = nested_error(payload);
    let code = nested
        .and_then(|error| string_field(error, "code"))
        .or_else(|| string_field(payload, "code"))
        .or_else(|| payload.get("error").and_then(Value::as_str))
        .and_then(safe_code)
        .unwrap_or_else(|| "OPENAI_OAUTH_REQUEST_FAILED".to_owned());
    let message = nested
        .and_then(|error| string_field(error, "message"))
        .or_else(|| string_field(payload, "error_description"))
        .or_else(|| string_field(payload, "message"))
        .and_then(|value| sanitized_message(value, refresh_token))
        .unwrap_or_else(|| format!("OpenAI OAuth 验证失败（HTTP {status}）"));
    let message = if code == "unsupported_country_region_territory" {
        OPENAI_UNSUPPORTED_REGION_MESSAGE.to_owned()
    } else {
        message
    };

    if let Some(nested) = nested {
        let mut error = Map::from_iter([
            ("code".to_owned(), Value::String(code)),
            ("message".to_owned(), Value::String(message)),
        ]);
        if let Some(error_type) = string_field(nested, "type").and_then(safe_code) {
            error.insert("type".to_owned(), Value::String(error_type));
        }
        json!({ "error": error })
    } else {
        json!({
            "error": code,
            "error_description": message,
        })
    }
}

fn safe_upstream_message(
    payload: &Map<String, Value>,
    status: StatusCode,
    access_token: &str,
) -> String {
    nested_error(payload)
        .and_then(|error| string_field(error, "message"))
        .or_else(|| string_field(payload, "message"))
        .and_then(|value| sanitized_message(value, access_token))
        .unwrap_or_else(|| format!("OpenAI AT 验证失败（HTTP {status}）"))
}
