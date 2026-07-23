use std::{cell::Cell, rc::Rc};

use serde_json::{Value, json};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AbortController, Headers, RequestCache, RequestCredentials, RequestInit, RequestRedirect,
    Response,
};

use super::{
    credentials::{OPENAI_CODEX_CLIENT_ID, OPENAI_MOBILE_CLIENT_ID, classify_refresh_token},
    model::{JsonMap, OAuthTokenInfo, PersonalAccessTokenInfo, RefreshTokenKind},
};

const OPENAI_REQUEST_TIMEOUT_MS: i32 = 15_000;
const GROK_REQUEST_TIMEOUT_MS: i32 = 20_000;
const GROK_SSO_REQUEST_TIMEOUT_MS: i32 = 96_000;
const VALIDATION_ENVIRONMENT_INVALID: &str = "VALIDATION_ENVIRONMENT_INVALID";
const VALIDATION_REQUEST_FAILED: &str = "VALIDATION_REQUEST_FAILED";
const VALIDATION_RESPONSE_INVALID: &str = "VALIDATION_RESPONSE_INVALID";
const VALIDATION_TIMEOUT: &str = "VALIDATION_TIMEOUT";

struct ApiError {
    message: String,
    status: u16,
    code: String,
}

impl ApiError {
    fn new(message: impl Into<String>, status: u16, code: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status,
            code: code.into(),
        }
    }
}

fn format_api_error(error: ApiError) -> String {
    if error.status == 0 {
        format!("{}（{}）", error.message, error.code)
    } else {
        format!("{}（HTTP {}，{}）", error.message, error.status, error.code)
    }
}

fn string_field(record: &JsonMap, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn js_error(value: JsValue) -> String {
    value
        .as_string()
        .or_else(|| js_sys::Error::from(value).message().as_string())
        .unwrap_or_else(|| "浏览器网络请求失败".to_owned())
}

fn read_error_details(payload: &JsonMap) -> (Option<String>, Option<String>) {
    let nested = payload.get("error").and_then(Value::as_object);
    let code = nested
        .and_then(|value| string_field(value, "code"))
        .or_else(|| {
            payload
                .get("error")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| string_field(payload, "code"));
    let message = nested
        .and_then(|value| string_field(value, "message"))
        .or_else(|| string_field(payload, "error_description"))
        .or_else(|| string_field(payload, "message"));
    (code, message)
}

fn looks_like_html(text: &str) -> bool {
    let lower = text.trim().to_ascii_lowercase();
    lower.starts_with("<!doctype html") || lower.starts_with("<html") || lower.ends_with("</html>")
}

fn http_error_message(label: &str, status: u16, plain_text: Option<&str>) -> String {
    let platform_error = plain_text.is_some_and(|text| {
        text.trim()
            .eq_ignore_ascii_case(&format!("error code: {status}"))
    });
    if status == 502 && (platform_error || plain_text.is_some_and(looks_like_html)) {
        return format!("{label} 联网验证暂不可用；验证服务器连接上游服务失败，请稍后重试");
    }
    if let Some(text) = plain_text
        .map(str::trim)
        .filter(|text| !text.is_empty() && !platform_error && text.chars().count() <= 200)
    {
        return format!("{label} 联网验证失败（HTTP {status}）：{text}");
    }
    format!("{label} 联网验证接口返回 HTTP {status}")
}

async fn post_json(
    endpoint: &str,
    body: &Value,
    label: &str,
    timeout_ms: i32,
    fallback_code: &str,
) -> Result<JsonMap, ApiError> {
    let window = web_sys::window()
        .ok_or_else(|| ApiError::new("浏览器环境不可用", 0, VALIDATION_ENVIRONMENT_INVALID))?;
    let controller = AbortController::new()
        .map_err(|error| ApiError::new(js_error(error), 0, VALIDATION_REQUEST_FAILED))?;
    let headers = Headers::new()
        .map_err(|error| ApiError::new(js_error(error), 0, VALIDATION_REQUEST_FAILED))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|error| ApiError::new(js_error(error), 0, VALIDATION_REQUEST_FAILED))?;
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_headers_headers(&headers);
    init.set_body(&JsValue::from_str(&body.to_string()));
    init.set_cache(RequestCache::NoStore);
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_redirect(RequestRedirect::Error);
    init.set_signal(Some(&controller.signal()));

    let timed_out = Rc::new(Cell::new(false));
    let timeout_flag = Rc::clone(&timed_out);
    let timeout_controller = controller.clone();
    let timeout = Closure::<dyn FnMut()>::once(move || {
        timeout_flag.set(true);
        timeout_controller.abort();
    });
    let timeout_id = window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout.as_ref().unchecked_ref(),
            timeout_ms,
        )
        .map_err(|error| ApiError::new(js_error(error), 0, VALIDATION_REQUEST_FAILED))?;

    let fetched = JsFuture::from(window.fetch_with_str_and_init(endpoint, &init)).await;
    let response = match fetched {
        Ok(value) => match value.dyn_into::<Response>() {
            Ok(response) => response,
            Err(error) => {
                window.clear_timeout_with_handle(timeout_id);
                drop(timeout);
                return Err(ApiError::new(
                    js_error(error),
                    0,
                    VALIDATION_RESPONSE_INVALID,
                ));
            }
        },
        Err(error) => {
            window.clear_timeout_with_handle(timeout_id);
            drop(timeout);
            return if timed_out.get() {
                Err(ApiError::new(
                    format!("{label} 联网验证超时，请稍后重试或检查服务器网络"),
                    0,
                    VALIDATION_TIMEOUT,
                ))
            } else {
                Err(ApiError::new(
                    format!(
                        "无法连接 {label} 联网验证接口，请稍后重试：{}",
                        js_error(error)
                    ),
                    0,
                    VALIDATION_REQUEST_FAILED,
                ))
            };
        }
    };
    let status = response.status();
    let text = match response.text() {
        Ok(promise) => JsFuture::from(promise).await,
        Err(error) => Err(error),
    };
    window.clear_timeout_with_handle(timeout_id);
    drop(timeout);
    let text = match text {
        Ok(value) => value.as_string().unwrap_or_default(),
        Err(_error) if timed_out.get() => {
            return Err(ApiError::new(
                format!("{label} 联网验证超时，请稍后重试或检查服务器网络"),
                0,
                VALIDATION_TIMEOUT,
            ));
        }
        Err(error) => {
            return Err(ApiError::new(
                js_error(error),
                status,
                VALIDATION_RESPONSE_INVALID,
            ));
        }
    };
    let payload = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    if response.ok() {
        return Ok(payload);
    }
    if status == 404 {
        return Err(ApiError::new(
            format!("{label} 联网验证接口不可用，请确认 Rust 服务已启动"),
            status,
            "VALIDATION_API_NOT_FOUND",
        ));
    }
    let (code, message) = read_error_details(&payload);
    Err(ApiError::new(
        message.unwrap_or_else(|| http_error_message(label, status, Some(&text))),
        status,
        code.unwrap_or_else(|| fallback_code.to_owned()),
    ))
}

async fn request_refresh_token(
    refresh_token: &str,
    client_id: &str,
) -> Result<OAuthTokenInfo, ApiError> {
    let fields = post_json(
        "/api/openai/refresh",
        &json!({
            "refresh_token": refresh_token,
            "client_id": client_id,
        }),
        "RT",
        OPENAI_REQUEST_TIMEOUT_MS,
        "OPENAI_OAUTH_REQUEST_FAILED",
    )
    .await?;
    if string_field(&fields, "access_token").is_none() {
        return Err(ApiError::new(
            "OpenAI 返回结果中缺少 access_token",
            502,
            "OPENAI_OAUTH_ACCESS_TOKEN_MISSING",
        ));
    }
    Ok(OAuthTokenInfo {
        fields,
        client_id: client_id.to_owned(),
    })
}

fn should_try_mobile(error: &ApiError) -> bool {
    matches!(error.status, 400 | 401)
        && matches!(
            error.code.to_ascii_lowercase().as_str(),
            "invalid_grant" | "invalid_client" | "unauthorized_client"
        )
}

async fn refresh_openai_token(refresh_token: &str) -> Result<OAuthTokenInfo, String> {
    match request_refresh_token(refresh_token, OPENAI_CODEX_CLIENT_ID).await {
        Ok(info) => Ok(info),
        Err(error) if should_try_mobile(&error) => {
            request_refresh_token(refresh_token, OPENAI_MOBILE_CLIENT_ID)
                .await
                .map_err(format_api_error)
        }
        Err(error) => Err(format_api_error(error)),
    }
}

pub async fn refresh_token(
    refresh_token: &str,
) -> Result<(RefreshTokenKind, OAuthTokenInfo), String> {
    let kind =
        classify_refresh_token(refresh_token).ok_or_else(|| "无法识别 RT 格式".to_owned())?;
    let info = match kind {
        RefreshTokenKind::OpenAi => refresh_openai_token(refresh_token).await?,
        RefreshTokenKind::Grok => refresh_grok_token(refresh_token).await?,
    };
    Ok((kind, info))
}

pub async fn validate_access_token(access_token: &str) -> Result<PersonalAccessTokenInfo, String> {
    let fields = post_json(
        "/api/openai/whoami",
        &json!({ "access_token": access_token }),
        "AT",
        OPENAI_REQUEST_TIMEOUT_MS,
        "OPENAI_CODEX_PAT_VALIDATE_FAILED",
    )
    .await
    .map_err(format_api_error)?;
    let required = |key, label| {
        string_field(&fields, key).ok_or_else(|| format!("OpenAI AT 验证结果缺少必要字段：{label}"))
    };
    let email = required("email", "邮箱")?;
    let user_id = required("chatgpt_user_id", "user_id")?;
    let account_id = required("chatgpt_account_id", "account_id")?;
    let plan_type = required("chatgpt_plan_type", "套餐")?;
    let is_fedramp = fields
        .get("chatgpt_account_is_fedramp")
        .and_then(Value::as_bool)
        .ok_or_else(|| "OpenAI AT 验证结果缺少必要字段：FedRAMP".to_owned())?;
    Ok(PersonalAccessTokenInfo {
        email,
        user_id,
        account_id,
        plan_type,
        is_fedramp,
    })
}

async fn refresh_grok_token(refresh_token: &str) -> Result<OAuthTokenInfo, String> {
    let fields = post_json(
        "/api/grok/refresh",
        &json!({ "refresh_token": refresh_token }),
        "Grok RT",
        GROK_REQUEST_TIMEOUT_MS,
        "GROK_OAUTH_REQUEST_FAILED",
    )
    .await
    .map_err(format_api_error)?;
    if string_field(&fields, "access_token").is_none() {
        return Err("xAI OAuth 返回结果中缺少 access_token".to_owned());
    }
    Ok(OAuthTokenInfo {
        client_id: string_field(&fields, "client_id").unwrap_or_default(),
        fields,
    })
}

pub async fn convert_grok_sso(sso_token: &str) -> Result<OAuthTokenInfo, String> {
    let fields = post_json(
        "/api/grok/sso",
        &json!({ "sso_token": sso_token }),
        "SSO",
        GROK_SSO_REQUEST_TIMEOUT_MS,
        "GROK_SSO_CONVERSION_FAILED",
    )
    .await
    .map_err(format_api_error)?;
    if string_field(&fields, "access_token").is_none() {
        return Err("xAI Device Flow 返回结果中缺少 access_token".to_owned());
    }
    Ok(OAuthTokenInfo {
        client_id: string_field(&fields, "client_id").unwrap_or_default(),
        fields,
    })
}
