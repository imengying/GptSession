use std::{cell::RefCell, collections::HashSet, rc::Rc};

use futures_util::future::join_all;
use js_sys::{Array, Date, Reflect, Uint8Array};
use serde_json::Value;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    Blob, BlobPropertyBag, Document, DragEvent, Element, Event, EventTarget, File, FileList,
    HtmlAnchorElement, HtmlButtonElement, HtmlDetailsElement, HtmlElement, HtmlInputElement,
    HtmlTableSectionElement, HtmlTextAreaElement, KeyboardEvent, Url,
};

use super::{
    api,
    credentials::{
        build_output_document, credential_keys, download_descriptor, normalize_grok_oauth,
        normalize_refreshed_rt, normalize_validated_at, output_supported,
        output_unsupported_reason, parse_credential_text, parse_manual_tokens, redact,
        sub2api_document_conflicts,
    },
    model::{
        DownloadDescriptor, InputMode, NormalizedAccount, OutputFormat, ParseIssue, ParseResult,
        RefreshTokenKind, SourceType,
    },
    zip::build_zip,
};

const MAX_FILE_SIZE: f64 = 10.0 * 1024.0 * 1024.0;
const MAX_TOTAL_IMPORT_SIZE: usize = 50 * 1024 * 1024;
const MAX_MANUAL_INPUT_SIZE: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 500;
const TOKEN_VALIDATION_CONCURRENCY: usize = 3;
const TOKEN_VALIDATION_WATCHDOG_PER_BATCH_MS: i32 = 20_000;
const GROK_SSO_WATCHDOG_PER_BATCH_MS: i32 = 100_000;
const TOKEN_VALIDATION_WATCHDOG_MARGIN_MS: i32 = 5_000;
const FORMAT_CONTROLS: [(&str, OutputFormat); 2] = [
    ("format-sub2api", OutputFormat::Sub2Api),
    ("format-cpa", OutputFormat::Cpa),
];
const INPUT_MODE_CONTROLS: [(&str, InputMode); 5] = [
    ("input-mode-json", InputMode::Json),
    ("input-mode-agent-identity", InputMode::AgentIdentity),
    ("input-mode-rt", InputMode::Rt),
    ("input-mode-at", InputMode::At),
    ("input-mode-grok-sso", InputMode::GrokSso),
];

type SharedApp = Rc<RefCell<App>>;

#[derive(Default)]
struct App {
    format: OutputFormat,
    input_mode: InputMode,
    accounts: Vec<NormalizedAccount>,
    issues: Vec<ParseIssue>,
    reveal_secrets: bool,
    generated_at: Option<f64>,
    operation_id: u64,
    validation_in_progress: bool,
}

fn window() -> Result<web_sys::Window, JsValue> {
    web_sys::window().ok_or_else(|| JsValue::from_str("window 不可用"))
}

fn document() -> Result<Document, JsValue> {
    window()?
        .document()
        .ok_or_else(|| JsValue::from_str("document 不可用"))
}

fn by_id<T: JsCast>(id: &str) -> Result<T, JsValue> {
    document()?
        .get_element_by_id(id)
        .ok_or_else(|| JsValue::from_str(&format!("缺少页面元素：#{id}")))?
        .dyn_into::<T>()
        .map_err(|_| JsValue::from_str(&format!("页面元素类型错误：#{id}")))
}

fn html_element(id: &str) -> Result<HtmlElement, JsValue> {
    by_id(id)
}

fn set_text(id: &str, text: &str) -> Result<(), JsValue> {
    html_element(id)?.set_text_content(Some(text));
    Ok(())
}

fn set_class(element: &Element, class_name: &str, enabled: bool) {
    let _ = element.class_list().toggle_with_force(class_name, enabled);
}

fn is_light_theme() -> Result<bool, JsValue> {
    Ok(document()?
        .document_element()
        .is_some_and(|root| root.get_attribute("data-theme").as_deref() == Some("light")))
}

fn set_theme(light: bool) -> Result<(), JsValue> {
    let document = document()?;
    let root = document
        .document_element()
        .ok_or_else(|| JsValue::from_str("html 元素不可用"))?;
    if light {
        root.set_attribute("data-theme", "light")?;
    } else {
        root.remove_attribute("data-theme")?;
    }

    let action = if light {
        "切换深色主题"
    } else {
        "切换浅色主题"
    };
    let button: HtmlButtonElement = by_id("theme-toggle")?;
    button.set_attribute("aria-label", action)?;
    button.set_attribute("title", action)?;
    button.set_attribute("aria-pressed", if light { "true" } else { "false" })?;

    if let Some(meta) = document.query_selector("meta[name='theme-color']")? {
        meta.set_attribute("content", if light { "#f4f4f5" } else { "#09090b" })?;
    }
    Ok(())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn base_name(value: &str) -> &str {
    value
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("未命名来源")
}

fn directory_name(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    normalized
        .rsplit_once('/')
        .map(|(directory, _)| directory.to_owned())
        .unwrap_or_default()
}

fn format_date(value: Option<&str>) -> Option<String> {
    let value = value?;
    let milliseconds = Date::parse(value);
    if !milliseconds.is_finite() {
        return Some(value.to_owned());
    }
    let date = Date::new(&milliseconds.into());
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        date.get_full_year(),
        date.get_month() + 1,
        date.get_date(),
        date.get_hours(),
        date.get_minutes()
    ))
}

fn format_account_id(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "account_id 未识别".to_owned();
    };
    if value.chars().count() <= 18 {
        return value.to_owned();
    }
    let first = value.chars().take(8).collect::<String>();
    let mut last = value.chars().rev().take(6).collect::<Vec<_>>();
    last.reverse();
    format!("{first}…{}", last.into_iter().collect::<String>())
}

fn set_input_status(message: &str, tone: Option<&str>) -> Result<(), JsValue> {
    let status = html_element("input-status")?;
    for class_name in ["is-working", "is-success", "is-error"] {
        let _ = status.class_list().remove_1(class_name);
    }
    if let Some(tone) = tone {
        let _ = status.class_list().add_1(&format!("is-{tone}"));
    }
    status.set_inner_html(&format!(
        "<span class=\"status-light\"></span>{}",
        escape_html(message)
    ));
    Ok(())
}

fn show_toast(message: &str, is_error: bool) -> Result<(), JsValue> {
    let toast = html_element("toast")?;
    toast.set_text_content(Some(message));
    set_class(toast.as_ref(), "is-error", is_error);
    set_class(toast.as_ref(), "is-visible", true);
    let callback = Closure::once_into_js(move || {
        if let Ok(toast) = html_element("toast") {
            set_class(toast.as_ref(), "is-visible", false);
        }
    });
    window()?
        .set_timeout_with_callback_and_timeout_and_arguments_0(callback.unchecked_ref(), 2_600)?;
    Ok(())
}

fn format_issues(app: &App) -> Vec<ParseIssue> {
    let mut issues = Vec::new();
    if app.format == OutputFormat::Cpa
        && app
            .accounts
            .iter()
            .any(|account| account.access_token.is_empty() && account.refresh_token.is_some())
    {
        issues.push(ParseIssue::new(
            "CPA RT 导出",
            "部分凭证仅包含 refresh_token；导入 CPA 后需联网刷新，才能生成 access_token 与账号信息",
        ));
    }
    if app.format == OutputFormat::Sub2Api {
        let conflicts = sub2api_document_conflicts(&app.accounts);
        if !conflicts.is_empty() {
            issues.push(ParseIssue::new(
                "Sub2API 合并导出",
                format!(
                    "多个导入包的顶层字段存在冲突，已从合并结果中省略：{}",
                    conflicts.join("、")
                ),
            ));
        }
    }
    issues
}

fn is_json_input_mode(mode: InputMode) -> bool {
    matches!(mode, InputMode::Json | InputMode::AgentIdentity)
}

fn has_agent_identity(app: &App) -> bool {
    app.accounts
        .iter()
        .any(|account| account.source_type == SourceType::AgentIdentity)
}

fn warning_count(app: &App) -> usize {
    app.issues.len()
        + format_issues(app).len()
        + app
            .accounts
            .iter()
            .map(|account| account.warnings.len())
            .sum::<usize>()
}

fn render_input(app: &App) -> Result<(), JsValue> {
    for (id, mode) in INPUT_MODE_CONTROLS {
        let button: HtmlButtonElement = by_id(id)?;
        let active = app.input_mode == mode;
        set_class(button.as_ref(), "is-active", active);
        button.set_attribute("aria-checked", if active { "true" } else { "false" })?;
        button.set_tab_index(if active { 0 } else { -1 });
        button.set_disabled(app.validation_in_progress);
    }
    let input: HtmlTextAreaElement = by_id("session-input")?;
    input.set_read_only(app.validation_in_progress);
    let token_mode = matches!(
        app.input_mode,
        InputMode::Rt | InputMode::At | InputMode::GrokSso
    );
    if let Some(toolbar) = document()?.query_selector(".input-toolbar")? {
        set_class(&toolbar, "is-token-mode", token_mode);
    }
    html_element("pick-files")?.set_hidden(token_mode);
    html_element("pick-folder")?.set_hidden(token_mode);

    match app.input_mode {
        InputMode::At => {
            set_text(
                "input-description",
                "粘贴 at- 开头的 Access Token，自动验证后导出 Sub2API 或 CPA。",
            )?;
            set_text("input-guide-title", "手动输入 Access Token")?;
            set_text(
                "input-guide-description",
                "输入后自动通过本站验证服务连接 OpenAI 获取账号信息。",
            )?;
            set_text("input-content-label", "Access Token（at-）")?;
            set_text("input-hint", "每行一个 · 自动去重 · 联网验证账号信息")?;
            input.set_placeholder("at-...");
        }
        InputMode::Rt => {
            set_text(
                "input-description",
                "粘贴 OpenAI 或 Grok Refresh Token，自动识别后导出 Sub2API 或 CPA。",
            )?;
            set_text("input-guide-title", "手动输入 RT")?;
            set_text(
                "input-guide-description",
                "自动识别 OpenAI Codex、OpenAI Mobile 与 Grok RT，并使用对应 OAuth 客户端换取完整凭证。",
            )?;
            set_text("input-content-label", "RT")?;
            set_text("input-hint", "每行一个 · 自动识别来源 · 联网验证账号信息")?;
            input.set_placeholder("每行粘贴一个 OpenAI 或 Grok RT");
        }
        InputMode::GrokSso => {
            set_text(
                "input-description",
                "粘贴 Grok Web SSO，通过 xAI Device Flow 换取 OAuth 凭证。",
            )?;
            set_text("input-guide-title", "导入 SSO")?;
            set_text(
                "input-guide-description",
                "支持原始 SSO、sso=、sso-rw= 与完整 Cookie 行；单次转换最长约 90 秒。",
            )?;
            set_text("input-content-label", "SSO")?;
            set_text(
                "input-hint",
                "每行一个 · 自动提取 Cookie · 联网完成 Device Flow",
            )?;
            input.set_placeholder("sso=... 或 Cookie: ...; sso=...");
        }
        InputMode::AgentIdentity => {
            set_text(
                "input-description",
                "粘贴 Sub2API Agent Identity JSON，本地校验后导出 Sub2API 或 CPA。",
            )?;
            set_text("input-guide-title", "导入 Agent Identity（AI）")?;
            set_text(
                "input-guide-description",
                "不需要联网验证；仅检查必要字段和 PKCS#8 Ed25519 私钥格式。",
            )?;
            set_text("input-content-label", "Agent Identity JSON")?;
            set_text(
                "input-hint",
                "支持单个、数组、连续 JSON 与文件导入 · 本地转换",
            )?;
            input.set_placeholder("{\"auth_mode\":\"agentIdentity\",\"agent_identity\":{...}}");
        }
        InputMode::Json => {
            set_text(
                "input-description",
                "粘贴 JSON，或导入一个文件、多个文件及整个目录。",
            )?;
            set_text(
                "input-guide-title",
                "自动识别 Session、CPA、Sub2API、AI 与 Grok",
            )?;
            html_element("input-guide-description")?.set_inner_html(
                "ChatGPT Session 可从 <a href=\"https://chatgpt.com/api/auth/session\" target=\"_blank\" rel=\"noreferrer\">chatgpt.com/api/auth/session</a> 获取。",
            );
            set_text("input-content-label", "JSON 内容")?;
            set_text("input-hint", "粘贴后自动解析 · 支持连续 JSON 与拖入文件")?;
            input.set_placeholder(
                "{\"type\":\"codex\",\"email\":\"you@example.com\",\"access_token\":\"...\"}",
            );
        }
    }
    Ok(())
}

fn render_format(app: &App) -> Result<(), JsValue> {
    for (id, format) in FORMAT_CONTROLS {
        let button: HtmlButtonElement = by_id(id)?;
        let active = app.format == format;
        set_class(button.as_ref(), "is-active", active);
        button.set_attribute("aria-selected", if active { "true" } else { "false" })?;
        button.set_tab_index(if active { 0 } else { -1 });
        let supported = output_supported(&app.accounts, format);
        button.set_disabled(!supported);
        button.set_attribute("aria-disabled", if supported { "false" } else { "true" })?;
        if let Some(reason) = output_unsupported_reason(&app.accounts, format) {
            button.set_attribute("title", reason)?;
        } else {
            button.remove_attribute("title")?;
        }
        if active {
            html_element("output-panel")?.set_attribute("aria-labelledby", id)?;
        }
    }
    let description = if has_agent_identity(app) {
        "Agent Identity 可转换为 Sub2API 或 CPA 签名凭证，并完整保留身份字段与私钥。"
    } else {
        "将导入的凭证转换为所选认证格式，并保留可恢复的 token、账号信息与过期时间。"
    };
    set_text("format-description", description)?;
    let download: HtmlButtonElement = by_id("download-output")?;
    if app.format == OutputFormat::Cpa {
        set_text("output-title", "CPA 认证文件")?;
        download.set_text_content(Some(if app.accounts.len() > 1 {
            "下载 ZIP"
        } else {
            "下载 JSON"
        }));
    } else {
        set_text("output-title", "Sub2API 认证文件")?;
        download.set_text_content(Some("下载 JSON"));
    }
    Ok(())
}

fn render_account_status(account: &NormalizedAccount) -> String {
    if account.source_type == SourceType::AgentIdentity {
        return "<div class=\"status-stack\"><span class=\"status-chip is-refreshable\">Agent Identity</span><span class=\"expiry-detail\">无需 OAuth 刷新</span></div>".to_owned();
    }
    let expires_at = format_date(account.token_expires_at.as_deref());
    let (label, tone, detail) = if account.is_refreshable {
        (
            "可自动刷新",
            "is-refreshable",
            expires_at.map(|value| format!("当前 token {value}")),
        )
    } else if account.is_expired {
        ("已过期", "is-expired", expires_at)
    } else if let Some(expires_at) = expires_at {
        ("不可刷新", "is-warning", Some(format!("到期 {expires_at}")))
    } else {
        ("有效期未知", "is-warning", Some("不可自动刷新".to_owned()))
    };
    let detail = detail.map_or_else(String::new, |detail| {
        format!(
            "<span class=\"expiry-detail\">{}</span>",
            escape_html(&detail)
        )
    });
    format!(
        "<div class=\"status-stack\"><span class=\"status-chip {tone}\">{label}</span>{detail}</div>"
    )
}

fn render_accounts(app: &App) -> Result<(), JsValue> {
    set_text("stat-accounts", &app.accounts.len().to_string())?;
    set_text(
        "stat-refreshable",
        &app.accounts
            .iter()
            .filter(|account| account.is_refreshable)
            .count()
            .to_string(),
    )?;
    set_text("stat-issues", &warning_count(app).to_string())?;
    let body: HtmlTableSectionElement = by_id("account-body")?;
    if app.accounts.is_empty() {
        body.set_inner_html(
            "<tr class=\"empty-row\"><td colspan=\"5\">解析后的账号与来源格式会显示在这里。</td></tr>",
        );
        return Ok(());
    }
    let rows = app
        .accounts
        .iter()
        .enumerate()
        .map(|(index, account)| {
            let source_base = base_name(&account.source_name);
            let source_directory = directory_name(&account.source_name);
            let source_path = if account.source_path == "$" {
                source_directory.as_str()
            } else {
                account.source_path.as_str()
            };
            let warning_title = if account.warnings.is_empty() {
                "未发现额外提示".to_owned()
            } else {
                account.warnings.join("\n")
            };
            let account_name = account.email.as_deref().unwrap_or(&account.name);
            let source_detail = if source_path.is_empty() {
                source_base.to_owned()
            } else {
                format!("{source_base} · {source_path}")
            };
            let source_title = if source_path.is_empty() {
                account.source_name.clone()
            } else {
                format!("{} · {source_path}", account.source_name)
            };
            format!(
                "<tr>\
                 <td><span class=\"account-primary\" title=\"{account_name}\">{account_name}</span>\
                 <span class=\"account-secondary\" title=\"{full_id}\">{short_id}</span></td>\
                 <td><span class=\"plan-chip\">{plan}</span></td>\
                 <td title=\"{warnings}\">{status}</td>\
                 <td><span class=\"source-chip source-{source_key}\" title=\"{source_name}\">{source_label}</span>\
                 <span class=\"account-secondary\" title=\"{source_title}\">{source_detail}</span></td>\
                 <td><button class=\"inline-button\" type=\"button\" data-download-index=\"{index}\">下载 JSON</button></td>\
                 </tr>",
                account_name = escape_html(account_name),
                full_id = escape_html(account.account_id.as_deref().unwrap_or("")),
                short_id = escape_html(&format_account_id(account.account_id.as_deref())),
                plan = escape_html(account.plan_type.as_deref().unwrap_or("未知")),
                warnings = escape_html(&warning_title),
                status = render_account_status(account),
                source_key = account.source_type.key(),
                source_name = escape_html(&account.source_name),
                source_label = account.source_type.label(),
                source_title = escape_html(&source_title),
                source_detail = escape_html(&source_detail),
            )
        })
        .collect::<String>();
    body.set_inner_html(&rows);
    Ok(())
}

fn render_issues(app: &App) -> Result<(), JsValue> {
    let format_issues = format_issues(app);
    let mut entries = app.issues.clone();
    entries.extend(format_issues.clone());
    for account in &app.accounts {
        entries.extend(account.warnings.iter().map(|warning| {
            ParseIssue {
                source_name: account
                    .email
                    .clone()
                    .unwrap_or_else(|| account.name.clone()),
                source_path: Some(account.source_path.clone()),
                reason: warning.clone(),
            }
        }));
    }
    let details: HtmlDetailsElement = by_id("issues-box")?;
    if entries.is_empty() {
        set_text("issues-summary", "暂无问题")?;
        html_element("issues-list")?.set_inner_html("<li class=\"issue-empty\">未发现问题。</li>");
        details.set_open(false);
        return Ok(());
    }
    set_text("issues-summary", &format!("{} 条提示", entries.len()))?;
    let list = entries
        .iter()
        .map(|issue| {
            let location = issue
                .source_path
                .as_deref()
                .filter(|path| *path != "$")
                .map(|path| format!(" · {path}"))
                .unwrap_or_default();
            format!(
                "<li><strong>{}</strong> — {}</li>",
                escape_html(&format!("{}{}", issue.source_name, location)),
                escape_html(&issue.reason)
            )
        })
        .collect::<String>();
    html_element("issues-list")?.set_inner_html(&list);
    if app.accounts.is_empty() || !app.issues.is_empty() || !format_issues.is_empty() {
        details.set_open(true);
    }
    Ok(())
}

fn current_document(app: &App) -> Option<Value> {
    (!app.accounts.is_empty() && output_supported(&app.accounts, app.format)).then(|| {
        build_output_document(
            &app.accounts,
            app.format,
            app.generated_at.unwrap_or_else(Date::now),
        )
    })
}

fn render_output(app: &App) -> Result<(), JsValue> {
    let has_accounts = !app.accounts.is_empty();
    let document = current_document(app);
    let has_output = document.is_some();
    let preview = document.as_ref().map(|document| {
        if app.reveal_secrets {
            document.clone()
        } else {
            redact(document, None)
        }
    });
    let preview_text = preview
        .as_ref()
        .and_then(|value| serde_json::to_string_pretty(value).ok())
        .unwrap_or_default();
    let output: HtmlTextAreaElement = by_id("output-preview")?;
    output.set_value(&preview_text);
    for id in ["copy-output", "download-output", "toggle-secrets"] {
        let button: HtmlButtonElement = by_id(id)?;
        button.set_disabled(!has_output);
    }
    let clear_results: HtmlButtonElement = by_id("clear-results")?;
    clear_results.set_disabled(!has_accounts && app.issues.is_empty());
    let toggle: HtmlButtonElement = by_id("toggle-secrets")?;
    toggle.set_attribute(
        "aria-pressed",
        if app.reveal_secrets { "true" } else { "false" },
    )?;
    toggle.set_text_content(Some(if app.reveal_secrets {
        "恢复脱敏预览"
    } else {
        "显示完整凭证"
    }));
    let badge = html_element("preview-badge")?;
    badge.set_text_content(Some(if app.reveal_secrets {
        "完整凭证可见"
    } else {
        "已脱敏预览"
    }));
    set_class(badge.as_ref(), "is-revealed", app.reveal_secrets);
    let meta = if !has_accounts {
        "等待账号".to_owned()
    } else if app.format == OutputFormat::Cpa && app.accounts.len() > 1 {
        format!("{} 个认证文件 · ZIP 下载", app.accounts.len())
    } else if app.format == OutputFormat::Cpa {
        "1 个认证文件 · JSON 下载".to_owned()
    } else {
        format!("{} 个账号 · 合并 JSON", app.accounts.len())
    };
    set_text("output-meta", &meta)?;
    render_format(app)
}

fn render(app: &App) -> Result<(), JsValue> {
    render_input(app)?;
    render_accounts(app)?;
    render_issues(app)?;
    render_output(app)
}

fn reset_results(app: &mut App) {
    app.accounts.clear();
    app.issues.clear();
    app.generated_at = None;
    app.reveal_secrets = false;
}

fn cancel_operation(app: &mut App) {
    app.operation_id = app.operation_id.wrapping_add(1);
    app.validation_in_progress = false;
}

fn auto_select_output(app: &mut App, accounts: &[NormalizedAccount]) {
    let sources = accounts
        .iter()
        .map(|account| account.source_type)
        .collect::<HashSet<_>>();
    if sources.len() != 1 {
        return;
    }
    if sources.contains(&SourceType::AgentIdentity) {
        app.format = if output_supported(accounts, OutputFormat::Cpa) {
            OutputFormat::Cpa
        } else {
            OutputFormat::Sub2Api
        };
    } else if sources.contains(&SourceType::Cpa) {
        app.format = OutputFormat::Sub2Api;
    } else if sources.contains(&SourceType::Sub2Api) {
        app.format = OutputFormat::Cpa;
    }
}

fn merge_result(app: &mut App, result: ParseResult, replace: bool) {
    if replace {
        app.accounts.clear();
        app.issues.clear();
    }
    let mut seen = app
        .accounts
        .iter()
        .flat_map(credential_keys)
        .collect::<HashSet<_>>();
    for account in result.accounts {
        let keys = credential_keys(&account);
        if keys.iter().any(|key| seen.contains(key)) {
            app.issues.push(
                ParseIssue::new(&account.source_name, "检测到重复凭证，已忽略")
                    .at_path(&account.source_path),
            );
        } else {
            seen.extend(keys);
            app.accounts.push(account);
        }
    }
    app.issues.extend(result.issues);
    app.generated_at = Some(Date::now());
    app.reveal_secrets = false;
}

fn filter_for_input_mode(
    mut result: ParseResult,
    mode: InputMode,
    source_name: &str,
) -> ParseResult {
    if mode != InputMode::AgentIdentity {
        return result;
    }
    let before = result.accounts.len();
    result
        .accounts
        .retain(|account| account.source_type == SourceType::AgentIdentity);
    let skipped = before.saturating_sub(result.accounts.len());
    if skipped > 0 {
        result.issues.push(ParseIssue::new(
            source_name,
            format!("AI 输入仅接受 Agent Identity JSON，已跳过 {skipped} 个其他凭证"),
        ));
    } else if result.accounts.is_empty() && result.issues.is_empty() {
        result.issues.push(ParseIssue::new(
            source_name,
            "未找到可识别的 Agent Identity 凭证",
        ));
    }
    result
}

fn process_json_input(shared: &SharedApp) -> Result<(), JsValue> {
    let input: HtmlTextAreaElement = by_id("session-input")?;
    let text = input.value();
    let mode = shared.borrow().input_mode;
    if text.trim().is_empty() {
        let message = if mode == InputMode::AgentIdentity {
            "请先粘贴 Agent Identity JSON。"
        } else {
            "请先粘贴 Session、CPA、Sub2API、AI 或 Grok JSON。"
        };
        set_input_status(message, Some("error"))?;
        show_toast("没有可解析的输入", true)?;
        return Ok(());
    }
    if text.len() > MAX_TOTAL_IMPORT_SIZE {
        set_input_status("粘贴内容超过 50 MB，请拆分后再导入。", Some("error"))?;
        show_toast("粘贴内容过大", true)?;
        return Ok(());
    }
    set_input_status("正在本地解析粘贴内容…", Some("working"))?;
    let now = Date::now();
    let result = filter_for_input_mode(
        parse_credential_text(&text, "粘贴内容", now),
        mode,
        "粘贴内容",
    );
    let mut app = shared.borrow_mut();
    cancel_operation(&mut app);
    auto_select_output(&mut app, &result.accounts);
    merge_result(&mut app, result, true);
    render(&app)?;
    if app.accounts.is_empty() {
        let message = if mode == InputMode::AgentIdentity {
            "未找到可导出的 Agent Identity，请检查 JSON 结构与私钥格式。"
        } else {
            "未找到可导出的凭证，请检查 JSON 结构。"
        };
        set_input_status(message, Some("error"))?;
    } else {
        let label = if mode == InputMode::AgentIdentity {
            "AI 本地校验完成"
        } else {
            "解析完成"
        };
        set_input_status(
            &format!(
                "{label}：可导出 {} 个账号，发现 {} 条提示。",
                app.accounts.len(),
                warning_count(&app)
            ),
            Some("success"),
        )?;
    }
    Ok(())
}

fn token_label(mode: InputMode) -> &'static str {
    match mode {
        InputMode::Json => "JSON",
        InputMode::Rt => "RT",
        InputMode::At => "AT",
        InputMode::GrokSso => "SSO",
        InputMode::AgentIdentity => "AI",
    }
}

fn prepare_manual_input(shared: &SharedApp) -> Result<Option<ParseResult>, JsValue> {
    let input: HtmlTextAreaElement = by_id("session-input")?;
    let text = input.value();
    let mode = shared.borrow().input_mode;
    let label = token_label(mode);
    if text.trim().is_empty() {
        let mut app = shared.borrow_mut();
        cancel_operation(&mut app);
        reset_results(&mut app);
        render(&app)?;
        let message = match mode {
            InputMode::At => "请先粘贴 Access Token。",
            InputMode::Rt => "请先粘贴 RT。",
            InputMode::GrokSso => "请先粘贴 SSO。",
            InputMode::Json => "请先粘贴 JSON。",
            InputMode::AgentIdentity => "请先粘贴 Agent Identity JSON。",
        };
        set_input_status(message, Some("error"))?;
        return Ok(None);
    }
    if text.len() > MAX_MANUAL_INPUT_SIZE {
        let mut app = shared.borrow_mut();
        cancel_operation(&mut app);
        reset_results(&mut app);
        render(&app)?;
        set_input_status("Token 输入超过 8 MB，请拆分后再验证。", Some("error"))?;
        return Ok(None);
    }
    let parsed = parse_manual_tokens(&text, mode, &format!("手动 {label}"), Date::now());
    {
        let mut app = shared.borrow_mut();
        cancel_operation(&mut app);
        app.accounts.clear();
        app.issues = parsed.issues.clone();
        app.generated_at = None;
        app.reveal_secrets = false;
        render(&app)?;
    }
    if parsed.accounts.is_empty() {
        let reason = parsed
            .issues
            .first()
            .map(|issue| issue.reason.as_str())
            .unwrap_or("未找到可验证的 token。");
        set_input_status(reason, Some("error"))?;
        return Ok(None);
    }
    set_input_status(
        &format!(
            "已读取 {} 个 {label}，正在准备联网验证…",
            parsed.accounts.len()
        ),
        None,
    )?;
    Ok(Some(parsed))
}

fn should_stop_batch(reason: &str) -> bool {
    [
        "联网验证超时",
        "无法连接",
        "暂不可用",
        "unsupported_country_region_territory",
        "HTTP 500",
        "HTTP 502",
        "HTTP 503",
        "HTTP 504",
    ]
    .iter()
    .any(|needle| reason.contains(needle))
}

fn schedule_validation_watchdog(
    shared: SharedApp,
    operation_id: u64,
    mode: InputMode,
    label: &'static str,
    total: usize,
) -> Result<(), JsValue> {
    let batches = total.div_ceil(TOKEN_VALIDATION_CONCURRENCY);
    let per_batch = if mode == InputMode::GrokSso {
        GROK_SSO_WATCHDOG_PER_BATCH_MS
    } else {
        TOKEN_VALIDATION_WATCHDOG_PER_BATCH_MS
    };
    let delay_ms = i32::try_from(batches)
        .unwrap_or(i32::MAX)
        .saturating_mul(per_batch)
        .saturating_add(TOKEN_VALIDATION_WATCHDOG_MARGIN_MS);
    let callback = Closure::once_into_js(move || {
        let timed_out = {
            let mut app = shared.borrow_mut();
            if app.operation_id != operation_id || !app.validation_in_progress {
                false
            } else {
                app.operation_id = app.operation_id.wrapping_add(1);
                app.validation_in_progress = false;
                app.issues.push(ParseIssue::new(
                    format!("手动 {label}"),
                    "联网验证超时，已停止本次验证；请检查服务端网络后重试",
                ));
                let _ = render(&app);
                true
            }
        };
        if timed_out {
            let _ = set_input_status(
                &format!("{label} 联网验证超时，已停止本次验证。"),
                Some("error"),
            );
            let _ = show_toast(&format!("{label} 联网验证超时"), true);
        }
    });
    window()?.set_timeout_with_callback_and_timeout_and_arguments_0(
        callback.unchecked_ref(),
        delay_ms,
    )?;
    Ok(())
}

fn start_manual_validation(shared: SharedApp) -> Result<(), JsValue> {
    let Some(parsed) = prepare_manual_input(&shared)? else {
        show_toast("Token 输入格式无效", true)?;
        return Ok(());
    };
    let mode = shared.borrow().input_mode;
    let label = token_label(mode);
    let operation_id = {
        let mut app = shared.borrow_mut();
        app.operation_id = app.operation_id.wrapping_add(1);
        app.validation_in_progress = true;
        render_input(&app)?;
        app.operation_id
    };
    let total = parsed.accounts.len();
    let platform = match mode {
        InputMode::Rt => "OpenAI / xAI",
        InputMode::GrokSso => "xAI",
        _ => "OpenAI",
    };
    let first_chunk_end = total.min(TOKEN_VALIDATION_CONCURRENCY);
    let first_range = if first_chunk_end == 1 {
        "1".to_owned()
    } else {
        format!("1 - {first_chunk_end}")
    };
    set_input_status(
        &format!("正在连接 {platform} 验证 {label}：正在处理 {first_range} / {total}…"),
        Some("working"),
    )?;
    if let Err(error) =
        schedule_validation_watchdog(Rc::clone(&shared), operation_id, mode, label, total)
    {
        let mut app = shared.borrow_mut();
        app.validation_in_progress = false;
        render_input(&app)?;
        return Err(error);
    }
    spawn_local(async move {
        let mut resolved = vec![None; total];
        let mut network_issues = Vec::new();
        let mut completed = 0;
        let mut batch_stop = None;

        for chunk_start in (0..total).step_by(TOKEN_VALIDATION_CONCURRENCY) {
            if shared.borrow().operation_id != operation_id {
                return;
            }
            let chunk_end = (chunk_start + TOKEN_VALIDATION_CONCURRENCY).min(total);
            let current = if chunk_end == chunk_start + 1 {
                chunk_end.to_string()
            } else {
                format!("{} - {}", chunk_start + 1, chunk_end)
            };
            let _ = set_input_status(
                &format!("正在连接 {platform} 验证 {label}：正在处理 {current} / {total}…"),
                Some("working"),
            );
            let jobs = parsed.accounts[chunk_start..chunk_end]
                .iter()
                .cloned()
                .enumerate()
                .map(|(offset, source)| {
                    let index = chunk_start + offset;
                    async move {
                        let token = if mode == InputMode::At {
                            Some(source.access_token.clone())
                        } else {
                            source.refresh_token.clone()
                        };
                        let result = match (mode, token.as_deref()) {
                            (InputMode::At, Some(token)) => {
                                api::validate_access_token(token).await.and_then(|info| {
                                    normalize_validated_at(token, &info, index, Date::now())
                                })
                            }
                            (InputMode::Rt, Some(token)) => api::refresh_token(token)
                                .await
                                .and_then(|(kind, info)| match kind {
                                    RefreshTokenKind::OpenAi => {
                                        normalize_refreshed_rt(token, &info, index, Date::now())
                                    }
                                    RefreshTokenKind::Grok => normalize_grok_oauth(
                                        Some(token),
                                        &info,
                                        mode,
                                        index,
                                        Date::now(),
                                    ),
                                }),
                            (InputMode::GrokSso, Some(token)) => {
                                api::convert_grok_sso(token).await.and_then(|info| {
                                    normalize_grok_oauth(None, &info, mode, index, Date::now())
                                })
                            }
                            _ => Err(format!("未找到可验证的 {label}")),
                        };
                        (index, source, result)
                    }
                });
            for (index, source, result) in join_all(jobs).await {
                completed += 1;
                match result {
                    Ok(account) => resolved[index] = Some(account),
                    Err(reason) => {
                        if should_stop_batch(&reason) && batch_stop.is_none() {
                            batch_stop = Some(reason.clone());
                        }
                        network_issues.push(
                            ParseIssue::new(source.source_name, reason).at_path(source.source_path),
                        );
                    }
                }
            }
            if shared.borrow().operation_id != operation_id {
                return;
            }
            let _ = set_input_status(
                &format!("正在连接 {platform} 验证 {label}：{completed} / {total}…"),
                Some("working"),
            );
            if batch_stop.is_some() {
                break;
            }
        }

        if shared.borrow().operation_id != operation_id {
            return;
        }
        if let Some(reason) = batch_stop {
            network_issues.insert(
                0,
                ParseIssue::new("批量验证", format!("批量验证已停止：{reason}")),
            );
        }
        let accounts = resolved.into_iter().flatten().collect::<Vec<_>>();
        let failure_count = network_issues.len();
        {
            let mut app = shared.borrow_mut();
            app.validation_in_progress = false;
            let mut issues = parsed.issues;
            issues.extend(network_issues);
            merge_result(&mut app, ParseResult { accounts, issues }, true);
            if render(&app).is_err() {
                return;
            }
            let success_count = app.accounts.len();
            let _ = if success_count > 0 {
                set_input_status(
                    &format!(
                        "{label} 验证完成：成功 {success_count} 个，失败 {failure_count} 个。"
                    ),
                    Some(if failure_count > 0 {
                        "error"
                    } else {
                        "success"
                    }),
                )
            } else {
                set_input_status(
                    &format!("{label} 验证失败，请展开提示查看原因。"),
                    Some("error"),
                )
            };
        }
    });
    Ok(())
}

fn process_current_input(shared: &SharedApp) -> Result<(), JsValue> {
    if is_json_input_mode(shared.borrow().input_mode) {
        process_json_input(shared)
    } else {
        start_manual_validation(Rc::clone(shared))
    }
}

fn file_source_name(file: &File) -> String {
    Reflect::get(file.as_ref(), &JsValue::from_str("webkitRelativePath"))
        .ok()
        .and_then(|value| value.as_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| file.name())
}

fn collect_files(list: &FileList) -> Vec<File> {
    (0..list.length())
        .filter_map(|index| list.item(index))
        .collect()
}

fn process_files(shared: SharedApp, files: Vec<File>) {
    let mode = shared.borrow().input_mode;
    if !is_json_input_mode(mode) {
        return;
    }
    let operation_id = {
        let mut app = shared.borrow_mut();
        cancel_operation(&mut app);
        app.operation_id
    };
    spawn_local(async move {
        let candidates = files
            .into_iter()
            .filter(|file| file.name().to_ascii_lowercase().ends_with(".json"))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            let _ = set_input_status("没有找到 JSON 文件。", Some("error"));
            let _ = show_toast("请选择 JSON 文件", true);
            return;
        }
        let candidate_count = candidates.len();
        let _ = set_input_status(
            &format!("正在读取并解析 {} 个文件…", candidate_count.min(MAX_FILES)),
            Some("working"),
        );
        let mut total_size = 0_usize;
        let mut issues = Vec::new();
        let mut readable = Vec::new();
        let mut skipped_total = false;
        for file in candidates.into_iter().take(MAX_FILES) {
            let source_name = file_source_name(&file);
            if file.size() > MAX_FILE_SIZE {
                issues.push(ParseIssue::new(source_name, "文件超过 10 MB，已跳过"));
                continue;
            }
            let file_size = file.size() as usize;
            if total_size.saturating_add(file_size) > MAX_TOTAL_IMPORT_SIZE {
                skipped_total = true;
                continue;
            }
            total_size += file_size;
            readable.push(file);
        }
        let mut results = Vec::new();
        for file in readable {
            let source_name = file_source_name(&file);
            match JsFuture::from(file.text()).await {
                Ok(value) => results.push(filter_for_input_mode(
                    parse_credential_text(
                        &value.as_string().unwrap_or_default(),
                        &source_name,
                        Date::now(),
                    ),
                    mode,
                    &source_name,
                )),
                Err(_) => results.push(ParseResult {
                    accounts: Vec::new(),
                    issues: vec![ParseIssue::new(source_name, "无法读取文件")],
                }),
            }
        }
        if shared.borrow().operation_id != operation_id || shared.borrow().input_mode != mode {
            return;
        }
        let mut app = shared.borrow_mut();
        if app.accounts.is_empty() {
            let imported_accounts = results
                .iter()
                .flat_map(|result| result.accounts.iter().cloned())
                .collect::<Vec<_>>();
            auto_select_output(&mut app, &imported_accounts);
        }
        for result in results {
            merge_result(&mut app, result, false);
        }
        app.issues.extend(issues);
        if skipped_total {
            app.issues.push(ParseIssue::new(
                "文件导入",
                "导入文件总大小超过 50 MB，超出部分已跳过",
            ));
        }
        if candidate_count > MAX_FILES {
            app.issues.push(ParseIssue::new(
                "文件导入",
                "一次最多处理 500 个文件，其余文件已跳过",
            ));
        }
        let _ = render(&app);
        let _ = if app.accounts.is_empty() {
            set_input_status(
                if mode == InputMode::AgentIdentity {
                    "文件中未找到可导出的 Agent Identity。"
                } else {
                    "文件中未找到可导出的 Session、CPA、Sub2API、AI 或 Grok 账号。"
                },
                Some("error"),
            )
        } else {
            set_input_status(
                &format!(
                    "文件解析完成：当前共有 {} 个可导出账号，{} 条提示。",
                    app.accounts.len(),
                    warning_count(&app)
                ),
                Some("success"),
            )
        };
    });
}

async fn copy_output(shared: SharedApp) {
    let text = {
        let app = shared.borrow();
        current_document(&app)
            .and_then(|document| serde_json::to_string_pretty(&document).ok())
            .unwrap_or_default()
    };
    if text.is_empty() {
        return;
    }
    let result = window()
        .map(|window| window.navigator().clipboard())
        .map(|clipboard| JsFuture::from(clipboard.write_text(&text)));
    if let Ok(future) = result {
        if future.await.is_ok() {
            let _ = show_toast("完整 JSON 已复制", false);
            return;
        }
    }
    let _ = show_toast("浏览器拒绝了剪贴板操作", true);
}

fn make_blob(bytes: Option<&[u8]>, text: Option<&str>, mime: &str) -> Result<Blob, JsValue> {
    let options = BlobPropertyBag::new();
    options.set_type(mime);
    if let Some(bytes) = bytes {
        let parts = Array::new();
        parts.push(&Uint8Array::from(bytes));
        Blob::new_with_u8_array_sequence_and_options(parts.as_ref(), &options)
    } else {
        let parts = Array::new();
        parts.push(&JsValue::from_str(text.unwrap_or_default()));
        Blob::new_with_str_sequence_and_options(parts.as_ref(), &options)
    }
}

fn trigger_download(blob: &Blob, file_name: &str) -> Result<(), JsValue> {
    let url = Url::create_object_url_with_blob(blob)?;
    let anchor: HtmlAnchorElement = document()?.create_element("a")?.dyn_into()?;
    anchor.set_href(&url);
    anchor.set_download(file_name);
    anchor.set_hidden(true);
    document()
        .and_then(|document| {
            document
                .body()
                .ok_or_else(|| JsValue::from_str("body 不可用"))
        })?
        .append_child(&anchor)?;
    anchor.click();
    anchor.remove();
    let callback = Closure::once_into_js(move || {
        let _ = Url::revoke_object_url(&url);
    });
    window()?
        .set_timeout_with_callback_and_timeout_and_arguments_0(callback.unchecked_ref(), 1_000)?;
    Ok(())
}

fn download(shared: &SharedApp, index: Option<usize>) -> Result<(), JsValue> {
    let app = shared.borrow();
    let accounts = index
        .and_then(|index| app.accounts.get(index))
        .map(std::slice::from_ref)
        .unwrap_or(app.accounts.as_slice());
    if accounts.is_empty() {
        return Ok(());
    }
    let now = app.generated_at.unwrap_or_else(Date::now);
    let descriptor = download_descriptor(accounts, app.format, now)
        .map_err(|error| JsValue::from_str(&error))?;
    let file_name = match descriptor {
        DownloadDescriptor::Json {
            file_name,
            document,
        } => {
            let text = format!(
                "{}\n",
                serde_json::to_string_pretty(&document).unwrap_or_default()
            );
            trigger_download(
                &make_blob(None, Some(&text), "application/json;charset=utf-8")?,
                &file_name,
            )?;
            file_name
        }
        DownloadDescriptor::Zip { file_name, entries } => {
            let bytes = build_zip(&entries, now).map_err(|error| JsValue::from_str(&error))?;
            trigger_download(
                &make_blob(Some(&bytes), None, "application/zip")?,
                &file_name,
            )?;
            file_name
        }
    };
    show_toast(&format!("已生成 {file_name}"), false)
}

fn listen_event<T, F>(target: &T, name: &str, callback: F) -> Result<(), JsValue>
where
    T: AsRef<EventTarget>,
    F: 'static + FnMut(Event),
{
    let closure = Closure::<dyn FnMut(Event)>::wrap(Box::new(callback));
    target
        .as_ref()
        .add_event_listener_with_callback(name, closure.as_ref().unchecked_ref())?;
    closure.forget();
    Ok(())
}

fn listen_keyboard<T, F>(target: &T, callback: F) -> Result<(), JsValue>
where
    T: AsRef<EventTarget>,
    F: 'static + FnMut(KeyboardEvent),
{
    let closure = Closure::<dyn FnMut(KeyboardEvent)>::wrap(Box::new(callback));
    target
        .as_ref()
        .add_event_listener_with_callback("keydown", closure.as_ref().unchecked_ref())?;
    closure.forget();
    Ok(())
}

fn listen_drag<T, F>(target: &T, name: &str, callback: F) -> Result<(), JsValue>
where
    T: AsRef<EventTarget>,
    F: 'static + FnMut(DragEvent),
{
    let closure = Closure::<dyn FnMut(DragEvent)>::wrap(Box::new(callback));
    target
        .as_ref()
        .add_event_listener_with_callback(name, closure.as_ref().unchecked_ref())?;
    closure.forget();
    Ok(())
}

fn schedule_input_processing(shared: &SharedApp, delay_ms: i32) -> Result<(), JsValue> {
    let operation_id = {
        let mut app = shared.borrow_mut();
        app.operation_id = app.operation_id.wrapping_add(1);
        app.operation_id
    };
    let callback_shared = Rc::clone(shared);
    let callback = Closure::once_into_js(move || {
        if callback_shared.borrow().operation_id != operation_id {
            return;
        }
        let _ = process_current_input(&callback_shared);
    });
    window()?.set_timeout_with_callback_and_timeout_and_arguments_0(
        callback.unchecked_ref(),
        delay_ms,
    )?;
    Ok(())
}

fn bind_segmented_controls(shared: &SharedApp) -> Result<(), JsValue> {
    for (id, format) in FORMAT_CONTROLS {
        let button: HtmlButtonElement = by_id(id)?;
        let click_shared = Rc::clone(shared);
        listen_event(&button, "click", move |_| {
            let mut app = click_shared.borrow_mut();
            if !output_supported(&app.accounts, format) {
                let message = output_unsupported_reason(&app.accounts, format)
                    .unwrap_or("当前凭证无法导出为所选格式");
                drop(app);
                let _ = show_toast(message, true);
                return;
            }
            app.format = format;
            app.reveal_secrets = false;
            let _ = render(&app);
        })?;
        let key_shared = Rc::clone(shared);
        listen_keyboard(&button, move |event| {
            let next = match event.key().as_str() {
                "ArrowLeft" | "ArrowUp" | "ArrowRight" | "ArrowDown" | "Home" | "End" => {
                    Some(if format == OutputFormat::Sub2Api {
                        OutputFormat::Cpa
                    } else {
                        OutputFormat::Sub2Api
                    })
                }
                _ => None,
            };
            if let Some(next) = next {
                event.prevent_default();
                let mut app = key_shared.borrow_mut();
                if !output_supported(&app.accounts, next) {
                    let message = output_unsupported_reason(&app.accounts, next)
                        .unwrap_or("当前凭证无法导出为所选格式");
                    drop(app);
                    let _ = show_toast(message, true);
                    return;
                }
                app.format = next;
                app.reveal_secrets = false;
                let _ = render(&app);
                let id = if next == OutputFormat::Cpa {
                    "format-cpa"
                } else {
                    "format-sub2api"
                };
                let _ = by_id::<HtmlButtonElement>(id).and_then(|button| button.focus());
            }
        })?;
    }
    for (id, mode) in INPUT_MODE_CONTROLS {
        let button: HtmlButtonElement = by_id(id)?;
        let click_shared = Rc::clone(shared);
        listen_event(&button, "click", move |_| {
            let mut app = click_shared.borrow_mut();
            if app.input_mode == mode || app.validation_in_progress {
                return;
            }
            cancel_operation(&mut app);
            app.input_mode = mode;
            reset_results(&mut app);
            if let Ok(input) = by_id::<HtmlTextAreaElement>("session-input") {
                input.set_value("");
                let _ = input.focus();
            }
            let _ = render(&app);
            let _ = set_input_status(
                if mode == InputMode::Json {
                    "已切换为 JSON 输入。".to_owned()
                } else if mode == InputMode::AgentIdentity {
                    "已切换为 AI 输入，本地校验 Agent Identity JSON。".to_owned()
                } else {
                    format!("已切换为手动 {} 输入。", token_label(mode))
                }
                .as_str(),
                None,
            );
        })?;
    }
    Ok(())
}

fn bind_input(shared: &SharedApp) -> Result<(), JsValue> {
    let input: HtmlTextAreaElement = by_id("session-input")?;
    let paste_shared = Rc::clone(shared);
    listen_event(&input, "paste", move |_| {
        let _ = schedule_input_processing(&paste_shared, 0);
    })?;
    let input_shared = Rc::clone(shared);
    listen_event(&input, "input", move |_| {
        if !is_json_input_mode(input_shared.borrow().input_mode) {
            let _ = schedule_input_processing(&input_shared, 450);
        }
    })?;
    let key_shared = Rc::clone(shared);
    listen_keyboard(&input, move |event| {
        if (event.ctrl_key() || event.meta_key()) && event.key() == "Enter" {
            event.prevent_default();
            {
                let mut app = key_shared.borrow_mut();
                app.operation_id = app.operation_id.wrapping_add(1);
            }
            let _ = process_current_input(&key_shared);
        }
    })?;
    Ok(())
}

fn bind_file_controls(shared: &SharedApp) -> Result<(), JsValue> {
    let pick_files: HtmlButtonElement = by_id("pick-files")?;
    listen_event(&pick_files, "click", move |event| {
        event.stop_propagation();
        if let Ok(input) = by_id::<HtmlInputElement>("file-input") {
            input.click();
        }
    })?;
    let pick_folder: HtmlButtonElement = by_id("pick-folder")?;
    listen_event(&pick_folder, "click", move |event| {
        event.stop_propagation();
        if let Ok(input) = by_id::<HtmlInputElement>("folder-input") {
            input.click();
        }
    })?;
    for id in ["file-input", "folder-input"] {
        let input: HtmlInputElement = by_id(id)?;
        let change_shared = Rc::clone(shared);
        let cloned_input = input.clone();
        listen_event(&input, "change", move |_| {
            if let Some(files) = cloned_input.files() {
                process_files(Rc::clone(&change_shared), collect_files(&files));
            }
            cloned_input.set_value("");
        })?;
    }
    let dropzone = html_element("dropzone")?;
    for name in ["dragenter", "dragover"] {
        let target = dropzone.clone();
        listen_drag(&dropzone, name, move |event| {
            event.prevent_default();
            set_class(target.as_ref(), "is-dragging", true);
        })?;
    }
    for name in ["dragleave", "drop"] {
        let target = dropzone.clone();
        listen_drag(&dropzone, name, move |event| {
            event.prevent_default();
            set_class(target.as_ref(), "is-dragging", false);
        })?;
    }
    let drop_shared = Rc::clone(shared);
    listen_drag(&dropzone, "drop", move |event| {
        if is_json_input_mode(drop_shared.borrow().input_mode) {
            if let Some(files) = event.data_transfer().and_then(|transfer| transfer.files()) {
                process_files(Rc::clone(&drop_shared), collect_files(&files));
            }
        }
    })?;
    Ok(())
}

fn bind_actions(shared: &SharedApp) -> Result<(), JsValue> {
    let theme_toggle: HtmlButtonElement = by_id("theme-toggle")?;
    listen_event(&theme_toggle, "click", move |_| {
        if let Ok(light) = is_light_theme() {
            let _ = set_theme(!light);
        }
    })?;

    let clear_all: HtmlButtonElement = by_id("clear-all")?;
    let clear_shared = Rc::clone(shared);
    listen_event(&clear_all, "click", move |_| {
        let mut app = clear_shared.borrow_mut();
        cancel_operation(&mut app);
        reset_results(&mut app);
        if let Ok(input) = by_id::<HtmlTextAreaElement>("session-input") {
            input.set_value("");
        }
        let _ = render(&app);
        let _ = set_input_status("已清空输入和转换结果。", None);
    })?;
    let clear_results: HtmlButtonElement = by_id("clear-results")?;
    let clear_result_shared = Rc::clone(shared);
    listen_event(&clear_results, "click", move |_| {
        let mut app = clear_result_shared.borrow_mut();
        cancel_operation(&mut app);
        reset_results(&mut app);
        let _ = render(&app);
        let _ = set_input_status("已清除转换结果，输入内容仍保留。", None);
    })?;
    let reveal: HtmlButtonElement = by_id("toggle-secrets")?;
    let reveal_shared = Rc::clone(shared);
    listen_event(&reveal, "click", move |_| {
        let mut app = reveal_shared.borrow_mut();
        app.reveal_secrets = !app.reveal_secrets;
        let _ = render_output(&app);
    })?;
    let copy: HtmlButtonElement = by_id("copy-output")?;
    let copy_shared = Rc::clone(shared);
    listen_event(&copy, "click", move |_| {
        spawn_local(copy_output(Rc::clone(&copy_shared)));
    })?;
    let download_button: HtmlButtonElement = by_id("download-output")?;
    let download_shared = Rc::clone(shared);
    listen_event(&download_button, "click", move |_| {
        if let Err(error) = download(&download_shared, None) {
            let _ = show_toast(
                &error.as_string().unwrap_or_else(|| "下载失败".to_owned()),
                true,
            );
        }
    })?;
    let account_body: HtmlTableSectionElement = by_id("account-body")?;
    let single_shared = Rc::clone(shared);
    listen_event(&account_body, "click", move |event| {
        let target = event
            .target()
            .and_then(|target| target.dyn_into::<Element>().ok());
        let button =
            target.and_then(|target| target.closest("[data-download-index]").ok().flatten());
        let index = button
            .and_then(|button| button.get_attribute("data-download-index"))
            .and_then(|value| value.parse::<usize>().ok());
        if let Some(index) = index {
            if let Err(error) = download(&single_shared, Some(index)) {
                let _ = show_toast(
                    &error.as_string().unwrap_or_else(|| "下载失败".to_owned()),
                    true,
                );
            }
        }
    })?;
    Ok(())
}

pub fn start() -> Result<(), JsValue> {
    let shared = Rc::new(RefCell::new(App::default()));
    set_theme(is_light_theme()?)?;
    bind_segmented_controls(&shared)?;
    bind_input(&shared)?;
    bind_file_controls(&shared)?;
    bind_actions(&shared)?;
    render(&shared.borrow())
}
