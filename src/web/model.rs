use serde_json::{Map, Value};

pub type JsonMap = Map<String, Value>;

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub enum OutputFormat {
    #[default]
    Sub2Api,
    Cpa,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub enum InputMode {
    #[default]
    Json,
    Rt,
    At,
    GrokSso,
    AgentIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RefreshTokenKind {
    OpenAi,
    Grok,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SourceType {
    ChatGptWebSession,
    Cpa,
    Sub2Api,
    ManualAt,
    ManualRt,
    ManualMobileRt,
    ManualGrokRt,
    ManualGrokSso,
    AgentIdentity,
}

impl SourceType {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ChatGptWebSession => "SESSION",
            Self::Cpa => "CPA",
            Self::Sub2Api => "Sub2API",
            Self::ManualAt => "AT",
            Self::ManualRt => "RT",
            Self::ManualMobileRt => "Mobile RT",
            Self::ManualGrokRt => "Grok RT",
            Self::ManualGrokSso => "SSO",
            Self::AgentIdentity => "AI",
        }
    }

    pub const fn key(self) -> &'static str {
        match self {
            Self::ChatGptWebSession => "chatgpt_web_session",
            Self::Cpa => "cpa",
            Self::Sub2Api => "sub2api",
            Self::ManualAt => "manual_at",
            Self::ManualRt => "manual_rt",
            Self::ManualMobileRt => "manual_mobile_rt",
            Self::ManualGrokRt => "manual_grok_rt",
            Self::ManualGrokSso => "manual_grok_sso",
            Self::AgentIdentity => "agent_identity",
        }
    }
}

#[derive(Clone, Default)]
pub struct Sub2ApiSettings {
    pub name: Option<String>,
    pub platform: Option<String>,
    pub account_type: Option<String>,
    pub concurrency: Option<f64>,
    pub priority: Option<f64>,
    pub rate_multiplier: Option<f64>,
    pub auto_pause_on_expired: Option<bool>,
    pub expires_at: Option<i64>,
    pub disabled: Option<bool>,
    pub credentials: JsonMap,
    pub extra: JsonMap,
    pub account_fields: JsonMap,
    pub original_credential_keys: Vec<String>,
    pub document_fields: Option<JsonMap>,
}

#[derive(Clone)]
pub struct NormalizedAccount {
    pub source_name: String,
    pub source_path: String,
    pub source_type: SourceType,
    pub name: String,
    pub email: Option<String>,
    pub account_id: Option<String>,
    pub user_id: Option<String>,
    pub plan_type: Option<String>,
    pub organization_id: Option<String>,
    pub auth_provider: String,
    pub access_token: String,
    pub session_token: Option<String>,
    pub refresh_token: Option<String>,
    pub input_id_token: Option<String>,
    pub id_token: Option<String>,
    pub id_token_synthetic: bool,
    pub token_expires_at: Option<String>,
    pub access_token_expires_at: Option<i64>,
    pub export_expires_at: Option<String>,
    pub last_refresh: String,
    pub disabled: bool,
    pub is_refreshable: bool,
    pub is_expired: bool,
    pub warnings: Vec<String>,
    pub preserved_cpa_fields: Option<JsonMap>,
    pub sub2api_settings: Option<Sub2ApiSettings>,
}

#[derive(Clone)]
pub struct ParseIssue {
    pub source_name: String,
    pub source_path: Option<String>,
    pub reason: String,
}

impl ParseIssue {
    pub fn new(source_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            source_path: None,
            reason: reason.into(),
        }
    }

    pub fn at_path(mut self, source_path: impl Into<String>) -> Self {
        self.source_path = Some(source_path.into());
        self
    }
}

pub struct ParseResult {
    pub accounts: Vec<NormalizedAccount>,
    pub issues: Vec<ParseIssue>,
}

pub struct ArchiveEntry {
    pub file_name: String,
    pub text: String,
}

pub enum DownloadDescriptor {
    Json {
        file_name: String,
        document: Value,
    },
    Zip {
        file_name: String,
        entries: Vec<ArchiveEntry>,
    },
}

pub struct OAuthTokenInfo {
    pub fields: JsonMap,
    pub client_id: String,
}

pub struct PersonalAccessTokenInfo {
    pub email: String,
    pub user_id: String,
    pub account_id: String,
    pub plan_type: String,
    pub is_fedramp: bool,
}
