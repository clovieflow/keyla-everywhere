//! Kiro (AWS CodeWhisperer) adapter.
//!
//! Ported from `src/providers/integrations/kiro/` (`kiro.ts`,
//! `kiro-request.ts`, `kiro-stream.ts`, `aws-event-stream.ts`,
//! `kiro-machine-id.ts`, `kiro-profile.ts`, `kiro-catalog.ts`,
//! `kiro-discovery.ts`, `kiro-quota.ts`).
//!
//! Kiro does not speak a chat-shaped protocol: a request is a
//! `conversationState` ledger, and the answer is an AWS EventStream binary frame
//! sequence, so this adapter bypasses the canonical codecs and translates the
//! wire itself.
//!
//! There is exactly one generation surface, `q.{region}.amazonaws.com`. The
//! legacy `codewhisperer.*` host is not what the real client talks to, and a
//! refusal is reported rather than replayed onto another service entry. Every
//! request carries a device identity (`KiroIDE-{version}-{machineId}`) and
//! closes its connection, and the profile ARN is never manufactured: the
//! account's own resolved profile is used when its sign-in produced one, and
//! the family default is resolved in [`resolve_kiro_profile_arn`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use futures_util::stream::StreamExt;
use keyla_core::{
    CanonicalEvent, CanonicalMessage, CanonicalRequest, CanonicalStopReason, ContentPart,
    GatewayError, GatewayErrorCode, GatewayErrorOrigin, ReasoningEffort, Role, TerminalState,
    TokenCount, ToolDefinition, ToolResultContent, UsageRecord,
};
use keyla_protocol::primitives::{resolve_image_source, split_data_url};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapter::{DispatchCredential, DispatchOutput, DispatchTarget, upstream_http_error};

/// Provider id this adapter registers under.
pub const KIRO_PROVIDER_ID: &str = "kiro";

/// The generation RPC path.
pub const KIRO_GENERATE_PATH: &str = "/generateAssistantResponse";

/// Base URL this provider registers.
pub const KIRO_BASE_URL: &str = "https://q.us-east-1.amazonaws.com";

/// Longest single message this adapter will buffer before treating the stream
/// as corrupt.
const KIRO_MAX_STREAM_BUFFER_BYTES: usize = 24 * 1024 * 1024;

/// Response header the upstream sets on a streaming answer.
const KIRO_STREAM_ACCEPT: &str = "application/vnd.amazon.eventstream";

/// Fallback IDE version stamped into the device marker. The TypeScript client
/// discovers this from the vendor's download page; the Rust port pins the
/// published fallback.
pub const KIRO_IDE_VERSION: &str = "1.2.4";
/// Runtime SDK version stamped into the generation User-Agent.
pub const KIRO_RUNTIME_SDK_VERSION: &str = "1.0.39";
/// AWS SSO OIDC SDK version stamped into login and token-refresh User-Agents.
pub const KIRO_SSO_SDK_VERSION: &str = "3.980.0";
/// Host segment the observed Kiro client reports.
pub const KIRO_SYSTEM_VERSION: &str = "win32#10.0.22631";
/// Node version the observed Kiro client reports.
pub const KIRO_NODE_VERSION: &str = "24.18.0";

/// Longest tool name the upstream accepts, counted in code points.
pub const KIRO_TOOL_NAME_MAX_LENGTH: usize = 64;
/// Longest tool description the upstream accepts, counted in code points.
pub const KIRO_TOOL_DESCRIPTION_MAX_LENGTH: usize = 10_237;
/// Longest tool call id the upstream accepts, counted in code points.
pub const KIRO_TOOL_ID_MAX_LENGTH: usize = 64;
/// Default thinking budget when a caller asks for thinking without a size.
pub const KIRO_THINKING_BUDGET_DEFAULT: i64 = 16_000;
/// Upstream ceiling on the thinking budget marker.
pub const KIRO_THINKING_BUDGET_MAX: i64 = 32_000;

/// Text substituted for a user turn carrying tool results but no text.
pub const KIRO_TOOL_RESULTS_PLACEHOLDER: &str = "Tool results provided.";
/// Text substituted for a user turn with nothing at all.
pub const KIRO_EMPTY_USER_PLACEHOLDER: &str = "continue";
/// Text substituted for an empty assistant turn.
pub const KIRO_EMPTY_ASSISTANT_PLACEHOLDER: &str = "...";

// ─── Auth state ─────────────────────────────────────────────────────────────

/// Non-secret per-account auth configuration, as stored on the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KiroAuthState {
    pub auth_method: String,
    pub region: String,
    pub profile_arn: Option<String>,
    pub machine_id: Option<String>,
}

/// Reads the account's stored auth configuration, or `None` when absent.
pub fn read_kiro_auth_state(raw: Option<&Value>) -> Option<KiroAuthState> {
    let raw = raw?.as_object()?;
    let auth_method = raw.get("authMethod").and_then(Value::as_str)?;
    let region = raw
        .get("region")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("us-east-1");
    let profile_arn = raw
        .get("profileArn")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let machine_id = raw
        .get("machineId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    Some(KiroAuthState {
        auth_method: auth_method.to_owned(),
        region: region.to_owned(),
        profile_arn: profile_arn.map(str::to_owned),
        machine_id: machine_id.map(str::to_owned),
    })
}

/// `true` when `region` has the shape of an AWS region.
pub fn is_aws_region(region: &str) -> bool {
    let bytes = region.as_bytes();
    if bytes.len() < 6 {
        return false;
    }
    let mut index = 0;
    let mut letters = 0;
    while index < bytes.len() && bytes[index].is_ascii_lowercase() {
        index += 1;
        letters += 1;
    }
    if letters != 2 || index >= bytes.len() || bytes[index] != b'-' {
        return false;
    }
    index += 1;
    let mut middle = 0;
    while index < bytes.len() && bytes[index].is_ascii_lowercase() {
        index += 1;
        middle += 1;
    }
    if middle == 0 || index >= bytes.len() || bytes[index] != b'-' {
        return false;
    }
    index += 1;
    let mut digits = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
        digits += 1;
    }
    (1..=2).contains(&digits) && index == bytes.len()
}

/// Region validated before interpolation into an endpoint URL.
fn safe_region(auth_state: Option<&KiroAuthState>) -> String {
    let region = auth_state
        .map(|state| state.region.as_str())
        .unwrap_or("us-east-1");
    if is_aws_region(region) {
        region.to_owned()
    } else {
        "us-east-1".to_owned()
    }
}

/// The single generation endpoint this adapter posts to.
pub fn kiro_endpoint(auth_state: Option<&KiroAuthState>) -> String {
    format!(
        "https://q.{}.amazonaws.com{}",
        safe_region(auth_state),
        KIRO_GENERATE_PATH
    )
}

// ─── Client identity ────────────────────────────────────────────────────────

/// `x-amz-user-agent` companion for the generation surface.
pub fn build_kiro_amz_user_agent(version: &str, machine_id: &str) -> String {
    format!("aws-sdk-js/{KIRO_RUNTIME_SDK_VERSION} KiroIDE-{version}-{machine_id}")
}

/// Full data-plane `user-agent`.
pub fn build_kiro_user_agent(version: &str, machine_id: &str) -> String {
    format!(
        "aws-sdk-js/{KIRO_RUNTIME_SDK_VERSION} ua/2.1 os/{KIRO_SYSTEM_VERSION} lang/js md/nodejs#{KIRO_NODE_VERSION} api/codewhispererstreaming#{KIRO_RUNTIME_SDK_VERSION} m/E KiroIDE-{version}-{machine_id}"
    )
}

/// `x-amz-user-agent` companion for an AWS SSO OIDC request.
pub fn build_kiro_sso_amz_user_agent() -> String {
    format!("aws-sdk-js/{KIRO_SSO_SDK_VERSION} KiroIDE")
}

/// Full `user-agent` for an AWS SSO OIDC request.
pub fn build_kiro_sso_user_agent() -> String {
    format!(
        "aws-sdk-js/{KIRO_SSO_SDK_VERSION} ua/2.1 os/{KIRO_SYSTEM_VERSION} lang/js md/nodejs#{KIRO_NODE_VERSION} api/sso-oidc#{KIRO_SSO_SDK_VERSION} m/E KiroIDE"
    )
}

/// `user-agent` the model-catalog and usage surfaces expect.
pub fn build_kiro_runtime_user_agent(version: &str, machine_id: &str) -> String {
    format!(
        "aws-sdk-js/{KIRO_RUNTIME_SDK_VERSION} ua/2.1 os/{KIRO_SYSTEM_VERSION} lang/js md/nodejs#{KIRO_NODE_VERSION} api/codewhispererruntime#{KIRO_RUNTIME_SDK_VERSION} m/N,E KiroIDE-{version}-{machine_id}"
    )
}

/// Builds the request headers for one generation request.
pub fn kiro_headers(
    secret: &str,
    auth_state: Option<&KiroAuthState>,
    machine_id: &str,
) -> Vec<(String, String)> {
    let version = KIRO_IDE_VERSION;
    let mut headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("accept".to_owned(), KIRO_STREAM_ACCEPT.to_owned()),
        ("connection".to_owned(), "close".to_owned()),
        ("x-amzn-codewhisperer-optout".to_owned(), "true".to_owned()),
        ("x-amzn-kiro-agent-mode".to_owned(), "spec".to_owned()),
        ("amz-sdk-request".to_owned(), "attempt=1; max=3".to_owned()),
        (
            "amz-sdk-invocation-id".to_owned(),
            Uuid::new_v4().to_string(),
        ),
        (
            "user-agent".to_owned(),
            build_kiro_user_agent(version, machine_id),
        ),
        (
            "x-amz-user-agent".to_owned(),
            build_kiro_amz_user_agent(version, machine_id),
        ),
        ("authorization".to_owned(), format!("Bearer {secret}")),
    ];
    match auth_state.map(|state| state.auth_method.as_str()) {
        Some("api_key") => headers.push(("tokentype".to_owned(), "API_KEY".to_owned())),
        Some("external_idp") => {
            headers.push(("tokentype".to_owned(), "EXTERNAL_IDP".to_owned()));
        }
        _ => {}
    }
    headers
}

// ─── Machine identity ───────────────────────────────────────────────────────

const OAUTH_SALT: &str = "KotlinNativeAPI/";
const API_KEY_SALT: &str = "KiroAPIKey/";
const FALLBACK_SALT: &str = "KiroFallback/";
const MACHINE_ID_LENGTH: usize = 64;

fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Normalizes a machine id supplied from outside the derivation.
pub fn normalize_machine_id(raw: Option<&Value>) -> Option<String> {
    let value = raw?.as_str()?.trim().to_lowercase();
    if value.len() == MACHINE_ID_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(value);
    }
    if value.len() == MACHINE_ID_LENGTH / 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(format!("{value}{value}"));
    }
    None
}

/// Derives the machine id an OAuth (refresh-token) credential presents.
pub fn derive_oauth_machine_id(refresh_token: &str) -> String {
    sha256_hex(&format!("{OAUTH_SALT}{refresh_token}"))
}

/// Derives the machine id an API-key credential presents.
pub fn derive_api_key_machine_id(api_key: &str) -> String {
    sha256_hex(&format!("{API_KEY_SALT}{api_key}"))
}

/// Derives the fallback machine id for a credential with no derivable
/// material.
pub fn fallback_machine_id(account_id: &str) -> String {
    sha256_hex(&format!("{FALLBACK_SALT}{account_id}"))
}

/// Resolves the device identity one account presents, from its stored
/// configuration.
pub fn machine_id_for_auth_state(raw: Option<&Value>, account_id: Option<&str>) -> String {
    let object = raw.and_then(Value::as_object);
    if let Some(frozen) = normalize_machine_id(object.and_then(|value| value.get("machineId"))) {
        return frozen;
    }
    let field = |name: &str| {
        object
            .and_then(|value| value.get(name))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_owned()
    };
    let client_id = field("clientId");
    let profile_arn = field("profileArn");
    let start_url = field("startUrl");
    let material = account_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| (!client_id.is_empty()).then_some(client_id))
        .or_else(|| (!profile_arn.is_empty()).then_some(profile_arn))
        .or_else(|| (!start_url.is_empty()).then_some(start_url))
        .unwrap_or_default();
    fallback_machine_id(&material)
}

/// Resolves the machine id for one credential during login.
pub fn resolve_machine_id(
    frozen: Option<&Value>,
    auth_method: &str,
    refresh_token: &str,
    api_key: &str,
    account_id: &str,
) -> String {
    if let Some(frozen) = normalize_machine_id(frozen) {
        return frozen;
    }
    if auth_method == "api_key" {
        if !api_key.is_empty() {
            return derive_api_key_machine_id(api_key);
        }
    } else if !refresh_token.is_empty() {
        return derive_oauth_machine_id(refresh_token);
    }
    fallback_machine_id(account_id)
}

// ─── Profile ARN ────────────────────────────────────────────────────────────

const BUILDER_ID_PROFILE_ARN: &str =
    "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX";
const SOCIAL_PROFILE_ARN: &str =
    "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK";

/// The profile ARN a request for this account carries, or `""` when it carries
/// none.
pub fn resolve_kiro_profile_arn(auth_state: Option<&Value>) -> String {
    let object = auth_state.and_then(Value::as_object);
    if let Some(own) = object
        .and_then(|value| value.get("profileArn"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return own.to_owned();
    }
    let Some(auth_method) = object
        .and_then(|value| value.get("authMethod"))
        .and_then(Value::as_str)
    else {
        return String::new();
    };
    if auth_method == "api_key" || auth_method == "external_idp" {
        return String::new();
    }
    if auth_method == "google" || auth_method == "github" {
        return SOCIAL_PROFILE_ARN.to_owned();
    }
    BUILDER_ID_PROFILE_ARN.to_owned()
}

// ─── Catalog ────────────────────────────────────────────────────────────────

/// One Kiro model row.
#[derive(Debug, Clone, Copy)]
pub struct KiroCatalogModel {
    pub id: &'static str,
    pub context_limit: i64,
    pub output_limit: i64,
    pub vision: bool,
    pub reasoning: bool,
    pub tool_call: bool,
    pub web_search: bool,
}

/// Effort tiers the Kiro models that accept an effort field advertise.
pub const KIRO_EFFORTS: [&str; 4] = ["low", "medium", "high", "xhigh"];

/// Offline seed catalog.
pub const KIRO_MODELS: &[KiroCatalogModel] = &[
    KiroCatalogModel {
        id: "claude-opus-5",
        context_limit: 1_000_000,
        output_limit: 128_000,
        vision: true,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "claude-opus-4.8",
        context_limit: 1_000_000,
        output_limit: 128_000,
        vision: true,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "claude-opus-4.7",
        context_limit: 1_000_000,
        output_limit: 128_000,
        vision: true,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "claude-opus-4.5",
        context_limit: 200_000,
        output_limit: 64_000,
        vision: true,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "claude-sonnet-5",
        context_limit: 1_000_000,
        output_limit: 128_000,
        vision: true,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "claude-sonnet-4.5",
        context_limit: 1_000_000,
        output_limit: 64_000,
        vision: true,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "claude-haiku-4.5",
        context_limit: 200_000,
        output_limit: 64_000,
        vision: true,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "gpt-5.6-sol",
        context_limit: 272_000,
        output_limit: 128_000,
        vision: false,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "gpt-5.6-terra",
        context_limit: 272_000,
        output_limit: 128_000,
        vision: false,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "gpt-5.6-luna",
        context_limit: 272_000,
        output_limit: 128_000,
        vision: false,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "deepseek-3.2",
        context_limit: 128_000,
        output_limit: 64_000,
        vision: false,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "qwen3-coder-next",
        context_limit: 1_000_000,
        output_limit: 64_000,
        vision: false,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "glm-5",
        context_limit: 204_800,
        output_limit: 131_072,
        vision: false,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
    KiroCatalogModel {
        id: "MiniMax-M2.5",
        context_limit: 204_800,
        output_limit: 131_072,
        vision: false,
        reasoning: true,
        tool_call: true,
        web_search: false,
    },
];

/// Window used for a model this catalog does not name; the Anthropic rows'
/// value.
pub const KIRO_DEFAULT_CONTEXT_WINDOW: i64 = 200_000;

/// The context window of a model id, as this catalog declares it.
pub fn kiro_context_window(model_id: &str) -> i64 {
    let normalized = model_id.trim().to_lowercase();
    KIRO_MODELS
        .iter()
        .find(|model| model.id.to_lowercase() == normalized)
        .map(|model| model.context_limit)
        .unwrap_or(KIRO_DEFAULT_CONTEXT_WINDOW)
}

/// The routed model id for a request, preferring the candidate's own id.
pub fn resolve_model_id(target_model: &str, request_model: &str) -> String {
    if target_model.trim().is_empty() {
        request_model.to_owned()
    } else {
        target_model.to_owned()
    }
}

// ─── Reasoning effort ───────────────────────────────────────────────────────

/// The two upstream effort schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KiroEffortPath {
    /// Claude models: `{thinking, output_config}`.
    OutputConfig,
    /// GPT family: `{reasoning}`.
    Reasoning,
}

fn contains_gpt_56(normalized: &str) -> bool {
    const NEEDLE: &str = "gpt.5.6";
    let mut from = 0;
    while let Some(index) = normalized[from..].find(NEEDLE) {
        let start = from + index;
        let end = start + NEEDLE.len();
        let before_ok = start == 0
            || matches!(
                normalized.as_bytes().get(start - 1),
                Some(b'/') | Some(b'.')
            );
        let after_ok = end == normalized.len()
            || matches!(normalized.as_bytes().get(end), Some(b'/') | Some(b'.'));
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Parses a Claude major/minor pair out of a normalized model id.
fn claude_version(normalized: &str) -> Option<(u32, Option<u32>)> {
    let mut from = 0;
    while let Some(index) = normalized[from..].find("claude") {
        let start = from + index;
        if start > 0
            && !matches!(
                normalized.as_bytes().get(start - 1),
                Some(b'/') | Some(b'.')
            )
        {
            from = start + "claude".len();
            continue;
        }
        let mut cursor = start + "claude".len();
        // Zero or more `[./][a-z]+` segments.
        loop {
            let bytes = normalized.as_bytes();
            if cursor >= bytes.len() || !matches!(bytes[cursor], b'/' | b'.') {
                break;
            }
            let mut probe = cursor + 1;
            let letters_start = probe;
            while probe < bytes.len() && bytes[probe].is_ascii_lowercase() {
                probe += 1;
            }
            if probe == letters_start {
                break;
            }
            cursor = probe;
        }
        let bytes = normalized.as_bytes();
        if cursor >= bytes.len() || !matches!(bytes[cursor], b'/' | b'.') {
            from = start + "claude".len();
            continue;
        }
        let mut probe = cursor + 1;
        let major_start = probe;
        while probe < bytes.len() && bytes[probe].is_ascii_digit() {
            probe += 1;
        }
        if probe == major_start {
            from = start + "claude".len();
            continue;
        }
        let major: u32 = normalized[major_start..probe].parse().ok()?;
        let mut minor = None;
        if probe < bytes.len() && matches!(bytes[probe], b'/' | b'.') {
            let mut minor_probe = probe + 1;
            let minor_start = minor_probe;
            while minor_probe < bytes.len() && bytes[minor_probe].is_ascii_digit() {
                minor_probe += 1;
            }
            if minor_probe > minor_start {
                minor = normalized[minor_start..minor_probe].parse().ok();
                probe = minor_probe;
            }
        }
        let boundary_ok = probe == bytes.len() || matches!(bytes[probe], b'/' | b'.');
        if boundary_ok {
            return Some((major, minor));
        }
        from = start + "claude".len();
    }
    None
}

/// Chooses the reasoning effort field this model accepts, or `None`.
pub fn kiro_effort_path(model_id: &str) -> Option<KiroEffortPath> {
    let normalized = model_id.to_lowercase().replace('-', ".");
    if contains_gpt_56(&normalized) {
        return Some(KiroEffortPath::Reasoning);
    }
    if !normalized.contains("claude") {
        return None;
    }
    let (major, minor) = claude_version(&normalized)?;
    if major < 4 {
        return None;
    }
    if major == 4 && (minor.is_none() || minor <= Some(5) || minor >= Some(1000)) {
        return None;
    }
    Some(KiroEffortPath::OutputConfig)
}

/// The thinking budget an effort tier asks for, or `None` for no reasoning.
pub fn kiro_thinking_budget_for_effort(effort: Option<ReasoningEffort>) -> Option<i64> {
    match effort? {
        ReasoningEffort::Minimal => Some(512),
        ReasoningEffort::Low => Some(1_024),
        ReasoningEffort::Medium => Some(8_192),
        ReasoningEffort::High => Some(KIRO_THINKING_BUDGET_DEFAULT),
        ReasoningEffort::Xhigh | ReasoningEffort::Max => Some(KIRO_THINKING_BUDGET_MAX),
        ReasoningEffort::None => None,
    }
}

fn build_additional_model_request_fields(options: &KiroWireRequestOptions) -> Option<Value> {
    let path = options.effort_path?;
    let effort = options.effort?;
    match path {
        KiroEffortPath::Reasoning => {
            let effort = match effort {
                ReasoningEffort::Max => "xhigh",
                ReasoningEffort::Minimal => "low",
                ReasoningEffort::Low => "low",
                ReasoningEffort::Medium => "medium",
                ReasoningEffort::High => "high",
                ReasoningEffort::Xhigh => "xhigh",
                ReasoningEffort::None => return None,
            };
            Some(json!({"reasoning": {"effort": effort}}))
        }
        KiroEffortPath::OutputConfig => {
            let effort = match effort {
                ReasoningEffort::Xhigh | ReasoningEffort::Max => "high",
                ReasoningEffort::Low => "low",
                ReasoningEffort::Medium => "medium",
                ReasoningEffort::High => "high",
                ReasoningEffort::Minimal | ReasoningEffort::None => return None,
            };
            Some(json!({
                "thinking": {"type": "adaptive", "display": "summarized"},
                "output_config": {"effort": effort},
            }))
        }
    }
}

// ─── Wire request ───────────────────────────────────────────────────────────

/// One `toolSpecification` entry in the wire payload.
#[derive(Debug, Clone)]
struct KiroToolSpecification {
    name: String,
    description: String,
    schema: Value,
}

/// One tool result in `userInputMessageContext`.
#[derive(Debug, Clone)]
struct KiroToolResult {
    tool_use_id: String,
    status: &'static str,
    text: String,
}

/// One `toolUses` entry on an assistant turn.
#[derive(Debug, Clone)]
struct KiroToolUse {
    tool_use_id: String,
    name: String,
    input: Value,
}

#[derive(Debug, Clone)]
struct KiroUserInputMessage {
    content: String,
    model_id: Option<String>,
    images: Vec<Value>,
    tool_results: Vec<KiroToolResult>,
}

#[derive(Debug, Clone)]
struct KiroAssistantMessage {
    content: String,
    tool_uses: Vec<KiroToolUse>,
}

#[derive(Debug, Clone)]
enum KiroTurn {
    User(KiroUserInputMessage),
    Assistant(KiroAssistantMessage),
}

#[derive(Debug, Clone)]
struct CurrentTurn {
    content: String,
    images: Vec<Value>,
    tool_results: Vec<KiroToolResult>,
}

/// The wire payload plus the bookkeeping the response side needs.
#[derive(Debug, Clone)]
pub struct KiroWireRequest {
    pub payload: Value,
    /// Sanitized tool name → the caller's original name.
    pub tool_name_map: BTreeMap<String, String>,
}

/// Why a conversation could not be expressed on this wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KiroConversationError {
    /// Per-turn taxonomy: `role:N`, `pair:N`, `id:N`, `spec:N`, `orphan:0`,
    /// `current`.
    pub problems: Vec<String>,
}

/// Options the adapter supplies that are not part of the canonical request.
#[derive(Debug, Clone)]
pub struct KiroWireRequestOptions {
    pub conversation_id: String,
    pub model_id: String,
    pub profile_arn: String,
    pub effort: Option<ReasoningEffort>,
    pub thinking_budget: Option<i64>,
    pub effort_path: Option<KiroEffortPath>,
}

/// A conversation id for a request that carried none.
pub fn generate_kiro_conversation_id() -> String {
    Uuid::new_v4().to_string()
}

/// The line that tells the model when this turn was sent.
pub fn build_current_time_line(now: DateTime<Utc>) -> String {
    format!(
        "[Context: Current time is {}]",
        now.format("%Y-%m-%dT%H:%M:%S%.3fZ")
    )
}

/// The marker the upstream reads to enable thinking with a budget.
pub fn build_thinking_marker(budget: i64) -> String {
    let safe = budget.clamp(1, KIRO_THINKING_BUDGET_MAX);
    format!(
        "<thinking_mode>enabled</thinking_mode>\n<max_thinking_length>{safe}</max_thinking_length>"
    )
}

fn trim_code_points(value: &str, max_length: usize) -> String {
    value.chars().take(max_length).collect()
}

/// Builds the stable text that precedes the opening user turn.
fn build_stable_prefix(request: &CanonicalRequest, options: &KiroWireRequestOptions) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(budget) = options.thinking_budget {
        parts.push(build_thinking_marker(budget));
    }
    let system_text = request
        .system
        .iter()
        .chain(request.instructions.iter())
        .flat_map(|parts| parts.iter())
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    if !system_text.trim().is_empty() {
        parts.push(system_text);
    }
    parts.join("\n\n")
}

/// Resolves the affinity key derived from the opening turn.
fn derive_conversation_affinity(request: &CanonicalRequest) -> Option<String> {
    let digest = |text: &str| -> String {
        let bytes = Sha256::digest(text.as_bytes());
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("aff_{}", &hex[..24])
    };
    if let Some(system) = request.system.as_ref().filter(|parts| !parts.is_empty()) {
        let text = system
            .iter()
            .map(|part| match part {
                ContentPart::Text { text } => text.as_str(),
                _ => "",
            })
            .collect::<String>();
        let trimmed = text.trim();
        if trimmed.chars().count() >= 30 {
            let head: String = trimmed.chars().take(2048).collect();
            return Some(digest(&head));
        }
    }
    let first = request.messages.first()?;
    let first_text = first
        .content
        .iter()
        .map(|part| match part {
            ContentPart::Text { text } => text.as_str(),
            _ => "",
        })
        .collect::<String>();
    let trimmed = first_text.trim();
    if trimmed.chars().count() >= 30 {
        let head: String = trimmed.chars().take(2048).collect();
        return Some(digest(&head));
    }
    None
}

/// The conversation id this request carries.
pub fn resolve_kiro_conversation_id(request: &CanonicalRequest) -> String {
    request
        .conversation
        .as_ref()
        .and_then(|conversation| conversation.conversation_id.clone())
        .or_else(|| request.conversation_id.clone())
        .or_else(|| derive_conversation_affinity(request))
        .unwrap_or_else(generate_kiro_conversation_id)
}

fn normalize_tool_input(value: &Value) -> Option<Value> {
    match value {
        Value::Null => Some(json!({})),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Some(json!({}));
            }
            match serde_json::from_str::<Value>(trimmed) {
                Ok(value @ Value::Object(_)) => Some(value),
                _ => None,
            }
        }
        Value::Object(_) => Some(value.clone()),
        _ => None,
    }
}

/// Rewrites a caller's tool name into one the upstream accepts.
pub fn wire_tool_name(raw_name: &str, index: usize) -> String {
    let sanitized: String = raw_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('_');
    if sanitized.is_empty() {
        return format!("tool_{}", index + 1);
    }
    if sanitized.chars().count() <= KIRO_TOOL_NAME_MAX_LENGTH {
        return sanitized.to_owned();
    }
    let hash: String = Sha256::digest(sanitized.as_bytes())
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let prefix_length = KIRO_TOOL_NAME_MAX_LENGTH - hash.len() - 1;
    format!("{}_{}", trim_code_points(sanitized, prefix_length), hash)
}

/// Normalizes a tool's JSON schema for the upstream.
pub fn normalize_json_schema(schema: &Value) -> Value {
    let mut root = match schema {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    root.remove("additionalProperties");
    root.insert("type".into(), json!("object"));
    let properties = match root.get("properties") {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    let names: BTreeSet<String> = properties.keys().cloned().collect();
    root.insert("properties".into(), Value::Object(properties));
    if let Some(required) = root.get("required").cloned() {
        if let Value::Array(entries) = required {
            let mut seen = BTreeSet::new();
            let filtered: Vec<Value> = entries
                .into_iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .filter(|entry| names.contains(entry))
                .filter(|entry| seen.insert(entry.clone()))
                .map(Value::String)
                .collect();
            if filtered.is_empty() {
                root.remove("required");
            } else {
                root.insert("required".into(), Value::Array(filtered));
            }
        } else {
            root.remove("required");
        }
    }
    Value::Object(root)
}

fn normalize_tool_specs(
    tools: &[ToolDefinition],
    name_map: &mut BTreeMap<String, String>,
    wire_name_by_original: &mut BTreeMap<String, String>,
) -> Vec<KiroToolSpecification> {
    let mut specs = Vec::new();
    let mut taken: BTreeSet<String> = BTreeSet::new();
    for (index, tool) in tools.iter().enumerate() {
        let raw_name = tool.name.trim();
        if raw_name.is_empty() {
            continue;
        }
        let base = wire_tool_name(raw_name, index);
        let mut name = base.clone();
        let mut suffix = 2usize;
        while taken.contains(&name) {
            let tail = format!("_{suffix}");
            let keep = KIRO_TOOL_NAME_MAX_LENGTH.saturating_sub(tail.len());
            name = format!("{}{}", trim_code_points(&base, keep), tail);
            suffix += 1;
        }
        taken.insert(name.clone());
        wire_name_by_original.insert(raw_name.to_owned(), name.clone());
        if name != raw_name {
            name_map.insert(name.clone(), raw_name.to_owned());
        }
        let description = match tool.description.as_deref() {
            Some(value) if !value.trim().is_empty() => {
                trim_code_points(value, KIRO_TOOL_DESCRIPTION_MAX_LENGTH)
            }
            _ => format!("Tool: {raw_name}"),
        };
        specs.push(KiroToolSpecification {
            name,
            description,
            schema: normalize_json_schema(&tool.json_schema),
        });
    }
    specs
}

fn media_type_to_kiro_format(media_type: &str) -> String {
    let subtype = media_type
        .split_once('/')
        .map(|(_, subtype)| subtype)
        .unwrap_or(media_type);
    if subtype.is_empty() {
        "png".to_owned()
    } else {
        subtype.to_lowercase()
    }
}

fn image_payload(payload: &Value) -> Option<(String, String)> {
    let source = resolve_image_source(payload)?;
    let url = source.url?;
    let split = split_data_url(&url)?;
    Some((media_type_to_kiro_format(&split.media_type), split.data))
}

fn images_of(message: &CanonicalMessage) -> Vec<Value> {
    let mut images = Vec::new();
    for part in &message.content {
        if let ContentPart::Image { payload } = part {
            if let Some((format, bytes)) = image_payload(payload) {
                images.push(json!({"format": format, "source": {"bytes": bytes}}));
            }
        }
    }
    images
}

fn tool_result_text(content: &ToolResultContent) -> String {
    match content {
        ToolResultContent::Text(text) => text.clone(),
        ToolResultContent::Parts(parts) => parts
            .iter()
            .map(|part| match part {
                ContentPart::Text { text } => text.clone(),
                ContentPart::Image { .. } => "[image]".to_owned(),
                _ => String::new(),
            })
            .collect::<String>(),
    }
}

fn reserve_tool_id(
    raw_id: &str,
    turn_index: usize,
    call_index: usize,
    name: &str,
    used: &mut BTreeSet<String>,
    reserved_by_raw_id: &mut BTreeMap<String, String>,
) -> String {
    if let Some(existing) = reserved_by_raw_id.get(raw_id) {
        return existing.clone();
    }
    let sanitized: String = raw_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect();
    let base = if sanitized.is_empty() {
        trim_code_points(
            &format!(
                "call_msg{turn_index}_tc{call_index}_{}",
                if name.is_empty() { "tool" } else { name }
            ),
            KIRO_TOOL_ID_MAX_LENGTH,
        )
    } else {
        trim_code_points(&sanitized, KIRO_TOOL_ID_MAX_LENGTH)
    };
    let mut candidate = base.clone();
    let mut suffix = 2usize;
    while used.contains(&candidate) {
        let tail = format!("_{suffix}");
        let keep = KIRO_TOOL_ID_MAX_LENGTH.saturating_sub(tail.len());
        candidate = format!("{}{}", trim_code_points(&base, keep), tail);
        suffix += 1;
    }
    used.insert(candidate.clone());
    reserved_by_raw_id.insert(raw_id.to_owned(), candidate.clone());
    candidate
}

fn merge_user_turns(
    first: KiroUserInputMessage,
    second: KiroUserInputMessage,
) -> KiroUserInputMessage {
    let mut tool_results = first.tool_results;
    tool_results.extend(second.tool_results);
    let mut images = first.images;
    images.extend(second.images);
    KiroUserInputMessage {
        content: format!("{}\n\n{}", first.content, second.content)
            .trim()
            .to_owned(),
        model_id: first.model_id.or(second.model_id),
        images,
        tool_results,
    }
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn split_conversation(
    messages: &[CanonicalMessage],
    model_id: &str,
    prefix: &str,
    wire_name_by_original: &BTreeMap<String, String>,
    now: DateTime<Utc>,
) -> (Vec<KiroTurn>, CurrentTurn, Vec<String>) {
    let empty = || CurrentTurn {
        content: KIRO_EMPTY_USER_PLACEHOLDER.to_owned(),
        images: Vec::new(),
        tool_results: Vec::new(),
    };
    let mut problems: Vec<String> = Vec::new();
    let mut turns: Vec<KiroTurn> = Vec::new();
    let mut reserved_by_raw_id: BTreeMap<String, String> = BTreeMap::new();
    let mut used_tool_ids: BTreeSet<String> = BTreeSet::new();
    let mut call_ids: Vec<String> = Vec::new();
    let mut result_ids: Vec<String> = Vec::new();

    for (index, message) in messages.iter().enumerate() {
        let text: String = message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();

        if message.role == Role::Assistant {
            let mut tool_uses = Vec::new();
            for call in message.content.iter().filter_map(|part| match part {
                ContentPart::ToolCall {
                    call_id,
                    name,
                    arguments,
                    ..
                } => Some((call_id, name, arguments)),
                _ => None,
            }) {
                let (call_id, name, arguments) = call;
                let Some(wire_name) = wire_name_by_original.get(name) else {
                    problems.push(format!("spec:{index}"));
                    continue;
                };
                let Some(input) = normalize_tool_input(arguments) else {
                    problems.push(format!("id:{index}"));
                    continue;
                };
                let tool_use_id = reserve_tool_id(
                    call_id,
                    index,
                    tool_uses.len(),
                    wire_name,
                    &mut used_tool_ids,
                    &mut reserved_by_raw_id,
                );
                call_ids.push(tool_use_id.clone());
                tool_uses.push(KiroToolUse {
                    tool_use_id,
                    name: wire_name.clone(),
                    input,
                });
            }
            turns.push(KiroTurn::Assistant(KiroAssistantMessage {
                content: if text.is_empty() {
                    KIRO_EMPTY_ASSISTANT_PLACEHOLDER.to_owned()
                } else {
                    text
                },
                tool_uses,
            }));
            continue;
        }

        let mut tool_results = Vec::new();
        for part in &message.content {
            let ContentPart::ToolResult {
                call_id,
                content,
                is_error,
                ..
            } = part
            else {
                continue;
            };
            let tool_use_id = reserve_tool_id(
                call_id,
                index,
                tool_results.len(),
                "tool",
                &mut used_tool_ids,
                &mut reserved_by_raw_id,
            );
            result_ids.push(tool_use_id.clone());
            tool_results.push(KiroToolResult {
                tool_use_id,
                status: if *is_error == Some(true) {
                    "error"
                } else {
                    "success"
                },
                text: tool_result_text(content),
            });
        }
        let images = images_of(message);
        turns.push(KiroTurn::User(KiroUserInputMessage {
            content: if !text.is_empty() {
                text
            } else if !tool_results.is_empty() {
                KIRO_TOOL_RESULTS_PLACEHOLDER.to_owned()
            } else {
                KIRO_EMPTY_USER_PLACEHOLDER.to_owned()
            },
            model_id: Some(model_id.to_owned()),
            images,
            tool_results,
        }));
    }

    // Adjacent same-role turns are merged rather than refused.
    let mut merged: Vec<KiroTurn> = Vec::new();
    for turn in turns {
        match (merged.pop(), turn) {
            (Some(KiroTurn::User(previous)), KiroTurn::User(next)) => {
                merged.push(KiroTurn::User(merge_user_turns(previous, next)));
            }
            (Some(KiroTurn::Assistant(mut previous)), KiroTurn::Assistant(next)) => {
                let mut tool_uses = previous.tool_uses;
                tool_uses.extend(next.tool_uses);
                previous.content = format!("{}\n\n{}", previous.content, next.content)
                    .trim()
                    .to_owned();
                previous.tool_uses = tool_uses;
                merged.push(KiroTurn::Assistant(previous));
            }
            (Some(previous), turn) => {
                merged.push(previous);
                merged.push(turn);
            }
            (None, turn) => merged.push(turn),
        }
    }

    for id in &result_ids {
        if !call_ids.contains(id) {
            problems.push(format!("pair:{}", messages.len().saturating_sub(1)));
        }
    }
    for id in &call_ids {
        if !result_ids.contains(id) {
            problems.push(format!("pair:{}", messages.len().saturating_sub(1)));
        }
    }
    if !problems.is_empty() {
        return (Vec::new(), empty(), dedupe(problems));
    }

    if merged.is_empty() {
        problems.push("current".to_owned());
        return (Vec::new(), empty(), problems);
    }
    if matches!(merged.last(), Some(KiroTurn::Assistant(_))) {
        merged.push(KiroTurn::User(KiroUserInputMessage {
            content: KIRO_EMPTY_USER_PLACEHOLDER.to_owned(),
            model_id: Some(model_id.to_owned()),
            images: Vec::new(),
            tool_results: Vec::new(),
        }));
    }
    let Some(KiroTurn::User(current)) = merged.last() else {
        problems.push("current".to_owned());
        return (Vec::new(), empty(), problems);
    };
    let current = current.clone();
    let images = current.images.clone();
    let time_line = build_current_time_line(now);

    if merged.len() == 1 {
        return (
            Vec::new(),
            CurrentTurn {
                content: format!("{prefix}\n\n{time_line}\n\n{}", current.content)
                    .trim()
                    .to_owned(),
                images,
                tool_results: current.tool_results,
            },
            problems,
        );
    }

    let mut history = merged;
    let current = match history.pop() {
        Some(KiroTurn::User(turn)) => turn,
        _ => {
            problems.push("current".to_owned());
            return (Vec::new(), empty(), problems);
        }
    };
    if let Some(KiroTurn::User(first)) = history.first_mut() {
        first.content = format!("{prefix}\n\n{}", first.content).trim().to_owned();
    }
    (
        history,
        CurrentTurn {
            content: format!("{time_line}\n\n{}", current.content)
                .trim()
                .to_owned(),
            images: current.images,
            tool_results: current.tool_results,
        },
        problems,
    )
}

fn turn_to_value(turn: &KiroTurn) -> Value {
    match turn {
        KiroTurn::User(message) => {
            let mut body = Map::new();
            body.insert("content".into(), json!(message.content));
            if let Some(model_id) = &message.model_id {
                body.insert("modelId".into(), json!(model_id));
            }
            if !message.images.is_empty() {
                body.insert("images".into(), Value::Array(message.images.clone()));
            }
            if !message.tool_results.is_empty() {
                let results: Vec<Value> = message
                    .tool_results
                    .iter()
                    .map(|result| {
                        json!({
                            "toolUseId": result.tool_use_id,
                            "status": result.status,
                            "content": [{"text": result.text}],
                        })
                    })
                    .collect();
                body.insert(
                    "userInputMessageContext".into(),
                    json!({"toolResults": results}),
                );
            }
            json!({"userInputMessage": Value::Object(body)})
        }
        KiroTurn::Assistant(message) => {
            let mut body = Map::new();
            body.insert("content".into(), json!(message.content));
            if !message.tool_uses.is_empty() {
                let uses: Vec<Value> = message
                    .tool_uses
                    .iter()
                    .map(|usage| {
                        json!({
                            "toolUseId": usage.tool_use_id,
                            "name": usage.name,
                            "input": usage.input,
                        })
                    })
                    .collect();
                body.insert("toolUses".into(), Value::Array(uses));
            }
            json!({"assistantResponseMessage": Value::Object(body)})
        }
    }
}

/// Builds the wire payload, or reports why the conversation cannot be sent.
pub fn build_kiro_wire_request(
    request: &CanonicalRequest,
    options: &KiroWireRequestOptions,
) -> Result<KiroWireRequest, KiroConversationError> {
    let mut tool_name_map: BTreeMap<String, String> = BTreeMap::new();
    let mut wire_name_by_original: BTreeMap<String, String> = BTreeMap::new();
    let tools = request.tools.as_deref().unwrap_or(&[]);
    let specs = normalize_tool_specs(tools, &mut tool_name_map, &mut wire_name_by_original);

    let prefix = build_stable_prefix(request, options);
    let (history, current, problems) = split_conversation(
        &request.messages,
        &options.model_id,
        &prefix,
        &wire_name_by_original,
        Utc::now(),
    );
    if !problems.is_empty() {
        return Err(KiroConversationError { problems });
    }

    let mut current_message = Map::new();
    current_message.insert("content".into(), json!(current.content));
    current_message.insert("modelId".into(), json!(options.model_id.as_str()));
    current_message.insert("origin".into(), json!("AI_EDITOR"));
    if !current.images.is_empty() {
        current_message.insert("images".into(), Value::Array(current.images));
    }
    if !specs.is_empty() || !current.tool_results.is_empty() {
        let mut context = Map::new();
        if !current.tool_results.is_empty() {
            let results: Vec<Value> = current
                .tool_results
                .iter()
                .map(|result| {
                    json!({
                        "toolUseId": result.tool_use_id,
                        "status": result.status,
                        "content": [{"text": result.text}],
                    })
                })
                .collect();
            context.insert("toolResults".into(), Value::Array(results));
        }
        if !specs.is_empty() {
            let entries: Vec<Value> = specs
                .iter()
                .map(|spec| {
                    json!({
                        "toolSpecification": {
                            "name": spec.name,
                            "description": spec.description,
                            "inputSchema": {"json": spec.schema},
                        }
                    })
                })
                .collect();
            context.insert("tools".into(), Value::Array(entries));
        }
        current_message.insert("userInputMessageContext".into(), Value::Object(context));
    }

    let mut conversation = Map::new();
    conversation.insert(
        "agentTaskType".into(),
        json!(if specs.is_empty() { "vibe" } else { "spectask" }),
    );
    conversation.insert(
        "agentContinuationId".into(),
        json!(Uuid::new_v4().to_string()),
    );
    conversation.insert("chatTriggerType".into(), json!("MANUAL"));
    conversation.insert(
        "conversationId".into(),
        json!(options.conversation_id.as_str()),
    );
    conversation.insert(
        "currentMessage".into(),
        json!({"userInputMessage": Value::Object(current_message)}),
    );
    conversation.insert(
        "history".into(),
        Value::Array(history.iter().map(turn_to_value).collect()),
    );

    let mut payload = Map::new();
    payload.insert("conversationState".into(), Value::Object(conversation));
    if !options.profile_arn.is_empty() {
        payload.insert("profileArn".into(), json!(options.profile_arn.as_str()));
    }
    if let Some(fields) = build_additional_model_request_fields(options) {
        payload.insert("additionalModelRequestFields".into(), fields);
    }

    Ok(KiroWireRequest {
        payload: Value::Object(payload),
        tool_name_map,
    })
}

// ─── Usage ──────────────────────────────────────────────────────────────────

/// Usage the upstream reported, in the units it reported them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KiroUsage {
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cache_read_tokens: Option<i64>,
    pub cache_write_tokens: Option<i64>,
    /// Provider-billed credits, when the metering event carried them.
    pub credits: Option<f64>,
    /// Context-window usage as a percentage of the model's window.
    pub context_usage_percentage: Option<f64>,
}

fn token_count(value: Option<i64>) -> TokenCount {
    match value {
        Some(value) if value > 0 => TokenCount::Number(value),
        _ => TokenCount::Unavailable,
    }
}

/// Builds the canonical usage record from what the upstream reported.
pub fn kiro_usage(usage: &KiroUsage, model_id: &str, output_text: &str) -> UsageRecord {
    let cache_read = usage.cache_read_tokens.unwrap_or(0);
    if usage.input_tokens.is_some() || usage.output_tokens.is_some() {
        let input = usage.input_tokens.unwrap_or(0);
        let output = usage.output_tokens.unwrap_or(0);
        return UsageRecord {
            input_tokens: input,
            cached_input_tokens: token_count(usage.cache_read_tokens),
            cache_write_tokens: token_count(usage.cache_write_tokens),
            uncached_input_tokens: if cache_read > 0 {
                TokenCount::Number((input - cache_read).max(0))
            } else {
                TokenCount::Unavailable
            },
            output_tokens: output,
            reasoning_tokens: TokenCount::Unavailable,
            estimated_cost: None,
            credit_used: usage.credits,
            total_tokens: Some(TokenCount::Number(input + output)),
            details: None,
        };
    }
    let output_length = output_text.encode_utf16().count() as i64;
    let completion_tokens = if output_length == 0 {
        0
    } else {
        (output_length / 4).max(1)
    };
    let measured_total = match usage.context_usage_percentage {
        Some(percentage) if percentage > 0.0 => {
            Some(((kiro_context_window(model_id) as f64 * percentage) / 100.0).round() as i64)
        }
        _ => None,
    };
    let input = measured_total
        .map(|total| (total - completion_tokens).max(0))
        .unwrap_or(0);
    let output = measured_total.map(|_| completion_tokens).unwrap_or(0);
    UsageRecord {
        input_tokens: input,
        cached_input_tokens: token_count(usage.cache_read_tokens),
        cache_write_tokens: token_count(usage.cache_write_tokens),
        uncached_input_tokens: if cache_read > 0 {
            TokenCount::Number((input - cache_read).max(0))
        } else {
            TokenCount::Unavailable
        },
        output_tokens: output,
        reasoning_tokens: TokenCount::Unavailable,
        estimated_cost: None,
        credit_used: usage.credits,
        total_tokens: Some(TokenCount::Number(input + output)),
        details: None,
    }
}

// ─── AWS EventStream framing ────────────────────────────────────────────────

const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: LazyLock<[u32; 256]> = LazyLock::new(|| {
        let mut table = [0u32; 256];
        for (index, entry) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = if value & 1 != 0 {
                    (value >> 1) ^ CRC32_POLYNOMIAL
                } else {
                    value >> 1
                };
            }
            *entry = value;
        }
        table
    });
    &TABLE
}

/// CRC32 of `bytes`, as an unsigned 32-bit integer.
pub fn crc32(bytes: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xff) as usize;
        crc = (crc >> 8) ^ table[index];
    }
    crc ^ 0xffff_ffff
}

/// Fixed part of a message: total length, headers length, prelude CRC.
pub const EVENTSTREAM_PRELUDE_BYTES: usize = 12;
/// Trailing message CRC.
pub const EVENTSTREAM_TRAILER_BYTES: usize = 4;
/// Smallest possible message: prelude + trailer.
pub const EVENTSTREAM_MIN_MESSAGE_BYTES: usize =
    EVENTSTREAM_PRELUDE_BYTES + EVENTSTREAM_TRAILER_BYTES;
/// Ceiling on one message.
pub const EVENTSTREAM_MAX_MESSAGE_BYTES: usize = 24 * 1024 * 1024;
/// Ceiling on the header block of one message.
pub const EVENTSTREAM_MAX_HEADERS_BYTES: usize = 128 * 1024;

/// One decoded EventStream message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStreamMessage {
    pub headers: BTreeMap<String, String>,
    pub payload: Option<String>,
}

/// Reason a message could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStreamDecodeFailure {
    Truncated,
    OversizeMessage,
    OversizeHeaders,
    PreludeCrcMismatch,
    MessageCrcMismatch,
    MalformedHeaders,
    InvalidPayloadUtf8,
}

impl EventStreamDecodeFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::OversizeMessage => "oversize_message",
            Self::OversizeHeaders => "oversize_headers",
            Self::PreludeCrcMismatch => "prelude_crc_mismatch",
            Self::MessageCrcMismatch => "message_crc_mismatch",
            Self::MalformedHeaders => "malformed_headers",
            Self::InvalidPayloadUtf8 => "invalid_payload_utf8",
        }
    }
}

/// One decode failure with a bounded explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStreamFailure {
    pub reason: EventStreamDecodeFailure,
    pub detail: String,
}

/// The result of decoding a buffered EventStream.
#[derive(Debug, Clone, Default)]
pub struct EventStreamDecodeResult {
    pub messages: Vec<EventStreamMessage>,
    /// Bytes consumed from the buffer.
    pub consumed: usize,
    pub failure: Option<EventStreamFailure>,
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

/// Decodes as many whole messages as `buffer` holds.
pub fn decode_event_stream_messages(buffer: &[u8]) -> EventStreamDecodeResult {
    let mut messages = Vec::new();
    let mut offset = 0usize;
    loop {
        let remaining = buffer.len() - offset;
        if remaining < EVENTSTREAM_MIN_MESSAGE_BYTES {
            break;
        }
        let total_length = read_u32(buffer, offset) as usize;
        let headers_length = read_u32(buffer, offset + 4) as usize;
        if total_length < EVENTSTREAM_MIN_MESSAGE_BYTES {
            return EventStreamDecodeResult {
                messages,
                consumed: offset,
                failure: Some(EventStreamFailure {
                    reason: EventStreamDecodeFailure::Truncated,
                    detail: format!(
                        "message length {total_length} is below the {EVENTSTREAM_MIN_MESSAGE_BYTES}-byte minimum"
                    ),
                }),
            };
        }
        if total_length > EVENTSTREAM_MAX_MESSAGE_BYTES {
            return EventStreamDecodeResult {
                messages,
                consumed: offset,
                failure: Some(EventStreamFailure {
                    reason: EventStreamDecodeFailure::OversizeMessage,
                    detail: format!(
                        "message length {total_length} exceeds the {EVENTSTREAM_MAX_MESSAGE_BYTES}-byte cap"
                    ),
                }),
            };
        }
        if headers_length > EVENTSTREAM_MAX_HEADERS_BYTES {
            return EventStreamDecodeResult {
                messages,
                consumed: offset,
                failure: Some(EventStreamFailure {
                    reason: EventStreamDecodeFailure::OversizeHeaders,
                    detail: format!(
                        "header block {headers_length} exceeds the {EVENTSTREAM_MAX_HEADERS_BYTES}-byte cap"
                    ),
                }),
            };
        }
        if headers_length > total_length - EVENTSTREAM_MIN_MESSAGE_BYTES {
            return EventStreamDecodeResult {
                messages,
                consumed: offset,
                failure: Some(EventStreamFailure {
                    reason: EventStreamDecodeFailure::MalformedHeaders,
                    detail: format!(
                        "header block {headers_length} does not fit in a {total_length}-byte message"
                    ),
                }),
            };
        }
        if remaining < total_length {
            break;
        }
        let message_end = offset + total_length;
        let declared_prelude_crc = read_u32(buffer, offset + 8);
        let actual_prelude_crc = crc32(&buffer[offset..offset + 8]);
        if declared_prelude_crc != actual_prelude_crc {
            return EventStreamDecodeResult {
                messages,
                consumed: offset,
                failure: Some(EventStreamFailure {
                    reason: EventStreamDecodeFailure::PreludeCrcMismatch,
                    detail: format!(
                        "prelude CRC {declared_prelude_crc} does not match computed {actual_prelude_crc}"
                    ),
                }),
            };
        }
        let declared_message_crc = read_u32(buffer, message_end - EVENTSTREAM_TRAILER_BYTES);
        let actual_message_crc = crc32(&buffer[offset..message_end - EVENTSTREAM_TRAILER_BYTES]);
        if declared_message_crc != actual_message_crc {
            return EventStreamDecodeResult {
                messages,
                consumed: offset,
                failure: Some(EventStreamFailure {
                    reason: EventStreamDecodeFailure::MessageCrcMismatch,
                    detail: format!(
                        "message CRC {declared_message_crc} does not match computed {actual_message_crc}"
                    ),
                }),
            };
        }
        let header_start = offset + EVENTSTREAM_PRELUDE_BYTES;
        let headers =
            match decode_event_stream_headers(&buffer[header_start..header_start + headers_length])
            {
                Ok(headers) => headers,
                Err(detail) => {
                    return EventStreamDecodeResult {
                        messages,
                        consumed: offset,
                        failure: Some(EventStreamFailure {
                            reason: EventStreamDecodeFailure::MalformedHeaders,
                            detail,
                        }),
                    };
                }
            };
        let payload_start = header_start + headers_length;
        let payload_end = message_end - EVENTSTREAM_TRAILER_BYTES;
        let payload = if payload_end > payload_start {
            match std::str::from_utf8(&buffer[payload_start..payload_end]) {
                Ok(text) => Some(text.to_owned()),
                Err(_) => {
                    return EventStreamDecodeResult {
                        messages,
                        consumed: offset,
                        failure: Some(EventStreamFailure {
                            reason: EventStreamDecodeFailure::InvalidPayloadUtf8,
                            detail: "message payload is not valid UTF-8".to_owned(),
                        }),
                    };
                }
            }
        } else {
            None
        };
        messages.push(EventStreamMessage { headers, payload });
        offset = message_end;
    }
    EventStreamDecodeResult {
        messages,
        consumed: offset,
        failure: None,
    }
}

fn decode_event_stream_headers(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut headers = BTreeMap::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let name_length = usize::from(bytes[offset]);
        offset += 1;
        if offset + name_length > bytes.len() {
            return Err("header name is truncated".to_owned());
        }
        let name = String::from_utf8_lossy(&bytes[offset..offset + name_length]).into_owned();
        offset += name_length;
        if offset >= bytes.len() {
            return Err(format!("header {name} has no value type"));
        }
        let value_type = bytes[offset];
        offset += 1;
        match value_type {
            0 | 1 => {
                headers.insert(
                    name,
                    if value_type == 1 { "true" } else { "false" }.to_owned(),
                );
            }
            2 => {
                if offset + 1 > bytes.len() {
                    return Err(format!("header {name} is truncated"));
                }
                headers.insert(name, (bytes[offset] as i8).to_string());
                offset += 1;
            }
            3 => {
                if offset + 2 > bytes.len() {
                    return Err(format!("header {name} is truncated"));
                }
                let value = i16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                headers.insert(name, value.to_string());
                offset += 2;
            }
            4 => {
                if offset + 4 > bytes.len() {
                    return Err(format!("header {name} is truncated"));
                }
                let value = i32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]);
                headers.insert(name, value.to_string());
                offset += 4;
            }
            5 | 8 => {
                if offset + 8 > bytes.len() {
                    return Err(format!("header {name} is truncated"));
                }
                offset += 8;
            }
            9 => {
                if offset + 16 > bytes.len() {
                    return Err(format!("header {name} is truncated"));
                }
                offset += 16;
            }
            6 | 7 => {
                if offset + 2 > bytes.len() {
                    return Err(format!("header {name} is truncated"));
                }
                let value_length =
                    usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
                offset += 2;
                if offset + value_length > bytes.len() {
                    return Err(format!("header {name} value is truncated"));
                }
                let value = &bytes[offset..offset + value_length];
                offset += value_length;
                headers.insert(
                    name,
                    if value_type == 7 {
                        String::from_utf8_lossy(value).into_owned()
                    } else {
                        BASE64.encode(value)
                    },
                );
            }
            other => {
                return Err(format!("header {name} has unknown value type {other}"));
            }
        }
    }
    Ok(headers)
}

// ─── Stream decoding ────────────────────────────────────────────────────────

/// One parsed event from the upstream, before interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KiroRawEvent {
    pub headers: BTreeMap<String, String>,
    pub payload: Option<String>,
}

impl From<EventStreamMessage> for KiroRawEvent {
    fn from(message: EventStreamMessage) -> Self {
        Self {
            headers: message.headers,
            payload: message.payload,
        }
    }
}

/// A delta the adapter should emit.
#[derive(Debug, Clone, PartialEq)]
pub enum KiroStreamDelta {
    Text(String),
    Reasoning(String),
    ToolCall {
        call_id: String,
        name: String,
        arguments_delta: String,
    },
    Usage(KiroUsage),
}

/// The outcome of feeding one event to the decoder.
#[derive(Debug, Clone, Default)]
pub struct KiroEventOutcome {
    pub deltas: Vec<KiroStreamDelta>,
    pub stop_reason: Option<CanonicalStopReason>,
    pub provider_stop_reason: Option<String>,
    pub failure: Option<String>,
}

/// Stateful decoder for one stream.
#[derive(Debug, Default)]
pub struct KiroStreamDecoder {
    in_thinking: bool,
    pending_text: String,
}

fn parse_payload(payload: Option<&str>) -> Option<Value> {
    let payload = payload?;
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

fn unwrap_value(value: Option<Value>, keys: &[&str]) -> Option<Value> {
    let value = value?;
    if let Value::Object(map) = &value {
        for key in keys {
            if let Some(nested) = map.get(*key) {
                if !nested.is_null() {
                    return Some(nested.clone());
                }
            }
        }
    }
    Some(value)
}

fn read_string(payload: Option<&str>, key: &str) -> String {
    let Some(value) = unwrap_value(parse_payload(payload), &[]) else {
        return String::new();
    };
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn read_reasoning(payload: Option<&str>) -> String {
    let parsed = parse_payload(payload);
    if let Some(Value::String(text)) = &parsed {
        return text.clone();
    }
    let Some(value) = unwrap_value(parsed, &["reasoningContentEvent"]) else {
        return String::new();
    };
    if let Value::String(text) = &value {
        return text.clone();
    }
    if let Value::Object(map) = &value {
        if let Some(text) = map.get("text").and_then(Value::as_str) {
            return text.to_owned();
        }
        if let Some(text) = map.get("content").and_then(Value::as_str) {
            return text.to_owned();
        }
    }
    String::new()
}

fn stop_reason_of(value: Option<Value>) -> Option<String> {
    let value = value?;
    let map = value.as_object()?;
    let read = |key: &str| {
        map.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    read("stopReason").or_else(|| read("stop_reason"))
}

fn number_field(value: Option<&Value>, key: &str) -> Option<f64> {
    let field = value?.get(key)?;
    match field {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Some(0.0)
            } else {
                trimmed
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite())
            }
        }
        _ => None,
    }
}

fn longest_marker_prefix(text: &str, marker: &str) -> usize {
    let max = text.len().min(marker.len().saturating_sub(1));
    for length in (1..=max).rev() {
        let start = text.len() - length;
        if text.as_bytes()[start..] == marker.as_bytes()[..length] {
            return length;
        }
    }
    0
}

impl KiroStreamDecoder {
    /// Interprets one upstream event.
    pub fn decode(&mut self, event: &KiroRawEvent) -> KiroEventOutcome {
        let message_type = event.headers.get(":message-type").map(String::as_str);
        if message_type == Some("error") || message_type == Some("exception") {
            return KiroEventOutcome {
                deltas: Vec::new(),
                stop_reason: None,
                provider_stop_reason: None,
                failure: Some(stop_reason_like_message(event.payload.as_deref())),
            };
        }
        let event_type = event
            .headers
            .get(":event-type")
            .map(String::as_str)
            .unwrap_or("");
        match event_type {
            "assistantResponseEvent" => {
                let text = read_string(event.payload.as_deref(), "content");
                KiroEventOutcome {
                    deltas: self.text_deltas(&text),
                    ..Default::default()
                }
            }
            "reasoningContentEvent" => {
                let text = read_reasoning(event.payload.as_deref());
                KiroEventOutcome {
                    deltas: if text.is_empty() {
                        Vec::new()
                    } else {
                        vec![KiroStreamDelta::Reasoning(text)]
                    },
                    ..Default::default()
                }
            }
            "codeEvent" => {
                let text = read_string(event.payload.as_deref(), "content");
                KiroEventOutcome {
                    deltas: self.text_deltas(&text),
                    ..Default::default()
                }
            }
            "toolUseEvent" => KiroEventOutcome {
                deltas: tool_deltas(event.payload.as_deref()),
                ..Default::default()
            },
            "messageStopEvent" => stop_outcome(stop_reason_of(unwrap_value(
                parse_payload(event.payload.as_deref()),
                &[],
            ))),
            "metadataEvent" | "MetadataEvent" => stop_outcome(stop_reason_of(unwrap_value(
                parse_payload(event.payload.as_deref()),
                &["metadataEvent", "metadata"],
            ))),
            "contextUsageEvent" => {
                let percentage = number_field(
                    unwrap_value(parse_payload(event.payload.as_deref()), &[]).as_ref(),
                    "contextUsagePercentage",
                );
                KiroEventOutcome {
                    deltas: percentage
                        .map(|percentage| {
                            vec![KiroStreamDelta::Usage(KiroUsage {
                                context_usage_percentage: Some(percentage),
                                ..Default::default()
                            })]
                        })
                        .unwrap_or_default(),
                    ..Default::default()
                }
            }
            "meteringEvent" => {
                let credits = number_field(
                    unwrap_value(parse_payload(event.payload.as_deref()), &["meteringEvent"])
                        .as_ref(),
                    "usage",
                );
                KiroEventOutcome {
                    deltas: credits
                        .map(|credits| {
                            vec![KiroStreamDelta::Usage(KiroUsage {
                                credits: Some(credits),
                                ..Default::default()
                            })]
                        })
                        .unwrap_or_default(),
                    ..Default::default()
                }
            }
            "metricsEvent" => {
                let metrics =
                    unwrap_value(parse_payload(event.payload.as_deref()), &["metricsEvent"]);
                let input_tokens = number_field(metrics.as_ref(), "inputTokens").map(|v| v as i64);
                let output_tokens =
                    number_field(metrics.as_ref(), "outputTokens").map(|v| v as i64);
                let cache_read_tokens = number_field(metrics.as_ref(), "cacheReadInputTokens")
                    .map(|v| v as i64)
                    .or_else(|| {
                        number_field(metrics.as_ref(), "cache_read_input_tokens").map(|v| v as i64)
                    });
                let cache_write_tokens = number_field(metrics.as_ref(), "cacheCreationInputTokens")
                    .map(|v| v as i64)
                    .or_else(|| {
                        number_field(metrics.as_ref(), "cache_creation_input_tokens")
                            .map(|v| v as i64)
                    });
                let usage = KiroUsage {
                    input_tokens,
                    output_tokens,
                    cache_read_tokens,
                    cache_write_tokens,
                    ..Default::default()
                };
                KiroEventOutcome {
                    deltas: if usage == KiroUsage::default() {
                        Vec::new()
                    } else {
                        vec![KiroStreamDelta::Usage(usage)]
                    },
                    ..Default::default()
                }
            }
            // An unknown event type is not an error: the upstream adds types
            // over time and a stream carrying one is still a valid answer.
            _ => KiroEventOutcome::default(),
        }
    }

    /// Emits any text still held back for a possible split marker.
    pub fn flush(&mut self) -> Vec<KiroStreamDelta> {
        let pending = std::mem::take(&mut self.pending_text);
        if pending.is_empty() {
            return Vec::new();
        }
        if self.in_thinking {
            vec![KiroStreamDelta::Reasoning(pending)]
        } else {
            vec![KiroStreamDelta::Text(pending)]
        }
    }

    fn text_deltas(&mut self, text: &str) -> Vec<KiroStreamDelta> {
        let mut deltas = Vec::new();
        let mut remaining = format!("{}{}", self.pending_text, text);
        self.pending_text.clear();
        loop {
            let marker = if self.in_thinking {
                "</thinking>"
            } else {
                "<thinking>"
            };
            if let Some(index) = remaining.find(marker) {
                let before = &remaining[..index];
                if !before.is_empty() {
                    deltas.push(if self.in_thinking {
                        KiroStreamDelta::Reasoning(before.to_owned())
                    } else {
                        KiroStreamDelta::Text(before.to_owned())
                    });
                }
                self.in_thinking = !self.in_thinking;
                remaining = remaining[index + marker.len()..].to_owned();
                continue;
            }
            let hold = longest_marker_prefix(&remaining, marker);
            let emit_length = remaining.len() - hold;
            if emit_length > 0 {
                let emit = &remaining[..emit_length];
                deltas.push(if self.in_thinking {
                    KiroStreamDelta::Reasoning(emit.to_owned())
                } else {
                    KiroStreamDelta::Text(emit.to_owned())
                });
            }
            self.pending_text = remaining[emit_length..].to_owned();
            break;
        }
        deltas
    }
}

fn tool_deltas(payload: Option<&str>) -> Vec<KiroStreamDelta> {
    let Some(parsed) = parse_payload(payload) else {
        return Vec::new();
    };
    let values = match parsed {
        Value::Array(values) => values,
        other => vec![other],
    };
    let mut deltas = Vec::new();
    for value in values {
        let Value::Object(map) = value else {
            continue;
        };
        let name = map
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        let call_id = map
            .get("toolUseId")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if name.is_empty() || call_id.is_empty() {
            continue;
        }
        let arguments_delta = match map.get("input") {
            None => String::new(),
            Some(Value::String(text)) => text.clone(),
            Some(other) => serde_json::to_string(other).unwrap_or_default(),
        };
        deltas.push(KiroStreamDelta::ToolCall {
            call_id: call_id.to_owned(),
            name: name.to_owned(),
            arguments_delta,
        });
    }
    deltas
}

fn stop_reason_like_message(payload: Option<&str>) -> String {
    if let Some(Value::Object(map)) = parse_payload(payload) {
        if let Some(message) = map.get("message").and_then(Value::as_str) {
            let trimmed = message.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }
    "Kiro upstream sent an EventStream error".to_owned()
}

fn stop_outcome(raw: Option<String>) -> KiroEventOutcome {
    let canonical = normalize_kiro_stop_reason(raw.as_deref());
    KiroEventOutcome {
        deltas: Vec::new(),
        stop_reason: canonical,
        provider_stop_reason: raw,
        failure: None,
    }
}

fn normalize_stop_text(raw: &str) -> String {
    let mut inserted = String::with_capacity(raw.len() + 4);
    let mut previous_lower = false;
    for ch in raw.chars() {
        if ch.is_ascii_uppercase() && previous_lower {
            inserted.push('_');
        }
        previous_lower = ch.is_lowercase();
        inserted.push(ch);
    }
    let mut normalized = String::with_capacity(inserted.len());
    let mut in_separator = false;
    for ch in inserted.to_lowercase().chars() {
        if ch.is_whitespace() || ch == '-' {
            if !in_separator {
                normalized.push('_');
                in_separator = true;
            }
        } else {
            normalized.push(ch);
            in_separator = false;
        }
    }
    normalized
}

/// Maps the upstream's stop vocabulary onto the canonical one.
pub fn normalize_kiro_stop_reason(raw: Option<&str>) -> Option<CanonicalStopReason> {
    let normalized = normalize_stop_text(raw?);
    match normalized.as_str() {
        "end_turn" | "endturn" | "stop" | "stop_sequence" => Some(CanonicalStopReason::Stop),
        "tool_use" | "tooluse" | "tool_calls" => Some(CanonicalStopReason::ToolUse),
        "max_tokens"
        | "maxtokens"
        | "max_output_tokens"
        | "length"
        | "model_context_window_exceeded" => Some(CanonicalStopReason::Length),
        "cancelled" | "canceled" => Some(CanonicalStopReason::Cancelled),
        "refusal" => Some(CanonicalStopReason::Refusal),
        _ => None,
    }
}

/// Whether the raw reason names a truncation.
pub fn is_kiro_truncation_reason(raw: Option<&str>) -> bool {
    let Some(raw) = raw else {
        return false;
    };
    matches!(
        normalize_stop_text(raw.trim()).as_str(),
        "max_tokens" | "model_context_window_exceeded"
    )
}

fn merge_stop_reason(
    current: Option<CanonicalStopReason>,
    next: CanonicalStopReason,
) -> CanonicalStopReason {
    fn severity(reason: Option<CanonicalStopReason>) -> u8 {
        match reason {
            None => 0,
            Some(CanonicalStopReason::Refusal) => 6,
            Some(CanonicalStopReason::Length) => 5,
            Some(CanonicalStopReason::ToolUse) => 4,
            Some(CanonicalStopReason::Stop) => 3,
            Some(_) => 1,
        }
    }
    if severity(Some(next)) >= severity(current) {
        next
    } else {
        current.unwrap_or(next)
    }
}

fn resolve_final_stop_reason(
    stop_reason: Option<CanonicalStopReason>,
    provider_stop_reason: Option<&str>,
    saw_tool_call: bool,
) -> CanonicalStopReason {
    if stop_reason == Some(CanonicalStopReason::Length)
        || is_kiro_truncation_reason(provider_stop_reason)
    {
        return CanonicalStopReason::Length;
    }
    if stop_reason == Some(CanonicalStopReason::ToolUse) || saw_tool_call {
        return CanonicalStopReason::ToolUse;
    }
    if stop_reason == Some(CanonicalStopReason::Cancelled) {
        return CanonicalStopReason::Cancelled;
    }
    if stop_reason == Some(CanonicalStopReason::Refusal) {
        return CanonicalStopReason::Refusal;
    }
    CanonicalStopReason::Stop
}

// ─── Error helpers ──────────────────────────────────────────────────────────

fn provider_details() -> Map<String, Value> {
    let mut details = Map::new();
    details.insert("providerId".into(), json!(KIRO_PROVIDER_ID));
    details
}

fn network_error(message: String) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::TransportUnavailable,
        502,
        message,
        provider_details(),
    )
    .with_origin(GatewayErrorOrigin::Network)
}

fn upstream_error(message: impl Into<String>) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::PlatformUnavailable,
        502,
        message,
        provider_details(),
    )
    .with_origin(GatewayErrorOrigin::Upstream)
}

fn content_delta(sequence_number: u64, content: ContentPart) -> CanonicalEvent {
    CanonicalEvent::ContentDelta {
        sequence_number,
        content,
        event_id: None,
        response_id: None,
        item_id: None,
        output_index: None,
        content_index: None,
        timestamp: None,
    }
}

// ─── Dispatch ───────────────────────────────────────────────────────────────

/// Dispatches one canonical request to Kiro's `generateAssistantResponse`
/// EventStream wire.
pub async fn dispatch_kiro(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let secret = credential.secret.as_deref().map(str::trim).unwrap_or("");
    if secret.is_empty() {
        return Err(GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "Missing Kiro credential",
            provider_details(),
        ));
    }

    let raw_auth_state = credential.auth_state.as_ref();
    let auth_state = read_kiro_auth_state(raw_auth_state);
    let model_id = resolve_model_id(&target.model_id, &request.model);
    let effort_path = kiro_effort_path(&model_id);
    let requested_effort = request
        .reasoning
        .as_ref()
        .and_then(|reasoning| reasoning.effort);
    let effort = match (effort_path, requested_effort) {
        (Some(_), Some(effort)) if effort != ReasoningEffort::None => Some(effort),
        _ => None,
    };
    let thinking_budget = if effort_path.is_some() {
        None
    } else {
        request
            .reasoning
            .as_ref()
            .and_then(|reasoning| reasoning.budget_tokens)
            .or_else(|| kiro_thinking_budget_for_effort(requested_effort))
    };
    let options = KiroWireRequestOptions {
        conversation_id: resolve_kiro_conversation_id(request),
        model_id: model_id.clone(),
        profile_arn: resolve_kiro_profile_arn(raw_auth_state),
        effort,
        thinking_budget,
        effort_path,
    };
    let built = build_kiro_wire_request(request, &options).map_err(|error| {
        let mut details = provider_details();
        details.insert("problems".into(), json!(error.problems));
        GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            "Kiro cannot accept this conversation",
            details,
        )
    })?;

    let body = serde_json::to_string(&built.payload).map_err(|error| {
        upstream_error(format!("Kiro request could not be serialized: {error}"))
    })?;
    let machine_id = machine_id_for_auth_state(raw_auth_state, credential.account_id.as_deref());
    let headers = kiro_headers(secret, auth_state.as_ref(), &machine_id);
    let mut builder = client.post(kiro_endpoint(auth_state.as_ref()));
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let response = builder
        .body(body)
        .send()
        .await
        .map_err(|error| network_error(format!("Kiro transport failed: {error}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(upstream_http_error(
            status.as_u16(),
            &body,
            KIRO_PROVIDER_ID,
        ));
    }

    let tool_name_map = built.tool_name_map;
    let response_model = request.model.clone();
    let usage_model = request.model.clone();
    let mut upstream = response.bytes_stream();
    let stream = async_stream::try_stream! {
        let mut decoder = KiroStreamDecoder::default();
        let mut pending: Vec<u8> = Vec::new();
        let mut sequence = 0u64;
        let mut stop_reason: Option<CanonicalStopReason> = None;
        let mut provider_stop_reason: Option<String> = None;
        let mut usage = KiroUsage::default();
        let mut saw_tool_call = false;
        let mut output_text = String::new();

        yield CanonicalEvent::ResponseStart {
            sequence_number: sequence,
            event_id: None,
            response_id: None,
            model: Some(response_model.clone()),
            system_fingerprint: None,
            timestamp: None,
        };
        sequence += 1;
        while let Some(chunk) = upstream.next().await {
            let chunk = chunk.map_err(|error| upstream_error(format!("Kiro stream failed: {error}")))?;
            if chunk.is_empty() {
                continue;
            }
            if pending.len() + chunk.len() > KIRO_MAX_STREAM_BUFFER_BYTES {
                Err::<(), GatewayError>(upstream_error(
                    "Kiro EventStream exceeded the buffer bound",
                ))?;
            }
            pending.extend_from_slice(&chunk);
            let decoded = decode_event_stream_messages(&pending);
            if let Some(failure) = &decoded.failure {
                let mut details = provider_details();
                details.insert("reason".into(), json!(failure.reason.as_str()));
                Err::<(), GatewayError>(
                    GatewayError::new(
                        GatewayErrorCode::PlatformUnavailable,
                        502,
                        format!("Kiro EventStream is corrupt: {}", failure.detail),
                        details,
                    )
                    .with_origin(GatewayErrorOrigin::Upstream),
                )?;
            }
            pending.drain(..decoded.consumed);
            for message in decoded.messages {
                let outcome = decoder.decode(&KiroRawEvent::from(message));
                if let Some(failure) = outcome.failure {
                    Err::<(), GatewayError>(
                        GatewayError::new(
                            GatewayErrorCode::PlatformUnavailable,
                            502,
                            failure,
                            provider_details(),
                        )
                        .with_origin(GatewayErrorOrigin::Upstream),
                    )?;
                }
                if let Some(raw) = outcome.provider_stop_reason {
                    provider_stop_reason = Some(raw);
                }
                if let Some(reason) = outcome.stop_reason {
                    stop_reason = Some(merge_stop_reason(stop_reason, reason));
                }
                for delta in outcome.deltas {
                    match delta {
                        KiroStreamDelta::Text(text) => {
                            output_text.push_str(&text);
                            yield content_delta(sequence, ContentPart::Text { text });
                            sequence += 1;
                        }
                        KiroStreamDelta::Reasoning(text) => {
                            output_text.push_str(&text);
                            yield content_delta(sequence, ContentPart::Reasoning {
                                payload: Value::Null,
                                opaque: None,
                                summary: Some(text),
                                summary_index: None,
                                signature: None,
                                encrypted_content: None,
                            });
                            sequence += 1;
                        }
                        KiroStreamDelta::ToolCall { call_id, name, arguments_delta } => {
                            saw_tool_call = true;
                            let name = tool_name_map
                                .get(&name)
                                .cloned()
                                .unwrap_or_else(|| name.clone());
                            output_text.push_str(&arguments_delta);
                            yield CanonicalEvent::ToolCallDelta {
                                sequence_number: sequence,
                                call_id,
                                index: None,
                                name: Some(name),
                                arguments_delta: if arguments_delta.is_empty() {
                                    None
                                } else {
                                    Some(arguments_delta)
                                },
                                event_id: None,
                                response_id: None,
                                item_id: None,
                                output_index: None,
                                timestamp: None,
                            };
                            sequence += 1;
                        }
                        KiroStreamDelta::Usage(reported) => merge_usage(&mut usage, reported),
                    }
                }
            }
        }

        for delta in decoder.flush() {
            match delta {
                KiroStreamDelta::Text(text) => {
                    output_text.push_str(&text);
                    yield content_delta(sequence, ContentPart::Text { text });
                    sequence += 1;
                }
                KiroStreamDelta::Reasoning(text) => {
                    output_text.push_str(&text);
                    yield content_delta(sequence, ContentPart::Reasoning {
                        payload: Value::Null,
                        opaque: None,
                        summary: Some(text),
                        summary_index: None,
                        signature: None,
                        encrypted_content: None,
                    });
                    sequence += 1;
                }
                _ => {}
            }
        }

        let final_usage = kiro_usage(&usage, &usage_model, &output_text);
        yield CanonicalEvent::Usage {
            sequence_number: sequence,
            usage: final_usage.clone(),
            event_id: None,
            response_id: None,
            timestamp: None,
        };
        sequence += 1;
        yield CanonicalEvent::Terminal {
            sequence_number: sequence,
            state: TerminalState::Complete,
            stop_reason: Some(resolve_final_stop_reason(
                stop_reason,
                provider_stop_reason.as_deref(),
                saw_tool_call,
            )),
            provider_stop_reason,
            stop_details: None,
            usage: Some(final_usage),
            event_id: None,
            response_id: None,
            timestamp: None,
        };
    };
    Ok(DispatchOutput::Stream(Box::pin(stream)))
}

fn merge_usage(current: &mut KiroUsage, next: KiroUsage) {
    if next.input_tokens.is_some() {
        current.input_tokens = next.input_tokens;
    }
    if next.output_tokens.is_some() {
        current.output_tokens = next.output_tokens;
    }
    if next.cache_read_tokens.is_some() {
        current.cache_read_tokens = next.cache_read_tokens;
    }
    if next.cache_write_tokens.is_some() {
        current.cache_write_tokens = next.cache_write_tokens;
    }
    if next.credits.is_some() {
        current.credits = next.credits;
    }
    if next.context_usage_percentage.is_some() {
        current.context_usage_percentage = next.context_usage_percentage;
    }
}

// ─── Quota ──────────────────────────────────────────────────────────────────

fn number_value(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite())
            }
        }
        _ => None,
    }
}

fn text_value(value: Option<&Value>) -> Option<String> {
    value?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn format_iso_millis(millis: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp_millis(millis)
        .map(|value| value.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}

fn iso_date(value: Option<&Value>) -> Option<String> {
    if let Some(number) = number_value(value) {
        let millis = if number > 1_000_000_000_000.0 {
            number
        } else {
            number * 1000.0
        };
        return format_iso_millis(millis as i64);
    }
    let text = text_value(value)?;
    if let Ok(parsed) = DateTime::parse_from_rfc3339(&text) {
        return format_iso_millis(parsed.timestamp_millis());
    }
    if let Ok(date) = NaiveDate::parse_from_str(&text, "%Y-%m-%d") {
        return format_iso_millis(date.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
    }
    if let Ok(date) = NaiveDateTime::parse_from_str(&text, "%Y-%m-%dT%H:%M:%S") {
        return format_iso_millis(date.and_utc().timestamp_millis());
    }
    None
}

fn quota_record(value: &Value) -> Map<String, Value> {
    let root = value.as_object().cloned().unwrap_or_default();
    for key in ["data", "result", "usage"] {
        if let Some(nested) = root.get(key).and_then(Value::as_object) {
            return nested.clone();
        }
    }
    root
}

fn percent_window(
    kind: &str,
    label: &str,
    used: f64,
    resets_at: Option<&str>,
    used_value: f64,
    limit: f64,
) -> Value {
    let used_percent = used.clamp(0.0, 100.0);
    json!({
        "kind": kind,
        "label": label,
        "usedPercent": used_percent,
        "remainingPercent": (100.0 - used_percent).max(0.0),
        "resetsAt": resets_at,
        "used": used_value,
        "limit": limit,
    })
}

fn breakdown_window(breakdown: &Map<String, Value>, reset: Option<&str>) -> Option<Value> {
    let used = number_value(breakdown.get("currentUsageWithPrecision"))
        .or_else(|| number_value(breakdown.get("currentUsage")))?;
    let limit = number_value(breakdown.get("usageLimitWithPrecision"))
        .or_else(|| number_value(breakdown.get("usageLimit")))?;
    if limit <= 0.0 {
        return None;
    }
    let kind = text_value(breakdown.get("resourceType"))
        .map(|value| value.to_lowercase())
        .unwrap_or_else(|| "unknown".to_owned());
    Some(percent_window(
        &kind,
        &kind,
        (used / limit) * 100.0,
        reset,
        used,
        limit,
    ))
}

fn free_trial_window(breakdown: &Map<String, Value>, reset: Option<&str>) -> Option<Value> {
    let trial = breakdown.get("freeTrialInfo")?.as_object()?;
    let used = number_value(trial.get("currentUsageWithPrecision"))
        .or_else(|| number_value(trial.get("currentUsage")))?;
    let limit = number_value(trial.get("usageLimitWithPrecision"))
        .or_else(|| number_value(trial.get("usageLimit")))?;
    if limit <= 0.0 {
        return None;
    }
    let kind = text_value(breakdown.get("resourceType"))
        .map(|value| value.to_lowercase())
        .unwrap_or_else(|| "unknown".to_owned());
    let reset = iso_date(trial.get("freeTrialExpiry")).or_else(|| reset.map(str::to_owned));
    Some(percent_window(
        &format!("{kind}_freetrial"),
        &format!("{kind} (free trial)"),
        (used / limit) * 100.0,
        reset.as_deref(),
        used,
        limit,
    ))
}

fn parse_usage(payload: &Value) -> Value {
    let root = quota_record(payload);
    let reset = iso_date(root.get("nextDateReset")).or_else(|| iso_date(root.get("resetDate")));
    let mut windows = Vec::new();
    if let Some(Value::Array(entries)) = root.get("usageBreakdownList") {
        for entry in entries {
            let Some(breakdown) = entry.as_object() else {
                continue;
            };
            if let Some(window) = breakdown_window(breakdown, reset.as_deref()) {
                windows.push(window);
            }
            if let Some(window) = free_trial_window(breakdown, reset.as_deref()) {
                windows.push(window);
            }
        }
    }
    let subscription = root.get("subscriptionInfo").and_then(Value::as_object);
    let plan = subscription
        .and_then(|value| text_value(value.get("subscriptionTitle")))
        .unwrap_or_else(|| "Kiro".to_owned());
    json!({
        "source": "kiro",
        "plan": plan,
        "windows": windows,
        "error": Value::Null,
    })
}

fn query_string(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn quota_error(message: impl Into<String>) -> Value {
    json!({
        "source": "kiro",
        "plan": Value::Null,
        "windows": [],
        "error": message.into(),
    })
}

/// Reads Kiro's usage limits.
///
/// The usage surface is `q.{region}` and only that; the legacy CodeWhisperer
/// host is not what the observed client calls.
pub async fn fetch_kiro_quota(
    client: &reqwest::Client,
    credential: &str,
    auth_state: Option<&Value>,
) -> Value {
    let token = credential.trim();
    if token.is_empty() {
        return quota_error("Kiro credential is empty.");
    }
    let raw = auth_state.and_then(Value::as_object);
    let region_raw = raw
        .and_then(|value| value.get("region"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let region = if is_aws_region(region_raw) {
        region_raw
    } else {
        "us-east-1"
    };
    let auth_method = raw
        .and_then(|value| value.get("authMethod"))
        .and_then(Value::as_str)
        .unwrap_or("builder-id");
    let profile_arn = resolve_kiro_profile_arn(auth_state);
    let machine_id = machine_id_for_auth_state(auth_state, None);

    let mut headers = vec![
        ("authorization".to_owned(), format!("Bearer {token}")),
        ("accept".to_owned(), "application/json".to_owned()),
        ("connection".to_owned(), "close".to_owned()),
        ("amz-sdk-request".to_owned(), "attempt=1; max=1".to_owned()),
        (
            "amz-sdk-invocation-id".to_owned(),
            Uuid::new_v4().to_string(),
        ),
        ("x-amzn-kiro-agent-mode".to_owned(), "vibe".to_owned()),
        ("x-amzn-codewhisperer-optout".to_owned(), "true".to_owned()),
        (
            "x-amz-user-agent".to_owned(),
            build_kiro_amz_user_agent(KIRO_IDE_VERSION, &machine_id),
        ),
        (
            "user-agent".to_owned(),
            build_kiro_runtime_user_agent(KIRO_IDE_VERSION, &machine_id),
        ),
    ];
    if auth_method == "api_key" {
        headers.push(("tokentype".to_owned(), "API_KEY".to_owned()));
    } else if auth_method == "external_idp" {
        headers.push(("tokentype".to_owned(), "EXTERNAL_IDP".to_owned()));
    }

    let mut query = vec![("origin", "AI_EDITOR")];
    if !profile_arn.is_empty() {
        query.push(("profileArn", profile_arn.as_str()));
    }
    query.push(("resourceType", "AGENTIC_REQUEST"));
    let url = format!(
        "https://q.{region}.amazonaws.com/getUsageLimits?{}",
        query_string(&query)
    );
    let mut builder = client.get(url).timeout(Duration::from_secs(15));
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let response = match builder.send().await {
        Ok(response) => response,
        Err(error) => return quota_error(format!("q-get: {error}")),
    };
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let _ = response.text().await;
        if status == 401 || status == 403 {
            return quota_error(
                "Kiro rejected the stored credential for usage. Reconnect the account if this persists.",
            );
        }
        return quota_error(format!("q-get: HTTP {status}"));
    }
    match response.json::<Value>().await {
        Ok(payload) => parse_usage(&payload),
        Err(_) => quota_error("q-get: response was not JSON"),
    }
}

// ─── Discovery ──────────────────────────────────────────────────────────────

/// Reads the account's available models.
///
/// Returns `None` rather than failing when the catalog cannot be read:
/// discovery is enrichment over the static seed.
pub async fn fetch_kiro_models(
    client: &reqwest::Client,
    credential: &str,
    auth_state: Option<&Value>,
) -> Option<Vec<Value>> {
    let credential = credential.trim();
    if credential.is_empty() {
        return None;
    }
    let raw = auth_state.and_then(Value::as_object);
    let region_raw = raw
        .and_then(|value| value.get("region"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let region = if is_aws_region(region_raw) {
        region_raw
    } else {
        "us-east-1"
    };
    let profile_arn = resolve_kiro_profile_arn(auth_state);
    let mut query = vec![("origin", "AI_EDITOR")];
    if !profile_arn.is_empty() {
        query.push(("profileArn", profile_arn.as_str()));
    }
    let machine_id = machine_id_for_auth_state(auth_state, None);
    let url = format!(
        "https://q.{region}.amazonaws.com/ListAvailableModels?{}",
        query_string(&query)
    );
    let response = client
        .get(url)
        .timeout(Duration::from_secs(20))
        .header("authorization", format!("Bearer {credential}"))
        .header("accept", "application/json")
        .header("connection", "close")
        .header("x-amzn-kiro-agent-mode", "vibe")
        .header("x-amzn-codewhisperer-optout", "true")
        .header("amz-sdk-request", "attempt=1; max=1")
        .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
        .header(
            "user-agent",
            build_kiro_runtime_user_agent(KIRO_IDE_VERSION, &machine_id),
        )
        .header(
            "x-amz-user-agent",
            build_kiro_amz_user_agent(KIRO_IDE_VERSION, &machine_id),
        )
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        let _ = response.text().await;
        return None;
    }
    let payload: Value = response.json().await.ok()?;
    let models = payload.get("models")?.as_array()?;
    let mut definitions = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in models.iter().take(500) {
        let Some(record) = entry.as_object() else {
            continue;
        };
        let model_id = record
            .get("modelId")
            .or_else(|| record.get("id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if model_id.is_empty() || !seen.insert(model_id.to_owned()) {
            continue;
        }
        let context_limit = record
            .get("tokenLimits")
            .and_then(Value::as_object)
            .and_then(|limits| limits.get("maxInputTokens"))
            .and_then(Value::as_i64)
            .filter(|value| *value > 0);
        definitions.push(json!({
            "modelId": model_id,
            "providerId": KIRO_PROVIDER_ID,
            "wireFamily": "chat",
            "endpoint": KIRO_GENERATE_PATH,
            "ctx": context_limit,
            "vision": true,
            "reasoning": true,
            "reasoningEfforts": KIRO_EFFORTS,
            "toolCall": true,
        }));
    }
    if definitions.is_empty() {
        None
    } else {
        Some(definitions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{GenerationControls, SourceSurface};

    fn base_request(messages: Vec<CanonicalMessage>) -> CanonicalRequest {
        CanonicalRequest {
            model: "claude-sonnet-4.5".to_owned(),
            system: None,
            instructions: None,
            messages,
            tools: None,
            tool_choice: None,
            generation_controls: GenerationControls::default(),
            reasoning: None,
            response_format: None,
            cache_hint: None,
            conversation: None,
            metadata: None,
            provider_options: None,
            session_id: None,
            thread_id: None,
            window_id: None,
            turn_id: None,
            parent_turn_id: None,
            conversation_id: None,
            residency: None,
            stream: true,
            source_surface: SourceSurface::Chat,
        }
    }

    fn user_message(text: &str) -> CanonicalMessage {
        CanonicalMessage {
            role: Role::User,
            content: vec![ContentPart::Text { text: text.into() }],
            phase: None,
        }
    }

    #[test]
    fn crc32_matches_the_ieee_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    fn eventstream_message(headers: &[(&str, &str)], payload: &str) -> Vec<u8> {
        let mut header_block = Vec::new();
        for (name, value) in headers {
            header_block.push(name.len() as u8);
            header_block.extend_from_slice(name.as_bytes());
            header_block.push(7);
            header_block.extend_from_slice(&(value.len() as u16).to_be_bytes());
            header_block.extend_from_slice(value.as_bytes());
        }
        let total = EVENTSTREAM_PRELUDE_BYTES
            + header_block.len()
            + payload.len()
            + EVENTSTREAM_TRAILER_BYTES;
        let mut message = Vec::with_capacity(total);
        message.extend_from_slice(&(total as u32).to_be_bytes());
        message.extend_from_slice(&(header_block.len() as u32).to_be_bytes());
        let prelude_crc = crc32(&message[..8]);
        message.extend_from_slice(&prelude_crc.to_be_bytes());
        message.extend_from_slice(&header_block);
        message.extend_from_slice(payload.as_bytes());
        let crc = crc32(&message);
        message.extend_from_slice(&crc.to_be_bytes());
        message
    }

    #[test]
    fn decodes_a_whole_eventstream_message() {
        let message = eventstream_message(
            &[(":event-type", "assistantResponseEvent")],
            r#"{"content":"hello"}"#,
        );
        let decoded = decode_event_stream_messages(&message);
        assert!(decoded.failure.is_none());
        assert_eq!(decoded.consumed, message.len());
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(
            decoded.messages[0]
                .headers
                .get(":event-type")
                .map(String::as_str),
            Some("assistantResponseEvent")
        );
        assert_eq!(
            decoded.messages[0].payload.as_deref(),
            Some(r#"{"content":"hello"}"#)
        );
    }

    #[test]
    fn leaves_a_partial_message_unconsumed() {
        let message = eventstream_message(
            &[(":event-type", "assistantResponseEvent")],
            r#"{"content":"hello"}"#,
        );
        let decoded = decode_event_stream_messages(&message[..message.len() - 2]);
        assert!(decoded.failure.is_none());
        assert!(decoded.messages.is_empty());
        assert_eq!(decoded.consumed, 0);
    }

    #[test]
    fn rejects_a_corrupt_crc() {
        let mut message = eventstream_message(
            &[(":event-type", "assistantResponseEvent")],
            r#"{"content":"hello"}"#,
        );
        let last = message.len() - 1;
        message[last] ^= 0xff;
        let decoded = decode_event_stream_messages(&message);
        assert_eq!(
            decoded.failure.as_ref().map(|failure| failure.reason),
            Some(EventStreamDecodeFailure::MessageCrcMismatch)
        );
    }

    #[test]
    fn splits_thinking_markers_across_events() {
        let mut decoder = KiroStreamDecoder::default();
        let mut outcome = decoder.decode(&KiroRawEvent {
            headers: BTreeMap::from([(
                ":event-type".to_owned(),
                "assistantResponseEvent".to_owned(),
            )]),
            payload: Some(r#"{"content":"before<think"}"#.to_owned()),
        });
        assert_eq!(
            outcome.deltas,
            vec![KiroStreamDelta::Text("before".to_owned())]
        );
        outcome = decoder.decode(&KiroRawEvent {
            headers: BTreeMap::from([(
                ":event-type".to_owned(),
                "assistantResponseEvent".to_owned(),
            )]),
            payload: Some(r#"{"content":"ing>secret</thinking>after"}"#.to_owned()),
        });
        assert_eq!(
            outcome.deltas,
            vec![
                KiroStreamDelta::Reasoning("secret".to_owned()),
                KiroStreamDelta::Text("after".to_owned()),
            ]
        );
        assert!(decoder.flush().is_empty());
    }

    #[test]
    fn flushes_held_marker_prefix_at_eof() {
        let mut decoder = KiroStreamDecoder::default();
        decoder.decode(&KiroRawEvent {
            headers: BTreeMap::from([(
                ":event-type".to_owned(),
                "assistantResponseEvent".to_owned(),
            )]),
            payload: Some(r#"{"content":"tail<"}"#.to_owned()),
        });
        assert_eq!(decoder.flush(), vec![KiroStreamDelta::Text("<".to_owned())]);
    }

    #[test]
    fn normalizes_upstream_stop_vocabulary() {
        assert_eq!(
            normalize_kiro_stop_reason(Some("endTurn")),
            Some(CanonicalStopReason::Stop)
        );
        assert_eq!(
            normalize_kiro_stop_reason(Some("max_tokens")),
            Some(CanonicalStopReason::Length)
        );
        assert_eq!(
            normalize_kiro_stop_reason(Some("toolUse")),
            Some(CanonicalStopReason::ToolUse)
        );
        assert_eq!(normalize_kiro_stop_reason(Some("mystery")), None);
        assert!(is_kiro_truncation_reason(Some(
            "model_context_window_exceeded"
        )));
    }

    #[test]
    fn chooses_the_effort_schema_from_the_model_id() {
        assert_eq!(
            kiro_effort_path("claude-sonnet-4.6"),
            Some(KiroEffortPath::OutputConfig)
        );
        assert_eq!(kiro_effort_path("claude-sonnet-4.5"), None);
        assert_eq!(kiro_effort_path("claude-opus-4.5"), None);
        assert_eq!(kiro_effort_path("claude-3-5-sonnet"), None);
        assert_eq!(
            kiro_effort_path("gpt-5.6-sol"),
            Some(KiroEffortPath::Reasoning)
        );
        assert_eq!(kiro_effort_path("deepseek-3.2"), None);
    }

    #[test]
    fn maps_effort_tiers_to_the_wire_schemas() {
        let reasoning = build_additional_model_request_fields(&KiroWireRequestOptions {
            conversation_id: "c".into(),
            model_id: "gpt-5.6-sol".into(),
            profile_arn: String::new(),
            effort: Some(ReasoningEffort::Max),
            thinking_budget: None,
            effort_path: Some(KiroEffortPath::Reasoning),
        });
        assert_eq!(reasoning, Some(json!({"reasoning": {"effort": "xhigh"}})));
        let config = build_additional_model_request_fields(&KiroWireRequestOptions {
            conversation_id: "c".into(),
            model_id: "claude-sonnet-4.5".into(),
            profile_arn: String::new(),
            effort: Some(ReasoningEffort::Xhigh),
            thinking_budget: None,
            effort_path: Some(KiroEffortPath::OutputConfig),
        });
        assert_eq!(
            config,
            Some(json!({
                "thinking": {"type": "adaptive", "display": "summarized"},
                "output_config": {"effort": "high"},
            }))
        );
    }

    #[test]
    fn sanitizes_and_dedupes_tool_names() {
        assert_eq!(wire_tool_name("foo bar!", 0), "foo_bar");
        let long = "x".repeat(80);
        let wire = wire_tool_name(&long, 0);
        assert_eq!(wire.chars().count(), KIRO_TOOL_NAME_MAX_LENGTH);
        let digest = Sha256::digest(long.as_bytes());
        let hash: String = digest
            .iter()
            .take(6)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(wire.ends_with(&hash));
        assert_eq!(wire_tool_name("   ", 2), "tool_3");
    }

    #[test]
    fn normalizes_json_schemas_for_the_upstream() {
        let schema = json!({
            "type": "string",
            "additionalProperties": true,
            "required": ["present", "absent"],
            "properties": {"present": {"type": "string"}},
        });
        let normalized = normalize_json_schema(&schema);
        assert_eq!(normalized.get("type"), Some(&json!("object")));
        assert!(normalized.get("additionalProperties").is_none());
        assert_eq!(normalized.get("required"), Some(&json!(["present"])));
    }

    #[test]
    fn derives_stable_machine_ids() {
        assert_eq!(
            derive_oauth_machine_id("refresh"),
            derive_oauth_machine_id("refresh")
        );
        assert_ne!(
            derive_oauth_machine_id("refresh"),
            derive_api_key_machine_id("refresh")
        );
        let frozen = "a".repeat(64);
        assert_eq!(
            normalize_machine_id(Some(&json!(frozen))).as_deref(),
            Some(frozen.as_str())
        );
        let doubled = "b".repeat(32);
        let expected = "b".repeat(64);
        assert_eq!(
            normalize_machine_id(Some(&json!(doubled))).as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(normalize_machine_id(Some(&json!("not-hex"))), None);
    }

    #[test]
    fn resolves_profile_arns_by_sign_in_family() {
        assert_eq!(
            resolve_kiro_profile_arn(Some(&json!({"authMethod": "api_key"}))),
            ""
        );
        assert_eq!(
            resolve_kiro_profile_arn(Some(&json!({"authMethod": "google"}))),
            SOCIAL_PROFILE_ARN
        );
        assert_eq!(
            resolve_kiro_profile_arn(Some(&json!({"authMethod": "builder-id"}))),
            BUILDER_ID_PROFILE_ARN
        );
        assert_eq!(
            resolve_kiro_profile_arn(Some(
                &json!({"authMethod": "builder-id", "profileArn": "arn:own"})
            )),
            "arn:own"
        );
    }

    #[test]
    fn estimates_tokens_from_the_context_percentage() {
        let usage = KiroUsage {
            context_usage_percentage: Some(10.0),
            ..Default::default()
        };
        let record = kiro_usage(&usage, "claude-sonnet-4.5", "abcdefgh");
        assert_eq!(record.input_tokens, 99_998);
        assert_eq!(record.output_tokens, 2);
        assert_eq!(record.total_tokens, Some(TokenCount::Number(100_000)));
        assert_eq!(record.estimated_cost, None);
    }

    #[test]
    fn builds_a_single_turn_payload_with_the_stable_prefix() {
        let mut request = base_request(vec![user_message("Hello")]);
        request.system = Some(vec![ContentPart::Text {
            text: "You are concise.".into(),
        }]);
        let built = build_kiro_wire_request(
            &request,
            &KiroWireRequestOptions {
                conversation_id: "conv".into(),
                model_id: "claude-sonnet-4.5".into(),
                profile_arn: String::new(),
                effort: None,
                thinking_budget: Some(1_024),
                effort_path: None,
            },
        )
        .expect("conversation is expressible");
        let value = &built.payload["conversationState"];
        assert_eq!(value["agentTaskType"], json!("vibe"));
        assert_eq!(value["conversationId"], json!("conv"));
        assert_eq!(value["history"], json!([]));
        let content = value["currentMessage"]["userInputMessage"]["content"]
            .as_str()
            .expect("content is a string");
        assert!(content.starts_with("<thinking_mode>enabled</thinking_mode>"));
        assert!(content.contains("You are concise."));
        assert!(content.ends_with("Hello"));
        assert!(built.payload.get("profileArn").is_none());
    }

    #[test]
    fn refuses_a_tool_call_with_missing_arguments() {
        let request = base_request(vec![
            user_message("Use a tool"),
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    call_id: "call-1".into(),
                    name: "missing_tool".into(),
                    arguments: json!("not json"),
                    index: None,
                    item_id: None,
                    call_kind: None,
                }],
                phase: None,
            },
            user_message("continue"),
        ]);
        let error = build_kiro_wire_request(
            &request,
            &KiroWireRequestOptions {
                conversation_id: "conv".into(),
                model_id: "claude-sonnet-4.5".into(),
                profile_arn: String::new(),
                effort: None,
                thinking_budget: None,
                effort_path: None,
            },
        )
        .expect_err("a tool call for nothing is refused");
        assert!(
            error
                .problems
                .iter()
                .any(|problem| problem.starts_with("spec:1"))
        );
    }

    #[test]
    fn pairs_tool_calls_and_results_on_the_wire() {
        let mut request = base_request(vec![
            user_message("Use a tool"),
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    call_id: "call.1".into(),
                    name: "look up".into(),
                    arguments: json!({"q": "rust"}),
                    index: None,
                    item_id: None,
                    call_kind: None,
                }],
                phase: None,
            },
            CanonicalMessage {
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    call_id: "call.1".into(),
                    content: ToolResultContent::Text("done".into()),
                    is_error: Some(false),
                    call_kind: None,
                    item_id: None,
                }],
                phase: None,
            },
        ]);
        request.tools = Some(vec![ToolDefinition {
            name: "look up".into(),
            description: None,
            json_schema: json!({"type": "object", "properties": {}}),
            strict: None,
            eager_input_streaming: None,
            defer_loading: None,
            input_examples: None,
            tool_type: None,
            native_type: None,
            allowed_callers: None,
        }]);
        let built = build_kiro_wire_request(
            &request,
            &KiroWireRequestOptions {
                conversation_id: "conv".into(),
                model_id: "claude-sonnet-4.5".into(),
                profile_arn: String::new(),
                effort: None,
                thinking_budget: None,
                effort_path: None,
            },
        )
        .expect("tool call and result pair");
        assert_eq!(
            built.tool_name_map.get("look_up").map(String::as_str),
            Some("look up")
        );
        let state = &built.payload["conversationState"];
        assert_eq!(state["agentTaskType"], json!("spectask"));
        let history = state["history"].as_array().expect("history array");
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn parses_usage_windows_and_the_free_trial() {
        let parsed = parse_usage(&json!({
            "subscriptionInfo": {"subscriptionTitle": "Pro"},
            "nextDateReset": 1_700_000_000,
            "usageBreakdownList": [{
                "resourceType": "AGENTIC_REQUEST",
                "currentUsageWithPrecision": 25,
                "usageLimitWithPrecision": 100,
                "freeTrialInfo": {
                    "currentUsage": 5,
                    "usageLimit": 10,
                    "freeTrialExpiry": 1_800_000_000,
                },
            }],
        }));
        assert_eq!(parsed["source"], json!("kiro"));
        assert_eq!(parsed["plan"], json!("Pro"));
        assert_eq!(parsed["error"], Value::Null);
        let windows = parsed["windows"].as_array().expect("windows");
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0]["kind"], json!("agentic_request"));
        assert_eq!(windows[0]["usedPercent"], json!(25.0));
        assert_eq!(windows[0]["remainingPercent"], json!(75.0));
        assert_eq!(windows[0]["resetsAt"], json!("2023-11-14T22:13:20.000Z"));
        assert_eq!(windows[1]["kind"], json!("agentic_request_freetrial"));
        assert_eq!(windows[1]["label"], json!("agentic_request (free trial)"));
        assert_eq!(windows[1]["usedPercent"], json!(50.0));
        assert_eq!(windows[1]["resetsAt"], json!("2027-01-15T08:00:00.000Z"));
    }
}
