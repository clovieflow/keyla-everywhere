//! Antigravity (Google Cloud Code Assist) adapter.
//!
//! Antigravity is Google's Cloud Code Assist backend
//! (`daily-cloudcode-pa.googleapis.com`), reached through Google OAuth. The
//! wire reuses the Gemini `generateContent` envelope, wrapped in Antigravity's
//! agent envelope (`project` / `requestId` / wire `model` / `request`) and
//! POSTed to the fixed `v1internal:{generate,streamGenerate}Content` RPC — no
//! per-model URL path. Ported from
//! `src/providers/integrations/antigravity/antigravity.ts` and
//! `antigravity-protocol.ts`.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use keyla_core::{
    CanonicalEvent, CanonicalRequest, CanonicalStopReason, ContentPart, GatewayError,
    GatewayErrorCode, GatewayErrorOrigin, Role, TerminalState, ThinkingType, TokenCount,
    ToolResultContent, UsageRecord,
};
use keyla_protocol::failure::{
    classify_upstream_error, extract_upstream_message, upstream_error_identifier,
};
use keyla_protocol::streaming::SseDecoder;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapter::{DispatchCredential, DispatchOutput, DispatchTarget, upstream_http_error};

pub const ANTIGRAVITY_PROVIDER_ID: &str = "antigravity";
pub const ANTIGRAVITY_BASE_URL: &str = "https://daily-cloudcode-pa.googleapis.com";
pub const ANTIGRAVITY_SANDBOX_BASE_URL: &str = "https://daily-cloudcode-pa.sandbox.googleapis.com";
pub const ANTIGRAVITY_GENERATE_PATH: &str = "/v1internal:generateContent";
pub const ANTIGRAVITY_STREAM_GENERATE_PATH: &str = "/v1internal:streamGenerateContent?alt=sse";
pub const ANTIGRAVITY_LOAD_CODE_ASSIST_METADATA_IDE_TYPE: &str = "ANTIGRAVITY";
pub const ANTIGRAVITY_SYSTEM_INSTRUCTION: &str = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.**Absolute paths only****Proactiveness**";

/// Sentinel Google APIs accept in place of a real base64 thought signature.
const SKIP_THOUGHT_SIGNATURE: &str = "skip_thought_signature_validator";

const ANTIGRAVITY_OS_TYPE: &str = "darwin";
const ANTIGRAVITY_ARCH: &str = "arm64";
const ANTIGRAVITY_CL: &str = "963137146";
const ANTIGRAVITY_DEFAULT_VERSION: &str = "2.19.1";

const MAX_SESSION_STATES: usize = 256;
const DEFAULT_SESSION_STATE_IDLE_TTL: Duration = Duration::from_secs(30 * 60);
const PROJECT_ID_CACHE_MAX: usize = 1024;
const ONBOARD_TIMEOUT: Duration = Duration::from_secs(30);
const ONBOARD_POLL_INTERVAL: Duration = Duration::from_secs(1);
const CONTROL_PLANE_TIMEOUT: Duration = Duration::from_secs(30);

// --- Client version / User-Agent -------------------------------------------

fn version_slot() -> &'static Mutex<String> {
    static VERSION: LazyLock<Mutex<String>> =
        LazyLock::new(|| Mutex::new(ANTIGRAVITY_DEFAULT_VERSION.to_owned()));
    &VERSION
}

/// Current `antigravity/hub` client version snapshot.
pub fn get_antigravity_version() -> String {
    version_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

/// Replaces the discovered `antigravity/hub` version.
pub fn set_antigravity_version(value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    *version_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = trimmed.to_owned();
}

/// Full `antigravity/hub/<version>` User-Agent string.
pub fn get_antigravity_user_agent() -> String {
    format!(
        "antigravity/hub/{} (aidev_client; os_type={ANTIGRAVITY_OS_TYPE}; arch={ANTIGRAVITY_ARCH}; cl={ANTIGRAVITY_CL})",
        get_antigravity_version()
    )
}

// --- Per-wire-id request constants -----------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntigravityModelWireProfile {
    pub model_enum: Option<&'static str>,
    pub max_output_tokens: i64,
}

/// `maxOutputTokens` the backend enforces per wire id. Keyed by the routed
/// upstream wire id (post effort-routing), not the collapsed logical id.
pub fn get_antigravity_model_wire_profile(
    wire_model_id: &str,
) -> Option<AntigravityModelWireProfile> {
    match wire_model_id {
        "claude-opus-4-6-thinking" => Some(AntigravityModelWireProfile {
            model_enum: None,
            max_output_tokens: 64_000,
        }),
        "claude-sonnet-4-6" => Some(AntigravityModelWireProfile {
            model_enum: None,
            max_output_tokens: 64_000,
        }),
        "gemini-3-flash-agent" => Some(AntigravityModelWireProfile {
            model_enum: Some("MODEL_PLACEHOLDER_M132"),
            max_output_tokens: 65_536,
        }),
        "gemini-3.1-pro-low" => Some(AntigravityModelWireProfile {
            model_enum: Some("MODEL_PLACEHOLDER_M36"),
            max_output_tokens: 65_535,
        }),
        "gemini-pro-agent" => Some(AntigravityModelWireProfile {
            model_enum: Some("MODEL_PLACEHOLDER_M16"),
            max_output_tokens: 65_535,
        }),
        _ => None,
    }
}

/// Collapses logical/display model ids to the upstream deployment ids.
pub fn antigravity_wire_model_id(model_id: &str) -> String {
    match model_id {
        "claude-opus-4-6" => "claude-opus-4-6-thinking",
        "gemini-3.1-pro" | "gemini-3.1-pro-high" => "gemini-pro-agent",
        "gemini-3.6-flash" => "gemini-3.6-flash-low",
        "gemini-3.7-flash" => "gemini-3.7-flash-low",
        "gemini-3.8-flash" => "gemini-3.8-flash-low",
        "gpt-oss-120b" => "gpt-oss-120b-medium",
        other => other,
    }
    .to_owned()
}

/// Collapses effort-routed wire ids back to their logical catalog id.
pub fn collapse_antigravity_variant(model_id: &str) -> String {
    match model_id {
        "claude-opus-4-6-thinking" => "claude-opus-4-6".to_owned(),
        "gemini-pro-agent" => "gemini-3.1-pro".to_owned(),
        other => {
            let mut value = other.to_owned();
            for suffix in ["extra-low", "low", "medium", "high", "tiered", "agent"] {
                let needle = format!("-{suffix}");
                if value.ends_with(&needle) {
                    value.truncate(value.len() - needle.len());
                    break;
                }
            }
            value
        }
    }
}

/// Static Antigravity catalog (the console's fallback when live discovery
/// fails).
#[derive(Debug, Clone, Copy)]
pub struct AntigravityModel {
    pub model_id: &'static str,
    pub context_limit: i64,
    pub output_limit: i64,
    pub reasoning: bool,
}

pub const ANTIGRAVITY_MODELS: &[AntigravityModel] = &[
    AntigravityModel {
        model_id: "claude-sonnet-4-6",
        context_limit: 250_000,
        output_limit: 64_000,
        reasoning: true,
    },
    AntigravityModel {
        model_id: "claude-opus-4-6",
        context_limit: 250_000,
        output_limit: 64_000,
        reasoning: true,
    },
    AntigravityModel {
        model_id: "gemini-3-flash",
        context_limit: 1_048_576,
        output_limit: 65_536,
        reasoning: true,
    },
    AntigravityModel {
        model_id: "gemini-3.1-flash-image",
        context_limit: 200_000,
        output_limit: 64_000,
        reasoning: false,
    },
    AntigravityModel {
        model_id: "gemini-3.1-pro",
        context_limit: 1_048_576,
        output_limit: 65_535,
        reasoning: true,
    },
    AntigravityModel {
        model_id: "gemini-3.6-flash",
        context_limit: 1_048_576,
        output_limit: 65_536,
        reasoning: true,
    },
    AntigravityModel {
        model_id: "gemini-3.7-flash",
        context_limit: 1_048_576,
        output_limit: 65_536,
        reasoning: true,
    },
    AntigravityModel {
        model_id: "gemini-3.8-flash",
        context_limit: 1_048_576,
        output_limit: 65_536,
        reasoning: true,
    },
    AntigravityModel {
        model_id: "gpt-oss-120b",
        context_limit: 131_072,
        output_limit: 32_768,
        reasoning: true,
    },
];

/// True when `model_id` is one of the catalog's logical ids.
pub fn is_antigravity_catalog_model(model_id: &str) -> bool {
    ANTIGRAVITY_MODELS
        .iter()
        .any(|model| model.model_id == model_id)
}

/// Thinking budget per wire model, matching the client's effort tiers.
pub fn antigravity_thinking_budget(model_id: &str) -> Option<i64> {
    if !model_id.contains("claude") && !model_id.contains("gemini-3") {
        return None;
    }
    if model_id.ends_with("-low") {
        return Some(1_000);
    }
    if model_id.ends_with("-medium") {
        return Some(4_000);
    }
    if model_id.ends_with("-high") {
        return Some(10_000);
    }
    Some(if model_id.contains("3.1-pro") {
        10_001
    } else {
        10_000
    })
}

// --- Live model discovery ---------------------------------------------------

const ANTIGRAVITY_DISCOVERY_PATH: &str = "/v1internal:fetchAvailableModels";
const ANTIGRAVITY_DEFAULT_CONTEXT_WINDOW: i64 = 200_000;
const ANTIGRAVITY_DEFAULT_MAX_OUTPUT_TOKENS: i64 = 64_000;

fn antigravity_discovery_denylisted(wire_id: &str) -> bool {
    matches!(wire_id, "chat_20706" | "chat_23310" | "gemini-2.5-pro")
}

fn positive_int(value: Option<&Value>, fallback: i64) -> i64 {
    value
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn normalize_discovery_models(payload: &Value) -> Option<Vec<Value>> {
    let models = payload.get("models")?.as_object()?;
    let mut by_id: HashMap<String, Value> = HashMap::new();
    for (wire_id, raw) in models {
        if antigravity_discovery_denylisted(wire_id) {
            continue;
        }
        let Some(model) = raw.as_object() else {
            continue;
        };
        if model.get("isInternal") == Some(&Value::Bool(true)) {
            continue;
        }
        let logical_id = collapse_antigravity_variant(wire_id);
        let definition = json!({
            "modelId": logical_id,
            "wireFamily": "chat",
            "endpointPath": ANTIGRAVITY_GENERATE_PATH,
            "contextLimit": positive_int(
                model.get("maxTokens"),
                ANTIGRAVITY_DEFAULT_CONTEXT_WINDOW,
            ),
            "outputLimit": positive_int(
                model.get("maxOutputTokens"),
                ANTIGRAVITY_DEFAULT_MAX_OUTPUT_TOKENS,
            ),
            "modalities": {"input": ["text", "image"], "output": ["text"]},
            "reasoning": model.get("supportsThinking") == Some(&Value::Bool(true)),
            "toolCall": true,
            // Cost is catalog-owned (`models.dev` in the TypeScript build) and
            // is attached by the registry, not by discovery.
        });
        let context = definition
            .get("contextLimit")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let replace = by_id
            .get(&logical_id)
            .and_then(|existing| existing.get("contextLimit"))
            .and_then(Value::as_i64)
            .map(|existing| context > existing)
            .unwrap_or(true);
        if replace {
            by_id.insert(logical_id, definition);
        }
    }
    let mut definitions: Vec<Value> = by_id.into_values().collect();
    definitions.sort_by(|left, right| {
        let left = left.get("modelId").and_then(Value::as_str).unwrap_or("");
        let right = right.get("modelId").and_then(Value::as_str).unwrap_or("");
        left.cmp(right)
    });
    Some(definitions)
}

/// Fetches Antigravity's live catalog, returning `None` when unreachable.
pub async fn discover_antigravity_models(
    client: &reqwest::Client,
    access_token: &str,
    base_url: Option<&str>,
) -> Option<Vec<Value>> {
    let primary = base_url
        .unwrap_or(ANTIGRAVITY_BASE_URL)
        .trim_end_matches('/')
        .to_owned();
    for endpoint in [primary, ANTIGRAVITY_SANDBOX_BASE_URL.to_owned()] {
        let response = client
            .post(format!("{endpoint}{ANTIGRAVITY_DISCOVERY_PATH}"))
            .timeout(Duration::from_secs(3))
            .header("authorization", format!("Bearer {access_token}"))
            .header("content-type", "application/json")
            .header("user-agent", get_antigravity_user_agent())
            .body("{}")
            .send()
            .await;
        let Ok(response) = response else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(payload) = response.json::<Value>().await else {
            continue;
        };
        if let Some(models) = normalize_discovery_models(&payload) {
            return Some(models);
        }
    }
    None
}

// --- Skip-thought-signature bypass -----------------------------------------

fn is_gemini_3_plus(model_id: &str) -> bool {
    let Some(rest) = model_id.strip_prefix("gemini-") else {
        return false;
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return false;
    }
    let major = digits.parse::<u32>().unwrap_or(0);
    let followed_by_break = rest[digits.len()..]
        .chars()
        .next()
        .map(|ch| ch == '.' || ch == '-')
        .unwrap_or(true);
    followed_by_break && (major >= 3 || digits.len() >= 2)
}

/// Adds the `skip_thought_signature_validator` sentinel to the first unsigned
/// `functionCall` of each `model`-role turn. No-op for non-Gemini-3+ models.
pub fn apply_skip_thought_signature_bypass(payload: &mut Value, model_id: &str) {
    if !is_gemini_3_plus(model_id) {
        return;
    }
    let Some(contents) = payload.get_mut("contents").and_then(Value::as_array_mut) else {
        return;
    };
    for turn in contents {
        let Some(turn) = turn.as_object_mut() else {
            continue;
        };
        if turn.get("role").and_then(Value::as_str) != Some("model") {
            continue;
        }
        let Some(parts) = turn.get_mut("parts").and_then(Value::as_array_mut) else {
            continue;
        };
        let mut first = true;
        for part in parts {
            let Some(part) = part.as_object_mut() else {
                continue;
            };
            if !part.get("functionCall").is_some_and(Value::is_object) {
                continue;
            }
            let signed = part.get("thoughtSignature").is_some_and(Value::is_string);
            if first && !signed {
                part.insert(
                    "thoughtSignature".into(),
                    Value::String(SKIP_THOUGHT_SIGNATURE.to_owned()),
                );
            }
            first = false;
        }
    }
}

// --- Session state ----------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AntigravitySessionState {
    pub agent_id: Option<String>,
    pub trajectory_id: Option<String>,
    pub session_id: Option<String>,
    pub step_index: Option<i64>,
    pub last_execution_id: Option<String>,
}

struct SessionEntry {
    state: AntigravitySessionState,
    touched: Instant,
}

/// Bounded in-process conversation store keyed by route identity. Idle entries
/// expire, recency refreshes on access, and the oldest entry is evicted at the
/// cap.
pub struct AntigravitySessionStore {
    entries: Mutex<HashMap<String, SessionEntry>>,
    max_entries: usize,
    idle_ttl: Duration,
}

impl AntigravitySessionStore {
    pub fn new(max_entries: usize, idle_ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
            idle_ttl,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, SessionEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Number of live entries after expiry eviction.
    pub fn size(&self) -> usize {
        let mut entries = self.lock();
        evict_expired(&mut entries, self.idle_ttl);
        entries.len()
    }

    /// Runs `apply` against the live state for `key`, creating it when absent or
    /// expired. The state is written back before the guard is released so
    /// concurrent turns see the same sticky ids.
    pub fn with_state<R>(
        &self,
        key: &str,
        apply: impl FnOnce(&mut AntigravitySessionState) -> R,
    ) -> R {
        let mut entries = self.lock();
        evict_expired(&mut entries, self.idle_ttl);
        let now = Instant::now();
        let entry = entries
            .entry(key.to_owned())
            .or_insert_with(|| SessionEntry {
                state: AntigravitySessionState::default(),
                touched: now,
            });
        entry.touched = now;
        let result = apply(&mut entry.state);
        while entries.len() > self.max_entries {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.touched)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
        }
        result
    }

    /// Deletes every entry whose key starts with `prefix` (except `keep`).
    pub fn reset_by_prefix(&self, prefix: &str, keep: Option<&str>) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|key, _| !(key.starts_with(prefix) && Some(key.as_str()) != keep));
        before - entries.len()
    }

    /// Resets one conversation/model state, or all model states for a
    /// conversation.
    pub fn reset_session(&self, route_identity: &str, wire_model_id: Option<&str>) -> usize {
        match wire_model_id {
            Some(wire_model_id) => {
                self.reset_by_prefix(&session_state_key(route_identity, wire_model_id), None)
            }
            None => self.reset_by_prefix(
                &format!("{}:", session_identity_digest(route_identity)),
                None,
            ),
        }
    }
}

impl Default for AntigravitySessionStore {
    fn default() -> Self {
        Self::new(MAX_SESSION_STATES, DEFAULT_SESSION_STATE_IDLE_TTL)
    }
}

fn evict_expired(entries: &mut HashMap<String, SessionEntry>, idle_ttl: Duration) {
    let now = Instant::now();
    entries.retain(|_, entry| now.duration_since(entry.touched) < idle_ttl);
}

fn global_session_store() -> &'static AntigravitySessionStore {
    static STORE: LazyLock<AntigravitySessionStore> =
        LazyLock::new(AntigravitySessionStore::default);
    &STORE
}

fn session_identity_digest(value: &str) -> String {
    let mut hash: u64 = 14_695_981_039_346_656_037;
    for character in value.chars() {
        hash ^= character as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    format!("{hash:016x}")
}

fn session_state_key(route_identity: &str, wire_model_id: &str) -> String {
    format!(
        "{}:antigravity:{wire_model_id}",
        session_identity_digest(route_identity)
    )
}

/// Negative signed session id matching the captured client shape.
pub fn signed_antigravity_session_id(seed: Option<&str>) -> String {
    if let Some(seed) = seed {
        let digits = seed.strip_prefix('-').unwrap_or(seed);
        if !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit()) {
            return seed.to_owned();
        }
    }
    let text = seed
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let digest = Sha256::digest(text.as_bytes());
    let head_hex = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let head = u64::from_str_radix(&head_hex, 16).unwrap_or(0);
    let random_bytes = *Uuid::new_v4().as_bytes();
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(&random_bytes[..8]);
    let random_part = u64::from_be_bytes(buffer) % 9_000_000_000_000_000_000;
    let combined = (head & 0x7FFF_FFFF_FFFF_FFFF) | random_part;
    format!("-{combined}")
}

fn first_user_text(request: &CanonicalRequest) -> String {
    for message in &request.messages {
        if message.role != Role::User {
            continue;
        }
        for part in &message.content {
            if let ContentPart::Text { text } = part {
                if !text.is_empty() {
                    return text.clone();
                }
            }
        }
    }
    String::new()
}

// --- Sandbox failover -------------------------------------------------------

fn is_failover_status(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

/// Sandbox twin of a production Antigravity URL, or `None` when the base is
/// not the known production host.
pub fn failover_antigravity_url(url: &str, base_url: &str) -> Option<String> {
    if !base_url.contains("daily-cloudcode-pa.googleapis.com") {
        return None;
    }
    let sandbox_base = base_url.replace(
        "daily-cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.sandbox.googleapis.com",
    );
    url.strip_prefix(base_url)
        .map(|suffix| format!("{sandbox_base}{suffix}"))
}

// --- Gemini payload encoder -------------------------------------------------

fn is_record(value: &Value) -> bool {
    value.is_object()
}

const GEMINI_SCHEMA_KEYS: &[&str] = &[
    "type",
    "format",
    "title",
    "description",
    "nullable",
    "enum",
    "const",
    "maxItems",
    "minItems",
    "properties",
    "required",
    "propertyOrdering",
    "minProperties",
    "maxProperties",
    "items",
    "anyOf",
    "oneOf",
];

fn sanitize_gemini_schema(value: &Value) -> Value {
    let Some(source) = value.as_object() else {
        return json!({});
    };
    let mut schema = Map::new();
    for (key, child) in source {
        if !GEMINI_SCHEMA_KEYS.contains(&key.as_str()) {
            continue;
        }
        match key.as_str() {
            "type" => match child {
                Value::String(kind) if kind == "null" => {
                    schema.insert("nullable".into(), Value::Bool(true));
                }
                Value::String(kind) => {
                    schema.insert("type".into(), Value::String(kind.clone()));
                }
                Value::Array(types) => {
                    let names: Vec<&str> = types.iter().filter_map(Value::as_str).collect();
                    if names.contains(&"null") {
                        schema.insert("nullable".into(), Value::Bool(true));
                    }
                    let non_null: Vec<&str> = names
                        .iter()
                        .copied()
                        .filter(|name| *name != "null")
                        .collect();
                    if non_null.len() == 1 {
                        schema.insert("type".into(), Value::String(non_null[0].to_owned()));
                    } else if non_null.len() > 1 {
                        schema.insert(
                            "anyOf".into(),
                            Value::Array(
                                non_null.iter().map(|kind| json!({"type": kind})).collect(),
                            ),
                        );
                    }
                }
                _ => {}
            },
            "const" => {
                schema.insert("enum".into(), Value::Array(vec![child.clone()]));
            }
            "properties" => {
                if let Some(properties) = child.as_object() {
                    let mut sanitized = Map::new();
                    for (name, property) in properties {
                        sanitized.insert(name.clone(), sanitize_gemini_schema(property));
                    }
                    schema.insert("properties".into(), Value::Object(sanitized));
                }
            }
            "items" => {
                if is_record(child) {
                    schema.insert("items".into(), sanitize_gemini_schema(child));
                }
            }
            "anyOf" | "oneOf" => {
                if let Some(entries) = child.as_array() {
                    schema.insert(
                        "anyOf".into(),
                        Value::Array(entries.iter().map(sanitize_gemini_schema).collect()),
                    );
                }
            }
            "required" => {
                if let Some(entries) = child.as_array() {
                    schema.insert(
                        "required".into(),
                        Value::Array(
                            entries
                                .iter()
                                .filter_map(Value::as_str)
                                .map(|name| Value::String(name.to_owned()))
                                .collect(),
                        ),
                    );
                }
            }
            _ => {
                schema.insert(key.clone(), child.clone());
            }
        }
    }
    if let (Some(Value::Array(required)), Some(Value::Object(properties))) =
        (schema.get("required"), schema.get("properties"))
    {
        let known: HashSet<String> = properties.keys().cloned().collect();
        let pruned: Vec<Value> = required
            .iter()
            .filter(|name| {
                name.as_str()
                    .map(|name| known.contains(name))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        schema.insert("required".into(), Value::Array(pruned));
    }
    if schema.get("type").and_then(Value::as_str) == Some("array") && schema.get("items").is_none()
    {
        schema.insert("items".into(), json!({}));
    }
    Value::Object(schema)
}

fn split_data_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("data:")?;
    let (media_type, data) = rest.split_once(";base64,")?;
    if media_type.is_empty() || data.is_empty() {
        return None;
    }
    Some((media_type.to_owned(), data.to_owned()))
}

struct ResolvedImage {
    url: Option<String>,
    file_id: Option<String>,
}

fn resolve_image_source(payload: &Value) -> Option<ResolvedImage> {
    if let Some(url) = payload.as_str() {
        return (!url.is_empty()).then(|| ResolvedImage {
            url: Some(url.to_owned()),
            file_id: None,
        });
    }
    let value = payload.as_object()?;
    let top_file_id = value.get("file_id").and_then(Value::as_str);
    let nested = value.get("image_url");
    if nested.is_none() {
        if let Some(file_id) = top_file_id {
            return Some(ResolvedImage {
                url: None,
                file_id: Some(file_id.to_owned()),
            });
        }
    }
    if let Some(url) = nested.and_then(Value::as_str) {
        return Some(ResolvedImage {
            url: Some(url.to_owned()),
            file_id: None,
        });
    }
    if let Some(inner) = nested.and_then(Value::as_object) {
        let url = inner.get("url").and_then(Value::as_str);
        let file_id = inner.get("file_id").and_then(Value::as_str);
        if url.is_some() || file_id.is_some() {
            return Some(ResolvedImage {
                url: url.map(str::to_owned),
                file_id: file_id.map(str::to_owned),
            });
        }
    }
    let url = value.get("url").and_then(Value::as_str);
    let file_id = value.get("file_id").and_then(Value::as_str);
    if url.is_some() || file_id.is_some() {
        return Some(ResolvedImage {
            url: url.map(str::to_owned),
            file_id: file_id.map(str::to_owned),
        });
    }
    if let Some(source) = value.get("source").and_then(Value::as_object) {
        match source.get("type").and_then(Value::as_str) {
            Some("base64") => {
                let data = source.get("data").and_then(Value::as_str)?;
                let media_type = source
                    .get("media_type")
                    .and_then(Value::as_str)
                    .unwrap_or("image/png");
                return Some(ResolvedImage {
                    url: Some(format!("data:{media_type};base64,{data}")),
                    file_id: None,
                });
            }
            Some("url") => {
                let url = source.get("url").and_then(Value::as_str)?;
                return Some(ResolvedImage {
                    url: Some(url.to_owned()),
                    file_id: None,
                });
            }
            Some("file") => {
                let file_id = source.get("file_id").and_then(Value::as_str)?;
                return Some(ResolvedImage {
                    url: None,
                    file_id: Some(file_id.to_owned()),
                });
            }
            _ => {}
        }
    }
    None
}

fn gemini_media_parts(
    data: &Value,
    media_type: &str,
    file_id: Option<&str>,
    url: Option<&str>,
    source_type: Option<&str>,
) -> Vec<Value> {
    if source_type == Some("text") {
        if let Some(text) = data.as_str() {
            return vec![json!({"text": text})];
        }
    }
    if let Some(file_id) = file_id {
        return vec![json!({"text": format!("[file: {file_id}]")})];
    }
    let candidate = data.as_str().filter(|value| !value.is_empty()).or(url);
    let Some(candidate) = candidate else {
        return vec![json!({"text": "[file: unsupported source]"})];
    };
    if let Some((mime, body)) = split_data_url(candidate) {
        return vec![json!({"inlineData": {"mimeType": mime, "data": body}})];
    }
    if url.is_some() || candidate.starts_with("http://") || candidate.starts_with("https://") {
        return vec![json!({"fileData": {"fileUri": candidate}})];
    }
    vec![json!({"inlineData": {"mimeType": media_type, "data": candidate}})]
}

fn parse_json_object(value: &str) -> Value {
    match serde_json::from_str::<Value>(value) {
        Ok(parsed @ Value::Object(_)) => parsed,
        Ok(_) | Err(_) => {
            if value.is_empty() {
                json!({})
            } else {
                json!({"content": value})
            }
        }
    }
}

fn to_gemini_parts(part: &ContentPart, tool_names: &HashMap<String, String>) -> Vec<Value> {
    match part {
        ContentPart::Text { text } => vec![json!({"text": text})],
        ContentPart::Reasoning {
            payload,
            summary,
            signature,
            ..
        } => {
            let text = summary
                .clone()
                .unwrap_or_else(|| payload.as_str().map(str::to_owned).unwrap_or_default());
            let mut value = json!({"text": text, "thought": true});
            if let Some(signature) = signature {
                if let Some(object) = value.as_object_mut() {
                    object.insert("thoughtSignature".into(), Value::String(signature.clone()));
                }
            }
            vec![value]
        }
        ContentPart::Image { payload } => match resolve_image_source(payload) {
            Some(ResolvedImage { url: Some(url), .. }) => match split_data_url(&url) {
                Some((mime, body)) => {
                    vec![json!({"inlineData": {"mimeType": mime, "data": body}})]
                }
                None => vec![json!({"fileData": {"fileUri": url}})],
            },
            Some(ResolvedImage {
                file_id: Some(file_id),
                ..
            }) => vec![json!({"text": format!("[image: {file_id}]")})],
            _ => vec![json!({"text": "[image: unsupported source]"})],
        },
        ContentPart::File {
            data,
            media_type,
            file_id,
            url,
            ..
        } => gemini_media_parts(data, media_type, file_id.as_deref(), url.as_deref(), None),
        ContentPart::Document {
            data,
            media_type,
            source_type,
            url,
            file_id,
            ..
        } => {
            let source_type = source_type.as_ref().map(|value| match value {
                keyla_core::DocumentSourceType::Base64 => "base64",
                keyla_core::DocumentSourceType::Url => "url",
                keyla_core::DocumentSourceType::File => "file",
                keyla_core::DocumentSourceType::Text => "text",
            });
            gemini_media_parts(
                data,
                media_type,
                file_id.as_deref(),
                url.as_deref(),
                source_type,
            )
        }
        ContentPart::Audio { data, media_type } => {
            let Some(raw) = data.as_str().filter(|value| !value.is_empty()) else {
                return vec![json!({"text": "[audio: unsupported source]"})];
            };
            let (mime, body) =
                split_data_url(raw).unwrap_or_else(|| (media_type.clone(), raw.to_owned()));
            vec![json!({"inlineData": {"mimeType": mime, "data": body}})]
        }
        ContentPart::ToolCall {
            call_id,
            name,
            arguments,
            ..
        } => {
            let args = match arguments {
                Value::String(raw) => parse_json_object(raw),
                Value::Null => json!({}),
                other => other.clone(),
            };
            let mut call = Map::new();
            call.insert("name".into(), Value::String(name.clone()));
            call.insert("args".into(), args);
            if !call_id.is_empty() {
                call.insert("id".into(), Value::String(call_id.clone()));
            }
            vec![json!({"functionCall": Value::Object(call)})]
        }
        ContentPart::ToolResult {
            call_id, content, ..
        } => {
            let mut name = tool_names
                .get(call_id)
                .cloned()
                .unwrap_or_else(|| call_id.clone());
            if name.is_empty() {
                name = "tool".to_owned();
            }
            let response = match content {
                ToolResultContent::Text(text) => parse_json_object(text),
                ToolResultContent::Parts(parts) => {
                    let serialized = serde_json::to_string(parts).unwrap_or_default();
                    json!({"content": serialized})
                }
            };
            let mut payload = Map::new();
            payload.insert("name".into(), Value::String(name));
            payload.insert("response".into(), response);
            if !call_id.is_empty() {
                payload.insert("id".into(), Value::String(call_id.clone()));
            }
            vec![json!({"functionResponse": Value::Object(payload)})]
        }
        // The Gemini encoder has no wire projection for refusals or opaque
        // extensions; TS drops them rather than inventing a part.
        ContentPart::Refusal { .. } | ContentPart::Extension { .. } => Vec::new(),
    }
}

fn gemini_thinking_output_floor(reasoning: Option<&keyla_core::ReasoningIntent>) -> Option<i64> {
    let reasoning = reasoning?;
    if reasoning.thinking_type == Some(ThinkingType::Disabled) {
        return None;
    }
    if let Some(budget) = reasoning.budget_tokens {
        return Some(match budget {
            value if value <= 1_024 => 8_192,
            value if value <= 8_192 => 16_384,
            value if value <= 24_576 => 32_768,
            _ => 65_535,
        });
    }
    match reasoning.effort.map(|effort| effort.as_str()) {
        Some("minimal") => Some(4_096),
        Some("low") => Some(8_192),
        Some("medium") => Some(16_384),
        Some("high") | Some("xhigh") | Some("max") => Some(65_535),
        _ => None,
    }
}

fn is_claude_billing_header_text(text: &str) -> bool {
    text.starts_with("x-anthropic-billing-header:")
}

/// Encodes a canonical request onto the Gemini `generateContent` wire.
pub fn build_gemini_payload(request: &CanonicalRequest) -> Value {
    let mut system_parts: Vec<Value> = Vec::new();
    let mut push_system_text = |text: &str| {
        if !is_claude_billing_header_text(text) {
            system_parts.push(json!({"text": text}));
        }
    };
    if let Some(system) = &request.system {
        for part in system {
            if let ContentPart::Text { text } = part {
                push_system_text(text);
            }
        }
    }
    if let Some(instructions) = &request.instructions {
        for part in instructions {
            if let ContentPart::Text { text } = part {
                push_system_text(text);
            }
        }
    }
    for message in &request.messages {
        if matches!(message.role, Role::System | Role::Developer) {
            let text = message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !text.is_empty() {
                push_system_text(&text);
            }
        }
    }

    let mut tool_names = HashMap::new();
    for message in &request.messages {
        for part in &message.content {
            if let ContentPart::ToolCall { call_id, name, .. } = part {
                tool_names.insert(call_id.clone(), name.clone());
            }
        }
    }

    let mut contents = Vec::new();
    for message in &request.messages {
        if matches!(message.role, Role::System | Role::Developer) {
            continue;
        }
        let role = if message.role == Role::Assistant {
            "model"
        } else {
            "user"
        };
        let mut parts: Vec<Value> = Vec::new();
        for part in &message.content {
            parts.extend(to_gemini_parts(part, &tool_names));
        }
        if parts.is_empty() {
            parts.push(json!({"text": ""}));
        }
        contents.push(json!({"role": role, "parts": parts}));
    }

    let mut payload = Map::new();
    payload.insert("contents".into(), Value::Array(contents));
    if !system_parts.is_empty() {
        payload.insert(
            "systemInstruction".into(),
            json!({"role": "user", "parts": system_parts}),
        );
    }
    if let Some(tools) = &request.tools {
        let declarations: Vec<Value> = tools
            .iter()
            .filter(|tool| !tool.name.is_empty())
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description.clone().unwrap_or_default(),
                    "parameters": sanitize_gemini_schema(&tool.json_schema),
                })
            })
            .collect();
        if !declarations.is_empty() {
            payload.insert(
                "tools".into(),
                json!([{"functionDeclarations": declarations}]),
            );
        }
    }

    let controls = &request.generation_controls;
    let mut generation = Map::new();
    if let Some(max_out) = controls
        .max_tokens
        .or(controls.max_output_tokens)
        .or(controls.max_completion_tokens)
    {
        generation.insert("maxOutputTokens".into(), json!(max_out));
    }
    if let Some(reasoning) = &request.reasoning {
        if reasoning.thinking_type != Some(ThinkingType::Disabled) {
            if let Some(budget) = reasoning.budget_tokens {
                generation.insert("thinkingConfig".into(), json!({"thinkingBudget": budget}));
            }
        }
    }
    if let Some(floor) = gemini_thinking_output_floor(request.reasoning.as_ref()) {
        let current = generation.get("maxOutputTokens").and_then(Value::as_i64);
        if current.unwrap_or(0) < floor {
            generation.insert("maxOutputTokens".into(), json!(floor));
        }
    }
    if !generation.is_empty() {
        payload.insert("generationConfig".into(), Value::Object(generation));
    }
    Value::Object(payload)
}

// --- Antigravity envelope ---------------------------------------------------

/// Wraps the Gemini payload in the Antigravity agent envelope.
pub fn build_antigravity_envelope(
    request: &CanonicalRequest,
    project_id: Option<&str>,
    wire_model_id: &str,
    logical_model_id: &str,
    state: &mut AntigravitySessionState,
    session_seed: &str,
) -> Value {
    let gemini_payload = build_gemini_payload(request);
    let profile = get_antigravity_model_wire_profile(wire_model_id);

    let mut generation = gemini_payload
        .get("generationConfig")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(profile) = profile {
        generation.insert("maxOutputTokens".into(), json!(profile.max_output_tokens));
    }
    if let Some(budget) = antigravity_thinking_budget(logical_model_id) {
        generation.insert(
            "thinkingConfig".into(),
            json!({"includeThoughts": true, "thinkingBudget": budget}),
        );
    }

    if state.agent_id.is_none() {
        state.agent_id = Some(Uuid::new_v4().to_string());
    }
    if state.trajectory_id.is_none() {
        state.trajectory_id = Some(Uuid::new_v4().to_string());
    }
    if state.session_id.is_none() {
        state.session_id = Some(signed_antigravity_session_id(Some(session_seed)));
    }
    let step = state.step_index.unwrap_or(1) + 1;
    state.step_index = Some(step);

    let mut labels = Map::new();
    if let Some(last) = &state.last_execution_id {
        labels.insert("last_execution_id".into(), json!(last));
    }
    labels.insert(
        "trajectory_id".into(),
        json!(state.trajectory_id.clone().unwrap_or_default()),
    );
    labels.insert("last_step_index".into(), json!((step - 1).to_string()));
    labels.insert(
        "used_claude".into(),
        json!(logical_model_id.contains("claude").to_string()),
    );
    labels.insert(
        "used_claude_conservative".into(),
        json!(logical_model_id.contains("claude").to_string()),
    );
    if let Some(model_enum) = profile.and_then(|profile| profile.model_enum) {
        labels.insert("model_enum".into(), json!(model_enum));
    }

    let existing_contents = gemini_payload
        .get("contents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let lower = logical_model_id.to_ascii_lowercase();
    let inject_identity = lower.contains("claude") || lower.contains("gemini-3");
    let existing_instruction = gemini_payload
        .get("systemInstruction")
        .and_then(Value::as_object)
        .cloned();
    let existing_parts = existing_instruction
        .as_ref()
        .and_then(|instruction| instruction.get("parts"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_identity = existing_parts.iter().any(|part| {
        part.get("text").and_then(Value::as_str) == Some(ANTIGRAVITY_SYSTEM_INSTRUCTION)
    });
    let system_instruction = if !inject_identity || has_identity {
        existing_instruction.map(Value::Object)
    } else {
        let mut parts = vec![json!({"text": ANTIGRAVITY_SYSTEM_INSTRUCTION})];
        parts.extend(existing_parts);
        Some(json!({"role": "user", "parts": parts}))
    };

    let mut request_payload = gemini_payload.as_object().cloned().unwrap_or_default();
    request_payload.insert("contents".into(), Value::Array(existing_contents));
    match system_instruction {
        Some(instruction) => {
            request_payload.insert("systemInstruction".into(), instruction);
        }
        None => {
            request_payload.remove("systemInstruction");
        }
    }
    request_payload.insert("labels".into(), Value::Object(labels));
    request_payload.insert(
        "sessionId".into(),
        json!(state.session_id.clone().unwrap_or_default()),
    );
    if generation.is_empty() {
        request_payload.remove("generationConfig");
    } else {
        request_payload.insert("generationConfig".into(), Value::Object(generation));
    }
    let wants_web_search = request.tools.as_ref().is_some_and(|tools| {
        tools
            .iter()
            .any(|tool| tool.name == "web_search" || tool.name == "web_search_preview")
    });
    if wants_web_search {
        let mut tools = request_payload
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        tools.push(json!({"googleSearch": {}}));
        request_payload.insert("tools".into(), Value::Array(tools));
    }
    if logical_model_id.contains("claude")
        && !request_payload
            .get("toolConfig")
            .is_some_and(Value::is_object)
    {
        request_payload.insert(
            "toolConfig".into(),
            json!({"functionCallingConfig": {"mode": "VALIDATED"}}),
        );
    }
    let mut request_value = Value::Object(request_payload);
    apply_skip_thought_signature_bypass(&mut request_value, logical_model_id);

    let mut envelope = Map::new();
    envelope.insert(
        "requestId".into(),
        json!(format!(
            "agent/{}/{}/{}/{step}",
            state.agent_id.clone().unwrap_or_default(),
            chrono::Utc::now().timestamp_millis(),
            state.trajectory_id.clone().unwrap_or_default(),
        )),
    );
    envelope.insert("model".into(), json!(wire_model_id));
    envelope.insert("userAgent".into(), json!("antigravity"));
    envelope.insert("requestType".into(), json!("agent"));
    envelope.insert("request".into(), request_value);
    if let Some(project_id) = project_id.filter(|value| !value.is_empty()) {
        envelope.insert("project".into(), json!(project_id));
    }
    Value::Object(envelope)
}

// --- Response decoding ------------------------------------------------------

fn gemini_candidate(body: &Value) -> (Value, Value, Vec<Value>) {
    let response = body
        .get("response")
        .filter(|value| is_record(value))
        .cloned()
        .unwrap_or_else(|| body.clone());
    let candidate = response
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
        .filter(|value| is_record(value))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let parts = candidate
        .get("content")
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter(|part| is_record(part))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    (response, candidate, parts)
}

struct DecodedToolCall {
    id: String,
    name: String,
    args: Value,
}

struct DecodedParts {
    text: String,
    thought: String,
    calls: Vec<DecodedToolCall>,
}

fn response_parts(parts: &[Value]) -> DecodedParts {
    let mut text = String::new();
    let mut thought = String::new();
    let mut calls = Vec::new();
    let mut call_index = 0;
    for part in parts {
        if let Some(value) = part.get("text").and_then(Value::as_str) {
            if part.get("thought") == Some(&Value::Bool(true)) {
                thought.push_str(value);
            } else {
                text.push_str(value);
            }
        }
        if let Some(call) = part.get("functionCall").and_then(Value::as_object) {
            let Some(name) = call.get("name").and_then(Value::as_str) else {
                continue;
            };
            let id = call
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    let id = format!("call_{call_index}");
                    call_index += 1;
                    id
                });
            calls.push(DecodedToolCall {
                id,
                name: name.to_owned(),
                args: call
                    .get("args")
                    .filter(|value| is_record(value))
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            });
        }
    }
    DecodedParts {
        text,
        thought,
        calls,
    }
}

/// Maps Gemini `usageMetadata` onto the canonical usage record, or `None` when
/// the upstream reported nothing.
pub fn gemini_usage(metadata: Option<&Value>) -> Option<UsageRecord> {
    let get = |key: &str| {
        metadata
            .and_then(|value| value.get(key))
            .and_then(Value::as_i64)
            .unwrap_or(0)
    };
    let prompt = get("promptTokenCount");
    let completion = get("candidatesTokenCount");
    let cached = get("cachedContentTokenCount");
    let total = get("totalTokenCount");
    if prompt <= 0 && completion <= 0 && cached <= 0 {
        return None;
    }
    let uncached = (prompt - cached).max(0);
    Some(UsageRecord {
        input_tokens: prompt,
        cached_input_tokens: TokenCount::Number(cached),
        cache_write_tokens: TokenCount::Unavailable,
        uncached_input_tokens: TokenCount::Number(uncached),
        output_tokens: completion,
        reasoning_tokens: TokenCount::Unavailable,
        estimated_cost: None,
        credit_used: None,
        total_tokens: Some(TokenCount::Number(total)),
        details: None,
    })
}

/// Antigravity's finish-reason mapping; tool use wins over a plain stop but not
/// over an explicit length/safety reason.
pub fn to_canonical_stop(finish_reason: Option<&str>, tool_count: usize) -> CanonicalStopReason {
    match finish_reason {
        Some("MAX_TOKENS") => CanonicalStopReason::Length,
        Some("STOP") => CanonicalStopReason::Stop,
        Some("SAFETY") => CanonicalStopReason::ContentFilter,
        _ if tool_count > 0 => CanonicalStopReason::ToolUse,
        _ => CanonicalStopReason::Stop,
    }
}

fn upstream_error(status: u16, message: impl Into<String>) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::PlatformUnavailable,
        status,
        message,
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Upstream)
}

fn network_error(message: impl Into<String>) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::TransportUnavailable,
        502,
        message,
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Network)
}

fn decode_stream_event(raw: &str, label: &str) -> Result<Option<Value>, GatewayError> {
    let data = raw.trim();
    if data.is_empty() {
        return Ok(None);
    }
    let parsed: Value = serde_json::from_str(data)
        .map_err(|error| upstream_error(502, format!("Malformed SSE event: {error}")))?;
    if !is_record(&parsed) {
        return Ok(None);
    }
    let error_value = parsed.get("error").filter(|value| !value.is_null());
    let Some(error_value) = error_value else {
        return Ok(Some(parsed));
    };
    let error_body = if is_record(error_value) {
        error_value.clone()
    } else {
        parsed.clone()
    };
    let identifier =
        upstream_error_identifier(&error_body).or_else(|| upstream_error_identifier(&parsed));
    let provider_status = ["status", "statusCode", "code"]
        .iter()
        .find_map(|key| error_body.get(*key))
        .and_then(Value::as_u64)
        .filter(|status| (400..600).contains(status))
        .map(|status| status as u16);
    let classification = classify_upstream_error(provider_status, identifier.as_deref());
    let message = [
        extract_upstream_message(&error_body),
        extract_upstream_message(&parsed),
        label.to_owned(),
    ]
    .into_iter()
    .find(|message| !message.is_empty())
    .unwrap_or_default();
    let mut details = Map::new();
    if let Some(status) = provider_status {
        details.insert("providerStatus".into(), json!(status));
    }
    if let Some(identifier) = identifier {
        details.insert("providerCode".into(), json!(identifier));
    }
    if classification.credential_evidence {
        details.insert("credentialEvidence".into(), json!(true));
    }
    if classification.rate_limit_scope_provider {
        details.insert("rateLimitScope".into(), json!("provider"));
    }
    Err(GatewayError::new(
        classification.code,
        classification.status,
        message.chars().take(500).collect::<String>(),
        details,
    )
    .with_origin(classification.origin))
}

fn response_start(sequence_number: u64, model: &str) -> CanonicalEvent {
    CanonicalEvent::ResponseStart {
        sequence_number,
        event_id: None,
        response_id: None,
        model: Some(model.to_owned()),
        system_fingerprint: None,
        timestamp: None,
    }
}

fn reasoning_delta(sequence_number: u64, summary: &str) -> CanonicalEvent {
    CanonicalEvent::ContentDelta {
        sequence_number,
        content: ContentPart::Reasoning {
            payload: Value::Null,
            opaque: None,
            summary: Some(summary.to_owned()),
            summary_index: None,
            signature: None,
            encrypted_content: None,
        },
        event_id: None,
        response_id: None,
        item_id: None,
        output_index: None,
        content_index: None,
        timestamp: None,
    }
}

fn text_delta(sequence_number: u64, text: &str) -> CanonicalEvent {
    CanonicalEvent::ContentDelta {
        sequence_number,
        content: ContentPart::Text {
            text: text.to_owned(),
        },
        event_id: None,
        response_id: None,
        item_id: None,
        output_index: None,
        content_index: None,
        timestamp: None,
    }
}

fn tool_delta(
    sequence_number: u64,
    call_id: &str,
    name: &str,
    arguments_delta: &str,
) -> CanonicalEvent {
    CanonicalEvent::ToolCallDelta {
        sequence_number,
        call_id: call_id.to_owned(),
        index: None,
        name: Some(name.to_owned()),
        arguments_delta: Some(arguments_delta.to_owned()),
        event_id: None,
        response_id: None,
        item_id: None,
        output_index: None,
        timestamp: None,
    }
}

fn terminal(
    sequence_number: u64,
    state: TerminalState,
    finish_reason: Option<&str>,
    tool_count: usize,
    usage: Option<UsageRecord>,
) -> CanonicalEvent {
    CanonicalEvent::Terminal {
        sequence_number,
        state,
        stop_reason: Some(to_canonical_stop(finish_reason, tool_count)),
        provider_stop_reason: finish_reason.map(str::to_owned),
        stop_details: None,
        usage,
        event_id: None,
        response_id: None,
        timestamp: None,
    }
}

// --- Project-id lookup / free-tier onboarding ------------------------------

fn project_cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: LazyLock<Mutex<HashMap<String, String>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    &CACHE
}

fn token_key(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn extract_project_id(payload: &Value) -> Option<String> {
    let raw = payload.get("cloudaicompanionProject")?;
    if let Some(value) = raw.as_str().filter(|value| !value.is_empty()) {
        return Some(value.to_owned());
    }
    raw.get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn has_tier_field(payload: &Value, field: &str) -> bool {
    payload.get(field).is_some_and(|value| !value.is_null())
}

fn is_free_tier_allowed(payload: &Value) -> bool {
    payload
        .get("allowedTiers")
        .and_then(Value::as_array)
        .is_some_and(|tiers| {
            tiers
                .iter()
                .any(|tier| tier.get("id").and_then(Value::as_str) == Some("free-tier"))
        })
}

fn free_tier_ineligibility(payload: &Value) -> Option<(String, Option<String>)> {
    let tiers = payload.get("ineligibleTiers")?.as_array()?;
    for candidate in tiers {
        if candidate.get("tierId").and_then(Value::as_str) != Some("free-tier") {
            continue;
        }
        let reason = candidate
            .get("reasonMessage")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())?;
        let url = candidate
            .get("validationUrl")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        return Some((reason.to_owned(), url));
    }
    None
}

fn assert_free_tier_eligible(payload: &Value) -> Result<(), GatewayError> {
    if is_free_tier_allowed(payload) {
        return Ok(());
    }
    let Some((reason, validation_url)) = free_tier_ineligibility(payload) else {
        return Ok(());
    };
    let message = match validation_url {
        Some(url) => format!("{reason}\n{url}"),
        None => reason,
    };
    Err(upstream_error(
        502,
        format!("antigravity provisioning: {message}"),
    ))
}

async fn cloud_code_assist_call(
    client: &reqwest::Client,
    base: &str,
    access_token: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, GatewayError> {
    let url = format!("{base}{path}");
    let mut builder = if body.is_some() {
        client.post(url)
    } else {
        client.get(url)
    };
    builder = builder
        .timeout(CONTROL_PLANE_TIMEOUT)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("authorization", format!("Bearer {access_token}"))
        .header("user-agent", get_antigravity_user_agent());
    if let Some(body) = body {
        builder = builder.json(body);
    }
    let response = builder
        .send()
        .await
        .map_err(|error| network_error(format!("{path} failed: {error}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(upstream_error(
            status.as_u16(),
            format!(
                "{path} failed: {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("")
            ),
        ));
    }
    let payload = response
        .json::<Value>()
        .await
        .map_err(|error| upstream_error(502, format!("{path} returned invalid JSON: {error}")))?;
    Ok(if is_record(&payload) {
        payload
    } else {
        json!({})
    })
}

async fn load_code_assist(
    client: &reqwest::Client,
    base: &str,
    access_token: &str,
) -> Result<Value, GatewayError> {
    let metadata = json!({"ideType": ANTIGRAVITY_LOAD_CODE_ASSIST_METADATA_IDE_TYPE});
    let first_body = json!({"metadata": metadata.clone()});
    let mut payload = cloud_code_assist_call(
        client,
        base,
        access_token,
        "/v1internal:loadCodeAssist",
        Some(&first_body),
    )
    .await?;
    let project_id = extract_project_id(&payload);
    if !has_tier_field(&payload, "paidTier") {
        if let Some(project_id) = project_id {
            let retry_body = json!({
                "cloudaicompanionProject": project_id,
                "metadata": metadata,
            });
            payload = cloud_code_assist_call(
                client,
                base,
                access_token,
                "/v1internal:loadCodeAssist",
                Some(&retry_body),
            )
            .await?;
        }
    }
    Ok(payload)
}

async fn onboard_user(
    client: &reqwest::Client,
    base: &str,
    access_token: &str,
) -> Result<(), GatewayError> {
    let deadline = Instant::now() + ONBOARD_TIMEOUT;
    let remaining = || -> Result<Duration, GatewayError> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(upstream_error(
                502,
                "antigravity provisioning: onboardUser timed out",
            ));
        }
        Ok(left)
    };
    let onboard_body = json!({
        "tierId": "free-tier",
        "metadata": {"ideType": ANTIGRAVITY_LOAD_CODE_ASSIST_METADATA_IDE_TYPE},
    });
    let mut operation = cloud_code_assist_call(
        client,
        base,
        access_token,
        "/v1internal:onboardUser",
        Some(&onboard_body),
    )
    .await?;
    loop {
        if operation.get("done") == Some(&Value::Bool(true)) {
            if let Some(error) = operation.get("error").filter(|value| is_record(value)) {
                if let Some(message) = error.get("message").and_then(Value::as_str) {
                    return Err(upstream_error(
                        502,
                        format!("antigravity provisioning: onboardUser failed: {message}"),
                    ));
                }
            }
            return Ok(());
        }
        let Some(name) = operation
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Err(upstream_error(
                502,
                "antigravity provisioning: onboardUser returned an operation without a name",
            ));
        };
        let wait = ONBOARD_POLL_INTERVAL.min(remaining()?);
        tokio::time::sleep(wait).await;
        operation = cloud_code_assist_call(
            client,
            base,
            access_token,
            &format!("/v1internal/{name}"),
            None,
        )
        .await?;
    }
}

/// Resolves the caller's Cloud Code Assist project, enrolling the account in
/// the free tier when it has no tier yet.
pub async fn discover_antigravity_project(
    client: &reqwest::Client,
    access_token: &str,
    base_url: Option<&str>,
) -> Result<String, GatewayError> {
    let base = base_url
        .unwrap_or(ANTIGRAVITY_BASE_URL)
        .trim_end_matches('/');
    let initial = load_code_assist(client, base, access_token).await?;
    assert_free_tier_eligible(&initial)?;
    if !has_tier_field(&initial, "currentTier") {
        onboard_user(client, base, access_token).await?;
    }
    let refreshed = load_code_assist(client, base, access_token).await?;
    let Some(project_id) = extract_project_id(&refreshed) else {
        return Err(upstream_error(
            502,
            "antigravity provisioning: loadCodeAssist did not return a cloudaicompanionProject",
        ));
    };
    {
        let mut cache = project_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        cache.insert(token_key(access_token), project_id.clone());
        while cache.len() > PROJECT_ID_CACHE_MAX {
            let Some(oldest) = cache.keys().next().cloned() else {
                break;
            };
            cache.remove(&oldest);
        }
    }
    Ok(project_id)
}

/// Best-effort project lookup used by dispatch: cached per access-token hash,
/// failures return `None` and are not cached.
pub async fn load_antigravity_project(
    client: &reqwest::Client,
    access_token: &str,
    base_url: Option<&str>,
) -> Option<String> {
    let key = token_key(access_token);
    if let Some(cached) = project_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&key)
        .cloned()
    {
        return Some(cached);
    }
    discover_antigravity_project(client, access_token, base_url)
        .await
        .ok()
}

// --- Dispatch ---------------------------------------------------------------

fn request_headers(
    credential: &DispatchCredential,
    stream: bool,
    access_token: &str,
) -> reqwest::header::HeaderMap {
    use reqwest::header::{
        ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue, USER_AGENT,
    };
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(if stream {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("Bearer {access_token}")) {
        headers.insert(AUTHORIZATION, value);
    }
    if let Ok(value) = HeaderValue::from_str(&get_antigravity_user_agent()) {
        headers.insert(USER_AGENT, value);
    }
    for (name, value) in &credential.extra_headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

/// Dispatches one canonical request to Antigravity's Cloud Code Assist wire.
pub async fn dispatch_antigravity(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    if credential.credential_kind != "oauth" {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            format!(
                "antigravity: Google OAuth credential required (got credential_kind={})",
                credential.credential_kind
            ),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Keyla));
    }
    let access_token = credential.secret.as_deref().map(str::trim).unwrap_or("");
    if access_token.is_empty() {
        return Err(GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "antigravity: OAuth access token is required",
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Keyla));
    }

    let base = if credential.base_url.trim().is_empty() {
        ANTIGRAVITY_BASE_URL.to_owned()
    } else {
        credential.base_url.trim_end_matches('/').to_owned()
    };
    let model = if target.model_id.is_empty() {
        request.model.clone()
    } else {
        target.model_id.clone()
    };
    let wire_model_id = antigravity_wire_model_id(&model);
    let url = format!(
        "{base}{}",
        if request.stream {
            ANTIGRAVITY_STREAM_GENERATE_PATH
        } else {
            ANTIGRAVITY_GENERATE_PATH
        }
    );

    let credential_scope = credential
        .account_id
        .clone()
        .or_else(|| {
            credential.secret.as_deref().map(|secret| {
                let digest = Sha256::digest(secret.as_bytes());
                let prefix: String = digest
                    .iter()
                    .take(8)
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                format!("cred:{prefix}")
            })
        })
        .unwrap_or_else(|| "anon".to_owned());
    let route_identity = request
        .conversation
        .as_ref()
        .and_then(|conversation| conversation.conversation_id.clone())
        .or_else(|| request.conversation_id.clone())
        .unwrap_or_else(|| format!("account:{credential_scope}"));
    let state_key = session_state_key(&route_identity, &wire_model_id);
    let store = global_session_store();
    store.reset_by_prefix(
        &format!("{}:", session_identity_digest(&route_identity)),
        Some(&state_key),
    );
    let live_state_key = state_key.clone();

    let project_id = load_antigravity_project(client, access_token, Some(&base)).await;
    let session_seed = first_user_text(request);

    let payload = {
        let store = global_session_store();
        store.with_state(&state_key, |state| {
            build_antigravity_envelope(
                request,
                project_id.as_deref(),
                &wire_model_id,
                &model,
                state,
                &session_seed,
            )
        })
    };

    let headers = request_headers(credential, request.stream, access_token);
    let attempt = |target_url: String, body: Value| {
        let client = client.clone();
        let headers = headers.clone();
        async move {
            client
                .post(target_url)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .map_err(|error| network_error(format!("antigravity request failed: {error}")))
        }
    };

    let mut response = attempt(url.clone(), payload.clone()).await?;
    let mut status = response.status();
    if !status.is_success() && is_failover_status(status.as_u16()) {
        if let Some(sandbox_url) = failover_antigravity_url(&url, &base) {
            response = attempt(sandbox_url, payload).await?;
            status = response.status();
        }
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(upstream_http_error(
            status.as_u16(),
            &body,
            &target.provider_id,
        ));
    }

    if !request.stream {
        let payload: Value = response.json().await.map_err(|error| {
            upstream_error(502, format!("antigravity returned invalid JSON: {error}"))
        })?;
        let (decoded, candidate, parts) = gemini_candidate(&payload);
        let output = response_parts(&parts);
        let mut events = Vec::new();
        let mut seq = 1u64;
        events.push(response_start(seq, &request.model));
        seq += 1;
        if !output.thought.is_empty() {
            events.push(reasoning_delta(seq, &output.thought));
            seq += 1;
        }
        if !output.text.is_empty() {
            events.push(text_delta(seq, &output.text));
            seq += 1;
        }
        for call in &output.calls {
            events.push(tool_delta(
                seq,
                &call.id,
                &call.name,
                &serde_json::to_string(&call.args).unwrap_or_default(),
            ));
            seq += 1;
        }
        if let Some(response_id) = decoded.get("responseId").and_then(Value::as_str) {
            global_session_store().with_state(&live_state_key, |state| {
                state.last_execution_id = Some(response_id.to_owned());
            });
        }
        let finish_reason = candidate
            .get("finishReason")
            .and_then(Value::as_str)
            .map(str::to_owned);
        events.push(terminal(
            seq,
            if finish_reason.is_none() {
                TerminalState::Failed
            } else {
                TerminalState::Complete
            },
            finish_reason.as_deref(),
            output.calls.len(),
            gemini_usage(decoded.get("usageMetadata")),
        ));
        return Ok(DispatchOutput::Events(events));
    }

    let model_for_start = request.model.clone();
    let mut upstream = response.bytes_stream();
    let stream = async_stream::try_stream! {
        let mut sse = SseDecoder::new();
        let mut seq = 1u64;
        let mut active_calls: HashSet<String> = HashSet::new();
        let mut raw_usage: Option<Value> = None;
        let mut finish_reason: Option<String> = None;
        let mut tool_count = 0usize;
        let mut last_execution_id: Option<String> = None;
        let mut saw_done = false;
        yield response_start(seq, &model_for_start);
        seq += 1;
        'stream: while let Some(chunk) = upstream.next().await {
            let chunk: Bytes = chunk.map_err(|error| network_error(format!("antigravity stream error: {error}")))?;
            for frame in sse.push(&chunk) {
                let data = frame.data.trim();
                if data == "[DONE]" {
                    saw_done = true;
                    break 'stream;
                }
                let Some(parsed) = decode_stream_event(data, "antigravity stream error")? else {
                    continue;
                };
                let (decoded, candidate, parts) = gemini_candidate(&parsed);
                let output = response_parts(&parts);
                if !output.thought.is_empty() {
                    yield reasoning_delta(seq, &output.thought);
                    seq += 1;
                }
                if !output.text.is_empty() {
                    yield text_delta(seq, &output.text);
                    seq += 1;
                }
                for call in &output.calls {
                    if active_calls.insert(call.id.clone()) {
                        yield tool_delta(seq, &call.id, &call.name, "");
                        seq += 1;
                    }
                    let args = serde_json::to_string(&call.args).unwrap_or_else(|_| "{}".to_owned());
                    if args != "{}" {
                        yield tool_delta(seq, &call.id, &call.name, &args);
                        seq += 1;
                    }
                    tool_count += 1;
                }
                if let Some(metadata) = decoded.get("usageMetadata").filter(|value| value.is_object()) {
                    raw_usage = Some(metadata.clone());
                }
                if let Some(response_id) = decoded.get("responseId").and_then(Value::as_str) {
                    last_execution_id = Some(response_id.to_owned());
                }
                if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
                    finish_reason = Some(reason.to_owned());
                }
            }
        }
        for frame in sse.finish() {
            if saw_done {
                continue;
            }
            let data = frame.data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            let Some(parsed) = decode_stream_event(data, "antigravity stream error")? else {
                continue;
            };
            let (decoded, candidate, parts) = gemini_candidate(&parsed);
            let output = response_parts(&parts);
            if !output.thought.is_empty() {
                yield reasoning_delta(seq, &output.thought);
                seq += 1;
            }
            if !output.text.is_empty() {
                yield text_delta(seq, &output.text);
                seq += 1;
            }
            for call in &output.calls {
                if active_calls.insert(call.id.clone()) {
                    yield tool_delta(seq, &call.id, &call.name, "");
                    seq += 1;
                }
                let args = serde_json::to_string(&call.args).unwrap_or_else(|_| "{}".to_owned());
                if args != "{}" {
                    yield tool_delta(seq, &call.id, &call.name, &args);
                    seq += 1;
                }
                tool_count += 1;
            }
            if let Some(metadata) = decoded.get("usageMetadata").filter(|value| value.is_object()) {
                raw_usage = Some(metadata.clone());
            }
            if let Some(response_id) = decoded.get("responseId").and_then(Value::as_str) {
                last_execution_id = Some(response_id.to_owned());
            }
            if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
                finish_reason = Some(reason.to_owned());
            }
        }
        if let Some(response_id) = last_execution_id {
            global_session_store().with_state(&live_state_key, |state| {
                state.last_execution_id = Some(response_id);
            });
        }
        let usage = gemini_usage(raw_usage.as_ref());
        let state = if finish_reason.is_none() {
            TerminalState::Failed
        } else {
            TerminalState::Complete
        };
        yield terminal(seq, state, finish_reason.as_deref(), tool_count, usage);
    };
    Ok(DispatchOutput::Stream(Box::pin(stream)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{CanonicalMessage, GenerationControls, SourceSurface};

    fn request(model: &str) -> CanonicalRequest {
        CanonicalRequest {
            model: model.to_owned(),
            system: None,
            instructions: None,
            messages: vec![CanonicalMessage {
                role: Role::User,
                content: vec![ContentPart::Text {
                    text: "hello".to_owned(),
                }],
                phase: None,
            }],
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
            stream: false,
            source_surface: SourceSurface::Chat,
        }
    }

    #[test]
    fn wire_model_ids_collapse_to_deployments() {
        assert_eq!(
            antigravity_wire_model_id("claude-opus-4-6"),
            "claude-opus-4-6-thinking"
        );
        assert_eq!(
            antigravity_wire_model_id("gemini-3.1-pro-high"),
            "gemini-pro-agent"
        );
        assert_eq!(
            antigravity_wire_model_id("gemini-3.1-pro"),
            "gemini-pro-agent"
        );
        assert_eq!(
            antigravity_wire_model_id("gemini-3.6-flash"),
            "gemini-3.6-flash-low"
        );
        assert_eq!(
            antigravity_wire_model_id("gpt-oss-120b"),
            "gpt-oss-120b-medium"
        );
        assert_eq!(antigravity_wire_model_id("custom-id"), "custom-id");
    }

    #[test]
    fn discovered_variants_collapse_to_logical_ids() {
        assert_eq!(
            collapse_antigravity_variant("gemini-3.8-flash-low"),
            "gemini-3.8-flash"
        );
        assert_eq!(
            collapse_antigravity_variant("gemini-3-flash-agent"),
            "gemini-3-flash"
        );
        assert_eq!(
            collapse_antigravity_variant("gemini-pro-agent"),
            "gemini-3.1-pro"
        );
        assert_eq!(
            collapse_antigravity_variant("claude-opus-4-6-thinking"),
            "claude-opus-4-6"
        );
        assert_eq!(
            collapse_antigravity_variant("gemini-3.1-pro"),
            "gemini-3.1-pro"
        );
    }

    #[test]
    fn wire_profiles_cap_output_tokens() {
        let claude = get_antigravity_model_wire_profile("claude-opus-4-6-thinking").unwrap();
        assert_eq!(claude.max_output_tokens, 64_000);
        assert_eq!(claude.model_enum, None);
        let gemini = get_antigravity_model_wire_profile("gemini-3.1-pro-low").unwrap();
        assert_eq!(gemini.max_output_tokens, 65_535);
        assert_eq!(gemini.model_enum, Some("MODEL_PLACEHOLDER_M36"));
        assert!(get_antigravity_model_wire_profile("unknown").is_none());
    }

    #[test]
    fn envelope_carries_antigravity_agent_shape() {
        let mut state = AntigravitySessionState::default();
        let mut req = request("gemini-3.1-pro");
        req.generation_controls.max_output_tokens = Some(100);
        let envelope = build_antigravity_envelope(
            &req,
            Some("project-1"),
            "gemini-pro-agent",
            "gemini-3.1-pro",
            &mut state,
            "seed text",
        );
        assert_eq!(envelope["model"], "gemini-pro-agent");
        assert_eq!(envelope["project"], "project-1");
        assert_eq!(envelope["userAgent"], "antigravity");
        assert_eq!(envelope["requestType"], "agent");
        assert!(
            envelope["requestId"]
                .as_str()
                .unwrap()
                .starts_with("agent/")
        );
        assert_eq!(
            envelope["request"]["generationConfig"]["maxOutputTokens"],
            json!(65_535)
        );
        assert_eq!(
            envelope["request"]["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            json!(10_001)
        );
        assert_eq!(
            envelope["request"]["labels"]["model_enum"],
            json!("MODEL_PLACEHOLDER_M16")
        );
        assert!(
            envelope["request"]["sessionId"]
                .as_str()
                .unwrap()
                .starts_with('-')
        );
        assert_eq!(
            envelope["request"]["systemInstruction"]["parts"][0]["text"],
            json!(ANTIGRAVITY_SYSTEM_INSTRUCTION)
        );
    }

    #[test]
    fn skip_thought_signature_only_touches_first_unsigned_call() {
        let mut payload = json!({
            "contents": [
                {"role": "model", "parts": [
                    {"functionCall": {"name": "a"}},
                    {"tag": "not-a-call"},
                    {"functionCall": {"name": "b"}},
                    {"thoughtSignature": "signed", "functionCall": {"name": "c"}},
                    {"functionCall": {"name": "d"}}
                ]}
            ]
        });
        apply_skip_thought_signature_bypass(&mut payload, "gemini-3.1-pro");
        let parts = payload["contents"][0]["parts"].as_array().unwrap();
        assert_eq!(parts[0]["thoughtSignature"], json!(SKIP_THOUGHT_SIGNATURE));
        assert!(parts[1].get("thoughtSignature").is_none());
        assert!(parts[2].get("thoughtSignature").is_none());
        assert_eq!(parts[3]["thoughtSignature"], json!("signed"));
        // The first call was already tagged, so the later unsigned second call
        // (index 4) stays bare: the rule is first-unsigned-only.
        assert!(parts[4].get("thoughtSignature").is_none());
    }

    #[test]
    fn skip_thought_signature_is_a_noop_before_gemini_3() {
        let mut payload = json!({
            "contents": [
                {"role": "model", "parts": [{"functionCall": {"name": "a"}}]}
            ]
        });
        apply_skip_thought_signature_bypass(&mut payload, "gemini-2.5-pro");
        assert!(
            payload["contents"][0]["parts"][0]
                .get("thoughtSignature")
                .is_none()
        );
        apply_skip_thought_signature_bypass(&mut payload, "claude-sonnet-4-6");
        assert!(
            payload["contents"][0]["parts"][0]
                .get("thoughtSignature")
                .is_none()
        );
    }

    #[test]
    fn tool_schema_sanitizer_prunes_unknown_required() {
        let schema = json!({
            "type": ["string", "null"],
            "properties": {"a": {"type": "string"}, "b": {"const": 3}},
            "required": ["a", "missing"],
            "items": {"type": "array"}
        });
        let sanitized = sanitize_gemini_schema(&schema);
        assert_eq!(sanitized["nullable"], json!(true));
        assert_eq!(sanitized["type"], json!("string"));
        assert_eq!(sanitized["required"], json!(["a"]));
        assert_eq!(sanitized["properties"]["b"]["enum"], json!([3]));
    }

    #[test]
    fn thinking_budgets_match_client_tiers() {
        assert_eq!(
            antigravity_thinking_budget("claude-opus-4-6-thinking"),
            Some(10_000)
        );
        assert_eq!(
            antigravity_thinking_budget("gemini-3.1-pro-low"),
            Some(1_000)
        );
        assert_eq!(
            antigravity_thinking_budget("gemini-3.1-pro-medium"),
            Some(4_000)
        );
        assert_eq!(
            antigravity_thinking_budget("gemini-3.1-pro-high"),
            Some(10_000)
        );
        assert_eq!(antigravity_thinking_budget("gemini-3.1-pro"), Some(10_001));
        assert_eq!(antigravity_thinking_budget("gpt-oss-120b-medium"), None);
    }

    #[test]
    fn stop_mapping_prefers_explicit_finish_reasons() {
        assert_eq!(
            to_canonical_stop(Some("MAX_TOKENS"), 2),
            CanonicalStopReason::Length
        );
        assert_eq!(
            to_canonical_stop(Some("SAFETY"), 0),
            CanonicalStopReason::ContentFilter
        );
        assert_eq!(
            to_canonical_stop(Some("OTHER"), 1),
            CanonicalStopReason::ToolUse
        );
        assert_eq!(to_canonical_stop(None, 0), CanonicalStopReason::Stop);
    }

    #[test]
    fn usage_is_absent_when_nothing_reported() {
        assert!(gemini_usage(None).is_none());
        assert!(gemini_usage(Some(&json!({"promptTokenCount": 0}))).is_none());
        let usage = gemini_usage(Some(&json!({
            "promptTokenCount": 10,
            "candidatesTokenCount": 4,
            "cachedContentTokenCount": 2,
            "totalTokenCount": 14
        })))
        .unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 4);
        assert_eq!(usage.uncached_input_tokens, TokenCount::Number(8));
    }

    #[test]
    fn signed_session_ids_are_negative_and_seeded() {
        let first = signed_antigravity_session_id(Some("seed"));
        let second = signed_antigravity_session_id(Some("seed"));
        assert!(first.starts_with('-'));
        assert!(first[1..].chars().all(|ch| ch.is_ascii_digit()));
        // The head is seeded but the low bits stay random, matching the
        // captured client shape rather than a deterministic hash.
        assert_ne!(first, second);
        assert_eq!(signed_antigravity_session_id(Some("-1234")), "-1234");
    }

    #[test]
    fn sandbox_failover_only_rewrites_production() {
        let url = "https://daily-cloudcode-pa.googleapis.com/v1internal:generateContent";
        assert_eq!(
            failover_antigravity_url(url, ANTIGRAVITY_BASE_URL).unwrap(),
            "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:generateContent"
        );
        assert!(failover_antigravity_url(url, "https://example.com").is_none());
    }

    #[test]
    fn session_store_expires_and_resets_prefixes() {
        let store = AntigravitySessionStore::new(8, Duration::from_millis(5));
        store.with_state("abc:antigravity:model", |state| {
            state.step_index = Some(2);
        });
        assert_eq!(store.size(), 1);
        assert_eq!(store.reset_by_prefix("abc:", None), 1);
        assert_eq!(store.size(), 0);
        std::thread::sleep(Duration::from_millis(10));
        store.with_state("other", |_| {});
        assert_eq!(store.size(), 1);
    }
}
