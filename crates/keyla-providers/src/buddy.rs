//! Tencent "buddy" family adapters: CodeBuddy International (`cb`),
//! CodeBuddy CN (`cbcn`), and WorkBuddy (`workbuddy`).
//!
//! Ported from `src/providers/integrations/buddy/`. All three speak the same
//! OpenAI-compatible Chat wire with a shared message/payload envelope; only the
//! identity headers, endpoints, catalogs, and a few payload hooks differ.
//!
//! The upstream contract is unusual in three ways:
//! - `stream=true` is mandatory, so a non-stream caller's request is still sent
//!   as an SSE request and the decoded events are returned in one batch;
//! - the wire must open with a `system` turn, and on CodeBuddy/WorkBuddy the
//!   text is a fixed product prompt rather than the caller's system prompt;
//! - tool names and tool-result ordering are validated upstream, so the payload
//!   is normalized (schema completion, name shortening, orphan repair).
//!
//! OAuth, quota, check-in, and activity helpers return `serde_json::Value` so
//! the console/OAuth wiring can consume them without a shared Rust DTO.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::stream::{BoxStream, StreamExt};
use keyla_core::{
    CanonicalEvent, CanonicalRequest, GatewayError, GatewayErrorCode, GatewayErrorOrigin,
};
use keyla_protocol::primitives::endpoint_url;
use keyla_protocol::request::chat::canonical_to_chat_payload;
use keyla_protocol::response::chat::{ChatSseDecoder, parse_chat_response_to_events};
use keyla_protocol::streaming::SseDecoder;
use keyla_protocol::translation::reasoning_effort_from_intent;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapter::{DispatchCredential, DispatchOutput, DispatchTarget, upstream_http_error};

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

pub const CODEBUDDY_PROVIDER_ID: &str = "cb";
pub const CODEBUDDY_CN_PROVIDER_ID: &str = "cbcn";
pub const WORKBUDDY_PROVIDER_ID: &str = "workbuddy";

pub const CODEBUDDY_BASE_URL: &str = "https://www.codebuddy.ai/v2";
pub const CODEBUDDY_CN_BASE_URL: &str = "https://copilot.tencent.com/v2";
pub const WORKBUDDY_BASE_URL: &str = "https://www.workbuddy.ai";

pub const CODEBUDDY_INTL_USAGE_URL: &str =
    "https://www.codebuddy.ai/v2/billing/meter/get-user-resource";
pub const CODEBUDDY_CN_USAGE_URL: &str =
    "https://copilot.tencent.com/v2/billing/meter/get-user-resource";
pub const WORKBUDDY_USAGE_URL: &str = "https://www.workbuddy.ai/v2/billing/meter/get-user-resource";

pub const CHECKIN_STATUS_PATH: &str = "/billing/meter/checkin-activity-status";
pub const CHECKIN_CLAIM_PATH: &str = "/billing/meter/daily-checkin";
pub const ACTIVITY_REPORT_PATH: &str = "/report";

pub const BUDDY_INTL_MODELS_PATH: &str = "/v2/enterprises/personal/models";
pub const BUDDY_CN_MODELS_PATH: &str = "/console/enterprises/personal/models";

pub const CODEBUDDY_INTL_DEVICE_START_URL: &str = "https://www.codebuddy.ai/v2/plugin/auth/state";
pub const CODEBUDDY_INTL_DEVICE_POLL_URL: &str = "https://www.codebuddy.ai/v2/plugin/auth/token";
pub const CODEBUDDY_INTL_REFRESH_URL: &str =
    "https://www.codebuddy.ai/v2/plugin/auth/token/refresh";
pub const CODEBUDDY_CN_DEVICE_START_URL: &str = "https://copilot.tencent.com/v2/plugin/auth/state";
pub const CODEBUDDY_CN_DEVICE_POLL_URL: &str = "https://copilot.tencent.com/v2/plugin/auth/token";
pub const CODEBUDDY_CN_REFRESH_URL: &str =
    "https://copilot.tencent.com/v2/plugin/auth/token/refresh";
pub const WORKBUDDY_DEVICE_START_URL: &str = "https://www.workbuddy.ai/v2/plugin/auth/state";
pub const WORKBUDDY_DEVICE_POLL_URL: &str = "https://www.workbuddy.ai/v2/plugin/auth/token";
pub const WORKBUDDY_REFRESH_URL: &str = "https://www.workbuddy.ai/v2/plugin/auth/token/refresh";

pub const WORKBUDDY_CHAT_PATH: &str = "/v2/chat/completions";
pub const CODEBUDDY_CHAT_PATH: &str = "/chat/completions";

pub const CODEBUDDY_SYSTEM_PROMPT: &str = "You are a pragmatic and direct software engineering assistant. Be honest and truthful: state what you know, say plainly when you are unsure or do not know, and never claim to have done something you have not done. Prefer concrete answers over filler, and say so when a request is ambiguous instead of guessing silently.";

pub const WORKBUDDY_SYSTEM_PROMPT: &str = CODEBUDDY_SYSTEM_PROMPT;

pub const CODEBUDDY_CN_NEUTRAL_PROMPT: &str =
    "You are a helpful AI assistant that helps with software engineering tasks.";

pub const DAILY_CHECKIN_PROVIDER_IDS: &[&str] = &[
    CODEBUDDY_PROVIDER_ID,
    CODEBUDDY_CN_PROVIDER_ID,
    WORKBUDDY_PROVIDER_ID,
];

/// Fork-friendly default versions. Callers may override the User-Agent supplied
/// to OAuth helpers; dispatch uses these resolved defaults (the TS adapter reads
/// a background-refreshed global resolver, which this crate does not own).
const CODEBUDDY_IDE_VERSION: &str = "2.161.2";
const CODEBUDDY_CN_VERSION: &str = "4.12.1.39217423";
const WORKBUDDY_CLIENT_VERSION: &str = "5.6.2.39458645";
const WORKBUDDY_CLI_VERSION: &str = "2.161.2";

const MAX_TOOL_NAME_LENGTH: usize = 64;
const MAX_REWRITE_DEPTH: usize = 256;
const REFILL_GAP_MS: f64 = 2.0 * 24.0 * 60.0 * 60.0 * 1000.0;
const BILLING_TIMEOUT: Duration = Duration::from_secs(15);
const CHECKIN_TIMEOUT: Duration = Duration::from_secs(15);
const BUDDY_PENDING_CODE: f64 = 11_217.0;
const ALREADY_CLAIMED_CODE: f64 = 1_001.0;
const NOT_ELIGIBLE_CODE: f64 = 1_002.0;
const EVENT_ENDED_CODE: f64 = 1_003.0;
const CLAIM_RETRY_DELAYS_MS: [u64; 2] = [1_000, 2_000];

// ---------------------------------------------------------------------------
// Small JSON helpers
// ---------------------------------------------------------------------------

fn json_object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn non_empty_str(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn js_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64().filter(|number| number.is_finite()),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Some(0.0);
            }
            trimmed
                .parse::<f64>()
                .ok()
                .filter(|number| number.is_finite())
        }
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        Value::Null => Some(0.0),
        _ => None,
    }
}

fn as_text(value: Option<&Value>) -> Option<String> {
    non_empty_str(value)
}

/// `quota-contracts.number` semantics: finite number, or a non-blank numeric
/// string. Unlike `js_number`, a blank string is absent rather than zero.
fn as_number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64().filter(|number| number.is_finite()),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed
                .parse::<f64>()
                .ok()
                .filter(|number| number.is_finite())
        }
        _ => None,
    }
}

fn sanitize_error(message: &str) -> String {
    // Mirrors quota-contracts.cleanError: redact bearer tokens, collapse
    // whitespace, and cap the audit string.
    let lower = message.to_ascii_lowercase();
    let mut output = String::new();
    let mut cursor = 0usize;
    while let Some(relative) = lower[cursor..].find("bearer") {
        let start = cursor + relative;
        output.push_str(&message[cursor..start]);
        let mut position = start + "bearer".len();
        while position < message.len()
            && message[position..]
                .chars()
                .next()
                .is_some_and(char::is_whitespace)
        {
            let step = message[position..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            position += step;
        }
        while position < message.len() {
            let character = message[position..].chars().next().unwrap_or_default();
            if character == '\n' || character == '"' || character == '\'' {
                break;
            }
            position += character.len_utf8();
        }
        output.push_str("Bearer [redacted]");
        cursor = position;
    }
    output.push_str(&message[cursor..]);
    let collapsed = output.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(240).collect()
}

// ---------------------------------------------------------------------------
// Chat payload normalization (buddy-chat-shared.ts)
// ---------------------------------------------------------------------------

fn valid_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_TOOL_NAME_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn clip_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn unique_tool_name(base: &str, used: &HashSet<String>) -> String {
    let base = if base.is_empty() { "tool" } else { base };
    let clipped = clip_chars(base, MAX_TOOL_NAME_LENGTH);
    if !used.contains(&clipped) {
        return clipped;
    }
    let mut suffix = 2usize;
    loop {
        let suffix_text = format!("_{suffix}");
        let keep = MAX_TOOL_NAME_LENGTH.saturating_sub(suffix_text.chars().count());
        let candidate = format!("{}{suffix_text}", clip_chars(&clipped, keep));
        if !used.contains(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn normalized_tool_name(value: &str, index: usize, used: &HashSet<String>) -> String {
    let base = if valid_tool_name(value) {
        value.to_owned()
    } else {
        value
            .chars()
            .filter(|character| {
                character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
            })
            .collect()
    };
    let fallback = if base.is_empty() {
        format!("tool_{}", index + 1)
    } else {
        base
    };
    unique_tool_name(&fallback, used)
}

/// Marks every declared property of a tool schema as `required`.
pub fn complete_required_schema(value: &Value) -> Value {
    complete_required_walk(value, 0)
}

fn complete_required_walk(value: &Value, depth: usize) -> Value {
    match value {
        Value::Array(entries) => {
            if depth >= MAX_REWRITE_DEPTH {
                return value.clone();
            }
            Value::Array(
                entries
                    .iter()
                    .map(|entry| complete_required_walk(entry, depth + 1))
                    .collect(),
            )
        }
        Value::Object(object) => {
            if depth >= MAX_REWRITE_DEPTH {
                return value.clone();
            }
            let mut out = Map::new();
            for (key, child) in object {
                if key == "properties" {
                    if let Value::Object(properties) = child {
                        let mut rewritten = Map::new();
                        for (name, schema) in properties {
                            rewritten
                                .insert(name.clone(), complete_required_walk(schema, depth + 1));
                        }
                        out.insert(key.clone(), Value::Object(rewritten));
                        continue;
                    }
                }
                out.insert(key.clone(), complete_required_walk(child, depth + 1));
            }
            if let Some(Value::Object(properties)) = out.get("properties") {
                let required: Vec<Value> = properties.keys().cloned().map(Value::String).collect();
                out.insert("required".into(), Value::Array(required));
            }
            Value::Object(out)
        }
        _ => value.clone(),
    }
}

/// Normalizes buddy tool names, completes tool schemas, and rewrites every
/// historical call / choice reference to the emitted name.
pub fn normalize_buddy_tool_names(payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    let Some(Value::Array(tools)) = object.get_mut("tools") else {
        return;
    };
    let mut used: HashSet<String> = HashSet::new();
    let mut replacements: HashMap<String, String> = HashMap::new();
    let mut rewritten: Vec<Value> = Vec::with_capacity(tools.len());
    for (index, raw_tool) in tools.drain(..).enumerate() {
        let Some(tool_object) = raw_tool.as_object() else {
            rewritten.push(raw_tool);
            continue;
        };
        let function = tool_object.get("function").and_then(json_object);
        let custom = tool_object.get("custom").and_then(json_object);
        let source_name = function
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
            .or_else(|| {
                custom
                    .and_then(|custom| custom.get("name"))
                    .and_then(Value::as_str)
            })
            .or_else(|| tool_object.get("name").and_then(Value::as_str));
        let Some(source_name) = source_name else {
            rewritten.push(raw_tool);
            continue;
        };
        let name = normalized_tool_name(source_name, index, &used);
        used.insert(name.clone());
        replacements
            .entry(source_name.to_owned())
            .or_insert_with(|| name.clone());

        let mut updated = tool_object.clone();
        if let Some(function) = function {
            let mut function = function.clone();
            function.insert("name".into(), Value::String(name.clone()));
            if let Some(parameters) = function.get("parameters") {
                let completed = complete_required_schema(parameters);
                function.insert("parameters".into(), completed);
            }
            updated.insert("function".into(), Value::Object(function));
        } else if let Some(custom) = custom {
            let mut custom = custom.clone();
            custom.insert("name".into(), Value::String(name.clone()));
            if let Some(format) = custom.get("format") {
                let completed = complete_required_schema(format);
                custom.insert("format".into(), completed);
            }
            updated.insert("custom".into(), Value::Object(custom));
        } else {
            updated.insert("name".into(), Value::String(name.clone()));
            if let Some(parameters) = updated.get("parameters") {
                let completed = complete_required_schema(parameters);
                updated.insert("parameters".into(), completed);
            }
        }
        rewritten.push(Value::Object(updated));
    }
    *tools = rewritten;

    if let Some(Value::Array(messages)) = object.get_mut("messages") {
        for message in messages {
            let Some(message) = message.as_object_mut() else {
                continue;
            };
            let Some(Value::Array(calls)) = message.get_mut("tool_calls") else {
                continue;
            };
            for call in calls {
                let Some(call) = call.as_object_mut() else {
                    continue;
                };
                let Some(function) = call.get_mut("function").and_then(Value::as_object_mut) else {
                    continue;
                };
                let replacement = function
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(|name| replacements.get(name))
                    .cloned();
                if let Some(replacement) = replacement {
                    function.insert("name".into(), Value::String(replacement));
                }
            }
        }
    }

    let Some(choice) = object.get_mut("tool_choice").and_then(Value::as_object_mut) else {
        return;
    };
    if choice.get("type").and_then(Value::as_str) == Some("allowed_tools") {
        if let Some(Value::Array(allowed)) = choice.get_mut("tools") {
            for raw_allowed in allowed {
                let Some(allowed_object) = raw_allowed.as_object_mut() else {
                    continue;
                };
                let name = if let Some(function) = allowed_object
                    .get_mut("function")
                    .and_then(Value::as_object_mut)
                {
                    function.get_mut("name")
                } else {
                    allowed_object.get_mut("name")
                };
                let Some(Value::String(name)) = name else {
                    continue;
                };
                if let Some(replacement) = replacements.get(name) {
                    *name = replacement.clone();
                }
            }
        }
        return;
    }
    let choice_name = choice
        .get("function")
        .and_then(json_object)
        .and_then(|function| function.get("name"))
        .and_then(Value::as_str)
        .or_else(|| {
            choice
                .get("custom")
                .and_then(json_object)
                .and_then(|custom| custom.get("name"))
                .and_then(Value::as_str)
        })
        .or_else(|| choice.get("name").and_then(Value::as_str));
    let Some(choice_name) = choice_name else {
        return;
    };
    let Some(replacement) = replacements.get(choice_name).cloned() else {
        return;
    };
    if let Some(function) = choice.get_mut("function").and_then(Value::as_object_mut) {
        function.insert("name".into(), Value::String(replacement));
    } else if let Some(custom) = choice.get_mut("custom").and_then(Value::as_object_mut) {
        custom.insert("name".into(), Value::String(replacement));
    } else {
        choice.insert("name".into(), Value::String(replacement));
    }
}

fn normalize_buddy_tool_choice(payload: &mut Map<String, Value>) {
    let Some(choice) = payload.get("tool_choice").cloned() else {
        return;
    };
    if let Some(text) = choice.as_str() {
        if text.trim().eq_ignore_ascii_case("none") {
            payload.remove("tool_choice");
            payload.remove("tools");
            payload.remove("functions");
        }
        return;
    }
    let Some(choice) = choice.as_object() else {
        payload.remove("tool_choice");
        return;
    };
    let variant = choice
        .get("type")
        .and_then(Value::as_str)
        .map(|text| text.trim().to_lowercase())
        .unwrap_or_default();
    match variant.as_str() {
        "none" => {
            payload.remove("tool_choice");
            payload.remove("tools");
            payload.remove("functions");
        }
        "auto" | "required" => {
            payload.insert("tool_choice".into(), Value::String(variant));
        }
        "function" => {
            let mut name = choice
                .get("function")
                .and_then(json_object)
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            if name.is_empty() {
                name = choice
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
            }
            let name = name.trim();
            payload.insert(
                "tool_choice".into(),
                Value::String(if name.is_empty() {
                    "auto".into()
                } else {
                    name.to_owned()
                }),
            );
        }
        _ => {
            payload.remove("tool_choice");
        }
    }
}

fn normalize_buddy_image_url(payload: &mut Value) {
    let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages {
        let Some(content) = message.get_mut("content").and_then(Value::as_array_mut) else {
            continue;
        };
        for part in content {
            let Some(part) = part.as_object_mut() else {
                continue;
            };
            if part.get("type").and_then(Value::as_str) != Some("image_url") {
                continue;
            }
            let url = match part.get("image_url") {
                Some(Value::String(url)) if !url.is_empty() => url.clone(),
                _ => continue,
            };
            part.insert("image_url".into(), json!({ "url": url }));
        }
    }
}

fn normalize_buddy_roles(payload: &mut Value) {
    let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages {
        let Some(message) = message.as_object_mut() else {
            continue;
        };
        if message.get("role").and_then(Value::as_str) == Some("developer") {
            message.insert("role".into(), Value::String("system".into()));
        }
    }
}

fn content_parts(content: Option<&Value>) -> Vec<Value> {
    match content {
        Some(Value::String(text)) => {
            if text.is_empty() {
                Vec::new()
            } else {
                vec![json!({"type": "text", "text": text})]
            }
        }
        Some(Value::Array(parts)) => parts
            .iter()
            .filter(|part| part.is_object())
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// Coalesces consecutive `user` turns, preserving content-part order so images
/// delivered as their own turn are not dropped upstream.
pub fn coalesce_consecutive_user_messages(messages: &mut Vec<Value>) {
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());
    for message in std::mem::take(messages) {
        let merge = message.get("role").and_then(Value::as_str) == Some("user")
            && out
                .last()
                .and_then(|previous| previous.get("role"))
                .and_then(Value::as_str)
                == Some("user");
        if !merge {
            out.push(message);
            continue;
        }
        let previous = out.pop().unwrap_or_else(|| json!({}));
        let mut merged = previous.as_object().cloned().unwrap_or_default();
        let mut parts = content_parts(merged.get("content"));
        parts.extend(content_parts(message.get("content")));
        merged.insert("content".into(), Value::Array(parts));
        out.push(Value::Object(merged));
    }
    *messages = out;
}

/// Merges adjacent assistant items (text/reasoning/parallel calls) into one
/// Chat message so the reasoning trace accompanies every call.
pub fn coalesce_consecutive_assistant_messages(messages: &mut Vec<Value>) {
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());
    for message in std::mem::take(messages) {
        let merge = message.get("role").and_then(Value::as_str) == Some("assistant")
            && out
                .last()
                .and_then(|previous| previous.get("role"))
                .and_then(Value::as_str)
                == Some("assistant");
        if !merge {
            out.push(message);
            continue;
        }
        let previous = out.pop().unwrap_or_else(|| json!({}));
        let Some(previous_object) = previous.as_object() else {
            out.push(previous);
            out.push(message);
            continue;
        };
        let Some(message_object) = message.as_object() else {
            out.push(previous);
            out.push(message);
            continue;
        };

        let first_content = previous_object.get("content");
        let next_content = message_object.get("content");
        let content = match (first_content, next_content) {
            (None, None) => Value::Null,
            (Some(content), None) | (None, Some(content)) => content.clone(),
            (Some(first), Some(next)) => {
                if first.is_null() {
                    next.clone()
                } else if next.is_null() {
                    first.clone()
                } else if let (Some(first), Some(next)) = (first.as_str(), next.as_str()) {
                    if first.is_empty() {
                        Value::String(next.to_owned())
                    } else if next.is_empty() {
                        Value::String(first.to_owned())
                    } else {
                        Value::String(format!("{first}\n{next}"))
                    }
                } else {
                    let mut parts = content_parts(Some(first));
                    parts.extend(content_parts(Some(next)));
                    Value::Array(parts)
                }
            }
        };

        let mut merged = previous_object.clone();
        for (key, value) in message_object {
            merged.insert(key.clone(), value.clone());
        }
        merged.insert("content".into(), content);

        let first_calls = previous_object.get("tool_calls").and_then(Value::as_array);
        let next_calls = message_object.get("tool_calls").and_then(Value::as_array);
        if first_calls.is_some() || next_calls.is_some() {
            let mut calls = first_calls.cloned().unwrap_or_default();
            calls.extend(next_calls.cloned().unwrap_or_default());
            merged.insert("tool_calls".into(), Value::Array(calls));
        }

        let first_reasoning = previous_object
            .get("reasoning_content")
            .and_then(Value::as_str);
        let next_reasoning = message_object
            .get("reasoning_content")
            .and_then(Value::as_str);
        match (first_reasoning, next_reasoning) {
            (Some(first), Some(next)) => {
                let reasoning = if first.is_empty() {
                    next.to_owned()
                } else if next.is_empty() {
                    first.to_owned()
                } else {
                    format!("{first}\n{next}")
                };
                merged.insert("reasoning_content".into(), Value::String(reasoning));
            }
            (Some(first), None) => {
                merged.insert("reasoning_content".into(), Value::String(first.to_owned()));
            }
            (None, Some(next)) => {
                merged.insert("reasoning_content".into(), Value::String(next.to_owned()));
            }
            (None, None) => {}
        }
        out.push(Value::Object(merged));
    }
    *messages = out;
}

/// Drops turns the upstream rejects as empty (`11151`), keeping every turn that
/// carries tool calls, a tool result, or reasoning.
pub fn drop_empty_buddy_messages(messages: &mut Vec<Value>) {
    messages.retain(|message| {
        let Some(object) = message.as_object() else {
            return true;
        };
        if object
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|calls| !calls.is_empty())
        {
            return true;
        }
        if object
            .get("tool_call_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.trim().is_empty())
        {
            return true;
        }
        if object
            .get("reasoning_content")
            .is_some_and(Value::is_string)
        {
            return true;
        }
        match object.get("content") {
            Some(Value::String(content)) => !content.trim().is_empty(),
            Some(Value::Array(content)) => !content.is_empty(),
            Some(Value::Null) | None => false,
            _ => false,
        }
    });
}

/// Guarantees the wire opens with a non-empty `system` turn (`11128`).
pub fn ensure_buddy_leading_system(messages: &mut Vec<Value>, system_prompt: &str) {
    if messages.is_empty() {
        messages.push(json!({"role": "system", "content": system_prompt}));
        return;
    }
    if messages
        .first()
        .and_then(|message| message.get("role"))
        .and_then(Value::as_str)
        == Some("system")
    {
        return;
    }
    messages.insert(0, json!({"role": "system", "content": system_prompt}));
}

fn flatten_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .map(|part| match part.get("text") {
                Some(Value::String(text)) => text.clone(),
                Some(Value::Null) => "null".to_owned(),
                Some(other) => other.to_string(),
                None => String::new(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// True when the system text is a vendor agent prompt the CN gateway rejects.
fn is_agent_prompt_text(text: &str) -> bool {
    let lower = text.to_lowercase();
    let has = |needle: &str| lower.contains(needle);

    if has("you are claude code") {
        return true;
    }
    if has("claude") && has("code") && has("official") && has("cli") {
        return true;
    }
    if (has("anthropic") || has("anxthxropic")) && has("official") && has("cli") {
        return true;
    }
    if let Some(index) = lower.find("you are ") {
        let mut tail = lower[index + "you are ".len()..].trim_start();
        for article in ["an ", "a "] {
            if let Some(rest) = tail.strip_prefix(article) {
                tail = rest.trim_start();
                break;
            }
        }
        for prefix in ["ai ", "coding ", "code "] {
            if let Some(rest) = tail.strip_prefix(prefix) {
                tail = rest.trim_start();
            }
        }
        if tail.starts_with("agent") {
            return true;
        }
        let first_word = tail
            .split(|character: char| !character.is_ascii_alphanumeric())
            .next()
            .unwrap_or("");
        if [
            "cursor", "windsurf", "cline", "aider", "continue", "copilot", "cody",
        ]
        .contains(&first_word)
        {
            return true;
        }
    }
    if has("cc_entrypoint") {
        let rest = lower.split("cc_entrypoint").nth(1).unwrap_or("");
        if ["cli", "vscode", "jetbrains", "gui"]
            .iter()
            .any(|entry| rest.contains(entry))
        {
            return true;
        }
    }
    if has("claude") && has("code") && has("issues") {
        return true;
    }
    if has("give feedback") && has("claude") && has("code") {
        return true;
    }
    if let Some(index) = lower.find("you are ") {
        let tail = &lower[index + "you are ".len()..];
        let window = tail.chars().take(60).collect::<String>();
        if window.contains("agent") && (window.contains("ai agent") || window.contains("powerful"))
        {
            return true;
        }
    }
    if has("orchestration capabilities") || has("ohmyopencode") {
        return true;
    }
    has("<agent-identity>") || has("<role>") || has("<behavior_instructions>")
}

/// Replaces CN agent-identity system prompts with the neutral prompt.
fn neutralize_cn_messages(messages: &mut [Value]) {
    for message in messages.iter_mut() {
        if message.get("role").and_then(Value::as_str) != Some("system") {
            continue;
        }
        let content = message.get("content").cloned();
        let text = flatten_content(content.as_ref());
        let character_count = text.encode_utf16().count();
        if character_count <= 2_000 && !is_agent_prompt_text(&text) {
            continue;
        }
        let string_content = content.as_ref().is_some_and(Value::is_string);
        let replacement = if string_content {
            Value::String(CODEBUDDY_CN_NEUTRAL_PROMPT.into())
        } else {
            json!([{"type": "text", "text": CODEBUDDY_CN_NEUTRAL_PROMPT}])
        };
        if let Some(object) = message.as_object_mut() {
            object.insert("content".into(), replacement);
        }
    }
}

/// Applies the buddy-family message envelope: drop caller system/developer
/// turns, install the variant's fixed leading prompt, and rebuild bare string
/// user content as a typed text block.
pub fn apply_buddy_system_prompt(messages: &mut Vec<Value>, system_prompt: &str) {
    let source: Vec<Value> = std::mem::take(messages)
        .into_iter()
        .filter(|message| {
            let role = message.get("role").and_then(Value::as_str);
            role != Some("system") && role != Some("developer")
        })
        .collect();
    messages.push(json!({"role": "system", "content": system_prompt}));
    for mut message in source {
        let is_string_user = message.get("role").and_then(Value::as_str) == Some("user")
            && message.get("content").is_some_and(Value::is_string);
        if is_string_user {
            let text = message
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            if let Some(object) = message.as_object_mut() {
                object.insert("content".into(), json!([{"type": "text", "text": text}]));
            }
        }
        messages.push(message);
    }
    finalize_buddy_messages(messages, system_prompt);
}

/// Merge user turns, drop empty turns, then guarantee a leading system turn.
pub fn finalize_buddy_messages(messages: &mut Vec<Value>, system_prompt: &str) {
    coalesce_consecutive_user_messages(messages);
    drop_empty_buddy_messages(messages);
    ensure_buddy_leading_system(messages, system_prompt);
}

fn is_assistant_with_tool_calls(message: &Value) -> bool {
    message.get("role").and_then(Value::as_str) == Some("assistant")
        && message
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|calls| !calls.is_empty())
}

/// Moves non-tool turns interleaved between an assistant tool-call turn and its
/// results to after the block (upstream `11148` tool_call_sequence_broken).
fn repack_buddy_tool_result_blocks(messages: &mut Vec<Value>) {
    if messages.len() < 3 {
        return;
    }
    let mut input = std::mem::take(messages).into_iter().peekable();
    let mut out: Vec<Value> = Vec::with_capacity(input.len());
    let mut changed = false;
    while let Some(message) = input.next() {
        if !is_assistant_with_tool_calls(&message) {
            out.push(message);
            continue;
        }
        let mut wanted: HashSet<String> = HashSet::new();
        if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                if let Some(id) = call.get("id").and_then(Value::as_str) {
                    if !id.is_empty() {
                        wanted.insert(id.to_owned());
                    }
                }
            }
        }
        out.push(message);
        let mut results: Vec<Value> = Vec::new();
        let mut between: Vec<Value> = Vec::new();
        let mut saw_non_tool = false;
        while let Some(next) = input.peek() {
            if !next.is_object() {
                break;
            }
            let role = next.get("role").and_then(Value::as_str);
            if role == Some("tool") {
                let is_wanted = next
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| wanted.contains(id));
                if !is_wanted {
                    break;
                }
                results.push(input.next().expect("peeked"));
                if saw_non_tool {
                    changed = true;
                }
                continue;
            }
            if results.is_empty() {
                break;
            }
            between.push(input.next().expect("peeked"));
            saw_non_tool = true;
        }
        let had_between = !between.is_empty();
        out.extend(results);
        out.extend(between);
        if had_between {
            changed = true;
        }
    }
    if changed {
        *messages = out;
    }
}

/// Removes orphan tool calls/results so a broken history self-heals instead of
/// returning `400` on every request.
fn cleanup_buddy_orphan_tool_pairs(messages: &mut Vec<Value>) {
    let mut tool_result_ids: HashSet<String> = HashSet::new();
    let mut tool_call_ids: HashSet<String> = HashSet::new();
    for message in messages.iter() {
        if message.get("role").and_then(Value::as_str) == Some("tool") {
            if let Some(id) = message.get("tool_call_id").and_then(Value::as_str) {
                tool_result_ids.insert(id.to_owned());
            }
        }
        if message.get("role").and_then(Value::as_str) == Some("assistant") {
            if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                for call in calls {
                    if let Some(id) = call.get("id").and_then(Value::as_str) {
                        tool_call_ids.insert(id.to_owned());
                    }
                }
            }
        }
    }
    if tool_result_ids.is_empty() && tool_call_ids.is_empty() {
        return;
    }
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());
    let mut changed = false;
    for message in std::mem::take(messages) {
        if message.get("role").and_then(Value::as_str) == Some("assistant") {
            if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                let kept: Vec<Value> = calls
                    .iter()
                    .filter(|call| {
                        call.get("id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| tool_result_ids.contains(id))
                    })
                    .cloned()
                    .collect();
                if kept.is_empty() && !tool_call_ids.is_empty() && !calls.is_empty() {
                    changed = true;
                    let mut rest = message.as_object().cloned().unwrap_or_default();
                    rest.remove("tool_calls");
                    out.push(Value::Object(rest));
                    continue;
                }
                if kept.len() != calls.len() {
                    changed = true;
                    let mut updated = message.as_object().cloned().unwrap_or_default();
                    updated.insert("tool_calls".into(), Value::Array(kept));
                    out.push(Value::Object(updated));
                    continue;
                }
            }
        }
        if message.get("role").and_then(Value::as_str) == Some("tool") {
            if let Some(id) = message.get("tool_call_id").and_then(Value::as_str) {
                if !tool_call_ids.contains(id) {
                    changed = true;
                    continue;
                }
            }
        }
        out.push(message);
    }
    if changed {
        *messages = out;
    }
}

fn inject_sol_reasoning_default(payload: &mut Map<String, Value>) {
    let model = payload
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    if !model.contains("sol") {
        return;
    }
    if payload.contains_key("reasoning_effort") {
        return;
    }
    if payload
        .get("thinking")
        .and_then(json_object)
        .and_then(|thinking| thinking.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|variant| !variant.is_empty())
    {
        return;
    }
    payload.insert("reasoning_effort".into(), Value::String("high".into()));
}

fn apply_deepseek_reasoning(payload: &mut Map<String, Value>) {
    let model = payload
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !model.starts_with("deepseek") {
        return;
    }
    let thinking_type = payload
        .get("thinking")
        .and_then(json_object)
        .and_then(|thinking| thinking.get("type"))
        .and_then(Value::as_str)
        .map(|variant| variant.trim().to_lowercase());
    if thinking_type.as_deref() == Some("disabled") {
        payload.remove("reasoning_effort");
        payload.remove("reasoningEffort");
        return;
    }
    if payload.get("thinking").is_none() {
        payload.insert("thinking".into(), json!({"type": "enabled"}));
    } else if let Some(thinking) = payload.get_mut("thinking").and_then(Value::as_object_mut) {
        let empty = thinking
            .get("type")
            .and_then(Value::as_str)
            .map(|variant| variant.trim().is_empty())
            .unwrap_or(true);
        if empty {
            thinking.insert("type".into(), Value::String("enabled".into()));
        }
    }
    let needs_effort = payload
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .map(|effort| effort.is_empty())
        .unwrap_or(true);
    if needs_effort {
        payload.insert("reasoning_effort".into(), Value::String("high".into()));
    }
}

fn backfill_deepseek_reasoning_content(payload: &mut Value) {
    let thinking_enabled = payload
        .get("thinking")
        .and_then(json_object)
        .and_then(|thinking| thinking.get("type"))
        .and_then(Value::as_str)
        == Some("enabled");
    let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    let has_trace = messages.iter().any(|message| {
        message
            .get("reasoning")
            .and_then(Value::as_str)
            .is_some_and(|reasoning| !reasoning.is_empty())
            || message.get("reasoning_content").is_some()
    });
    if !thinking_enabled && !has_trace {
        return;
    }
    for message in messages {
        let Some(message) = message.as_object_mut() else {
            continue;
        };
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        if message
            .get("reasoning_content")
            .is_some_and(Value::is_string)
        {
            continue;
        }
        let reasoning = message
            .get("reasoning")
            .and_then(Value::as_str)
            .filter(|reasoning| !reasoning.is_empty());
        if let Some(reasoning) = reasoning {
            message.insert(
                "reasoning_content".into(),
                Value::String(reasoning.to_owned()),
            );
        }
    }
}

/// Payload prefix shared by every buddy variant.
pub fn buddy_pre_payload_common(payload: &mut Value, request: &CanonicalRequest) {
    if !payload.is_object() {
        return;
    }
    // Token alias + tool-choice normalization, then the whole-payload walks.
    {
        let object = payload.as_object_mut().expect("checked above");
        if !object.contains_key("max_tokens") {
            if let Some(value) = object.get("max_completion_tokens").cloned() {
                if let Value::Number(number) = &value {
                    if number.as_f64().is_some_and(|value| value > 0.0) {
                        object.insert("max_tokens".into(), value);
                    }
                }
            }
        }
        object.remove("max_completion_tokens");
        normalize_buddy_tool_choice(object);
    }
    normalize_buddy_image_url(payload);
    normalize_buddy_roles(payload);

    {
        let object = payload.as_object_mut().expect("checked above");
        if !object.contains_key("reasoning_effort") {
            if let Some(effort) = reasoning_effort_from_intent(request.reasoning.as_ref()) {
                object.insert(
                    "reasoning_effort".into(),
                    Value::String(effort.as_str().to_owned()),
                );
            }
        }
        apply_deepseek_reasoning(object);
        inject_sol_reasoning_default(object);
        object.insert("stream".into(), Value::Bool(true));

        let effort = object
            .get("reasoning_effort")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match effort.as_deref() {
            Some("none") | Some("off") => {
                object.remove("reasoning_effort");
                object.remove("reasoning_summary");
            }
            Some(value) if !value.is_empty() => {
                object.insert("reasoning_summary".into(), Value::String("auto".into()));
            }
            _ => {
                object.remove("reasoning_summary");
            }
        }
    }
    backfill_deepseek_reasoning_content(payload);

    {
        let object = payload.as_object_mut().expect("checked above");
        if let Some(Value::Array(messages)) = object.get_mut("messages") {
            repack_buddy_tool_result_blocks(messages);
            cleanup_buddy_orphan_tool_pairs(messages);
            coalesce_consecutive_assistant_messages(messages);
        }
        object.remove("agent");
        object.remove("agent_mode");
        object.remove("agent_prompt");
    }
}

fn restore_historical_tool_definitions(payload: &mut Value, messages: &[Value]) {
    let mut historical_names: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for message in messages {
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(calls) = message.get("tool_calls").and_then(Value::as_array) else {
            continue;
        };
        for call in calls {
            let name = call
                .get("function")
                .and_then(json_object)
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|name| !name.is_empty());
            if let Some(name) = name {
                if seen.insert(name.to_owned()) {
                    historical_names.push(name.to_owned());
                }
            }
        }
    }
    if historical_names.is_empty() {
        return;
    }
    let existing: Vec<Value> = payload
        .get("tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut defined: HashSet<String> = HashSet::new();
    for tool in &existing {
        let name = tool
            .get("function")
            .and_then(json_object)
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
            .or_else(|| tool.get("name").and_then(Value::as_str));
        if let Some(name) = name {
            defined.insert(name.to_owned());
        }
    }
    let recovered: Vec<Value> = historical_names
        .into_iter()
        .filter(|name| !defined.contains(name))
        .map(|name| {
            json!({
                "type": "function",
                "function": {
                    "name": name,
                    "description": "Recovered from historical tool calls.",
                    "parameters": {"type": "object", "additionalProperties": true},
                },
            })
        })
        .collect();
    if recovered.is_empty() {
        return;
    }
    let mut all = existing;
    all.extend(recovered);
    payload["tools"] = Value::Array(all);
}

fn ensure_payload_model(
    payload: &mut Value,
    target: &DispatchTarget,
    label: &str,
) -> Result<(), GatewayError> {
    let has_model = payload
        .get("model")
        .and_then(Value::as_str)
        .is_some_and(|model| !model.is_empty());
    if has_model {
        return Ok(());
    }
    if !target.model_id.is_empty() {
        payload["model"] = Value::String(target.model_id.clone());
        return Ok(());
    }
    Err(GatewayError::new(
        GatewayErrorCode::InvalidRequest,
        400,
        format!("{label} model is required"),
        Map::new(),
    ))
}

// ---------------------------------------------------------------------------
// Provider identity and catalogs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuddyKind {
    CodeBuddyIntl,
    CodeBuddyCn,
    WorkBuddy,
}

#[derive(Debug, Clone, Copy)]
struct BuddyProvider {
    id: &'static str,
    display: &'static str,
    base_url: &'static str,
    kind: BuddyKind,
    default_chat_path: &'static str,
}

fn provider_config(provider_id: &str) -> Option<BuddyProvider> {
    match provider_id.trim().to_lowercase().as_str() {
        "cb" | "codebuddy" | "codebuddy-intl" => Some(BuddyProvider {
            id: CODEBUDDY_PROVIDER_ID,
            display: "CodeBuddy",
            base_url: CODEBUDDY_BASE_URL,
            kind: BuddyKind::CodeBuddyIntl,
            default_chat_path: CODEBUDDY_CHAT_PATH,
        }),
        "cbcn" | "codebuddy-cn" | "codebuddy_cn" => Some(BuddyProvider {
            id: CODEBUDDY_CN_PROVIDER_ID,
            display: "CodeBuddy CN",
            base_url: CODEBUDDY_CN_BASE_URL,
            kind: BuddyKind::CodeBuddyCn,
            default_chat_path: CODEBUDDY_CHAT_PATH,
        }),
        "workbuddy" => Some(BuddyProvider {
            id: WORKBUDDY_PROVIDER_ID,
            display: "WorkBuddy",
            base_url: WORKBUDDY_BASE_URL,
            kind: BuddyKind::WorkBuddy,
            default_chat_path: WORKBUDDY_CHAT_PATH,
        }),
        _ => None,
    }
}

/// One static catalog row: id, name, reasoning, vision, context, output, and an
/// optional explicit tool-call flag.
pub type BuddyRawEntry = (
    &'static str,
    &'static str,
    bool,
    bool,
    Option<i64>,
    Option<i64>,
    Option<bool>,
);

pub const BUDDY_SHARED_RAW: &[BuddyRawEntry] = &[
    ("auto", "Auto", true, true, Some(168_000), None, None),
    (
        "primary-model",
        "Primary",
        true,
        true,
        Some(272_000),
        Some(72_000),
        None,
    ),
    (
        "claude-opus-4.6",
        "Claude Opus 4.6",
        true,
        true,
        Some(200_000),
        Some(64_000),
        None,
    ),
    (
        "claude-opus-4.7-1m",
        "Claude Opus 4.7 1M",
        true,
        true,
        Some(1_000_000),
        Some(64_000),
        None,
    ),
    (
        "claude-sonnet-4.6",
        "Claude Sonnet 4.6",
        true,
        true,
        Some(200_000),
        Some(32_000),
        None,
    ),
    (
        "deepseek-v4.1-flash",
        "DeepSeek V4.1 Flash",
        true,
        false,
        Some(1_000_000),
        Some(384_000),
        None,
    ),
    (
        "deepseek-v4.1-flash-sg",
        "DeepSeek V4.1 Flash SG",
        true,
        false,
        Some(1_000_000),
        Some(128_000),
        None,
    ),
    (
        "deepseek-v4.1-pro",
        "DeepSeek V4.1 Pro",
        true,
        false,
        Some(1_000_000),
        Some(384_000),
        None,
    ),
    (
        "gemini-2.5-flash-image",
        "Gemini 2.5 Flash Image",
        true,
        true,
        Some(1_000_000),
        Some(64_000),
        None,
    ),
    (
        "gemini-3.0-pro-image",
        "Gemini 3.0 Pro Image",
        true,
        true,
        Some(1_000_000),
        Some(64_000),
        None,
    ),
    (
        "gemini-3.1-flash-image",
        "Gemini 3.1 Flash Image",
        true,
        true,
        Some(1_000_000),
        Some(64_000),
        None,
    ),
    (
        "gemini-3.1-pro",
        "Gemini 3.1 Pro",
        true,
        true,
        Some(1_048_576),
        Some(65_536),
        None,
    ),
    (
        "gemini-3.5-flash",
        "Gemini 3.5 Flash",
        true,
        true,
        Some(1_048_576),
        Some(65_536),
        None,
    ),
    (
        "glm-5.3",
        "GLM-5.3",
        true,
        false,
        Some(1_000_000),
        Some(131_072),
        None,
    ),
    (
        "glm-5.3-flash",
        "GLM-5.3 Flash",
        true,
        false,
        Some(1_000_000),
        Some(131_072),
        None,
    ),
    (
        "glm-5v-turbo",
        "GLM-5V Turbo",
        true,
        true,
        Some(200_000),
        Some(131_072),
        None,
    ),
    (
        "gpt-5.3-codex",
        "GPT-5.3 Codex",
        true,
        true,
        Some(400_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-5.4",
        "GPT-5.4",
        true,
        true,
        Some(1_050_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-5.5",
        "GPT-5.5",
        true,
        true,
        Some(1_050_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-5.6-luna",
        "GPT-5.6 Luna",
        true,
        true,
        Some(1_050_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-5.6-sol",
        "GPT-5.6 Sol",
        true,
        true,
        Some(1_050_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-5.6-terra",
        "GPT-5.6 Terra",
        true,
        true,
        Some(1_050_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-6-astra",
        "GPT-6 Astra",
        true,
        true,
        Some(1_050_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-6.1-sol",
        "GPT-6.1 Sol",
        true,
        true,
        Some(1_050_000),
        Some(128_000),
        None,
    ),
    (
        "gpt-image-2",
        "GPT-Image-2",
        true,
        true,
        Some(400_000),
        Some(128_000),
        None,
    ),
    (
        "grok-4.6",
        "Grok 4.6",
        true,
        true,
        Some(500_000),
        Some(500_000),
        None,
    ),
    (
        "grok-4.7",
        "Grok 4.7",
        true,
        true,
        Some(500_000),
        Some(500_000),
        None,
    ),
    (
        "hy3",
        "Hy3",
        true,
        false,
        Some(1_000_000),
        Some(64_000),
        Some(true),
    ),
    (
        "hy4-preview",
        "Hy4 Preview",
        true,
        false,
        Some(1_000_000),
        Some(64_000),
        Some(true),
    ),
    (
        "hy4-preview-f",
        "Hy4 Preview F",
        true,
        false,
        Some(1_000_000),
        Some(64_000),
        Some(true),
    ),
    (
        "kimi-k2.5",
        "Kimi K2.5",
        true,
        false,
        Some(164_000),
        Some(262_144),
        None,
    ),
    (
        "kimi-k2.6",
        "Kimi K2.6",
        true,
        false,
        Some(256_000),
        Some(262_144),
        None,
    ),
    (
        "kimi-k2.7",
        "Kimi K2.7",
        true,
        false,
        Some(256_000),
        Some(65_536),
        None,
    ),
    (
        "kimi-k2.8-preview",
        "Kimi K2.8 Preview",
        true,
        false,
        Some(256_000),
        Some(65_536),
        None,
    ),
    (
        "kimi-k3",
        "Kimi K3",
        true,
        false,
        Some(1_048_576),
        Some(131_072),
        None,
    ),
    (
        "kimi-k3.1",
        "Kimi K3.1",
        true,
        false,
        Some(1_000_000),
        Some(131_072),
        None,
    ),
    (
        "minimax-m3",
        "MiniMax-M3",
        true,
        false,
        Some(512_000),
        Some(512_000),
        None,
    ),
];

pub const CODEBUDDY_CN_RAW: &[BuddyRawEntry] = &[
    (
        "glm-5.3",
        "GLM 5.3",
        true,
        true,
        Some(1_000_000),
        Some(48_000),
        None,
    ),
    (
        "glm-5.3-flash",
        "GLM 5.3 Flash",
        true,
        true,
        Some(1_000_000),
        Some(32_000),
        None,
    ),
    (
        "glm-5v-turbo",
        "GLM 5v Turbo",
        true,
        true,
        Some(200_000),
        Some(64_000),
        None,
    ),
    (
        "minimax-m3",
        "MiniMax M3",
        true,
        true,
        Some(512_000),
        Some(128_000),
        None,
    ),
    (
        "kimi-k2.8-preview",
        "Kimi K2.8 Preview",
        true,
        true,
        Some(256_000),
        Some(32_000),
        None,
    ),
    (
        "kimi-k2.7",
        "Kimi K2.7",
        true,
        true,
        Some(256_000),
        Some(32_000),
        None,
    ),
    (
        "kimi-k2.6",
        "Kimi K2.6",
        true,
        true,
        Some(256_000),
        Some(32_000),
        None,
    ),
    (
        "kimi-k2.5",
        "Kimi K2.5",
        true,
        true,
        Some(164_000),
        Some(32_000),
        None,
    ),
    (
        "kimi-k3-1",
        "Kimi K3",
        true,
        true,
        Some(1_000_000),
        Some(32_000),
        None,
    ),
    ("hy3", "Hy3", true, true, Some(192_000), Some(64_000), None),
    (
        "hy4-preview",
        "Hy4 Preview",
        true,
        true,
        Some(1_000_000),
        Some(64_000),
        None,
    ),
    (
        "deepseek-v4.1-flash",
        "DeepSeek V4.1 Flash",
        true,
        true,
        Some(1_000_000),
        Some(50_000),
        None,
    ),
];

#[allow(clippy::too_many_arguments)]
fn buddy_model_row_owned(
    id: &str,
    name: &str,
    reasoning: bool,
    vision: bool,
    context: Option<i64>,
    output: Option<i64>,
    tool_call: Option<bool>,
    provider_id: &str,
    endpoint: Option<&str>,
) -> Value {
    let mut input = vec![Value::String("text".into())];
    if vision {
        input.push(Value::String("image".into()));
    }
    let output = match (context, output) {
        (Some(context), Some(output)) => Some(output.min(context)),
        _ => output,
    };
    json!({
        "modelId": id,
        "name": name,
        "providerId": provider_id,
        "wireFamily": "chat",
        "serviceKind": "llm",
        "endpointPath": endpoint.unwrap_or(CODEBUDDY_CHAT_PATH),
        "contextLimit": context,
        "outputLimit": output,
        "modalities": {"input": input, "output": ["text"]},
        "reasoning": reasoning,
        "toolCall": tool_call.unwrap_or(true),
    })
}

fn buddy_model_row(entry: &BuddyRawEntry, provider_id: &str, endpoint: Option<&str>) -> Value {
    let (id, name, reasoning, vision, context, output, tool_call) = *entry;
    buddy_model_row_owned(
        id,
        name,
        reasoning,
        vision,
        context,
        output,
        tool_call,
        provider_id,
        endpoint,
    )
}

/// Rows for the shared international roster (`cb` / `workbuddy`).
pub fn buddy_shared_models(provider_id: &str, endpoint: Option<&str>) -> Vec<Value> {
    BUDDY_SHARED_RAW
        .iter()
        .map(|entry| buddy_model_row(entry, provider_id, endpoint))
        .collect()
}

/// Static CodeBuddy International catalog.
pub fn codebuddy_models() -> Vec<Value> {
    buddy_shared_models(CODEBUDDY_PROVIDER_ID, None)
}

/// Static WorkBuddy catalog (explicit `/v2/chat/completions` endpoint).
pub fn workbuddy_models() -> Vec<Value> {
    buddy_shared_models(WORKBUDDY_PROVIDER_ID, Some(WORKBUDDY_CHAT_PATH))
}

/// Rows for the CodeBuddy CN roster.
pub fn codebuddy_cn_models() -> Vec<Value> {
    CODEBUDDY_CN_RAW
        .iter()
        .map(|entry| buddy_model_row(entry, CODEBUDDY_CN_PROVIDER_ID, None))
        .collect()
}

/// Strips the version segment from a provider base URL so a directory path that
/// carries its own `/v2` does not join into `/v2/v2/...`.
fn buddy_site_origin(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((prefix, segment))
            if segment.len() >= 2
                && segment.starts_with('v')
                && segment[1..]
                    .chars()
                    .all(|character| character.is_ascii_digit()) =>
        {
            prefix.to_owned()
        }
        _ => trimmed.to_owned(),
    }
}

/// Parses one console directory envelope into model rows.
///
/// Returns `None` when the endpoint is unusable (non-zero envelope code or no
/// callable models) so a failed sync is not persisted over a working catalog.
pub fn parse_buddy_directory_models(
    payload: &Value,
    provider_id: &str,
    endpoint: Option<&str>,
) -> Option<Vec<Value>> {
    let envelope = payload.as_object()?;
    if envelope.get("code") != Some(&json!(0)) {
        return None;
    }
    let data = envelope.get("data").and_then(json_object)?;
    let raw_models = data.get("models")?.as_array()?;

    let mut cli_roster: Option<HashSet<String>> = None;
    if let Some(agents) = data.get("agents").and_then(Value::as_array) {
        for entry in agents {
            let Some(agent) = entry.as_object() else {
                continue;
            };
            if agent.get("name").and_then(Value::as_str) != Some("cli") {
                continue;
            }
            if let Some(listed) = agent.get("models").and_then(Value::as_array) {
                if !listed.is_empty() {
                    cli_roster = Some(
                        listed
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect(),
                    );
                }
            }
            break;
        }
    }

    let mut rows: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for entry in raw_models {
        let Some(model) = entry.as_object() else {
            continue;
        };
        let Some(id) = model
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        if seen.contains(id) {
            continue;
        }
        if model.get("disabled").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if cli_roster
            .as_ref()
            .is_some_and(|roster| !roster.contains(id))
        {
            continue;
        }
        seen.insert(id.to_owned());
        let name = model
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(id);
        let catalog_number = |value: Option<&Value>| {
            value
                .and_then(Value::as_f64)
                .filter(|number| number.is_finite())
                .map(|number| number as i64)
        };
        let context = catalog_number(model.get("maxInputTokens"));
        let output = catalog_number(model.get("maxOutputTokens"));
        rows.push(buddy_model_row_owned(
            id,
            name,
            model.get("supportsReasoning").and_then(Value::as_bool) == Some(true),
            model.get("supportsImages").and_then(Value::as_bool) == Some(true),
            context,
            output,
            Some(model.get("supportsToolCall").and_then(Value::as_bool) == Some(true)),
            provider_id,
            endpoint,
        ));
    }
    if rows.is_empty() { None } else { Some(rows) }
}

/// Reads one buddy site's live console directory. Returns a JSON array of model
/// rows, or `null` when the directory is unreachable/invalid.
pub async fn discover_buddy_models(
    client: &reqwest::Client,
    provider_id: &str,
    credential: &str,
) -> Value {
    let Some(config) = provider_config(provider_id) else {
        return Value::Null;
    };
    let (path, endpoint) = match config.kind {
        BuddyKind::CodeBuddyIntl => (BUDDY_INTL_MODELS_PATH, None),
        BuddyKind::CodeBuddyCn => (BUDDY_CN_MODELS_PATH, None),
        BuddyKind::WorkBuddy => (BUDDY_INTL_MODELS_PATH, Some(WORKBUDDY_CHAT_PATH)),
    };
    let url = format!("{}{}", buddy_site_origin(config.base_url), path);
    let uid = buddy_account_uid(credential);
    let mut headers = vec![
        ("accept", "application/json".to_owned()),
        ("authorization", format!("Bearer {credential}")),
        ("x-product", "SaaS".to_owned()),
    ];
    match uid {
        Some(uid) => headers.push(("x-user-id", uid)),
        None => headers.push(("x-no-user-id", "1".to_owned())),
    }
    headers.push(("x-no-enterprise-id", "1".to_owned()));
    headers.push(("x-no-department-info", "1".to_owned()));
    let response = match client
        .get(url)
        .headers(header_map_from_pairs(headers))
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return Value::Null,
    };
    if !response.status().is_success() {
        return Value::Null;
    }
    let payload: Value = match response.json().await {
        Ok(payload) => payload,
        Err(_) => return Value::Null,
    };
    parse_buddy_directory_models(&payload, config.id, endpoint)
        .map(Value::Array)
        .unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// Dispatch headers
// ---------------------------------------------------------------------------

fn build_codebuddy_user_agent(identity: &str) -> String {
    let version = if identity.eq_ignore_ascii_case("CLI") {
        CODEBUDDY_CN_VERSION
    } else {
        CODEBUDDY_IDE_VERSION
    };
    format!("{identity}/{version} CodeBuddy/{version}")
}

fn build_workbuddy_user_agent() -> String {
    format!(
        "WorkBuddy/{WORKBUDDY_CLIENT_VERSION} WorkBuddy AI/{WORKBUDDY_CLIENT_VERSION} CLI/{WORKBUDDY_CLI_VERSION}"
    )
}

fn codebuddy_domain(identity: &str) -> &'static str {
    if identity.eq_ignore_ascii_case("CLI") {
        "copilot.tencent.com"
    } else {
        "www.codebuddy.ai"
    }
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(name, value);
    }
}

fn credential_bearer(credential: &DispatchCredential) -> Option<String> {
    // `withBearerAuthentication` forwards every non-`none` credential kind.
    if credential.credential_kind == "none" {
        return None;
    }
    credential
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|secret| !secret.is_empty())
        .map(|secret| {
            let lower = secret.to_ascii_lowercase();
            if lower.starts_with("bearer")
                && secret
                    .get(6..)
                    .is_some_and(|tail| tail.starts_with(char::is_whitespace))
            {
                secret[6..].trim().to_owned()
            } else {
                secret.to_owned()
            }
        })
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn resolve_session_id(request: &CanonicalRequest) -> Option<String> {
    for candidate in [
        request.session_id.as_deref(),
        request.conversation_id.as_deref(),
    ] {
        if let Some(value) = candidate.map(str::trim).filter(|value| !value.is_empty()) {
            return Some(value.to_owned());
        }
    }
    if let Some(value) = request
        .conversation
        .as_ref()
        .and_then(|conversation| conversation.conversation_id.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_owned());
    }
    derive_conversation_affinity(request)
}

fn derive_conversation_affinity(request: &CanonicalRequest) -> Option<String> {
    let text_from_parts = |parts: &[keyla_core::ContentPart]| -> String {
        parts
            .iter()
            .map(|part| match part {
                keyla_core::ContentPart::Text { text } => text.as_str(),
                _ => "",
            })
            .collect::<String>()
    };
    if let Some(system) = request.system.as_ref().filter(|system| !system.is_empty()) {
        let text = text_from_parts(system);
        if text.trim().chars().count() >= 30 {
            let trimmed = text.trim().chars().take(2048).collect::<String>();
            return Some(format!("aff_{}", &sha256_hex(&trimmed)[..24]));
        }
    }
    let first = request.messages.first()?;
    let text = text_from_parts(&first.content);
    if text.trim().chars().count() >= 30 {
        let trimmed = text.trim().chars().take(2048).collect::<String>();
        return Some(format!("aff_{}", &sha256_hex(&trimmed)[..24]));
    }
    None
}

fn random_id() -> String {
    Uuid::new_v4().to_string()
}

fn random_request_id() -> String {
    Uuid::new_v4().simple().to_string()
}

fn codebuddy_headers(identity: &str, request: &CanonicalRequest) -> Vec<(&'static str, String)> {
    let conversation_id = resolve_session_id(request).unwrap_or_else(random_id);
    vec![
        ("accept", "text/event-stream".into()),
        ("User-Agent", build_codebuddy_user_agent(identity)),
        ("X-Product", "SaaS".into()),
        ("X-IDE-Type", identity.into()),
        ("X-IDE-Name", identity.into()),
        ("X-Domain", codebuddy_domain(identity).into()),
        ("x-requested-with", "XMLHttpRequest".into()),
        ("x-codebuddy-request", "1".into()),
        ("x-conversation-id", conversation_id),
        ("x-conversation-request-id", random_id()),
        ("x-conversation-message-id", random_id()),
        ("x-request-id", random_request_id()),
    ]
}

fn derive_account_stable_id(account_id: &str, purpose: &str) -> String {
    let digest = sha256_hex(&format!("wb2a:{purpose}:{account_id}"));
    digest[..36].to_owned()
}

fn workbuddy_headers(
    credential: &DispatchCredential,
    request: &CanonicalRequest,
) -> Vec<(&'static str, String)> {
    let conversation_id = resolve_session_id(request).unwrap_or_else(random_id);
    let mut headers = vec![
        ("accept", "application/json, text/event-stream".to_owned()),
        ("user-agent", build_workbuddy_user_agent()),
        ("origin", "https://www.workbuddy.ai".to_owned()),
        ("referer", "https://www.workbuddy.ai/".to_owned()),
        ("accept-language", "en-US".to_owned()),
        ("x-requested-with", "XMLHttpRequest".to_owned()),
        ("x-codebuddy-request", "1".to_owned()),
        ("x-domain", "www.workbuddy.ai".to_owned()),
        ("x-agent-purpose", "conversation".to_owned()),
        ("x-ide-name", "WorkBuddy".to_owned()),
        ("x-ide-type", "WorkBuddy".to_owned()),
        ("x-ide-version", WORKBUDDY_CLIENT_VERSION.to_owned()),
        ("x-product", "WorkBuddy".to_owned()),
        ("x-no-enterprise-id", "1".to_owned()),
        ("x-conversation-id", conversation_id),
        ("x-request-id", random_request_id()),
    ];
    if let Some(account_id) = credential
        .account_id
        .as_deref()
        .map(str::trim)
        .filter(|account_id| !account_id.is_empty())
    {
        headers.push(("x-user-id", account_id.to_owned()));
        headers.push((
            "x-machine-id",
            derive_account_stable_id(account_id, "machine"),
        ));
        headers.push((
            "x-session-id",
            derive_account_stable_id(account_id, "session"),
        ));
    }
    headers
}

fn dispatch_headers(
    config: &BuddyProvider,
    credential: &DispatchCredential,
    request: &CanonicalRequest,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "content-type", "application/json");
    let identity = match config.kind {
        BuddyKind::CodeBuddyIntl => "IDE",
        BuddyKind::CodeBuddyCn => "CLI",
        BuddyKind::WorkBuddy => "",
    };
    let pairs = match config.kind {
        BuddyKind::WorkBuddy => workbuddy_headers(credential, request),
        _ => codebuddy_headers(identity, request),
    };
    for (name, value) in pairs {
        insert_header(&mut headers, name, &value);
    }
    if let Some(bearer) = credential_bearer(credential) {
        insert_header(&mut headers, "authorization", &format!("Bearer {bearer}"));
    }
    for (name, value) in &credential.extra_headers {
        insert_header(&mut headers, name, value);
    }
    headers
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn network_error(message: String) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::TransportUnavailable,
        502,
        message,
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Network)
}

fn chat_path(config: &BuddyProvider, target: &DispatchTarget) -> String {
    let candidate = target.endpoint_path.trim();
    match config.kind {
        BuddyKind::WorkBuddy => {
            if candidate.is_empty()
                || candidate == CODEBUDDY_CHAT_PATH
                || candidate == "/v1/chat/completions"
            {
                WORKBUDDY_CHAT_PATH.to_owned()
            } else {
                candidate.to_owned()
            }
        }
        _ => {
            if candidate.is_empty() {
                config.default_chat_path.to_owned()
            } else {
                candidate.to_owned()
            }
        }
    }
}

fn prepare_payload(
    config: &BuddyProvider,
    payload: &mut Value,
    request: &CanonicalRequest,
    target: &DispatchTarget,
) -> Result<(), GatewayError> {
    buddy_pre_payload_common(payload, request);
    match config.kind {
        BuddyKind::CodeBuddyIntl => {
            if payload
                .get("model")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                ensure_payload_model(payload, target, "CodeBuddy")?;
            }
            if let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) {
                apply_buddy_system_prompt(messages, CODEBUDDY_SYSTEM_PROMPT);
            }
            normalize_buddy_tool_names(payload);
        }
        BuddyKind::CodeBuddyCn => {
            if let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) {
                neutralize_cn_messages(messages);
                coalesce_consecutive_user_messages(messages);
                drop_empty_buddy_messages(messages);
                ensure_buddy_leading_system(messages, CODEBUDDY_CN_NEUTRAL_PROMPT);
            }
            ensure_payload_model(payload, target, "CodeBuddy CN")?;
            normalize_buddy_tool_names(payload);
        }
        BuddyKind::WorkBuddy => {
            if payload
                .get("model")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                ensure_payload_model(payload, target, "WorkBuddy")?;
            }
            if let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) {
                apply_buddy_system_prompt(messages, WORKBUDDY_SYSTEM_PROMPT);
            }
            let messages = payload
                .get("messages")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            restore_historical_tool_definitions(payload, &messages);
            normalize_buddy_tool_names(payload);
        }
    }
    Ok(())
}

async fn collect_sse_response(
    response: reqwest::Response,
    model: &str,
) -> Result<Vec<CanonicalEvent>, GatewayError> {
    let mut upstream = response.bytes_stream();
    let mut sse = SseDecoder::new();
    let mut decoder = ChatSseDecoder::new(model.to_owned());
    let mut events = decoder.start();
    while let Some(chunk) = upstream.next().await {
        let chunk: Bytes =
            chunk.map_err(|error| network_error(format!("upstream stream error: {error}")))?;
        for frame in sse.push(&chunk) {
            events.extend(decoder.push(&frame.data)?);
        }
    }
    for frame in sse.finish() {
        events.extend(decoder.push(&frame.data)?);
    }
    events.extend(decoder.finish(false));
    Ok(events)
}

fn stream_sse_response(
    response: reqwest::Response,
    model: String,
) -> BoxStream<'static, Result<CanonicalEvent, GatewayError>> {
    let mut upstream = response.bytes_stream();
    let stream = async_stream::try_stream! {
        let mut sse = SseDecoder::new();
        let mut decoder = ChatSseDecoder::new(model);
        let mut start = decoder.start();
        let mut emitted_start = false;
        while let Some(chunk) = upstream.next().await {
            let chunk: Bytes =
                chunk.map_err(|error| network_error(format!("upstream stream error: {error}")))?;
            for frame in sse.push(&chunk) {
                let events = decoder.push(&frame.data)?;
                if !emitted_start {
                    for event in start.drain(..) {
                        yield event;
                    }
                    emitted_start = true;
                }
                for event in events {
                    yield event;
                }
            }
        }
        if !emitted_start {
            for event in start.drain(..) {
                yield event;
            }
        }
        for frame in sse.finish() {
            for event in decoder.push(&frame.data)? {
                yield event;
            }
        }
        for event in decoder.finish(false) {
            yield event;
        }
    };
    Box::pin(stream)
}

async fn dispatch_with_config(
    client: &reqwest::Client,
    config: BuddyProvider,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let mut upstream_request = request.clone();
    upstream_request.model = target.model_id.clone();
    let mut payload = canonical_to_chat_payload(&upstream_request, true);
    prepare_payload(&config, &mut payload, request, target)?;

    let base = if credential.base_url.trim().is_empty() {
        config.base_url
    } else {
        credential.base_url.as_str()
    };
    let url = endpoint_url(Some(base), &chat_path(&config, target), false);
    let headers = dispatch_headers(&config, credential, request);
    let response = client
        .post(&url)
        .headers(headers)
        .json(&payload)
        .send()
        .await
        .map_err(|error| network_error(format!("buddy request failed: {error}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(upstream_http_error(status.as_u16(), &body, config.id));
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.contains("text/event-stream") {
        if request.stream {
            return Ok(DispatchOutput::Stream(stream_sse_response(
                response,
                target.model_id.clone(),
            )));
        }
        let events = collect_sse_response(response, &target.model_id).await?;
        return Ok(DispatchOutput::Events(events));
    }

    let body = response
        .bytes()
        .await
        .map_err(|error| network_error(format!("upstream body error: {error}")))?;
    let value: Value = serde_json::from_slice(&body).map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::PlatformUnavailable,
            502,
            format!("Malformed upstream JSON: {error}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Upstream)
    })?;
    Ok(DispatchOutput::Events(parse_chat_response_to_events(
        &value,
        &target.model_id,
    )))
}

/// Dispatches one canonical request to any buddy-family provider.
///
/// `provider_id` accepts the canonical ids (`cb`, `cbcn`, `workbuddy`) and the
/// display aliases (`codebuddy`, `codebuddy-cn`).
pub async fn dispatch_buddy(
    client: &reqwest::Client,
    provider_id: &str,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let Some(config) = provider_config(provider_id) else {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            format!("Unsupported buddy provider {provider_id}"),
            Map::new(),
        ));
    };
    dispatch_with_config(client, config, request, target, credential).await
}

/// CodeBuddy International (`cb`).
pub async fn dispatch_codebuddy(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    dispatch_buddy(client, CODEBUDDY_PROVIDER_ID, request, target, credential).await
}

/// CodeBuddy CN (`cbcn`).
pub async fn dispatch_codebuddy_cn(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    dispatch_buddy(
        client,
        CODEBUDDY_CN_PROVIDER_ID,
        request,
        target,
        credential,
    )
    .await
}

/// WorkBuddy (`workbuddy`).
pub async fn dispatch_workbuddy(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    dispatch_buddy(client, WORKBUDDY_PROVIDER_ID, request, target, credential).await
}

// ---------------------------------------------------------------------------
// OAuth (buddy-oauth-shared.ts + variant files)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct BuddyOAuthVariant {
    pub provider_id: &'static str,
    pub provider_label: &'static str,
    pub domain: &'static str,
    pub platform: &'static str,
    pub device_start_url: &'static str,
    pub device_poll_url: &'static str,
    pub refresh_url: &'static str,
    /// WorkBuddy reads the envelope code through `Number()`; CodeBuddy is strict.
    pub coercing_code: bool,
}

pub const CODEBUDDY_INTL_VARIANT: BuddyOAuthVariant = BuddyOAuthVariant {
    provider_id: CODEBUDDY_PROVIDER_ID,
    provider_label: "CodeBuddy",
    domain: "www.codebuddy.ai",
    platform: "ide",
    device_start_url: CODEBUDDY_INTL_DEVICE_START_URL,
    device_poll_url: CODEBUDDY_INTL_DEVICE_POLL_URL,
    refresh_url: CODEBUDDY_INTL_REFRESH_URL,
    coercing_code: false,
};

pub const CODEBUDDY_CN_VARIANT: BuddyOAuthVariant = BuddyOAuthVariant {
    provider_id: CODEBUDDY_CN_PROVIDER_ID,
    provider_label: "CodeBuddy",
    domain: "copilot.tencent.com",
    platform: "CLI",
    device_start_url: CODEBUDDY_CN_DEVICE_START_URL,
    device_poll_url: CODEBUDDY_CN_DEVICE_POLL_URL,
    refresh_url: CODEBUDDY_CN_REFRESH_URL,
    coercing_code: false,
};

pub const WORKBUDDY_VARIANT: BuddyOAuthVariant = BuddyOAuthVariant {
    provider_id: WORKBUDDY_PROVIDER_ID,
    provider_label: "WorkBuddy",
    domain: "www.workbuddy.ai",
    platform: "CLI",
    device_start_url: WORKBUDDY_DEVICE_START_URL,
    device_poll_url: WORKBUDDY_DEVICE_POLL_URL,
    refresh_url: WORKBUDDY_REFRESH_URL,
    coercing_code: true,
};

/// The OAuth variant for a provider id, if this family implements one.
pub fn oauth_variant(provider_id: &str) -> Option<&'static BuddyOAuthVariant> {
    match provider_id.trim().to_lowercase().as_str() {
        "cb" | "codebuddy" | "codebuddy-intl" => Some(&CODEBUDDY_INTL_VARIANT),
        "cbcn" | "codebuddy-cn" | "codebuddy_cn" => Some(&CODEBUDDY_CN_VARIANT),
        "workbuddy" => Some(&WORKBUDDY_VARIANT),
        _ => None,
    }
}

/// The `data` object of a buddy auth response, or `null` when absent.
pub fn buddy_response_data(payload: &Value) -> Value {
    payload
        .get("data")
        .filter(|data| data.is_object())
        .cloned()
        .unwrap_or(Value::Null)
}

/// Projects one buddy auth response onto the token fields the flow consumes.
pub fn parse_buddy_token_data(payload: &Value) -> Value {
    let data = payload
        .get("data")
        .filter(|data| data.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    json!({
        "accessToken": data.get("accessToken").cloned().unwrap_or(Value::Null),
        "refreshToken": data.get("refreshToken").cloned().unwrap_or(Value::Null),
        "tokenType": data.get("tokenType").cloned().unwrap_or(Value::Null),
        "expiresIn": data.get("expiresIn").cloned().unwrap_or(Value::Null),
    })
}

/// Strict envelope-code read: finite number, or a numeric string.
pub fn strict_response_code(payload: &Value) -> Option<f64> {
    let code = payload.get("code")?;
    match code {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(_) => js_number(code),
        _ => None,
    }
}

/// `Number(code)` read used by the WorkBuddy gateway.
pub fn coercing_response_code(payload: &Value) -> Option<f64> {
    payload.get("code").and_then(js_number)
}

fn response_code(variant: &BuddyOAuthVariant, payload: &Value) -> Option<f64> {
    if variant.coercing_code {
        coercing_response_code(payload)
    } else {
        strict_response_code(payload)
    }
}

fn decode_base64_url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

/// Decodes a JWT payload without verifying it (metadata only).
pub fn decode_jwt_payload(token: &str) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let bytes = decode_base64_url(parts[1])?;
    let parsed: Value = serde_json::from_slice(&bytes).ok()?;
    parsed.as_object().cloned()
}

/// The account uid carried by a buddy access token (`sub`, then `uid`).
pub fn buddy_account_uid(access_token: &str) -> Option<String> {
    let claims = decode_jwt_payload(access_token)?;
    non_empty_str(claims.get("sub")).or_else(|| non_empty_str(claims.get("uid")))
}

/// Human display label from the Keycloak JWT claims.
pub fn buddy_account_label(access_token: &str) -> Option<String> {
    let claims = decode_jwt_payload(access_token)?;
    let email = non_empty_str(claims.get("email"))
        .or_else(|| non_empty_str(claims.get("preferred_username")));
    let given = non_empty_str(claims.get("given_name"));
    let family = non_empty_str(claims.get("family_name"));
    let full = match (given, family) {
        (Some(given), Some(family)) => Some(format!("{given} {family}")),
        _ => non_empty_str(claims.get("name")),
    };
    match (email, full) {
        (Some(email), Some(full)) => Some(format!("{full} <{email}>")),
        (Some(email), None) => Some(email),
        (None, Some(full)) => Some(full),
        (None, None) => non_empty_str(claims.get("sub")),
    }
}

fn expiration_iso(expires_in: Option<&Value>) -> String {
    let seconds = expires_in
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .unwrap_or(86_400.0)
        .max(0.0);
    let millis = (seconds * 1000.0) as i64;
    let expires = Utc::now() + chrono::Duration::milliseconds(millis);
    expires.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn token_result(
    variant: &BuddyOAuthVariant,
    payload: &Value,
    fallback_refresh: Option<&str>,
) -> Result<Value, String> {
    let data = parse_buddy_token_data(payload);
    let access = non_empty_str(data.get("accessToken"))
        .ok_or_else(|| format!("{} token response omitted accessToken", variant.provider_id))?;
    let refresh = non_empty_str(data.get("refreshToken"))
        .or_else(|| fallback_refresh.map(str::to_owned))
        .unwrap_or_default();
    let mut result = json!({
        "access": access,
        "refresh": refresh,
        "expiresAt": expiration_iso(data.get("expiresIn")),
    });
    if let Some(label) = buddy_account_label(
        result
            .get("access")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ) {
        result["accountLabel"] = Value::String(label);
    }
    Ok(result)
}

fn oauth_user_agent(variant: &BuddyOAuthVariant, override_user_agent: Option<&str>) -> String {
    if let Some(user_agent) = override_user_agent
        .map(str::trim)
        .filter(|user_agent| !user_agent.is_empty())
    {
        return user_agent.to_owned();
    }
    match variant.provider_id {
        CODEBUDDY_PROVIDER_ID => build_codebuddy_user_agent("IDE"),
        CODEBUDDY_CN_PROVIDER_ID => build_codebuddy_user_agent("CLI"),
        _ => build_workbuddy_user_agent(),
    }
}

fn auth_identity_headers(
    variant: &BuddyOAuthVariant,
    user_agent: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("accept", "application/json".to_owned()),
        ("user-agent", user_agent.to_owned()),
        ("x-requested-with", "XMLHttpRequest".to_owned()),
        ("x-domain", variant.domain.to_owned()),
        ("x-product", "SaaS".to_owned()),
    ]
}

fn device_start_headers(
    variant: &BuddyOAuthVariant,
    user_agent: &str,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![("content-type", "application/json".to_owned())];
    headers.extend(auth_identity_headers(variant, user_agent));
    headers.push(("x-no-authorization", "true".to_owned()));
    headers.push(("x-no-user-id", "true".to_owned()));
    headers
}

fn device_poll_headers(
    variant: &BuddyOAuthVariant,
    user_agent: &str,
) -> Vec<(&'static str, String)> {
    let mut headers = auth_identity_headers(variant, user_agent);
    headers.push(("x-no-authorization", "true".to_owned()));
    headers.push(("x-no-user-id", "true".to_owned()));
    headers.push(("x-no-enterprise-id", "true".to_owned()));
    headers.push(("x-no-department-info", "true".to_owned()));
    headers
}

fn refresh_headers(
    variant: &BuddyOAuthVariant,
    refresh_token: &str,
    user_agent: &str,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![("content-type", "application/json".to_owned())];
    headers.extend(auth_identity_headers(variant, user_agent));
    headers.push(("x-refresh-token", refresh_token.to_owned()));
    headers.push(("x-auth-refresh-source", "plugin".to_owned()));
    headers
}

fn header_map_from_pairs(pairs: Vec<(&'static str, String)>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        insert_header(&mut headers, name, &value);
    }
    headers
}

fn encode_query_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

async fn read_json_response(response: reqwest::Response, label: &str) -> Result<Value, String> {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "{label} request failed ({}): {}",
            status.as_u16(),
            text.chars().take(500).collect::<String>()
        ));
    }
    serde_json::from_str(&text).map_err(|_| format!("{label} returned invalid JSON"))
}

fn oauth_failure(reason: impl Into<String>) -> Value {
    json!({"status": "failed", "reason": reason.into()})
}

/// Starts a buddy device authorization.
///
/// Returns either `{verificationUri,userCode,deviceAuthId,intervalSeconds,expiresInSeconds}`
/// or `{status:"failed",reason}`.
pub async fn oauth_start(
    client: &reqwest::Client,
    provider_id: &str,
    user_agent: Option<&str>,
) -> Value {
    let Some(variant) = oauth_variant(provider_id) else {
        return oauth_failure(format!("unsupported buddy provider {provider_id}"));
    };
    let url = format!(
        "{}?platform={}",
        variant.device_start_url,
        encode_query_component(variant.platform)
    );
    let headers = header_map_from_pairs(device_start_headers(
        variant,
        &oauth_user_agent(variant, user_agent),
    ));
    let response = match client.post(&url).headers(headers).body("{}").send().await {
        Ok(response) => response,
        Err(error) => {
            return oauth_failure(format!(
                "{} state request failed: {error}",
                variant.provider_id
            ));
        }
    };
    let payload = match read_json_response(
        response,
        &format!("{} device authorization", variant.provider_id),
    )
    .await
    {
        Ok(payload) => payload,
        Err(error) => return oauth_failure(error),
    };
    if response_code(variant, &payload) != Some(0.0) {
        let detail =
            non_empty_str(payload.get("msg")).unwrap_or_else(|| "missing state/authUrl".to_owned());
        return oauth_failure(format!("{} state error: {detail}", variant.provider_id));
    }
    let data = buddy_response_data(&payload);
    let device_auth_id = non_empty_str(data.get("state"));
    let verification_uri = non_empty_str(data.get("authUrl"));
    let (Some(device_auth_id), Some(verification_uri)) = (device_auth_id, verification_uri) else {
        return oauth_failure(format!(
            "{} device authorization returned an invalid response",
            variant.provider_id
        ));
    };
    json!({
        "verificationUri": verification_uri,
        "userCode": "",
        "deviceAuthId": device_auth_id,
        "intervalSeconds": 5,
        "expiresInSeconds": 900,
    })
}

/// Polls a started buddy device authorization.
///
/// Returns `{status:"pending"}`, `{status:"complete",result:{access,refresh,expiresAt,accountLabel?}}`,
/// or `{status:"failed",reason}`.
pub async fn oauth_poll(
    client: &reqwest::Client,
    provider_id: &str,
    device_auth_id: &str,
    user_agent: Option<&str>,
) -> Value {
    let Some(variant) = oauth_variant(provider_id) else {
        return oauth_failure(format!("unsupported buddy provider {provider_id}"));
    };
    let url = format!(
        "{}?state={}",
        variant.device_poll_url,
        encode_query_component(device_auth_id)
    );
    let headers = header_map_from_pairs(device_poll_headers(
        variant,
        &oauth_user_agent(variant, user_agent),
    ));
    let response = match client.get(&url).headers(headers).send().await {
        Ok(response) => response,
        Err(error) => {
            return oauth_failure(format!(
                "{} token polling failed: {error}",
                variant.provider_id
            ));
        }
    };
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let payload: Value = match serde_json::from_str(&text) {
        Ok(payload) => payload,
        Err(_) => {
            return oauth_failure(format!(
                "{} token endpoint returned invalid JSON",
                variant.provider_id
            ));
        }
    };
    if !status.is_success() {
        return oauth_failure(format!(
            "{} token polling failed ({})",
            variant.provider_id,
            status.as_u16()
        ));
    }
    let code = response_code(variant, &payload);
    if code == Some(BUDDY_PENDING_CODE) {
        return json!({"status": "pending"});
    }
    if code != Some(0.0) {
        let detail = non_empty_str(payload.get("msg"))
            .unwrap_or_else(|| format!("{} token polling failed", variant.provider_id));
        return oauth_failure(detail);
    }
    let data = buddy_response_data(&payload);
    if non_empty_str(data.get("accessToken")).is_none() {
        return oauth_failure(format!(
            "{} token response omitted accessToken",
            variant.provider_id
        ));
    }
    match token_result(variant, &payload, None) {
        Ok(result) => json!({"status": "complete", "result": result}),
        Err(error) => oauth_failure(error),
    }
}

/// Refreshes a buddy access token.
///
/// Returns `{access,refresh,expiresAt}` or `{status:"failed",reason}`.
pub async fn oauth_refresh(
    client: &reqwest::Client,
    provider_id: &str,
    refresh_token: &str,
    user_agent: Option<&str>,
) -> Value {
    let Some(variant) = oauth_variant(provider_id) else {
        return oauth_failure(format!("unsupported buddy provider {provider_id}"));
    };
    let headers = header_map_from_pairs(refresh_headers(
        variant,
        refresh_token,
        &oauth_user_agent(variant, user_agent),
    ));
    let response = match client
        .post(variant.refresh_url)
        .headers(headers)
        .body("{}")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return oauth_failure(format!(
                "{} token refresh failed: {error}",
                variant.provider_id
            ));
        }
    };
    let payload =
        match read_json_response(response, &format!("{} token refresh", variant.provider_id)).await
        {
            Ok(payload) => payload,
            Err(error) => return oauth_failure(error),
        };
    if response_code(variant, &payload) != Some(0.0) {
        let detail = non_empty_str(payload.get("msg"));
        let message = match detail {
            Some(detail) => format!("{} token refresh failed: {detail}", variant.provider_id),
            None => format!("{} token refresh failed", variant.provider_id),
        };
        return oauth_failure(message);
    }
    match token_result(variant, &payload, Some(refresh_token)) {
        Ok(result) => {
            let mut output = Map::new();
            output.insert(
                "access".into(),
                result.get("access").cloned().unwrap_or(Value::Null),
            );
            if let Some(refresh) = result
                .get("refresh")
                .and_then(Value::as_str)
                .filter(|refresh| !refresh.is_empty())
            {
                output.insert("refresh".into(), Value::String(refresh.to_owned()));
            }
            output.insert(
                "expiresAt".into(),
                result.get("expiresAt").cloned().unwrap_or(Value::Null),
            );
            Value::Object(output)
        }
        Err(error) => oauth_failure(error),
    }
}

// ---------------------------------------------------------------------------
// Quota (buddy-quota-shared.ts)
// ---------------------------------------------------------------------------

fn parse_billing_reset_time(value: Option<&Value>) -> Option<String> {
    let value = value?;
    match value {
        Value::Null => None,
        Value::Number(number) => {
            let number = number.as_f64().filter(|number| number.is_finite())?;
            let millis = if number < 1e12 {
                number * 1000.0
            } else {
                number
            };
            DateTime::from_timestamp_millis(millis as i64)
                .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true))
        }
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            if trimmed.chars().all(|character| character.is_ascii_digit()) {
                let timestamp = trimmed.parse::<f64>().ok()?;
                if !timestamp.is_finite() {
                    return None;
                }
                let millis = if timestamp < 1e12 {
                    timestamp * 1000.0
                } else {
                    timestamp
                };
                return DateTime::from_timestamp_millis(millis as i64)
                    .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true));
            }
            parse_date_string(trimmed)
        }
        _ => None,
    }
}

fn parse_date_string(value: &str) -> Option<String> {
    if let Ok(date) = DateTime::parse_from_rfc3339(value) {
        return Some(
            date.with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        );
    }
    for format in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"] {
        if let Ok(date) = chrono::NaiveDateTime::parse_from_str(value, format) {
            return Some(date.and_utc().to_rfc3339_opts(SecondsFormat::Millis, true));
        }
        if format == "%Y-%m-%d" {
            if let Ok(date) = chrono::NaiveDate::parse_from_str(value, format) {
                return Some(
                    date.and_hms_opt(0, 0, 0)?
                        .and_utc()
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                );
            }
        }
    }
    None
}

fn billing_num(precise: Option<&Value>, plain: Option<&Value>) -> f64 {
    let chosen = match precise {
        Some(Value::Null) | None => plain,
        Some(value) => Some(value),
    };
    chosen
        .and_then(js_number)
        .filter(|value| value.is_finite())
        .unwrap_or(0.0)
}

fn cycle_end_ms(account: &Map<String, Value>) -> f64 {
    parse_billing_reset_time(account.get("CycleEndTime"))
        .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
        .map(|date| date.timestamp_millis() as f64)
        .unwrap_or(f64::INFINITY)
}

fn is_refill(account: &Map<String, Value>) -> bool {
    let cycle_end = cycle_end_ms(account);
    let deduction_end = parse_billing_reset_time(account.get("DeductionEndTime"))
        .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
        .map(|date| date.timestamp_millis() as f64)
        .unwrap_or(f64::NAN);
    cycle_end.is_finite() && deduction_end.is_finite() && deduction_end - cycle_end > REFILL_GAP_MS
}

fn refill_cadence(account: &Map<String, Value>) -> &'static str {
    let start = parse_billing_reset_time(account.get("CycleStartTime"))
        .and_then(|value| DateTime::parse_from_rfc3339(&value).ok());
    let end = parse_billing_reset_time(account.get("CycleEndTime"))
        .and_then(|value| DateTime::parse_from_rfc3339(&value).ok());
    if let (Some(start), Some(end)) = (start, end) {
        let days = (end.timestamp_millis() - start.timestamp_millis()) as f64 / 86_400_000.0;
        if days <= 1.5 {
            return "Daily";
        }
        if days <= 10.0 {
            return "Weekly";
        }
    }
    "Monthly"
}

fn used_percent(used: f64, total: f64) -> Option<f64> {
    if !used.is_finite() || !total.is_finite() || total <= 0.0 {
        return None;
    }
    let percent = (used / total) * 100.0;
    if !percent.is_finite() {
        return None;
    }
    Some(percent.clamp(0.0, 100.0))
}

fn percent_window(
    kind: &str,
    label: &str,
    used: Option<f64>,
    resets_at: Option<&str>,
    used_value: f64,
    limit: f64,
) -> Value {
    let used_percent = used.map(|value| value.clamp(0.0, 100.0));
    json!({
        "kind": kind,
        "label": label,
        "usedPercent": used_percent,
        "remainingPercent": used_percent.map(|value| (100.0 - value).max(0.0)),
        "resetsAt": resets_at,
        "used": used_value,
        "limit": limit,
    })
}

fn extract_billing_accounts(parsed: &Value) -> Vec<Map<String, Value>> {
    let root = parsed.as_object();
    let outer_data = root
        .and_then(|root| root.get("data"))
        .and_then(json_object)
        .or(root);
    let Some(outer_data) = outer_data else {
        return Vec::new();
    };
    let response_record = outer_data
        .get("Response")
        .and_then(json_object)
        .or_else(|| outer_data.get("response").and_then(json_object))
        .unwrap_or(outer_data);
    let inner_data = response_record
        .get("Data")
        .and_then(json_object)
        .or_else(|| response_record.get("data").and_then(json_object))
        .unwrap_or(response_record);
    let accounts = inner_data
        .get("Accounts")
        .or_else(|| inner_data.get("accounts"));
    let Some(Value::Array(accounts)) = accounts else {
        return Vec::new();
    };
    accounts.iter().filter_map(json_object).cloned().collect()
}

fn build_billing_windows(
    accounts: &[Map<String, Value>],
    default_plan: &str,
) -> (String, Vec<Value>) {
    let mut refills: Vec<&Map<String, Value>> = accounts
        .iter()
        .filter(|account| is_refill(account))
        .collect();
    refills.sort_by(|left, right| {
        cycle_end_ms(left)
            .partial_cmp(&cycle_end_ms(right))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut bonuses: Vec<&Map<String, Value>> = accounts
        .iter()
        .filter(|account| !is_refill(account))
        .collect();
    bonuses.sort_by(|left, right| {
        cycle_end_ms(left)
            .partial_cmp(&cycle_end_ms(right))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut windows = Vec::new();
    let mut seen_refill: HashMap<&'static str, usize> = HashMap::new();
    for account in &refills {
        let base = refill_cadence(account);
        let count = seen_refill.entry(base).or_insert(0);
        *count += 1;
        let count = *count;
        let label = if count > 1 {
            format!("{base} {count}")
        } else {
            base.to_owned()
        };
        let used = billing_num(
            account.get("CycleCapacityUsedPrecise"),
            account.get("CycleCapacityUsed"),
        );
        let total = billing_num(
            account.get("CycleCapacitySizePrecise"),
            account.get("CycleCapacitySize"),
        );
        let reset_at = parse_billing_reset_time(account.get("CycleEndTime"));
        let percent = used_percent(used, total);
        let kind = if count > 1 {
            format!("quota:{}_{count}", base.to_lowercase())
        } else {
            format!("quota:{}", base.to_lowercase())
        };
        let mut window = percent_window(&kind, &label, percent, reset_at.as_deref(), used, total);
        window["kind"] = Value::String(kind);
        window["label"] = Value::String(label);
        window["recurring"] = Value::Bool(true);
        windows.push(window);
    }

    for (index, account) in bonuses.iter().enumerate() {
        let label = format!("Bonus Pack {}", index + 1);
        let kind = format!("bonus:{}", index + 1);
        let used = billing_num(
            account.get("CapacityUsedPrecise"),
            account.get("CapacityUsed"),
        );
        let total = billing_num(
            account.get("CapacitySizePrecise"),
            account.get("CapacitySize"),
        );
        let reset_at = parse_billing_reset_time(account.get("CycleEndTime"));
        let percent = used_percent(used, total);
        let mut window = percent_window(&kind, &label, percent, reset_at.as_deref(), used, total);
        window["kind"] = Value::String(kind);
        window["label"] = Value::String(label);
        window["recurring"] = Value::Bool(false);
        windows.push(window);
    }

    let base_package = refills.first().copied().or_else(|| accounts.first());
    let plan = base_package
        .and_then(|package| as_text(package.get("PackageName")))
        .or_else(|| base_package.and_then(|package| as_text(package.get("SubProductName"))))
        .unwrap_or_else(|| default_plan.to_owned());
    (plan, windows)
}

fn resolve_bearer_token(credential: &str) -> Option<String> {
    let trimmed = credential.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('{') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            if let Some(object) = parsed.as_object() {
                let candidate = ["accessToken", "access_token", "apiKey", "api_key", "token"]
                    .iter()
                    .find_map(|key| as_text(object.get(*key)));
                if let Some(candidate) = candidate {
                    return Some(candidate);
                }
            }
        }
    }
    Some(trimmed.to_owned())
}

fn enterprise_id(auth_state: Option<&Value>) -> Option<String> {
    auth_state
        .and_then(json_object)
        .and_then(|state| state.get("enterpriseId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn add_enterprise_headers(headers: &mut Vec<(&'static str, String)>, enterprise_id: Option<&str>) {
    if let Some(enterprise_id) = enterprise_id {
        headers.push(("X-Tenant-Id", enterprise_id.to_owned()));
        headers.push(("X-Enterprise-Id", enterprise_id.to_owned()));
    }
}

fn codebuddy_billing_headers(
    identity: &str,
    enterprise_id: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("User-Agent", build_codebuddy_user_agent(identity)),
        ("X-Product", "SaaS".to_owned()),
        ("X-IDE-Type", identity.to_owned()),
        ("X-IDE-Name", identity.to_owned()),
        ("X-Domain", codebuddy_domain(identity).to_owned()),
        ("x-requested-with", "XMLHttpRequest".to_owned()),
        ("x-codebuddy-request", "1".to_owned()),
    ];
    add_enterprise_headers(&mut headers, enterprise_id);
    headers
}

fn workbuddy_billing_headers(enterprise_id: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("User-Agent", build_workbuddy_user_agent()),
        ("X-Product", "SaaS".to_owned()),
        ("X-Domain", "www.workbuddy.ai".to_owned()),
        ("X-Requested-With", "XMLHttpRequest".to_owned()),
        ("X-CodeBuddy-Request", "1".to_owned()),
        ("Accept-Language", "en-US".to_owned()),
    ];
    add_enterprise_headers(&mut headers, enterprise_id);
    headers
}

fn billing_stamp(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn quota_failure(source: &str, message: impl Into<String>) -> Value {
    json!({
        "source": source,
        "plan": Value::Null,
        "windows": [],
        "error": message.into(),
    })
}

/// Fetches one buddy provider's quota from the Tencent billing endpoint.
///
/// `auth_state` may carry `enterpriseId` for the tenant headers. The credential
/// may be a bare token or an OAuth envelope JSON.
pub async fn fetch_quota(
    client: &reqwest::Client,
    provider_id: &str,
    credential: &str,
    auth_state: Option<&Value>,
) -> Value {
    let Some(config) = provider_config(provider_id) else {
        return quota_failure(
            provider_id,
            format!("Unsupported buddy provider {provider_id}"),
        );
    };
    let source = config.id;
    let display = config.display;
    let (url, default_plan) = match config.kind {
        BuddyKind::CodeBuddyIntl => (CODEBUDDY_INTL_USAGE_URL, "CodeBuddy"),
        BuddyKind::CodeBuddyCn => (CODEBUDDY_CN_USAGE_URL, "CodeBuddy"),
        BuddyKind::WorkBuddy => (WORKBUDDY_USAGE_URL, "WorkBuddy"),
    };
    let Some(bearer) = resolve_bearer_token(credential) else {
        return quota_failure(source, format!("{display} credential not available."));
    };
    let enterprise = enterprise_id(auth_state);
    let mut headers = match config.kind {
        BuddyKind::CodeBuddyIntl => codebuddy_billing_headers("IDE", enterprise.as_deref()),
        BuddyKind::CodeBuddyCn => codebuddy_billing_headers("CLI", enterprise.as_deref()),
        BuddyKind::WorkBuddy => workbuddy_billing_headers(enterprise.as_deref()),
    };
    let uid = if config.kind == BuddyKind::WorkBuddy {
        buddy_account_uid(&bearer)
    } else {
        None
    };
    if let Some(uid) = uid.filter(|uid| !uid.is_empty()) {
        headers.push(("X-User-Id", uid));
    }
    headers.push(("Authorization", format!("Bearer {bearer}")));
    headers.push(("Content-Type", "application/json".to_owned()));
    headers.push(("Accept", "application/json".to_owned()));

    let now = Utc::now();
    let end = now + chrono::Duration::days(365 * 101);
    let body = json!({
        "PageNumber": 1,
        "PageSize": 100,
        "ProductCode": "p_tcaca",
        "Status": [0, 3],
        "PackageEndTimeRangeBegin": billing_stamp(now),
        "PackageEndTimeRangeEnd": billing_stamp(end),
    });
    let response = match client
        .post(url)
        .headers(header_map_from_pairs(headers))
        .json(&body)
        .timeout(BILLING_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return quota_failure(source, sanitize_error(&error.to_string())),
    };

    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return quota_failure(source, format!("{display} credential invalid or expired."));
    }
    if !status.is_success() {
        return quota_failure(
            source,
            format!("{display} quota API error ({}).", status.as_u16()),
        );
    }
    let text_body = match response.text().await {
        Ok(text) => text,
        Err(error) => return quota_failure(source, sanitize_error(&error.to_string())),
    };
    let parsed: Value = if text_body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_str(&text_body) {
            Ok(value) => value,
            Err(_) => {
                return quota_failure(
                    source,
                    format!("{display} quota response returned invalid JSON"),
                );
            }
        }
    };
    if let Some(code) = parsed.get("code").and_then(js_number) {
        if code != 0.0 {
            let message = as_text(parsed.get("msg")).unwrap_or_else(|| "unknown".to_owned());
            return quota_failure(source, format!("{display} quota error: {message}"));
        }
    }
    let accounts = extract_billing_accounts(&parsed);
    if accounts.is_empty() {
        return quota_failure(
            source,
            format!("{display} connected. No credit package found."),
        );
    }
    let (plan, windows) = build_billing_windows(&accounts, default_plan);
    json!({
        "source": source,
        "plan": plan,
        "windows": windows,
        "error": Value::Null,
    })
}

// ---------------------------------------------------------------------------
// Daily check-in and activity report (buddy-checkin.ts)
// ---------------------------------------------------------------------------

fn version_segment(provider_id: &str) -> &'static str {
    if provider_config(provider_id)
        .map(|config| config.kind == BuddyKind::WorkBuddy)
        .unwrap_or(false)
    {
        "/v2"
    } else {
        ""
    }
}

fn checkin_headers(provider_id: &str) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("X-Product", "SaaS".to_owned()),
        ("X-Requested-With", "XMLHttpRequest".to_owned()),
        ("X-CodeBuddy-Request", "1".to_owned()),
        ("Content-Type", "application/json".to_owned()),
        ("Accept", "application/json".to_owned()),
    ];
    let canonical = provider_config(provider_id).map(|config| config.id);
    match canonical {
        Some(CODEBUDDY_PROVIDER_ID) => {
            headers.push(("User-Agent", build_codebuddy_user_agent("IDE")));
            headers.push(("X-IDE-Type", "IDE".to_owned()));
            headers.push(("X-IDE-Name", "IDE".to_owned()));
            headers.push(("X-Domain", codebuddy_domain("IDE").to_owned()));
        }
        Some(CODEBUDDY_CN_PROVIDER_ID) => {
            headers.push(("User-Agent", build_codebuddy_user_agent("CLI")));
            headers.push(("X-IDE-Type", "CLI".to_owned()));
            headers.push(("X-IDE-Name", "CLI".to_owned()));
            headers.push(("X-Domain", codebuddy_domain("CLI").to_owned()));
        }
        _ => {
            headers.push(("User-Agent", build_workbuddy_user_agent()));
            headers.push(("X-Domain", "www.workbuddy.ai".to_owned()));
            headers.push(("Accept-Language", "en-US".to_owned()));
        }
    }
    headers
}

fn checkin_url(provider_id: &str, path: &str) -> String {
    let base = provider_config(provider_id)
        .map(|config| config.base_url)
        .unwrap_or(WORKBUDDY_BASE_URL);
    format!(
        "{}{}{}",
        base.trim_end_matches('/'),
        version_segment(provider_id),
        path
    )
}

fn envelope_code(payload: &Value) -> Option<f64> {
    let object = payload.as_object()?;
    as_number(object.get("code"))
}

fn envelope_data(payload: &Value) -> Option<Map<String, Value>> {
    let data = payload.get("data").and_then(json_object)?;
    if data.contains_key("today_checked_in")
        || data.contains_key("active")
        || data.contains_key("streak_days")
    {
        return Some(data.clone());
    }
    data.get("Response")
        .and_then(json_object)
        .and_then(|response| response.get("Data"))
        .and_then(json_object)
        .cloned()
}

fn as_text_field(payload: &Value) -> Option<String> {
    let object = payload.as_object()?;
    let direct = object.get("msg").or_else(|| object.get("message"));
    direct
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn already_claimed_message(payload: &Value, raw_body: &str) -> Option<String> {
    let message = as_text_field(payload).unwrap_or_else(|| raw_body.trim().to_owned());
    if message.is_empty() {
        return None;
    }
    if message.contains("已签到") {
        return Some(message);
    }
    let lower = message.to_lowercase();
    if lower.contains("already") && lower.contains("check") {
        return Some(message);
    }
    None
}

fn checkin_failure(
    provider_id: &str,
    account_id: &str,
    state: &str,
    message: impl Into<String>,
) -> Value {
    json!({
        "providerId": provider_id,
        "accountId": account_id,
        "state": state,
        "credit": Value::Null,
        "streakDays": Value::Null,
        "error": message.into(),
    })
}

fn checkin_status_value(
    provider_id: &str,
    account_id: &str,
    state: &str,
    credit: Option<f64>,
    streak_days: Option<f64>,
) -> Value {
    json!({
        "providerId": provider_id,
        "accountId": account_id,
        "state": state,
        "credit": credit,
        "streakDays": streak_days,
        "error": Value::Null,
    })
}

/// Performs one account's daily check-in: status probe first, claim only when
/// the account has not claimed today (or `force_claim` is set).
pub async fn fetch_daily_checkin(
    client: &reqwest::Client,
    provider_id: &str,
    account_id: &str,
    credential: &str,
    force_claim: bool,
) -> Value {
    let Some(config) = provider_config(provider_id) else {
        return checkin_failure(
            provider_id,
            account_id,
            "error",
            format!("Unsupported buddy provider {provider_id}"),
        );
    };
    let provider_id = config.id;
    if credential.trim().is_empty() {
        return checkin_failure(
            provider_id,
            account_id,
            "error",
            "Account has no stored credential.",
        );
    }
    let mut headers = checkin_headers(provider_id);
    headers.push(("Authorization", format!("Bearer {}", credential.trim())));
    let headers = header_map_from_pairs(headers);

    let status_url = checkin_url(provider_id, CHECKIN_STATUS_PATH);
    let status = match client
        .post(&status_url)
        .headers(headers.clone())
        .body("{}")
        .timeout(CHECKIN_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return checkin_failure(provider_id, account_id, "error", error.to_string()),
    };
    let status_code = status.status();
    if status_code == reqwest::StatusCode::UNAUTHORIZED
        || status_code == reqwest::StatusCode::FORBIDDEN
    {
        return checkin_failure(
            provider_id,
            account_id,
            "error",
            "Credential invalid or expired.",
        );
    }
    if !status_code.is_success() {
        return checkin_failure(
            provider_id,
            account_id,
            "error",
            format!("Check-in status API error ({}).", status_code.as_u16()),
        );
    }
    let status_payload: Value = status
        .text()
        .await
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    if let Some(code) = envelope_code(&status_payload) {
        if code != 0.0 {
            return checkin_failure(
                provider_id,
                account_id,
                "error",
                format!("Check-in status error (code {}).", code as i64),
            );
        }
    }
    let Some(data) = envelope_data(&status_payload) else {
        return checkin_failure(
            provider_id,
            account_id,
            "unavailable",
            "Check-in activity unavailable.",
        );
    };
    if data.get("active").and_then(Value::as_bool) == Some(false) {
        return checkin_failure(
            provider_id,
            account_id,
            "unavailable",
            "No check-in activity running.",
        );
    }
    let streak = data
        .get("streak_days")
        .and_then(|value| as_number(Some(value)));
    if !force_claim && data.get("today_checked_in").and_then(Value::as_bool) == Some(true) {
        return checkin_status_value(provider_id, account_id, "already_claimed", None, streak);
    }

    let claim_url = checkin_url(provider_id, CHECKIN_CLAIM_PATH);
    let mut attempt = 0usize;
    let (claim_payload, claim_raw): (Value, String) = loop {
        let response = match client
            .post(&claim_url)
            .headers(headers.clone())
            .body("{}")
            .timeout(CHECKIN_TIMEOUT)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let retryable = !error.is_timeout();
                if retryable && attempt < CLAIM_RETRY_DELAYS_MS.len() {
                    tokio::time::sleep(Duration::from_millis(CLAIM_RETRY_DELAYS_MS[attempt])).await;
                    attempt += 1;
                    continue;
                }
                return checkin_failure(provider_id, account_id, "error", error.to_string());
            }
        };
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return checkin_failure(
                provider_id,
                account_id,
                "error",
                "Credential invalid or expired.",
            );
        }
        if status.as_u16() >= 500 && attempt < CLAIM_RETRY_DELAYS_MS.len() {
            tokio::time::sleep(Duration::from_millis(CLAIM_RETRY_DELAYS_MS[attempt])).await;
            attempt += 1;
            continue;
        }
        if !status.is_success() {
            return checkin_failure(
                provider_id,
                account_id,
                "error",
                format!("Daily check-in API error ({}).", status.as_u16()),
            );
        }
        let claim_raw = response.text().await.unwrap_or_default();
        if claim_raw.is_empty() {
            break (Value::Null, claim_raw);
        }
        match serde_json::from_str(&claim_raw) {
            Ok(value) => break (value, claim_raw),
            Err(_) => {
                return checkin_failure(
                    provider_id,
                    account_id,
                    "error",
                    "Daily check-in response returned invalid JSON.",
                );
            }
        }
    };

    if let Some(code) = envelope_code(&claim_payload) {
        if code != 0.0 {
            if code == ALREADY_CLAIMED_CODE
                || already_claimed_message(&claim_payload, &claim_raw).is_some()
            {
                return checkin_status_value(
                    provider_id,
                    account_id,
                    "already_claimed",
                    None,
                    streak,
                );
            }
            if code == NOT_ELIGIBLE_CODE {
                return checkin_status_value(provider_id, account_id, "not_eligible", None, streak);
            }
            if code == EVENT_ENDED_CODE {
                return checkin_status_value(provider_id, account_id, "event_ended", None, streak);
            }
            return checkin_failure(
                provider_id,
                account_id,
                "error",
                format!("Daily check-in error (code {}).", code as i64),
            );
        }
    }
    if envelope_code(&claim_payload) == Some(0.0)
        && already_claimed_message(&claim_payload, &claim_raw).is_some()
    {
        return checkin_status_value(provider_id, account_id, "already_claimed", None, streak);
    }
    let claim_data = envelope_data(&claim_payload);
    let credit = claim_data
        .as_ref()
        .and_then(|data| data.get("credit"))
        .and_then(|value| as_number(Some(value)))
        .or_else(|| {
            claim_data
                .as_ref()
                .and_then(|data| data.get("today_credit"))
                .and_then(|value| as_number(Some(value)))
        });
    let claim_streak = claim_data
        .as_ref()
        .and_then(|data| data.get("streak_days"))
        .and_then(|value| as_number(Some(value)));
    checkin_status_value(
        provider_id,
        account_id,
        "claimed",
        credit,
        claim_streak.or(streak),
    )
}

/// Builds one growth-activity report event (`chat_request_send`).
pub fn build_activity_report_event(
    conversation_id: &str,
    user_id: &str,
    request_id: Option<&str>,
    now: i64,
) -> Value {
    let request_id = request_id.unwrap_or(conversation_id);
    json!({
        "eventCode": "chat_request_send",
        "timestamp": now,
        "reportDelay": 0,
        "mode": "unknown",
        "conversationId": conversation_id,
        "requestId": request_id,
        "inputLength": 0,
        "requestModelId": "default-model",
        "requestModelName": "Auto",
        "isPlan": false,
        "isAutoExecuteTerminal": false,
        "isAutoModify": false,
        "codebaseEnable": false,
        "maxToken": 0,
        "maxSteps": 0,
        "temperature": 0,
        "maxRetries": 0,
        "mentionContexts": [],
        "knowledgeId": [],
        "knowledgeName": [],
        "codebaseId": "",
        "mentionContextCount": 0,
        "command": "",
        "recommendId": "",
        "skillId": "",
        "skillCount": 0,
        "totalCount": 0,
        "presentAt": now,
        "rootRequestId": conversation_id,
        "parentConversationId": conversation_id,
        "agentName": "default",
        "agentType": "main",
        "product": "SaaS",
        "userId": user_id,
    })
}

fn activity_failure(
    provider_id: &str,
    account_id: &str,
    state: &str,
    message: impl Into<String>,
) -> Value {
    json!({
        "providerId": provider_id,
        "accountId": account_id,
        "state": state,
        "error": message.into(),
    })
}

/// Sends one growth-activity report (`POST {base}/v2/report`).
pub async fn fetch_activity_report(
    client: &reqwest::Client,
    provider_id: &str,
    account_id: &str,
    credential: &str,
    user_id: &str,
    conversation_id: Option<&str>,
) -> Value {
    let Some(config) = provider_config(provider_id) else {
        return activity_failure(
            provider_id,
            account_id,
            "error",
            format!("Unsupported buddy provider {provider_id}"),
        );
    };
    let provider_id = config.id;
    if credential.trim().is_empty() {
        return activity_failure(
            provider_id,
            account_id,
            "error",
            "Account has no stored credential.",
        );
    }
    if user_id.trim().is_empty() {
        return activity_failure(
            provider_id,
            account_id,
            "error",
            "Account uid is unavailable; cannot report activity.",
        );
    }
    let mut headers = checkin_headers(provider_id);
    headers.push(("Authorization", format!("Bearer {}", credential.trim())));
    headers.push(("X-User-Id", user_id.to_owned()));
    let url = checkin_url(provider_id, ACTIVITY_REPORT_PATH);
    let generated = format!("activity-{}", Utc::now().timestamp_millis());
    let conversation_id = conversation_id.unwrap_or(&generated);
    let event = build_activity_report_event(
        conversation_id,
        user_id,
        None,
        Utc::now().timestamp_millis(),
    );
    let response = match client
        .post(&url)
        .headers(header_map_from_pairs(headers))
        .json(&vec![event])
        .timeout(CHECKIN_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return activity_failure(provider_id, account_id, "error", error.to_string()),
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return activity_failure(
            provider_id,
            account_id,
            "error",
            "Credential invalid or expired.",
        );
    }
    if !status.is_success() {
        return activity_failure(
            provider_id,
            account_id,
            "error",
            format!("Activity report API error ({}).", status.as_u16()),
        );
    }
    let text = response.text().await.unwrap_or_default();
    let payload: Value = if text.is_empty() {
        Value::Null
    } else {
        match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => {
                return activity_failure(
                    provider_id,
                    account_id,
                    "error",
                    "Activity report response returned invalid JSON.",
                );
            }
        }
    };
    if let Some(code) = envelope_code(&payload) {
        if code != 0.0 {
            return activity_failure(
                provider_id,
                account_id,
                "error",
                format!("Activity report error (code {}).", code as i64),
            );
        }
    }
    json!({
        "providerId": provider_id,
        "accountId": account_id,
        "state": "reported",
        "error": Value::Null,
    })
}

/// Calendar-day key in UTC, matching the provider's day boundary.
pub fn checkin_day_key_for(now: DateTime<Utc>) -> String {
    now.format("%Y-%m-%d").to_string()
}

/// Calendar-day key for the current UTC day.
pub fn checkin_day_key() -> String {
    checkin_day_key_for(Utc::now())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request() -> CanonicalRequest {
        serde_json::from_value(json!({
            "model": "auto",
            "messages": [],
            "stream": false,
            "source_surface": "chat",
        }))
        .expect("canonical request")
    }

    #[test]
    fn complete_required_marks_every_property() {
        let schema = json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "options": {
                    "type": "object",
                    "properties": {"limit": {"type": "number"}}
                }
            }
        });
        let completed = complete_required_schema(&schema);
        assert_eq!(completed["required"], json!(["query", "options"]));
        assert_eq!(
            completed["properties"]["options"]["required"],
            json!(["limit"])
        );
    }

    #[test]
    fn tool_names_are_shortened_deduplicated_and_rewritten() {
        let mut payload = json!({
            "tools": [
                {"type": "function", "function": {"name": "weird name", "parameters": {"type": "object", "properties": {"a": {"type": "string"}}}}},
                {"type": "function", "function": {"name": "weird name", "parameters": {"type": "object"}}},
                {"type": "function", "function": {"name": "ok-name"}}
            ],
            "messages": [
                {"role": "assistant", "tool_calls": [
                    {"id": "1", "type": "function", "function": {"name": "weird name", "arguments": "{}"}}
                ]}
            ],
            "tool_choice": {"type": "function", "function": {"name": "weird name"}}
        });
        normalize_buddy_tool_names(&mut payload);
        assert_eq!(payload["tools"][0]["function"]["name"], "weirdname");
        assert_eq!(payload["tools"][1]["function"]["name"], "weirdname_2");
        assert_eq!(
            payload["tools"][0]["function"]["parameters"]["required"],
            json!(["a"])
        );
        assert_eq!(
            payload["messages"][0]["tool_calls"][0]["function"]["name"],
            "weirdname"
        );
        assert_eq!(payload["tool_choice"]["function"]["name"], "weirdname");
    }

    #[test]
    fn system_prompt_drops_caller_turns_and_coalesces_users() {
        let mut messages = vec![
            json!({"role": "system", "content": "caller system"}),
            json!({"role": "user", "content": "hello"}),
            json!({"role": "user", "content": "again"}),
            json!({"role": "assistant", "content": ""}),
        ];
        apply_buddy_system_prompt(&mut messages, "fixed prompt");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "fixed prompt");
        assert_eq!(
            messages[1]["content"],
            json!([
                {"type": "text", "text": "hello"},
                {"type": "text", "text": "again"}
            ])
        );
    }

    #[test]
    fn common_payload_forces_stream_and_applies_deepseek_contract() {
        let mut payload = json!({
            "model": "deepseek-v4.1-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "max_completion_tokens": 123,
            "reasoning_effort": "low",
            "agent": "x",
            "agent_mode": true,
            "tool_choice": "none",
            "tools": [{"type": "function", "function": {"name": "x"}}]
        });
        buddy_pre_payload_common(&mut payload, &test_request());
        assert_eq!(payload["stream"], true);
        assert_eq!(payload["max_tokens"], 123);
        assert!(payload.get("max_completion_tokens").is_none());
        assert!(payload.get("agent").is_none());
        assert!(payload.get("agent_mode").is_none());
        assert!(payload.get("tools").is_none());
        assert!(payload.get("tool_choice").is_none());
        assert_eq!(payload["thinking"], json!({"type": "enabled"}));
        assert_eq!(payload["reasoning_effort"], "low");
        assert_eq!(payload["reasoning_summary"], "auto");

        let mut implicit = json!({
            "model": "deepseek-v4.1-flash",
            "messages": [{"role": "user", "content": "hi"}]
        });
        buddy_pre_payload_common(&mut implicit, &test_request());
        assert_eq!(implicit["thinking"], json!({"type": "enabled"}));
        assert_eq!(implicit["reasoning_effort"], "high");
    }

    #[test]
    fn sol_defaults_to_high_reasoning_only_without_effort() {
        let mut payload = json!({"model": "gpt-5.6-sol", "messages": []});
        buddy_pre_payload_common(&mut payload, &test_request());
        assert_eq!(payload["reasoning_effort"], "high");
        let mut explicit =
            json!({"model": "gpt-5.6-sol", "messages": [], "reasoning_effort": "low"});
        buddy_pre_payload_common(&mut explicit, &test_request());
        assert_eq!(explicit["reasoning_effort"], "low");
    }

    #[test]
    fn consecutive_assistant_turns_merge_content_calls_and_reasoning() {
        let mut messages = vec![
            json!({"role": "assistant", "content": "one", "reasoning_content": "r1"}),
            json!({
                "role": "assistant",
                "content": "two",
                "reasoning_content": "r2",
                "tool_calls": [{"id": "1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]
            }),
            json!({"role": "user", "content": "next"}),
        ];
        coalesce_consecutive_assistant_messages(&mut messages);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["content"], "one\ntwo");
        assert_eq!(messages[0]["reasoning_content"], "r1\nr2");
        assert_eq!(messages[0]["tool_calls"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn orphan_tool_results_are_removed_and_interleaved_results_repacked() {
        let mut messages = vec![
            json!({"role": "assistant", "tool_calls": [
                {"id": "1", "type": "function", "function": {"name": "a", "arguments": "{}"}}
            ]}),
            json!({"role": "tool", "tool_call_id": "1", "content": "result"}),
            json!({"role": "user", "content": "noise"}),
            json!({"role": "tool", "tool_call_id": "orphan", "content": "bad"}),
        ];
        repack_buddy_tool_result_blocks(&mut messages);
        cleanup_buddy_orphan_tool_pairs(&mut messages);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[1]["role"], "tool");
        assert_eq!(messages[1]["tool_call_id"], "1");
        assert_eq!(messages[2]["role"], "user");
    }

    #[test]
    fn cn_agent_prompts_are_detected() {
        assert!(is_agent_prompt_text(
            "You are Claude Code, Anthropic's official CLI for coding"
        ));
        assert!(is_agent_prompt_text(
            "OhMyOpenCode orchestration capabilities"
        ));
        assert!(!is_agent_prompt_text("You are a helpful assistant"));
    }

    #[test]
    fn cn_neutralization_replaces_agent_prompts_only() {
        let mut messages = vec![
            json!({"role": "system", "content": "You are Claude Code, Anthropic's official CLI"}),
            json!({"role": "system", "content": "You are a helpful assistant"}),
        ];
        neutralize_cn_messages(&mut messages);
        assert_eq!(messages[0]["content"], CODEBUDDY_CN_NEUTRAL_PROMPT);
        assert_eq!(messages[1]["content"], "You are a helpful assistant");
    }

    #[test]
    fn jwt_uid_and_label_are_decoded() {
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1aWQtNDIiLCJlbWFpbCI6ImRldkBleGFtcGxlLmNvbSIsImdpdmVuX25hbWUiOiJBZGEiLCJmYW1pbHlfbmFtZSI6IkxvdmVsYWNlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRhIn0.sig";
        assert_eq!(buddy_account_uid(token).as_deref(), Some("uid-42"));
        assert_eq!(
            buddy_account_label(token).as_deref(),
            Some("Ada Lovelace <dev@example.com>")
        );
        assert!(buddy_account_uid("opaque-api-key").is_none());
    }

    #[test]
    fn account_stable_device_ids_are_fixed_vectors() {
        assert_eq!(
            derive_account_stable_id("user-123", "machine"),
            "eff2ab79d361e871a4474cdec3e7e0344a8e"
        );
        assert_eq!(
            derive_account_stable_id("user-123", "session"),
            "861a2172d3f6077c70ee8eb339e03b1a96b1"
        );
    }

    #[test]
    fn strict_and_coercing_codes_differ_on_malformed_payloads() {
        assert_eq!(strict_response_code(&json!({"code": null})), None);
        assert_eq!(coercing_response_code(&json!({"code": null})), Some(0.0));
        assert_eq!(
            strict_response_code(&json!({"code": "11217"})),
            Some(11_217.0)
        );
        assert_eq!(strict_response_code(&json!({"code": true})), None);
        assert_eq!(coercing_response_code(&json!({"code": true})), Some(1.0));
    }

    #[test]
    fn oauth_variants_use_exact_endpoints_and_platforms() {
        let intl = oauth_variant("cb").expect("cb");
        assert_eq!(intl.platform, "ide");
        assert_eq!(intl.device_start_url, CODEBUDDY_INTL_DEVICE_START_URL);
        assert!(!intl.coercing_code);
        let cn = oauth_variant("cbcn").expect("cbcn");
        assert_eq!(cn.platform, "CLI");
        assert_eq!(cn.domain, "copilot.tencent.com");
        let work = oauth_variant("workbuddy").expect("workbuddy");
        assert!(work.coercing_code);
        assert_eq!(work.device_poll_url, WORKBUDDY_DEVICE_POLL_URL);
    }

    #[test]
    fn billing_reset_times_accept_seconds_millis_and_iso() {
        assert_eq!(
            parse_billing_reset_time(Some(&json!(1_735_689_600u64))).as_deref(),
            Some("2025-01-01T00:00:00.000Z")
        );
        assert_eq!(
            parse_billing_reset_time(Some(&json!(1_735_689_600_000u64))).as_deref(),
            Some("2025-01-01T00:00:00.000Z")
        );
        assert_eq!(
            parse_billing_reset_time(Some(&json!("2025-01-01T00:00:00Z"))).as_deref(),
            Some("2025-01-01T00:00:00.000Z")
        );
        assert_eq!(parse_billing_reset_time(Some(&json!(""))), None);
    }

    #[test]
    fn billing_windows_split_refill_and_bonus() {
        let accounts = vec![
            json!({
                "PackageName": "Pro",
                "CycleStartTime": "2026-01-01T00:00:00Z",
                "CycleEndTime": "2026-01-02T00:00:00Z",
                "DeductionEndTime": "2026-01-10T00:00:00Z",
                "CycleCapacityUsedPrecise": "50",
                "CycleCapacitySizePrecise": "100"
            })
            .as_object()
            .unwrap()
            .clone(),
            json!({
                "CycleEndTime": "2026-01-05T00:00:00Z",
                "DeductionEndTime": "2026-01-05T00:00:00Z",
                "CapacityUsed": 10,
                "CapacitySize": 40
            })
            .as_object()
            .unwrap()
            .clone(),
        ];
        let (plan, windows) = build_billing_windows(&accounts, "CodeBuddy");
        assert_eq!(plan, "Pro");
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0]["kind"], "quota:daily");
        assert_eq!(windows[0]["label"], "Daily");
        assert_eq!(windows[0]["usedPercent"], 50.0);
        assert_eq!(windows[0]["recurring"], true);
        assert_eq!(windows[1]["kind"], "bonus:1");
        assert_eq!(windows[1]["label"], "Bonus Pack 1");
        assert_eq!(windows[1]["usedPercent"], 25.0);
        assert_eq!(windows[1]["recurring"], false);
    }

    #[test]
    fn credential_envelope_resolves_bearer() {
        assert_eq!(
            resolve_bearer_token(r#"{"accessToken":"abc"}"#).as_deref(),
            Some("abc")
        );
        assert_eq!(
            resolve_bearer_token(r#"{"api_key":"key"}"#).as_deref(),
            Some("key")
        );
        assert_eq!(resolve_bearer_token(" raw ").as_deref(), Some("raw"));
        assert_eq!(resolve_bearer_token("   "), None);
    }

    #[test]
    fn activity_event_matches_the_desktop_report_shape() {
        let event = build_activity_report_event("activity-1", "uid-42", None, 1_700_000_000_000);
        assert_eq!(event["eventCode"], "chat_request_send");
        assert_eq!(event["conversationId"], "activity-1");
        assert_eq!(event["requestId"], "activity-1");
        assert_eq!(event["userId"], "uid-42");
        assert_eq!(event["rootRequestId"], "activity-1");
        assert_eq!(event["presentAt"], 1_700_000_000_000i64);
        assert_eq!(event["mentionContexts"], json!([]));
    }

    #[test]
    fn checkin_day_key_uses_utc_calendar_day() {
        let now = DateTime::parse_from_rfc3339("2026-11-12T23:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(checkin_day_key_for(now), "2026-11-12");
    }

    #[test]
    fn directory_models_filter_disabled_and_cli_unlisted_rows() {
        let payload = json!({
            "code": 0,
            "data": {
                "models": [
                    {"id": "kept", "name": "Kept", "maxInputTokens": 1000, "maxOutputTokens": 500, "supportsImages": true},
                    {"id": "disabled", "disabled": true},
                    {"id": "not-cli"},
                    {"id": "kept"}
                ],
                "agents": [{"name": "cli", "models": ["kept", "disabled"]}]
            }
        });
        let rows =
            parse_buddy_directory_models(&payload, "workbuddy", Some("/v2/chat/completions"))
                .expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["modelId"], "kept");
        assert_eq!(rows[0]["name"], "Kept");
        assert_eq!(rows[0]["contextLimit"], 1000);
        assert_eq!(rows[0]["toolCall"], false);
        assert_eq!(rows[0]["endpointPath"], "/v2/chat/completions");
        assert!(
            parse_buddy_directory_models(&json!({"code": 1, "data": {}}), "cb", None).is_none()
        );
    }

    #[test]
    fn shared_and_cn_catalogs_have_their_exact_rows() {
        let shared = buddy_shared_models("cb", None);
        assert_eq!(shared.len(), BUDDY_SHARED_RAW.len());
        assert_eq!(shared[0]["modelId"], "auto");
        assert_eq!(shared[0]["contextLimit"], 168_000);
        assert!(shared[0]["outputLimit"].is_null());
        let kimi = shared
            .iter()
            .find(|row| row["modelId"] == "kimi-k2.6")
            .expect("kimi-k2.6");
        assert_eq!(kimi["outputLimit"], 256_000);
        let cn = codebuddy_cn_models();
        assert_eq!(cn.len(), 12);
        assert_eq!(cn[8]["modelId"], "kimi-k3-1");
        assert_eq!(cn[8]["providerId"], "cbcn");
    }
}
