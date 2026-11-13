//! Shared wire-protocol primitives used by every provider codec.
//!
//! Port of `src/protocol/primitives.ts` (the generic half) and
//! `src/security/outbound-headers.ts` (the protected-header contract).

use std::collections::HashMap;
use std::sync::LazyLock;

use keyla_core::{
    CanonicalEvent, CanonicalStopReason, GatewayError, GatewayErrorCode, GenerationControls,
    TerminalState, UsageRecord, WireFamily,
};
use regex::Regex;
use serde_json::{Map, Value, json};

/// Deepest nesting the recursive rewriters descend into. A value past the
/// bound is forwarded unchanged rather than dropped.
pub const MAX_REWRITE_DEPTH: usize = 256;

/// Deepest nesting accepted for a JSON document carried by a request.
pub const MAX_JSON_DEPTH: usize = 64;

pub fn is_record(value: &Value) -> bool {
    value.is_object()
}

pub fn read_string<'a>(value: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

pub fn read_number(value: &Map<String, Value>, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

pub fn read_boolean(value: &Map<String, Value>, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

/// Reads an SSE frame's `output_index` as an integer slot; fractional values
/// are truncated and non-finite values discarded.
pub fn read_output_index(record: &Map<String, Value>) -> Option<i64> {
    record
        .get("output_index")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .map(|value| value.trunc() as i64)
}

/// Shared 32-bit string hash (`hash * 31` accumulation, unsigned) over UTF-16
/// code units, matching the JavaScript implementation.
pub fn hash32(input: &str) -> u32 {
    let mut hash: u32 = 0;
    for unit in input.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(u32::from(unit));
    }
    hash
}

fn hash_id(input: &str) -> String {
    format!("{:08x}", hash32(input))
}

fn is_valid_anthropic_tool_call_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn fallback_anthropic_tool_call_id(original: &str) -> String {
    format!("toolu_{}", hash_id(original))
}

fn with_duplicate_suffix(canonical: &str, index: usize) -> String {
    let suffix = format!("_dup{index}");
    let keep = 64usize.saturating_sub(suffix.len());
    let mut out: String = canonical.chars().take(keep).collect();
    out.push_str(&suffix);
    out
}

/// Normalizes a tool-call ID for Anthropic's strict 64-char
/// `^[a-zA-Z0-9_-]+$` requirement, with a per-request uniqueness ledger.
pub fn normalize_anthropic_tool_call_id(raw: &str, seen: &mut HashMap<String, usize>) -> String {
    let base = raw.split('|').next().unwrap_or(raw);
    let mut canonical: String = base
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if canonical.is_empty() {
        canonical = fallback_anthropic_tool_call_id(raw);
    }
    if canonical.chars().count() > 64 {
        let hash = hash_id(raw);
        let prefix: String = canonical.chars().take(55).collect();
        canonical = format!("{prefix}_{}", &hash[..8.min(hash.len())])
            .chars()
            .take(64)
            .collect();
    }
    if !is_valid_anthropic_tool_call_id(&canonical) {
        canonical = fallback_anthropic_tool_call_id(raw);
    }
    let mut index = *seen.get(&canonical).unwrap_or(&0);
    let mut normalized = if index == 0 {
        canonical.clone()
    } else {
        with_duplicate_suffix(&canonical, index)
    };
    while seen.contains_key(&normalized) {
        index += 1;
        normalized = with_duplicate_suffix(&canonical, index);
    }
    seen.insert(canonical.clone(), index + 1);
    if normalized != canonical {
        *seen.entry(normalized.clone()).or_insert(0) += 1;
    }
    normalized
}

// ─── Schema rewriting ───────────────────────────────────────────────────────

fn complete_required_walk(value: &Value, depth: usize) -> Value {
    if depth >= MAX_REWRITE_DEPTH {
        return value.clone();
    }
    match value {
        Value::Array(entries) => Value::Array(
            entries
                .iter()
                .map(|entry| complete_required_walk(entry, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map {
                if key == "properties" {
                    if let Value::Object(properties) = child {
                        let mut rewritten = Map::new();
                        for (name, schema) in properties {
                            rewritten
                                .insert(name.clone(), complete_required_walk(schema, depth + 1));
                        }
                        out.insert("properties".into(), Value::Object(rewritten));
                        continue;
                    }
                }
                out.insert(key.clone(), complete_required_walk(child, depth + 1));
            }
            if let Some(Value::Object(properties)) = out.get("properties") {
                out.insert(
                    "required".into(),
                    Value::Array(
                        properties
                            .keys()
                            .map(|name| Value::String(name.clone()))
                            .collect(),
                    ),
                );
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Marks every declared property of a tool schema as `required`.
pub fn complete_required_schema(value: &Value) -> Value {
    complete_required_walk(value, 0)
}

static SUPPORTED_SCHEMA_KEYS: LazyLock<std::collections::BTreeSet<&'static str>> =
    LazyLock::new(|| {
        [
            "$ref",
            "$defs",
            "definitions",
            "type",
            "enum",
            "const",
            "description",
            "title",
            "default",
            "properties",
            "required",
            "additionalProperties",
            "items",
            "anyOf",
            "oneOf",
            "allOf",
            "minItems",
            "maxItems",
            "minLength",
            "maxLength",
            "pattern",
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "minProperties",
            "maxProperties",
        ]
        .into_iter()
        .collect()
    });

fn sanitize_schema_walk(value: &Value, depth: usize) -> Value {
    if depth >= MAX_REWRITE_DEPTH {
        return value.clone();
    }
    match value {
        Value::Array(entries) => Value::Array(
            entries
                .iter()
                .map(|entry| sanitize_schema_walk(entry, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map {
                if key == "properties" {
                    if let Value::Object(properties) = child {
                        let mut rewritten = Map::new();
                        for (name, schema) in properties {
                            rewritten.insert(name.clone(), sanitize_schema_walk(schema, depth + 1));
                        }
                        out.insert("properties".into(), Value::Object(rewritten));
                        continue;
                    }
                }
                if !SUPPORTED_SCHEMA_KEYS.contains(key.as_str()) {
                    continue;
                }
                out.insert(key.clone(), sanitize_schema_walk(child, depth + 1));
            }
            if let Some(Value::Object(properties)) = out.get("properties") {
                let names: Vec<String> = properties.keys().cloned().collect();
                out.entry("type").or_insert_with(|| json!("object"));
                out.insert(
                    "required".into(),
                    Value::Array(names.into_iter().map(Value::String).collect()),
                );
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Drops wire-unsupported JSON-Schema keywords and forces declared properties
/// into `required`, as strict Anthropic-compatible upstreams expect.
pub fn sanitize_schema_for_anthropic(value: &Value) -> Value {
    sanitize_schema_walk(value, 0)
}

// ─── JSON helpers ───────────────────────────────────────────────────────────

/// Rejects a value nested deeper than [`MAX_JSON_DEPTH`], failing before it
/// recurses past the bound.
pub fn assert_bounded_json_depth(value: &Value) -> Result<(), GatewayError> {
    assert_bounded_depth_walk(value, 0)
}

fn assert_bounded_depth_walk(value: &Value, depth: usize) -> Result<(), GatewayError> {
    if depth > MAX_JSON_DEPTH {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            "request body nesting exceeds the allowed depth",
            Map::new(),
        ));
    }
    match value {
        Value::Array(entries) => {
            for entry in entries {
                assert_bounded_depth_walk(entry, depth + 1)?;
            }
        }
        Value::Object(map) => {
            for entry in map.values() {
                assert_bounded_depth_walk(entry, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Coerces a tool-call argument string into a JSON value. An empty string is a
/// zero-argument call (`{}`); unparsable text is preserved verbatim.
pub fn parse_arguments(value: &Value) -> Result<Value, GatewayError> {
    if let Value::String(text) = value {
        if text.trim().is_empty() {
            return Ok(Value::Object(Map::new()));
        }
        match serde_json::from_str::<Value>(text) {
            Ok(parsed) => {
                assert_bounded_json_depth(&parsed)?;
                Ok(parsed)
            }
            Err(_) => Ok(Value::String(text.clone())),
        }
    } else if value.is_null() {
        Ok(Value::Object(Map::new()))
    } else {
        Ok(value.clone())
    }
}

pub fn try_parse_json_object(text: &str) -> Option<Map<String, Value>> {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
}

static DATA_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^data:([^;,]+);base64,(.*)$").expect("data url pattern is valid")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataUrlPayload {
    pub media_type: String,
    pub data: String,
}

/// Splits a base64 `data:` URL into its media type and payload. Returns `None`
/// for a non-`data:` URL or a non-base64 payload.
pub fn split_data_url(url: &str) -> Option<DataUrlPayload> {
    let captures = DATA_URL.captures(url)?;
    let media_type = captures.get(1)?.as_str().to_owned();
    let data = captures.get(2)?.as_str().to_owned();
    if data.is_empty() {
        return None;
    }
    Some(DataUrlPayload { media_type, data })
}

/// An image part's provider-neutral source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedImageSource {
    pub url: Option<String>,
    pub file_id: Option<String>,
    pub detail: Option<String>,
}

/// Resolves an opaque canonical image payload into its URL/file-id/detail
/// triple, tolerating every origin shape this codebase produces.
pub fn resolve_image_source(payload: &Value) -> Option<ResolvedImageSource> {
    match payload {
        Value::String(url) => (!url.is_empty()).then(|| ResolvedImageSource {
            url: Some(url.clone()),
            ..Default::default()
        }),
        Value::Object(value) => {
            let top_detail = value
                .get("detail")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let top_file_id = value
                .get("file_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let nested = value.get("image_url");
            if nested.is_none() {
                if let Some(file_id) = top_file_id.clone() {
                    return Some(ResolvedImageSource {
                        file_id: Some(file_id),
                        detail: top_detail,
                        ..Default::default()
                    });
                }
            }
            if let Some(Value::String(url)) = nested {
                return Some(ResolvedImageSource {
                    url: Some(url.clone()),
                    detail: top_detail,
                    ..Default::default()
                });
            }
            if let Some(Value::Object(inner)) = nested {
                let url = inner.get("url").and_then(Value::as_str).map(str::to_owned);
                let file_id = inner
                    .get("file_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let detail = inner
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| top_detail.clone());
                if url.is_some() || file_id.is_some() {
                    return Some(ResolvedImageSource {
                        url,
                        file_id,
                        detail,
                    });
                }
            }
            let url = value.get("url").and_then(Value::as_str).map(str::to_owned);
            let file_id = value
                .get("file_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if url.is_some() || file_id.is_some() {
                return Some(ResolvedImageSource {
                    url,
                    file_id,
                    detail: top_detail,
                });
            }
            if let Some(Value::Object(source)) = value.get("source") {
                let kind = source
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                match kind {
                    "base64" => {
                        if let Some(data) = source.get("data").and_then(Value::as_str) {
                            let media_type = source
                                .get("media_type")
                                .and_then(Value::as_str)
                                .unwrap_or("image/png");
                            return Some(ResolvedImageSource {
                                url: Some(format!("data:{media_type};base64,{data}")),
                                detail: top_detail,
                                ..Default::default()
                            });
                        }
                    }
                    "url" => {
                        if let Some(url) = source.get("url").and_then(Value::as_str) {
                            return Some(ResolvedImageSource {
                                url: Some(url.to_owned()),
                                detail: top_detail,
                                ..Default::default()
                            });
                        }
                    }
                    "file" => {
                        if let Some(file_id) = source.get("file_id").and_then(Value::as_str) {
                            return Some(ResolvedImageSource {
                                file_id: Some(file_id.to_owned()),
                                detail: top_detail,
                                ..Default::default()
                            });
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        _ => None,
    }
}

pub fn join_url(base: &str, path: &str) -> String {
    let normalized_base = base.strip_suffix('/').unwrap_or(base);
    let normalized_path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    format!("{normalized_base}{normalized_path}")
}

/// Builds a provider URL. `is_oauth` appends the `beta=true` query Claude Code
/// uses.
pub fn endpoint_url(base_url: Option<&str>, endpoint_path: &str, is_oauth: bool) -> String {
    let is_absolute = endpoint_path
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || endpoint_path
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"));
    if is_absolute {
        if is_oauth && !endpoint_path.contains("?beta=true") {
            let separator = if endpoint_path.contains('?') {
                "&"
            } else {
                "?"
            };
            return format!("{endpoint_path}{separator}beta=true");
        }
        return endpoint_path.to_owned();
    }
    let base = base_url
        .unwrap_or("https://api.anthropic.com")
        .trim_end_matches('/');
    let url = join_url(base, endpoint_path);
    if is_oauth {
        format!("{url}?beta=true")
    } else {
        url
    }
}

#[derive(Debug)]
pub struct TerminalInput {
    pub sequence_number: u64,
    pub state: TerminalState,
    pub stop_reason: Option<CanonicalStopReason>,
    pub provider_stop_reason: Option<String>,
    pub stop_details: Option<Map<String, Value>>,
    pub usage: Option<UsageRecord>,
    pub response_id: Option<String>,
    pub event_id: Option<String>,
}

/// Builds the canonical terminal event, omitting absent optionals.
pub fn canonical_terminal(input: TerminalInput) -> CanonicalEvent {
    CanonicalEvent::Terminal {
        sequence_number: input.sequence_number,
        state: input.state,
        stop_reason: input.stop_reason,
        provider_stop_reason: input.provider_stop_reason,
        stop_details: input.stop_details,
        usage: input.usage,
        event_id: input.event_id,
        response_id: input.response_id,
        timestamp: None,
    }
}

/// Fallback endpoint paths for builtin providers on versioned bases.
pub fn builtin_default_endpoint(family: WireFamily) -> &'static str {
    match family {
        WireFamily::Chat => "/chat/completions",
        WireFamily::Responses => "/v1/responses",
        WireFamily::Messages => "/v1/messages",
    }
}

/// Endpoint paths for bare-host roots (BYOK roots and generic API-key
/// providers), which carry their own `/v1` prefix.
pub fn bare_root_endpoint(family: WireFamily) -> Option<&'static str> {
    match family {
        WireFamily::Chat => Some("/v1/chat/completions"),
        WireFamily::Responses => Some("/v1/responses"),
        WireFamily::Messages => Some("/v1/messages"),
    }
}

/// Encodes a tool-call ID as a Responses-safe composite `callId__itemId`.
pub fn encode_codex_tool_call_id(call_id: &str, item_id: Option<&str>) -> String {
    let stable_item_id = item_id
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("fc_{}", hash_to_base36(call_id)));
    format!("{call_id}__{stable_item_id}")
}

/// Decodes current `__` composites and accepts legacy `|` values on replay.
pub fn decode_codex_tool_call_id(raw: &str) -> String {
    let separator = if raw.contains("__") { "__" } else { "|" };
    raw.find(separator)
        .map(|index| raw[..index].to_owned())
        .unwrap_or_else(|| raw.to_owned())
}

pub fn hash_to_base36(input: &str) -> String {
    base36(hash32(input))
}

fn base36(mut value: u32) -> String {
    if value == 0 {
        return "0".into();
    }
    let alphabet = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(alphabet[(value % 36) as usize]);
        value /= 36;
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

/// Maps canonical reasoning effort to the wire tier strings the ChatGPT
/// backend accepts; unknown values fall back to `"medium"`.
pub fn map_reasoning_effort_to_wire_tier(effort: Option<&str>) -> Option<&'static str> {
    let effort = effort?;
    Some(match effort {
        "none" => "none",
        "minimal" => "minimal",
        "low" => "low",
        "medium" => "medium",
        "high" => "high",
        "xhigh" => "xhigh",
        "max" => "max",
        _ => "medium",
    })
}

/// Resolves the requested output verbosity from a canonical request's
/// generation controls, with surface-specific spellings taking precedence.
pub fn resolve_output_verbosity(controls: Option<&GenerationControls>) -> Option<String> {
    let controls = controls?;
    for key in ["extension:responses.verbosity", "extension:verbosity"] {
        if let Some(Value::String(value)) = controls.extensions.get(key) {
            if !value.is_empty() {
                return Some(value.clone());
            }
        }
    }
    controls.verbosity.map(|verbosity| match verbosity {
        keyla_core::Verbosity::Low => "low".into(),
        keyla_core::Verbosity::Medium => "medium".into(),
        keyla_core::Verbosity::High => "high".into(),
    })
}

static HARMONY_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<\|(start|end|message|channel|constrain|return|call)\|>")
        .expect("harmony token pattern is valid")
});

/// Escapes reserved Harmony control tokens; idempotent.
pub fn escape_harmony_control_tokens(text: &str) -> String {
    HARMONY_TOKEN.replace_all(text, "<\\|$1\\|>").into_owned()
}

/// Recursively escapes every string leaf of a JSON-like value.
pub fn escape_harmony_control_tokens_deep(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(escape_harmony_control_tokens(text)),
        Value::Array(entries) => Value::Array(
            entries
                .iter()
                .map(escape_harmony_control_tokens_deep)
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, entry)| (key.clone(), escape_harmony_control_tokens_deep(entry)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// ASCII-safe JSON: escapes every non-ASCII UTF-16 code unit as `\uXXXX`.
pub fn to_ascii_json_string(value: &Value) -> String {
    let json = serde_json::to_string(value).unwrap_or_default();
    let mut out = String::with_capacity(json.len());
    for unit in json.encode_utf16() {
        if unit >= 0x7f {
            out.push_str(&format!("\\u{unit:04x}"));
        } else {
            out.push(char::from_u32(u32::from(unit)).unwrap_or('?'));
        }
    }
    out
}

// ─── Outbound header contract ───────────────────────────────────────────────

static PROTECTED_HEADERS: LazyLock<std::collections::BTreeSet<&'static str>> =
    LazyLock::new(|| {
        [
            "host",
            "content-type",
            "content-length",
            "authorization",
            "x-api-key",
            "cookie",
            "connection",
            "keep-alive",
            "proxy-connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "via",
            "forwarded",
            "x-real-ip",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-keyla-surface",
            "x-keyla-tenant",
            "x-cartethyia-surface",
            "x-cartethyia-tenant",
        ]
        .into_iter()
        .collect()
    });

static HEADER_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$").expect("header token pattern is valid")
});
static HEADER_CONTROL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\r\n\x00-\x1f\x7f]").expect("header control pattern is valid"));

pub fn is_protected_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PROTECTED_HEADERS.contains(lower.as_str()) || lower.starts_with("x-forwarded-")
}

/// Validates operator-configured outbound custom headers. Protected names,
/// non-RFC tokens, values over 4 KiB, and control characters are rejected.
pub fn filter_provider_custom_headers(
    input: Option<&Map<String, Value>>,
    extra_reserved: Option<&[&str]>,
) -> Result<BTreeMapString, GatewayError> {
    let Some(input) = input else {
        return Ok(BTreeMapString::new());
    };
    let extra: std::collections::BTreeSet<String> = extra_reserved
        .unwrap_or_default()
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let mut filtered = BTreeMapString::new();
    for (raw_name, raw_value) in input {
        let name = raw_name.to_ascii_lowercase();
        if !HEADER_TOKEN.is_match(&name) {
            return Err(header_error(
                format!("invalid custom header name: {raw_name}"),
                raw_name,
            ));
        }
        if is_protected_header(&name) || extra.contains(&name) {
            return Err(header_error(
                format!("custom header is protected: {raw_name}"),
                raw_name,
            ));
        }
        let Some(value) = raw_value.as_str() else {
            return Err(header_error(
                format!("custom header value must be a string: {raw_name}"),
                raw_name,
            ));
        };
        if value.len() > 4096 {
            return Err(header_error(
                format!("custom header value exceeds 4KiB: {raw_name}"),
                raw_name,
            ));
        }
        if HEADER_CONTROL.is_match(value) {
            return Err(header_error(
                format!("custom header value contains control characters: {raw_name}"),
                raw_name,
            ));
        }
        filtered.insert(name, value.to_owned());
    }
    Ok(filtered)
}

pub type BTreeMapString = std::collections::BTreeMap<String, String>;

fn header_error(message: String, header: &str) -> GatewayError {
    let mut details = Map::new();
    details.insert("header".into(), Value::String(header.to_owned()));
    GatewayError::new(GatewayErrorCode::InvalidRequest, 400, message, details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash32_matches_the_javascript_accumulation() {
        // Values computed with the TypeScript implementation.
        assert_eq!(hash32("abc"), 96_354);
        assert_eq!(hash32("toolu_01"), 3_312_351_139);
        assert_eq!(hash32("call_1"), 2_927_191_696);
        assert_eq!(hash32("héllo"), 103_094_734);
    }

    #[test]
    fn tool_call_id_normalization_handles_invalid_and_duplicates() {
        let mut seen = HashMap::new();
        assert_eq!(
            normalize_anthropic_tool_call_id("call!x", &mut seen),
            "call_x"
        );
        assert_eq!(
            normalize_anthropic_tool_call_id("call@x", &mut seen),
            "call_x_dup1"
        );
        let long = "a".repeat(80);
        let normalized = normalize_anthropic_tool_call_id(&long, &mut seen);
        assert!(normalized.len() <= 64);
        assert_eq!(
            normalize_anthropic_tool_call_id("call|item", &mut seen),
            "call"
        );
    }

    #[test]
    fn complete_required_schema_walks_properties() {
        let schema = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "nested": {"type": "object", "properties": {"x": {"type": "number"}}}
            }
        });
        let completed = complete_required_schema(&schema);
        assert_eq!(completed["required"], json!(["path", "nested"]));
        assert_eq!(completed["properties"]["nested"]["required"], json!(["x"]));
    }

    #[test]
    fn anthropic_schema_sanitization_drops_unknown_keys() {
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string", "unsupported": true}},
            "unsupportedRoot": 1
        });
        let sanitized = sanitize_schema_for_anthropic(&schema);
        assert!(sanitized.get("unsupportedRoot").is_none());
        assert!(sanitized["properties"]["path"].get("unsupported").is_none());
        assert_eq!(sanitized["required"], json!(["path"]));
    }

    #[test]
    fn data_urls_split_only_base64_payloads() {
        let split = split_data_url("data:application/pdf;base64,AAAA").unwrap();
        assert_eq!(split.media_type, "application/pdf");
        assert_eq!(split.data, "AAAA");
        assert!(split_data_url("data:text/plain,hello").is_none());
        assert!(split_data_url("https://example.test/x").is_none());
    }

    #[test]
    fn image_sources_cover_every_origin_shape() {
        assert_eq!(
            resolve_image_source(&json!("https://x/y.png"))
                .unwrap()
                .url
                .as_deref(),
            Some("https://x/y.png")
        );
        assert_eq!(
            resolve_image_source(
                &json!({"image_url": {"url": "https://x/y.png", "detail": "high"}})
            )
            .unwrap()
            .detail
            .as_deref(),
            Some("high")
        );
        assert_eq!(
            resolve_image_source(&json!({"file_id": "file_1"}))
                .unwrap()
                .file_id
                .as_deref(),
            Some("file_1")
        );
        assert_eq!(
            resolve_image_source(
                &json!({"source": {"type": "base64", "media_type": "image/png", "data": "AA"}})
            )
            .unwrap()
            .url
            .as_deref(),
            Some("data:image/png;base64,AA")
        );
    }

    #[test]
    fn tool_arguments_coerce_empty_and_preserve_unparseable() {
        assert_eq!(parse_arguments(&json!("")).unwrap(), json!({}));
        assert_eq!(parse_arguments(&json!("  ")).unwrap(), json!({}));
        assert_eq!(
            parse_arguments(&json!("{\"a\":1}")).unwrap(),
            json!({"a":1})
        );
        assert_eq!(
            parse_arguments(&json!("not json")).unwrap(),
            json!("not json")
        );
        assert_eq!(parse_arguments(&json!(null)).unwrap(), json!({}));
    }

    #[test]
    fn depth_guard_rejects_deep_nesting() {
        let mut value = json!(1);
        for _ in 0..70 {
            value = Value::Array(vec![value]);
        }
        assert!(assert_bounded_json_depth(&value).is_err());
        assert!(assert_bounded_json_depth(&json!({"a":[1,2]})).is_ok());
    }

    #[test]
    fn protected_custom_headers_are_rejected() {
        let mut headers = Map::new();
        headers.insert("authorization".into(), json!("Bearer x"));
        assert!(filter_provider_custom_headers(Some(&headers), None).is_err());

        let mut headers = Map::new();
        headers.insert("x-custom".into(), json!("ok"));
        assert_eq!(
            filter_provider_custom_headers(Some(&headers), None)
                .unwrap()
                .get("x-custom")
                .map(String::as_str),
            Some("ok")
        );
    }

    #[test]
    fn harmony_tokens_and_ascii_json_are_escaped() {
        assert_eq!(
            escape_harmony_control_tokens("a<|start|>b"),
            "a<\\|start\\|>b"
        );
        assert_eq!(
            to_ascii_json_string(&json!({"x": "é"})),
            "{\"x\":\"\\u00e9\"}"
        );
    }

    #[test]
    fn codex_ids_round_trip() {
        let encoded = encode_codex_tool_call_id("call_1", None);
        assert!(encoded.starts_with("call_1__fc_"));
        assert_eq!(decode_codex_tool_call_id(&encoded), "call_1");
        assert_eq!(decode_codex_tool_call_id("call_1|item"), "call_1");
    }
}
