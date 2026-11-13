//! Claude Messages wire → canonical events: stop-reason mapping, content-block
//! parsing, usage normalization, non-stream conversion, and the SSE stream
//! decoder. Pure data transformation — no network I/O.
//! Port of `src/protocol/response/messages.ts`.

use std::collections::HashMap;

use keyla_core::{
    CanonicalEvent, CanonicalStopReason, ContentPart, GatewayError, GatewayErrorCode,
    GatewayErrorOrigin, TerminalState, TokenCount, ToolResultContent, UsageRecord,
};
use serde_json::{Map, Value, json};

use crate::primitives::{TerminalInput, canonical_terminal};

fn map_claude_stop_reason(raw: &str) -> CanonicalStopReason {
    match raw {
        "end_turn" | "stop_sequence" | "pause_turn" => CanonicalStopReason::Stop,
        "max_tokens" | "model_context_window_exceeded" => CanonicalStopReason::Length,
        "tool_use" => CanonicalStopReason::ToolUse,
        "refusal" | "sensitive" => CanonicalStopReason::Error,
        _ => CanonicalStopReason::Stop,
    }
}

fn unprefix_claude_tool_name(name: &str, is_oauth: bool) -> String {
    if is_oauth {
        if let Some(stripped) = name.strip_prefix('_') {
            return stripped.to_owned();
        }
    }
    name.to_owned()
}

fn js_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn upstream_error(message: impl Into<String>) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::PlatformUnavailable,
        502,
        message,
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Upstream)
}

/// Parses one Anthropic content block into its canonical part.
pub fn parse_claude_content(value: &Value, is_oauth: bool) -> Result<ContentPart, GatewayError> {
    if let Some(text) = value.as_str() {
        return Ok(ContentPart::Text {
            text: text.to_owned(),
        });
    }
    let Some(block) = value.as_object() else {
        return Ok(ContentPart::Extension {
            name: "messages:unknown".into(),
            payload: value.clone(),
        });
    };
    let kind = block.get("type").and_then(Value::as_str);
    match kind {
        Some("text") => Ok(ContentPart::Text {
            text: block
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        }),
        Some("image") => Ok(ContentPart::Image {
            payload: value.clone(),
        }),
        Some("tool_use") => {
            let id = block.get("id").and_then(Value::as_str);
            let name = block.get("name").and_then(Value::as_str);
            let (Some(id), Some(name)) = (id, name) else {
                return Err(upstream_error(
                    "Claude response tool_use is missing id or name",
                ));
            };
            Ok(ContentPart::ToolCall {
                call_id: id.to_owned(),
                name: unprefix_claude_tool_name(name, is_oauth),
                arguments: block
                    .get("input")
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                index: block.get("index").and_then(finite_i64),
                item_id: None,
                call_kind: None,
            })
        }
        Some("tool_result") => {
            let Some(call_id) = block.get("tool_use_id").and_then(Value::as_str) else {
                return Err(upstream_error(
                    "Claude response tool_result is missing tool_use_id",
                ));
            };
            let content = match block.get("content") {
                Some(Value::String(text)) => ToolResultContent::Text(text.clone()),
                Some(Value::Array(entries)) => ToolResultContent::Parts(
                    entries
                        .iter()
                        .map(|entry| parse_claude_content(entry, is_oauth))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                Some(Value::Null) | None => ToolResultContent::Text(String::new()),
                Some(other) => ToolResultContent::Parts(vec![ContentPart::Text {
                    text: js_text(other),
                }]),
            };
            Ok(ContentPart::ToolResult {
                call_id: call_id.to_owned(),
                content,
                is_error: (block.get("is_error").and_then(Value::as_bool) == Some(true))
                    .then_some(true),
                call_kind: None,
                item_id: None,
            })
        }
        Some("thinking") => {
            let thinking = block
                .get("thinking")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Ok(ContentPart::Reasoning {
                payload: json!(thinking),
                opaque: None,
                summary: Some(thinking),
                summary_index: None,
                signature: block
                    .get("signature")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                encrypted_content: None,
            })
        }
        Some("redacted_thinking") => Ok(ContentPart::Reasoning {
            payload: value.clone(),
            opaque: Some(true),
            summary: None,
            summary_index: None,
            signature: None,
            encrypted_content: None,
        }),
        Some(kind @ ("server_tool_use" | "search_result" | "web_search_tool_result")) => {
            Ok(ContentPart::Extension {
                name: kind.to_owned(),
                payload: value.clone(),
            })
        }
        Some(other) => Ok(ContentPart::Extension {
            name: format!("messages:{other}"),
            payload: value.clone(),
        }),
        None => Ok(ContentPart::Extension {
            name: "messages:unknown".into(),
            payload: value.clone(),
        }),
    }
}

fn finite_i64(value: &Value) -> Option<i64> {
    value
        .as_f64()
        .filter(|number| number.is_finite())
        .map(|number| number as i64)
}

fn finite_number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite())
}

fn number_field(map: &Map<String, Value>, key: &str) -> Option<f64> {
    finite_number(map.get(key))
}

fn token_count(value: Option<f64>) -> TokenCount {
    match value {
        Some(value) => TokenCount::Number(value.max(0.0) as i64),
        None => TokenCount::Unavailable,
    }
}

fn details_number(map: &Map<String, Value>, key: &str, detail_key: &str) -> Option<f64> {
    map.get(key)
        .and_then(Value::as_object)
        .and_then(|details| finite_number(details.get(detail_key)))
}

/// Normalizes a provider usage payload into canonical accounting.
fn normalize_usage(input: &Map<String, Value>) -> UsageRecord {
    let mut input_tokens = number_field(input, "input_tokens")
        .or_else(|| number_field(input, "prompt_tokens"))
        .map_or(0, |value| value.max(0.0) as i64);
    let output_tokens = number_field(input, "output_tokens")
        .or_else(|| number_field(input, "completion_tokens"))
        .map_or(0, |value| value.max(0.0) as i64);

    let anthropic_cache_read = number_field(input, "cache_read_input_tokens");
    let mut cached_input_tokens = anthropic_cache_read.map(|value| value.max(0.0) as i64);

    if let Some(hit) = number_field(input, "prompt_cache_hit_tokens") {
        cached_input_tokens = Some(hit.max(0.0) as i64);
    }
    if cached_input_tokens.is_none() {
        if let Some(cached) = details_number(input, "input_tokens_details", "cached_tokens") {
            cached_input_tokens = Some(cached.max(0.0) as i64);
        }
    }
    if cached_input_tokens.is_none() {
        if let Some(cached) = details_number(input, "prompt_tokens_details", "cached_tokens") {
            cached_input_tokens = Some(cached.max(0.0) as i64);
        }
    }
    if cached_input_tokens.is_none() {
        if let Some(cached) = number_field(input, "cached_tokens") {
            cached_input_tokens = Some(cached.max(0.0) as i64);
        }
    }
    if cached_input_tokens.is_none() {
        if let Some(cached) = number_field(input, "cachedContentTokenCount") {
            cached_input_tokens = Some(cached.max(0.0) as i64);
        }
    }

    let mut cache_write_tokens =
        number_field(input, "cache_creation_input_tokens").map(|value| value.max(0.0) as i64);
    if cache_write_tokens.is_none() {
        if let Some(breakdown) = input.get("cache_creation").and_then(Value::as_object) {
            let ephemeral_5m = number_field(breakdown, "ephemeral_5m_input_tokens").unwrap_or(0.0);
            let ephemeral_1h = number_field(breakdown, "ephemeral_1h_input_tokens").unwrap_or(0.0);
            if ephemeral_5m > 0.0 || ephemeral_1h > 0.0 {
                cache_write_tokens = Some((ephemeral_5m + ephemeral_1h) as i64);
            }
        }
    }

    let has_anthropic_cache_shape = anthropic_cache_read.is_some();
    let mut uncached_input_tokens: Option<i64> = None;
    if let Some(cached) = cached_input_tokens {
        if has_anthropic_cache_shape {
            uncached_input_tokens = Some(input_tokens);
            input_tokens += cached + cache_write_tokens.unwrap_or(0);
        } else {
            uncached_input_tokens = Some((input_tokens - input_tokens.min(cached)).max(0));
            cached_input_tokens = Some(input_tokens.min(cached));
        }
    } else if has_anthropic_cache_shape {
        if let Some(writes) = cache_write_tokens {
            input_tokens += writes;
        }
    }

    let output_details = input
        .get("output_tokens_details")
        .and_then(Value::as_object)
        .or_else(|| {
            input
                .get("completion_tokens_details")
                .and_then(Value::as_object)
        });
    let mut reasoning_tokens = None;
    let mut details = keyla_core::UsageDetails::default();
    if let Some(output_details) = output_details {
        reasoning_tokens = number_field(output_details, "thinking_tokens")
            .or_else(|| number_field(output_details, "reasoning_tokens"))
            .map(|value| value.max(0.0) as i64);
        details.accepted_prediction_tokens =
            number_field(output_details, "accepted_prediction_tokens")
                .map(|value| TokenCount::Number(value.max(0.0) as i64));
        details.rejected_prediction_tokens =
            number_field(output_details, "rejected_prediction_tokens")
                .map(|value| TokenCount::Number(value.max(0.0) as i64));
    }

    let credit_used = number_field(input, "credit").filter(|value| *value >= 0.0);

    UsageRecord {
        input_tokens,
        cached_input_tokens: token_count(cached_input_tokens.map(|value| value as f64)),
        cache_write_tokens: token_count(cache_write_tokens.map(|value| value as f64)),
        uncached_input_tokens: token_count(uncached_input_tokens.map(|value| value as f64)),
        output_tokens,
        reasoning_tokens: token_count(reasoning_tokens.map(|value| value as f64)),
        estimated_cost: None,
        credit_used,
        total_tokens: None,
        details: (details.accepted_prediction_tokens.is_some()
            || details.rejected_prediction_tokens.is_some())
        .then_some(details),
    }
}

fn has_reported_usage(usage: &UsageRecord) -> bool {
    usage.input_tokens > 0
        || usage.output_tokens > 0
        || matches!(usage.cached_input_tokens, TokenCount::Number(value) if value > 0)
        || matches!(usage.cache_write_tokens, TokenCount::Number(value) if value > 0)
        || matches!(usage.reasoning_tokens, TokenCount::Number(value) if value > 0)
}

/// Normalizes a provider usage payload, or `None` when nothing was reported.
pub fn usage_from_provider(raw: &Value) -> Option<UsageRecord> {
    let map = raw.as_object()?;
    let usage = normalize_usage(map);
    has_reported_usage(&usage).then_some(usage)
}

fn merge_usage(raw: &mut Option<Map<String, Value>>, usage: &Map<String, Value>) {
    let merged = raw.get_or_insert_with(Map::new);
    for (key, value) in usage {
        merged.insert(key.clone(), value.clone());
    }
}

fn event_content(parts: &[ContentPart], sequence: u64) -> (Vec<CanonicalEvent>, u64) {
    let mut events = Vec::new();
    let mut next = sequence;
    for part in parts {
        match part {
            ContentPart::ToolCall {
                call_id,
                index,
                name,
                arguments,
                ..
            } => events.push(CanonicalEvent::ToolCallDelta {
                sequence_number: next,
                call_id: call_id.clone(),
                index: *index,
                name: Some(name.clone()),
                arguments_delta: Some(
                    serde_json::to_string(arguments).unwrap_or_else(|_| "{}".into()),
                ),
                event_id: None,
                response_id: None,
                item_id: None,
                output_index: None,
                timestamp: None,
            }),
            ContentPart::ToolResult {
                call_id, content, ..
            } => {
                let content = match content {
                    ToolResultContent::Text(text) => vec![ContentPart::Text { text: text.clone() }],
                    ToolResultContent::Parts(parts) => parts.clone(),
                };
                events.push(CanonicalEvent::ToolResult {
                    sequence_number: next,
                    call_id: call_id.clone(),
                    content,
                    event_id: None,
                    response_id: None,
                    item_id: None,
                    timestamp: None,
                });
            }
            other => events.push(CanonicalEvent::ContentDelta {
                sequence_number: next,
                content: other.clone(),
                event_id: None,
                response_id: None,
                item_id: None,
                output_index: None,
                content_index: None,
                timestamp: None,
            }),
        }
        next += 1;
    }
    (events, next)
}

fn error_event(
    sequence_number: u64,
    category: &str,
    message: impl Into<String>,
    retryable: Option<bool>,
) -> CanonicalEvent {
    CanonicalEvent::Error {
        sequence_number,
        category: category.to_owned(),
        message: message.into(),
        event_id: None,
        response_id: None,
        retryable,
        timestamp: None,
    }
}

fn response_to_events(body: &Value, fallback_model: &str, is_oauth: bool) -> Vec<CanonicalEvent> {
    let json = body.as_object();
    let id = json
        .and_then(|json| json.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("msg_claude")
        .to_owned();
    let model = json
        .and_then(|json| json.get("model"))
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty())
        .unwrap_or(fallback_model)
        .to_owned();

    let mut events = vec![CanonicalEvent::MessageStart {
        sequence_number: 1,
        event_id: Some(id),
        response_id: None,
        model: Some(model),
        system_fingerprint: None,
        timestamp: None,
    }];
    let mut sequence = 2;

    let blocks: &[Value] = json
        .and_then(|json| json.get("content"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for block in blocks {
        match parse_claude_content(block, is_oauth) {
            Ok(part) => {
                let (content_events, next) = event_content(&[part], sequence);
                events.extend(content_events);
                sequence = next;
            }
            Err(error) => {
                events.push(error_event(
                    sequence,
                    error.code.as_str(),
                    error.message,
                    Some(error.status >= 500),
                ));
                events.push(canonical_terminal(TerminalInput {
                    sequence_number: sequence + 1,
                    state: TerminalState::Failed,
                    stop_reason: Some(CanonicalStopReason::Error),
                    provider_stop_reason: None,
                    stop_details: None,
                    usage: None,
                    response_id: None,
                    event_id: None,
                }));
                return events;
            }
        }
    }

    let reason = json
        .and_then(|json| json.get("stop_reason"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let usage = json
        .and_then(|json| json.get("usage"))
        .and_then(usage_from_provider);
    let stop_details = json
        .and_then(|json| json.get("stop_details"))
        .and_then(Value::as_object)
        .cloned()
        .or_else(|| {
            json.and_then(|json| json.get("delta"))
                .and_then(Value::as_object)
                .and_then(|delta| delta.get("stop_details"))
                .and_then(Value::as_object)
                .cloned()
        });

    events.push(canonical_terminal(TerminalInput {
        sequence_number: sequence,
        state: TerminalState::Complete,
        stop_reason: reason.as_deref().map(map_claude_stop_reason),
        provider_stop_reason: reason,
        stop_details,
        usage,
        response_id: None,
        event_id: None,
    }));
    events
}

/// Converts one complete Claude Messages response into canonical events.
pub fn parse_messages_response(body: &Value, model: &str) -> Vec<CanonicalEvent> {
    response_to_events(body, model, false)
}

#[derive(Debug, Clone)]
struct StreamCall {
    call_id: String,
    name: Option<String>,
}

/// Mutable state carried across one Anthropic Messages SSE stream.
#[derive(Debug, Clone)]
pub struct MessagesStreamState {
    calls: HashMap<i64, StreamCall>,
    stop_reason: Option<String>,
    stop_details: Option<Map<String, Value>>,
    usage: Option<UsageRecord>,
    raw_usage: Option<Map<String, Value>>,
    saw_message_stop: bool,
    failed: bool,
    is_oauth: bool,
    sequence: u64,
}

impl Default for MessagesStreamState {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagesStreamState {
    pub fn new() -> Self {
        Self {
            calls: HashMap::new(),
            stop_reason: None,
            stop_details: None,
            usage: None,
            raw_usage: None,
            saw_message_stop: false,
            failed: false,
            is_oauth: false,
            sequence: 1,
        }
    }

    pub fn with_oauth(is_oauth: bool) -> Self {
        let mut state = Self::new();
        state.is_oauth = is_oauth;
        state
    }

    pub fn set_oauth(&mut self, is_oauth: bool) {
        self.is_oauth = is_oauth;
    }

    pub fn saw_message_stop(&self) -> bool {
        self.saw_message_stop
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    pub fn usage(&self) -> Option<&UsageRecord> {
        self.usage.as_ref()
    }

    pub fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }

    pub fn stop_details(&self) -> Option<&Map<String, Value>> {
        self.stop_details.as_ref()
    }

    /// Emits the terminal event once the stream reached `message_stop`.
    ///
    /// A stream that ended without `message_stop` yields a canonical error,
    /// mirroring the reference decoder's "ended before message_stop" failure.
    pub fn finish(&mut self) -> Vec<CanonicalEvent> {
        if self.failed {
            return Vec::new();
        }
        if !self.saw_message_stop {
            let sequence = self.sequence;
            self.sequence += 1;
            return vec![error_event(
                sequence,
                GatewayErrorCode::PlatformUnavailable.as_str(),
                "Claude stream ended before message_stop",
                Some(true),
            )];
        }
        vec![canonical_terminal(TerminalInput {
            sequence_number: self.sequence,
            state: TerminalState::Complete,
            stop_reason: self.stop_reason.as_deref().map(map_claude_stop_reason),
            provider_stop_reason: self.stop_reason.clone(),
            stop_details: self.stop_details.clone(),
            usage: self.usage.clone(),
            response_id: None,
            event_id: None,
        })]
    }
}

fn stream_error_category(status: u16) -> &'static str {
    match status {
        400 | 422 => "invalid_request",
        401 => "authentication_failed",
        403 => "policy_rejected",
        404 => "upstream_not_found",
        408 => "deadline_exceeded",
        413 => "request_too_large",
        429 => "accounts_rate_limited",
        _ => "platform_unavailable",
    }
}

fn stream_error_event(state: &mut MessagesStreamState, error: &Value) -> Vec<CanonicalEvent> {
    state.failed = true;
    let status = error
        .get("status")
        .and_then(Value::as_f64)
        .filter(|status| status.is_finite())
        .map_or(502, |status| status as u16);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Claude stream returned an error");
    let message: String = message.chars().take(500).collect();
    let retryable = status == 429 || status >= 500;
    let sequence = state.sequence;
    state.sequence += 1;
    vec![error_event(
        sequence,
        stream_error_category(status),
        message,
        Some(retryable),
    )]
}

fn stream_event_to_canonical(
    decoded: &Value,
    state: &mut MessagesStreamState,
) -> Vec<CanonicalEvent> {
    let mut events = Vec::new();
    let Some(event) = decoded.as_object() else {
        return events;
    };
    let kind = event.get("type").and_then(Value::as_str);
    match kind {
        Some("message_start") => {
            if let Some(usage) = event
                .get("message")
                .and_then(Value::as_object)
                .and_then(|message| message.get("usage"))
                .and_then(Value::as_object)
            {
                merge_usage(&mut state.raw_usage, usage);
                state.usage = state
                    .raw_usage
                    .as_ref()
                    .and_then(|raw| usage_from_provider(&Value::Object(raw.clone())));
            }
        }
        Some("content_block_start") => {
            let index = event.get("index").and_then(finite_i64).unwrap_or(0);
            let block = event
                .get("content_block")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let block_type = block.get("type").and_then(Value::as_str);
            if block_type == Some("tool_use") {
                if let Some(id) = block.get("id").and_then(Value::as_str) {
                    let name = block
                        .get("name")
                        .and_then(Value::as_str)
                        .map(|name| unprefix_claude_tool_name(name, state.is_oauth));
                    state.calls.insert(
                        index,
                        StreamCall {
                            call_id: id.to_owned(),
                            name: name.clone(),
                        },
                    );
                    let has_input = block
                        .get("input")
                        .and_then(Value::as_object)
                        .is_some_and(|input| !input.is_empty());
                    if has_input {
                        let arguments = block.get("input").cloned().unwrap_or_else(|| json!({}));
                        let sequence = state.sequence;
                        state.sequence += 1;
                        events.push(CanonicalEvent::ToolCallDelta {
                            sequence_number: sequence,
                            call_id: id.to_owned(),
                            index: None,
                            name,
                            arguments_delta: Some(
                                serde_json::to_string(&arguments).unwrap_or_else(|_| "{}".into()),
                            ),
                            event_id: None,
                            response_id: None,
                            item_id: None,
                            output_index: None,
                            timestamp: None,
                        });
                    }
                }
            } else if matches!(
                block_type,
                Some("server_tool_use" | "search_result" | "web_search_tool_result")
            ) {
                if let Ok(part) = parse_claude_content(&Value::Object(block), state.is_oauth) {
                    let sequence = state.sequence;
                    state.sequence += 1;
                    events.push(CanonicalEvent::ContentDelta {
                        sequence_number: sequence,
                        content: part,
                        event_id: None,
                        response_id: None,
                        item_id: None,
                        output_index: None,
                        content_index: None,
                        timestamp: None,
                    });
                }
            }
        }
        Some("content_block_delta") => {
            let index = event.get("index").and_then(finite_i64).unwrap_or(0);
            let delta = event
                .get("delta")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let delta_type = delta.get("type").and_then(Value::as_str);
            match delta_type {
                Some("text_delta") => {
                    if let Some(text) = delta.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            let sequence = state.sequence;
                            state.sequence += 1;
                            events.push(CanonicalEvent::ContentDelta {
                                sequence_number: sequence,
                                content: ContentPart::Text {
                                    text: text.to_owned(),
                                },
                                event_id: None,
                                response_id: None,
                                item_id: None,
                                output_index: None,
                                content_index: None,
                                timestamp: None,
                            });
                        }
                    }
                }
                Some("thinking_delta") => {
                    if let Some(thinking) = delta.get("thinking").and_then(Value::as_str) {
                        if !thinking.is_empty() {
                            let sequence = state.sequence;
                            state.sequence += 1;
                            events.push(CanonicalEvent::ContentDelta {
                                sequence_number: sequence,
                                content: ContentPart::Reasoning {
                                    payload: json!(thinking),
                                    opaque: None,
                                    summary: Some(thinking.to_owned()),
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
                            });
                        }
                    }
                }
                Some("signature_delta") => {
                    let sequence = state.sequence;
                    state.sequence += 1;
                    events.push(CanonicalEvent::ContentDelta {
                        sequence_number: sequence,
                        content: ContentPart::Reasoning {
                            payload: json!(""),
                            opaque: None,
                            summary: None,
                            summary_index: None,
                            signature: Some(
                                delta
                                    .get("signature")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                            encrypted_content: None,
                        },
                        event_id: None,
                        response_id: None,
                        item_id: None,
                        output_index: None,
                        content_index: None,
                        timestamp: None,
                    });
                }
                Some("input_json_delta") => {
                    let call = state.calls.get(&index);
                    let sequence = state.sequence;
                    state.sequence += 1;
                    events.push(CanonicalEvent::ToolCallDelta {
                        sequence_number: sequence,
                        call_id: call
                            .map(|call| call.call_id.clone())
                            .unwrap_or_else(|| format!("call-{index}")),
                        index: None,
                        name: call.and_then(|call| call.name.clone()),
                        arguments_delta: Some(
                            delta
                                .get("partial_json")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                        ),
                        event_id: None,
                        response_id: None,
                        item_id: None,
                        output_index: None,
                        timestamp: None,
                    });
                }
                Some("redacted_thinking_delta") => {
                    let sequence = state.sequence;
                    state.sequence += 1;
                    events.push(CanonicalEvent::ContentDelta {
                        sequence_number: sequence,
                        content: ContentPart::Reasoning {
                            payload: json!({
                                "type": "redacted_thinking",
                                "data": delta.get("data").cloned().unwrap_or(Value::Null),
                            }),
                            opaque: Some(true),
                            summary: None,
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
                    });
                }
                _ => {}
            }
        }
        Some("message_delta") => {
            let delta = event.get("delta").and_then(Value::as_object);
            if let Some(reason) = delta
                .and_then(|delta| delta.get("stop_reason"))
                .and_then(Value::as_str)
            {
                state.stop_reason = Some(reason.to_owned());
            }
            if let Some(stop_details) = delta
                .and_then(|delta| delta.get("stop_details"))
                .and_then(Value::as_object)
            {
                state.stop_details = Some(stop_details.clone());
            } else if let Some(stop_details) = event.get("stop_details").and_then(Value::as_object)
            {
                state.stop_details = Some(stop_details.clone());
            }
            if let Some(usage) = event.get("usage").and_then(Value::as_object) {
                merge_usage(&mut state.raw_usage, usage);
                state.usage = state
                    .raw_usage
                    .as_ref()
                    .and_then(|raw| usage_from_provider(&Value::Object(raw.clone())));
            }
        }
        Some("message_stop") => {
            state.saw_message_stop = true;
        }
        Some("ping") => {
            let sequence = state.sequence;
            state.sequence += 1;
            events.push(CanonicalEvent::Keepalive {
                sequence_number: sequence,
                event_id: None,
                timestamp: None,
            });
        }
        _ => {}
    }
    events
}

/// Decodes one Anthropic SSE frame into canonical events.
///
/// The caller checks [`MessagesStreamState::saw_message_stop`] after the
/// stream and calls [`MessagesStreamState::finish`] for the terminal event.
pub fn parse_messages_sse_event(
    event_name: Option<&str>,
    data: &str,
    state: &mut MessagesStreamState,
) -> Vec<CanonicalEvent> {
    if data.trim() == "[DONE]" {
        return Vec::new();
    }
    let decoded: Value = match serde_json::from_str(data) {
        Ok(decoded) => decoded,
        Err(_) => {
            state.failed = true;
            let sequence = state.sequence;
            state.sequence += 1;
            return vec![error_event(
                sequence,
                GatewayErrorCode::PlatformUnavailable.as_str(),
                "Malformed Claude SSE event",
                Some(true),
            )];
        }
    };
    if !decoded.is_object() {
        state.failed = true;
        let sequence = state.sequence;
        state.sequence += 1;
        return vec![error_event(
            sequence,
            GatewayErrorCode::PlatformUnavailable.as_str(),
            "Invalid Claude SSE event",
            Some(true),
        )];
    }
    if event_name == Some("error") || decoded.get("type").and_then(Value::as_str) == Some("error") {
        let error = decoded.get("error").cloned().unwrap_or(decoded);
        return stream_error_event(state, &error);
    }
    stream_event_to_canonical(&decoded, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn non_stream_response_parses_text_tool_use_usage_and_stop_reason() {
        let body = json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-6",
            "content": [
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": "toolu_1", "name": "_read", "input": {"path": "a.md"}}
            ],
            "stop_reason": "tool_use",
            "stop_sequence": null,
            "usage": {
                "input_tokens": 12,
                "output_tokens": 7,
                "cache_read_input_tokens": 3,
                "cache_creation_input_tokens": 2,
                "output_tokens_details": {"thinking_tokens": 1}
            }
        });
        let events = parse_messages_response(&body, "fallback");
        assert_eq!(events[0].sequence_number(), 1);
        assert!(matches!(
            &events[0],
            CanonicalEvent::MessageStart { model: Some(model), .. } if model == "claude-sonnet-4-6"
        ));
        assert!(matches!(
            events.get(1),
            Some(CanonicalEvent::ContentDelta {
                content: ContentPart::Text { text }, ..
            }) if text == "Let me check."
        ));
        assert!(matches!(
            events.get(2),
            Some(CanonicalEvent::ToolCallDelta { call_id, name: Some(name), arguments_delta: Some(arguments), .. })
                if call_id == "toolu_1" && name == "_read" && arguments.contains("a.md")
        ));
        let CanonicalEvent::Terminal {
            stop_reason,
            usage: Some(usage),
            state,
            ..
        } = events.last().unwrap()
        else {
            panic!("terminal event expected");
        };
        assert_eq!(*stop_reason, Some(CanonicalStopReason::ToolUse));
        assert_eq!(*state, TerminalState::Complete);
        assert_eq!(usage.input_tokens, 17);
        assert_eq!(usage.uncached_input_tokens, TokenCount::Number(12));
        assert_eq!(usage.cached_input_tokens, TokenCount::Number(3));
        assert_eq!(usage.cache_write_tokens, TokenCount::Number(2));
        assert_eq!(usage.output_tokens, 7);
        assert_eq!(usage.reasoning_tokens, TokenCount::Number(1));
    }

    #[test]
    fn sse_frames_decode_in_order_with_merged_usage() {
        let mut state = MessagesStreamState::with_oauth(true);
        let start = parse_messages_sse_event(
            Some("message_start"),
            &json!({
                "type": "message_start",
                "message": {
                    "id": "msg_1",
                    "usage": {"input_tokens": 10, "cache_read_input_tokens": 4, "output_tokens": 0}
                }
            })
            .to_string(),
            &mut state,
        );
        assert!(start.is_empty());
        assert!(state.usage.is_some());

        let block = parse_messages_sse_event(
            Some("content_block_start"),
            &json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "toolu_1", "name": "_search", "input": {}}
            })
            .to_string(),
            &mut state,
        );
        assert!(block.is_empty());

        let delta = parse_messages_sse_event(
            Some("content_block_delta"),
            &json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"q\":"}
            })
            .to_string(),
            &mut state,
        );
        assert!(matches!(
            delta.as_slice(),
            [CanonicalEvent::ToolCallDelta { call_id, name: Some(name), arguments_delta: Some(arg), .. }]
                if call_id == "toolu_1" && name == "search" && arg == "{\"q\":"
        ));

        let stop = parse_messages_sse_event(
            Some("content_block_stop"),
            &json!({"type": "content_block_stop", "index": 0}).to_string(),
            &mut state,
        );
        assert!(stop.is_empty());

        let usage = parse_messages_sse_event(
            Some("message_delta"),
            &json!({
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                "usage": {"output_tokens": 5}
            })
            .to_string(),
            &mut state,
        );
        assert!(usage.is_empty());
        let usage = state.usage().expect("merged usage");
        assert_eq!(usage.input_tokens, 14);
        assert_eq!(usage.output_tokens, 5);

        let ping = parse_messages_sse_event(
            Some("ping"),
            &json!({"type": "ping"}).to_string(),
            &mut state,
        );
        assert!(matches!(
            ping.as_slice(),
            [CanonicalEvent::Keepalive { .. }]
        ));

        assert!(
            parse_messages_sse_event(
                Some("message_stop"),
                &json!({"type": "message_stop"}).to_string(),
                &mut state
            )
            .is_empty()
        );
        assert!(state.saw_message_stop());

        let terminal = state.finish();
        assert!(matches!(
            terminal.as_slice(),
            [CanonicalEvent::Terminal {
                state: TerminalState::Complete,
                stop_reason: Some(CanonicalStopReason::ToolUse),
                usage: Some(_),
                ..
            }]
        ));
    }

    #[test]
    fn thinking_delta_and_display_survive() {
        let mut state = MessagesStreamState::new();
        let events = parse_messages_sse_event(
            Some("content_block_delta"),
            &json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "thinking_delta", "thinking": "pondering"}
            })
            .to_string(),
            &mut state,
        );
        assert!(matches!(
            events.as_slice(),
            [CanonicalEvent::ContentDelta {
                content: ContentPart::Reasoning { summary: Some(summary), .. },
                ..
            }] if summary == "pondering"
        ));
    }
}
