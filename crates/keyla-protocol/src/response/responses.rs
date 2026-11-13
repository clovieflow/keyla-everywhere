//! OpenAI Responses response decoder: wire JSON/SSE to canonical events.
//! Port of `src/protocol/response/responses.ts` (non-Codex variant).

use std::collections::{HashMap, HashSet};

use keyla_core::{
    CanonicalEvent, CanonicalStopReason, ContentPart, TerminalState, TokenCount, UsageDetails,
    UsageRecord,
};
use serde_json::{Map, Value, json};

use crate::primitives::{TerminalInput, canonical_terminal, read_output_index};

/// The model-facing name the Responses wire uses for computer-use tool calls.
const COMPUTER_TOOL_NAME: &str = "computer";

fn map_responses_stop_reason(
    status: Option<&str>,
    has_tool_call: bool,
) -> Option<CanonicalStopReason> {
    match status {
        Some("completed") => Some(if has_tool_call {
            CanonicalStopReason::ToolUse
        } else {
            CanonicalStopReason::Stop
        }),
        Some("incomplete") => Some(CanonicalStopReason::Length),
        Some("failed" | "cancelled") => Some(CanonicalStopReason::Error),
        _ => None,
    }
}

fn numeric_field(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

fn non_negative(value: Option<&Value>) -> Option<i64> {
    numeric_field(value).map(|value| value.max(0.0) as i64)
}

fn details_cached_tokens(usage: &Map<String, Value>) -> Option<i64> {
    usage
        .get("input_tokens_details")
        .and_then(Value::as_object)
        .and_then(|details| non_negative(details.get("cached_tokens")))
}

/// The xAI Grok wire splits usage across lifecycle frames: `response.created`
/// and `response.in_progress` carry the real cached count while
/// `response.completed` repeats truncated totals. Keep later totals, keep the
/// largest cached count, and never let a later 0 wipe a prior hit.
pub fn merge_responses_usage(
    current: Option<&Map<String, Value>>,
    update: Option<&Map<String, Value>>,
) -> Option<Map<String, Value>> {
    let Some(update) = update else {
        return current.cloned();
    };
    let Some(current) = current else {
        return Some(update.clone());
    };
    let mut merged = current.clone();
    for (key, value) in update {
        if key == "input_tokens_details" || key == "output_tokens_details" {
            continue;
        }
        merged.insert(key.clone(), value.clone());
    }
    let current_cached = details_cached_tokens(current).unwrap_or(0);
    let update_cached = details_cached_tokens(update);
    let cached = current_cached.max(update_cached.unwrap_or(0));
    let update_details = update
        .get("input_tokens_details")
        .and_then(Value::as_object);
    let current_details = current
        .get("input_tokens_details")
        .and_then(Value::as_object);
    if update_details.is_some() || current_details.is_some() || cached > 0 {
        let mut details = current_details.cloned().unwrap_or_default();
        if let Some(update_details) = update_details {
            for (key, value) in update_details {
                details.insert(key.clone(), value.clone());
            }
        }
        details.insert("cached_tokens".into(), json!(cached));
        merged.insert("input_tokens_details".into(), Value::Object(details));
    }
    let update_out = update
        .get("output_tokens_details")
        .and_then(Value::as_object);
    let current_out = current
        .get("output_tokens_details")
        .and_then(Value::as_object);
    if update_out.is_some() || current_out.is_some() {
        let mut details = current_out.cloned().unwrap_or_default();
        if let Some(update_out) = update_out {
            for (key, value) in update_out {
                details.insert(key.clone(), value.clone());
            }
        }
        merged.insert("output_tokens_details".into(), Value::Object(details));
    }
    Some(merged)
}

/// Maps a `computer_call_output.output` payload onto canonical content parts.
fn computer_output_to_content(output: &Value) -> Vec<ContentPart> {
    if let Some(text) = output.as_str() {
        return vec![ContentPart::Text {
            text: text.to_owned(),
        }];
    }
    if let Some(object) = output.as_object() {
        let image_url = object.get("image_url").or_else(|| object.get("url"));
        if let Some(image_url) = image_url.and_then(Value::as_str) {
            return vec![ContentPart::Image {
                payload: json!({"type": "output_image", "image_url": image_url}),
            }];
        }
        if let Some(text) = object.get("text").and_then(Value::as_str) {
            return vec![ContentPart::Text {
                text: text.to_owned(),
            }];
        }
    }
    vec![ContentPart::Text {
        text: serde_json::to_string(output).unwrap_or_default(),
    }]
}

/// String `delta` of a known reasoning-summary event.
pub fn read_responses_reasoning_delta(event: &Map<String, Value>) -> Option<&str> {
    let event_type = event.get("type").and_then(Value::as_str)?;
    if !matches!(
        event_type,
        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta"
    ) {
        return None;
    }
    event.get("delta").and_then(Value::as_str)
}

fn normalize_usage(input: &Map<String, Value>) -> UsageRecord {
    let mut input_tokens = non_negative(input.get("input_tokens"))
        .or_else(|| non_negative(input.get("prompt_tokens")))
        .unwrap_or(0);
    let output_tokens = non_negative(input.get("output_tokens"))
        .or_else(|| non_negative(input.get("completion_tokens")))
        .unwrap_or(0);

    let anthropic_cache_read = non_negative(input.get("cache_read_input_tokens"));
    let mut cached_input_tokens = anthropic_cache_read;
    if let Some(hit) = non_negative(input.get("prompt_cache_hit_tokens")) {
        cached_input_tokens = Some(hit);
    }
    if cached_input_tokens.is_none() {
        cached_input_tokens = input
            .get("input_tokens_details")
            .and_then(Value::as_object)
            .and_then(|details| non_negative(details.get("cached_tokens")));
    }
    if cached_input_tokens.is_none() {
        cached_input_tokens = input
            .get("prompt_tokens_details")
            .and_then(Value::as_object)
            .and_then(|details| non_negative(details.get("cached_tokens")));
    }
    if cached_input_tokens.is_none() {
        cached_input_tokens = non_negative(input.get("cached_tokens"));
    }
    if cached_input_tokens.is_none() {
        cached_input_tokens = non_negative(input.get("cachedContentTokenCount"));
    }

    let mut cache_write_tokens = non_negative(input.get("cache_creation_input_tokens"));
    if cache_write_tokens.is_none() {
        if let Some(breakdown) = input.get("cache_creation").and_then(Value::as_object) {
            let five_minutes =
                non_negative(breakdown.get("ephemeral_5m_input_tokens")).unwrap_or(0);
            let one_hour = non_negative(breakdown.get("ephemeral_1h_input_tokens")).unwrap_or(0);
            if five_minutes > 0 || one_hour > 0 {
                cache_write_tokens = Some(five_minutes + one_hour);
            }
        }
    }

    let has_anthropic_cache_shape = anthropic_cache_read.is_some();
    let mut uncached_input_tokens = None;
    if let Some(cached) = cached_input_tokens {
        if has_anthropic_cache_shape {
            uncached_input_tokens = Some(input_tokens);
            input_tokens += cached + cache_write_tokens.unwrap_or(0);
        } else {
            uncached_input_tokens = Some(0.max(input_tokens - input_tokens.min(cached)));
            cached_input_tokens = Some(input_tokens.min(cached));
        }
    } else if has_anthropic_cache_shape {
        if let Some(write) = cache_write_tokens {
            input_tokens += write;
        }
    }

    let mut reasoning_tokens = None;
    let mut details = UsageDetails::default();
    let output_details = input
        .get("output_tokens_details")
        .and_then(Value::as_object)
        .or_else(|| {
            input
                .get("completion_tokens_details")
                .and_then(Value::as_object)
        });
    if let Some(output_details) = output_details {
        reasoning_tokens = non_negative(output_details.get("thinking_tokens"))
            .or_else(|| non_negative(output_details.get("reasoning_tokens")));
        details.accepted_prediction_tokens =
            non_negative(output_details.get("accepted_prediction_tokens")).map(TokenCount::from);
        details.rejected_prediction_tokens =
            non_negative(output_details.get("rejected_prediction_tokens")).map(TokenCount::from);
    }

    UsageRecord {
        input_tokens,
        cached_input_tokens: cached_input_tokens.map_or(TokenCount::Unavailable, TokenCount::from),
        cache_write_tokens: cache_write_tokens.map_or(TokenCount::Unavailable, TokenCount::from),
        uncached_input_tokens: uncached_input_tokens
            .map_or(TokenCount::Unavailable, TokenCount::from),
        output_tokens,
        reasoning_tokens: reasoning_tokens.map_or(TokenCount::Unavailable, TokenCount::from),
        estimated_cost: None,
        credit_used: numeric_field(input.get("credit")).filter(|credit| *credit >= 0.0),
        total_tokens: None,
        details: if details.accepted_prediction_tokens.is_some()
            || details.rejected_prediction_tokens.is_some()
        {
            Some(details)
        } else {
            None
        },
    }
}

fn has_reported_usage(usage: &UsageRecord) -> bool {
    usage.input_tokens > 0
        || usage.output_tokens > 0
        || usage.cached_input_tokens.value().unwrap_or(0) > 0
        || usage.cache_write_tokens.value().unwrap_or(0) > 0
        || usage.reasoning_tokens.value().unwrap_or(0) > 0
}

/// Normalizes a provider usage payload, or `None` when nothing was reported.
pub fn usage_from_provider(raw: Option<&Value>) -> Option<UsageRecord> {
    let object = raw?.as_object()?;
    let usage = normalize_usage(object);
    has_reported_usage(&usage).then_some(usage)
}

/// Collapses provider-specific duplicate spellings of one logical call id.
fn tool_identity_key(call_id: &str) -> String {
    call_id
        .strip_prefix("call_")
        .or_else(|| call_id.strip_prefix("fc_"))
        .unwrap_or(call_id)
        .to_owned()
}

#[derive(Debug, Clone, Default)]
struct LedgerEntry {
    name: Option<String>,
    arguments: Option<String>,
    streamed_arguments: bool,
}

/// Per-stream tool-call emission ledger: one entry per logical call.
#[derive(Debug, Default, Clone)]
struct ToolEmitLedger {
    entries: HashMap<String, LedgerEntry>,
    orphan_seq: u64,
}

impl ToolEmitLedger {
    fn claim_first_emission(
        &mut self,
        call_id: &str,
        name: Option<&str>,
        args: Option<&str>,
    ) -> bool {
        let key = tool_identity_key(call_id);
        if self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(
            key,
            LedgerEntry {
                name: name.map(str::to_owned),
                arguments: args.map(str::to_owned),
                streamed_arguments: false,
            },
        );
        true
    }

    fn has_streamed_arguments(&self, call_id: &str) -> bool {
        self.entries
            .get(&tool_identity_key(call_id))
            .is_some_and(|entry| entry.streamed_arguments)
    }

    fn is_duplicate_definition(&self, call_id: &str, name: &str, args: &str) -> bool {
        if args.trim().is_empty() {
            return false;
        }
        if call_id.starts_with("call_") || call_id.starts_with("fc_") {
            return false;
        }
        let key = tool_identity_key(call_id);
        self.entries.iter().any(|(id, entry)| {
            id != &key
                && entry.name.as_deref() == Some(name)
                && entry.arguments.as_deref() == Some(args)
        })
    }

    fn mark_streamed_arguments(&mut self, call_id: &str) {
        let key = tool_identity_key(call_id);
        self.entries.entry(key).or_default().streamed_arguments = true;
    }

    fn next_orphan_id(&mut self, prefix: &str) -> String {
        self.orphan_seq += 1;
        format!("{prefix}-orphan-{}", self.orphan_seq)
    }
}

fn response_start_event(
    sequence: u64,
    event_id: Option<&str>,
    model: &str,
    fingerprint: Option<&str>,
) -> CanonicalEvent {
    CanonicalEvent::ResponseStart {
        sequence_number: sequence,
        event_id: event_id.map(str::to_owned),
        response_id: None,
        model: Some(model.to_owned()),
        system_fingerprint: fingerprint.map(str::to_owned),
        timestamp: None,
    }
}

fn content_delta_event(
    sequence: u64,
    content: ContentPart,
    response_id: Option<&str>,
    item_id: Option<&str>,
    output_index: Option<i64>,
) -> CanonicalEvent {
    CanonicalEvent::ContentDelta {
        sequence_number: sequence,
        content,
        event_id: None,
        response_id: response_id.map(str::to_owned),
        item_id: item_id.map(str::to_owned),
        output_index,
        content_index: None,
        timestamp: None,
    }
}

fn tool_call_event(
    sequence: u64,
    response_id: Option<&str>,
    item_id: Option<&str>,
    output_index: Option<i64>,
    call_id: &str,
    name: Option<&str>,
    arguments: &str,
) -> CanonicalEvent {
    CanonicalEvent::ToolCallDelta {
        sequence_number: sequence,
        call_id: call_id.to_owned(),
        index: None,
        name: name.map(str::to_owned),
        arguments_delta: Some(arguments.to_owned()),
        event_id: None,
        response_id: response_id.map(str::to_owned),
        item_id: item_id.map(str::to_owned),
        output_index,
        timestamp: None,
    }
}

fn extension_event(
    sequence: u64,
    response_id: Option<&str>,
    name: String,
    payload: Value,
) -> CanonicalEvent {
    content_delta_event(
        sequence,
        ContentPart::Extension { name, payload },
        response_id,
        None,
        None,
    )
}

/// Summaries of one reasoning item, in wire order, plus its encrypted payload.
fn reasoning_summaries(item: &Map<String, Value>) -> (Vec<(i64, String)>, Option<String>) {
    let summary = item
        .get("summary")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let content = item
        .get("content")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let raw_parts = if summary.is_empty() { content } else { summary };
    let mut summaries: Vec<(i64, String)> = Vec::new();
    for (index, part) in raw_parts.iter().enumerate() {
        let text = part
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !text.is_empty() {
            summaries.push((index as i64, text));
        }
    }
    let encrypted = item
        .get("encrypted_content")
        .and_then(Value::as_str)
        .map(str::to_owned);
    (summaries, encrypted)
}

fn reasoning_content(
    text: &str,
    summary_index: i64,
    encrypted: Option<&str>,
    include_encrypted: bool,
) -> ContentPart {
    ContentPart::Reasoning {
        payload: Value::Null,
        opaque: None,
        summary: if text.is_empty() {
            None
        } else {
            Some(text.to_owned())
        },
        summary_index: Some(summary_index),
        signature: None,
        encrypted_content: if include_encrypted {
            encrypted.map(str::to_owned)
        } else {
            None
        },
    }
}

fn terminal_event(
    sequence: u64,
    response_id: Option<&str>,
    status: Option<&str>,
    truncated: bool,
    has_tool_call: bool,
    usage: Option<&Value>,
) -> CanonicalEvent {
    let state = match status {
        Some("cancelled") => TerminalState::Aborted,
        Some("failed") => TerminalState::Failed,
        _ if truncated => TerminalState::Failed,
        _ => TerminalState::Complete,
    };
    canonical_terminal(TerminalInput {
        sequence_number: sequence,
        state,
        stop_reason: map_responses_stop_reason(status, has_tool_call),
        provider_stop_reason: status.map(str::to_owned),
        stop_details: None,
        usage: usage_from_provider(usage),
        response_id: response_id.map(str::to_owned),
        event_id: None,
    })
}

/// Decodes a non-streaming Responses body into ordered canonical events.
pub fn parse_responses_response(body: &Value, model: &str) -> Vec<CanonicalEvent> {
    let empty = Map::new();
    let json = body.as_object().unwrap_or(&empty);
    let id = json
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("resp_responses")
        .to_owned();
    let response_model = json
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(model)
        .to_owned();
    let system_fingerprint = json.get("system_fingerprint").and_then(Value::as_str);
    let mut events = vec![response_start_event(
        1,
        Some(&id),
        &response_model,
        system_fingerprint,
    )];
    let output = json
        .get("output")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut has_tool_call = false;
    let mut ledger = ToolEmitLedger::default();
    for (output_index, raw_item) in output.iter().enumerate() {
        let Some(item) = raw_item.as_object() else {
            continue;
        };
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
        if item_type == "message" {
            let content = item
                .get("content")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for raw_part in &content {
                let Some(part) = raw_part.as_object() else {
                    continue;
                };
                match part.get("type").and_then(Value::as_str) {
                    Some("output_text") => {
                        if let Some(text) = part.get("text").and_then(Value::as_str) {
                            let item_id = item.get("id").and_then(Value::as_str);
                            let sequence = events.len() as u64 + 1;
                            events.push(content_delta_event(
                                sequence,
                                ContentPart::Text {
                                    text: text.to_owned(),
                                },
                                Some(&id),
                                item_id,
                                Some(output_index as i64),
                            ));
                        }
                    }
                    Some("refusal") => {
                        if let Some(refusal) = part.get("refusal").and_then(Value::as_str) {
                            let sequence = events.len() as u64 + 1;
                            events.push(content_delta_event(
                                sequence,
                                ContentPart::Refusal {
                                    text: refusal.to_owned(),
                                },
                                Some(&id),
                                None,
                                None,
                            ));
                        }
                    }
                    _ => {}
                }
            }
        } else if item_type == "reasoning" {
            let (summaries, encrypted) = reasoning_summaries(item);
            let item_id = item.get("id").and_then(Value::as_str);
            let emitted = if summaries.is_empty() {
                vec![(0, String::new())]
            } else {
                summaries
            };
            for (position, (summary_index, text)) in emitted.iter().enumerate() {
                let sequence = events.len() as u64 + 1;
                events.push(content_delta_event(
                    sequence,
                    reasoning_content(text, *summary_index, encrypted.as_deref(), position == 0),
                    Some(&id),
                    item_id,
                    Some(output_index as i64),
                ));
            }
        } else if item_type == "function_call" {
            has_tool_call = true;
            let item_id = item.get("id").and_then(Value::as_str);
            let raw_call_id = item
                .get("call_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| item_id.map(str::to_owned))
                .unwrap_or_else(|| ledger.next_orphan_id("call"));
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let arguments = item
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if ledger.is_duplicate_definition(&raw_call_id, &name, &arguments)
                || !ledger.claim_first_emission(&raw_call_id, Some(&name), Some(&arguments))
            {
                continue;
            }
            let sequence = events.len() as u64 + 1;
            events.push(tool_call_event(
                sequence,
                Some(&id),
                item_id,
                Some(output_index as i64),
                &raw_call_id,
                Some(&name),
                &arguments,
            ));
        } else if item_type == "computer_call" {
            has_tool_call = true;
            let call_id = item
                .get("call_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| item.get("id").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| ledger.next_orphan_id(COMPUTER_TOOL_NAME));
            let actions = item
                .get("actions")
                .and_then(Value::as_array)
                .cloned()
                .or_else(|| item.get("action").map(|action| vec![action.clone()]))
                .unwrap_or_default();
            let arguments = serde_json::to_string(&json!({"actions": actions}))
                .unwrap_or_else(|_| "{\"actions\":[]}".into());
            if ledger.is_duplicate_definition(&call_id, COMPUTER_TOOL_NAME, &arguments)
                || !ledger.claim_first_emission(
                    &call_id,
                    Some(COMPUTER_TOOL_NAME),
                    Some(&arguments),
                )
            {
                continue;
            }
            let sequence = events.len() as u64 + 1;
            let item_id = item.get("id").and_then(Value::as_str);
            events.push(tool_call_event(
                sequence,
                Some(&id),
                item_id,
                Some(output_index as i64),
                &call_id,
                Some(COMPUTER_TOOL_NAME),
                &arguments,
            ));
        } else if item_type == "computer_call_output" {
            if let Some(call_id) = item.get("call_id").and_then(Value::as_str) {
                let sequence = events.len() as u64 + 1;
                events.push(CanonicalEvent::ToolResult {
                    sequence_number: sequence,
                    call_id: call_id.to_owned(),
                    content: computer_output_to_content(item.get("output").unwrap_or(&Value::Null)),
                    event_id: None,
                    response_id: Some(id.clone()),
                    item_id: None,
                    timestamp: None,
                });
            }
        } else if item.get("type").and_then(Value::as_str).is_some() {
            let sequence = events.len() as u64 + 1;
            events.push(extension_event(
                sequence,
                Some(&id),
                format!("responses:{item_type}"),
                raw_item.clone(),
            ));
        }
    }
    let status = json.get("status").and_then(Value::as_str);
    let usage = json.get("usage");
    let sequence = events.len() as u64 + 1;
    events.push(terminal_event(
        sequence,
        Some(&id),
        status,
        false,
        has_tool_call,
        usage,
    ));
    events
}

#[derive(Debug, Clone, Default)]
struct CallInfo {
    name: Option<String>,
    call_id: Option<String>,
}

/// Accumulated SSE decoding state for one Responses stream.
#[derive(Debug, Clone)]
pub struct ResponsesStreamState {
    model: String,
    sequence: u64,
    started: bool,
    terminal_emitted: bool,
    status: Option<String>,
    raw_usage: Option<Map<String, Value>>,
    has_tool_call: bool,
    call_info: HashMap<String, CallInfo>,
    ledger: ToolEmitLedger,
    last_function_call_id: Option<String>,
    last_function_call_id_by_output_index: HashMap<i64, String>,
    call_name_by_id: HashMap<String, String>,
    named_calls: HashSet<String>,
    streamed_reasoning_item_ids: HashSet<String>,
    has_streamed_reasoning_deltas: bool,
}

impl ResponsesStreamState {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            sequence: 1,
            started: false,
            terminal_emitted: false,
            status: None,
            raw_usage: None,
            has_tool_call: false,
            call_info: HashMap::new(),
            ledger: ToolEmitLedger::default(),
            last_function_call_id: None,
            last_function_call_id_by_output_index: HashMap::new(),
            call_name_by_id: HashMap::new(),
            named_calls: HashSet::new(),
            streamed_reasoning_item_ids: HashSet::new(),
            has_streamed_reasoning_deltas: false,
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.sequence;
        self.sequence += 1;
        sequence
    }

    fn emit_terminal(&mut self, events: &mut Vec<CanonicalEvent>) {
        if self.terminal_emitted {
            return;
        }
        let truncated = self.status.is_none();
        let sequence = self.next_sequence();
        let status = self.status.clone();
        let usage = self
            .raw_usage
            .as_ref()
            .map(|usage| Value::Object(usage.clone()));
        events.push(terminal_event(
            sequence,
            None,
            status.as_deref(),
            truncated,
            self.has_tool_call,
            usage.as_ref(),
        ));
        self.terminal_emitted = true;
    }

    /// Emits the terminal frame when the transport closed without one.
    pub fn finish(&mut self) -> Vec<CanonicalEvent> {
        let mut events = Vec::new();
        if !self.started {
            self.started = true;
            let sequence = self.next_sequence();
            events.push(response_start_event(
                sequence,
                None,
                &self.model.clone(),
                None,
            ));
        }
        if !self.terminal_emitted {
            self.emit_terminal(&mut events);
        }
        events
    }
}

fn stream_error_event(sequence: u64, error: &Value, label: &str) -> CanonicalEvent {
    let (category, message) = match error {
        Value::String(text) => (
            "platform_unavailable".to_owned(),
            if text.is_empty() {
                label.to_owned()
            } else {
                text.chars().take(500).collect()
            },
        ),
        Value::Object(object) => {
            let identifier = object
                .get("type")
                .and_then(Value::as_str)
                .or_else(|| object.get("code").and_then(Value::as_str))
                .unwrap_or_default();
            let category = match identifier {
                "authentication_error" | "invalid_api_key" => "authentication_failed",
                "insufficient_quota" | "quota_exceeded" => "quota_exceeded",
                "rate_limit_exceeded" | "rate_limit_error" => "accounts_rate_limited",
                "context_length_exceeded" => "context_length_exceeded",
                "invalid_request_error" | "invalid_request" => "invalid_request",
                "server_error" | "api_error" => "platform_unavailable",
                _ => "platform_unavailable",
            };
            let message = object
                .get("message")
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
                .unwrap_or(label);
            (category.to_owned(), message.to_owned())
        }
        _ => ("platform_unavailable".to_owned(), label.to_owned()),
    };
    CanonicalEvent::Error {
        sequence_number: sequence,
        category,
        message,
        event_id: None,
        response_id: None,
        retryable: None,
        timestamp: None,
    }
}

/// Decodes one Responses SSE frame into ordered canonical events.
///
/// The caller supplies the SSE `event:` name when present; a frame whose JSON
/// payload carries its own `type` wins, mirroring the wire.
pub fn parse_responses_sse_event(
    event_name: Option<&str>,
    data: &str,
    state: &mut ResponsesStreamState,
) -> Vec<CanonicalEvent> {
    let mut events = Vec::new();
    if !state.started {
        state.started = true;
        let sequence = state.next_sequence();
        events.push(response_start_event(
            sequence,
            None,
            &state.model.clone(),
            None,
        ));
    }
    if state.terminal_emitted {
        return events;
    }

    let data = data.trim();
    if data == "[DONE]" {
        state.emit_terminal(&mut events);
        return events;
    }

    let parsed: Value = match serde_json::from_str(data) {
        Ok(value) => value,
        Err(error) => {
            let sequence = state.next_sequence();
            events.push(stream_error_event(
                sequence,
                &Value::String(format!("Malformed SSE event: {error}")),
                "upstream returned a failed response",
            ));
            state.terminal_emitted = true;
            return events;
        }
    };
    let empty = Map::new();
    let event = parsed.as_object().unwrap_or(&empty);
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .or(event_name)
        .unwrap_or_default()
        .to_owned();

    // An explicit failure inside a 200 OK: a top-level `type: "error"` frame,
    // or a `response.failed` terminal whose `response.error` explains why.
    let failed_response = if event_type == "response.failed" {
        event.get("response").and_then(Value::as_object)
    } else {
        None
    };
    let error_envelope: Option<&Value> = if event_type == "error" {
        event.get("error").or(Some(&parsed))
    } else {
        failed_response.and_then(|response| response.get("error"))
    };
    if let Some(error) = error_envelope {
        let sequence = state.next_sequence();
        events.push(stream_error_event(
            sequence,
            error,
            "upstream returned a failed response",
        ));
        state.terminal_emitted = true;
        return events;
    }

    match event_type.as_str() {
        "response.output_text.delta" => {
            if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                if !delta.is_empty() {
                    let sequence = state.next_sequence();
                    events.push(content_delta_event(
                        sequence,
                        ContentPart::Text {
                            text: delta.to_owned(),
                        },
                        None,
                        None,
                        None,
                    ));
                }
            }
        }
        "response.reasoning_text.delta" | "response.reasoning_summary_text.delta" => {
            let summary = read_responses_reasoning_delta(event).map(str::to_owned);
            if let Some(summary) = summary.filter(|summary| !summary.is_empty()) {
                let summary_index = event
                    .get("summary_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if let Some(item_id) = event.get("item_id").and_then(Value::as_str) {
                    state.streamed_reasoning_item_ids.insert(item_id.to_owned());
                }
                state.has_streamed_reasoning_deltas = true;
                let sequence = state.next_sequence();
                events.push(content_delta_event(
                    sequence,
                    ContentPart::Reasoning {
                        payload: Value::Null,
                        opaque: None,
                        summary: Some(summary),
                        summary_index: Some(summary_index),
                        signature: None,
                        encrypted_content: None,
                    },
                    None,
                    None,
                    None,
                ));
            }
        }
        "response.output_item.added" => {
            let item = event.get("item").and_then(Value::as_object);
            let added_index = read_output_index(event);
            let item_type = item
                .and_then(|item| item.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if item_type == "function_call" {
                let Some(item) = item else {
                    return events;
                };
                let item_id = item.get("id").and_then(Value::as_str);
                let item_call_id = item.get("call_id").and_then(Value::as_str);
                let id = item_id
                    .map(str::to_owned)
                    .or_else(|| item_call_id.map(str::to_owned))
                    .unwrap_or_else(|| state.ledger.next_orphan_id("call"));
                state.call_info.insert(
                    id,
                    CallInfo {
                        name: item.get("name").and_then(Value::as_str).map(str::to_owned),
                        call_id: item_call_id.map(str::to_owned),
                    },
                );
                if let Some(resolved_call_id) = item_call_id.or(item_id).map(str::to_owned) {
                    state.last_function_call_id = Some(resolved_call_id.clone());
                    if let Some(index) = added_index {
                        state
                            .last_function_call_id_by_output_index
                            .insert(index, resolved_call_id.clone());
                    }
                }
                let resolved_call_id = item_call_id.or(item_id);
                if let (Some(item_name), Some(resolved_call_id)) =
                    (item.get("name").and_then(Value::as_str), resolved_call_id)
                {
                    if !item_name.is_empty() {
                        state
                            .call_name_by_id
                            .insert(resolved_call_id.to_owned(), item_name.to_owned());
                    }
                }
            } else if item_type == "computer_call" {
                state.has_tool_call = true;
                let Some(item) = item else {
                    return events;
                };
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| item.get("id").and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_else(|| state.ledger.next_orphan_id(COMPUTER_TOOL_NAME));
                let actions = item
                    .get("actions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let arguments = serde_json::to_string(&json!({"actions": actions}))
                    .unwrap_or_else(|_| "{\"actions\":[]}".into());
                if state.ledger.claim_first_emission(
                    &call_id,
                    Some(COMPUTER_TOOL_NAME),
                    Some(&arguments),
                ) {
                    let sequence = state.next_sequence();
                    let item_id = item.get("id").and_then(Value::as_str);
                    events.push(tool_call_event(
                        sequence,
                        None,
                        item_id,
                        None,
                        &call_id,
                        Some(COMPUTER_TOOL_NAME),
                        &arguments,
                    ));
                }
            } else if item_type == "reasoning" {
                if let Some(item) = item {
                    let (summaries, encrypted) = reasoning_summaries(item);
                    let item_id = item.get("id").and_then(Value::as_str).map(str::to_owned);
                    let emitted = if summaries.is_empty() {
                        vec![(0, String::new())]
                    } else {
                        summaries
                    };
                    for (position, (summary_index, text)) in emitted.iter().enumerate() {
                        let sequence = state.next_sequence();
                        events.push(content_delta_event(
                            sequence,
                            reasoning_content(
                                text,
                                *summary_index,
                                encrypted.as_deref(),
                                position == 0,
                            ),
                            None,
                            item_id.as_deref(),
                            None,
                        ));
                    }
                }
            }
        }
        "response.output_item.done" => {
            let item = event.get("item").and_then(Value::as_object);
            let item_type = item
                .and_then(|item| item.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if item_type == "function_call" {
                let Some(item) = item else {
                    return events;
                };
                state.has_tool_call = true;
                let item_id = item.get("id").and_then(Value::as_str);
                let done_index = read_output_index(event);
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| item_id.map(str::to_owned))
                    .or_else(|| {
                        done_index.and_then(|index| {
                            state
                                .last_function_call_id_by_output_index
                                .get(&index)
                                .cloned()
                        })
                    })
                    .unwrap_or_else(|| state.ledger.next_orphan_id("call"));
                let args = item
                    .get("arguments")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| {
                        let key = item_id.unwrap_or(&call_id);
                        state.call_info.get(key).and_then(|info| info.name.clone())
                    })
                    .or_else(|| state.call_name_by_id.get(&call_id).cloned());
                let name_ref = name.as_deref();
                if !state
                    .ledger
                    .is_duplicate_definition(&call_id, name_ref.unwrap_or(""), &args)
                    && state
                        .ledger
                        .claim_first_emission(&call_id, name_ref, Some(&args))
                    && !state.ledger.has_streamed_arguments(&call_id)
                {
                    if name.is_some() {
                        state.named_calls.insert(call_id.clone());
                    }
                    let sequence = state.next_sequence();
                    events.push(tool_call_event(
                        sequence, None, item_id, None, &call_id, name_ref, &args,
                    ));
                } else if name.is_some()
                    && state.ledger.has_streamed_arguments(&call_id)
                    && !state.named_calls.contains(&call_id)
                {
                    state.named_calls.insert(call_id.clone());
                    let sequence = state.next_sequence();
                    events.push(tool_call_event(
                        sequence, None, item_id, None, &call_id, name_ref, "",
                    ));
                }
            } else if item_type == "computer_call" {
                let Some(item) = item else {
                    return events;
                };
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| item.get("id").and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_else(|| state.ledger.next_orphan_id(COMPUTER_TOOL_NAME));
                let actions = item
                    .get("actions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let arguments = serde_json::to_string(&json!({"actions": actions}))
                    .unwrap_or_else(|_| "{\"actions\":[]}".into());
                if !state
                    .ledger
                    .is_duplicate_definition(&call_id, COMPUTER_TOOL_NAME, &arguments)
                    && state.ledger.claim_first_emission(
                        &call_id,
                        Some(COMPUTER_TOOL_NAME),
                        Some(&arguments),
                    )
                {
                    state.has_tool_call = true;
                    let sequence = state.next_sequence();
                    let item_id = item.get("id").and_then(Value::as_str);
                    events.push(tool_call_event(
                        sequence,
                        None,
                        item_id,
                        None,
                        &call_id,
                        Some(COMPUTER_TOOL_NAME),
                        &arguments,
                    ));
                }
            } else if item_type == "computer_call_output" {
                if let Some(call_id) = item
                    .and_then(|item| item.get("call_id"))
                    .and_then(Value::as_str)
                {
                    let sequence = state.next_sequence();
                    events.push(CanonicalEvent::ToolResult {
                        sequence_number: sequence,
                        call_id: call_id.to_owned(),
                        content: computer_output_to_content(
                            item.and_then(|item| item.get("output"))
                                .unwrap_or(&Value::Null),
                        ),
                        event_id: None,
                        response_id: None,
                        item_id: None,
                        timestamp: None,
                    });
                }
            } else if item_type == "reasoning" {
                if let Some(item) = item {
                    let (summaries, encrypted) = reasoning_summaries(item);
                    let item_id = item.get("id").and_then(Value::as_str).map(str::to_owned);
                    let already_streamed = match &item_id {
                        Some(item_id) => state.streamed_reasoning_item_ids.contains(item_id),
                        None => state.has_streamed_reasoning_deltas,
                    };
                    if !summaries.is_empty() && !already_streamed {
                        for (position, (summary_index, text)) in summaries.iter().enumerate() {
                            let sequence = state.next_sequence();
                            events.push(content_delta_event(
                                sequence,
                                reasoning_content(
                                    text,
                                    *summary_index,
                                    encrypted.as_deref(),
                                    position == 0,
                                ),
                                None,
                                item_id.as_deref(),
                                None,
                            ));
                        }
                    }
                }
            }
        }
        "response.function_call_arguments.delta" => {
            state.has_tool_call = true;
            let item_id = event
                .get("item_id")
                .and_then(Value::as_str)
                .filter(|item_id| !item_id.is_empty());
            let delta_index = read_output_index(event);
            let info = item_id.and_then(|item_id| state.call_info.get(item_id));
            let call_id = info
                .and_then(|info| info.call_id.clone())
                .or_else(|| item_id.map(str::to_owned))
                .or_else(|| {
                    delta_index.and_then(|index| {
                        state
                            .last_function_call_id_by_output_index
                            .get(&index)
                            .cloned()
                    })
                })
                .or_else(|| state.last_function_call_id.clone())
                .unwrap_or_else(|| state.ledger.next_orphan_id("call"));
            state.ledger.mark_streamed_arguments(&call_id);
            let delta_name = info
                .and_then(|info| info.name.clone())
                .or_else(|| state.call_name_by_id.get(&call_id).cloned());
            if delta_name.is_some() {
                state.named_calls.insert(call_id.clone());
            }
            let delta = event
                .get("delta")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let sequence = state.next_sequence();
            events.push(tool_call_event(
                sequence,
                None,
                None,
                None,
                &call_id,
                delta_name.as_deref(),
                delta,
            ));
        }
        "response.function_call_arguments.done" => {
            state.has_tool_call = true;
            let item_id = event
                .get("item_id")
                .and_then(Value::as_str)
                .filter(|item_id| !item_id.is_empty());
            let done_index = read_output_index(event);
            let raw_call_id = event
                .get("call_id")
                .and_then(Value::as_str)
                .filter(|call_id| !call_id.is_empty());
            let item_info = item_id.and_then(|item_id| state.call_info.get(item_id));
            let call_id = raw_call_id
                .map(str::to_owned)
                .or_else(|| item_info.and_then(|info| info.call_id.clone()))
                .or_else(|| item_id.map(str::to_owned))
                .or_else(|| {
                    done_index.and_then(|index| {
                        state
                            .last_function_call_id_by_output_index
                            .get(&index)
                            .cloned()
                    })
                })
                .or_else(|| state.last_function_call_id.clone())
                .unwrap_or_else(|| state.ledger.next_orphan_id("call"));
            let args = event
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let name = item_info
                .and_then(|info| info.name.clone())
                .or_else(|| {
                    state
                        .call_info
                        .get(&call_id)
                        .and_then(|info| info.name.clone())
                })
                .or_else(|| state.call_name_by_id.get(&call_id).cloned());
            let name_ref = name.as_deref();
            if !state
                .ledger
                .is_duplicate_definition(&call_id, name_ref.unwrap_or(""), &args)
                && state
                    .ledger
                    .claim_first_emission(&call_id, name_ref, Some(&args))
                && !state.ledger.has_streamed_arguments(&call_id)
            {
                if name.is_some() {
                    state.named_calls.insert(call_id.clone());
                }
                let sequence = state.next_sequence();
                events.push(tool_call_event(
                    sequence, None, item_id, None, &call_id, name_ref, &args,
                ));
            } else if name.is_some()
                && state.ledger.has_streamed_arguments(&call_id)
                && !state.named_calls.contains(&call_id)
            {
                state.named_calls.insert(call_id.clone());
                let sequence = state.next_sequence();
                events.push(tool_call_event(
                    sequence, None, item_id, None, &call_id, name_ref, "",
                ));
            }
        }
        "response.created"
        | "response.in_progress"
        | "response.completed"
        | "response.incomplete"
        | "response.failed" => {
            let response = event.get("response").and_then(Value::as_object);
            if matches!(
                event_type.as_str(),
                "response.completed" | "response.incomplete" | "response.failed"
            ) {
                state.status = response
                    .and_then(|response| response.get("status"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| event_type.strip_prefix("response.").map(str::to_owned));
            }
            state.raw_usage = merge_responses_usage(
                state.raw_usage.as_ref(),
                response
                    .and_then(|response| response.get("usage"))
                    .and_then(Value::as_object),
            );
            // A backend may report a tool call only here, either because it
            // emits no incremental frames or because it appends a sibling call
            // that never streamed. Only unseen calls are surfaced.
            if let Some(output) = response
                .and_then(|response| response.get("output"))
                .and_then(Value::as_array)
            {
                for raw in output {
                    let Some(raw) = raw.as_object() else {
                        continue;
                    };
                    if raw.get("type").and_then(Value::as_str) != Some("function_call") {
                        continue;
                    }
                    let name = raw
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_owned();
                    if name.is_empty() {
                        continue;
                    }
                    let item_id = raw.get("id").and_then(Value::as_str);
                    let item_call_id = raw.get("call_id").and_then(Value::as_str);
                    let call_id = item_call_id
                        .map(str::to_owned)
                        .or_else(|| item_id.map(str::to_owned))
                        .unwrap_or_else(|| state.ledger.next_orphan_id("call"));
                    let args = raw
                        .get("arguments")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    if !state
                        .ledger
                        .claim_first_emission(&call_id, Some(&name), Some(&args))
                    {
                        continue;
                    }
                    state.has_tool_call = true;
                    state.call_name_by_id.insert(call_id.clone(), name.clone());
                    state.named_calls.insert(call_id.clone());
                    state.last_function_call_id = Some(call_id.clone());
                    let sequence = state.next_sequence();
                    events.push(tool_call_event(
                        sequence,
                        None,
                        item_id,
                        None,
                        &call_id,
                        Some(&name),
                        &args,
                    ));
                }
            }
            if matches!(
                event_type.as_str(),
                "response.completed" | "response.incomplete" | "response.failed"
            ) {
                state.emit_terminal(&mut events);
            }
        }
        "" => {}
        other => {
            let sequence = state.next_sequence();
            events.push(extension_event(
                sequence,
                None,
                format!("responses:{other}"),
                parsed.clone(),
            ));
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_message_function_call_reasoning_and_usage() {
        let body = json!({
            "id": "resp_1",
            "model": "gpt-5",
            "system_fingerprint": "fp_1",
            "status": "completed",
            "output": [
                {
                    "type": "reasoning",
                    "id": "rs_1",
                    "summary": [{"type": "summary_text", "text": "thinking"}],
                    "encrypted_content": "cipher"
                },
                {
                    "type": "message",
                    "id": "msg_1",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": "hello"},
                        {"type": "refusal", "refusal": "no"}
                    ]
                },
                {
                    "type": "function_call",
                    "id": "fc_1",
                    "call_id": "call_1",
                    "name": "read",
                    "arguments": "{\"path\":\"a\"}"
                }
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 4,
                "input_tokens_details": {"cached_tokens": 3},
                "output_tokens_details": {"reasoning_tokens": 2}
            }
        });
        let events = parse_responses_response(&body, "fallback");
        assert!(matches!(
            events[0],
            CanonicalEvent::ResponseStart {
                sequence_number: 1,
                ..
            }
        ));
        let CanonicalEvent::ContentDelta { content, .. } = &events[1] else {
            panic!("expected reasoning delta");
        };
        let ContentPart::Reasoning {
            summary,
            summary_index,
            encrypted_content,
            ..
        } = content
        else {
            panic!("expected reasoning content");
        };
        assert_eq!(summary.as_deref(), Some("thinking"));
        assert_eq!(*summary_index, Some(0));
        assert_eq!(encrypted_content.as_deref(), Some("cipher"));

        let CanonicalEvent::ContentDelta { content, .. } = &events[2] else {
            panic!("expected text delta");
        };
        assert_eq!(
            content,
            &ContentPart::Text {
                text: "hello".into()
            }
        );
        assert!(matches!(
            &events[3],
            CanonicalEvent::ContentDelta {
                content: ContentPart::Refusal { text },
                ..
            } if text == "no"
        ));
        let CanonicalEvent::ToolCallDelta {
            call_id,
            name,
            arguments_delta,
            ..
        } = &events[4]
        else {
            panic!("expected tool call");
        };
        assert_eq!(call_id, "call_1");
        assert_eq!(name.as_deref(), Some("read"));
        assert_eq!(arguments_delta.as_deref(), Some("{\"path\":\"a\"}"));

        let CanonicalEvent::Terminal {
            state,
            stop_reason,
            usage,
            provider_stop_reason,
            ..
        } = events.last().unwrap()
        else {
            panic!("expected terminal");
        };
        assert_eq!(*state, TerminalState::Complete);
        assert_eq!(*stop_reason, Some(CanonicalStopReason::ToolUse));
        assert_eq!(provider_stop_reason.as_deref(), Some("completed"));
        let usage = usage.as_ref().unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 4);
        assert_eq!(usage.cached_input_tokens, TokenCount::Number(3));
        assert_eq!(usage.reasoning_tokens, TokenCount::Number(2));
    }

    #[test]
    fn non_streaming_computer_call_and_output_round_trip() {
        let body = json!({
            "id": "resp_c",
            "model": "gpt-5",
            "status": "completed",
            "output": [
                {
                    "type": "computer_call",
                    "id": "cu_1",
                    "call_id": "call_c",
                    "actions": [{"type": "click", "x": 1}]
                },
                {
                    "type": "computer_call_output",
                    "call_id": "call_c",
                    "output": {"image_url": "https://example.test/shot.png"}
                }
            ]
        });
        let events = parse_responses_response(&body, "gpt-5");
        let CanonicalEvent::ToolCallDelta {
            call_id,
            name,
            arguments_delta,
            ..
        } = &events[1]
        else {
            panic!("expected computer call");
        };
        assert_eq!(call_id, "call_c");
        assert_eq!(name.as_deref(), Some(COMPUTER_TOOL_NAME));
        assert_eq!(
            arguments_delta.as_deref(),
            Some("{\"actions\":[{\"type\":\"click\",\"x\":1}]}")
        );
        let CanonicalEvent::ToolResult {
            call_id, content, ..
        } = &events[2]
        else {
            panic!("expected computer output");
        };
        assert_eq!(call_id, "call_c");
        assert!(matches!(
            &content[0],
            ContentPart::Image { payload } if payload["image_url"] == "https://example.test/shot.png"
        ));
    }

    fn feed(frames: &[(&str, Value)]) -> (Vec<CanonicalEvent>, ResponsesStreamState) {
        let mut state = ResponsesStreamState::new("gpt-5");
        let mut events = Vec::new();
        for (name, payload) in frames {
            let data = payload.to_string();
            events.extend(parse_responses_sse_event(Some(name), &data, &mut state));
        }
        events.extend(state.finish());
        (events, state)
    }

    #[test]
    fn sse_parses_deltas_tool_calls_and_orders_the_terminal() {
        let frames = [
            (
                "response.created",
                json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}),
            ),
            (
                "response.output_text.delta",
                json!({"type": "response.output_text.delta", "delta": "he"}),
            ),
            (
                "response.output_text.delta",
                json!({"type": "response.output_text.delta", "delta": "llo"}),
            ),
            (
                "response.output_item.added",
                json!({"type": "response.output_item.added", "output_index": 1, "item": {
                    "type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "read", "arguments": ""
                }}),
            ),
            (
                "response.function_call_arguments.delta",
                json!({"type": "response.function_call_arguments.delta", "item_id": "fc_1", "delta": "{\"path\""}),
            ),
            (
                "response.function_call_arguments.delta",
                json!({"type": "response.function_call_arguments.delta", "item_id": "fc_1", "delta": ":1}"}),
            ),
            (
                "response.completed",
                json!({"type": "response.completed", "response": {
                    "id": "resp_1",
                    "status": "completed",
                    "usage": {"input_tokens": 5, "output_tokens": 3}
                }}),
            ),
        ];
        let (events, _state) = feed(&frames);
        assert!(matches!(events[0], CanonicalEvent::ResponseStart { .. }));
        let mut texts = Vec::new();
        let mut tool_deltas = Vec::new();
        for event in &events {
            match event {
                CanonicalEvent::ContentDelta {
                    content: ContentPart::Text { text },
                    ..
                } => texts.push(text.clone()),
                CanonicalEvent::ToolCallDelta {
                    call_id,
                    name,
                    arguments_delta,
                    ..
                } => tool_deltas.push((
                    call_id.clone(),
                    name.clone(),
                    arguments_delta.clone().unwrap_or_default(),
                )),
                _ => {}
            }
        }
        assert_eq!(texts, vec!["he".to_owned(), "llo".to_owned()]);
        assert_eq!(tool_deltas.len(), 2);
        assert_eq!(tool_deltas[0].0, "call_1");
        assert_eq!(tool_deltas[0].1.as_deref(), Some("read"));
        assert_eq!(tool_deltas[0].2, "{\"path\"");
        assert_eq!(tool_deltas[1].2, ":1}");
        let CanonicalEvent::Terminal {
            state,
            stop_reason,
            usage,
            ..
        } = events.last().unwrap()
        else {
            panic!("terminal must be last");
        };
        assert_eq!(*state, TerminalState::Complete);
        assert_eq!(*stop_reason, Some(CanonicalStopReason::ToolUse));
        assert_eq!(usage.as_ref().unwrap().input_tokens, 5);
        // Exactly one terminal event.
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, CanonicalEvent::Terminal { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn sse_reasoning_deltas_suppress_the_complete_item() {
        let frames = [
            (
                "response.reasoning_summary_text.delta",
                json!({"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "summary_index": 0, "delta": "think"}),
            ),
            (
                "response.output_item.done",
                json!({"type": "response.output_item.done", "item": {
                    "type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "think"}]
                }}),
            ),
            (
                "response.completed",
                json!({"type": "response.completed", "response": {"status": "completed"}}),
            ),
        ];
        let (events, _state) = feed(&frames);
        let reasoning: Vec<&str> = events
            .iter()
            .filter_map(|event| match event {
                CanonicalEvent::ContentDelta {
                    content:
                        ContentPart::Reasoning {
                            summary: Some(summary),
                            ..
                        },
                    ..
                } => Some(summary.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(reasoning, vec!["think"]);
    }

    #[test]
    fn sse_incomplete_and_failed_map_to_terminal_states() {
        let frames = [(
            "response.incomplete",
            json!({"type": "response.incomplete", "response": {"status": "incomplete"}}),
        )];
        let (events, _state) = feed(&frames);
        let CanonicalEvent::Terminal {
            state, stop_reason, ..
        } = events.last().unwrap()
        else {
            panic!("expected terminal");
        };
        assert_eq!(*state, TerminalState::Complete);
        assert_eq!(*stop_reason, Some(CanonicalStopReason::Length));

        let frames = [(
            "response.failed",
            json!({"type": "response.failed", "response": {"status": "failed"}}),
        )];
        let (events, _state) = feed(&frames);
        let CanonicalEvent::Terminal { state, .. } = events.last().unwrap() else {
            panic!("expected terminal");
        };
        assert_eq!(*state, TerminalState::Failed);
    }

    #[test]
    fn sse_error_frames_and_done_finish_the_stream() {
        let frames = [
            (
                "response.output_text.delta",
                json!({"type": "response.output_text.delta", "delta": "hi"}),
            ),
            ("", json!("[DONE]")),
        ];
        let (events, _state) = feed(&frames);
        assert!(matches!(
            events.last(),
            Some(CanonicalEvent::Terminal {
                state: TerminalState::Failed,
                ..
            })
        ));

        let mut state = ResponsesStreamState::new("gpt-5");
        let error = parse_responses_sse_event(
            Some("error"),
            &json!({"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}})
                .to_string(),
            &mut state,
        );
        assert!(matches!(
            error.last(),
            Some(CanonicalEvent::Error { category, message, .. })
                if category == "accounts_rate_limited" && message == "slow down"
        ));
    }

    #[test]
    fn sse_merges_usage_across_lifecycle_frames() {
        let mut state = ResponsesStreamState::new("gpt-5");
        parse_responses_sse_event(
            None,
            &json!({"type": "response.created", "response": {"usage": {
                "input_tokens": 10, "output_tokens": 0,
                "input_tokens_details": {"cached_tokens": 9}
            }}})
            .to_string(),
            &mut state,
        );
        let events = parse_responses_sse_event(
            None,
            &json!({"type": "response.completed", "response": {"status": "completed", "usage": {
                "input_tokens": 10, "output_tokens": 2,
                "input_tokens_details": {"cached_tokens": 0}
            }}})
            .to_string(),
            &mut state,
        );
        let CanonicalEvent::Terminal { usage, .. } = events.last().unwrap() else {
            panic!("expected terminal");
        };
        let usage = usage.as_ref().unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 2);
        assert_eq!(usage.cached_input_tokens, TokenCount::Number(9));
    }
}
