//! Chat Completions response encoders. Port of
//! `src/transport/surface/chat/encode.ts`.

use std::collections::{HashMap, HashSet};

use keyla_core::{CanonicalEvent, CanonicalStopReason, ContentPart, TerminalState};
use serde_json::{Map, Value, json};

use crate::surface::events::{
    ReasoningSummaryIdentity, event_audio, event_obfuscation, event_reasoning_text, event_text,
    reasoning_summary_identity, reasoning_summary_separator,
};
use crate::surface::tool_identity::ToolCallTracker;
use crate::surface::usage::usage_to_chat_wire;

#[derive(Debug, Clone, Default)]
pub struct ChatEncodeOptions {
    pub response_id: Option<String>,
    pub model: Option<String>,
    pub created: Option<i64>,
    pub service_tier: Option<String>,
    pub include_usage: Option<bool>,
    pub include_obfuscation: Option<bool>,
    /// Operator-configured padding; outranks the synthesized placeholder.
    pub obfuscation: Option<String>,
    pub cancelled: bool,
}

impl ChatEncodeOptions {
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn with_response_id(mut self, id: impl Into<String>) -> Self {
        self.response_id = Some(id.into());
        self
    }

    pub fn with_created(mut self, created: i64) -> Self {
        self.created = Some(created);
        self
    }
}

fn start_event(events: &[CanonicalEvent]) -> Option<&CanonicalEvent> {
    events.iter().find(|event| {
        matches!(
            event,
            CanonicalEvent::ResponseStart { .. } | CanonicalEvent::MessageStart { .. }
        )
    })
}

fn start_field<'a>(event: &'a CanonicalEvent, field: &str) -> Option<&'a str> {
    match event {
        CanonicalEvent::ResponseStart {
            event_id,
            model,
            system_fingerprint,
            ..
        }
        | CanonicalEvent::MessageStart {
            event_id,
            model,
            system_fingerprint,
            ..
        } => match field {
            "event_id" => event_id.as_deref(),
            "model" => model.as_deref(),
            "system_fingerprint" => system_fingerprint.as_deref(),
            _ => None,
        },
        _ => None,
    }
}

pub fn get_response_id(options: &ChatEncodeOptions, events: &[CanonicalEvent]) -> String {
    if let Some(id) = &options.response_id {
        return id.clone();
    }
    start_event(events)
        .and_then(|event| start_field(event, "event_id"))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("chatcmpl-{}", uuid::Uuid::new_v4()))
}

pub fn get_model(options: &ChatEncodeOptions, events: &[CanonicalEvent]) -> String {
    if let Some(model) = &options.model {
        return model.clone();
    }
    start_event(events)
        .and_then(|event| start_field(event, "model"))
        .unwrap_or_default()
        .to_owned()
}

/// Resolves the `obfuscation` padding for a stream. A pinned operator value
/// outranks the synthesized placeholder; upstream padding may take over only
/// when nothing was pinned.
pub fn resolve_obfuscation(options: &ChatEncodeOptions) -> (Option<String>, bool) {
    if let Some(configured) = &options.obfuscation {
        return (Some(configured.clone()), true);
    }
    if options.include_obfuscation == Some(true) {
        return (Some("0000000000000000".into()), false);
    }
    (None, false)
}

fn merged_reasoning_text(events: &[CanonicalEvent]) -> String {
    let mut chunks = String::new();
    let mut previous_identity: Option<ReasoningSummaryIdentity> = None;
    let mut previous_text: Option<String> = None;
    for event in events {
        let Some(text) = event_reasoning_text(event) else {
            continue;
        };
        let identity = reasoning_summary_identity(event);
        let separator =
            if previous_text.is_some() && (previous_identity.is_none() || identity.is_none()) {
                "\n\n"
            } else {
                reasoning_summary_separator(
                    previous_identity.as_ref(),
                    identity.as_ref(),
                    previous_text.as_deref(),
                    text,
                )
            };
        chunks.push_str(separator);
        chunks.push_str(text);
        previous_identity = identity;
        previous_text = Some(text.to_owned());
    }
    chunks
}

pub fn finish_reason(stop_reason: Option<CanonicalStopReason>) -> &'static str {
    match stop_reason {
        Some(CanonicalStopReason::Stop) => "stop",
        Some(CanonicalStopReason::Length) => "length",
        Some(CanonicalStopReason::ToolUse) => "tool_calls",
        Some(CanonicalStopReason::ContentFilter) => "content_filter",
        Some(CanonicalStopReason::Refusal) => "content_filter",
        Some(CanonicalStopReason::Error) => "error",
        Some(CanonicalStopReason::Cancelled) => "error",
        Some(CanonicalStopReason::PauseTurn) => "stop",
        None => "stop",
    }
}

struct ToolEvent {
    id: String,
    name: Option<String>,
    arguments: String,
    index: Option<i64>,
}

fn event_tool_call(event: &CanonicalEvent) -> Option<ToolEvent> {
    match event {
        CanonicalEvent::ToolCallDelta {
            call_id,
            index,
            name,
            arguments_delta,
            ..
        } => Some(ToolEvent {
            id: call_id.clone(),
            name: name.clone(),
            arguments: arguments_delta.clone().unwrap_or_default(),
            index: (*index).filter(|index| *index >= 0),
        }),
        CanonicalEvent::ContentDelta {
            content:
                ContentPart::ToolCall {
                    call_id,
                    name,
                    arguments,
                    index,
                    ..
                },
            ..
        } => Some(ToolEvent {
            id: call_id.clone(),
            name: Some(name.clone()),
            arguments: match arguments {
                Value::String(value) => value.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            },
            index: (*index).filter(|index| *index >= 0),
        }),
        _ => None,
    }
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// Encodes canonical events as one non-streaming JSON completion.
pub fn json_completion(
    events: &[CanonicalEvent],
    options: &ChatEncodeOptions,
    model: &str,
    id: &str,
    created: i64,
) -> Value {
    let content: String = events.iter().filter_map(event_text).collect();
    let reasoning_content = merged_reasoning_text(events);
    let mut tool_calls: std::collections::BTreeMap<
        i64,
        crate::surface::tool_identity::ToolCallState,
    > = std::collections::BTreeMap::new();
    let mut tracker = ToolCallTracker::new();
    let mut terminal_finish_reason: Option<&'static str> = None;
    let mut usage: Option<Value> = None;
    let cancelled = options.cancelled;

    for event in events {
        if let Some(tool) = event_tool_call(event) {
            let (index, _, state) = tracker.track(
                &tool.id,
                tool.name.as_deref(),
                Some(&tool.arguments),
                tool.index,
                None,
            );
            tool_calls.insert(index, state);
        }
        match event {
            CanonicalEvent::Usage { usage: record, .. } => {
                usage = Some(usage_to_chat_wire(record));
            }
            CanonicalEvent::Terminal {
                stop_reason,
                state,
                usage: terminal_usage,
                ..
            } => {
                terminal_finish_reason = Some(finish_reason(*stop_reason));
                if !cancelled && *state != TerminalState::Aborted {
                    if let Some(record) = terminal_usage {
                        usage = Some(usage_to_chat_wire(record));
                    }
                }
            }
            _ => {}
        }
    }
    if cancelled {
        usage = None;
    }

    let mut message = Map::new();
    message.insert("role".into(), json!("assistant"));
    message.insert(
        "content".into(),
        if content.is_empty() {
            Value::Null
        } else {
            Value::String(content)
        },
    );
    if !reasoning_content.is_empty() {
        message.insert("reasoning_content".into(), Value::String(reasoning_content));
    }
    if !tool_calls.is_empty() {
        let calls: Vec<Value> = tool_calls
            .values()
            .filter(|tool| {
                tool.name
                    .as_deref()
                    .is_some_and(|name| !name.trim().is_empty())
            })
            .map(|tool| {
                json!({
                    "id": tool.id,
                    "type": "function",
                    "function": {
                        "name": tool.name.clone().unwrap_or_default(),
                        "arguments": if tool.arguments.is_empty() { "{}" } else { tool.arguments.as_str() },
                    }
                })
            })
            .collect();
        message.insert("tool_calls".into(), Value::Array(calls));
    }
    if let Some(audio) = events.iter().filter_map(event_audio).next_back() {
        message.insert("audio".into(), Value::Object(audio.clone()));
    }

    let mut result = Map::new();
    result.insert("id".into(), json!(id));
    result.insert("object".into(), json!("chat.completion"));
    result.insert("created".into(), json!(created));
    result.insert("model".into(), json!(model));
    result.insert(
        "choices".into(),
        json!([{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": terminal_finish_reason,
        }]),
    );
    result.insert("usage".into(), usage.unwrap_or(Value::Null));

    if events.iter().any(|event| {
        matches!(
            event,
            CanonicalEvent::Terminal {
                state: TerminalState::Failed,
                ..
            }
        )
    }) {
        let (code, message) = events
            .iter()
            .rev()
            .find_map(|event| match event {
                CanonicalEvent::Terminal {
                    state: TerminalState::Failed,
                    stop_reason,
                    ..
                } => Some((
                    stop_reason
                        .map(CanonicalStopReason::as_str)
                        .unwrap_or("provider_error"),
                    "The upstream response failed",
                )),
                _ => None,
            })
            .unwrap_or(("provider_error", "The upstream response failed"));
        result.insert(
            "error".into(),
            json!({
                "type": "server_error",
                "code": code,
                "message": message,
            }),
        );
    }
    if let Some(service_tier) = &options.service_tier {
        result.insert("service_tier".into(), json!(service_tier));
    }
    if let Some(fingerprint) =
        start_event(events).and_then(|event| start_field(event, "system_fingerprint"))
    {
        result.insert("system_fingerprint".into(), json!(fingerprint));
    }
    Value::Object(result)
}

/// Incremental SSE encoder for Chat Completions.
#[derive(Debug)]
pub struct ChatStreamEncoder {
    options: ChatEncodeOptions,
    base_id: String,
    base_model: String,
    created: i64,
    service_tier: Option<String>,
    include_usage: Option<bool>,
    cancelled: bool,
    configured_obfuscation: Option<String>,
    obfuscation_pinned: bool,
    tracker: ToolCallTracker,
    emitted_arguments: HashMap<String, usize>,
    emitted_tool_names: HashSet<String>,
    final_usage: Option<Value>,
    terminal_state: Option<TerminalState>,
    emitted_any: bool,
    previous_reasoning_identity: Option<ReasoningSummaryIdentity>,
    previous_reasoning_text: Option<String>,
}

impl ChatStreamEncoder {
    pub fn new(options: ChatEncodeOptions) -> Self {
        let base_model = options.model.clone().unwrap_or_default();
        let base_id = options
            .response_id
            .clone()
            .unwrap_or_else(|| format!("chatcmpl-{}", uuid::Uuid::new_v4()));
        let created = options.created.unwrap_or_else(now_seconds);
        let service_tier = options.service_tier.clone();
        let include_usage = options.include_usage;
        let cancelled = options.cancelled;
        let (configured_obfuscation, obfuscation_pinned) = resolve_obfuscation(&options);
        Self {
            options,
            base_id,
            base_model,
            created,
            service_tier,
            include_usage,
            cancelled,
            configured_obfuscation,
            obfuscation_pinned,
            tracker: ToolCallTracker::new(),
            emitted_arguments: HashMap::new(),
            emitted_tool_names: HashSet::new(),
            final_usage: None,
            terminal_state: None,
            emitted_any: false,
            previous_reasoning_identity: None,
            previous_reasoning_text: None,
        }
    }

    pub fn with_created(mut self, created: i64) -> Self {
        self.created = created;
        self
    }

    fn with_base(&self, choices: Value, usage: Value, obfuscation: Option<&str>) -> Value {
        let mut chunk = Map::new();
        chunk.insert("id".into(), json!(self.base_id));
        chunk.insert("object".into(), json!("chat.completion.chunk"));
        chunk.insert("created".into(), json!(self.created));
        chunk.insert("model".into(), json!(self.base_model));
        if let Some(service_tier) = &self.service_tier {
            chunk.insert("service_tier".into(), json!(service_tier));
        }
        chunk.insert("choices".into(), choices);
        chunk.insert("usage".into(), usage);
        if let Some(obfuscation) = obfuscation {
            chunk.insert("obfuscation".into(), json!(obfuscation));
        }
        Value::Object(chunk)
    }

    fn delta_chunk(&self, delta: Value, obfuscation: Option<&str>) -> Value {
        self.with_base(
            json!([{ "index": 0, "delta": delta, "finish_reason": null }]),
            Value::Null,
            obfuscation,
        )
    }

    pub fn push(&mut self, event: &CanonicalEvent) -> Vec<Value> {
        if let CanonicalEvent::Usage { usage, .. } = event {
            self.final_usage = Some(usage_to_chat_wire(usage));
            return Vec::new();
        }

        if let CanonicalEvent::MessageStart {
            model, event_id, ..
        }
        | CanonicalEvent::ResponseStart {
            model, event_id, ..
        } = event
        {
            if self.options.model.is_none() && self.options.response_id.is_none() {
                if let Some(model) = model {
                    if *model != self.base_model {
                        self.base_model = model.clone();
                    }
                }
                if let Some(event_id) = event_id {
                    if *event_id != self.base_id {
                        self.base_id = event_id.clone();
                    }
                }
            }
        }

        let event_padding = event_obfuscation(event).map(str::to_owned);
        if let Some(padding) = event_padding {
            if !self.obfuscation_pinned {
                self.configured_obfuscation = Some(padding);
            }
        }
        let padding = self.configured_obfuscation.clone();
        let padding_ref = padding.as_deref();

        match event {
            CanonicalEvent::MessageStart { .. } | CanonicalEvent::ResponseStart { .. } => {
                self.emitted_any = true;
                vec![self.delta_chunk(json!({"role":"assistant","content":""}), padding_ref)]
            }
            _ => {
                if let Some(reasoning) = event_reasoning_text(event) {
                    let identity = reasoning_summary_identity(event);
                    let separator = reasoning_summary_separator(
                        self.previous_reasoning_identity.as_ref(),
                        identity.as_ref(),
                        self.previous_reasoning_text.as_deref(),
                        reasoning,
                    );
                    self.previous_reasoning_identity = identity;
                    self.previous_reasoning_text = Some(reasoning.to_owned());
                    self.emitted_any = true;
                    return vec![self.delta_chunk(
                        json!({"reasoning_content": format!("{separator}{reasoning}")}),
                        padding_ref,
                    )];
                }
                if let Some(text) = event_text(event) {
                    self.emitted_any = true;
                    return vec![self.delta_chunk(json!({"content": text}), padding_ref)];
                }
                if let Some(audio) = event_audio(event) {
                    self.emitted_any = true;
                    return vec![
                        self.delta_chunk(
                            json!({"audio": Value::Object(audio.clone())}),
                            padding_ref,
                        ),
                    ];
                }
                if let Some(tool) = event_tool_call(event) {
                    let (index, is_first, state) = self.tracker.track(
                        &tool.id,
                        tool.name.as_deref(),
                        Some(&tool.arguments),
                        tool.index,
                        None,
                    );
                    let mut delta = Map::new();
                    delta.insert("index".into(), json!(index));
                    if is_first {
                        delta.insert("id".into(), json!(tool.id));
                    }
                    delta.insert("type".into(), json!("function"));
                    let mut function = Map::new();
                    if let Some(name) = &state.name {
                        if self.emitted_tool_names.insert(state.id.clone()) {
                            function.insert("name".into(), json!(name));
                        }
                    }
                    // OpenAI streaming clients concatenate argument deltas
                    // themselves. The tracker stores the accumulated string
                    // for non-streaming assembly, so send only the suffix that
                    // has not already been emitted; resending the whole
                    // accumulated object produces duplicated JSON and breaks
                    // tool calls that arrive in multiple frames.
                    let sent = self.emitted_arguments.get(&state.id).copied().unwrap_or(0);
                    let pending = state.arguments.get(sent..).unwrap_or("");
                    function.insert("arguments".into(), json!(pending));
                    self.emitted_arguments
                        .insert(state.id.clone(), state.arguments.len());
                    delta.insert("function".into(), Value::Object(function));
                    self.emitted_any = true;
                    return vec![
                        self.delta_chunk(
                            json!({"tool_calls": [Value::Object(delta)]}),
                            padding_ref,
                        ),
                    ];
                }
                match event {
                    CanonicalEvent::Keepalive { .. } => {
                        self.emitted_any = true;
                        vec![self.with_base(json!([]), Value::Null, padding_ref)]
                    }
                    CanonicalEvent::Terminal {
                        state,
                        stop_reason,
                        usage,
                        ..
                    } => {
                        self.terminal_state = Some(*state);
                        if !self.cancelled && *state != TerminalState::Aborted {
                            if let Some(usage) = usage {
                                self.final_usage = Some(usage_to_chat_wire(usage));
                            }
                        }
                        let reason = finish_reason(*stop_reason);
                        let usage = if self.cancelled || *state == TerminalState::Aborted {
                            Value::Null
                        } else {
                            self.final_usage.clone().unwrap_or(Value::Null)
                        };
                        self.emitted_any = true;
                        vec![self.with_base(
                            json!([{ "index": 0, "delta": {}, "finish_reason": reason }]),
                            usage,
                            padding_ref,
                        )]
                    }
                    _ => Vec::new(),
                }
            }
        }
    }

    pub fn finish(&self) -> Vec<Value> {
        let mut result = Vec::new();
        if self.terminal_state.is_none() && !self.emitted_any {
            result.push(self.with_base(
                json!([]),
                Value::Null,
                self.configured_obfuscation.as_deref(),
            ));
        }
        if self.include_usage == Some(true)
            && self.terminal_state == Some(TerminalState::Complete)
            && !self.cancelled
            && self.final_usage.is_some()
        {
            result.push(self.with_base(
                json!([]),
                self.final_usage.clone().unwrap_or(Value::Null),
                self.configured_obfuscation.as_deref(),
            ));
        }
        result
    }
}

/// Encodes a wire value as UTF-8 JSON bytes.
pub fn as_json_bytes(value: &Value) -> Vec<u8> {
    json_bytes(value)
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats a data-only SSE frame (`data: <json>\n\n`).
pub fn sse_data(value: &Value) -> String {
    format!(
        "data: {}\n\n",
        serde_json::to_string(value).unwrap_or_default()
    )
}

/// Formats a named SSE frame (`event: <name>\ndata: <json>\n\n`).
pub fn sse_event(name: &str, value: &Value) -> String {
    format!(
        "event: {name}\ndata: {}\n\n",
        serde_json::to_string(value).unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{ContentPart, UsageRecord};

    fn text_delta(text: &str, sequence: u64) -> CanonicalEvent {
        CanonicalEvent::ContentDelta {
            sequence_number: sequence,
            content: ContentPart::Text { text: text.into() },
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            content_index: None,
            timestamp: None,
        }
    }

    fn terminal(
        stop: CanonicalStopReason,
        state: TerminalState,
        usage: Option<UsageRecord>,
    ) -> CanonicalEvent {
        CanonicalEvent::Terminal {
            sequence_number: 9,
            state,
            stop_reason: Some(stop),
            provider_stop_reason: None,
            stop_details: None,
            usage,
            event_id: None,
            response_id: None,
            timestamp: None,
        }
    }

    fn usage() -> UsageRecord {
        UsageRecord {
            input_tokens: 3,
            cached_input_tokens: keyla_core::TokenCount::Unavailable,
            cache_write_tokens: keyla_core::TokenCount::Unavailable,
            uncached_input_tokens: keyla_core::TokenCount::Unavailable,
            output_tokens: 2,
            reasoning_tokens: keyla_core::TokenCount::Unavailable,
            estimated_cost: None,
            credit_used: None,
            total_tokens: None,
            details: None,
        }
    }

    #[test]
    fn json_completion_assembles_content_usage_and_finish_reason() {
        let events = vec![
            CanonicalEvent::MessageStart {
                sequence_number: 0,
                event_id: Some("chatcmpl-1".into()),
                response_id: None,
                model: Some("gpt-test".into()),
                system_fingerprint: Some("fp_1".into()),
                timestamp: None,
            },
            text_delta("hel", 1),
            text_delta("lo", 2),
            CanonicalEvent::Usage {
                sequence_number: 3,
                usage: usage(),
                event_id: None,
                response_id: None,
                timestamp: None,
            },
            terminal(CanonicalStopReason::Stop, TerminalState::Complete, None),
        ];
        let value = json_completion(
            &events,
            &ChatEncodeOptions::default(),
            "gpt-test",
            "chatcmpl-1",
            1_700_000_000,
        );
        assert_eq!(value["id"], "chatcmpl-1");
        assert_eq!(value["object"], "chat.completion");
        assert_eq!(value["choices"][0]["message"]["content"], "hello");
        assert_eq!(value["choices"][0]["finish_reason"], "stop");
        assert_eq!(value["usage"]["prompt_tokens"], 3);
        assert_eq!(value["system_fingerprint"], "fp_1");
        assert!(value.get("error").is_none());
    }

    #[test]
    fn json_completion_marks_failed_terminals() {
        let events = vec![
            text_delta("x", 1),
            terminal(CanonicalStopReason::Error, TerminalState::Failed, None),
        ];
        let value = json_completion(&events, &ChatEncodeOptions::default(), "m", "id", 0);
        assert_eq!(value["choices"][0]["finish_reason"], "error");
        assert_eq!(value["error"]["code"], "error");
        assert_eq!(value["error"]["type"], "server_error");
    }

    #[test]
    fn json_completion_keeps_zero_argument_calls_valid() {
        let events = vec![
            CanonicalEvent::ToolCallDelta {
                sequence_number: 1,
                call_id: "call_1".into(),
                index: Some(0),
                name: Some("ping".into()),
                arguments_delta: Some(String::new()),
                event_id: None,
                response_id: None,
                item_id: None,
                output_index: None,
                timestamp: None,
            },
            terminal(CanonicalStopReason::ToolUse, TerminalState::Complete, None),
        ];
        let value = json_completion(&events, &ChatEncodeOptions::default(), "m", "id", 0);
        assert_eq!(
            value["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
            "{}"
        );
        assert_eq!(value["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn stream_encoder_sends_argument_deltas_not_the_accumulated_object() {
        let mut encoder = ChatStreamEncoder::new(ChatEncodeOptions::default());
        let first = encoder.push(&CanonicalEvent::ToolCallDelta {
            sequence_number: 1,
            call_id: "call_1".into(),
            index: Some(0),
            name: Some("read".into()),
            arguments_delta: Some("{\"a\"".into()),
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            timestamp: None,
        });
        assert_eq!(
            first[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "{\"a\""
        );
        let second = encoder.push(&CanonicalEvent::ToolCallDelta {
            sequence_number: 2,
            call_id: "call_1".into(),
            index: None,
            name: None,
            arguments_delta: Some(":1}".into()),
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            timestamp: None,
        });
        assert_eq!(
            second[0]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            ":1}"
        );
        assert!(
            second[0]["choices"][0]["delta"]["tool_calls"][0]["function"]
                .get("name")
                .is_none()
        );
    }

    #[test]
    fn stream_encoder_emits_role_content_and_terminal() {
        let mut encoder = ChatStreamEncoder::new(
            ChatEncodeOptions::default()
                .with_model("gpt-test")
                .with_response_id("chatcmpl-1")
                .with_created(1_700_000_000),
        );
        let start = CanonicalEvent::MessageStart {
            sequence_number: 0,
            event_id: Some("chatcmpl-1".into()),
            response_id: None,
            model: Some("gpt-test".into()),
            system_fingerprint: None,
            timestamp: None,
        };
        let chunks = encoder.push(&start);
        assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
        let chunks = encoder.push(&text_delta("hi", 1));
        assert_eq!(chunks[0]["choices"][0]["delta"]["content"], "hi");
        let chunks = encoder.push(&terminal(
            CanonicalStopReason::Stop,
            TerminalState::Complete,
            Some(usage()),
        ));
        assert_eq!(chunks[0]["choices"][0]["finish_reason"], "stop");
        assert_eq!(chunks[0]["usage"]["prompt_tokens"], 3);
        assert!(encoder.finish().is_empty());

        let mut with_usage = ChatStreamEncoder::new(ChatEncodeOptions {
            include_usage: Some(true),
            ..ChatEncodeOptions::default()
        });
        with_usage.push(&text_delta("x", 1));
        with_usage.push(&terminal(
            CanonicalStopReason::Stop,
            TerminalState::Complete,
            Some(usage()),
        ));
        let frames = with_usage.finish();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["usage"]["total_tokens"], 5);
        assert_eq!(frames[0]["choices"], json!([]));
    }
}
