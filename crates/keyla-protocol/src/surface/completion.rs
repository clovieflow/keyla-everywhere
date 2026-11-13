//! Legacy text Completions surface. Port of `src/transport/surface/completion.ts`.

use keyla_core::{
    CacheHint, CanonicalEvent, CanonicalRequest, CanonicalStopReason, ContentPart,
    GenerationControls, ReasoningEffort, ReasoningIntent, SourceSurface, StopSequence,
    TerminalState,
};
use serde_json::{Map, Value, json};

use crate::surface::chat_encode::sse_data;
use crate::surface::events::event_text;
use crate::surface::usage::usage_to_chat_wire;

#[derive(Debug, Clone, Default)]
pub struct CompletionEncodeOptions {
    pub response_id: Option<String>,
    pub model: Option<String>,
    pub created: Option<i64>,
    pub prompt: Option<Value>,
    pub echo: bool,
    pub suffix: Option<String>,
}

fn text_prompts(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(prompt)) => vec![prompt.clone()],
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn stop_reason(events: &[CanonicalEvent]) -> Option<&'static str> {
    let terminal = events.iter().rev().find_map(|event| match event {
        CanonicalEvent::Terminal {
            stop_reason, state, ..
        } => Some((stop_reason, state)),
        _ => None,
    })?;
    match terminal {
        (Some(CanonicalStopReason::Length), _) => Some("length"),
        (Some(CanonicalStopReason::ContentFilter), _) => Some("content_filter"),
        (_, TerminalState::Complete) | (Some(CanonicalStopReason::Stop), _) => Some("stop"),
        _ => None,
    }
}

fn response_usage(events: &[CanonicalEvent]) -> Option<Value> {
    let terminal_usage = events.iter().rev().find_map(|event| match event {
        CanonicalEvent::Terminal { usage, .. } => usage.as_ref(),
        _ => None,
    });
    let event_usage = events.iter().rev().find_map(|event| match event {
        CanonicalEvent::Usage { usage, .. } => Some(usage),
        _ => None,
    });
    terminal_usage.or(event_usage).map(usage_to_chat_wire)
}

fn output_text(events: &[CanonicalEvent], options: &CompletionEncodeOptions) -> String {
    let mut text: String = events.iter().filter_map(event_text).collect();
    if options.echo {
        if let Some(Value::String(prompt)) = &options.prompt {
            text = format!("{prompt}{text}");
        }
    }
    if let Some(suffix) = &options.suffix {
        text.push_str(suffix);
    }
    text
}

fn model_for(events: &[CanonicalEvent], options: &CompletionEncodeOptions) -> String {
    if let Some(model) = &options.model {
        return model.clone();
    }
    events
        .iter()
        .find_map(|event| match event {
            CanonicalEvent::MessageStart { model, .. }
            | CanonicalEvent::ResponseStart { model, .. } => model.clone(),
            _ => None,
        })
        .unwrap_or_default()
}

/// Encodes canonical events as one `text_completion` body.
pub fn encode_completion_response(
    events: &[CanonicalEvent],
    options: &CompletionEncodeOptions,
) -> Value {
    let now = crate::translation::now_millis() / 1000;
    let mut response = Map::new();
    response.insert(
        "id".into(),
        json!(
            options
                .response_id
                .clone()
                .unwrap_or_else(|| format!("cmpl-{}", uuid::Uuid::new_v4()))
        ),
    );
    response.insert("object".into(), json!("text_completion"));
    response.insert("created".into(), json!(options.created.unwrap_or(now)));
    response.insert("model".into(), json!(model_for(events, options)));
    response.insert(
        "choices".into(),
        json!([{
            "text": output_text(events, options),
            "index": 0,
            "logprobs": null,
            "finish_reason": stop_reason(events),
        }]),
    );
    if let Some(usage) = response_usage(events) {
        response.insert("usage".into(), usage);
    }
    Value::Object(response)
}

/// Stateful streaming encoder for the legacy Completions wire.
#[derive(Debug)]
pub struct CompletionStreamEncoder {
    options: CompletionEncodeOptions,
    id: String,
    created: i64,
    terminal: Option<(Option<CanonicalStopReason>, TerminalState, Option<Value>)>,
    usage_event: Option<Value>,
    text_delta_count: u64,
}

impl CompletionStreamEncoder {
    pub fn new(options: CompletionEncodeOptions) -> Self {
        let id = options
            .response_id
            .clone()
            .unwrap_or_else(|| format!("cmpl-{}", uuid::Uuid::new_v4()));
        let created = options
            .created
            .unwrap_or_else(|| crate::translation::now_millis() / 1000);
        Self {
            options,
            id,
            created,
            terminal: None,
            usage_event: None,
            text_delta_count: 0,
        }
    }

    fn usage(&self) -> Option<Value> {
        let terminal_usage = self
            .terminal
            .as_ref()
            .and_then(|(_, _, usage)| usage.clone());
        terminal_usage.or_else(|| self.usage_event.clone())
    }

    fn chunk(&self, text: &str, finish_reason: Option<&str>, usage: Option<Value>) -> Value {
        let mut chunk = Map::new();
        chunk.insert("id".into(), json!(self.id));
        chunk.insert("object".into(), json!("text_completion"));
        chunk.insert("created".into(), json!(self.created));
        chunk.insert(
            "model".into(),
            json!(self.options.model.clone().unwrap_or_default()),
        );
        chunk.insert(
            "choices".into(),
            json!([{
                "text": text,
                "index": 0,
                "logprobs": null,
                "finish_reason": finish_reason,
            }]),
        );
        if let Some(usage) = usage {
            chunk.insert("usage".into(), usage);
        }
        Value::Object(chunk)
    }

    pub fn push(&mut self, event: &CanonicalEvent) -> Vec<Value> {
        match event {
            CanonicalEvent::Terminal {
                stop_reason,
                state,
                usage,
                ..
            } => {
                self.terminal =
                    Some((*stop_reason, *state, usage.as_ref().map(usage_to_chat_wire)));
                let reason = match (stop_reason, state) {
                    (Some(CanonicalStopReason::Length), _) => Some("length"),
                    (Some(CanonicalStopReason::ContentFilter), _) => Some("content_filter"),
                    (_, TerminalState::Complete) | (Some(CanonicalStopReason::Stop), _) => {
                        Some("stop")
                    }
                    _ => None,
                };
                vec![self.chunk("", reason, self.usage())]
            }
            CanonicalEvent::Usage { usage, .. } => {
                self.usage_event = Some(usage_to_chat_wire(usage));
                Vec::new()
            }
            _ => {
                let Some(text) = event_text(event) else {
                    return Vec::new();
                };
                self.text_delta_count += 1;
                let text = if self.options.echo && self.text_delta_count == 1 {
                    let prompt = match &self.options.prompt {
                        Some(Value::String(prompt)) => prompt.as_str(),
                        _ => "",
                    };
                    format!("{prompt}{text}")
                } else {
                    text.to_owned()
                };
                vec![self.chunk(&text, None, None)]
            }
        }
    }

    pub fn finish(&mut self) -> Vec<Value> {
        Vec::new()
    }

    /// One SSE data-only frame for a chunk.
    pub fn frame(chunk: &Value) -> String {
        sse_data(chunk)
    }
}

/// The legacy Completions surface adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct CompletionAdapter;

impl CompletionAdapter {
    pub fn matches_body_shape(&self, body: &Value) -> bool {
        let Some(map) = body.as_object() else {
            return false;
        };
        map.get("prompt")
            .is_some_and(|value| value.is_string() || value.is_array())
    }

    pub fn parse(&self, body: &Value) -> Result<CanonicalRequest, keyla_core::GatewayError> {
        let empty = Map::new();
        let value = body.as_object().unwrap_or(&empty);
        let prompts = text_prompts(value.get("prompt"));
        if prompts.is_empty() {
            return Err(keyla_core::GatewayError::new(
                keyla_core::GatewayErrorCode::InvalidRequest,
                400,
                "completion requests require a non-empty prompt",
                Map::new(),
            ));
        }
        let mut controls = GenerationControls::default();
        for field in ["temperature", "top_p"] {
            if let Some(value) = value.get(field).and_then(Value::as_f64) {
                if field == "temperature" {
                    controls.temperature = Some(value);
                } else {
                    controls.top_p = Some(value);
                }
            }
        }
        if let Some(value) = value.get("n").and_then(Value::as_f64) {
            controls.n = Some(value as i64);
        }
        if let Some(value) = value.get("seed").and_then(Value::as_f64) {
            controls.seed = Some(value as i64);
        }
        if let Some(value) = value.get("max_tokens").and_then(Value::as_f64) {
            controls.max_tokens = Some(value as i64);
        }
        match value.get("logprobs") {
            Some(Value::Number(number)) => {
                controls.logprobs = Some(true);
                controls.top_logprobs = number.as_f64().map(|value| value as i64);
            }
            Some(Value::Bool(flag)) => controls.logprobs = Some(*flag),
            _ => {}
        }
        match value.get("stop") {
            Some(Value::String(stop)) => controls.stop = Some(StopSequence::One(stop.clone())),
            Some(Value::Array(entries)) if entries.iter().all(Value::is_string) => {
                controls.stop = Some(StopSequence::Many(
                    entries
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                ));
            }
            _ => {}
        }
        let reasoning = value
            .get("reasoning_effort")
            .or_else(|| value.get("reasoning_level"))
            .and_then(Value::as_str)
            .and_then(|effort| match effort {
                "none" => Some(ReasoningEffort::None),
                "minimal" => Some(ReasoningEffort::Minimal),
                "low" => Some(ReasoningEffort::Low),
                "medium" => Some(ReasoningEffort::Medium),
                "high" => Some(ReasoningEffort::High),
                "xhigh" => Some(ReasoningEffort::Xhigh),
                "max" => Some(ReasoningEffort::Max),
                _ => None,
            })
            .map(|effort| ReasoningIntent {
                effort: Some(effort),
                ..Default::default()
            });
        let cache_key = value.get("prompt_cache_key").and_then(Value::as_str);
        let cache_hint = cache_key.is_some_and(|key| !key.is_empty())
            || value.get("cache_control").and_then(Value::as_str) == Some("auto");
        if let Some(key) = cache_key.filter(|key| !key.is_empty()) {
            controls
                .extensions
                .insert("extension:prompt_cache_key".into(), json!(key));
        }
        if let Some(prompt) = value.get("prompt") {
            controls
                .extensions
                .insert("extension:completion.prompt".into(), prompt.clone());
        }
        if let Some(echo) = value.get("echo").and_then(Value::as_bool) {
            controls
                .extensions
                .insert("extension:completion.echo".into(), json!(echo));
        }
        if let Some(suffix) = value.get("suffix").and_then(Value::as_str) {
            controls
                .extensions
                .insert("extension:completion.suffix".into(), json!(suffix));
        }
        Ok(CanonicalRequest {
            model: value
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            system: None,
            instructions: None,
            messages: prompts
                .into_iter()
                .map(|prompt| keyla_core::CanonicalMessage {
                    role: keyla_core::Role::User,
                    content: vec![ContentPart::Text { text: prompt }],
                    phase: None,
                })
                .collect(),
            tools: None,
            tool_choice: None,
            generation_controls: controls,
            reasoning,
            response_format: None,
            cache_hint: cache_hint.then_some(CacheHint::StablePrefix),
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
            stream: value.get("stream").and_then(Value::as_bool) == Some(true),
            source_surface: SourceSurface::Completion,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn terminal(stop: CanonicalStopReason, state: TerminalState) -> CanonicalEvent {
        CanonicalEvent::Terminal {
            sequence_number: 9,
            state,
            stop_reason: Some(stop),
            provider_stop_reason: None,
            stop_details: None,
            usage: None,
            event_id: None,
            response_id: None,
            timestamp: None,
        }
    }

    #[test]
    fn parse_requires_a_non_empty_prompt() {
        let adapter = CompletionAdapter;
        let error = adapter
            .parse(&json!({"model": "m", "prompt": []}))
            .unwrap_err();
        assert_eq!(error.code, keyla_core::GatewayErrorCode::InvalidRequest);
        let request = adapter
            .parse(&json!({"model": "m", "prompt": ["a", "b"], "echo": true}))
            .unwrap();
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.source_surface, SourceSurface::Completion);
        assert_eq!(
            request
                .generation_controls
                .extensions
                .get("extension:completion.echo"),
            Some(&json!(true))
        );
    }

    #[test]
    fn encoding_applies_echo_and_suffix_and_maps_stop_reason() {
        let events = vec![
            text_delta("world", 1),
            terminal(CanonicalStopReason::Stop, TerminalState::Complete),
        ];
        let value = encode_completion_response(
            &events,
            &CompletionEncodeOptions {
                model: Some("m".into()),
                prompt: Some(json!("hello ")),
                echo: true,
                suffix: Some("!".into()),
                ..Default::default()
            },
        );
        assert_eq!(value["object"], "text_completion");
        assert_eq!(value["choices"][0]["text"], "hello world!");
        assert_eq!(value["choices"][0]["finish_reason"], "stop");

        let length = vec![terminal(
            CanonicalStopReason::Length,
            TerminalState::Complete,
        )];
        let value = encode_completion_response(&length, &CompletionEncodeOptions::default());
        assert_eq!(value["choices"][0]["finish_reason"], "length");
    }

    #[test]
    fn stream_encoder_keeps_one_id_and_emits_terminal_once() {
        let mut encoder = CompletionStreamEncoder::new(CompletionEncodeOptions {
            model: Some("m".into()),
            created: Some(1_700_000_000),
            ..Default::default()
        });
        let first = encoder.push(&text_delta("a", 1));
        let second = encoder.push(&text_delta("b", 2));
        assert_eq!(first[0]["id"], second[0]["id"]);
        assert_eq!(first[0]["choices"][0]["text"], "a");
        assert_eq!(second[0]["choices"][0]["text"], "b");
        let terminal = encoder.push(&terminal(
            CanonicalStopReason::Stop,
            TerminalState::Complete,
        ));
        assert_eq!(terminal[0]["choices"][0]["finish_reason"], "stop");
        assert_eq!(terminal[0]["choices"][0]["text"], "");
    }
}
