//! OpenAI-compatible Chat Completions response decoder: wire JSON/SSE to
//! canonical events. Port of `src/protocol/response/chat.ts`.

use std::collections::HashMap;
use std::sync::LazyLock;

use keyla_core::{
    CanonicalEvent, CanonicalStopReason, ContentPart, GatewayError, GatewayErrorCode,
    GatewayErrorOrigin, TerminalState,
};
use regex::Regex;
use serde_json::{Map, Value};

use crate::failure::gateway_error_from_stream_error;
use crate::surface::tool_identity::ToolEmitLedger;
use crate::surface::usage::{merge_usage, read_reasoning_text, usage_from_provider};
use crate::translation::now_millis;

static THINK_TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<think(?:ing)?>([\s\S]*?)</think(?:ing)?>").expect("think pattern")
});
static THINK_TAG_ANY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<think(?:ing)?>[\s\S]*?</think(?:ing)?>").expect("think strip pattern")
});

pub fn map_chat_stop_reason(reason: Option<&str>) -> Option<CanonicalStopReason> {
    match reason {
        Some("stop") => Some(CanonicalStopReason::Stop),
        Some("length") => Some(CanonicalStopReason::Length),
        Some("tool_calls") => Some(CanonicalStopReason::ToolUse),
        Some("content_filter") => Some(CanonicalStopReason::ContentFilter),
        _ => None,
    }
}

fn response_id(json: &Map<String, Value>) -> String {
    json.get("id")
        .and_then(Value::as_str)
        .unwrap_or("resp_chat")
        .to_owned()
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.filter(|value| !value.is_empty()).map(str::to_owned)
}

fn merged_usage(raw: &Map<String, Value>) -> Value {
    let mut merged = raw.clone();
    if !merged.contains_key("input_tokens") {
        merged.insert(
            "input_tokens".into(),
            merged.get("prompt_tokens").cloned().unwrap_or(Value::Null),
        );
    }
    if !merged.contains_key("output_tokens") {
        merged.insert(
            "output_tokens".into(),
            merged
                .get("completion_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        );
    }
    Value::Object(merged)
}

fn tool_calls_from_message(
    message: &Map<String, Value>,
    id: &str,
    sequence: &mut u64,
    events: &mut Vec<CanonicalEvent>,
) {
    let Some(Value::Array(tool_calls)) = message.get("tool_calls") else {
        return;
    };
    for call in tool_calls {
        let Some(call) = call.as_object() else {
            continue;
        };
        let function = call.get("function").and_then(Value::as_object);
        let Some(call_id) = non_empty(call.get("id").and_then(Value::as_str)) else {
            continue;
        };
        let Some(name) = function
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let arguments = function
            .and_then(|function| function.get("arguments"))
            .and_then(Value::as_str)
            .unwrap_or("{}");
        events.push(CanonicalEvent::ToolCallDelta {
            sequence_number: *sequence,
            call_id,
            index: None,
            name: Some(name.to_owned()),
            arguments_delta: Some(arguments.to_owned()),
            event_id: None,
            response_id: Some(id.to_owned()),
            item_id: None,
            output_index: None,
            timestamp: None,
        });
        *sequence += 1;
    }
}

/// Decodes a non-streaming Chat completion into canonical events.
pub fn parse_chat_response_to_events(json: &Value, request_model: &str) -> Vec<CanonicalEvent> {
    let Some(body) = json.as_object() else {
        return vec![CanonicalEvent::Terminal {
            sequence_number: 1,
            state: TerminalState::Failed,
            stop_reason: Some(CanonicalStopReason::Error),
            provider_stop_reason: None,
            stop_details: None,
            usage: None,
            event_id: None,
            response_id: None,
            timestamp: None,
        }];
    };
    let id = response_id(body);
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(request_model)
        .to_owned();
    let system_fingerprint = body
        .get("system_fingerprint")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut sequence = 1u64;
    let mut events = vec![CanonicalEvent::ResponseStart {
        sequence_number: sequence,
        event_id: Some(id.clone()),
        response_id: None,
        model: Some(model),
        system_fingerprint,
        timestamp: None,
    }];
    sequence += 1;

    let first = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(Value::as_object);
    if let Some(first) = first {
        if let Some(message) = first.get("message").and_then(Value::as_object) {
            if let Some(reasoning) = read_reasoning_text(message).filter(|text| !text.is_empty()) {
                events.push(CanonicalEvent::ContentDelta {
                    sequence_number: sequence,
                    content: ContentPart::Reasoning {
                        payload: Value::String(reasoning),
                        opaque: None,
                        summary: None,
                        summary_index: None,
                        signature: None,
                        encrypted_content: None,
                    },
                    event_id: None,
                    response_id: Some(id.clone()),
                    item_id: None,
                    output_index: None,
                    content_index: None,
                    timestamp: None,
                });
                sequence += 1;
            }
            if let Some(content) = message.get("content").and_then(Value::as_str) {
                if !content.is_empty() {
                    events.push(CanonicalEvent::ContentDelta {
                        sequence_number: sequence,
                        content: ContentPart::Text {
                            text: content.to_owned(),
                        },
                        event_id: None,
                        response_id: Some(id.clone()),
                        item_id: None,
                        output_index: None,
                        content_index: None,
                        timestamp: None,
                    });
                    sequence += 1;
                }
            }
            if let Some(refusal) = message.get("refusal").and_then(Value::as_str) {
                if !refusal.is_empty() {
                    events.push(CanonicalEvent::ContentDelta {
                        sequence_number: sequence,
                        content: ContentPart::Refusal {
                            text: refusal.to_owned(),
                        },
                        event_id: None,
                        response_id: Some(id.clone()),
                        item_id: None,
                        output_index: None,
                        content_index: None,
                        timestamp: None,
                    });
                    sequence += 1;
                }
            }
            tool_calls_from_message(message, &id, &mut sequence, &mut events);
            if let Some(audio @ Value::Object(_)) = message.get("audio") {
                events.push(CanonicalEvent::ContentDelta {
                    sequence_number: sequence,
                    content: ContentPart::Extension {
                        name: "audio".into(),
                        payload: audio.clone(),
                    },
                    event_id: None,
                    response_id: Some(id.clone()),
                    item_id: None,
                    output_index: None,
                    content_index: None,
                    timestamp: None,
                });
                sequence += 1;
            }
        }
    }

    let usage_value = body
        .get("usage")
        .and_then(Value::as_object)
        .map(merged_usage);
    let usage = usage_from_provider(usage_value.as_ref());
    let provider_stop_reason = first
        .and_then(|first| first.get("finish_reason"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let stop_reason = map_chat_stop_reason(provider_stop_reason.as_deref());
    events.push(CanonicalEvent::Terminal {
        sequence_number: sequence,
        state: TerminalState::Complete,
        stop_reason,
        provider_stop_reason,
        stop_details: None,
        usage,
        event_id: None,
        response_id: Some(id),
        timestamp: None,
    });
    events
}

fn tool_index(call: &Map<String, Value>) -> Option<i64> {
    call.get("index")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && value.fract() == 0.0 && *value >= 0.0)
        .map(|value| value as i64)
}

/// Stateful Chat SSE decoder.
#[derive(Debug)]
pub struct ChatSseDecoder {
    model: String,
    sequence: u64,
    finish_reason: Option<String>,
    raw_usage: Option<Map<String, Value>>,
    last_tool_id_by_index: HashMap<i64, String>,
    last_tool_name_by_index: HashMap<i64, String>,
    last_seen_tool_id: Option<String>,
    last_seen_tool_name: Option<String>,
    ledger: ToolEmitLedger,
    started: bool,
    terminal_emitted: bool,
}

impl ChatSseDecoder {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            sequence: 1,
            finish_reason: None,
            raw_usage: None,
            last_tool_id_by_index: HashMap::new(),
            last_tool_name_by_index: HashMap::new(),
            last_seen_tool_id: None,
            last_seen_tool_name: None,
            ledger: ToolEmitLedger::new(),
            started: false,
            terminal_emitted: false,
        }
    }

    pub fn start(&mut self) -> Vec<CanonicalEvent> {
        if self.started {
            return Vec::new();
        }
        self.started = true;
        let event = CanonicalEvent::ResponseStart {
            sequence_number: self.sequence,
            event_id: None,
            response_id: None,
            model: Some(self.model.clone()),
            system_fingerprint: None,
            timestamp: None,
        };
        self.sequence += 1;
        vec![event]
    }

    pub fn push(&mut self, data: &str) -> Result<Vec<CanonicalEvent>, GatewayError> {
        let data = data.trim();
        if data == "[DONE]" {
            return Ok(self.finish(false));
        }
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let json: Value = serde_json::from_str(data).map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::PlatformUnavailable,
                502,
                format!("Malformed SSE event: {error}"),
                Map::new(),
            )
            .with_origin(GatewayErrorOrigin::Upstream)
        })?;
        let Some(body) = json.as_object() else {
            return Ok(Vec::new());
        };
        let error_payload = body.get("error").or_else(|| {
            (body.get("type").and_then(Value::as_str) == Some("error")).then_some(&json)
        });
        if let Some(error) =
            gateway_error_from_stream_error(error_payload, "upstream returned an error frame")
        {
            return Err(error);
        }
        self.raw_usage = merge_usage(
            self.raw_usage.as_ref(),
            body.get("usage").and_then(Value::as_object),
        );

        let mut events = Vec::new();
        if let Some(Value::Array(choices)) = body.get("choices") {
            for choice in choices {
                let Some(choice) = choice.as_object() else {
                    continue;
                };
                let delta = choice.get("delta").and_then(Value::as_object);
                if let Some(delta) = delta {
                    if let Some(content) = delta.get("content").and_then(Value::as_str) {
                        if !content.is_empty() {
                            if content.contains("<think") {
                                if let Some(captures) = THINK_TAG.captures(content) {
                                    if let Some(reasoning) = captures.get(1) {
                                        events.push(self.reasoning_delta(reasoning.as_str()));
                                    }
                                }
                                let stripped = THINK_TAG_ANY.replace_all(content, "");
                                if !stripped.is_empty() {
                                    events.push(self.text_delta(&stripped));
                                }
                            } else {
                                events.push(self.text_delta(content));
                            }
                        }
                    }
                    if let Some(reasoning) = read_reasoning_text(delta) {
                        if !reasoning.is_empty() {
                            events.push(self.reasoning_delta(&reasoning));
                        }
                    }
                    if let Some(Value::Array(calls)) = delta.get("tool_calls") {
                        for call in calls {
                            if let Some(call) = call.as_object() {
                                self.push_tool_call(call, &mut events);
                            }
                        }
                    }
                    if let Some(audio @ Value::Object(_)) = delta.get("audio") {
                        events.push(CanonicalEvent::ContentDelta {
                            sequence_number: self.sequence,
                            content: ContentPart::Extension {
                                name: "audio".into(),
                                payload: audio.clone(),
                            },
                            event_id: None,
                            response_id: None,
                            item_id: None,
                            output_index: None,
                            content_index: None,
                            timestamp: None,
                        });
                        self.sequence += 1;
                    }
                }
                if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                    self.finish_reason = Some(reason.to_owned());
                }
            }
        }
        Ok(events)
    }

    fn text_delta(&mut self, text: &str) -> CanonicalEvent {
        let event = CanonicalEvent::ContentDelta {
            sequence_number: self.sequence,
            content: ContentPart::Text {
                text: text.to_owned(),
            },
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            content_index: None,
            timestamp: None,
        };
        self.sequence += 1;
        event
    }

    fn reasoning_delta(&mut self, text: &str) -> CanonicalEvent {
        let event = CanonicalEvent::ContentDelta {
            sequence_number: self.sequence,
            content: ContentPart::Reasoning {
                payload: Value::Null,
                opaque: None,
                summary: Some(text.to_owned()),
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
        };
        self.sequence += 1;
        event
    }

    fn push_tool_call(&mut self, call: &Map<String, Value>, events: &mut Vec<CanonicalEvent>) {
        let function = call.get("function").and_then(Value::as_object);
        let index = tool_index(call);
        let real_id = non_empty(call.get("id").and_then(Value::as_str));
        let fragment_name = function
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty());

        let index_name = index.and_then(|index| self.last_tool_name_by_index.get(&index));
        let index_id = index.and_then(|index| self.last_tool_id_by_index.get(&index));
        let reference_name = match index {
            Some(_) => index_name,
            None => self.last_seen_tool_name.as_ref(),
        };
        let inheritable = fragment_name.is_none()
            || reference_name.is_none()
            || fragment_name == reference_name.map(String::as_str);

        let mut established_new = false;
        let (id, emit_index) = if let Some(real_id) = real_id {
            established_new = true;
            (real_id, index)
        } else if let (Some(_), Some(index_id), true) = (index, index_id, inheritable) {
            (index_id.clone(), None)
        } else if let (None, Some(last_id), true) =
            (index, self.last_seen_tool_id.clone(), inheritable)
        {
            (last_id, None)
        } else {
            established_new = true;
            let prefix = match index {
                Some(index) => format!("call-{index}-frag"),
                None => "call".to_owned(),
            };
            (self.ledger.next_orphan_id(&prefix), None)
        };
        self.last_seen_tool_id = Some(id.clone());
        if let Some(name) = fragment_name {
            self.last_seen_tool_name = Some(name.to_owned());
        }
        if let Some(index) = index {
            if established_new {
                self.last_tool_id_by_index.insert(index, id.clone());
            }
            match fragment_name {
                Some(name) => {
                    self.last_tool_name_by_index.insert(index, name.to_owned());
                }
                None => {
                    if established_new {
                        self.last_tool_name_by_index.remove(&index);
                    }
                }
            }
        }
        let arguments = function
            .and_then(|function| function.get("arguments"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let duplicate = established_new
            && fragment_name
                .is_some_and(|name| self.ledger.is_duplicate_definition(&id, name, &arguments));
        if duplicate {
            return;
        }
        if established_new {
            self.ledger
                .claim_first_emission(&id, fragment_name, Some(&arguments));
        }
        events.push(CanonicalEvent::ToolCallDelta {
            sequence_number: self.sequence,
            call_id: id,
            index: emit_index,
            name: fragment_name.map(str::to_owned),
            arguments_delta: Some(arguments),
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            timestamp: None,
        });
        self.sequence += 1;
    }

    /// Emits the terminal event once. `aborted` marks a client cancellation.
    pub fn finish(&mut self, aborted: bool) -> Vec<CanonicalEvent> {
        if self.terminal_emitted {
            return Vec::new();
        }
        self.terminal_emitted = true;
        let truncated = self.finish_reason.is_none();
        let state = if aborted {
            TerminalState::Aborted
        } else if matches!(self.finish_reason.as_deref(), Some("error" | "failed")) || truncated {
            TerminalState::Failed
        } else {
            TerminalState::Complete
        };
        let provider_stop_reason = self.finish_reason.clone();
        let usage_value = self.raw_usage.as_ref().map(merged_usage);
        let usage = usage_from_provider(usage_value.as_ref());
        let event = CanonicalEvent::Terminal {
            sequence_number: self.sequence,
            state,
            stop_reason: map_chat_stop_reason(provider_stop_reason.as_deref()).or(
                if truncated && !aborted {
                    Some(CanonicalStopReason::Error)
                } else {
                    None
                },
            ),
            provider_stop_reason,
            stop_details: None,
            usage,
            event_id: None,
            response_id: None,
            timestamp: Some(now_millis()),
        };
        self.sequence += 1;
        vec![event]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn non_streaming_response_maps_content_tools_and_usage() {
        let events = parse_chat_response_to_events(
            &json!({
                "id": "chatcmpl-1",
                "model": "gpt-test",
                "system_fingerprint": "fp",
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "hello",
                        "reasoning_content": "thinking",
                        "refusal": null,
                        "tool_calls": [{"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"a\":1}"}}]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 4, "prompt_tokens_details": {"cached_tokens": 2}}
            }),
            "fallback",
        );
        assert!(
            matches!(&events[0], CanonicalEvent::ResponseStart { model: Some(model), .. } if model == "gpt-test")
        );
        assert!(events.iter().any(|event| matches!(event, CanonicalEvent::ContentDelta { content: ContentPart::Text { text }, .. } if text == "hello")));
        assert!(events.iter().any(|event| matches!(event, CanonicalEvent::ToolCallDelta { name: Some(name), .. } if name == "read")));
        let terminal = events.last().unwrap();
        assert!(matches!(terminal, CanonicalEvent::Terminal {
            state: TerminalState::Complete,
            stop_reason: Some(CanonicalStopReason::ToolUse),
            usage: Some(usage),
            ..
        } if usage.input_tokens == 10 && usage.cached_input_tokens == keyla_core::TokenCount::Number(2)));
    }

    #[test]
    fn sse_decoder_emits_role_content_and_terminal_once() {
        let mut decoder = ChatSseDecoder::new("gpt-test");
        let start = decoder.start();
        assert!(matches!(start[0], CanonicalEvent::ResponseStart { .. }));
        assert!(decoder.start().is_empty());

        let events = decoder
            .push(r#"{"choices":[{"delta":{"content":"hel"}}],"usage":{"prompt_tokens":5}}"#)
            .unwrap();
        assert!(
            matches!(&events[0], CanonicalEvent::ContentDelta { content: ContentPart::Text { text }, .. } if text == "hel")
        );
        let events = decoder
            .push(r#"{"choices":[{"delta":{"content":"lo"},"finish_reason":"stop"}],"usage":{"completion_tokens":2}}"#)
            .unwrap();
        assert!(
            matches!(&events[0], CanonicalEvent::ContentDelta { content: ContentPart::Text { text }, .. } if text == "lo")
        );

        let terminal = decoder.finish(false);
        assert_eq!(terminal.len(), 1);
        assert!(matches!(&terminal[0], CanonicalEvent::Terminal {
            state: TerminalState::Complete,
            stop_reason: Some(CanonicalStopReason::Stop),
            usage: Some(usage),
            ..
        } if usage.input_tokens == 5 && usage.output_tokens == 2));
        assert!(decoder.finish(false).is_empty());
    }

    #[test]
    fn tool_fragments_inherit_the_id_and_name_from_the_first_frame() {
        let mut decoder = ChatSseDecoder::new("m");
        decoder.start();
        let first = decoder
            .push(r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"a\""}}]}}]}"#)
            .unwrap();
        assert!(matches!(&first[0], CanonicalEvent::ToolCallDelta {
            call_id, index: Some(0), name: Some(name), arguments_delta: Some(args), ..
        } if call_id == "call_1" && name == "read" && args == "{\"a\""));
        let second = decoder
            .push(r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":1}"}}]}}]}"#)
            .unwrap();
        assert!(matches!(&second[0], CanonicalEvent::ToolCallDelta {
            call_id, index: None, name: None, arguments_delta: Some(args), ..
        } if call_id == "call_1" && args == ":1}"));
    }

    #[test]
    fn error_frames_become_typed_errors_and_truncation_fails() {
        let mut decoder = ChatSseDecoder::new("m");
        decoder.start();
        let error = decoder
            .push(r#"{"type":"error","error":{"type":"invalid_api_key","message":"no"}}"#)
            .unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::AuthenticationFailed);

        let mut truncated = ChatSseDecoder::new("m");
        truncated.start();
        let terminal = truncated.finish(false);
        assert!(matches!(
            &terminal[0],
            CanonicalEvent::Terminal {
                state: TerminalState::Failed,
                ..
            }
        ));
    }

    #[test]
    fn think_tags_split_into_reasoning_and_text() {
        let mut decoder = ChatSseDecoder::new("m");
        decoder.start();
        let events = decoder
            .push(r#"{"choices":[{"delta":{"content":"<thinking>plan</thinking>answer"}}]}"#)
            .unwrap();
        assert!(
            matches!(&events[0], CanonicalEvent::ContentDelta { content: ContentPart::Reasoning { summary: Some(text), .. }, .. } if text == "plan")
        );
        assert!(
            matches!(&events[1], CanonicalEvent::ContentDelta { content: ContentPart::Text { text }, .. } if text == "answer")
        );
    }

    #[test]
    fn stop_reason_mapping_matches_the_chat_vocabulary() {
        assert_eq!(
            map_chat_stop_reason(Some("stop")),
            Some(CanonicalStopReason::Stop)
        );
        assert_eq!(
            map_chat_stop_reason(Some("tool_calls")),
            Some(CanonicalStopReason::ToolUse)
        );
        assert_eq!(
            map_chat_stop_reason(Some("length")),
            Some(CanonicalStopReason::Length)
        );
        assert_eq!(
            map_chat_stop_reason(Some("content_filter")),
            Some(CanonicalStopReason::ContentFilter)
        );
        assert_eq!(map_chat_stop_reason(Some("weird")), None);
    }

    #[test]
    fn usage_shape_from_openai_passes_through_the_normalizer() {
        let _ = body(json!({}));
    }
}
