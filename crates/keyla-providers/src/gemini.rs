//! Native Gemini `generateContent` / `streamGenerateContent` adapter.

use futures_util::StreamExt;
use keyla_core::{
    CanonicalEvent, CanonicalRequest, CanonicalStopReason, ContentPart, GatewayError,
    GatewayErrorCode, GatewayErrorOrigin, Role, TokenCount, UsageRecord,
};
use serde_json::{Map, Value, json};

use crate::adapter::{DispatchCredential, DispatchOutput, DispatchTarget};

fn error(status: u16, message: impl Into<String>) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::UpstreamConflict,
        status,
        message,
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Upstream)
}

fn content_text(parts: &[ContentPart]) -> String {
    parts
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn image_part(payload: &Value) -> Option<Value> {
    if let Some(url) = payload.get("url").and_then(Value::as_str) {
        return Some(
            json!({"fileData": {"fileUri": url, "mimeType": payload.get("media_type").and_then(Value::as_str).unwrap_or("image/png")}}),
        );
    }
    let media = payload
        .get("media_type")
        .and_then(Value::as_str)
        .unwrap_or("image/png");
    if let Some(data) = payload.get("data").and_then(Value::as_str) {
        let data = data
            .rsplit_once(',')
            .map(|(_, value)| value)
            .unwrap_or(data);
        return Some(json!({"inlineData": {"mimeType": media, "data": data}}));
    }
    None
}

fn build_payload(request: &CanonicalRequest) -> Value {
    let system = request
        .system
        .as_ref()
        .or(request.instructions.as_ref())
        .map(|parts| json!({"parts": [{"text": content_text(parts)}]}));
    let mut contents = Vec::new();
    for message in &request.messages {
        let role = match message.role {
            Role::Assistant => "model",
            Role::System => continue,
            Role::Tool => "user",
            _ => "user",
        };
        let mut parts = Vec::new();
        for part in &message.content {
            match part {
                ContentPart::Text { text } => parts.push(json!({"text": text})),
                ContentPart::Image { payload } => {
                    if let Some(part) = image_part(payload) {
                        parts.push(part);
                    }
                }
                ContentPart::ToolCall {
                    name, arguments, ..
                } => parts.push(json!({"functionCall": {"name": name, "args": arguments}})),
                ContentPart::ToolResult {
                    call_id, content, ..
                } => {
                    let value = serde_json::to_value(content).unwrap_or(Value::Null);
                    parts.push(json!({"functionResponse": {"name": call_id, "response": {"result": value}}}));
                }
                ContentPart::Reasoning {
                    summary: Some(summary),
                    ..
                } => parts.push(json!({"text": summary, "thought": true})),
                _ => {}
            }
        }
        if !parts.is_empty() {
            contents.push(json!({"role": role, "parts": parts}));
        }
    }
    let mut payload = json!({"contents": contents});
    let object = payload.as_object_mut().expect("object");
    if let Some(system) = system {
        object.insert("systemInstruction".into(), system);
    }
    let controls = &request.generation_controls;
    let mut generation = Map::new();
    if let Some(value) = controls.temperature {
        generation.insert("temperature".into(), json!(value));
    }
    if let Some(value) = controls.top_p {
        generation.insert("topP".into(), json!(value));
    }
    if let Some(value) = controls.top_k {
        generation.insert("topK".into(), json!(value));
    }
    let max = controls
        .max_output_tokens
        .or(controls.max_completion_tokens)
        .or(controls.max_tokens);
    if let Some(value) = max {
        generation.insert("maxOutputTokens".into(), json!(value));
    }
    if let Some(stop) = &controls.stop {
        let values = match stop {
            keyla_core::StopSequence::One(value) => vec![value.clone()],
            keyla_core::StopSequence::Many(values) => values.clone(),
        };
        generation.insert("stopSequences".into(), json!(values));
    }
    if !generation.is_empty() {
        object.insert("generationConfig".into(), Value::Object(generation));
    }
    if let Some(tools) = &request.tools {
        let declarations: Vec<Value> = tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.json_schema,
                })
            })
            .collect();
        object.insert(
            "tools".into(),
            json!([{"functionDeclarations": declarations}]),
        );
        if let Some(choice) = &request.tool_choice {
            let config = match choice {
                keyla_core::ToolChoice::None => json!({"mode": "NONE"}),
                keyla_core::ToolChoice::Required => json!({"mode": "ANY"}),
                keyla_core::ToolChoice::Tool { name } | keyla_core::ToolChoice::Custom { name } => {
                    json!({"mode": "ANY", "allowedFunctionNames": [name]})
                }
                _ => json!({"mode": "AUTO"}),
            };
            object.insert(
                "toolConfig".into(),
                json!({"functionCallingConfig": config}),
            );
        }
    }
    payload
}

fn usage(metadata: Option<&Value>) -> UsageRecord {
    let get = |key: &str| {
        metadata
            .and_then(|value| value.get(key))
            .and_then(Value::as_i64)
            .unwrap_or(0)
    };
    let prompt = get("promptTokenCount");
    let cached = get("cachedContentTokenCount");
    let completion = get("candidatesTokenCount") + get("thoughtsTokenCount");
    UsageRecord {
        input_tokens: prompt,
        cached_input_tokens: if cached > 0 {
            TokenCount::Number(cached)
        } else {
            TokenCount::Unavailable
        },
        cache_write_tokens: TokenCount::Unavailable,
        uncached_input_tokens: TokenCount::Number((prompt - cached).max(0)),
        output_tokens: completion,
        reasoning_tokens: if get("thoughtsTokenCount") > 0 {
            TokenCount::Number(get("thoughtsTokenCount"))
        } else {
            TokenCount::Unavailable
        },
        estimated_cost: None,
        credit_used: None,
        total_tokens: Some(TokenCount::Number(get("totalTokenCount"))),
        details: None,
    }
}

fn stop_reason(reason: Option<&str>, has_tools: bool) -> CanonicalStopReason {
    match reason {
        Some("MAX_TOKENS") => CanonicalStopReason::Length,
        Some("SAFETY") | Some("RECITATION") => CanonicalStopReason::ContentFilter,
        _ if has_tools => CanonicalStopReason::ToolUse,
        _ => CanonicalStopReason::Stop,
    }
}

fn parts_from_candidate(candidate: &Value) -> (Vec<CanonicalEvent>, usize) {
    let mut events = Vec::new();
    let mut calls = 0;
    if let Some(parts) = candidate
        .get("content")
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
    {
        for part in parts {
            if let Some(text) = part.get("text").and_then(Value::as_str) {
                let thought = part
                    .get("thought")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !text.is_empty() {
                    events.push(CanonicalEvent::ContentDelta {
                        sequence_number: 0,
                        content: if thought {
                            ContentPart::Reasoning {
                                payload: Value::Null,
                                opaque: None,
                                summary: Some(text.to_owned()),
                                summary_index: None,
                                signature: None,
                                encrypted_content: None,
                            }
                        } else {
                            ContentPart::Text {
                                text: text.to_owned(),
                            }
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
            if let Some(call) = part.get("functionCall") {
                calls += 1;
                let name = call.get("name").and_then(Value::as_str).unwrap_or("tool");
                let args = call.get("args").cloned().unwrap_or_else(|| json!({}));
                events.push(CanonicalEvent::ToolCallDelta {
                    sequence_number: 0,
                    call_id: format!("call_{calls}"),
                    index: Some(calls as i64 - 1),
                    name: Some(name.to_owned()),
                    arguments_delta: Some(serde_json::to_string(&args).unwrap_or_default()),
                    event_id: None,
                    response_id: None,
                    item_id: None,
                    output_index: Some(calls as i64 - 1),
                    timestamp: None,
                });
            }
        }
    }
    (events, calls)
}

fn sequence(events: &mut [CanonicalEvent], start: &mut u64) {
    for event in events {
        match event {
            CanonicalEvent::ContentDelta {
                sequence_number, ..
            }
            | CanonicalEvent::ToolCallDelta {
                sequence_number, ..
            }
            | CanonicalEvent::Terminal {
                sequence_number, ..
            }
            | CanonicalEvent::ResponseStart {
                sequence_number, ..
            } => {
                *sequence_number = *start;
                *start += 1;
            }
            _ => {}
        }
    }
}

/// Dispatches one canonical request to Gemini's native generateContent wire.
pub async fn dispatch_gemini(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let action = if request.stream {
        "streamGenerateContent?alt=sse"
    } else {
        "generateContent"
    };
    let url = format!(
        "{}/v1beta/models/{}:{}",
        credential.base_url.trim_end_matches('/'),
        target.model_id,
        action
    );
    let payload = build_payload(request);
    let mut builder = client
        .post(url)
        .header("content-type", "application/json")
        .header(
            "accept",
            if request.stream {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .json(&payload);
    if let Some(secret) = &credential.secret {
        builder = builder.header("x-goog-api-key", secret);
    }
    let response = builder.send().await.map_err(|source| {
        GatewayError::new(
            GatewayErrorCode::TransportUnavailable,
            502,
            format!("gemini request failed: {source}"),
            Map::new(),
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(error(
            status.as_u16(),
            format!(
                "gemini returned HTTP {}: {}",
                status.as_u16(),
                body.chars().take(200).collect::<String>()
            ),
        ));
    }
    if request.stream {
        let model = target.model_id.clone();
        let mut upstream = response.bytes_stream();
        let stream = async_stream::try_stream! {
            let mut sse = keyla_protocol::streaming::SseDecoder::new();
            let mut seq = 1u64;
            let mut calls = 0usize;
            let mut usage_meta: Option<Value> = None;
            let mut finish: Option<String> = None;
            yield CanonicalEvent::ResponseStart {
                sequence_number: seq, event_id: None, response_id: None,
                model: Some(model.clone()), system_fingerprint: None, timestamp: None,
            };
            seq += 1;
            while let Some(chunk) = upstream.next().await {
                let chunk = chunk.map_err(|source| GatewayError::new(
                    GatewayErrorCode::TransportUnavailable, 502,
                    format!("gemini stream failed: {source}"), Map::new(),
                ))?;
                for frame in sse.push(&chunk) {
                    let data = frame.data.trim();
                    if data.is_empty() { continue; }
                    let parsed: Value = match serde_json::from_str(data) { Ok(value) => value, Err(_) => continue };
                    if let Some(metadata) = parsed.get("usageMetadata") {
                        usage_meta = Some(metadata.clone());
                    }
                    if let Some(cand) = parsed.get("candidates").and_then(Value::as_array).and_then(|c| c.first()) {
                        if let Some(reason) = cand.get("finishReason").and_then(Value::as_str) {
                            finish = Some(reason.to_owned());
                        }
                        let (mut events, found) = parts_from_candidate(cand);
                        calls += found;
                        sequence(&mut events, &mut seq);
                        for event in events { yield event; }
                    }
                }
            }
            for frame in sse.finish() {
                let data = frame.data.trim();
                if data.is_empty() { continue; }
                if let Ok(parsed) = serde_json::from_str::<Value>(data) {
                    if let Some(cand) = parsed.get("candidates").and_then(Value::as_array).and_then(|c| c.first()) {
                        let (mut events, found) = parts_from_candidate(cand);
                        calls += found;
                        sequence(&mut events, &mut seq);
                        for event in events { yield event; }
                    }
                }
            }
            yield CanonicalEvent::Terminal {
                sequence_number: seq,
                state: keyla_core::TerminalState::Complete,
                stop_reason: Some(stop_reason(finish.as_deref(), calls > 0)),
                provider_stop_reason: finish,
                stop_details: None,
                usage: Some(usage(usage_meta.as_ref())),
                event_id: None,
                response_id: None,
                timestamp: None,
            };
        };
        return Ok(DispatchOutput::Stream(Box::pin(stream)));
    }
    let payload: Value = response
        .json()
        .await
        .map_err(|source| error(502, format!("gemini returned invalid JSON: {source}")))?;
    let mut events = Vec::new();
    let mut calls = 0usize;
    let mut finish = None;
    if let Some(candidate) = payload
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
    {
        finish = candidate
            .get("finishReason")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let (mut content, found) = parts_from_candidate(candidate);
        calls += found;
        events.append(&mut content);
    }
    let mut seq = 1u64;
    events.insert(
        0,
        CanonicalEvent::ResponseStart {
            sequence_number: 0,
            event_id: None,
            response_id: None,
            model: Some(target.model_id.clone()),
            system_fingerprint: None,
            timestamp: None,
        },
    );
    events.push(CanonicalEvent::Terminal {
        sequence_number: 0,
        state: keyla_core::TerminalState::Complete,
        stop_reason: Some(stop_reason(finish.as_deref(), calls > 0)),
        provider_stop_reason: finish,
        stop_details: None,
        usage: Some(usage(payload.get("usageMetadata"))),
        event_id: None,
        response_id: None,
        timestamp: None,
    });
    sequence(&mut events, &mut seq);
    Ok(DispatchOutput::Events(events))
}
