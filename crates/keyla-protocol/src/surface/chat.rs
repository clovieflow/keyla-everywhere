//! OpenAI Chat Completions surface: request parsing and response encoding.
//! Port of `src/transport/surface/chat/{parse,adapter,encode}.ts`.

use keyla_core::{
    CacheHint, CanonicalMessage, CanonicalRequest, ContentPart, GatewayError, GenerationControls,
    ReasoningIntent, Role, SourceSurface, StopSequence, ToolChoice, ToolDefinition,
};
use serde_json::{Map, Value};

use crate::dialects::{
    ToolDialect, is_service_tier, parse_reasoning_intent, parse_response_format, parse_tool_choice,
    parse_tool_definition,
};
use crate::primitives::{is_record, read_number, read_string};
use crate::surface::content_parts::{normalize_inline_file, text_part};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
    pub index: i64,
}

const AUDIO_FORMAT_MEDIA_TYPE: [(&str, &str); 3] = [
    ("wav", "audio/wav"),
    ("mp3", "audio/mpeg"),
    ("mpeg", "audio/mpeg"),
];

/// OpenAI discrete audio format ids to the canonical MIME media type.
pub fn audio_format_to_media_type(format: Option<&str>) -> String {
    let Some(format) = format.filter(|value| !value.is_empty()) else {
        return "audio/mpeg".into();
    };
    if format.contains('/') {
        return format.to_owned();
    }
    let lower = format.to_ascii_lowercase();
    AUDIO_FORMAT_MEDIA_TYPE
        .iter()
        .find(|(name, _)| *name == lower)
        .map(|(_, media_type)| (*media_type).to_owned())
        .unwrap_or_else(|| "audio/mpeg".into())
}

fn parse_error(message: impl Into<String>) -> GatewayError {
    GatewayError::invalid_request(message)
}

pub fn parse_content_part(value: &Value) -> Result<ContentPart, GatewayError> {
    if let Some(text) = value.as_str() {
        return Ok(text_part(text));
    }
    let Some(object) = value.as_object() else {
        return Err(parse_error(
            "Malformed content part: expected string or object",
        ));
    };
    let kind = read_string(object, "type");
    match kind.unwrap_or_default() {
        "text" | "input_text" | "output_text" => {
            let text = read_string(object, "text")
                .ok_or_else(|| parse_error("Malformed content part: text block requires text"))?;
            Ok(text_part(text))
        }
        "image_url" | "image" => Ok(ContentPart::Image {
            payload: object
                .get("image_url")
                .cloned()
                .unwrap_or_else(|| value.clone()),
        }),
        "input_audio" | "audio" => {
            let nested = object
                .get("input_audio")
                .and_then(Value::as_object)
                .unwrap_or(object);
            let format =
                read_string(nested, "format").or_else(|| read_string(nested, "media_type"));
            let data = nested
                .get("data")
                .or_else(|| nested.get("audio"))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new()));
            Ok(ContentPart::Audio {
                data,
                media_type: audio_format_to_media_type(format),
            })
        }
        "file" | "input_file" | "output_file" => {
            let nested = object
                .get("file")
                .and_then(Value::as_object)
                .unwrap_or(object);
            let filename = read_string(nested, "filename").map(str::to_owned);
            let file_id = read_string(nested, "file_id").map(str::to_owned);
            let url = read_string(nested, "file_url")
                .or_else(|| read_string(nested, "url"))
                .map(str::to_owned);
            let raw_data = nested
                .get("file_data")
                .or_else(|| nested.get("data"))
                .or_else(|| nested.get("url"))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new()));
            let media_type =
                read_string(nested, "mime_type").or_else(|| read_string(nested, "media_type"));
            let (data, media_type) = normalize_inline_file(&raw_data, media_type);
            Ok(ContentPart::File {
                data,
                media_type,
                filename,
                file_id,
                url,
            })
        }
        "document" => {
            let raw_source = match object.get("source") {
                Some(Value::Object(source)) => source,
                _ => object,
            };
            let raw_data = raw_source
                .get("data")
                .or_else(|| raw_source.get("file_id"))
                .or_else(|| raw_source.get("url"))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new()));
            let media_type =
                read_string(raw_source, "media_type").or_else(|| read_string(object, "mime_type"));
            let (data, media_type) = normalize_inline_file(&raw_data, media_type);
            Ok(ContentPart::Document {
                data,
                media_type,
                title: object
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                citations: None,
                source_type: None,
                url: None,
                file_id: None,
            })
        }
        "thinking" | "reasoning" => {
            let text = read_string(object, "thinking")
                .or_else(|| read_string(object, "text"))
                .or_else(|| read_string(object, "summary"));
            Ok(ContentPart::Reasoning {
                payload: text
                    .map(|text| Value::String(text.to_owned()))
                    .unwrap_or(Value::Null),
                opaque: None,
                summary: text.map(str::to_owned),
                summary_index: None,
                signature: None,
                encrypted_content: None,
            })
        }
        "redacted_thinking" => Ok(ContentPart::Reasoning {
            payload: value.clone(),
            opaque: Some(true),
            summary: None,
            summary_index: None,
            signature: None,
            encrypted_content: None,
        }),
        other => Err(parse_error(format!(
            "Malformed content part: unsupported type \"{}\"",
            if other.is_empty() { "unknown" } else { other }
        ))),
    }
}

pub fn parse_content(value: &Value) -> Result<Vec<ContentPart>, GatewayError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![text_part(text)]);
    }
    let Some(parts) = value.as_array() else {
        return Ok(Vec::new());
    };
    parts.iter().map(parse_content_part).collect()
}

pub fn parse_tool_call(value: &Value, index: i64) -> Option<ParsedToolCall> {
    let object = value.as_object()?;
    let id = read_string(object, "id")?;
    let kind = read_string(object, "type");
    let holder = object
        .get("function")
        .and_then(Value::as_object)
        .unwrap_or(object);
    let name = read_string(holder, "name")?;
    if kind.is_some_and(|kind| kind != "function") {
        return None;
    }
    // A history tool call without arguments is a zero-arg call, not a
    // malformed one.
    let arguments = read_string(holder, "arguments")
        .filter(|arguments| !arguments.trim().is_empty())
        .unwrap_or("{}")
        .to_owned();
    Some(ParsedToolCall {
        id: id.to_owned(),
        name: name.to_owned(),
        arguments,
        index,
    })
}

pub fn parse_message(value: &Value) -> Result<CanonicalMessage, GatewayError> {
    let object = value
        .as_object()
        .ok_or_else(|| parse_error("Malformed message: expected object"))?;
    let role = match read_string(object, "role") {
        Some("system") => Role::System,
        Some("developer") => Role::Developer,
        Some("user") => Role::User,
        Some("assistant") => Role::Assistant,
        Some("tool") => Role::Tool,
        other => {
            return Err(parse_error(format!(
                "Malformed message: unsupported role \"{}\"",
                other.unwrap_or("unknown")
            )));
        }
    };

    let mut content = parse_content(object.get("content").unwrap_or(&Value::Null))?;
    // Chat carries prior reasoning as a sibling string, not a content block.
    // Presence, not length, decides.
    if role == Role::Assistant {
        if let Some(reasoning) = read_string(object, "reasoning_content") {
            content.insert(
                0,
                ContentPart::Reasoning {
                    payload: Value::String(reasoning.to_owned()),
                    opaque: None,
                    summary: Some(reasoning.to_owned()),
                    summary_index: None,
                    signature: None,
                    encrypted_content: None,
                },
            );
        }
    }
    if role == Role::Assistant {
        if let Some(Value::Array(tool_calls)) = object.get("tool_calls") {
            let calls: Vec<ContentPart> = tool_calls
                .iter()
                .enumerate()
                .filter_map(|(index, call)| parse_tool_call(call, index as i64))
                .map(|call| ContentPart::ToolCall {
                    call_id: call.id,
                    name: call.name,
                    arguments: Value::String(call.arguments),
                    index: Some(call.index),
                    item_id: None,
                    call_kind: None,
                })
                .collect();
            content.extend(calls);
            return Ok(CanonicalMessage {
                role,
                content,
                phase: None,
            });
        }
    }

    if role == Role::Tool {
        let Some(call_id) = read_string(object, "tool_call_id") else {
            return Ok(CanonicalMessage {
                role,
                content,
                phase: None,
            });
        };
        let result_content = match object.get("content") {
            Some(Value::String(text)) => keyla_core::ToolResultContent::Text(text.clone()),
            _ => keyla_core::ToolResultContent::Parts(content),
        };
        return Ok(CanonicalMessage {
            role,
            content: vec![ContentPart::ToolResult {
                call_id: call_id.to_owned(),
                content: result_content,
                is_error: None,
                call_kind: None,
                item_id: None,
            }],
            phase: None,
        });
    }

    Ok(CanonicalMessage {
        role,
        content,
        phase: None,
    })
}

fn non_negative_number(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && *value >= 0.0)
}

fn add_extension(controls: &mut GenerationControls, key: &str, value: Value) {
    controls
        .extensions
        .insert(format!("extension:{key}"), value);
}

pub fn parse_generation_controls(body: &Map<String, Value>) -> GenerationControls {
    let mut controls = GenerationControls {
        temperature: read_number(body, "temperature"),
        top_p: read_number(body, "top_p"),
        n: read_number(body, "n").map(|value| value as i64),
        top_logprobs: read_number(body, "top_logprobs").map(|value| value as i64),
        seed: read_number(body, "seed").map(|value| value as i64),
        logprobs: body.get("logprobs").and_then(Value::as_bool),
        parallel_tool_calls: body.get("parallel_tool_calls").and_then(Value::as_bool),
        service_tier: read_string(body, "service_tier").map(str::to_owned),
        ..Default::default()
    };
    if let Some(value) = body
        .get("omit_encrypted_reasoning")
        .and_then(Value::as_bool)
    {
        add_extension(
            &mut controls,
            "omit_encrypted_reasoning",
            Value::Bool(value),
        );
    }
    match body.get("stop") {
        Some(Value::String(stop)) => controls.stop = Some(StopSequence::One(stop.clone())),
        Some(Value::Array(entries)) if entries.iter().all(|entry| entry.is_string()) => {
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
    if let Some(limit) = non_negative_number(read_number(body, "max_tokens")) {
        controls.max_tokens = Some(limit as i64);
    }
    if let Some(limit) = non_negative_number(read_number(body, "max_completion_tokens")) {
        controls.max_completion_tokens = Some(limit as i64);
    }
    if let Some(options) = body.get("stream_options").and_then(Value::as_object) {
        if let Some(value) = options.get("include_usage").and_then(Value::as_bool) {
            add_extension(&mut controls, "include_usage", Value::Bool(value));
        }
        if let Some(value) = options.get("include_obfuscation").and_then(Value::as_bool) {
            add_extension(&mut controls, "include_obfuscation", Value::Bool(value));
        }
    }
    if let Some(value) = body.get("user") {
        add_extension(&mut controls, "user", value.clone());
    }
    if let Some(value) = body.get("metadata") {
        add_extension(&mut controls, "metadata", value.clone());
    }
    if let Some(value) = read_number(body, "frequency_penalty") {
        add_extension(&mut controls, "frequency_penalty", Value::from(value));
    }
    if let Some(value) = read_number(body, "presence_penalty") {
        add_extension(&mut controls, "presence_penalty", Value::from(value));
    }
    for key in [
        "logit_bias",
        "prompt_cache_options",
        "audio",
        "prediction",
        "moderation",
        "web_search_options",
    ] {
        if let Some(value @ Value::Object(_)) = body.get(key) {
            add_extension(&mut controls, key, value.clone());
        }
    }
    if let Some(value) = read_string(body, "prompt_cache_retention") {
        add_extension(
            &mut controls,
            "prompt_cache_retention",
            Value::String(value.to_owned()),
        );
    }
    if let Some(Value::Array(modalities)) = body.get("modalities") {
        if modalities.iter().all(|entry| entry.is_string()) {
            add_extension(
                &mut controls,
                "modalities",
                Value::Array(modalities.clone()),
            );
        }
    }
    if let Some(value) = body.get("store").and_then(Value::as_bool) {
        add_extension(&mut controls, "store", Value::Bool(value));
    }
    if let Some(value) = read_string(body, "safety_identifier") {
        add_extension(
            &mut controls,
            "safety_identifier",
            Value::String(value.to_owned()),
        );
    }
    if let Some(value) = read_string(body, "verbosity") {
        add_extension(&mut controls, "verbosity", Value::String(value.to_owned()));
    }
    if let Some(value) = read_string(body, "prompt_cache_key") {
        if !value.is_empty() {
            add_extension(
                &mut controls,
                "prompt_cache_key",
                Value::String(value.to_owned()),
            );
        }
    }
    if let Some(service_tier) = read_string(body, "service_tier") {
        if !is_service_tier(service_tier) {
            add_extension(
                &mut controls,
                "service_tier",
                Value::String(service_tier.to_owned()),
            );
        }
    }
    controls
}

/// The OpenAI Chat Completions surface adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChatAdapter;

impl ChatAdapter {
    /// Whether a body has the distinguishing Chat `messages[]` shape.
    pub fn matches_body_shape(&self, body: &Value) -> bool {
        let Some(object) = body.as_object() else {
            return false;
        };
        if object.contains_key("input") {
            return false;
        }
        let Some(Value::Array(messages)) = object.get("messages") else {
            return false;
        };
        !messages.is_empty()
            && messages.iter().any(|message| {
                message
                    .as_object()
                    .is_some_and(|message| message.get("role").is_some_and(Value::is_string))
            })
    }

    /// Parses a wire body into the canonical request.
    pub fn parse(&self, value: &Value) -> Result<CanonicalRequest, GatewayError> {
        let body = value.as_object();
        let empty = Map::new();
        let body = body.unwrap_or(&empty);
        let wire_messages = match body.get("messages") {
            Some(Value::Array(messages)) => messages.as_slice(),
            _ => &[],
        };
        let mut system: Vec<ContentPart> = Vec::new();
        let mut instructions: Vec<ContentPart> = Vec::new();
        let mut messages: Vec<CanonicalMessage> = Vec::new();
        for wire_message in wire_messages {
            let message = parse_message(wire_message)?;
            match message.role {
                Role::System => system.extend(message.content),
                Role::Developer => instructions.extend(message.content),
                _ => messages.push(message),
            }
        }

        let tools: Vec<ToolDefinition> = match body.get("tools") {
            Some(Value::Array(tools)) => tools
                .iter()
                .filter_map(|tool| parse_tool_definition(tool, ToolDialect::Chat))
                .collect(),
            _ => Vec::new(),
        };
        let controls = parse_generation_controls(body);
        let tool_choice = match body.get("tool_choice") {
            Some(value) => parse_tool_choice(value, ToolDialect::Chat)?,
            None => None,
        };
        let response_format = body.get("response_format").and_then(parse_response_format);
        let model = read_string(body, "model").unwrap_or_default().to_owned();

        let mut request = CanonicalRequest {
            model,
            system: None,
            instructions: None,
            messages,
            tools: None,
            tool_choice: None,
            generation_controls: controls,
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
            stream: body.get("stream").and_then(Value::as_bool) == Some(true),
            source_surface: SourceSurface::Chat,
        };
        let prompt_cache_key = read_string(body, "prompt_cache_key").unwrap_or_default();
        if !prompt_cache_key.is_empty()
            || body.get("cache_control").and_then(Value::as_str) == Some("auto")
        {
            request.cache_hint = Some(CacheHint::StablePrefix);
        }
        if !system.is_empty() {
            request.system = Some(system);
        }
        if !instructions.is_empty() {
            request.instructions = Some(instructions);
        }
        if !tools.is_empty() {
            request.tools = Some(tools);
        }
        if let Some(choice) = tool_choice {
            request.tool_choice = Some(choice);
        }
        if let Some(format) = response_format {
            request.response_format = Some(format);
        }
        let reasoning: Option<ReasoningIntent> = parse_reasoning_intent(body);
        if let Some(reasoning) = reasoning {
            request.reasoning = Some(reasoning);
        }
        Ok(request)
    }

    pub fn parse_tool_choice_for_test(
        &self,
        value: &Value,
    ) -> Result<Option<ToolChoice>, GatewayError> {
        parse_tool_choice(value, ToolDialect::Chat)
    }
}

/// Whether a value is the record shape the wire readers accept.
pub fn is_object(value: &Value) -> bool {
    is_record(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{ReasoningEffort, ToolType};
    use serde_json::json;

    #[test]
    fn parses_system_developer_and_conversation_turns() {
        let body = json!({
            "model": "gpt-test",
            "messages": [
                {"role": "system", "content": "be nice"},
                {"role": "developer", "content": "be terse"},
                {"role": "user", "content": [{"type": "text", "text": "hi"}]},
                {"role": "assistant", "content": "hello", "reasoning_content": "",
                 "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "read", "arguments": "{\"path\":\"a\"}"}}]},
                {"role": "tool", "tool_call_id": "call_1", "content": "done"}
            ],
            "stream": true,
            "prompt_cache_key": "session-1",
            "reasoning_effort": "high",
            "tools": [{"type": "function", "function": {"name": "read", "parameters": {"type":"object","properties":{"path":{"type":"string"}}}}}]
        });
        let request = ChatAdapter.parse(&body).unwrap();
        assert_eq!(request.model, "gpt-test");
        assert_eq!(request.system.as_ref().unwrap().len(), 1);
        assert_eq!(request.instructions.as_ref().unwrap().len(), 1);
        assert_eq!(request.messages.len(), 3);
        assert_eq!(request.messages[0].role, Role::User);
        assert!(matches!(
            request.messages[1].content[0],
            ContentPart::Reasoning { .. }
        ));
        assert!(matches!(
            request.messages[1].content[2],
            ContentPart::ToolCall { .. }
        ));
        assert!(matches!(
            request.messages[2].content[0],
            ContentPart::ToolResult { .. }
        ));
        assert_eq!(request.cache_hint, Some(CacheHint::StablePrefix));
        assert_eq!(
            request.reasoning.as_ref().unwrap().effort,
            Some(ReasoningEffort::High)
        );
        assert_eq!(
            request.tools.as_ref().unwrap()[0].tool_type,
            Some(ToolType::Function)
        );
        assert!(request.stream);
        assert_eq!(request.source_surface, SourceSurface::Chat);
    }

    #[test]
    fn empty_reasoning_content_presence_is_preserved() {
        let body = json!({
            "messages": [{"role": "assistant", "reasoning_content": "", "content": "x"}]
        });
        let request = ChatAdapter.parse(&body).unwrap();
        assert!(matches!(
            request.messages[0].content[0],
            ContentPart::Reasoning { .. }
        ));
    }

    #[test]
    fn tool_message_with_string_content_keeps_the_string_contract() {
        let body = json!({
            "messages": [{"role": "tool", "tool_call_id": "c", "content": "raw"}]
        });
        let request = ChatAdapter.parse(&body).unwrap();
        let ContentPart::ToolResult { content, .. } = &request.messages[0].content[0] else {
            panic!("expected tool result");
        };
        assert_eq!(content, &keyla_core::ToolResultContent::Text("raw".into()));
    }

    #[test]
    fn generation_controls_carry_unknown_wire_fields_as_extensions() {
        let body = json!({
            "messages": [{"role":"user","content":"x"}],
            "temperature": 0.7,
            "n": 2,
            "stop": ["a", "b"],
            "max_tokens": 128,
            "stream_options": {"include_usage": true},
            "user": "u",
            "frequency_penalty": 0.5,
            "service_tier": "priority",
            "verbosity": "high"
        });
        let request = ChatAdapter.parse(&body).unwrap();
        let controls = &request.generation_controls;
        assert_eq!(controls.temperature, Some(0.7));
        assert_eq!(controls.n, Some(2));
        assert_eq!(
            controls.stop,
            Some(StopSequence::Many(vec!["a".into(), "b".into()]))
        );
        assert_eq!(controls.max_tokens, Some(128));
        assert_eq!(
            controls.extensions.get("extension:include_usage"),
            Some(&json!(true))
        );
        assert_eq!(controls.extensions.get("extension:user"), Some(&json!("u")));
        assert_eq!(
            controls.extensions.get("extension:frequency_penalty"),
            Some(&json!(0.5))
        );
        assert_eq!(controls.service_tier.as_deref(), Some("priority"));
        assert_eq!(
            controls.extensions.get("extension:verbosity"),
            Some(&json!("high"))
        );
        assert!(!controls.extensions.contains_key("extension:service_tier"));
    }

    #[test]
    fn malformed_content_and_roles_fail_with_gateway_errors() {
        let error = ChatAdapter
            .parse(&json!({"messages": [{"role": "wizard", "content": "x"}]}))
            .unwrap_err();
        assert_eq!(error.code, keyla_core::GatewayErrorCode::InvalidRequest);

        let error = ChatAdapter
            .parse(&json!({"messages": [{"role": "user", "content": [{"type": "video"}]}]}))
            .unwrap_err();
        assert!(error.message.contains("unsupported type"));
    }

    #[test]
    fn body_shape_matcher_rejects_responses_and_empty_messages() {
        let adapter = ChatAdapter;
        assert!(adapter.matches_body_shape(&json!({"messages": [{"role":"user","content":"x"}]})));
        assert!(!adapter.matches_body_shape(&json!({"input": "x", "messages": [{"role":"user"}]})));
        assert!(!adapter.matches_body_shape(&json!({"messages": []})));
        assert!(!adapter.matches_body_shape(&json!({"messages": "nope"})));
    }
}
