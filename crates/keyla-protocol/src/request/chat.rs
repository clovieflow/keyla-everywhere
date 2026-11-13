//! OpenAI Chat request encoder: canonical request to provider wire body.
//! Port of `src/protocol/request/chat.ts`.

use keyla_core::{
    CanonicalRequest, ContentPart, DocumentSourceType, ResponseFormat, Role, ToolChoice,
    ToolResultContent, ToolType,
};
use serde_json::{Map, Value, json};

use crate::primitives::{is_record, resolve_image_source};
use crate::translation::{
    apply_chat_controls, cache_hint_has_breakpoints, clamp_reasoning_effort,
    mark_latest_chat_cache_breakpoint, normalize_wire_max_tokens, reasoning_effort_from_intent,
    resolve_prompt_cache_key, resolve_supported_reasoning_efforts, resolve_wire_max_tokens,
};

const CLAUDE_BILLING_HEADER_PREFIX: &str = "x-anthropic-billing-header:";

fn is_claude_billing_header_text(text: &str) -> bool {
    text.starts_with(CLAUDE_BILLING_HEADER_PREFIX)
}

/// OpenAI `input_audio.format` accepts only the discrete ids `wav`/`mp3`.
fn resolve_audio_format(media_type: &str) -> &'static str {
    match media_type.to_ascii_lowercase().as_str() {
        "audio/mpeg" | "audio/mp3" | "mp3" => "mp3",
        "audio/wav" | "audio/wave" | "audio/x-wav" | "wav" => "wav",
        _ => "mp3",
    }
}

/// Rebuilds an OpenAI `image_url` part, preserving `detail`.
fn chat_image_part(payload: &Value) -> Option<Value> {
    let source = resolve_image_source(payload)?;
    let url = source.url?;
    let mut image_url = Map::new();
    image_url.insert("url".into(), Value::String(url));
    if let Some(detail) = source.detail {
        image_url.insert("detail".into(), Value::String(detail));
    }
    Some(json!({
        "type": "image_url",
        "image_url": Value::Object(image_url),
    }))
}

/// Text fallback for an image the Chat wire cannot encode (a bare `file_id`).
fn chat_image_reference_text(payload: &Value) -> String {
    match resolve_image_source(payload).and_then(|source| source.file_id) {
        Some(file_id) => format!("[image: {file_id}]"),
        None => "[image: unsupported source]".to_owned(),
    }
}

/// Projects the canonical response format onto the Chat `json_schema` envelope.
fn chat_response_format(format: &ResponseFormat) -> Value {
    match format {
        ResponseFormat::JsonObject { .. } => json!({"type": "json_object"}),
        ResponseFormat::JsonSchema {
            schema,
            strict,
            name,
            description,
            ..
        } => {
            let mut json_schema = Map::new();
            if let Some(name) = name {
                json_schema.insert("name".into(), json!(name));
            }
            if let Some(description) = description {
                json_schema.insert("description".into(), json!(description));
            }
            json_schema.insert("schema".into(), schema.clone());
            if let Some(strict) = strict {
                json_schema.insert("strict".into(), json!(strict));
            }
            json!({
                "type": "json_schema",
                "json_schema": Value::Object(json_schema),
            })
        }
    }
}

struct FileInput<'a> {
    data: &'a Value,
    media_type: Option<&'a str>,
    filename: Option<&'a str>,
    file_id: Option<&'a str>,
    url: Option<&'a str>,
    source_type: Option<DocumentSourceType>,
}

/// OpenAI `file` content part. A reference-only document degrades to a text
/// part carrying the reference rather than a malformed empty block.
fn chat_file_part(part: FileInput<'_>) -> Value {
    let reference_only = matches!(
        part.source_type,
        Some(DocumentSourceType::Url | DocumentSourceType::File)
    ) || part
        .url
        .is_some_and(|url| part.data == &Value::String(url.to_owned()));
    let inline_data = if reference_only {
        None
    } else {
        match part.data {
            Value::Null => None,
            Value::String(text) if text.is_empty() => None,
            other => Some(other),
        }
    };
    if let Some(file_id) = part.file_id {
        let mut file = Map::new();
        file.insert("file_id".into(), json!(file_id));
        if let Some(filename) = part.filename {
            file.insert("filename".into(), json!(filename));
        }
        return json!({"type": "file", "file": Value::Object(file)});
    }
    if let Some(inline_data) = inline_data {
        let file_data = match inline_data {
            Value::String(text) if text.starts_with("data:") => text.clone(),
            Value::String(text) => {
                let media_type = part
                    .media_type
                    .filter(|value| !value.is_empty())
                    .unwrap_or("application/octet-stream");
                format!("data:{media_type};base64,{text}")
            }
            other => serde_json::to_string(other).unwrap_or_default(),
        };
        let mut file = Map::new();
        file.insert("file_data".into(), Value::String(file_data));
        if let Some(filename) = part.filename {
            file.insert("filename".into(), json!(filename));
        }
        return json!({"type": "file", "file": Value::Object(file)});
    }
    let reference = part.url.map(str::to_owned).or_else(|| match part.data {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        _ => None,
    });
    json!({
        "type": "text",
        "text": reference
            .map(|value| format!("[file: {value}]"))
            .unwrap_or_else(|| "[file: unsupported source]".to_owned()),
    })
}

fn tool_result_wire_content(content: &ToolResultContent) -> String {
    match content {
        ToolResultContent::Text(text) => text.clone(),
        ToolResultContent::Parts(parts) => serde_json::to_string(parts).unwrap_or_default(),
    }
}

fn reasoning_text(parts: &[ContentPart]) -> String {
    parts
        .iter()
        .filter_map(|part| match part {
            ContentPart::Reasoning {
                payload, summary, ..
            } => Some(
                summary
                    .clone()
                    .or_else(|| payload.as_str().map(str::to_owned))
                    .unwrap_or_default(),
            ),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn has_reasoning(parts: &[ContentPart]) -> bool {
    parts
        .iter()
        .any(|part| matches!(part, ContentPart::Reasoning { .. }))
}

fn is_web_search_tool(tool: &keyla_core::ToolDefinition) -> bool {
    tool.native_type
        .as_deref()
        .is_some_and(|native| native.starts_with("web_search_"))
        || tool.tool_type == Some(ToolType::WebSearch)
}

fn apply_tool_choice(payload: &mut Map<String, Value>, choice: &ToolChoice) {
    let value = match choice {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Tool { name } => json!({"type":"function","function":{"name":name}}),
        ToolChoice::Custom { name } => json!({"type":"custom","custom":{"name":name}}),
        ToolChoice::AllowedTools { mode, names } => json!({
            "type": "allowed_tools",
            "mode": mode,
            "tools": names
                .iter()
                .map(|name| json!({"type":"function","function":{"name":name}}))
                .collect::<Vec<_>>(),
        }),
    };
    payload.insert("tool_choice".into(), value);
}

/// Encodes a canonical request as an OpenAI-compatible Chat body.
pub fn canonical_to_chat_payload(
    request: &CanonicalRequest,
    supports_prompt_caching: bool,
) -> Value {
    let mut messages: Vec<Value> = Vec::new();

    if let Some(system) = &request.system {
        for part in system {
            if let ContentPart::Text { text } = part {
                if !is_claude_billing_header_text(text) {
                    messages.push(json!({"role": "system", "content": text}));
                }
            }
        }
    }
    if let Some(instructions) = &request.instructions {
        for part in instructions {
            if let ContentPart::Text { text } = part {
                if !is_claude_billing_header_text(text) {
                    messages.push(json!({"role": "developer", "content": text}));
                }
            }
        }
    }

    for message in &request.messages {
        let has_tool_call = message
            .content
            .iter()
            .any(|part| matches!(part, ContentPart::ToolCall { .. }));
        if message.role == Role::Assistant && has_tool_call {
            let tool_calls: Vec<Value> = message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::ToolCall {
                        call_id,
                        name,
                        arguments,
                        ..
                    } => Some(json!({
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": match arguments {
                                Value::String(value) => value.clone(),
                                other => serde_json::to_string(other).unwrap_or_default(),
                            },
                        },
                    })),
                    _ => None,
                })
                .collect();
            let text_parts: Vec<&str> = message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            let content = if text_parts.is_empty() {
                Value::Null
            } else {
                Value::String(text_parts.join("\n"))
            };
            let mut wire = Map::new();
            wire.insert("role".into(), json!("assistant"));
            wire.insert("content".into(), content);
            wire.insert("tool_calls".into(), Value::Array(tool_calls));
            if has_reasoning(&message.content) {
                wire.insert(
                    "reasoning_content".into(),
                    Value::String(reasoning_text(&message.content)),
                );
            }
            messages.push(Value::Object(wire));
        } else if message.role == Role::Tool {
            for part in &message.content {
                if let ContentPart::ToolResult {
                    call_id,
                    content,
                    is_error,
                    ..
                } = part
                {
                    let content = tool_result_wire_content(content);
                    let content = if *is_error == Some(true) {
                        format!("[tool_error] {content}")
                    } else {
                        content
                    };
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": content,
                    }));
                }
            }
        } else {
            // Tool results re-homed into a user turn by the Messages ledger
            // must still reach the provider as role:"tool" messages.
            for part in &message.content {
                if let ContentPart::ToolResult {
                    call_id,
                    content,
                    is_error,
                    ..
                } = part
                {
                    let content = tool_result_wire_content(content);
                    let content = if *is_error == Some(true) {
                        format!("[tool_error] {content}")
                    } else {
                        content
                    };
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": content,
                    }));
                }
            }
            let reasoning_content = reasoning_text(&message.content);
            let message_has_reasoning = has_reasoning(&message.content);
            let has_rich_content = message.content.iter().any(|part| {
                matches!(
                    part,
                    ContentPart::Image { .. }
                        | ContentPart::File { .. }
                        | ContentPart::Audio { .. }
                        | ContentPart::Document { .. }
                )
            });
            if has_rich_content {
                let mut parts: Vec<Value> = Vec::new();
                for part in &message.content {
                    match part {
                        ContentPart::Text { text } => {
                            parts.push(json!({"type":"text","text":text}));
                        }
                        ContentPart::Image { payload } => {
                            parts.push(chat_image_part(payload).unwrap_or_else(|| {
                                json!({"type":"text","text": chat_image_reference_text(payload)})
                            }));
                        }
                        ContentPart::Document {
                            data,
                            media_type,
                            title,
                            source_type,
                            url,
                            file_id,
                            ..
                        } => {
                            parts.push(chat_file_part(FileInput {
                                data,
                                media_type: Some(media_type.as_str()),
                                filename: title.as_deref(),
                                file_id: file_id.as_deref(),
                                url: url.as_deref(),
                                source_type: *source_type,
                            }));
                        }
                        ContentPart::File {
                            data,
                            media_type,
                            filename,
                            file_id,
                            url,
                        } => {
                            parts.push(chat_file_part(FileInput {
                                data,
                                media_type: Some(media_type.as_str()),
                                filename: filename.as_deref(),
                                file_id: file_id.as_deref(),
                                url: url.as_deref(),
                                source_type: None,
                            }));
                        }
                        ContentPart::Audio { data, media_type } => {
                            parts.push(json!({
                                "type": "input_audio",
                                "input_audio": {
                                    "data": data,
                                    "format": resolve_audio_format(media_type),
                                },
                            }));
                        }
                        ContentPart::Refusal { text } => {
                            parts.push(json!({"type":"text","text":text}));
                        }
                        _ => {}
                    }
                }
                let mut wire = Map::new();
                wire.insert("role".into(), json!(role_str(message.role)));
                wire.insert("content".into(), Value::Array(parts));
                if message.role == Role::Assistant && message_has_reasoning {
                    wire.insert("reasoning_content".into(), Value::String(reasoning_content));
                }
                messages.push(Value::Object(wire));
            } else {
                let text_parts: Vec<&str> = message
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                let has_text = text_parts.iter().any(|text| !text.is_empty());
                if !has_text && !has_rich_content {
                    if message.role == Role::Assistant && message_has_reasoning {
                        messages.push(json!({
                            "role": "assistant",
                            "content": "",
                            "reasoning_content": reasoning_content,
                        }));
                        continue;
                    }
                    if message.role != Role::Assistant
                        && message_has_reasoning
                        && !reasoning_content.is_empty()
                    {
                        if let Some(last) = messages.last_mut() {
                            if last.get("role").and_then(Value::as_str) == Some("tool") {
                                if let Some(object) = last.as_object_mut() {
                                    object.insert(
                                        "reasoning_content".into(),
                                        Value::String(reasoning_content),
                                    );
                                }
                            }
                        }
                    }
                    continue;
                }
                let content = message
                    .content
                    .iter()
                    .map(|part| match part {
                        ContentPart::Text { text } => text.clone(),
                        ContentPart::Reasoning { .. } => String::new(),
                        ContentPart::Refusal { text } => text.clone(),
                        _ => String::new(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let mut wire = Map::new();
                wire.insert("role".into(), json!(role_str(message.role)));
                wire.insert("content".into(), Value::String(content));
                if message.role == Role::Assistant && message_has_reasoning {
                    wire.insert("reasoning_content".into(), Value::String(reasoning_content));
                }
                messages.push(Value::Object(wire));
            }
        }
    }

    if supports_prompt_caching && cache_hint_has_breakpoints(request.cache_hint.as_ref()) {
        mark_latest_chat_cache_breakpoint(&mut messages);
    }

    let mut payload = Map::new();
    payload.insert("model".into(), json!(request.model));
    payload.insert("messages".into(), Value::Array(messages));
    payload.insert("stream".into(), json!(request.stream));

    if supports_prompt_caching {
        if let Some(key) = resolve_prompt_cache_key(Some(&request.generation_controls)) {
            payload.insert("prompt_cache_key".into(), Value::String(key));
        }
    }

    if let Some(tools) = &request.tools {
        if !tools.is_empty() {
            let wire_tools: Vec<Value> = tools
                .iter()
                .map(|tool| {
                    if tool.tool_type == Some(ToolType::Custom) {
                        let mut custom = Map::new();
                        custom.insert("name".into(), json!(tool.name));
                        if let Some(description) = &tool.description {
                            custom.insert("description".into(), json!(description));
                        }
                        if is_record(&tool.json_schema)
                            && tool
                                .json_schema
                                .as_object()
                                .is_some_and(|schema| !schema.is_empty())
                        {
                            custom.insert("format".into(), tool.json_schema.clone());
                        }
                        return json!({"type":"custom","custom": Value::Object(custom)});
                    }
                    if is_web_search_tool(tool) {
                        return json!({"type": "web_search_preview"});
                    }
                    if tool.tool_type.is_some()
                        && tool.tool_type != Some(ToolType::Function)
                        && is_record(&tool.json_schema)
                    {
                        return tool.json_schema.clone();
                    }
                    let mut function = Map::new();
                    function.insert("name".into(), json!(tool.name));
                    if let Some(description) = &tool.description {
                        function.insert("description".into(), json!(description));
                    }
                    function.insert("parameters".into(), tool.json_schema.clone());
                    if let Some(strict) = tool.strict {
                        function.insert("strict".into(), json!(strict));
                    }
                    if let Some(examples) = &tool.input_examples {
                        function.insert("input_examples".into(), json!(examples));
                    }
                    if let Some(defer) = tool.defer_loading {
                        function.insert("defer_loading".into(), json!(defer));
                    }
                    if let Some(callers) = &tool.allowed_callers {
                        function.insert("allowed_callers".into(), json!(callers));
                    }
                    json!({"type":"function","function": Value::Object(function)})
                })
                .collect();
            payload.insert("tools".into(), Value::Array(wire_tools));
        }
    }

    if let Some(choice) = &request.tool_choice {
        apply_tool_choice(&mut payload, choice);
    }
    if let Some(format) = &request.response_format {
        payload.insert("response_format".into(), chat_response_format(format));
    }

    if request.reasoning.is_some() {
        let supported = resolve_supported_reasoning_efforts(
            Some(&request.model),
            keyla_core::WireFamily::Chat,
            None,
        );
        if let Some(effort) = clamp_reasoning_effort(
            reasoning_effort_from_intent(request.reasoning.as_ref()),
            &supported,
        ) {
            payload.insert("reasoning_effort".into(), json!(effort.as_str()));
        }
    }

    let include_usage = request
        .generation_controls
        .extensions
        .get("extension:include_usage")
        .and_then(Value::as_bool);
    let include_obfuscation = request
        .generation_controls
        .extensions
        .get("extension:include_obfuscation")
        .and_then(Value::as_bool);
    if include_usage.is_some() || include_obfuscation.is_some() {
        let mut options = Map::new();
        if let Some(value) = include_usage {
            options.insert("include_usage".into(), json!(value));
        }
        if let Some(value) = include_obfuscation {
            options.insert("include_obfuscation".into(), json!(value));
        }
        payload.insert("stream_options".into(), Value::Object(options));
    }
    if let Some(Value::Array(modalities)) = request
        .generation_controls
        .extensions
        .get("extension:modalities")
    {
        payload.insert("modalities".into(), Value::Array(modalities.clone()));
    }
    if let Some(Value::Object(audio)) = request
        .generation_controls
        .extensions
        .get("extension:audio")
    {
        payload.insert("audio".into(), Value::Object(audio.clone()));
    }
    let metadata = request
        .generation_controls
        .extensions
        .get("extension:metadata")
        .or_else(|| {
            request
                .generation_controls
                .extensions
                .get("extension:responses.item_metadata")
        });
    if let Some(Value::Object(metadata)) = metadata {
        payload.insert("metadata".into(), Value::Object(metadata.clone()));
    }
    let user = request
        .generation_controls
        .extensions
        .get("extension:user")
        .or_else(|| {
            request
                .generation_controls
                .extensions
                .get("extension:responses.user")
        });
    if let Some(Value::String(user)) = user {
        payload.insert("user".into(), json!(user));
    }

    const PASSTHROUGH: [(&str, &str); 12] = [
        ("extension:store", "store"),
        ("extension:prediction", "prediction"),
        ("extension:moderation", "moderation"),
        ("extension:safety_identifier", "safety_identifier"),
        ("extension:verbosity", "verbosity"),
        ("extension:web_search_options", "web_search_options"),
        ("extension:frequency_penalty", "frequency_penalty"),
        ("extension:presence_penalty", "presence_penalty"),
        ("extension:logit_bias", "logit_bias"),
        ("extension:prompt_cache_options", "prompt_cache_options"),
        ("extension:prompt_cache_retention", "prompt_cache_retention"),
        ("extension:prompt_cache_key", "prompt_cache_key"),
    ];
    for (extension, field) in PASSTHROUGH {
        let value = request
            .generation_controls
            .extensions
            .get(extension)
            .or_else(|| {
                request
                    .generation_controls
                    .extensions
                    .get(&format!("extension:responses.{field}"))
            });
        if let Some(value) = value {
            payload.insert(field.into(), value.clone());
        }
    }

    let normalized = normalize_wire_max_tokens(&request.generation_controls);
    apply_chat_controls(&mut payload, &normalized);
    if let Some(requested) = payload.get("max_tokens").and_then(Value::as_i64) {
        if let Some(bounded) = resolve_wire_max_tokens("chat", Some(requested), false, false) {
            payload.insert("max_tokens".into(), json!(bounded));
        }
    }
    Value::Object(payload)
}

fn role_str(role: Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::Developer => "developer",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{
        CanonicalMessage, GenerationControls, SourceSurface, TokenCount, ToolDefinition,
        ToolResultContent, UsageRecord,
    };

    fn request(messages: Vec<CanonicalMessage>) -> CanonicalRequest {
        CanonicalRequest {
            model: "gpt-test".into(),
            system: None,
            instructions: None,
            messages,
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
    fn payload_keeps_system_developer_and_user_text() {
        let request = CanonicalRequest {
            system: Some(vec![ContentPart::Text {
                text: "be nice".into(),
            }]),
            instructions: Some(vec![
                ContentPart::Text {
                    text: "x-anthropic-billing-header: skip".into(),
                },
                ContentPart::Text {
                    text: "be terse".into(),
                },
            ]),
            ..request(vec![CanonicalMessage {
                role: Role::User,
                content: vec![ContentPart::Text { text: "hi".into() }],
                phase: None,
            }])
        };
        let payload = canonical_to_chat_payload(&request, true);
        let messages = payload["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[1]["role"], "developer");
        assert_eq!(messages[1]["content"], "be terse");
        assert_eq!(messages[2]["role"], "user");
    }

    #[test]
    fn assistant_tool_turn_carries_tool_calls_and_reasoning() {
        let request = request(vec![CanonicalMessage {
            role: Role::Assistant,
            content: vec![
                ContentPart::Reasoning {
                    payload: json!("thinking"),
                    opaque: None,
                    summary: Some("thinking".into()),
                    summary_index: None,
                    signature: None,
                    encrypted_content: None,
                },
                ContentPart::ToolCall {
                    call_id: "call_1".into(),
                    name: "read".into(),
                    arguments: json!({"path":"a"}),
                    index: Some(0),
                    item_id: None,
                    call_kind: None,
                },
            ],
            phase: None,
        }]);
        let payload = canonical_to_chat_payload(&request, true);
        let message = &payload["messages"][0];
        assert_eq!(message["role"], "assistant");
        assert_eq!(message["content"], Value::Null);
        assert_eq!(
            message["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"a\"}"
        );
        assert_eq!(message["reasoning_content"], "thinking");
    }

    #[test]
    fn tool_results_become_tool_messages_with_error_prefix() {
        let request = request(vec![CanonicalMessage {
            role: Role::User,
            content: vec![
                ContentPart::ToolResult {
                    call_id: "call_1".into(),
                    content: ToolResultContent::Text("boom".into()),
                    is_error: Some(true),
                    call_kind: None,
                    item_id: None,
                },
                ContentPart::Text {
                    text: "next".into(),
                },
            ],
            phase: None,
        }]);
        let payload = canonical_to_chat_payload(&request, true);
        let messages = payload["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "tool");
        assert_eq!(messages[0]["content"], "[tool_error] boom");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "\nnext");
    }

    #[test]
    fn tools_project_function_custom_and_web_search() {
        let mut request = request(vec![]);
        request.tools = Some(vec![
            ToolDefinition {
                name: "read".into(),
                description: Some("Read".into()),
                json_schema: json!({"type":"object","properties":{"path":{"type":"string"}}}),
                strict: Some(true),
                eager_input_streaming: None,
                defer_loading: None,
                input_examples: None,
                tool_type: Some(ToolType::Function),
                native_type: None,
                allowed_callers: None,
            },
            ToolDefinition {
                name: "grammar".into(),
                description: None,
                json_schema: json!({"type":"grammar"}),
                strict: None,
                eager_input_streaming: None,
                defer_loading: None,
                input_examples: None,
                tool_type: Some(ToolType::Custom),
                native_type: None,
                allowed_callers: None,
            },
            ToolDefinition {
                name: "web_search".into(),
                description: None,
                json_schema: json!({}),
                strict: None,
                eager_input_streaming: None,
                defer_loading: None,
                input_examples: None,
                tool_type: Some(ToolType::WebSearch),
                native_type: None,
                allowed_callers: None,
            },
        ]);
        request.tool_choice = Some(ToolChoice::Tool {
            name: "read".into(),
        });
        let payload = canonical_to_chat_payload(&request, true);
        assert_eq!(payload["tools"][0]["type"], "function");
        assert_eq!(payload["tools"][0]["function"]["strict"], true);
        assert_eq!(payload["tools"][1]["type"], "custom");
        assert_eq!(payload["tools"][2]["type"], "web_search_preview");
        assert_eq!(
            payload["tool_choice"],
            json!({"type":"function","function":{"name":"read"}})
        );
    }

    #[test]
    fn generation_controls_are_projected_and_bounded() {
        let mut request = request(vec![]);
        request.generation_controls = GenerationControls {
            temperature: Some(0.5),
            max_output_tokens: Some(100_000),
            stop: Some(keyla_core::StopSequence::One("END".into())),
            ..Default::default()
        };
        let payload = canonical_to_chat_payload(&request, true);
        assert_eq!(payload["temperature"], 0.5);
        assert_eq!(payload["max_tokens"], 32_000);
        assert_eq!(payload["stop"], "END");
    }

    #[test]
    fn usage_record_maps_to_chat_wire() {
        let usage = UsageRecord {
            input_tokens: 2,
            cached_input_tokens: TokenCount::Number(1),
            cache_write_tokens: TokenCount::Unavailable,
            uncached_input_tokens: TokenCount::Number(1),
            output_tokens: 3,
            reasoning_tokens: TokenCount::Unavailable,
            estimated_cost: None,
            credit_used: None,
            total_tokens: None,
            details: None,
        };
        let wire = crate::surface::usage::usage_to_chat_wire(&usage);
        assert_eq!(wire["total_tokens"], 5);
        assert_eq!(wire["prompt_tokens_details"]["cached_tokens"], 1);
    }
}
