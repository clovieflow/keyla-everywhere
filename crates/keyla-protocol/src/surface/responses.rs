//! OpenAI Responses surface: request parsing and response encoding.
//! Port of `src/transport/surface/responses/{parse,adapter,encode,wire-output}.ts`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use keyla_core::{
    CallKind, CanonicalEvent, CanonicalMessage, CanonicalRequest, CanonicalStopReason, ContentPart,
    GatewayError, GatewayErrorCode, GenerationControls, Role, SourceSurface, TerminalState,
    TokenCount, ToolResultContent, UsageRecord,
};
use serde_json::{Map, Value, json};

use crate::dialects::{
    ToolDialect, is_service_tier, parse_reasoning_intent, parse_response_format, parse_tool_choice,
    parse_tool_definition,
};
use crate::primitives::{read_boolean, read_number, read_string, resolve_image_source};
use crate::surface::content_parts::{normalize_inline_file, text_part};

const OPENAI_RESPONSE_INCLUDES: [&str; 8] = [
    "file_search_call.results",
    "web_search_call.results",
    "web_search_call.action.sources",
    "message.input_image.image_url",
    "computer_call_output.output.image_url",
    "code_interpreter_call.outputs",
    "reasoning.encrypted_content",
    "message.output_text.logprobs",
];

static OPENAI_RESPONSE_INCLUDE_SET: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| OPENAI_RESPONSE_INCLUDES.into_iter().collect());

/// Computer-use action types accepted on a `computer_call` item.
const COMPUTER_ACTION_TYPES: [&str; 9] = [
    "click",
    "double_click",
    "drag",
    "keypress",
    "move",
    "screenshot",
    "scroll",
    "type",
    "wait",
];

const UNSUPPORTED_EXPLICIT_PROMPT_CACHE_MESSAGE: &str = "responses: prompt_cache_options and prompt_cache_breakpoint are unsupported; use prompt_cache_key instead";

fn parse_error(message: impl Into<String>) -> GatewayError {
    GatewayError::invalid_request(message)
}

fn is_responses_include(value: &str) -> bool {
    OPENAI_RESPONSE_INCLUDE_SET.contains(value)
}

fn has_own(value: &Map<String, Value>, key: &str) -> bool {
    value.contains_key(key)
}

fn has_unsupported_explicit_prompt_cache_fields(body: &Value) -> bool {
    let Some(body) = body.as_object() else {
        return false;
    };
    if has_own(body, "prompt_cache_options") || has_own(body, "prompt_cache_breakpoint") {
        return true;
    }
    let Some(Value::Array(input)) = body.get("input") else {
        return false;
    };
    input.iter().any(|item| {
        let Some(item) = item.as_object() else {
            return false;
        };
        if has_own(item, "prompt_cache_breakpoint") {
            return true;
        }
        item.get("content")
            .and_then(Value::as_array)
            .is_some_and(|parts| {
                parts.iter().any(|part| {
                    part.as_object()
                        .is_some_and(|part| has_own(part, "prompt_cache_breakpoint"))
                })
            })
    })
}

fn reject_unsupported_explicit_prompt_cache_fields(body: &Value) -> Result<(), GatewayError> {
    if has_unsupported_explicit_prompt_cache_fields(body) {
        return Err(parse_error(UNSUPPORTED_EXPLICIT_PROMPT_CACHE_MESSAGE));
    }
    Ok(())
}

fn parse_json_body(value: &Value) -> Result<Value, GatewayError> {
    match value {
        Value::String(text) => serde_json::from_str(text)
            .map_err(|error| parse_error(format!("Malformed JSON body: {error}"))),
        other => Ok(other.clone()),
    }
}

/// Unwraps a raw body or a registry `SurfaceInput` envelope into JSON.
pub fn unwrap_body(input: &Value) -> Result<Value, GatewayError> {
    if let Some(object) = input.as_object() {
        if has_own(object, "body") && (has_own(object, "headers") || has_own(object, "path")) {
            return parse_json_body(object.get("body").unwrap_or(&Value::Null));
        }
    }
    parse_json_body(input)
}

/// The readable text of a `reasoning` item, from either place a provider puts it.
fn response_reasoning_summary(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Array(entries)) => {
            let texts: Vec<&str> = entries
                .iter()
                .filter_map(|entry| entry.get("text").and_then(Value::as_str))
                .collect();
            (!texts.is_empty()).then(|| texts.join("\n\n"))
        }
        _ => None,
    }
}

/// The `reasoning_text` bodies of a reasoning item's `content` blocks.
fn response_reasoning_content(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Array(entries)) => {
            let texts: Vec<&str> = entries
                .iter()
                .filter_map(|entry| {
                    let kind = entry.get("type").and_then(Value::as_str);
                    if kind != Some("reasoning_text") && kind != Some("text") {
                        return None;
                    }
                    entry.get("text").and_then(Value::as_str)
                })
                .collect();
            (!texts.is_empty()).then(|| texts.join("\n\n"))
        }
        _ => None,
    }
}

fn reasoning_item_text(item: &Map<String, Value>) -> Option<String> {
    response_reasoning_summary(item.get("summary"))
        .or_else(|| response_reasoning_content(item.get("content")))
}

fn parse_input_content(
    value: Option<&Value>,
) -> Result<(Vec<ContentPart>, Vec<String>), GatewayError> {
    let Some(value) = value else {
        return Ok((Vec::new(), Vec::new()));
    };
    if let Some(text) = value.as_str() {
        return Ok((vec![text_part(text)], vec!["input_text".to_owned()]));
    }
    let Some(parts) = value.as_array() else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut content: Vec<ContentPart> = Vec::new();
    let mut content_types: Vec<String> = Vec::new();
    for raw_part in parts {
        let Some(raw_part) = raw_part.as_object() else {
            return Err(parse_error(
                "Responses message content blocks must be objects",
            ));
        };
        let kind = read_string(raw_part, "type");
        match kind.unwrap_or_default() {
            "input_text" | "output_text" | "text" => {
                let text = read_string(raw_part, "text")
                    .ok_or_else(|| parse_error("Responses text content blocks require text"))?;
                content.push(text_part(text));
                content_types.push(kind.unwrap_or_default().to_owned());
            }
            "input_image" | "output_image" | "image" => {
                content.push(ContentPart::Image {
                    payload: Value::Object(raw_part.clone()),
                });
                content_types.push(kind.unwrap_or_default().to_owned());
            }
            "input_file" | "output_file" | "file" => {
                let filename = read_string(raw_part, "filename").map(str::to_owned);
                let file_id = read_string(raw_part, "file_id").map(str::to_owned);
                let url = read_string(raw_part, "file_url")
                    .or_else(|| read_string(raw_part, "url"))
                    .map(str::to_owned);
                let raw_data = raw_part
                    .get("file_data")
                    .cloned()
                    .or_else(|| url.as_ref().map(|url| Value::String(url.clone())))
                    .unwrap_or_else(|| Value::String(String::new()));
                let media_type = read_string(raw_part, "mime_type")
                    .or_else(|| read_string(raw_part, "media_type"));
                let (data, media_type) = normalize_inline_file(&raw_data, media_type);
                content.push(ContentPart::File {
                    data,
                    media_type,
                    filename,
                    file_id,
                    url,
                });
                content_types.push(kind.unwrap_or_default().to_owned());
            }
            "document" => {
                let source = raw_part
                    .get("source")
                    .and_then(Value::as_object)
                    .unwrap_or(raw_part);
                let source_type = read_string(source, "type");
                let file_id = read_string(source, "file_id").map(str::to_owned);
                let url = read_string(source, "url").map(str::to_owned);
                let raw_data = source
                    .get("data")
                    .cloned()
                    .or_else(|| file_id.as_ref().map(|id| Value::String(id.clone())))
                    .or_else(|| url.as_ref().map(|url| Value::String(url.clone())))
                    .unwrap_or_else(|| Value::String(String::new()));
                let media_type = read_string(source, "media_type")
                    .or_else(|| read_string(raw_part, "mime_type"));
                let (data, media_type) = normalize_inline_file(&raw_data, media_type);
                content.push(ContentPart::Document {
                    data,
                    media_type,
                    title: read_string(raw_part, "title").map(str::to_owned),
                    citations: None,
                    source_type: match source_type {
                        Some("base64") => Some(keyla_core::DocumentSourceType::Base64),
                        Some("url") => Some(keyla_core::DocumentSourceType::Url),
                        Some("file") => Some(keyla_core::DocumentSourceType::File),
                        Some("text") => Some(keyla_core::DocumentSourceType::Text),
                        _ => None,
                    },
                    url,
                    file_id,
                });
                content_types.push(kind.unwrap_or_default().to_owned());
            }
            "input_audio" | "output_audio" | "audio" => {
                let data = raw_part
                    .get("data")
                    .or_else(|| raw_part.get("audio"))
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new()));
                content.push(ContentPart::Audio {
                    data,
                    media_type: read_string(raw_part, "media_type")
                        .unwrap_or("audio/mpeg")
                        .to_owned(),
                });
                content_types.push(kind.unwrap_or_default().to_owned());
            }
            "refusal" => {
                content.push(ContentPart::Refusal {
                    text: read_string(raw_part, "refusal")
                        .unwrap_or_default()
                        .to_owned(),
                });
                content_types.push("refusal".to_owned());
            }
            // A reasoning block replayed from the Messages wire (`thinking`) or
            // nested inside a message instead of its own `reasoning` item.
            "thinking" | "reasoning" => {
                let text = read_string(raw_part, "thinking")
                    .or_else(|| read_string(raw_part, "text"))
                    .or_else(|| read_string(raw_part, "summary"))
                    .map(str::to_owned);
                content.push(ContentPart::Reasoning {
                    payload: text
                        .as_ref()
                        .map(|text| Value::String(text.clone()))
                        .unwrap_or(Value::Null),
                    opaque: None,
                    summary: text,
                    summary_index: None,
                    signature: None,
                    encrypted_content: None,
                });
                content_types.push(kind.unwrap_or_default().to_owned());
            }
            "redacted_thinking" => {
                content.push(ContentPart::Reasoning {
                    payload: Value::Object(raw_part.clone()),
                    opaque: Some(true),
                    summary: None,
                    summary_index: None,
                    signature: None,
                    encrypted_content: None,
                });
                content_types.push("redacted_thinking".to_owned());
            }
            other => {
                let name = if other.is_empty() { "unknown" } else { other };
                content.push(ContentPart::Extension {
                    name: format!("responses.content.{name}"),
                    payload: Value::Object(raw_part.clone()),
                });
                content_types.push(name.to_owned());
            }
        }
    }
    Ok((content, content_types))
}

fn item_metadata(
    item: &Map<String, Value>,
    content_types: Option<&[String]>,
) -> Map<String, Value> {
    let mut metadata = Map::new();
    metadata.insert(
        "type".into(),
        json!(read_string(item, "type").unwrap_or("message")),
    );
    if let Some(id) = read_string(item, "id") {
        metadata.insert("id".into(), json!(id));
    }
    if let Some(call_id) = read_string(item, "call_id") {
        metadata.insert("call_id".into(), json!(call_id));
    }
    if let Some(role) = read_string(item, "role") {
        metadata.insert("role".into(), json!(role));
    }
    if let Some(content_types) = content_types {
        metadata.insert("content_types".into(), json!(content_types));
    }
    if let Some(phase) = read_string(item, "phase") {
        if phase == "commentary" || phase == "final_answer" {
            metadata.insert("phase".into(), json!(phase));
        }
    }
    if let Some(checks) = item.get("pending_safety_checks").and_then(Value::as_array) {
        metadata.insert("pending_safety_checks".into(), Value::Array(checks.clone()));
    }
    metadata
}

fn parse_responses_computer_action(action: &Value, index: usize) -> Result<Value, GatewayError> {
    let Some(action) = action.as_object() else {
        return Err(parse_error(format!(
            "Responses computer action {index} must be an object"
        )));
    };
    match read_string(action, "type") {
        Some(kind) if COMPUTER_ACTION_TYPES.contains(&kind) => Ok(Value::Object(action.clone())),
        other => Err(parse_error(format!(
            "Responses computer action {index} has unsupported type: {}",
            other.unwrap_or("missing")
        ))),
    }
}

fn parse_responses_computer_actions(item: &Map<String, Value>) -> Result<Vec<Value>, GatewayError> {
    let raw = item
        .get("actions")
        .cloned()
        .or_else(|| {
            item.get("action")
                .map(|action| Value::Array(vec![action.clone()]))
        })
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let Some(actions) = raw.as_array() else {
        return Err(parse_error(
            "Responses computer_call actions must be an array",
        ));
    };
    actions
        .iter()
        .enumerate()
        .map(|(index, action)| parse_responses_computer_action(action, index))
        .collect()
}

fn parse_computer_call_output(output: Option<&Value>) -> ToolResultContent {
    match output {
        Some(Value::String(text)) => ToolResultContent::Text(text.clone()),
        Some(Value::Object(object)) => {
            let image_url = object.get("image_url").or_else(|| object.get("url"));
            let detail = read_string(object, "detail");
            if let Some(image_url) = image_url {
                let mut payload = Map::new();
                payload.insert("type".into(), json!("output_image"));
                payload.insert("image_url".into(), image_url.clone());
                if let Some(detail) = detail {
                    payload.insert("detail".into(), json!(detail));
                }
                return ToolResultContent::Parts(vec![ContentPart::Image {
                    payload: Value::Object(payload),
                }]);
            }
            if let Some(file_id) = read_string(object, "file_id") {
                return ToolResultContent::Parts(vec![ContentPart::Image {
                    payload: json!({"type": "output_image", "file_id": file_id}),
                }]);
            }
            ToolResultContent::Text(
                serde_json::to_string(output.unwrap_or(&Value::Null)).unwrap_or_default(),
            )
        }
        Some(Value::Null) | None => ToolResultContent::Text(String::new()),
        Some(other) => ToolResultContent::Text(serde_json::to_string(other).unwrap_or_default()),
    }
}

/// Parses the `actions` of a streamed computer call from its argument chunks.
pub fn parse_responses_computer_action_chunks(chunks: &str) -> Vec<Value> {
    let text = chunks.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let Ok(parsed) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    if let Some(actions) = parsed.get("actions").and_then(Value::as_array) {
        return actions.clone();
    }
    match parsed {
        Value::Array(actions) => actions,
        Value::Object(_) => vec![parsed],
        _ => Vec::new(),
    }
}

fn role_from_str(role: &str) -> Option<Role> {
    match role {
        "system" => Some(Role::System),
        "developer" => Some(Role::Developer),
        "user" => Some(Role::User),
        "assistant" => Some(Role::Assistant),
        "tool" => Some(Role::Tool),
        _ => None,
    }
}

fn parse_input_item(
    item: &Map<String, Value>,
) -> Result<(CanonicalMessage, Map<String, Value>), GatewayError> {
    let item_type = read_string(item, "type").unwrap_or("message");
    if item_type == "message" {
        let role = read_string(item, "role").unwrap_or("user");
        let Some(role) = role_from_str(role) else {
            return Err(parse_error(format!(
                "Unsupported Responses message role: {role}"
            )));
        };
        let (parts, content_types) = parse_input_content(item.get("content"))?;
        let metadata = item_metadata(item, Some(&content_types));
        let mut message = CanonicalMessage {
            role,
            content: parts,
            phase: None,
        };
        if role == Role::Assistant {
            if let Some(phase) = metadata.get("phase").and_then(Value::as_str) {
                message.phase = match phase {
                    "commentary" => Some(keyla_core::AssistantItemPhase::Commentary),
                    "final_answer" => Some(keyla_core::AssistantItemPhase::FinalAnswer),
                    _ => None,
                };
            }
        }
        return Ok((message, metadata));
    }
    if item_type == "function_call" {
        let id = read_string(item, "id").map(str::to_owned);
        let call_id = read_string(item, "call_id")
            .map(str::to_owned)
            .or_else(|| id.clone());
        let name = read_string(item, "name").map(str::to_owned);
        let (Some(call_id), Some(name)) = (call_id, name) else {
            return Err(parse_error(
                "Responses function_call requires call_id and name",
            ));
        };
        let Some(arguments) = item.get("arguments") else {
            return Err(parse_error("Responses function_call requires arguments"));
        };
        return Ok((
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    call_id,
                    name,
                    arguments: arguments.clone(),
                    index: None,
                    item_id: id,
                    call_kind: None,
                }],
                phase: None,
            },
            item_metadata(item, None),
        ));
    }
    if item_type == "function_call_output" {
        let Some(call_id) = read_string(item, "call_id").map(str::to_owned) else {
            return Err(parse_error(
                "Responses function_call_output requires call_id",
            ));
        };
        let item_id = read_string(item, "id").map(str::to_owned);
        let output = item.get("output");
        let (content, metadata) = match output {
            Some(Value::String(text)) => (
                ToolResultContent::Text(text.clone()),
                item_metadata(item, None),
            ),
            Some(Value::Array(_)) => {
                let (parts, content_types) = parse_input_content(output)?;
                (
                    ToolResultContent::Parts(parts),
                    item_metadata(item, Some(&content_types)),
                )
            }
            Some(other) => (
                ToolResultContent::Text(serde_json::to_string(other).unwrap_or_default()),
                item_metadata(item, None),
            ),
            None => (
                ToolResultContent::Text(String::new()),
                item_metadata(item, None),
            ),
        };
        return Ok((
            CanonicalMessage {
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    call_id,
                    content,
                    is_error: None,
                    call_kind: None,
                    item_id,
                }],
                phase: None,
            },
            metadata,
        ));
    }
    if item_type == "computer_call" {
        let id = read_string(item, "id").map(str::to_owned);
        let call_id = read_string(item, "call_id")
            .map(str::to_owned)
            .or_else(|| id.clone());
        let Some(call_id) = call_id else {
            return Err(parse_error("Responses computer_call requires call_id"));
        };
        let actions = parse_responses_computer_actions(item)?;
        return Ok((
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    call_id,
                    name: "computer".into(),
                    arguments: json!({"actions": actions}),
                    index: None,
                    item_id: id,
                    call_kind: Some(CallKind::Computer),
                }],
                phase: None,
            },
            item_metadata(item, None),
        ));
    }
    if item_type == "computer_call_output" {
        let id = read_string(item, "id").map(str::to_owned);
        let Some(call_id) = read_string(item, "call_id").map(str::to_owned) else {
            return Err(parse_error(
                "Responses computer_call_output requires call_id",
            ));
        };
        return Ok((
            CanonicalMessage {
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    call_id,
                    content: parse_computer_call_output(item.get("output")),
                    is_error: None,
                    call_kind: Some(CallKind::Computer),
                    item_id: id,
                }],
                phase: None,
            },
            item_metadata(item, None),
        ));
    }
    if item_type == "reasoning" {
        let encrypted_present = has_own(item, "encrypted_content");
        let encrypted = item.get("encrypted_content");
        let summary = reasoning_item_text(item);
        if encrypted_present {
            let Some(encrypted) = encrypted.and_then(Value::as_str) else {
                return Err(GatewayError::new(
                    GatewayErrorCode::CapabilityUnsupported,
                    400,
                    "Encrypted reasoning must remain a string artifact",
                    Map::from_iter([("field".to_owned(), json!("reasoning.encrypted_content"))]),
                ));
            };
            return Ok((
                CanonicalMessage {
                    role: Role::Assistant,
                    content: vec![ContentPart::Reasoning {
                        payload: json!(encrypted),
                        opaque: Some(true),
                        summary,
                        summary_index: None,
                        signature: None,
                        encrypted_content: Some(encrypted.to_owned()),
                    }],
                    phase: None,
                },
                item_metadata(item, None),
            ));
        }
        return Ok((
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::Reasoning {
                    payload: summary
                        .as_ref()
                        .map(|summary| json!(summary))
                        .unwrap_or(Value::Null),
                    opaque: None,
                    summary,
                    summary_index: None,
                    signature: None,
                    encrypted_content: None,
                }],
                phase: None,
            },
            item_metadata(item, None),
        ));
    }
    Err(parse_error(format!(
        "Unsupported Responses input item type: {item_type}"
    )))
}

fn assign_extension(controls: &mut GenerationControls, key: &str, value: Value) {
    controls
        .extensions
        .insert(format!("extension:{key}"), value);
}

fn is_reasoning_only(message: &CanonicalMessage) -> bool {
    message.role == Role::Assistant
        && !message.content.is_empty()
        && message
            .content
            .iter()
            .all(|part| matches!(part, ContentPart::Reasoning { .. }))
}

fn is_tool_call_turn(message: Option<&CanonicalMessage>) -> bool {
    message.is_some_and(|message| {
        message.role == Role::Assistant
            && message
                .content
                .iter()
                .any(|part| matches!(part, ContentPart::ToolCall { .. }))
    })
}

/// Parse an OpenAI Responses body into the provider-neutral canonical request.
pub fn parse_responses_request(value: &Value) -> Result<CanonicalRequest, GatewayError> {
    let body_value = unwrap_body(value)?;
    let Some(body) = body_value.as_object() else {
        return Err(parse_error("Responses request body must be an object"));
    };
    reject_unsupported_explicit_prompt_cache_fields(&body_value)?;
    let Some(model) = read_string(body, "model") else {
        return Err(parse_error("Responses request requires model"));
    };

    let raw_input = body.get("input");
    let mut input_items: Vec<Map<String, Value>> = Vec::new();
    match raw_input {
        Some(Value::String(text)) => input_items.push(Map::from_iter([
            ("type".to_owned(), json!("message")),
            ("role".to_owned(), json!("user")),
            ("content".to_owned(), json!(text)),
        ])),
        Some(Value::Array(items)) => {
            for item in items {
                let Some(item) = item.as_object() else {
                    return Err(parse_error("Responses input items must be objects"));
                };
                input_items.push(item.clone());
            }
        }
        Some(_) => {
            return Err(parse_error(
                "Responses input must be a string or item array",
            ));
        }
        None => {}
    }

    let mut parsed_items = Vec::with_capacity(input_items.len());
    for item in &input_items {
        parsed_items.push(parse_input_item(item)?);
    }

    // Anthropic-style top-level hoisting: system and developer turns become
    // canonical `system`/`instructions` so no downstream wire ever receives a
    // `developer` role or a mid-array system turn.
    let mut hoisted_system_parts: Vec<ContentPart> = Vec::new();
    let mut hoisted_instruction_parts: Vec<ContentPart> = Vec::new();
    let mut messages: Vec<CanonicalMessage> = Vec::new();
    for (message, _) in &parsed_items {
        match message.role {
            Role::System => hoisted_system_parts.extend(message.content.clone()),
            Role::Developer => hoisted_instruction_parts.extend(message.content.clone()),
            _ => messages.push(message.clone()),
        }
    }

    // A `reasoning` item is its own entry in `input`, and providers emit it on
    // either side of the assistant item it produced. Fold the two into one
    // message so a reasoning-carrying consumer attaches it to the tool-call
    // turn instead of splitting the turn.
    let mut messages_with_reasoning: Vec<CanonicalMessage> = Vec::new();
    let mut pending_reasoning: Option<Vec<ContentPart>> = None;
    for message in messages {
        if is_reasoning_only(&message) {
            let previous = messages_with_reasoning.last().cloned();
            if is_tool_call_turn(previous.as_ref()) {
                if let Some(previous) = messages_with_reasoning.last_mut() {
                    let mut content = message.content.clone();
                    content.extend(previous.content.clone());
                    previous.content = content;
                }
                continue;
            }
            pending_reasoning
                .get_or_insert_with(Vec::new)
                .extend(message.content);
            continue;
        }
        if let Some(reasoning) = pending_reasoning.take() {
            if message.role == Role::Assistant {
                let mut content = reasoning;
                content.extend(message.content);
                messages_with_reasoning.push(CanonicalMessage { content, ..message });
                continue;
            }
            messages_with_reasoning.push(CanonicalMessage {
                role: Role::Assistant,
                content: reasoning,
                phase: None,
            });
        }
        messages_with_reasoning.push(message);
    }
    if let Some(reasoning) = pending_reasoning {
        messages_with_reasoning.push(CanonicalMessage {
            role: Role::Assistant,
            content: reasoning,
            phase: None,
        });
    }

    let metadata = parsed_items
        .iter()
        .map(|(_, metadata)| Value::Object(metadata.clone()))
        .collect::<Vec<_>>();

    let mut controls = GenerationControls::default();
    if let Some(max_output_tokens) = read_number(body, "max_output_tokens") {
        if max_output_tokens.fract() != 0.0 || max_output_tokens < 1.0 {
            return Err(parse_error("max_output_tokens must be a positive integer"));
        }
        controls.max_output_tokens = Some(max_output_tokens as i64);
    }
    if let Some(parallel) = read_boolean(body, "parallel_tool_calls") {
        controls.parallel_tool_calls = Some(parallel);
    }
    if let Some(service_tier) = read_string(body, "service_tier") {
        if is_service_tier(service_tier) {
            controls.service_tier = Some(service_tier.to_owned());
        }
    }
    if let Some(temperature) = read_number(body, "temperature") {
        controls.temperature = Some(temperature);
    }
    if let Some(top_p) = read_number(body, "top_p") {
        controls.top_p = Some(top_p);
    }

    const EXTENSION_FIELDS: [&str; 13] = [
        "max_tool_calls",
        "truncation",
        "store",
        "prompt_cache_key",
        "prompt_cache_retention",
        "background",
        "user",
        "stream_options",
        "top_logprobs",
        "moderation",
        "safety_identifier",
        "prompt",
        "context_management",
    ];
    for field in EXTENSION_FIELDS {
        if let Some(value) = body.get(field) {
            assign_extension(&mut controls, &format!("responses.{field}"), value.clone());
        }
    }
    if let Some(raw_include) = body.get("include") {
        let Some(include) = raw_include.as_array() else {
            return Err(parse_error("Responses include must be an array"));
        };
        let filtered: Vec<Value> = include
            .iter()
            .filter(|value| value.as_str().is_some_and(is_responses_include))
            .cloned()
            .collect();
        assign_extension(&mut controls, "responses.include", Value::Array(filtered));
    }
    assign_extension(
        &mut controls,
        "responses.item_metadata",
        Value::Array(metadata),
    );
    if let Some(omit) = read_boolean(body, "omit_encrypted_reasoning") {
        assign_extension(&mut controls, "omit_encrypted_reasoning", Value::Bool(omit));
    }
    if let Some(text) = body.get("text").and_then(Value::as_object) {
        if let Some(verbosity) = text.get("verbosity") {
            assign_extension(&mut controls, "responses.verbosity", verbosity.clone());
        }
    }

    let tools = body.get("tools").and_then(Value::as_array).map(|tools| {
        tools
            .iter()
            .filter_map(|tool| parse_tool_definition(tool, ToolDialect::Responses))
            .collect::<Vec<_>>()
    });

    let mut request = CanonicalRequest {
        model: model.to_owned(),
        system: None,
        instructions: None,
        messages: messages_with_reasoning,
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
        stream: read_boolean(body, "stream").unwrap_or(false),
        source_surface: SourceSurface::Responses,
    };
    if !hoisted_system_parts.is_empty() {
        request.system = Some(hoisted_system_parts);
    }
    let instruction_parts: Vec<ContentPart> = read_string(body, "instructions")
        .map(|instructions| vec![text_part(instructions)])
        .unwrap_or_default()
        .into_iter()
        .chain(hoisted_instruction_parts)
        .collect();
    if !instruction_parts.is_empty() {
        request.instructions = Some(instruction_parts);
    }
    let previous_response_id = read_string(body, "previous_response_id").map(str::to_owned);
    let conversation_id = read_string(body, "conversation").map(str::to_owned);
    if previous_response_id.is_some() || conversation_id.is_some() {
        request.conversation = Some(keyla_core::ConversationState {
            previous_response_id,
            conversation_id,
            ..Default::default()
        });
    }
    if let Some(metadata) = body.get("metadata").and_then(Value::as_object) {
        let mut filtered = Map::new();
        for (key, value) in metadata {
            if value.is_null() || value.is_string() || value.is_number() || value.is_boolean() {
                filtered.insert(key.clone(), value.clone());
            }
        }
        request.metadata = Some(filtered);
    }
    if let Some(tools) = tools {
        request.tools = Some(tools);
    }
    if let Some(tool_choice) = body.get("tool_choice") {
        let tool_choice = parse_tool_choice(tool_choice, ToolDialect::Responses)?;
        request.tool_choice = tool_choice;
    }
    let reasoning = {
        let nested = body
            .get("reasoning")
            .and_then(Value::as_object)
            .map(|reasoning| {
                Map::from_iter([("reasoning".to_owned(), Value::Object(reasoning.clone()))])
            })
            .and_then(|wrapper| parse_reasoning_intent(&wrapper));
        nested.or_else(|| {
            let effort = body
                .get("reasoning_effort")
                .cloned()
                .or_else(|| body.get("reasoning_level").cloned());
            let mut reasoning = Map::new();
            if let Some(effort) = effort {
                reasoning.insert("effort".into(), effort);
            }
            let wrapper = Map::from_iter([("reasoning".to_owned(), Value::Object(reasoning))]);
            parse_reasoning_intent(&wrapper)
        })
    };
    if let Some(reasoning) = reasoning {
        request.reasoning = Some(reasoning);
    }
    let text_format = body
        .get("text")
        .and_then(Value::as_object)
        .and_then(|text| text.get("format"));
    if let Some(format) = text_format.and_then(parse_response_format) {
        request.response_format = Some(format);
    }
    if let Some(cache_key) = read_string(body, "prompt_cache_key") {
        if !cache_key.is_empty() {
            request.cache_hint = Some(keyla_core::CacheHint::StablePrefix);
        }
    }
    Ok(request)
}

/// The OpenAI Responses public surface adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResponsesAdapter;

impl ResponsesAdapter {
    /// Check only top-level Responses shape markers, never prompt text.
    pub fn matches_body_shape(&self, body: &Value) -> bool {
        let Ok(candidate) = unwrap_body(body) else {
            return false;
        };
        let Some(candidate) = candidate.as_object() else {
            return false;
        };
        candidate.get("input").is_some_and(Value::is_array)
            || candidate.get("instructions").is_some_and(Value::is_string)
            || has_own(candidate, "previous_response_id")
            || has_own(candidate, "conversation")
    }

    /// Parses a request body into canonical form.
    pub fn parse(&self, body: &Value) -> Result<CanonicalRequest, GatewayError> {
        parse_responses_request(body)
    }
}

// ─── Response encoding ──────────────────────────────────────────────────────

fn usage_to_responses_wire(usage: &UsageRecord) -> Value {
    let mut result = Map::new();
    result.insert("input_tokens".into(), json!(usage.input_tokens));
    result.insert("output_tokens".into(), json!(usage.output_tokens));
    result.insert(
        "total_tokens".into(),
        json!(usage.input_tokens + usage.output_tokens),
    );
    if let TokenCount::Number(cached) = usage.cached_input_tokens {
        result.insert("cached_input_tokens".into(), json!(cached));
        result.insert(
            "input_tokens_details".into(),
            json!({"cached_tokens": cached}),
        );
    }
    if let TokenCount::Number(reasoning) = usage.reasoning_tokens {
        result.insert("reasoning_tokens".into(), json!(reasoning));
        result.insert(
            "output_tokens_details".into(),
            json!({"reasoning_tokens": reasoning}),
        );
    }
    Value::Object(result)
}

fn part_to_responses_content(part: &ContentPart, content_type: Option<&str>) -> Option<Value> {
    match part {
        ContentPart::Text { text } => Some(json!({
            "type": if content_type == Some("output_text") { "output_text" } else { "input_text" },
            "text": text,
        })),
        ContentPart::Image { payload } => {
            let source = resolve_image_source(payload);
            match source {
                Some(source) if source.url.is_some() => {
                    let mut block = Map::new();
                    block.insert("type".into(), json!("input_image"));
                    block.insert("image_url".into(), json!(source.url));
                    if let Some(detail) = source.detail {
                        block.insert("detail".into(), json!(detail));
                    }
                    Some(Value::Object(block))
                }
                Some(source) if source.file_id.is_some() => {
                    let mut block = Map::new();
                    block.insert("type".into(), json!("input_image"));
                    block.insert("file_id".into(), json!(source.file_id));
                    if let Some(detail) = source.detail {
                        block.insert("detail".into(), json!(detail));
                    }
                    Some(Value::Object(block))
                }
                _ => Some(payload.clone()),
            }
        }
        ContentPart::File {
            data,
            media_type,
            filename,
            file_id,
            url,
        } => {
            let mut block = Map::new();
            block.insert("type".into(), json!("input_file"));
            if let Some(file_id) = file_id {
                block.insert("file_id".into(), json!(file_id));
            } else if let Some(url) = url {
                let reference_only = matches!(data, Value::Null)
                    || data
                        .as_str()
                        .is_some_and(|text| text.is_empty() || text == url);
                if reference_only {
                    block.insert("file_url".into(), json!(url));
                } else if let Some(data) = file_data(data) {
                    block.insert("file_data".into(), data);
                }
            } else if let Some(data) = file_data(data) {
                block.insert("file_data".into(), data);
            }
            block.insert("mime_type".into(), json!(media_type));
            if let Some(filename) = filename {
                block.insert("filename".into(), json!(filename));
            }
            Some(Value::Object(block))
        }
        ContentPart::Audio { data, media_type } => Some(json!({
            "type": "input_audio",
            "data": data,
            "media_type": media_type,
        })),
        ContentPart::Document {
            data,
            media_type,
            title,
            source_type,
            url,
            file_id,
            ..
        } => {
            if *source_type == Some(keyla_core::DocumentSourceType::Text) {
                if let Some(text) = data.as_str() {
                    return Some(json!({"type": "input_text", "text": text}));
                }
            }
            let mut block = Map::new();
            block.insert("type".into(), json!("input_file"));
            block.insert("mime_type".into(), json!(media_type));
            if let Some(file_id) = file_id {
                block.insert("file_id".into(), json!(file_id));
            } else if let Some(url) = url {
                let reference_only = matches!(data, Value::Null)
                    || data
                        .as_str()
                        .is_some_and(|text| text.is_empty() || text == url);
                if reference_only {
                    block.insert("file_url".into(), json!(url));
                } else if let Some(data) = file_data(data) {
                    block.insert("file_data".into(), data);
                }
            } else if let Some(data) = file_data(data) {
                block.insert("file_data".into(), data);
            }
            if let Some(title) = title {
                block.insert("filename".into(), json!(title));
            }
            Some(Value::Object(block))
        }
        // reasoning / refusal / extension carry no message-input block.
        _ => None,
    }
}

fn file_data(data: &Value) -> Option<Value> {
    match data {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        other => Some(other.clone()),
    }
}

fn output_to_wire(content: &ToolResultContent) -> Value {
    match content {
        ToolResultContent::Text(text) => Value::String(text.clone()),
        ToolResultContent::Parts(parts) => Value::Array(
            parts
                .iter()
                .filter_map(|part| part_to_responses_content(part, None))
                .collect(),
        ),
    }
}

fn computer_output_to_wire(content: &ToolResultContent) -> Value {
    match content {
        ToolResultContent::Text(text) => json!({
            "type": "computer_screenshot",
            "image_url": text,
        }),
        ToolResultContent::Parts(parts) => {
            if let Some(ContentPart::Image { payload }) = parts
                .iter()
                .find(|part| matches!(part, ContentPart::Image { .. }))
            {
                if let Some(payload) = payload.as_object() {
                    let mut output = Map::new();
                    output.insert("type".into(), json!("computer_screenshot"));
                    for key in ["image_url", "url"] {
                        if let Some(value) = payload.get(key) {
                            output.insert("image_url".into(), value.clone());
                            break;
                        }
                    }
                    if let Some(file_id) = payload.get("file_id") {
                        output.insert("file_id".into(), file_id.clone());
                    }
                    if let Some(detail) = payload.get("detail") {
                        output.insert("detail".into(), detail.clone());
                    }
                    return Value::Object(output);
                }
            }
            json!({
                "type": "computer_screenshot",
                "image_url": output_to_wire(content),
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenKind {
    Text,
    Reasoning,
    Tool,
}

#[derive(Debug, Clone)]
struct OpenOutput {
    kind: OpenKind,
    item: Map<String, Value>,
    item_id: String,
    output_index: usize,
    content_index: i64,
    call_id: Option<String>,
    is_computer: bool,
    /// Streaming content or argument deltas, joined once at finalization.
    chunks: Vec<String>,
    summary_parts: BTreeMap<i64, Vec<String>>,
    source_summary_indexes: HashMap<String, i64>,
    next_summary_index: i64,
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Stateful Responses event lifecycle encoder.
#[derive(Debug, Clone)]
pub struct ResponsesStreamEncoder {
    sequence: u64,
    input_sequence: Option<u64>,
    started: bool,
    terminal: bool,
    response_model: Option<String>,
    system_fingerprint: Option<String>,
    usage: Option<UsageRecord>,
    open: Option<OpenOutput>,
    parked: HashMap<String, OpenOutput>,
    output_items: Vec<Map<String, Value>>,
    computer_calls: HashSet<String>,
    model: String,
    response_id: String,
    created_at: i64,
}

impl ResponsesStreamEncoder {
    pub fn new(model: &str) -> Self {
        Self {
            sequence: 0,
            input_sequence: None,
            started: false,
            terminal: false,
            response_model: None,
            system_fingerprint: None,
            usage: None,
            open: None,
            parked: HashMap::new(),
            output_items: Vec::new(),
            computer_calls: HashSet::new(),
            model: model.to_owned(),
            response_id: format!("resp-{}", uuid::Uuid::new_v4()),
            created_at: now_seconds(),
        }
    }

    /// One id and creation time for the whole response.
    pub fn with_response_id(mut self, id: impl Into<String>) -> Self {
        self.response_id = id.into();
        self
    }

    pub fn with_created_at(mut self, created_at: i64) -> Self {
        self.created_at = created_at;
        self
    }

    fn emit(&mut self, event_type: &str, payload: Map<String, Value>) -> (String, Value) {
        let mut event = Map::new();
        event.insert("type".into(), json!(event_type));
        event.insert("sequence_number".into(), json!(self.sequence));
        for (key, value) in payload {
            event.insert(key, value);
        }
        self.sequence += 1;
        (event_type.to_owned(), Value::Object(event))
    }

    fn lifecycle_error(
        &mut self,
        category: &str,
        message: impl Into<String>,
    ) -> Vec<(String, Value)> {
        let mut payload = Map::new();
        payload.insert("category".into(), json!(category));
        payload.insert("message".into(), json!(message.into()));
        vec![self.emit("response.error", payload)]
    }

    fn response_object(&self, status: &str) -> Value {
        let mut response = Map::new();
        response.insert("id".into(), json!(self.response_id));
        response.insert("object".into(), json!("response"));
        response.insert("created_at".into(), json!(self.created_at));
        response.insert("status".into(), json!(status));
        response.insert(
            "model".into(),
            json!(
                self.response_model
                    .as_deref()
                    .unwrap_or(self.model.as_str())
            ),
        );
        response.insert(
            "output".into(),
            Value::Array(
                self.output_items
                    .iter()
                    .map(|item| Value::Object(item.clone()))
                    .collect(),
            ),
        );
        if let Some(fingerprint) = &self.system_fingerprint {
            response.insert("system_fingerprint".into(), json!(fingerprint));
        }
        if let Some(usage) = &self.usage {
            response.insert("usage".into(), usage_to_responses_wire(usage));
        }
        Value::Object(response)
    }

    fn start(&mut self, model: Option<&str>) -> Vec<(String, Value)> {
        if self.started {
            if let (Some(model), Some(response_model)) = (model, self.response_model.as_deref()) {
                if model != response_model {
                    return self.lifecycle_error(
                        "invalid_lifecycle",
                        "Response model changed after response.created",
                    );
                }
            }
            return Vec::new();
        }
        self.started = true;
        self.response_model = Some(model.unwrap_or(&self.model).to_owned());
        let mut payload = Map::new();
        payload.insert("response".into(), self.response_object("in_progress"));
        vec![self.emit("response.created", payload)]
    }

    fn open_key(kind: OpenKind, call_id: Option<&str>) -> String {
        if kind == OpenKind::Tool {
            format!("tool:{}", call_id.unwrap_or_default())
        } else if kind == OpenKind::Text {
            "text".into()
        } else {
            "reasoning".into()
        }
    }

    /// Park the active item without emitting done events; it resumes on return.
    fn suspend_open(&mut self) {
        if let Some(open) = self.open.take() {
            let key = Self::open_key(open.kind, open.call_id.as_deref());
            self.parked.insert(key, open);
        }
    }

    /// Restore a parked item as active, if present.
    fn restore_parked(&mut self, key: &str) -> bool {
        let Some(state) = self.parked.remove(key) else {
            return false;
        };
        self.open = Some(state);
        true
    }

    /// Finalize every open item (active first, then parked by output order).
    fn close_all(&mut self) -> Vec<(String, Value)> {
        let mut events = Vec::new();
        if let Some(state) = self.open.take() {
            self.parked
                .remove(&Self::open_key(state.kind, state.call_id.as_deref()));
            events.extend(self.finalize_state(state));
        }
        let mut rest: Vec<OpenOutput> = self.parked.drain().map(|(_, state)| state).collect();
        rest.sort_by_key(|state| state.output_index);
        for state in rest {
            events.extend(self.finalize_state(state));
        }
        events
    }

    /// Finalize one item: materialize chunks, snapshot output, emit done.
    fn finalize_state(&mut self, mut open: OpenOutput) -> Vec<(String, Value)> {
        open.item.insert("status".into(), json!("completed"));
        let output_index = open.output_index;
        let chunks = open.chunks.join("");
        let summary_parts: Option<Vec<(i64, Vec<String>)>> = if open.kind == OpenKind::Reasoning {
            Some(
                open.summary_parts
                    .iter()
                    .map(|(index, chunks)| (*index, chunks.clone()))
                    .collect(),
            )
        } else {
            None
        };
        if open.kind == OpenKind::Text {
            if let Some(Value::Array(content)) = open.item.get_mut("content") {
                if let Some(Value::Object(text_part)) = content.first_mut() {
                    if text_part.get("type").and_then(Value::as_str) == Some("output_text") {
                        text_part.insert("text".into(), json!(chunks));
                    }
                }
            }
        } else if open.kind == OpenKind::Tool {
            if open.is_computer {
                open.item.insert(
                    "actions".into(),
                    Value::Array(parse_responses_computer_action_chunks(&chunks)),
                );
            } else {
                open.item.insert("arguments".into(), json!(chunks));
            }
        } else if open.kind == OpenKind::Reasoning {
            if !open.chunks.is_empty() {
                open.item.insert(
                    "content".into(),
                    json!([{"type": "reasoning_text", "text": chunks}]),
                );
            }
            if let Some(summary_parts) = summary_parts.as_ref() {
                if !summary_parts.is_empty() {
                    open.item.insert(
                        "summary".into(),
                        Value::Array(
                            summary_parts
                                .iter()
                                .map(|(_, chunks)| {
                                    json!({"type": "summary_text", "text": chunks.join("")})
                                })
                                .collect(),
                        ),
                    );
                }
            }
        }
        if let Some(slot) = self.output_items.get_mut(output_index) {
            *slot = open.item.clone();
        } else {
            self.output_items.push(open.item.clone());
        }
        let mut events: Vec<(String, Value)> = Vec::new();
        match open.kind {
            OpenKind::Text => {
                let text = open
                    .item
                    .get("content")
                    .and_then(Value::as_array)
                    .and_then(|content| content.first())
                    .and_then(|part| part.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let mut payload = Map::new();
                payload.insert("item_id".into(), json!(open.item_id));
                payload.insert("output_index".into(), json!(output_index));
                payload.insert("content_index".into(), json!(open.content_index));
                payload.insert("text".into(), json!(text));
                events.push(self.emit("response.output_text.done", payload));
                let mut payload = Map::new();
                payload.insert("item_id".into(), json!(open.item_id));
                payload.insert("output_index".into(), json!(output_index));
                payload.insert("content_index".into(), json!(open.content_index));
                payload.insert("part".into(), json!({"type": "output_text"}));
                events.push(self.emit("response.content_part.done", payload));
            }
            OpenKind::Tool => {
                if !open.is_computer {
                    let mut payload = Map::new();
                    payload.insert("item_id".into(), json!(open.item_id));
                    payload.insert("output_index".into(), json!(output_index));
                    payload.insert(
                        "arguments".into(),
                        open.item.get("arguments").cloned().unwrap_or(Value::Null),
                    );
                    events.push(self.emit("response.function_call_arguments.done", payload));
                }
            }
            OpenKind::Reasoning => {
                if let Some(summary_parts) = summary_parts.as_ref() {
                    for (summary_index, summary_chunks) in summary_parts {
                        let text = summary_chunks.join("");
                        let mut payload = Map::new();
                        payload.insert("item_id".into(), json!(open.item_id));
                        payload.insert("output_index".into(), json!(output_index));
                        payload.insert("summary_index".into(), json!(summary_index));
                        payload.insert("text".into(), json!(text));
                        events.push(self.emit("response.reasoning_summary_text.done", payload));
                        let mut payload = Map::new();
                        payload.insert("item_id".into(), json!(open.item_id));
                        payload.insert("output_index".into(), json!(output_index));
                        payload.insert("summary_index".into(), json!(summary_index));
                        payload
                            .insert("part".into(), json!({"type": "summary_text", "text": text}));
                        events.push(self.emit("response.reasoning_summary_part.done", payload));
                    }
                }
                if !open.chunks.is_empty() {
                    let mut payload = Map::new();
                    payload.insert("item_id".into(), json!(open.item_id));
                    payload.insert("output_index".into(), json!(output_index));
                    payload.insert("content_index".into(), json!(0));
                    payload.insert("text".into(), json!(chunks));
                    events.push(self.emit("response.reasoning_text.done", payload));
                }
            }
        }
        let mut payload = Map::new();
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("item".into(), Value::Object(open.item));
        events.push(self.emit("response.output_item.done", payload));
        events
    }

    fn open_text(&mut self) -> Vec<(String, Value)> {
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.kind == OpenKind::Text)
        {
            return Vec::new();
        }
        self.suspend_open();
        if self.restore_parked("text") {
            return Vec::new();
        }
        let mut events = Vec::new();
        let output_index = self.output_items.len();
        let item_id = format!("item-{output_index}");
        let mut item = Map::new();
        item.insert("id".into(), json!(item_id));
        item.insert("type".into(), json!("message"));
        item.insert("role".into(), json!("assistant"));
        item.insert("status".into(), json!("in_progress"));
        item.insert("content".into(), json!([]));
        self.open = Some(OpenOutput {
            kind: OpenKind::Text,
            item: item.clone(),
            item_id,
            output_index,
            content_index: 0,
            call_id: None,
            is_computer: false,
            chunks: Vec::new(),
            summary_parts: BTreeMap::new(),
            source_summary_indexes: HashMap::new(),
            next_summary_index: 0,
        });
        self.output_items.push(item.clone());
        let mut payload = Map::new();
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("item".into(), Value::Object(item));
        events.push(self.emit("response.output_item.added", payload));
        let mut payload = Map::new();
        payload.insert(
            "item_id".into(),
            json!(self.open.as_ref().map(|open| open.item_id.clone())),
        );
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("content_index".into(), json!(0));
        payload.insert(
            "part".into(),
            json!({"type": "output_text", "text": "", "annotations": []}),
        );
        events.push(self.emit("response.content_part.added", payload));
        events
    }

    fn open_reasoning(&mut self, content: &ContentPart) -> Vec<(String, Value)> {
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.kind == OpenKind::Reasoning)
        {
            return Vec::new();
        }
        self.suspend_open();
        if self.restore_parked("reasoning") {
            return Vec::new();
        }
        let mut events = Vec::new();
        let output_index = self.output_items.len();
        let item_id = format!("item-{output_index}");
        let mut item = Map::new();
        item.insert("id".into(), json!(item_id));
        item.insert("type".into(), json!("reasoning"));
        item.insert("status".into(), json!("in_progress"));
        item.insert("summary".into(), json!([]));
        item.insert("content".into(), json!([]));
        if let ContentPart::Reasoning {
            encrypted_content: Some(encrypted_content),
            ..
        } = content
        {
            item.insert("encrypted_content".into(), json!(encrypted_content));
        }
        self.open = Some(OpenOutput {
            kind: OpenKind::Reasoning,
            item: item.clone(),
            item_id,
            output_index,
            content_index: 0,
            call_id: None,
            is_computer: false,
            chunks: Vec::new(),
            summary_parts: BTreeMap::new(),
            source_summary_indexes: HashMap::new(),
            next_summary_index: 0,
        });
        self.output_items.push(item.clone());
        let mut payload = Map::new();
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("item".into(), Value::Object(item));
        events.push(self.emit("response.output_item.added", payload));
        events
    }

    /// Maps a source reasoning-item/summary-index pair to one summary part.
    fn output_summary_index(
        open: &mut OpenOutput,
        source_item_id: Option<&str>,
        source_output_index: Option<i64>,
        content: &ContentPart,
    ) -> i64 {
        let source_index = match content {
            ContentPart::Reasoning { summary_index, .. } => summary_index.unwrap_or(0),
            _ => 0,
        };
        let source_identity = match source_item_id {
            Some(item_id) => format!("item:{item_id}"),
            None => format!("output:{}", source_output_index.unwrap_or(0)),
        };
        let key = format!("{source_identity}:{source_index}");
        if let Some(existing) = open.source_summary_indexes.get(&key) {
            return *existing;
        }
        let mut output_index = source_index;
        if open.summary_parts.contains_key(&output_index) {
            output_index = open.next_summary_index;
            while open.summary_parts.contains_key(&output_index) {
                output_index += 1;
            }
        }
        open.source_summary_indexes.insert(key, output_index);
        open.next_summary_index = open.next_summary_index.max(output_index + 1);
        output_index
    }

    fn open_reasoning_summary_part(
        &mut self,
        item_id: &str,
        output_index: usize,
        summary_index: i64,
    ) -> Vec<(String, Value)> {
        if let Some(open) = self.open.as_mut() {
            if open.summary_parts.contains_key(&summary_index) {
                return Vec::new();
            }
            open.summary_parts.insert(summary_index, Vec::new());
        }
        let mut payload = Map::new();
        payload.insert("item_id".into(), json!(item_id));
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("summary_index".into(), json!(summary_index));
        payload.insert("part".into(), json!({"type": "summary_text", "text": ""}));
        vec![self.emit("response.reasoning_summary_part.added", payload)]
    }

    fn open_tool(&mut self, call_id: &str, name: Option<&str>) -> Vec<(String, Value)> {
        if self.open.as_ref().is_some_and(|open| {
            open.kind == OpenKind::Tool && open.call_id.as_deref() == Some(call_id)
        }) {
            return Vec::new();
        }
        self.suspend_open();
        let key = Self::open_key(OpenKind::Tool, Some(call_id));
        if self.restore_parked(&key) {
            return Vec::new();
        }
        let mut events = Vec::new();
        let output_index = self.output_items.len();
        let item_id = call_id.to_owned();
        let is_computer = name == Some("computer");
        if is_computer {
            self.computer_calls.insert(call_id.to_owned());
        }
        let item = if is_computer {
            Map::from_iter([
                ("id".to_owned(), json!(item_id)),
                ("type".to_owned(), json!("computer_call")),
                ("call_id".to_owned(), json!(call_id)),
                ("actions".to_owned(), json!([])),
                ("pending_safety_checks".to_owned(), json!([])),
                ("status".to_owned(), json!("in_progress")),
            ])
        } else {
            let mut item = Map::from_iter([
                ("id".to_owned(), json!(item_id)),
                ("type".to_owned(), json!("function_call")),
                ("call_id".to_owned(), json!(call_id)),
                ("arguments".to_owned(), json!("")),
                ("status".to_owned(), json!("in_progress")),
            ]);
            if let Some(name) = name {
                item.insert("name".into(), json!(name));
            }
            item
        };
        self.open = Some(OpenOutput {
            kind: OpenKind::Tool,
            item: item.clone(),
            item_id,
            output_index,
            content_index: 0,
            call_id: Some(call_id.to_owned()),
            is_computer,
            chunks: Vec::new(),
            summary_parts: BTreeMap::new(),
            source_summary_indexes: HashMap::new(),
            next_summary_index: 0,
        });
        self.output_items.push(item.clone());
        let mut payload = Map::new();
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("item".into(), Value::Object(item));
        events.push(self.emit("response.output_item.added", payload));
        events
    }

    fn process_content(
        &mut self,
        content: &ContentPart,
        source_item_id: Option<&str>,
        source_output_index: Option<i64>,
    ) -> Vec<(String, Value)> {
        match content {
            ContentPart::Text { text } => {
                let mut events = self.open_text();
                let (item_id, output_index, content_index) = self
                    .open
                    .as_ref()
                    .map(|open| (open.item_id.clone(), open.output_index, open.content_index))
                    .unwrap_or_default();
                let mut payload = Map::new();
                payload.insert("item_id".into(), json!(item_id));
                payload.insert("output_index".into(), json!(output_index));
                payload.insert("content_index".into(), json!(content_index));
                payload.insert("delta".into(), json!(text));
                events.push(self.emit("response.output_text.delta", payload));
                if let Some(open) = self.open.as_mut() {
                    open.chunks.push(text.clone());
                    let needs_part = !matches!(
                        open.item.get("content"),
                        Some(Value::Array(parts)) if !parts.is_empty()
                    );
                    if needs_part {
                        open.item.insert(
                            "content".into(),
                            json!([{"type": "output_text", "text": "", "annotations": []}]),
                        );
                    }
                }
                events
            }
            ContentPart::Reasoning {
                summary,
                encrypted_content,
                ..
            } => {
                let mut events = self.open_reasoning(content);
                if let (Some(summary), Some(open)) = (summary, self.open.as_mut()) {
                    if open.kind == OpenKind::Reasoning {
                        let summary_index = Self::output_summary_index(
                            open,
                            source_item_id,
                            source_output_index,
                            content,
                        );
                        let item_id = open.item_id.clone();
                        let output_index = open.output_index;
                        events.extend(self.open_reasoning_summary_part(
                            &item_id,
                            output_index,
                            summary_index,
                        ));
                        let Some(open) = self.open.as_mut() else {
                            return events;
                        };
                        let Some(summary_chunks) = open.summary_parts.get(&summary_index) else {
                            return events;
                        };
                        let separator = if summary_chunks.is_empty()
                            && open.summary_parts.len() > 1
                            && !summary.starts_with(char::is_whitespace)
                        {
                            "\n\n"
                        } else {
                            ""
                        };
                        let delta = format!("{separator}{summary}");
                        let item_id = open.item_id.clone();
                        let output_index = open.output_index;
                        if let Some(summary_chunks) = open.summary_parts.get_mut(&summary_index) {
                            summary_chunks.push(delta.clone());
                        }
                        let mut payload = Map::new();
                        payload.insert("item_id".into(), json!(item_id));
                        payload.insert("output_index".into(), json!(output_index));
                        payload.insert("summary_index".into(), json!(summary_index));
                        payload.insert("delta".into(), json!(delta));
                        events.push(self.emit("response.reasoning_summary_text.delta", payload));
                    }
                }
                if let Some(encrypted_content) = encrypted_content {
                    let (item_id, output_index) = self
                        .open
                        .as_ref()
                        .map(|open| (open.item_id.clone(), open.output_index))
                        .unwrap_or_default();
                    let mut payload = Map::new();
                    payload.insert("item_id".into(), json!(item_id));
                    payload.insert("output_index".into(), json!(output_index));
                    payload.insert("encrypted_content".into(), json!(encrypted_content));
                    events.push(self.emit("response.reasoning.encrypted_content", payload));
                }
                // Readable reasoning text (non-opaque payload) is the model's
                // visible chain of thought, distinct from the condensed summary.
                let readable = match content {
                    ContentPart::Reasoning {
                        payload,
                        opaque,
                        encrypted_content,
                        ..
                    } if *opaque != Some(true) && encrypted_content.is_none() => payload.as_str(),
                    _ => None,
                };
                if let (Some(readable), Some(open)) = (readable, self.open.as_mut()) {
                    let item_id = open.item_id.clone();
                    let output_index = open.output_index;
                    open.chunks.push(readable.to_owned());
                    let needs_content = !matches!(
                        open.item.get("content"),
                        Some(Value::Array(parts)) if !parts.is_empty()
                    );
                    if needs_content {
                        open.item.insert(
                            "content".into(),
                            json!([{"type": "reasoning_text", "text": ""}]),
                        );
                    }
                    let mut payload = Map::new();
                    payload.insert("item_id".into(), json!(item_id));
                    payload.insert("output_index".into(), json!(output_index));
                    payload.insert("content_index".into(), json!(0));
                    payload.insert("delta".into(), json!(readable));
                    events.push(self.emit("response.reasoning_text.delta", payload));
                }
                events
            }
            ContentPart::ToolCall {
                call_id,
                name,
                arguments,
                ..
            } => {
                let mut events = self.open_tool(call_id, Some(name));
                let delta = match arguments {
                    Value::String(value) => value.clone(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                };
                let (output_index, is_computer) = self
                    .open
                    .as_ref()
                    .map(|open| (open.output_index, open.is_computer))
                    .unwrap_or_default();
                if let Some(open) = self.open.as_mut() {
                    open.chunks.push(delta.clone());
                }
                if !is_computer {
                    let mut payload = Map::new();
                    payload.insert("item_id".into(), json!(call_id));
                    payload.insert("output_index".into(), json!(output_index));
                    payload.insert("delta".into(), json!(delta));
                    events.push(self.emit("response.function_call_arguments.delta", payload));
                }
                events
            }
            ContentPart::ToolResult {
                call_id, content, ..
            } => self.process_tool_result(call_id, content),
            ContentPart::Image { payload } => {
                let mut events = self.open_text();
                let image_part = json!({"type": "output_image", "image": payload});
                let (item_id, output_index, content_index) = self
                    .open
                    .as_ref()
                    .map(|open| (open.item_id.clone(), open.output_index, open.content_index))
                    .unwrap_or_default();
                let mut event_payload = Map::new();
                event_payload.insert("item_id".into(), json!(item_id));
                event_payload.insert("output_index".into(), json!(output_index));
                event_payload.insert("content_index".into(), json!(content_index));
                event_payload.insert("part".into(), image_part.clone());
                events.push(self.emit("response.content_part.added", event_payload));
                if let Some(open) = self.open.as_mut() {
                    let mut existing = open
                        .item
                        .get("content")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    existing.push(image_part);
                    open.item.insert("content".into(), Value::Array(existing));
                }
                events
            }
            ContentPart::Refusal { text } => {
                let mut payload = Map::new();
                payload.insert("name".into(), json!("refusal"));
                payload.insert("payload".into(), json!(text));
                vec![self.emit("response.extension", payload)]
            }
            other => {
                let kind = other.kind();
                let mut payload = Map::new();
                payload.insert("name".into(), json!(kind));
                payload.insert(
                    "payload".into(),
                    serde_json::to_value(other).unwrap_or(Value::Null),
                );
                vec![self.emit("response.extension", payload)]
            }
        }
    }

    fn process_tool_result(
        &mut self,
        call_id: &str,
        content: &ToolResultContent,
    ) -> Vec<(String, Value)> {
        // Finalize exactly this call wherever it lives (active or parked) so a
        // result for one parallel call never closes its siblings.
        let key = Self::open_key(OpenKind::Tool, Some(call_id));
        let mut events: Vec<(String, Value)> = Vec::new();
        if self.open.as_ref().is_some_and(|open| {
            open.kind == OpenKind::Tool && open.call_id.as_deref() == Some(call_id)
        }) {
            if let Some(state) = self.open.take() {
                self.parked.remove(&key);
                events = self.finalize_state(state);
            }
        } else if let Some(state) = self.parked.remove(&key) {
            events = self.finalize_state(state);
        }
        let output_index = self.output_items.len();
        let item = if self.computer_calls.contains(call_id) {
            Map::from_iter([
                ("id".to_owned(), json!(call_id)),
                ("type".to_owned(), json!("computer_call_output")),
                ("call_id".to_owned(), json!(call_id)),
                ("output".to_owned(), computer_output_to_wire(content)),
                ("status".to_owned(), json!("completed")),
            ])
        } else {
            Map::from_iter([
                ("id".to_owned(), json!(call_id)),
                ("type".to_owned(), json!("function_call_output")),
                ("call_id".to_owned(), json!(call_id)),
                ("output".to_owned(), output_to_wire(content)),
                ("status".to_owned(), json!("completed")),
            ])
        };
        self.output_items.push(item.clone());
        let mut payload = Map::new();
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("item".into(), Value::Object(item.clone()));
        events.push(self.emit("response.output_item.added", payload));
        let mut payload = Map::new();
        payload.insert("output_index".into(), json!(output_index));
        payload.insert("item".into(), Value::Object(item));
        events.push(self.emit("response.output_item.done", payload));
        events
    }

    fn process_terminal(
        &mut self,
        state: TerminalState,
        stop_reason: Option<CanonicalStopReason>,
        usage: Option<&UsageRecord>,
    ) -> Vec<(String, Value)> {
        if self.terminal {
            return self.lifecycle_error(
                "invalid_lifecycle",
                "Responses stream has more than one terminal event",
            );
        }
        if let Some(usage) = usage {
            self.usage = Some(usage.clone());
        }
        let mut events = self.close_all();
        let (event_type, status) = match state {
            TerminalState::Complete => ("response.completed", "completed"),
            TerminalState::Failed => ("response.failed", "failed"),
            TerminalState::Aborted => ("response.incomplete", "incomplete"),
        };
        let mut response = self.response_object(status);
        if status == "incomplete" {
            if let Some(reason) = stop_reason.and_then(|stop_reason| match stop_reason {
                CanonicalStopReason::Length => Some("max_output_tokens"),
                CanonicalStopReason::ContentFilter => Some("content_filter"),
                _ => None,
            }) {
                if let Some(response) = response.as_object_mut() {
                    response.insert("incomplete_details".into(), json!({"reason": reason}));
                }
            }
        }
        if state == TerminalState::Failed {
            if let Some(response) = response.as_object_mut() {
                response.insert(
                    "error".into(),
                    json!({
                        "type": "server_error",
                        "code": stop_reason.map(CanonicalStopReason::as_str).unwrap_or("provider_error"),
                        "message": "The upstream response failed",
                    }),
                );
            }
        }
        let mut payload = Map::new();
        payload.insert("response".into(), response);
        events.push(self.emit(event_type, payload));
        self.terminal = true;
        events
    }

    /// Consume one canonical event and return all corresponding wire events.
    pub fn push(&mut self, event: &CanonicalEvent) -> Vec<(String, Value)> {
        let sequence = event.sequence_number();
        if self
            .input_sequence
            .is_some_and(|previous| sequence <= previous)
        {
            return self.lifecycle_error(
                "invalid_sequence",
                format!("Canonical sequence_number must increase monotonically: {sequence}"),
            );
        }
        self.input_sequence = Some(sequence);
        if self.terminal {
            return self.lifecycle_error(
                "invalid_lifecycle",
                "Canonical event arrived after terminal Responses event",
            );
        }
        match event {
            CanonicalEvent::ResponseStart {
                model,
                system_fingerprint,
                ..
            } => {
                if let Some(fingerprint) = system_fingerprint {
                    self.system_fingerprint = Some(fingerprint.clone());
                }
                self.start(model.as_deref())
            }
            CanonicalEvent::MessageStart {
                system_fingerprint, ..
            } => {
                if let Some(fingerprint) = system_fingerprint {
                    self.system_fingerprint = Some(fingerprint.clone());
                }
                self.start(None)
            }
            CanonicalEvent::ContentDelta {
                content,
                item_id,
                output_index,
                ..
            } => {
                let mut events = self.start(None);
                events.extend(self.process_content(content, item_id.as_deref(), *output_index));
                events
            }
            CanonicalEvent::ToolCallDelta {
                call_id,
                name,
                arguments_delta,
                ..
            } => {
                let mut events = self.start(None);
                events.extend(self.open_tool(call_id, name.as_deref()));
                let delta = arguments_delta.clone().unwrap_or_default();
                let (output_index, is_computer) = self
                    .open
                    .as_ref()
                    .map(|open| (open.output_index, open.is_computer))
                    .unwrap_or_default();
                if let Some(open) = self.open.as_mut() {
                    open.chunks.push(delta.clone());
                }
                if !is_computer {
                    let mut payload = Map::new();
                    payload.insert("item_id".into(), json!(call_id));
                    payload.insert("output_index".into(), json!(output_index));
                    payload.insert("delta".into(), json!(delta));
                    events.push(self.emit("response.function_call_arguments.delta", payload));
                }
                events
            }
            CanonicalEvent::ToolResult {
                call_id, content, ..
            } => {
                let mut events = self.start(None);
                events.extend(
                    self.process_tool_result(call_id, &ToolResultContent::Parts(content.clone())),
                );
                events
            }
            CanonicalEvent::Usage { usage, .. } => {
                self.usage = Some(usage.clone());
                self.start(None)
            }
            CanonicalEvent::Keepalive { .. } => {
                let mut events = self.start(None);
                events.push(self.emit("response.keepalive", Map::new()));
                events
            }
            CanonicalEvent::Error {
                category, message, ..
            } => {
                let mut events = self.start(None);
                let mut payload = Map::new();
                payload.insert("category".into(), json!(category));
                payload.insert("message".into(), json!(message));
                events.push(self.emit("response.error", payload));
                events
            }
            CanonicalEvent::Terminal {
                state,
                stop_reason,
                usage,
                ..
            } => {
                let mut events = self.start(None);
                events.extend(self.process_terminal(*state, *stop_reason, usage.as_ref()));
                events
            }
        }
    }

    /// Complete the encoder and enforce exactly one terminal event.
    pub fn finish(&mut self) -> Vec<(String, Value)> {
        if self.terminal {
            return Vec::new();
        }
        self.lifecycle_error(
            "invalid_lifecycle",
            "Responses stream ended without a terminal event",
        )
    }
}

/// Encodes canonical events as one non-streaming Responses body.
pub fn encode_responses_response(events: &[CanonicalEvent], model: &str) -> Value {
    let mut encoder = ResponsesStreamEncoder::new(model);
    let mut response = Value::Null;
    for event in events {
        for (event_type, payload) in encoder.push(event) {
            if matches!(
                event_type.as_str(),
                "response.completed" | "response.incomplete" | "response.failed"
            ) {
                if let Some(value) = payload.get("response") {
                    response = value.clone();
                }
            }
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{ReasoningEffort, TerminalState};
    use serde_json::json;

    #[test]
    fn parses_string_input_and_instructions() {
        let body = json!({
            "model": "gpt-5",
            "input": "hello",
            "instructions": "be terse",
            "stream": true,
            "max_output_tokens": 64,
            "parallel_tool_calls": false,
            "temperature": 0.2,
            "top_p": 0.9,
            "text": {"format": {"type": "json_object"}},
            "reasoning": {"effort": "high", "summary": "auto"},
            "previous_response_id": "resp_1",
            "prompt_cache_key": "k",
            "metadata": {"user": "u", "bad": [1]},
            "store": false,
            "include": ["reasoning.encrypted_content", "nope"],
            "service_tier": "priority"
        });
        let request = ResponsesAdapter.parse(&body).unwrap();
        assert_eq!(request.model, "gpt-5");
        assert_eq!(request.source_surface, SourceSurface::Responses);
        assert!(request.stream);
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].role, Role::User);
        assert_eq!(
            request.messages[0].content,
            vec![ContentPart::Text {
                text: "hello".into()
            }]
        );
        assert_eq!(
            request.instructions.as_ref().unwrap(),
            &vec![ContentPart::Text {
                text: "be terse".into()
            }]
        );
        assert_eq!(request.generation_controls.max_output_tokens, Some(64));
        assert_eq!(request.generation_controls.parallel_tool_calls, Some(false));
        assert_eq!(request.generation_controls.temperature, Some(0.2));
        assert_eq!(request.generation_controls.top_p, Some(0.9));
        assert_eq!(
            request.reasoning.as_ref().unwrap().effort,
            Some(ReasoningEffort::High)
        );
        assert_eq!(
            request
                .conversation
                .as_ref()
                .unwrap()
                .previous_response_id
                .as_deref(),
            Some("resp_1")
        );
        assert_eq!(
            request.cache_hint,
            Some(keyla_core::CacheHint::StablePrefix)
        );
        assert_eq!(
            request.metadata.as_ref().unwrap().get("user"),
            Some(&json!("u"))
        );
        assert!(request.metadata.as_ref().unwrap().get("bad").is_none());
        assert_eq!(
            request
                .generation_controls
                .extensions
                .get("extension:responses.include"),
            Some(&json!(["reasoning.encrypted_content"]))
        );
        assert_eq!(
            request
                .generation_controls
                .extensions
                .get("extension:responses.store"),
            Some(&json!(false))
        );
        assert!(matches!(
            request.response_format,
            Some(keyla_core::ResponseFormat::JsonObject { .. })
        ));
    }

    #[test]
    fn parses_item_array_hoisting_and_reasoning_folding() {
        let body = json!({
            "model": "gpt-5",
            "input": [
                {"type": "message", "role": "system", "content": "sys"},
                {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "dev"}]},
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]},
                {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "think"}]},
                {"type": "function_call", "call_id": "call_1", "name": "read", "arguments": "{}"},
                {"type": "reasoning", "id": "rs_2", "content": [{"type": "reasoning_text", "text": "after"}]},
                {"type": "function_call_output", "call_id": "call_1", "output": "done"}
            ]
        });
        let request = ResponsesAdapter.parse(&body).unwrap();
        assert_eq!(
            request.system.as_ref().unwrap(),
            &vec![ContentPart::Text { text: "sys".into() }]
        );
        assert_eq!(
            request.instructions.as_ref().unwrap(),
            &vec![ContentPart::Text { text: "dev".into() }]
        );
        assert_eq!(request.messages.len(), 3);
        assert_eq!(request.messages[0].role, Role::User);
        // Leading reasoning folds into the assistant tool-call turn...
        assert_eq!(request.messages[1].role, Role::Assistant);
        assert!(matches!(
            request.messages[1].content[0],
            ContentPart::Reasoning { .. }
        ));
        assert!(matches!(
            request.messages[1].content[1],
            ContentPart::Reasoning { .. }
        ));
        assert!(matches!(
            request.messages[1].content[2],
            ContentPart::ToolCall { .. }
        ));
        assert_eq!(request.messages[2].role, Role::Tool);
        assert!(matches!(
            request.messages[2].content[0],
            ContentPart::ToolResult {
                content: ToolResultContent::Text(_),
                ..
            }
        ));
        let metadata = request
            .generation_controls
            .extensions
            .get("extension:responses.item_metadata")
            .unwrap();
        assert_eq!(metadata.as_array().unwrap().len(), 7);
        assert_eq!(metadata[3]["type"], "reasoning");
    }

    #[test]
    fn parses_tools_choice_and_text_format() {
        let body = json!({
            "model": "gpt-5",
            "input": "hi",
            "tools": [
                {"type": "function", "name": "read", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}},
                {"type": "custom", "name": "edit", "format": {"type": "text"}},
                {"type": "web_search_preview"}
            ],
            "tool_choice": {"type": "function", "name": "read"},
            "text": {"format": {"type": "json_schema", "name": "answer", "schema": {"type": "object"}, "strict": true}}
        });
        let request = ResponsesAdapter.parse(&body).unwrap();
        let tools = request.tools.as_ref().unwrap();
        assert_eq!(tools.len(), 3);
        assert_eq!(tools[0].name, "read");
        assert_eq!(tools[0].tool_type, Some(keyla_core::ToolType::Function));
        assert_eq!(tools[1].tool_type, Some(keyla_core::ToolType::Provider));
        assert_eq!(tools[2].tool_type, Some(keyla_core::ToolType::WebSearch));
        assert_eq!(
            request.tool_choice,
            Some(keyla_core::ToolChoice::Tool {
                name: "read".into()
            })
        );
        let Some(keyla_core::ResponseFormat::JsonSchema { name, strict, .. }) =
            request.response_format
        else {
            panic!("expected json_schema format");
        };
        assert_eq!(name.as_deref(), Some("answer"));
        assert_eq!(strict, Some(true));
    }

    #[test]
    fn rejects_malformed_bodies() {
        let error = ResponsesAdapter.parse(&json!([])).unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
        let error = ResponsesAdapter.parse(&json!({"input": "x"})).unwrap_err();
        assert_eq!(error.message, "Responses request requires model");
        let error = ResponsesAdapter
            .parse(&json!({"model": "m", "max_output_tokens": 0}))
            .unwrap_err();
        assert_eq!(
            error.message,
            "max_output_tokens must be a positive integer"
        );
        let error = ResponsesAdapter
            .parse(&json!({"model": "m", "input": "x", "include": "nope"}))
            .unwrap_err();
        assert_eq!(error.message, "Responses include must be an array");
        let error = ResponsesAdapter
            .parse(&json!({"model": "m", "input": [{"type": "message", "role": "wizard"}]}))
            .unwrap_err();
        assert_eq!(error.message, "Unsupported Responses message role: wizard");
        let error = ResponsesAdapter
            .parse(&json!({"model": "m", "input": "x", "prompt_cache_breakpoint": {}}))
            .unwrap_err();
        assert_eq!(error.message, UNSUPPORTED_EXPLICIT_PROMPT_CACHE_MESSAGE);
        let error = ResponsesAdapter
            .parse(&json!({"model": "m", "input": [{"type": "reasoning", "encrypted_content": 5}]}))
            .unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::CapabilityUnsupported);
    }

    #[test]
    fn matches_only_top_level_responses_markers() {
        let adapter = ResponsesAdapter;
        assert!(adapter.matches_body_shape(&json!({"input": [{"role": "user", "content": "x"}]})));
        assert!(adapter.matches_body_shape(&json!({"instructions": "x"})));
        assert!(adapter.matches_body_shape(&json!({"previous_response_id": "r"})));
        assert!(adapter.matches_body_shape(&json!({"conversation": "c"})));
        assert!(!adapter.matches_body_shape(&json!({"messages": []})));
        assert!(!adapter.matches_body_shape(&json!({"input": "x"})));
        assert!(!adapter.matches_body_shape(&json!({"input": 5})));
    }

    #[test]
    fn parses_wrapped_surface_input_bodies() {
        let adapter = ResponsesAdapter;
        let body = json!({"body": {"model": "m", "input": [{"role": "user", "content": "hi"}]}, "headers": {}});
        assert!(adapter.matches_body_shape(&body));
        let request = adapter.parse(&body).unwrap();
        assert_eq!(request.model, "m");
        let body = json!({"body": "{\"model\":\"m\",\"input\":\"hi\"}", "path": "/v1/responses"});
        assert_eq!(adapter.parse(&body).unwrap().messages.len(), 1);
    }

    #[test]
    fn stream_encoder_emits_ordered_lifecycle_events() {
        let events = vec![
            CanonicalEvent::ResponseStart {
                sequence_number: 1,
                event_id: None,
                response_id: None,
                model: Some("gpt-5".into()),
                system_fingerprint: Some("fp".into()),
                timestamp: None,
            },
            CanonicalEvent::ContentDelta {
                sequence_number: 2,
                content: ContentPart::Text {
                    text: "hello".into(),
                },
                event_id: None,
                response_id: None,
                item_id: None,
                output_index: None,
                content_index: None,
                timestamp: None,
            },
            CanonicalEvent::Terminal {
                sequence_number: 3,
                state: TerminalState::Complete,
                stop_reason: Some(CanonicalStopReason::Stop),
                provider_stop_reason: None,
                stop_details: None,
                usage: None,
                event_id: None,
                response_id: None,
                timestamp: None,
            },
        ];
        let mut encoder = ResponsesStreamEncoder::new("gpt-5")
            .with_response_id("resp_fixed")
            .with_created_at(7);
        let mut wire = Vec::new();
        for event in &events {
            wire.extend(encoder.push(event));
        }
        wire.extend(encoder.finish());
        let names: Vec<&str> = wire.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        let created = &wire[0].1;
        assert_eq!(created["response"]["id"], "resp_fixed");
        assert_eq!(created["response"]["status"], "in_progress");
        let delta = &wire[3].1;
        assert_eq!(delta["delta"], "hello");
        assert_eq!(delta["sequence_number"], 3);
        let completed = &wire.last().unwrap().1;
        assert_eq!(completed["response"]["status"], "completed");
        assert_eq!(
            completed["response"]["output"][0]["content"][0]["text"],
            "hello"
        );
        assert_eq!(completed["response"]["system_fingerprint"], "fp");
        assert_eq!(completed["response"]["created_at"], 7);
    }

    #[test]
    fn elapsed_reasoning_and_tool_deltas_are_shaped() {
        let mut encoder = ResponsesStreamEncoder::new("gpt-5");
        let mut wire = encoder.push(&CanonicalEvent::MessageStart {
            sequence_number: 1,
            event_id: None,
            response_id: None,
            model: None,
            system_fingerprint: None,
            timestamp: None,
        });
        wire.extend(encoder.push(&CanonicalEvent::ContentDelta {
            sequence_number: 2,
            content: ContentPart::Reasoning {
                payload: json!("thought"),
                opaque: None,
                summary: Some("summary".into()),
                summary_index: Some(0),
                signature: None,
                encrypted_content: None,
            },
            event_id: None,
            response_id: None,
            item_id: Some("rs_1".into()),
            output_index: Some(0),
            content_index: None,
            timestamp: None,
        }));
        wire.extend(encoder.push(&CanonicalEvent::ToolCallDelta {
            sequence_number: 3,
            call_id: "call_1".into(),
            index: None,
            name: Some("read".into()),
            arguments_delta: Some("{\"a\":1}".into()),
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            timestamp: None,
        }));
        wire.extend(encoder.push(&CanonicalEvent::Terminal {
            sequence_number: 4,
            state: TerminalState::Complete,
            stop_reason: Some(CanonicalStopReason::ToolUse),
            provider_stop_reason: None,
            stop_details: None,
            usage: None,
            event_id: None,
            response_id: None,
            timestamp: None,
        }));
        let names: Vec<&str> = wire.iter().map(|(name, _)| name.as_str()).collect();
        assert!(names.contains(&"response.reasoning_summary_part.added"));
        assert!(names.contains(&"response.reasoning_summary_text.delta"));
        assert!(names.contains(&"response.reasoning_text.delta"));
        assert!(names.contains(&"response.function_call_arguments.delta"));
        assert!(names.contains(&"response.function_call_arguments.done"));
        assert!(names.contains(&"response.output_item.done"));
        let reasoning_added = wire
            .iter()
            .find(|(name, payload)| {
                name == "response.output_item.added" && payload["item"]["type"] == "reasoning"
            })
            .unwrap();
        assert_eq!(reasoning_added.1["item"]["type"], "reasoning");
        let completed = &wire.last().unwrap().1;
        let output = completed["response"]["output"].as_array().unwrap();
        assert_eq!(output[0]["type"], "reasoning");
        assert_eq!(output[0]["summary"][0]["text"], "summary");
        assert_eq!(output[0]["content"][0]["text"], "thought");
        assert_eq!(output[1]["type"], "function_call");
        assert_eq!(output[1]["arguments"], "{\"a\":1}");
    }

    #[test]
    fn non_streaming_encode_returns_the_terminal_response() {
        let events = crate::response::responses::parse_responses_response(
            &json!({
                "id": "resp_1",
                "model": "gpt-5",
                "status": "completed",
                "output": [{
                    "type": "message", "id": "msg_1", "role": "assistant",
                    "content": [{"type": "output_text", "text": "hello"}]
                }]
            }),
            "gpt-5",
        );
        let response = encode_responses_response(&events, "gpt-5");
        assert!(
            response["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("resp-"))
        );
        assert_eq!(response["status"], "completed");
        assert_eq!(response["output"][0]["content"][0]["text"], "hello");
    }

    #[test]
    fn non_streaming_encode_marks_incomplete_and_failed() {
        let events = vec![CanonicalEvent::Terminal {
            sequence_number: 1,
            state: TerminalState::Aborted,
            stop_reason: Some(CanonicalStopReason::Length),
            provider_stop_reason: None,
            stop_details: None,
            usage: None,
            event_id: None,
            response_id: None,
            timestamp: None,
        }];
        let response = encode_responses_response(&events, "gpt-5");
        assert_eq!(response["status"], "incomplete");
        assert_eq!(
            response["incomplete_details"]["reason"],
            "max_output_tokens"
        );

        let events = vec![CanonicalEvent::Terminal {
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
        let response = encode_responses_response(&events, "gpt-5");
        assert_eq!(response["status"], "failed");
        assert_eq!(response["error"]["code"], "error");
    }
}
