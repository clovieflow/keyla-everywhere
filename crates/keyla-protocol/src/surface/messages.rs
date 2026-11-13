//! Anthropic Messages surface adapter: wire request parsing, response
//! encoding, and the incremental SSE encoder.
//! Port of `src/transport/surface/messages/{parse,encode,stream,adapter}.ts`.

use std::collections::{BTreeMap, HashMap, HashSet};

use keyla_core::{
    CacheHint, CanonicalEvent, CanonicalMessage, CanonicalRequest, CanonicalStopReason,
    ContentPart, GatewayError, GatewayErrorCode, GenerationControls, ReasoningIntent, Role,
    SourceSurface, StopSequence, TerminalState, ThinkingDisplay, ThinkingType, ToolResultContent,
    UsageRecord, can_contain_tool_result,
};
use serde_json::{Map, Value, json};

use crate::dialects::{
    CANONICAL_REASONING_EFFORTS, ToolDialect, is_reasoning_effort, parse_reasoning_intent,
    parse_tool_choice, parse_tool_definition,
};
use crate::primitives::is_record;
use crate::surface::events::{
    ReasoningSummaryIdentity, reasoning_summary_identity, reasoning_summary_separator,
};
use crate::surface::tool_identity::{ToolCallState, ToolCallTracker};

// ─── Request parsing ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct MessagesParseOptions {
    model_generation: Option<String>,
    headers: Option<BTreeMap<String, String>>,
}

fn invalid(message: impl Into<String>) -> GatewayError {
    GatewayError::invalid_request(message)
}

fn ledger_error(message: impl Into<String>) -> GatewayError {
    let mut details = Map::new();
    details.insert("surface".into(), json!("messages"));
    details.insert("reason".into(), json!("tool_ledger_mismatch"));
    GatewayError::new(GatewayErrorCode::InvalidRequest, 400, message, details)
}

fn finite_number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite())
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

fn text_part(value: &Value) -> ContentPart {
    ContentPart::Text {
        text: match value {
            Value::String(text) => text.clone(),
            other => js_text(other),
        },
    }
}

fn content_array(value: &Value, label: &str) -> Result<Vec<Value>, GatewayError> {
    if value.is_string() {
        return Ok(vec![value.clone()]);
    }
    match value.as_array() {
        Some(entries) => Ok(entries.clone()),
        None => Err(invalid(format!(
            "Messages {label} must be a string or block array"
        ))),
    }
}

fn parse_block(value: &Value) -> Result<ContentPart, GatewayError> {
    if value.is_string() {
        return Ok(text_part(value));
    }
    let Some(block) = value.as_object() else {
        return Ok(ContentPart::Extension {
            name: "unknown".into(),
            payload: value.clone(),
        });
    };
    let kind = block.get("type").and_then(Value::as_str);
    match kind {
        Some("text") => Ok(text_part(
            block.get("text").unwrap_or(&Value::String(String::new())),
        )),
        Some("image") => Ok(ContentPart::Image {
            payload: value.clone(),
        }),
        Some("document") => {
            let source = block
                .get("source")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let source_type = source.get("type").and_then(Value::as_str);
            let file_id = source.get("file_id").and_then(Value::as_str);
            let url = source.get("url").and_then(Value::as_str);
            let data = source
                .get("data")
                .filter(|value| !value.is_null())
                .cloned()
                .or_else(|| file_id.map(|value| json!(value)))
                .or_else(|| url.map(|value| json!(value)))
                .unwrap_or_else(|| json!(""));
            let media_type = source
                .get("media_type")
                .and_then(Value::as_str)
                .unwrap_or("application/octet-stream")
                .to_owned();
            let mut part = Map::new();
            part.insert("kind".into(), json!("document"));
            part.insert("data".into(), data);
            part.insert("media_type".into(), json!(media_type));
            if let Some(title) = block.get("title").and_then(Value::as_str) {
                part.insert("title".into(), json!(title));
            }
            if block
                .get("citations")
                .and_then(Value::as_object)
                .and_then(|citations| citations.get("enabled"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                part.insert("citations".into(), json!(true));
            }
            let source_type = match source_type {
                Some("base64") => Some(keyla_core::DocumentSourceType::Base64),
                Some("url") => Some(keyla_core::DocumentSourceType::Url),
                Some("file") => Some(keyla_core::DocumentSourceType::File),
                Some("text") => Some(keyla_core::DocumentSourceType::Text),
                _ => None,
            };
            if let Some(source_type) = source_type {
                part.insert("source_type".into(), json!(source_type));
            }
            if let Some(url) = url {
                part.insert("url".into(), json!(url));
            }
            if let Some(file_id) = file_id {
                part.insert("file_id".into(), json!(file_id));
            }
            serde_json::from_value(Value::Object(part))
                .map_err(|error| invalid(format!("Messages document failed to parse: {error}")))
        }
        Some("audio") => {
            let source = block.get("source").and_then(Value::as_object);
            let data = source
                .and_then(|source| source.get("data"))
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| json!(""));
            let media_type = source
                .and_then(|source| source.get("media_type"))
                .and_then(Value::as_str)
                .unwrap_or("audio/mpeg")
                .to_owned();
            Ok(ContentPart::Audio { data, media_type })
        }
        Some("refusal") => Ok(ContentPart::Refusal {
            text: block
                .get("refusal")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        }),
        Some("tool_use") => {
            let id = block.get("id").and_then(Value::as_str);
            let name = block.get("name").and_then(Value::as_str);
            let (Some(id), Some(name)) = (id, name) else {
                return Err(invalid("Messages tool_use requires id and name"));
            };
            Ok(ContentPart::ToolCall {
                call_id: id.to_owned(),
                name: name.to_owned(),
                arguments: block
                    .get("input")
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                index: block
                    .get("index")
                    .and_then(Value::as_f64)
                    .map(|number| number as i64),
                item_id: None,
                call_kind: None,
            })
        }
        Some("tool_result") => {
            let Some(call_id) = block.get("tool_use_id").and_then(Value::as_str) else {
                return Err(invalid("Messages tool_result requires tool_use_id"));
            };
            let content = match block.get("content") {
                Some(Value::String(text)) => ToolResultContent::Text(text.clone()),
                Some(Value::Array(entries)) => ToolResultContent::Parts(
                    entries
                        .iter()
                        .map(parse_block)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                Some(Value::Null) | None => ToolResultContent::Text(String::new()),
                Some(other) => ToolResultContent::Parts(vec![text_part(other)]),
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
        Some("server_tool_use") => Ok(ContentPart::Extension {
            name: "server_tool_use".into(),
            payload: value.clone(),
        }),
        Some("search_result") => Ok(ContentPart::Extension {
            name: "search_result".into(),
            payload: value.clone(),
        }),
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

fn parse_blocks(value: &Value, label: &str) -> Result<Vec<ContentPart>, GatewayError> {
    content_array(value, label)?
        .iter()
        .map(parse_block)
        .collect()
}

fn parse_message(value: &Value) -> Result<CanonicalMessage, GatewayError> {
    let Some(message) = value.as_object() else {
        return Err(invalid("message must be an object"));
    };
    let role = message.get("role").and_then(Value::as_str);
    let role = match role {
        Some("system") => Role::System,
        Some("user") => Role::User,
        Some("assistant") => Role::Assistant,
        Some("tool") => Role::Tool,
        _ => {
            return Err(invalid(
                "Messages message role must be system, user, assistant, or tool",
            ));
        }
    };
    if role == Role::System {
        return Ok(CanonicalMessage {
            role,
            content: parse_blocks(
                message.get("content").unwrap_or(&Value::Null),
                "system content",
            )?,
            phase: None,
        });
    }
    if role == Role::Tool {
        let call_id = message
            .get("tool_call_id")
            .or_else(|| message.get("tool_use_id"))
            .and_then(Value::as_str);
        let Some(call_id) = call_id else {
            return Err(invalid("Messages tool message requires tool_call_id"));
        };
        let content = match message.get("content") {
            Some(Value::String(text)) => ToolResultContent::Text(text.clone()),
            other => ToolResultContent::Parts(parse_blocks(
                other.unwrap_or(&Value::Null),
                "tool content",
            )?),
        };
        return Ok(CanonicalMessage {
            role: Role::User,
            content: vec![ContentPart::ToolResult {
                call_id: call_id.to_owned(),
                content,
                is_error: None,
                call_kind: None,
                item_id: None,
            }],
            phase: None,
        });
    }
    let phase = match message.get("phase").and_then(Value::as_str) {
        Some("commentary") => Some(keyla_core::AssistantItemPhase::Commentary),
        Some("final_answer") => Some(keyla_core::AssistantItemPhase::FinalAnswer),
        _ => None,
    };
    Ok(CanonicalMessage {
        role,
        content: parse_blocks(
            message.get("content").unwrap_or(&Value::Null),
            "message content",
        )?,
        phase,
    })
}

fn parse_tools(
    value: Option<&Value>,
) -> Result<Option<Vec<keyla_core::ToolDefinition>>, GatewayError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(entries) = value.as_array() else {
        return Err(invalid("Messages tools must be an array"));
    };
    let mut tools = Vec::with_capacity(entries.len());
    for entry in entries {
        let parsed = parse_tool_definition(entry, ToolDialect::Messages)
            .ok_or_else(|| invalid("Messages tool failed to parse"))?;
        tools.push(parsed);
    }
    Ok(Some(tools))
}

fn prefix_mismatch_behavior(value: Option<&Value>) -> Option<keyla_core::PrefixMismatchBehavior> {
    let value = value?.as_object()?;
    match value
        .get("prefix_mismatch_behavior")
        .and_then(Value::as_str)
    {
        Some("drop_block") => Some(keyla_core::PrefixMismatchBehavior::DropBlock),
        Some("error") => Some(keyla_core::PrefixMismatchBehavior::Error),
        _ => None,
    }
}

fn parse_generation(model: &str, explicit: Option<&str>) -> Option<f64> {
    let numeric = regex::Regex::new(r"^\d+(?:[.-]\d+)?$").ok()?;
    if let Some(explicit) = explicit {
        if numeric.is_match(explicit) {
            return explicit.replace('-', ".").parse::<f64>().ok();
        }
    }
    let source = explicit.unwrap_or(model);
    let pattern = regex::Regex::new(r"(?i)(?:claude[-_ ]?)(\d+)(?:[.-](\d+))?").ok()?;
    let captures = pattern.captures(source)?;
    let major = captures.get(1)?.as_str();
    let minor = captures.get(2).map_or("0", |capture| capture.as_str());
    format!("{major}.{minor}").parse::<f64>().ok()
}

fn parse_thinking(
    value: Option<&Value>,
    model: &str,
    options: &MessagesParseOptions,
    max_tokens: i64,
) -> Result<Option<ReasoningIntent>, GatewayError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(thinking) = value.as_object() else {
        return Err(invalid("thinking must be an object"));
    };
    let thinking_type = thinking.get("type").and_then(Value::as_str);
    let thinking_type = match thinking_type {
        Some("enabled") => ThinkingType::Enabled,
        Some("adaptive") => ThinkingType::Adaptive,
        Some("disabled") => ThinkingType::Disabled,
        _ => {
            return Err(invalid(
                "Messages thinking.type must be enabled, adaptive, or disabled",
            ));
        }
    };
    let display = thinking.get("display");
    if let Some(display) = display {
        if !matches!(display.as_str(), Some("summarized" | "omitted")) {
            return Err(invalid(
                "Messages thinking.display must be summarized or omitted",
            ));
        }
    }
    let display_value = match display.and_then(Value::as_str) {
        Some("summarized") => Some(ThinkingDisplay::Summarized),
        Some("omitted") => Some(ThinkingDisplay::Omitted),
        _ => None,
    };
    let prefix_mismatch = prefix_mismatch_behavior(thinking.get("block_binding"));
    if thinking_type == ThinkingType::Disabled {
        return Ok(Some(ReasoningIntent {
            thinking_type: Some(ThinkingType::Disabled),
            display: display_value,
            ..ReasoningIntent::default()
        }));
    }
    let budget = finite_number(thinking.get("budget_tokens"));
    let generation = parse_generation(model, options.model_generation.as_deref());
    let beta =
        keyla_core::get_header(options.headers.as_ref(), "anthropic-beta").is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|entry| entry == "interleaved-thinking-2025-05-14")
        });
    if thinking_type == ThinkingType::Enabled {
        let Some(budget) = budget.filter(|budget| budget.fract() == 0.0) else {
            return Err(invalid(
                "Manual Messages thinking requires integer budget_tokens",
            ));
        };
        if generation.is_some_and(|generation| generation >= 4.7) {
            return Err(invalid(
                "Manual Messages thinking is rejected for model generation 4.7+",
            ));
        }
        if budget < 1024.0 || (!beta && budget >= max_tokens as f64) {
            return Err(invalid(
                "Messages thinking budget_tokens must be at least 1024 and less than max_tokens",
            ));
        }
        return Ok(Some(ReasoningIntent {
            thinking_type: Some(ThinkingType::Enabled),
            budget_tokens: Some(budget as i64),
            display: display_value,
            prefix_mismatch_behavior: prefix_mismatch,
            ..ReasoningIntent::default()
        }));
    }
    if let Some(budget) = budget {
        if budget.fract() != 0.0 || budget < 1024.0 {
            return Err(invalid(
                "Adaptive Messages thinking budget_tokens must be an integer of at least 1024 when supplied",
            ));
        }
    }
    if let Some(budget) = budget {
        if !beta && budget >= max_tokens as f64 {
            return Err(invalid(
                "Adaptive Messages thinking budget_tokens must be less than max_tokens",
            ));
        }
    }
    Ok(Some(ReasoningIntent {
        thinking_type: Some(ThinkingType::Adaptive),
        budget_tokens: budget
            .filter(|budget| budget.is_finite())
            .map(|budget| budget as i64),
        display: display_value,
        prefix_mismatch_behavior: prefix_mismatch,
        ..ReasoningIntent::default()
    }))
}

fn system_blocks(value: Option<&Value>) -> Result<Option<Vec<ContentPart>>, GatewayError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(parse_blocks(value, "system")?)),
    }
}

fn cache_hint(body: &Map<String, Value>, system: Option<&[ContentPart]>) -> Option<CacheHint> {
    let top = body
        .get("cache_control")
        .filter(|value| !value.is_null())
        .or_else(|| body.get("cacheControl").filter(|value| !value.is_null()));
    let mut breakpoints: Vec<u32> = Vec::new();
    let mut inspect = |blocks: &Value| {
        let Some(blocks) = blocks.as_array() else {
            return;
        };
        for (index, block) in blocks.iter().enumerate() {
            if let Some(block) = block.as_object() {
                if block.contains_key("cache_control") || block.contains_key("cacheControl") {
                    breakpoints.push(index as u32);
                }
            }
        }
    };
    if let Some(system) = body.get("system") {
        inspect(system);
    }
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            if let Some(content) = message
                .as_object()
                .and_then(|message| message.get("content"))
            {
                inspect(content);
            }
        }
    }
    if top
        .and_then(Value::as_object)
        .and_then(|top| top.get("type"))
        .and_then(Value::as_str)
        == Some("ephemeral")
    {
        return Some(CacheHint::StablePrefix);
    }
    if !breakpoints.is_empty() {
        return Some(CacheHint::Breakpoint { list: breakpoints });
    }
    if system.is_some_and(|system| !system.is_empty())
        && body.get("cache_control").and_then(Value::as_str) == Some("auto")
    {
        return Some(CacheHint::StablePrefix);
    }
    None
}

fn extension_controls(
    body: &Map<String, Value>,
    user_id: Option<&Value>,
) -> BTreeMap<String, Value> {
    let mut extensions = BTreeMap::new();
    if let Some(context_management) = body
        .get("context_management")
        .filter(|value| !value.is_null())
        .or_else(|| {
            body.get("contextManagement")
                .filter(|value| !value.is_null())
        })
    {
        extensions.insert(
            "extension:context_management".into(),
            context_management.clone(),
        );
    }
    if let Some(user_id) = user_id {
        extensions.insert("extension:metadata_user_id".into(), user_id.clone());
    }
    if let Some(service_tier) = body.get("service_tier").and_then(Value::as_str) {
        if service_tier == "auto" || service_tier == "standard_only" {
            extensions.insert("extension:service_tier".into(), json!(service_tier));
        }
    }
    if let Some(container) = body.get("container").filter(|value| is_record(value)) {
        extensions.insert("extension:container".into(), container.clone());
    }
    if let Some(inference_geo) = body.get("inference_geo").and_then(Value::as_str) {
        extensions.insert("extension:inference_geo".into(), json!(inference_geo));
    }
    if let Some(user_profile_id) = body.get("user_profile_id").and_then(Value::as_str) {
        extensions.insert("extension:user_profile_id".into(), json!(user_profile_id));
    }
    if let Some(workspace_id) = body.get("workspace_id").and_then(Value::as_str) {
        extensions.insert("extension:workspace_id".into(), json!(workspace_id));
    }
    extensions
}

// ─── Tool ledger ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ToolCallOccurrence {
    server: bool,
}

#[derive(Debug, Clone)]
struct ToolResultOccurrence {
    result: ContentPart,
    message_index: usize,
}

fn is_server_tool(part: &ContentPart) -> bool {
    matches!(
        part,
        ContentPart::Extension { name, .. }
            if name == "server_tool_use" || name == "search_result"
    )
}

fn server_tool_id(part: &ContentPart) -> Option<String> {
    let ContentPart::Extension { payload, .. } = part else {
        return None;
    };
    if !is_server_tool(part) {
        return None;
    }
    let payload = payload.as_object()?;
    payload
        .get("id")
        .or_else(|| payload.get("tool_use_id"))
        .or_else(|| payload.get("call_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn is_tool_result(part: &ContentPart) -> bool {
    matches!(part, ContentPart::ToolResult { .. })
}

fn result_message(results: &[ContentPart]) -> Option<CanonicalMessage> {
    if results.is_empty() {
        return None;
    }
    Some(CanonicalMessage {
        role: Role::User,
        content: results.to_vec(),
        phase: None,
    })
}

fn free_content(message: &CanonicalMessage) -> Vec<ContentPart> {
    message
        .content
        .iter()
        .filter(|part| !is_tool_result(part))
        .cloned()
        .collect()
}

/// Rebuilds canonical Messages tool rounds under one explicit policy owner.
fn apply_messages_tool_ledger(
    messages: &[CanonicalMessage],
) -> Result<Vec<CanonicalMessage>, GatewayError> {
    let mut calls: HashMap<String, ToolCallOccurrence> = HashMap::new();
    let mut results: Vec<ToolResultOccurrence> = Vec::new();
    let mut server_ids: HashSet<String> = HashSet::new();
    for (message_index, message) in messages.iter().enumerate() {
        for part in &message.content {
            if let ContentPart::ToolCall { call_id, name, .. } = part {
                if call_id.is_empty() || name.is_empty() {
                    return Err(ledger_error("tool_call must include call_id and name"));
                }
                if calls.contains_key(call_id) {
                    return Err(ledger_error(format!(
                        "duplicate tool call occurrence: {call_id}"
                    )));
                }
                calls.insert(call_id.clone(), ToolCallOccurrence { server: false });
            }
            if let Some(server_id) = server_tool_id(part) {
                server_ids.insert(server_id.clone());
                calls.insert(server_id, ToolCallOccurrence { server: true });
            }
            if can_contain_tool_result(message) && is_tool_result(part) {
                results.push(ToolResultOccurrence {
                    result: part.clone(),
                    message_index,
                });
            }
        }
    }

    let mut by_call: HashMap<String, ToolResultOccurrence> = HashMap::new();
    for occurrence in &results {
        let ContentPart::ToolResult { call_id, .. } = &occurrence.result else {
            continue;
        };
        let Some(call) = calls.get(call_id) else {
            if server_ids.contains(call_id) {
                continue;
            }
            return Err(ledger_error(format!(
                "tool_result has no matching tool_use: {call_id}"
            )));
        };
        if call.server {
            continue;
        }
        if by_call.contains_key(call_id) {
            return Err(ledger_error(format!(
                "duplicate tool_result occurrence: {call_id}"
            )));
        }
        by_call.insert(call_id.clone(), occurrence.clone());
    }

    let result_message_indexes: HashSet<usize> = results
        .iter()
        .map(|occurrence| occurrence.message_index)
        .collect();
    let mut output: Vec<CanonicalMessage> = Vec::new();
    let mut consumed_result_messages: HashSet<usize> = HashSet::new();

    for (message_index, message) in messages.iter().enumerate() {
        let call_parts: Vec<&ContentPart> = message
            .content
            .iter()
            .filter(|part| matches!(part, ContentPart::ToolCall { .. }))
            .collect();
        let server_parts: Vec<&ContentPart> = message
            .content
            .iter()
            .filter(|part| is_server_tool(part))
            .collect();
        if !call_parts.is_empty() {
            output.push(message.clone());
            let matched: Vec<ToolResultOccurrence> = call_parts
                .iter()
                .filter_map(|part| {
                    let ContentPart::ToolCall { call_id, .. } = part else {
                        return None;
                    };
                    by_call.get(call_id).cloned()
                })
                .collect();
            for entry in &matched {
                consumed_result_messages.insert(entry.message_index);
            }
            let rebuilt: Vec<ContentPart> =
                matched.iter().map(|entry| entry.result.clone()).collect();
            if let Some(rebuilt) = result_message(&rebuilt) {
                output.push(rebuilt);
            }
            continue;
        }
        if result_message_indexes.contains(&message_index) {
            if consumed_result_messages.contains(&message_index) {
                let previous = message_index
                    .checked_sub(1)
                    .and_then(|index| messages.get(index));
                let trailing = free_content(message);
                if !trailing.is_empty()
                    && previous.is_none_or(|previous| !previous.content.iter().any(is_server_tool))
                {
                    output.push(CanonicalMessage {
                        role: message.role,
                        content: trailing,
                        phase: None,
                    });
                }
                continue;
            }
            let free = free_content(message);
            let results_only: Vec<ContentPart> = message
                .content
                .iter()
                .filter(|part| is_tool_result(part))
                .filter(|part| {
                    let ContentPart::ToolResult { call_id, .. } = part else {
                        return false;
                    };
                    !server_ids.contains(call_id)
                })
                .cloned()
                .collect();
            consumed_result_messages.insert(message_index);
            if let Some(rebuilt) = result_message(&results_only) {
                output.push(rebuilt);
            }
            let previous = message_index
                .checked_sub(1)
                .and_then(|index| messages.get(index));
            let previous_has_direct_server = previous
                .is_some_and(|previous| previous.content.iter().any(is_server_tool))
                || !server_parts.is_empty();
            if !free.is_empty() && !previous_has_direct_server {
                output.push(CanonicalMessage {
                    role: message.role,
                    content: free,
                    phase: None,
                });
            }
            continue;
        }
        if message_index > 0
            && messages
                .get(message_index - 1)
                .is_some_and(|previous| previous.content.iter().any(is_server_tool))
            && message.role == Role::User
        {
            continue;
        }
        if !message.content.is_empty() {
            output.push(message.clone());
        }
    }
    Ok(output)
}

// ─── Adapter ────────────────────────────────────────────────────────────────

/// Anthropic Messages surface adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct MessagesAdapter;

impl MessagesAdapter {
    /// Pure body-shape check used by the once-only surface registry.
    pub fn matches_body_shape(&self, body: &Value) -> bool {
        let Some(body) = body.as_object() else {
            return false;
        };
        body.get("messages").is_some_and(Value::is_array)
            && (body.contains_key("max_tokens") || body.contains_key("maxTokens"))
            && body.get("model").and_then(Value::as_str).is_some()
    }

    /// Parses a Messages wire request into the canonical request model.
    pub fn parse(&self, body: &Value) -> Result<CanonicalRequest, GatewayError> {
        self.parse_with_options(body, &MessagesParseOptions::default())
    }

    fn parse_with_options(
        &self,
        body: &Value,
        options: &MessagesParseOptions,
    ) -> Result<CanonicalRequest, GatewayError> {
        let Some(body) = body.as_object() else {
            return Err(invalid("request must be an object"));
        };
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Messages request requires model"))?
            .to_owned();
        let Some(entries) = body.get("messages").and_then(Value::as_array) else {
            return Err(invalid("Messages request requires messages[]"));
        };
        let max_tokens = finite_number(body.get("max_tokens"))
            .or_else(|| finite_number(body.get("maxTokens")))
            .filter(|value| value.fract() == 0.0 && *value > 0.0)
            .ok_or_else(|| invalid("Messages request requires positive integer max_tokens"))?
            as i64;

        let declared_system = system_blocks(body.get("system"))?;
        let parsed_messages: Vec<CanonicalMessage> = entries
            .iter()
            .map(parse_message)
            .collect::<Result<Vec<_>, _>>()?;
        let hoisted_system: Vec<ContentPart> = parsed_messages
            .iter()
            .filter(|message| message.role == Role::System)
            .flat_map(|message| message.content.iter().cloned())
            .collect();
        let system = if declared_system.is_none() && hoisted_system.is_empty() {
            None
        } else {
            let mut combined = declared_system.unwrap_or_default();
            combined.extend(hoisted_system);
            Some(combined)
        };
        let non_system: Vec<CanonicalMessage> = parsed_messages
            .into_iter()
            .filter(|message| message.role != Role::System)
            .collect();
        let messages = apply_messages_tool_ledger(&non_system)?;

        let disabled_parallel = body
            .get("disable_parallel_tool_use")
            .filter(|value| !value.is_null())
            .or_else(|| {
                body.get("disableParallelToolUse")
                    .filter(|value| !value.is_null())
            });
        let stop = body
            .get("stop_sequences")
            .filter(|value| !value.is_null())
            .or_else(|| body.get("stopSequences").filter(|value| !value.is_null()));
        let top_p = finite_number(body.get("top_p")).or_else(|| finite_number(body.get("topP")));
        let top_k = finite_number(body.get("top_k")).or_else(|| finite_number(body.get("topK")));

        let extensions = extension_controls(
            body,
            body.get("metadata")
                .and_then(Value::as_object)
                .and_then(|metadata| metadata.get("user_id").or_else(|| metadata.get("userId"))),
        );
        let stop_sequence = stop.and_then(|stop| {
            if let Some(entries) = stop.as_array() {
                Some(StopSequence::Many(
                    entries
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                ))
            } else {
                stop.as_str().map(|stop| StopSequence::One(stop.to_owned()))
            }
        });
        let generation_controls = GenerationControls {
            temperature: finite_number(body.get("temperature")),
            top_p,
            top_k,
            stop: stop_sequence,
            max_tokens: Some(max_tokens),
            parallel_tool_calls: disabled_parallel.map(|value| value.as_bool() != Some(true)),
            extensions,
            ..GenerationControls::default()
        };

        let mut reasoning = parse_thinking(body.get("thinking"), &model, options, max_tokens)?;
        if let Some(output_config) = body.get("output_config").and_then(Value::as_object) {
            let intent = reasoning.get_or_insert_with(ReasoningIntent::default);
            if let Some(effort) = output_config
                .get("effort")
                .and_then(Value::as_str)
                .filter(|effort| CANONICAL_REASONING_EFFORTS.contains(effort))
                .and_then(is_reasoning_effort)
            {
                intent.effort = Some(effort);
            }
            if let Some(task_budget) = finite_number(output_config.get("task_budget")) {
                intent.task_budget = Some(task_budget as i64);
            }
        }
        if reasoning
            .as_ref()
            .and_then(|reasoning| reasoning.effort)
            .is_none()
        {
            if let Some(shared) = parse_reasoning_intent(body) {
                if let Some(effort) = shared.effort {
                    reasoning
                        .get_or_insert_with(ReasoningIntent::default)
                        .effort = Some(effort);
                }
            }
        }

        let cache = cache_hint(body, system.as_deref());
        let tools = parse_tools(body.get("tools"))?;
        let tool_choice_value = body
            .get("tool_choice")
            .or_else(|| body.get("toolChoice"))
            .cloned()
            .unwrap_or(Value::Null);
        let tool_choice = parse_tool_choice(&tool_choice_value, ToolDialect::Messages)?;

        Ok(CanonicalRequest {
            model,
            system,
            instructions: None,
            messages,
            tools,
            tool_choice,
            generation_controls,
            reasoning,
            response_format: None,
            cache_hint: cache,
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
            source_surface: SourceSurface::Messages,
        })
    }
}

// ─── Response encoding ──────────────────────────────────────────────────────

fn parse_args_lossy(value: &Value) -> Value {
    match crate::primitives::parse_arguments(value) {
        Ok(parsed) => parsed,
        Err(_) => value.clone(),
    }
}

fn block_from_part(part: &ContentPart) -> Option<Value> {
    match part {
        ContentPart::Text { text } => Some(json!({"type": "text", "text": text})),
        ContentPart::Image { payload } => Some(if is_record(payload) {
            payload.clone()
        } else {
            json!({"type": "image", "source": payload})
        }),
        ContentPart::File {
            data,
            media_type,
            filename,
            file_id,
            ..
        } => {
            let source = match file_id {
                Some(file_id) => json!({"type": "file", "file_id": file_id}),
                None => json!({"type": "base64", "media_type": media_type, "data": data}),
            };
            let mut block = Map::new();
            block.insert("type".into(), json!("document"));
            block.insert("source".into(), source);
            if let Some(filename) = filename {
                block.insert("title".into(), json!(filename));
            }
            Some(Value::Object(block))
        }
        ContentPart::Document {
            data,
            media_type,
            title,
            citations,
            ..
        } => {
            let mut block = Map::new();
            block.insert("type".into(), json!("document"));
            block.insert(
                "source".into(),
                json!({"type": "base64", "media_type": media_type, "data": data}),
            );
            if let Some(title) = title {
                block.insert("title".into(), json!(title));
            }
            if let Some(citations) = citations {
                block.insert("citations".into(), json!({"enabled": citations}));
            }
            Some(Value::Object(block))
        }
        ContentPart::Audio { data, media_type } => Some(json!({
            "type": "audio",
            "source": {"type": "base64", "media_type": media_type, "data": data},
        })),
        ContentPart::Refusal { text } => Some(json!({"type": "text", "text": text})),
        ContentPart::ToolCall {
            call_id,
            name,
            arguments,
            ..
        } => Some(json!({
            "type": "tool_use",
            "id": call_id,
            "name": name,
            "input": parse_args_lossy(arguments),
        })),
        ContentPart::ToolResult {
            call_id,
            content,
            is_error,
            ..
        } => {
            let content = match content {
                ToolResultContent::Text(text) => Value::String(text.clone()),
                ToolResultContent::Parts(parts) => {
                    Value::Array(parts.iter().filter_map(block_from_part).collect::<Vec<_>>())
                }
            };
            let mut block = Map::new();
            block.insert("type".into(), json!("tool_result"));
            block.insert("tool_use_id".into(), json!(call_id));
            block.insert("content".into(), content);
            if *is_error == Some(true) {
                block.insert("is_error".into(), json!(true));
            }
            Some(Value::Object(block))
        }
        ContentPart::Reasoning {
            payload,
            opaque,
            summary,
            signature,
            ..
        } => {
            if *opaque == Some(true) {
                return Some(if is_record(payload) {
                    payload.clone()
                } else {
                    json!({"type": "redacted_thinking", "data": payload})
                });
            }
            let thinking = summary
                .clone()
                .or_else(|| payload.as_str().map(str::to_owned))
                .unwrap_or_default();
            let mut block = Map::new();
            block.insert("type".into(), json!("thinking"));
            block.insert("thinking".into(), json!(thinking));
            if let Some(signature) = signature {
                block.insert("signature".into(), json!(signature));
            }
            Some(Value::Object(block))
        }
        ContentPart::Extension { name, payload } => {
            if !is_record(payload) {
                return None;
            }
            if name == "server_tool_use" || name == "search_result" || name == "document" {
                return Some(payload.clone());
            }
            if name.starts_with("messages:") && name != "messages:unknown" {
                let mut block = payload.as_object().cloned().unwrap_or_default();
                block
                    .entry("type".to_owned())
                    .or_insert_with(|| json!(name.trim_start_matches("messages:")));
                return Some(Value::Object(block));
            }
            None
        }
    }
}

#[derive(Debug, Clone)]
struct ToolArgs {
    name: Option<String>,
    chunks: Vec<String>,
}

fn flush_tools(
    tool_arguments: &mut Vec<(String, ToolArgs)>,
    blocks: &mut Vec<Value>,
    dropped_unnamed: &mut usize,
) {
    for (call_id, call) in tool_arguments.drain(..) {
        let named = call
            .name
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty());
        if !named {
            *dropped_unnamed += 1;
            continue;
        }
        blocks.push(json!({
            "type": "tool_use",
            "id": call_id,
            "name": call.name.unwrap_or_default(),
            "input": parse_args_lossy(&Value::String(call.chunks.concat())),
        }));
    }
}

fn reasoning_has_boundary(
    previous: Option<&ReasoningSummaryIdentity>,
    current: Option<&ReasoningSummaryIdentity>,
) -> bool {
    let (Some(previous), Some(current)) = (previous, current) else {
        return false;
    };
    (previous.item_id.is_some() && current.item_id.is_some() && previous.item_id != current.item_id)
        || (previous.output_index.is_some()
            && current.output_index.is_some()
            && previous.output_index != current.output_index)
        || (previous.summary_index.is_some()
            && current.summary_index.is_some()
            && previous.summary_index != current.summary_index)
}

fn grouped_blocks(events: &[CanonicalEvent]) -> (Vec<Value>, usize) {
    let mut blocks: Vec<Value> = Vec::new();
    let mut previous_identity: Option<ReasoningSummaryIdentity> = None;
    let mut previous_text: Option<String> = None;
    let mut dropped_unnamed = 0usize;
    let mut tool_arguments: Vec<(String, ToolArgs)> = Vec::new();

    for event in events {
        if let CanonicalEvent::ToolCallDelta {
            call_id,
            name,
            arguments_delta,
            ..
        } = event
        {
            if let Some((_, entry)) = tool_arguments
                .iter_mut()
                .find(|(existing, _)| existing == call_id)
            {
                entry
                    .chunks
                    .push(arguments_delta.clone().unwrap_or_default());
                if name.is_some() {
                    entry.name = name.clone();
                }
            } else {
                tool_arguments.push((
                    call_id.clone(),
                    ToolArgs {
                        name: name.clone(),
                        chunks: vec![arguments_delta.clone().unwrap_or_default()],
                    },
                ));
            }
            continue;
        }
        flush_tools(&mut tool_arguments, &mut blocks, &mut dropped_unnamed);
        match event {
            CanonicalEvent::ContentDelta { content, .. } => {
                let Some(next) = block_from_part(content) else {
                    continue;
                };
                let next_type = next
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let previous = blocks.last_mut();
                let previous_type = previous
                    .as_ref()
                    .and_then(|block| block.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if next_type == "text" && previous_type == "text" {
                    if let Some(previous) = previous {
                        let merged = format!(
                            "{}{}",
                            previous
                                .get("text")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                            next.get("text").and_then(Value::as_str).unwrap_or_default()
                        );
                        previous["text"] = json!(merged);
                    }
                    previous_identity = None;
                    previous_text = None;
                } else if next_type == "thinking" && previous_type == "thinking" {
                    let identity = reasoning_summary_identity(event);
                    let next_text = next
                        .get("thinking")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let separator = reasoning_summary_separator(
                        previous_identity.as_ref(),
                        identity.as_ref(),
                        previous_text.as_deref(),
                        &next_text,
                    );
                    if reasoning_has_boundary(previous_identity.as_ref(), identity.as_ref()) {
                        let mut separated = Map::new();
                        separated.insert("type".into(), json!("thinking"));
                        separated
                            .insert("thinking".into(), json!(format!("{separator}{next_text}")));
                        if let Some(signature) = next.get("signature").cloned() {
                            separated.insert("signature".into(), signature);
                        }
                        blocks.push(Value::Object(separated));
                    } else if let Some(previous) = previous {
                        let merged = format!(
                            "{}{}",
                            previous
                                .get("thinking")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                            next_text
                        );
                        previous["thinking"] = json!(merged);
                    }
                    previous_identity = identity;
                    previous_text = Some(next_text);
                } else {
                    let next_is_thinking = next_type == "thinking";
                    let next_text = next
                        .get("thinking")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    blocks.push(next);
                    previous_identity = if next_is_thinking {
                        reasoning_summary_identity(event)
                    } else {
                        None
                    };
                    previous_text = if next_is_thinking { next_text } else { None };
                }
            }
            CanonicalEvent::ToolResult {
                call_id, content, ..
            } => {
                previous_identity = None;
                previous_text = None;
                let part = ContentPart::ToolResult {
                    call_id: call_id.clone(),
                    content: ToolResultContent::Parts(content.clone()),
                    is_error: None,
                    call_kind: None,
                    item_id: None,
                };
                if let Some(block) = block_from_part(&part) {
                    blocks.push(block);
                }
            }
            _ => {}
        }
    }
    flush_tools(&mut tool_arguments, &mut blocks, &mut dropped_unnamed);
    (blocks, dropped_unnamed)
}

fn map_stop_reason(reason: Option<CanonicalStopReason>) -> Option<&'static str> {
    reason.map(|reason| match reason {
        CanonicalStopReason::Stop => "end_turn",
        CanonicalStopReason::Length => "max_tokens",
        CanonicalStopReason::ToolUse => "tool_use",
        CanonicalStopReason::Refusal | CanonicalStopReason::ContentFilter => "refusal",
        CanonicalStopReason::Error | CanonicalStopReason::Cancelled => "end_turn",
        CanonicalStopReason::PauseTurn => "pause_turn",
    })
}

fn start_model(events: &[CanonicalEvent]) -> Option<String> {
    events
        .iter()
        .find_map(|event| match event {
            CanonicalEvent::ResponseStart {
                model: Some(model), ..
            }
            | CanonicalEvent::MessageStart {
                model: Some(model), ..
            } => Some(model.clone()),
            _ => None,
        })
        .filter(|model| !model.is_empty())
}

#[derive(Debug, Clone, Default)]
struct StopData {
    reason: Option<String>,
    usage: Option<UsageRecord>,
    failed: bool,
}

fn stop_data(events: &[CanonicalEvent]) -> StopData {
    let terminal = events
        .iter()
        .rev()
        .find(|event| matches!(event, CanonicalEvent::Terminal { .. }));
    let usage_event = events
        .iter()
        .rev()
        .find(|event| matches!(event, CanonicalEvent::Usage { .. }));
    let Some(CanonicalEvent::Terminal {
        state: terminal_state,
        stop_reason: terminal_stop_reason,
        usage: terminal_usage,
        ..
    }) = terminal
    else {
        let usage = usage_event.and_then(|event| match event {
            CanonicalEvent::Usage { usage, .. } => Some(usage.clone()),
            _ => None,
        });
        return StopData {
            reason: None,
            usage,
            failed: false,
        };
    };
    let reason = match terminal_stop_reason {
        Some(reason) => map_stop_reason(Some(*reason)).map(str::to_owned),
        None if *terminal_state == TerminalState::Complete => Some("end_turn".to_owned()),
        None => None,
    };
    let usage = terminal_usage.clone().or_else(|| {
        usage_event.and_then(|event| match event {
            CanonicalEvent::Usage { usage, .. } => Some(usage.clone()),
            _ => None,
        })
    });
    StopData {
        reason,
        usage,
        failed: *terminal_state == TerminalState::Failed,
    }
}

/// Encodes canonical usage as Anthropic Messages wire usage.
pub(crate) fn usage_to_messages_wire(usage: Option<&UsageRecord>) -> Value {
    let Some(usage) = usage else {
        return json!({"input_tokens": 0, "output_tokens": 0});
    };
    let has_cache_info = matches!(usage.cached_input_tokens, keyla_core::TokenCount::Number(_));
    let input_tokens = if has_cache_info {
        match usage.uncached_input_tokens {
            keyla_core::TokenCount::Number(value) => value.max(0),
            keyla_core::TokenCount::Unavailable => usage.input_tokens,
        }
    } else {
        usage.input_tokens
    };
    let mut wire = Map::new();
    wire.insert("input_tokens".into(), json!(input_tokens));
    wire.insert("output_tokens".into(), json!(usage.output_tokens));
    if let keyla_core::TokenCount::Number(cached) = usage.cached_input_tokens {
        wire.insert("cache_read_input_tokens".into(), json!(cached));
    }
    if let keyla_core::TokenCount::Number(written) = usage.cache_write_tokens {
        wire.insert("cache_creation_input_tokens".into(), json!(written));
    }
    if let keyla_core::TokenCount::Number(reasoning) = usage.reasoning_tokens {
        wire.insert(
            "output_tokens_details".into(),
            json!({"thinking_tokens": reasoning}),
        );
    }
    Value::Object(wire)
}

/// Encodes canonical events as a complete Messages response.
pub fn encode_messages_response(
    events: &[CanonicalEvent],
    model: &str,
    include_usage: bool,
) -> Value {
    let response_id = format!("msg-{}", uuid::Uuid::new_v4());
    let model = if model.is_empty() {
        start_model(events).unwrap_or_else(|| "unknown".into())
    } else {
        model.to_owned()
    };
    let data = stop_data(events);
    let (content, dropped_unnamed_tool_calls) = grouped_blocks(events);
    let has_tool_use_block = content
        .iter()
        .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"));
    let stop_reason = if dropped_unnamed_tool_calls > 0
        && !has_tool_use_block
        && data.reason.as_deref() == Some("tool_use")
    {
        Some("end_turn".to_owned())
    } else {
        data.reason
    };
    let usage = usage_to_messages_wire(if include_usage {
        data.usage.as_ref()
    } else {
        None
    });
    if data.failed {
        return json!({
            "id": response_id,
            "type": "error",
            "error": {"type": "server_error", "message": "The upstream response failed"},
        });
    }
    json!({
        "id": response_id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": usage,
    })
}

// ─── Streaming encoder ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct OpenBlock {
    block_type: String,
    index: u64,
}

/// Incremental streaming encoder for Anthropic Messages.
#[derive(Debug)]
pub struct MessagesStreamEncoder {
    response_id: String,
    model: String,
    include_usage: bool,
    started: bool,
    finished: bool,
    next_index: u64,
    open_block: Option<OpenBlock>,
    open_reasoning_identity: Option<ReasoningSummaryIdentity>,
    previous_reasoning_text: Option<String>,
    tools: ToolCallTracker,
    wire_ids: HashMap<String, String>,
    opened_tool_calls: HashSet<String>,
    emitted_arguments: HashMap<String, usize>,
    dropped_unnamed_tool_calls: usize,
    usage: Option<UsageRecord>,
    failed: bool,
    stop_reason: Option<String>,
}

impl MessagesStreamEncoder {
    pub fn new(model: &str, include_usage: bool) -> Self {
        Self {
            response_id: format!("msg-{}", uuid::Uuid::new_v4()),
            model: model.to_owned(),
            include_usage,
            started: false,
            finished: false,
            next_index: 0,
            open_block: None,
            open_reasoning_identity: None,
            previous_reasoning_text: None,
            tools: ToolCallTracker::new(),
            wire_ids: HashMap::new(),
            opened_tool_calls: HashSet::new(),
            emitted_arguments: HashMap::new(),
            dropped_unnamed_tool_calls: 0,
            usage: None,
            failed: false,
            stop_reason: None,
        }
    }

    pub fn with_response_id(mut self, response_id: impl Into<String>) -> Self {
        self.response_id = response_id.into();
        self
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    fn message_start(&self) -> Value {
        json!({
            "type": "message_start",
            "message": {
                "id": self.response_id,
                "type": "message",
                "role": "assistant",
                "model": self.model,
                "content": [],
                "stop_reason": Value::Null,
                "stop_sequence": Value::Null,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        })
    }

    fn key_for(&mut self, call_id: &str) -> String {
        let key = tool_identity_key(call_id);
        self.wire_ids
            .entry(key.clone())
            .or_insert_with(|| call_id.to_owned());
        key
    }

    fn emit_tool_call(&mut self, call_id: &str, entry: &ToolCallState) -> Vec<Value> {
        let mut out = Vec::new();
        let Some(name) = entry.name.as_deref().filter(|name| !name.trim().is_empty()) else {
            return out;
        };
        let index = match self.tools.index_by_id.get(call_id).copied() {
            Some(index) => index,
            None => {
                let index = self.next_index as i64;
                self.next_index += 1;
                index
            }
        };
        self.tools.index_by_id.insert(call_id.to_owned(), index);
        let sent = self.emitted_arguments.get(call_id).copied().unwrap_or(0);
        let pending = utf16_suffix(&entry.arguments, sent);
        if !self.opened_tool_calls.contains(call_id) {
            self.opened_tool_calls.insert(call_id.to_owned());
            out.extend(self.close_open_block());
            let wire_id = self
                .wire_ids
                .get(call_id)
                .cloned()
                .unwrap_or_else(|| call_id.to_owned());
            out.push(json!({
                "type": "content_block_start",
                "index": index,
                "content_block": {"type": "tool_use", "id": wire_id, "name": name, "input": {}},
            }));
            self.open_block = Some(OpenBlock {
                block_type: "tool_use".into(),
                index: index.max(0) as u64,
            });
        } else if !pending.is_empty()
            && self.open_block.as_ref().map(|block| block.index) != Some(index.max(0) as u64)
        {
            out.extend(self.close_open_block());
            self.open_block = Some(OpenBlock {
                block_type: "tool_use".into(),
                index: index.max(0) as u64,
            });
        }
        if !pending.is_empty() {
            out.push(json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "input_json_delta", "partial_json": pending},
            }));
            self.emitted_arguments
                .insert(call_id.to_owned(), utf16_len(&entry.arguments));
        }
        out
    }

    fn flush_tool_calls(&mut self, final_flush: bool) -> Vec<Value> {
        let mut out = Vec::new();
        let mut states: Vec<(String, ToolCallState)> = self
            .tools
            .states
            .iter()
            .map(|(id, state)| (id.clone(), state.clone()))
            .collect();
        states.sort_by_key(|(_, state)| state.index);
        for (call_id, entry) in states {
            let named = entry
                .name
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty());
            if !named {
                if final_flush {
                    self.dropped_unnamed_tool_calls += 1;
                }
                continue;
            }
            out.extend(self.emit_tool_call(&call_id, &entry));
        }
        out
    }

    fn close_open_block(&mut self) -> Vec<Value> {
        let Some(block) = self.open_block.take() else {
            return Vec::new();
        };
        vec![json!({"type": "content_block_stop", "index": block.index})]
    }

    fn final_usage(&self) -> Value {
        usage_to_messages_wire(if self.include_usage {
            self.usage.as_ref()
        } else {
            None
        })
    }

    fn downgrade_stop_reason(&mut self) {
        if self.dropped_unnamed_tool_calls > 0
            && self.opened_tool_calls.is_empty()
            && self.stop_reason.as_deref() == Some("tool_use")
        {
            self.stop_reason = Some("end_turn".into());
        }
    }

    fn reset_tools(&mut self) {
        self.emitted_arguments.clear();
        self.opened_tool_calls.clear();
        self.wire_ids.clear();
        self.tools.reset();
    }

    pub fn push(&mut self, event: &CanonicalEvent) -> Vec<Value> {
        if self.finished {
            return vec![json!({
                "type": "error",
                "error": {
                    "type": "invalid_request",
                    "message": "Messages stream has more than one terminal event",
                },
            })];
        }
        let mut out = Vec::new();
        if !self.started {
            self.started = true;
            out.push(self.message_start());
        }
        match event {
            CanonicalEvent::Usage { usage, .. } => {
                self.usage = Some(usage.clone());
                out
            }
            CanonicalEvent::Keepalive { .. } => out,
            CanonicalEvent::Error { .. } => {
                self.failed = true;
                out
            }
            CanonicalEvent::ContentDelta { content, .. } => match content {
                ContentPart::Text { text } => {
                    if text.is_empty() {
                        return out;
                    }
                    if self
                        .open_block
                        .as_ref()
                        .map(|block| block.block_type.as_str())
                        != Some("text")
                    {
                        out.extend(self.close_open_block());
                        let index = self.next_index;
                        self.next_index += 1;
                        out.push(json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": {"type": "text", "text": ""},
                        }));
                        self.open_block = Some(OpenBlock {
                            block_type: "text".into(),
                            index,
                        });
                        self.open_reasoning_identity = None;
                        self.previous_reasoning_text = None;
                    }
                    if let Some(block) = &self.open_block {
                        out.push(json!({
                            "type": "content_block_delta",
                            "index": block.index,
                            "delta": {"type": "text_delta", "text": text},
                        }));
                    }
                    out
                }
                ContentPart::Reasoning {
                    payload,
                    opaque,
                    summary,
                    signature,
                    ..
                } => {
                    let is_redacted = *opaque == Some(true);
                    let summary = summary
                        .clone()
                        .or_else(|| payload.as_str().map(str::to_owned))
                        .unwrap_or_default();
                    let signature = signature.clone().unwrap_or_default();
                    if !is_redacted && summary.is_empty() && signature.is_empty() {
                        return out;
                    }
                    let block_type = if is_redacted {
                        "redacted_thinking"
                    } else {
                        "thinking"
                    };
                    let identity = reasoning_summary_identity(event);
                    let separator = if block_type == "thinking" {
                        reasoning_summary_separator(
                            self.open_reasoning_identity.as_ref(),
                            identity.as_ref(),
                            self.previous_reasoning_text.as_deref(),
                            &summary,
                        )
                    } else {
                        ""
                    };
                    if block_type == "thinking"
                        && reasoning_has_boundary(
                            self.open_reasoning_identity.as_ref(),
                            identity.as_ref(),
                        )
                        && self
                            .open_block
                            .as_ref()
                            .map(|block| block.block_type.as_str())
                            == Some("thinking")
                    {
                        out.extend(self.close_open_block());
                    }
                    if self
                        .open_block
                        .as_ref()
                        .map(|block| block.block_type.as_str())
                        != Some(block_type)
                    {
                        out.extend(self.close_open_block());
                        let index = self.next_index;
                        self.next_index += 1;
                        let initial = if is_redacted {
                            json!({"type": "redacted_thinking"})
                        } else {
                            json!({"type": "thinking", "thinking": ""})
                        };
                        out.push(json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": initial,
                        }));
                        self.open_block = Some(OpenBlock {
                            block_type: block_type.into(),
                            index,
                        });
                    }
                    if block_type == "thinking" {
                        self.open_reasoning_identity = identity;
                        self.previous_reasoning_text = Some(summary.clone());
                    }
                    let index = self
                        .open_block
                        .as_ref()
                        .map(|block| block.index)
                        .unwrap_or(0);
                    if is_redacted {
                        out.push(json!({
                            "type": "content_block_delta",
                            "index": index,
                            "delta": {
                                "type": "redacted_thinking_delta",
                                "data": payload,
                            },
                        }));
                    } else {
                        if !summary.is_empty() {
                            out.push(json!({
                                "type": "content_block_delta",
                                "index": index,
                                "delta": {
                                    "type": "thinking_delta",
                                    "thinking": format!("{separator}{summary}"),
                                },
                            }));
                        }
                        if !signature.is_empty() {
                            out.push(json!({
                                "type": "content_block_delta",
                                "index": index,
                                "delta": {"type": "signature_delta", "signature": signature},
                            }));
                        }
                    }
                    out
                }
                ContentPart::Image { payload } => {
                    out.extend(self.close_open_block());
                    let index = self.next_index;
                    self.next_index += 1;
                    out.push(json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {"type": "image", "source": payload},
                    }));
                    out.push(json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "image_delta", "data": payload},
                    }));
                    out.push(json!({"type": "content_block_stop", "index": index}));
                    out
                }
                ContentPart::ToolResult { .. } => {
                    out.extend(self.close_open_block());
                    out.extend(self.flush_tool_calls(false));
                    out.extend(self.close_open_block());
                    self.tools.states.clear();
                    self.emitted_arguments.clear();
                    self.opened_tool_calls.clear();
                    self.wire_ids.clear();
                    let Some(result_block) = block_from_part(content) else {
                        return out;
                    };
                    let index = self.next_index;
                    self.next_index += 1;
                    out.push(json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": result_block.clone(),
                    }));
                    out.push(json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "tool_result_delta", "data": result_block},
                    }));
                    out.push(json!({"type": "content_block_stop", "index": index}));
                    out
                }
                other => {
                    out.extend(self.close_open_block());
                    let Some(block) = block_from_part(other) else {
                        return out;
                    };
                    let index = self.next_index;
                    self.next_index += 1;
                    let block_type = block
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    out.push(json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": block.clone(),
                    }));
                    out.push(json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": format!("{block_type}_delta"), "data": block},
                    }));
                    out.push(json!({"type": "content_block_stop", "index": index}));
                    out
                }
            },
            CanonicalEvent::ToolCallDelta {
                call_id,
                name,
                arguments_delta,
                ..
            } => {
                let call_key = self.key_for(call_id);
                let fallback = self.next_index as i64;
                let (index, _, state) = self.tools.track(
                    &call_key,
                    name.as_deref(),
                    arguments_delta.as_deref(),
                    None,
                    Some(fallback),
                );
                self.next_index = self.next_index.max((index + 1).max(0) as u64);
                if state
                    .name
                    .as_deref()
                    .is_none_or(|name| name.trim().is_empty())
                {
                    return out;
                }
                out.extend(self.emit_tool_call(&call_key, &state));
                out
            }
            CanonicalEvent::Terminal {
                state,
                stop_reason,
                usage,
                ..
            } => {
                self.failed = self.failed || *state == TerminalState::Failed;
                self.stop_reason = match stop_reason {
                    Some(reason) => map_stop_reason(Some(*reason)).map(str::to_owned),
                    None if *state == TerminalState::Complete => Some("end_turn".into()),
                    None => None,
                };
                if let Some(usage) = usage {
                    self.usage = Some(usage.clone());
                }
                out.extend(self.close_open_block());
                out.extend(self.flush_tool_calls(true));
                out.extend(self.close_open_block());
                self.downgrade_stop_reason();
                self.reset_tools();
                let usage = self.final_usage();
                let stop_reason = if self.failed {
                    Value::Null
                } else {
                    match &self.stop_reason {
                        Some(reason) => json!(reason),
                        None => Value::Null,
                    }
                };
                out.push(json!({
                    "type": "message_delta",
                    "delta": {"stop_reason": stop_reason, "stop_sequence": Value::Null},
                    "usage": usage,
                }));
                out.push(json!({"type": "message_stop"}));
                self.finished = true;
                out
            }
            _ => out,
        }
    }

    pub fn finish(&mut self) -> Vec<Value> {
        if !self.started {
            self.started = true;
            self.finished = true;
            let usage = self.final_usage();
            let stop_reason = match &self.stop_reason {
                Some(reason) => json!(reason),
                None => Value::Null,
            };
            return vec![
                self.message_start(),
                json!({
                    "type": "message_delta",
                    "delta": {"stop_reason": stop_reason, "stop_sequence": Value::Null},
                    "usage": usage,
                }),
                json!({"type": "message_stop"}),
            ];
        }
        if self.finished {
            return Vec::new();
        }
        let mut out = Vec::new();
        out.extend(self.close_open_block());
        out.extend(self.flush_tool_calls(true));
        out.extend(self.close_open_block());
        self.downgrade_stop_reason();
        self.reset_tools();
        let usage = self.final_usage();
        let stop_reason = match &self.stop_reason {
            Some(reason) => json!(reason),
            None => Value::Null,
        };
        out.push(json!({
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": Value::Null},
            "usage": usage,
        }));
        out.push(json!({"type": "message_stop"}));
        self.finished = true;
        out
    }
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn utf16_suffix(text: &str, skip: usize) -> String {
    let units: Vec<u16> = text.encode_utf16().skip(skip).collect();
    String::from_utf16_lossy(&units)
}

fn tool_identity_key(call_id: &str) -> String {
    for prefix in ["call_", "fc_"] {
        if let Some(stripped) = call_id.strip_prefix(prefix) {
            return stripped.to_owned();
        }
    }
    call_id.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::TokenCount;

    #[test]
    fn body_shape_requires_messages_max_tokens_and_model() {
        let adapter = MessagesAdapter;
        assert!(adapter.matches_body_shape(&json!({
            "model": "claude",
            "max_tokens": 10,
            "messages": []
        })));
        assert!(adapter.matches_body_shape(&json!({
            "model": "claude",
            "maxTokens": 10,
            "messages": []
        })));
        assert!(!adapter.matches_body_shape(&json!({
            "model": "claude",
            "messages": []
        })));
    }

    #[test]
    fn parses_system_tool_use_result_media_thinking_and_choice() {
        let adapter = MessagesAdapter;
        let request = adapter
            .parse(&json!({
                "model": "claude-sonnet-4-6",
                "max_tokens": 2048,
                "stream": true,
                "system": "You are helpful",
                "thinking": {"type": "adaptive"},
                "tool_choice": {"type": "auto"},
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "hi"},
                            {"type": "image", "source": {"type": "url", "url": "https://example.test/a.png"}},
                            {
                                "type": "document",
                                "source": {"type": "base64", "media_type": "application/pdf", "data": "AAAA"},
                                "title": "doc"
                            }
                        ]
                    },
                    {
                        "role": "assistant",
                        "content": [
                            {"type": "thinking", "thinking": "hmm", "signature": "sig"},
                            {"type": "tool_use", "id": "toolu_1", "name": "read", "input": {"path": "a"}}
                        ]
                    },
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "ok"}]}
                        ]
                    }
                ]
            }))
            .expect("valid messages request");

        assert_eq!(request.model, "claude-sonnet-4-6");
        assert!(request.stream);
        assert_eq!(request.source_surface, SourceSurface::Messages);
        assert!(matches!(
            request.system.as_deref(),
            Some([ContentPart::Text { text }]) if text == "You are helpful"
        ));
        assert_eq!(request.generation_controls.max_tokens, Some(2048));
        assert!(matches!(
            request.reasoning,
            Some(ReasoningIntent {
                thinking_type: Some(ThinkingType::Adaptive),
                ..
            })
        ));
        assert_eq!(request.tool_choice, Some(keyla_core::ToolChoice::Auto));
        let user = &request.messages[0];
        assert!(matches!(
            user.content.get(1),
            Some(ContentPart::Image { payload })
                if payload["source"]["url"] == "https://example.test/a.png"
        ));
        assert!(matches!(
            user.content.get(2),
            Some(ContentPart::Document {
                source_type: Some(keyla_core::DocumentSourceType::Base64),
                title: Some(title),
                ..
            }) if title == "doc"
        ));
        let assistant = &request.messages[1];
        assert!(matches!(
            assistant.content.first(),
            Some(ContentPart::Reasoning {
                signature: Some(signature),
                ..
            }) if signature == "sig"
        ));
        assert!(matches!(
            assistant.content.get(1),
            Some(ContentPart::ToolCall { call_id, name, .. })
                if call_id == "toolu_1" && name == "read"
        ));
        assert!(matches!(
            request.messages.get(2).map(|message| &message.content[0]),
            Some(ContentPart::ToolResult { call_id, .. }) if call_id == "toolu_1"
        ));
    }

    #[test]
    fn malformed_bodies_return_errors() {
        let adapter = MessagesAdapter;
        assert!(
            adapter
                .parse(&json!({"model": "claude", "messages": []}))
                .is_err()
        );
        assert!(
            adapter
                .parse(&json!({"model": "claude", "max_tokens": 0, "messages": []}))
                .is_err()
        );
        assert!(
            adapter
                .parse(&json!({
                    "model": "claude",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": [{"type": "tool_use", "id": "x"}]}]
                }))
                .is_err()
        );
    }

    #[test]
    fn encodes_non_streaming_response_and_usage() {
        let usage = UsageRecord {
            input_tokens: 10,
            cached_input_tokens: TokenCount::Number(4),
            cache_write_tokens: TokenCount::Number(2),
            uncached_input_tokens: TokenCount::Number(6),
            output_tokens: 5,
            reasoning_tokens: TokenCount::Number(1),
            estimated_cost: None,
            credit_used: None,
            total_tokens: None,
            details: None,
        };
        let events = vec![
            CanonicalEvent::MessageStart {
                sequence_number: 1,
                event_id: Some("msg_1".into()),
                response_id: None,
                model: Some("claude-sonnet-4-6".into()),
                system_fingerprint: None,
                timestamp: None,
            },
            CanonicalEvent::ContentDelta {
                sequence_number: 2,
                content: ContentPart::Text {
                    text: "Hello".into(),
                },
                event_id: None,
                response_id: None,
                item_id: None,
                output_index: None,
                content_index: None,
                timestamp: None,
            },
            CanonicalEvent::ToolCallDelta {
                sequence_number: 3,
                call_id: "toolu_1".into(),
                index: None,
                name: Some("read".into()),
                arguments_delta: Some("{\"path\":\"a\"}".into()),
                event_id: None,
                response_id: None,
                item_id: None,
                output_index: None,
                timestamp: None,
            },
            CanonicalEvent::Terminal {
                sequence_number: 4,
                state: TerminalState::Complete,
                stop_reason: Some(CanonicalStopReason::Stop),
                provider_stop_reason: None,
                stop_details: None,
                usage: Some(usage),
                event_id: None,
                response_id: None,
                timestamp: None,
            },
        ];
        let response = encode_messages_response(&events, "claude-sonnet-4-6", true);
        assert_eq!(response["type"], "message");
        assert_eq!(response["model"], "claude-sonnet-4-6");
        assert_eq!(response["content"][0]["type"], "text");
        assert_eq!(response["content"][0]["text"], "Hello");
        assert_eq!(response["content"][1]["type"], "tool_use");
        assert_eq!(response["content"][1]["input"]["path"], "a");
        assert_eq!(response["stop_reason"], "end_turn");
        assert!(response["stop_sequence"].is_null());
        assert_eq!(response["usage"]["input_tokens"], 6);
        assert_eq!(response["usage"]["cache_read_input_tokens"], 4);
        assert_eq!(response["usage"]["cache_creation_input_tokens"], 2);
        assert_eq!(
            response["usage"]["output_tokens_details"]["thinking_tokens"],
            1
        );
    }

    #[test]
    fn stream_encoder_opens_blocks_and_terminates_once() {
        let mut encoder = MessagesStreamEncoder::new("claude-sonnet-4-6", true);
        let first = encoder.push(&CanonicalEvent::ContentDelta {
            sequence_number: 1,
            content: ContentPart::Text { text: "Hi".into() },
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            content_index: None,
            timestamp: None,
        });
        assert_eq!(first[0]["type"], "message_start");
        assert_eq!(first[1]["type"], "content_block_start");
        assert_eq!(first[1]["index"], 0);
        assert_eq!(first[2]["delta"]["type"], "text_delta");

        let second = encoder.push(&CanonicalEvent::ContentDelta {
            sequence_number: 2,
            content: ContentPart::Text {
                text: " there".into(),
            },
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            content_index: None,
            timestamp: None,
        });
        assert_eq!(second.len(), 1);
        assert_eq!(second[0]["delta"]["text"], " there");

        let tool = encoder.push(&CanonicalEvent::ToolCallDelta {
            sequence_number: 3,
            call_id: "call_1".into(),
            index: None,
            name: Some("read".into()),
            arguments_delta: Some("{\"path\":\"a\"}".into()),
            event_id: None,
            response_id: None,
            item_id: None,
            output_index: None,
            timestamp: None,
        });
        let kinds: Vec<&str> = tool
            .iter()
            .map(|frame| frame["type"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            kinds,
            vec![
                "content_block_stop",
                "content_block_start",
                "content_block_delta"
            ]
        );

        let terminal = encoder.push(&CanonicalEvent::Terminal {
            sequence_number: 4,
            state: TerminalState::Complete,
            stop_reason: Some(CanonicalStopReason::ToolUse),
            provider_stop_reason: None,
            stop_details: None,
            usage: None,
            event_id: None,
            response_id: None,
            timestamp: None,
        });
        let kinds: Vec<&str> = terminal
            .iter()
            .map(|frame| frame["type"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            kinds,
            vec!["content_block_stop", "message_delta", "message_stop"]
        );
        assert_eq!(terminal[1]["delta"]["stop_reason"], "tool_use");
        assert!(encoder.finish().is_empty());
    }
}
