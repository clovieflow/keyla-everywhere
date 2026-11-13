//! Canonical → Claude Messages request builder.
//! Port of `src/protocol/request/messages.ts`.

use std::collections::HashMap;

use keyla_core::{
    CanonicalRequest, ContentPart, DocumentSourceType, ReasoningEffort, ReasoningIntent,
    StopSequence, ThinkingDisplay, ThinkingType, ToolChoice, WireFamily,
};
use serde_json::{Map, Value, json};

use crate::primitives::{
    is_record, normalize_anthropic_tool_call_id, parse_arguments, resolve_image_source,
    sanitize_schema_for_anthropic, split_data_url,
};
use crate::translation::{
    EffortLevel, clamp_reasoning_effort, level_to_budget, normalize_wire_max_tokens,
    resolve_supported_reasoning_efforts, resolve_wire_max_tokens,
};

/// Output-token ceiling applied to OAuth-authenticated Messages traffic.
pub const OAUTH_MESSAGES_MAX_OUTPUT_TOKENS: i64 = 64_000;

/// Gateway default when the caller sent no `max_tokens`.
pub const ANTHROPIC_DEFAULT_MAX_TOKENS: i64 = 4_096;

const THINKING_BUDGET_OUTPUT_BUFFER: i64 = 1_024;
const MAX_STOP_SEQUENCES: usize = 4;
const CLAUDE_TOOL_PREFIX: &str = "_";
const CLAUDE_BILLING_HEADER_PREFIX: &str = "x-anthropic-billing-header:";

const ANTHROPIC_IMAGE_MEDIA_TYPES: [&str; 4] =
    ["image/jpeg", "image/png", "image/gif", "image/webp"];

const ANTHROPIC_BUILTIN_TOOL_NAMES: [&str; 13] = [
    "web_search",
    "web_fetch",
    "code_execution",
    "code_execution_20250825",
    "code_execution_20260120",
    "code_execution_20260521",
    "text_editor",
    "computer",
    "tool_search_tool_regex_20251119",
    "tool_search_tool_bm25_20251119",
    "tool_search_tool_regex",
    "tool_search_tool_bm25",
    "mcp_toolset",
];

fn is_claude_billing_header_text(text: &str) -> bool {
    text.starts_with(CLAUDE_BILLING_HEADER_PREFIX)
}

fn prefix_claude_tool_name(name: &str, is_oauth: bool) -> String {
    if !is_oauth
        || ANTHROPIC_BUILTIN_TOOL_NAMES
            .iter()
            .any(|builtin| name.to_lowercase() == *builtin)
    {
        return name.to_owned();
    }
    format!("{CLAUDE_TOOL_PREFIX}{name}")
}

/// Normalizes a base64 image block's `media_type` against Anthropic's set.
fn normalize_anthropic_image_media_type(media_type: &str) -> String {
    let lower = media_type.to_lowercase();
    let normalized = if ANTHROPIC_IMAGE_MEDIA_TYPES.contains(&lower.as_str()) {
        lower.clone()
    } else {
        match lower.as_str() {
            "image/jpg" | "jpg" | "jpeg" => "image/jpeg".to_owned(),
            "png" => "image/png".to_owned(),
            "gif" => "image/gif".to_owned(),
            "webp" => "image/webp".to_owned(),
            _ => lower,
        }
    };
    if ANTHROPIC_IMAGE_MEDIA_TYPES.contains(&normalized.as_str()) {
        normalized
    } else {
        media_type.to_owned()
    }
}

fn parse_arguments_lossy(value: &Value) -> Value {
    match parse_arguments(value) {
        Ok(parsed) => parsed,
        Err(_) => value.clone(),
    }
}

/// Projects a canonical image part onto an Anthropic `image` block.
fn normalize_image_block(payload: &Value) -> Value {
    let Some(payload_map) = payload.as_object() else {
        if let Some(resolved) = resolve_image_source(payload) {
            if let Some(url) = resolved.url {
                if let Some(split) = split_data_url(&url) {
                    return json!({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": split.media_type,
                            "data": split.data,
                        },
                    });
                }
                return json!({"type": "image", "source": {"type": "url", "url": url}});
            }
            if let Some(file_id) = resolved.file_id {
                return json!({"type": "image", "source": {"type": "file", "file_id": file_id}});
            }
        }
        return json!({"type": "image", "source": payload.clone()});
    };

    let raw_source = payload_map
        .get("source")
        .and_then(Value::as_object)
        .unwrap_or(payload_map);
    let source_is_anthropic = matches!(
        raw_source.get("type").and_then(Value::as_str),
        Some("base64" | "url" | "file")
    );
    let mut source = if source_is_anthropic {
        raw_source.clone()
    } else {
        Map::new()
    };

    if source_is_anthropic && source.get("type").and_then(Value::as_str) == Some("url") {
        if let Some(url) = source.get("url").and_then(Value::as_str) {
            if let Some(split) = split_data_url(url) {
                source.insert("type".into(), json!("base64"));
                source.insert("media_type".into(), json!(split.media_type));
                source.insert("data".into(), json!(split.data));
                source.remove("url");
            }
        }
    }

    if !source_is_anthropic {
        let file_id = raw_source.get("file_id").and_then(Value::as_str);
        let nested = raw_source.get("image_url");
        let nested_url = match nested {
            Some(Value::Object(inner)) => inner.get("url").and_then(Value::as_str),
            Some(Value::String(url)) => Some(url.as_str()),
            _ => None,
        };
        let url = nested_url.or_else(|| raw_source.get("url").and_then(Value::as_str));
        let inline_data = raw_source.get("data").and_then(Value::as_str);
        if let Some(file_id) = file_id {
            source.insert("type".into(), json!("file"));
            source.insert("file_id".into(), json!(file_id));
        } else if let Some(url) = url {
            if let Some(split) = split_data_url(url) {
                source.insert("type".into(), json!("base64"));
                source.insert("media_type".into(), json!(split.media_type));
                source.insert("data".into(), json!(split.data));
            } else {
                source.insert("type".into(), json!("url"));
                source.insert("url".into(), json!(url));
            }
        } else if let Some(inline_data) = inline_data {
            source.insert("type".into(), json!("base64"));
            let media_type = raw_source
                .get("media_type")
                .and_then(Value::as_str)
                .unwrap_or("image/png");
            source.insert("media_type".into(), json!(media_type));
            source.insert("data".into(), json!(inline_data));
        }
    }

    if let Some(media_type) = source.get("media_type").and_then(Value::as_str) {
        let normalized = normalize_anthropic_image_media_type(media_type);
        source.insert("media_type".into(), json!(normalized));
    }

    if !matches!(
        source.get("type").and_then(Value::as_str),
        Some("base64" | "url" | "file")
    ) {
        return if raw_source == payload_map {
            json!({"type": "image", "source": Value::Object(source)})
        } else {
            let mut out = payload_map.clone();
            out.insert("source".into(), Value::Object(source));
            Value::Object(out)
        };
    }
    if raw_source == payload_map {
        json!({"type": "image", "source": Value::Object(source)})
    } else {
        let mut out = payload_map.clone();
        out.insert("source".into(), Value::Object(source));
        Value::Object(out)
    }
}

fn anthropic_file_source(part: &ContentPart) -> Option<Value> {
    let ContentPart::File {
        data,
        media_type,
        file_id,
        url,
        ..
    } = part
    else {
        return None;
    };
    if let Some(file_id) = file_id {
        return Some(json!({"type": "file", "file_id": file_id}));
    }
    if let Some(url) = url {
        let data_is_url = match data {
            Value::Null => true,
            Value::String(text) => text.is_empty() || text == url,
            _ => false,
        };
        if data_is_url {
            return Some(json!({"type": "url", "url": url}));
        }
    }
    Some(json!({"type": "base64", "media_type": media_type, "data": data}))
}

fn anthropic_document_source(part: &ContentPart) -> Option<Value> {
    let ContentPart::Document {
        data,
        media_type,
        source_type,
        url,
        file_id,
        ..
    } = part
    else {
        return None;
    };
    if *source_type == Some(DocumentSourceType::Url) {
        if let Some(url) = url {
            return Some(json!({"type": "url", "url": url}));
        }
    }
    if *source_type == Some(DocumentSourceType::File) {
        if let Some(file_id) = file_id {
            return Some(json!({"type": "file", "file_id": file_id}));
        }
    }
    if *source_type == Some(DocumentSourceType::Text) {
        return Some(json!({"type": "text", "media_type": media_type, "data": data}));
    }
    Some(json!({"type": "base64", "media_type": media_type, "data": data}))
}

#[derive(Debug, Default)]
struct WireContext {
    seen: HashMap<String, usize>,
    id_map: HashMap<String, String>,
    is_oauth: bool,
}

fn part_to_claude_block(part: &ContentPart, ctx: &mut WireContext) -> Option<Value> {
    match part {
        ContentPart::Text { text } => Some(json!({"type": "text", "text": text})),
        ContentPart::Image { payload } => Some(normalize_image_block(payload)),
        ContentPart::File { filename, .. } => {
            let mut block = Map::new();
            block.insert("type".into(), json!("document"));
            block.insert(
                "source".into(),
                anthropic_file_source(part).unwrap_or_else(|| json!({})),
            );
            if let Some(filename) = filename {
                block.insert("title".into(), json!(filename));
            }
            Some(Value::Object(block))
        }
        ContentPart::Document {
            title, citations, ..
        } => {
            let mut block = Map::new();
            block.insert("type".into(), json!("document"));
            block.insert(
                "source".into(),
                anthropic_document_source(part).unwrap_or_else(|| json!({})),
            );
            if let Some(title) = title {
                block.insert("title".into(), json!(title));
            }
            if let Some(citations) = citations {
                block.insert("citations".into(), json!({"enabled": citations}));
            }
            Some(Value::Object(block))
        }
        ContentPart::Audio { .. } => Some(json!({"type": "text", "text": "[audio]"})),
        ContentPart::Refusal { text } => Some(json!({"type": "text", "text": text})),
        ContentPart::ToolCall {
            call_id,
            name,
            arguments,
            ..
        } => {
            let normalized = normalize_anthropic_tool_call_id(call_id, &mut ctx.seen);
            ctx.id_map.insert(call_id.clone(), normalized.clone());
            Some(json!({
                "type": "tool_use",
                "id": normalized,
                "name": prefix_claude_tool_name(name, ctx.is_oauth),
                "input": parse_arguments_lossy(arguments),
            }))
        }
        ContentPart::ToolResult {
            call_id,
            content,
            is_error,
            ..
        } => {
            let normalized = if let Some(existing) = ctx.id_map.get(call_id) {
                existing.clone()
            } else {
                let normalized = normalize_anthropic_tool_call_id(call_id, &mut ctx.seen);
                ctx.id_map.insert(call_id.clone(), normalized.clone());
                normalized
            };
            let content = match content {
                keyla_core::ToolResultContent::Text(text) => Value::String(text.clone()),
                keyla_core::ToolResultContent::Parts(parts) => Value::Array(
                    parts
                        .iter()
                        .filter_map(|part| part_to_claude_block(part, ctx))
                        .collect(),
                ),
            };
            let mut block = Map::new();
            block.insert("type".into(), json!("tool_result"));
            block.insert("tool_use_id".into(), json!(normalized));
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
            if *opaque != Some(true)
                && signature
                    .as_deref()
                    .is_none_or(|signature| signature.trim().is_empty())
            {
                let text = summary
                    .clone()
                    .or_else(|| payload.as_str().map(str::to_owned))
                    .unwrap_or_default();
                return (!text.is_empty()).then(|| json!({"type": "text", "text": text}));
            }
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
            if name == "server_tool_use"
                || name == "search_result"
                || name == "document"
                || (name.starts_with("messages:") && name != "messages:unknown")
            {
                return Some(payload.clone());
            }
            None
        }
    }
}

fn canonical_tool_choice(value: Option<&ToolChoice>) -> Option<Value> {
    match value? {
        ToolChoice::Auto => Some(json!({"type": "auto"})),
        ToolChoice::None => Some(json!({"type": "none"})),
        ToolChoice::Required => Some(json!({"type": "any"})),
        ToolChoice::Tool { name } => Some(json!({"type": "tool", "name": name})),
        ToolChoice::Custom { name } => Some(json!({"type": "tool", "name": name})),
        ToolChoice::AllowedTools { mode, names } => Some(json!({
            "type": "allowed_tools",
            "mode": mode,
            "tools": names
                .iter()
                .map(|name| json!({"type": "tool", "name": name}))
                .collect::<Vec<_>>(),
        })),
    }
}

fn stable_partition_tool_use(blocks: &mut Vec<Value>) {
    let mut saw_tool_use = false;
    let mut needs_partition = false;
    for block in blocks.iter() {
        if block.get("type").and_then(Value::as_str) == Some("tool_use") {
            saw_tool_use = true;
        } else if saw_tool_use {
            needs_partition = true;
            break;
        }
    }
    if !needs_partition {
        return;
    }
    let mut non_tool_use = Vec::with_capacity(blocks.len());
    let mut tool_use = Vec::new();
    for block in blocks.drain(..) {
        if block.get("type").and_then(Value::as_str) == Some("tool_use") {
            tool_use.push(block);
        } else {
            non_tool_use.push(block);
        }
    }
    blocks.extend(non_tool_use);
    blocks.extend(tool_use);
}

fn is_thinking_enabled(reasoning: Option<&ReasoningIntent>) -> bool {
    let Some(reasoning) = reasoning else {
        return false;
    };
    matches!(
        reasoning.thinking_type,
        Some(ThinkingType::Enabled | ThinkingType::Adaptive)
    )
}

fn ensure_max_tokens_for_thinking(current: i64, budget: Option<i64>) -> i64 {
    match budget {
        Some(budget) if budget > 0 => {
            current.max(budget.saturating_add(THINKING_BUDGET_OUTPUT_BUFFER))
        }
        _ => current,
    }
}

fn claude_uses_adaptive_thinking(model: &str) -> bool {
    let id = model.to_lowercase().replace('.', "-");
    id.contains("fable")
        || id.contains("mythos")
        || id.contains("opus-5")
        || id.contains("sonnet-5")
        || id.contains("opus-4-6")
        || id.contains("sonnet-4-6")
        || id.contains("opus-4-7")
        || id.contains("opus-4-8")
}

fn effort_level(effort: Option<ReasoningEffort>) -> Option<EffortLevel> {
    match effort? {
        ReasoningEffort::None => None,
        ReasoningEffort::Minimal => Some(EffortLevel::Minimal),
        ReasoningEffort::Low => Some(EffortLevel::Low),
        ReasoningEffort::Medium => Some(EffortLevel::Medium),
        ReasoningEffort::High => Some(EffortLevel::High),
        ReasoningEffort::Xhigh => Some(EffortLevel::Xhigh),
        ReasoningEffort::Max => Some(EffortLevel::Max),
    }
}

fn thinking_type_wire(value: Option<ThinkingType>) -> &'static str {
    match value {
        Some(ThinkingType::Enabled) => "enabled",
        Some(ThinkingType::Adaptive) => "adaptive",
        Some(ThinkingType::Disabled) => "disabled",
        None => "adaptive",
    }
}

fn display_wire(value: Option<ThinkingDisplay>) -> Option<&'static str> {
    value.map(|display| match display {
        ThinkingDisplay::Summarized => "summarized",
        ThinkingDisplay::Omitted => "omitted",
        ThinkingDisplay::Updates => "updates",
    })
}

fn build_anthropic_thinking_payload(reasoning: &ReasoningIntent) -> Value {
    let mut block = Map::new();
    block.insert(
        "type".into(),
        json!(thinking_type_wire(reasoning.thinking_type)),
    );
    if let Some(budget) = reasoning.budget_tokens {
        block.insert("budget_tokens".into(), json!(budget));
    }
    if let Some(display) = display_wire(reasoning.display) {
        block.insert("display".into(), json!(display));
    }
    if let Some(behavior) = reasoning.prefix_mismatch_behavior {
        block.insert(
            "block_binding".into(),
            json!({"prefix_mismatch_behavior": behavior}),
        );
    }
    Value::Object(block)
}

fn apply_cache_control(block: &mut Value) {
    if let Some(map) = block.as_object_mut() {
        map.insert("cache_control".into(), json!({"type": "ephemeral"}));
    }
}

fn cacheable_message_block(block: &Value) -> bool {
    matches!(
        block.get("type").and_then(Value::as_str),
        Some("text" | "image" | "document" | "audio" | "tool_use" | "tool_result")
    )
}

/// Encodes a canonical request as a Claude Messages body.
pub fn canonical_to_messages_payload(request: &CanonicalRequest, is_oauth: bool) -> Value {
    let mut ctx = WireContext {
        is_oauth,
        ..WireContext::default()
    };
    let mut messages: Vec<Value> = Vec::new();
    let mut hoisted_system: Vec<ContentPart> = Vec::new();

    for message in &request.messages {
        if matches!(
            message.role,
            keyla_core::Role::System | keyla_core::Role::Developer
        ) {
            hoisted_system.extend(message.content.iter().cloned());
            continue;
        }
        let content: Vec<Value> = message
            .content
            .iter()
            .filter_map(|part| part_to_claude_block(part, &mut ctx))
            .collect();
        if let Some(previous) = messages.last_mut() {
            if previous.get("role").and_then(Value::as_str) == Some("assistant")
                && matches!(message.role, keyla_core::Role::Assistant)
            {
                if let Some(previous_content) =
                    previous.get_mut("content").and_then(Value::as_array_mut)
                {
                    previous_content.extend(content);
                }
                continue;
            }
        }
        let role = match message.role {
            keyla_core::Role::Tool => "user",
            keyla_core::Role::Developer | keyla_core::Role::System => "user",
            keyla_core::Role::Assistant => "assistant",
            keyla_core::Role::User => "user",
        };
        messages.push(json!({"role": role, "content": content}));
    }

    for message in &mut messages {
        if message.get("role").and_then(Value::as_str) == Some("assistant") {
            if let Some(content) = message.get_mut("content").and_then(Value::as_array_mut) {
                stable_partition_tool_use(content);
            }
        }
    }

    // Caller-driven cache breakpoints only: no implicit TTL/scope is added.
    if let Some(last) = messages.last_mut() {
        if let Some(blocks) = last.get_mut("content").and_then(Value::as_array_mut) {
            for block in blocks.iter_mut().rev() {
                if cacheable_message_block(block) {
                    apply_cache_control(block);
                    break;
                }
            }
        }
    }

    let normalized_controls = normalize_wire_max_tokens(&request.generation_controls);
    let requested_max = normalized_controls.max_tokens;
    let has_tools = request
        .tools
        .as_ref()
        .is_some_and(|tools| !tools.is_empty());
    let mut max_tokens = resolve_wire_max_tokens("messages", requested_max, has_tools, is_oauth)
        .unwrap_or(ANTHROPIC_DEFAULT_MAX_TOKENS);

    if is_thinking_enabled(request.reasoning.as_ref())
        && request
            .reasoning
            .as_ref()
            .and_then(|r| r.budget_tokens)
            .is_some()
    {
        max_tokens = ensure_max_tokens_for_thinking(
            max_tokens,
            request.reasoning.as_ref().and_then(|r| r.budget_tokens),
        );
    }

    let adaptive_thinking = claude_uses_adaptive_thinking(&request.model);
    let mut effective_budget_tokens = request.reasoning.as_ref().and_then(|r| r.budget_tokens);
    let wants_reasoning = request
        .reasoning
        .as_ref()
        .is_some_and(|r| r.thinking_type != Some(ThinkingType::Disabled));
    if wants_reasoning && !adaptive_thinking && effective_budget_tokens.is_none() {
        if let Some(level) = effort_level(request.reasoning.as_ref().and_then(|r| r.effort)) {
            effective_budget_tokens = Some(level_to_budget(Some(level)).max(1_024));
        }
    }
    if !adaptive_thinking {
        if let Some(budget) = effective_budget_tokens {
            max_tokens = ensure_max_tokens_for_thinking(max_tokens, Some(budget));
        }
    }

    let mut payload = Map::new();
    payload.insert("model".into(), json!(request.model));
    payload.insert("max_tokens".into(), json!(max_tokens));
    payload.insert("messages".into(), Value::Array(messages));
    payload.insert("stream".into(), json!(request.stream));

    let mut system_parts: Vec<ContentPart> = Vec::new();
    if let Some(system) = &request.system {
        system_parts.extend(system.iter().cloned());
    }
    if let Some(instructions) = &request.instructions {
        system_parts.extend(instructions.iter().cloned());
    }
    system_parts.extend(hoisted_system);
    if !system_parts.is_empty() {
        let system: Vec<Value> = system_parts
            .iter()
            .filter(|part| {
                !matches!(part, ContentPart::Text { text } if is_claude_billing_header_text(text))
            })
            .filter_map(|part| part_to_claude_block(part, &mut ctx))
            .collect();
        if !system.is_empty() {
            payload.insert("system".into(), Value::Array(system));
        }
    }

    if let Some(tools) = &request.tools {
        if !tools.is_empty() {
            let tools: Vec<Value> = tools
                .iter()
                .map(|tool| {
                    let mut entry = Map::new();
                    entry.insert(
                        "name".into(),
                        json!(prefix_claude_tool_name(&tool.name, is_oauth)),
                    );
                    if let Some(description) = &tool.description {
                        entry.insert("description".into(), json!(description));
                    }
                    entry.insert(
                        "input_schema".into(),
                        sanitize_schema_for_anthropic(&tool.json_schema),
                    );
                    if tool.strict == Some(true) {
                        entry.insert("strict".into(), json!(true));
                    }
                    if let Some(eager) = tool.eager_input_streaming {
                        entry.insert("eager_input_streaming".into(), json!(eager));
                    }
                    if let Some(defer) = tool.defer_loading {
                        entry.insert("defer_loading".into(), json!(defer));
                    }
                    if let Some(examples) = &tool.input_examples {
                        if let Ok(value) = serde_json::to_value(examples) {
                            entry.insert("input_examples".into(), value);
                        }
                    }
                    if let Some(callers) = &tool.allowed_callers {
                        entry.insert("allowed_callers".into(), json!(callers));
                    }
                    Value::Object(entry)
                })
                .collect();
            payload.insert("tools".into(), Value::Array(tools));
        }
    }

    let mut raw_tool_choice = canonical_tool_choice(request.tool_choice.as_ref());
    if let Some(choice) = raw_tool_choice.as_mut() {
        if choice.get("type").and_then(Value::as_str) == Some("tool") {
            if let Some(name) = choice.get("name").and_then(Value::as_str) {
                let prefixed = prefix_claude_tool_name(name, is_oauth);
                if let Some(map) = choice.as_object_mut() {
                    map.insert("name".into(), json!(prefixed));
                }
            }
        }
    }
    let parallel_tool_calls_disabled =
        request.generation_controls.parallel_tool_calls == Some(false);
    if raw_tool_choice.is_some() || parallel_tool_calls_disabled {
        let mut choice = raw_tool_choice
            .take()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_else(|| {
                let mut map = Map::new();
                map.insert("type".into(), json!("auto"));
                map
            });
        if parallel_tool_calls_disabled {
            choice.insert("disable_parallel_tool_use".into(), json!(true));
        }
        payload.insert("tool_choice".into(), Value::Object(choice));
    }

    if let Some(system) = payload.get_mut("system").and_then(Value::as_array_mut) {
        if let Some(last) = system.last_mut() {
            apply_cache_control(last);
        }
    }
    if let Some(tools) = payload.get_mut("tools").and_then(Value::as_array_mut) {
        if let Some(last) = tools.last_mut() {
            apply_cache_control(last);
        }
    }

    let controls = &request.generation_controls;
    let thinking_stripped = is_thinking_enabled(request.reasoning.as_ref());
    if let Some(temperature) = controls.temperature {
        if !thinking_stripped {
            payload.insert("temperature".into(), json!(temperature));
        }
    }
    if let Some(top_p) = controls.top_p {
        if !thinking_stripped {
            payload.insert("top_p".into(), json!(top_p));
        }
    }
    if let Some(top_k) = controls.top_k {
        if !thinking_stripped {
            payload.insert("top_k".into(), json!(top_k));
        }
    }
    if let Some(stop) = &controls.stop {
        let stop_list: Vec<String> = match stop {
            StopSequence::One(one) => vec![one.clone()],
            StopSequence::Many(many) => many.clone(),
        };
        payload.insert(
            "stop_sequences".into(),
            Value::Array(
                stop_list
                    .into_iter()
                    .take(MAX_STOP_SEQUENCES)
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    if let Some(reasoning) = &request.reasoning {
        if reasoning.thinking_type == Some(ThinkingType::Disabled) {
            payload.insert(
                "thinking".into(),
                build_anthropic_thinking_payload(reasoning),
            );
        } else if adaptive_thinking {
            let mut adaptive = reasoning.clone();
            adaptive.budget_tokens = None;
            adaptive.thinking_type = Some(ThinkingType::Adaptive);
            if adaptive.display.is_none() {
                adaptive.display = Some(ThinkingDisplay::Summarized);
            }
            payload.insert(
                "thinking".into(),
                build_anthropic_thinking_payload(&adaptive),
            );
            payload.insert(
                "context_management".into(),
                controls
                    .extensions
                    .get("extension:context_management")
                    .filter(|value| is_record(value))
                    .cloned()
                    .unwrap_or_else(
                        || json!({"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]}),
                    ),
            );
        } else {
            let mut enabled = reasoning.clone();
            enabled.thinking_type = Some(ThinkingType::Enabled);
            enabled.budget_tokens = effective_budget_tokens;
            payload.insert(
                "thinking".into(),
                build_anthropic_thinking_payload(&enabled),
            );
            payload.insert(
                "context_management".into(),
                controls
                    .extensions
                    .get("extension:context_management")
                    .filter(|value| is_record(value))
                    .cloned()
                    .unwrap_or_else(
                        || json!({"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]}),
                    ),
            );
        }

        let supported =
            resolve_supported_reasoning_efforts(Some(&request.model), WireFamily::Messages, None);
        let effort = clamp_reasoning_effort(effort_level(reasoning.effort), &supported);
        let task_budget = reasoning.task_budget;
        if effort.is_some() || task_budget.is_some() {
            let mut output_config = Map::new();
            if let Some(effort) = effort {
                output_config.insert("effort".into(), json!(effort.as_str()));
            }
            if let Some(task_budget) = task_budget {
                output_config.insert("task_budget".into(), json!(task_budget));
            }
            payload.insert("output_config".into(), Value::Object(output_config));
        }
    }

    if let Some(container) = controls.extensions.get("extension:container") {
        if is_record(container) {
            payload.insert("container".into(), container.clone());
        }
    }
    if let Some(inference_geo) = controls
        .extensions
        .get("extension:inference_geo")
        .and_then(Value::as_str)
    {
        payload.insert("inference_geo".into(), json!(inference_geo));
    }
    if let Some(service_tier) = controls
        .extensions
        .get("extension:service_tier")
        .and_then(Value::as_str)
    {
        if service_tier == "auto" || service_tier == "standard_only" {
            payload.insert("service_tier".into(), json!(service_tier));
        }
    }
    if let Some(user_profile_id) = controls
        .extensions
        .get("extension:user_profile_id")
        .and_then(Value::as_str)
    {
        payload.insert("user_profile_id".into(), json!(user_profile_id));
    }
    if let Some(workspace_id) = controls
        .extensions
        .get("extension:workspace_id")
        .and_then(Value::as_str)
    {
        payload.insert("workspace_id".into(), json!(workspace_id));
    }
    if let Some(metadata_user_id) = controls
        .extensions
        .get("extension:metadata_user_id")
        .and_then(Value::as_str)
    {
        payload.insert("metadata".into(), json!({"user_id": metadata_user_id}));
    }

    Value::Object(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{CanonicalMessage, GenerationControls, Role};

    fn request_with(parts: Vec<ContentPart>) -> CanonicalRequest {
        CanonicalRequest {
            model: "claude-sonnet-4-6".into(),
            system: None,
            instructions: None,
            messages: vec![CanonicalMessage {
                role: Role::User,
                content: parts,
                phase: None,
            }],
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
            source_surface: keyla_core::SourceSurface::Messages,
        }
    }

    #[test]
    fn projects_system_tools_tool_choice_and_thinking() {
        let mut request = request_with(vec![ContentPart::Text {
            text: "hello".into(),
        }]);
        request.system = Some(vec![ContentPart::Text {
            text: "be terse".into(),
        }]);
        request.tools = Some(vec![keyla_core::ToolDefinition {
            name: "read".into(),
            description: Some("Read a file".into()),
            json_schema: json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "$schema": "drop-me",
            }),
            strict: Some(true),
            eager_input_streaming: None,
            defer_loading: None,
            input_examples: None,
            tool_type: Some(keyla_core::ToolType::Function),
            native_type: None,
            allowed_callers: Some(vec![keyla_core::ToolCaller::Direct]),
        }]);
        request.tool_choice = Some(ToolChoice::Tool {
            name: "read".into(),
        });
        request.generation_controls.max_tokens = Some(200);
        request.reasoning = Some(ReasoningIntent {
            thinking_type: Some(ThinkingType::Adaptive),
            ..ReasoningIntent::default()
        });

        let payload = canonical_to_messages_payload(&request, true);

        assert_eq!(payload["model"], "claude-sonnet-4-6");
        assert_eq!(payload["max_tokens"], 32_000);
        assert_eq!(payload["system"][0]["text"], "be terse");
        assert_eq!(payload["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(payload["tools"][0]["name"], "_read");
        assert_eq!(payload["tools"][0]["strict"], true);
        assert_eq!(payload["tools"][0]["allowed_callers"], json!(["direct"]));
        assert!(payload["tools"][0]["input_schema"].get("$schema").is_none());
        assert_eq!(payload["tool_choice"]["type"], "tool");
        assert_eq!(payload["tool_choice"]["name"], "_read");
        assert_eq!(payload["thinking"]["type"], "adaptive");
        assert_eq!(payload["thinking"]["display"], "summarized");
        assert_eq!(
            payload["context_management"]["edits"][0]["type"],
            "clear_thinking_20251015"
        );
        assert_eq!(
            payload["messages"][0]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
        assert!(payload.get("temperature").is_none());
        assert!(payload.get("stream_options").is_none());
    }

    #[test]
    fn max_tokens_floor_and_thinking_buffer_apply() {
        let mut request = request_with(vec![ContentPart::Text { text: "hi".into() }]);
        request.generation_controls.max_tokens = Some(10);
        let payload = canonical_to_messages_payload(&request, false);
        assert_eq!(payload["max_tokens"], 16);

        request.model = "claude-sonnet-4-5".into();
        request.reasoning = Some(ReasoningIntent {
            thinking_type: Some(ThinkingType::Enabled),
            budget_tokens: Some(2_000),
            ..ReasoningIntent::default()
        });
        let payload = canonical_to_messages_payload(&request, false);
        assert_eq!(payload["max_tokens"], 3_024);
        assert_eq!(payload["thinking"]["type"], "enabled");
        assert_eq!(payload["thinking"]["budget_tokens"], 2_000);
    }

    #[test]
    fn hoists_mid_conversation_system_and_merges_assistant_turns() {
        let mut request = request_with(vec![ContentPart::Text {
            text: "question".into(),
        }]);
        request.messages = vec![
            CanonicalMessage {
                role: Role::System,
                content: vec![ContentPart::Text { text: "env".into() }],
                phase: None,
            },
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::Text {
                    text: "part one".into(),
                }],
                phase: None,
            },
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::Text {
                    text: "part two".into(),
                }],
                phase: None,
            },
            CanonicalMessage {
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    call_id: "call_1".into(),
                    content: keyla_core::ToolResultContent::Text("done".into()),
                    is_error: None,
                    call_kind: None,
                    item_id: None,
                }],
                phase: None,
            },
        ];
        let payload = canonical_to_messages_payload(&request, false);
        assert_eq!(payload["system"][0]["text"], "env");
        assert_eq!(payload["messages"].as_array().unwrap().len(), 2);
        assert_eq!(payload["messages"][0]["content"][1]["text"], "part two");
        assert_eq!(payload["messages"][1]["role"], "user");
        assert_eq!(payload["messages"][1]["content"][0]["type"], "tool_result");
    }
}
