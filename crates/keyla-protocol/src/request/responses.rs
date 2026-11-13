//! OpenAI Responses request encoder: canonical request to provider wire body.
//! Port of `src/protocol/request/responses.ts` (non-Codex variant).

use keyla_core::{
    AssistantItemPhase, CanonicalMessage, CanonicalRequest, ContentPart, DocumentSourceType,
    ResponseFormat, Role, ToolCaller, ToolChoice, ToolDefinition, ToolResultContent, ToolType,
    WireFamily,
};
use serde_json::{Map, Value, json};

use crate::primitives::{is_record, resolve_image_source, resolve_output_verbosity};
use crate::translation::{
    cache_hint_has_breakpoints, clamp_reasoning_effort, normalize_wire_max_tokens,
    reasoning_effort_from_intent, resolve_prompt_cache_key, resolve_supported_reasoning_efforts,
    resolve_wire_max_tokens,
};

/// Knobs that change the projected body's shape.
///
/// The TypeScript encoder takes `supportsPromptCaching`; the remaining fields
/// are the surface-level booleans a caller may need to pin (a stateful proxy
/// that always stores, or a caller that forces streaming on/off). Absent
/// values fall back to the canonical request.
#[derive(Debug, Clone, Copy)]
pub struct ResponsesPayloadOptions {
    pub supports_prompt_caching: bool,
    pub stream: Option<bool>,
    pub store: Option<bool>,
}

impl Default for ResponsesPayloadOptions {
    fn default() -> Self {
        Self {
            supports_prompt_caching: true,
            stream: None,
            store: None,
        }
    }
}

impl ResponsesPayloadOptions {
    pub fn with_prompt_caching(supports_prompt_caching: bool) -> Self {
        Self {
            supports_prompt_caching,
            ..Self::default()
        }
    }

    pub fn with_stream(mut self, stream: bool) -> Self {
        self.stream = Some(stream);
        self
    }

    pub fn with_store(mut self, store: bool) -> Self {
        self.store = Some(store);
        self
    }
}

const CLAUDE_BILLING_HEADER_PREFIX: &str = "x-anthropic-billing-header:";

const RESPONSES_CACHEABLE_BLOCK_TYPES: [&str; 5] = [
    "input_text",
    "output_text",
    "input_image",
    "input_file",
    "input_audio",
];

fn is_claude_billing_header_text(text: &str) -> bool {
    text.starts_with(CLAUDE_BILLING_HEADER_PREFIX)
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

fn phase_value(phase: AssistantItemPhase) -> Value {
    match phase {
        AssistantItemPhase::Commentary => json!("commentary"),
        AssistantItemPhase::FinalAnswer => json!("final_answer"),
    }
}

fn json_string(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Marks the latest stable input block with an explicit prompt-cache breakpoint.
pub fn mark_latest_responses_cache_breakpoint(input: &mut [Value]) {
    let is_input_item = |item: &Value| {
        item.get("type").and_then(Value::as_str) == Some("message")
            && matches!(
                item.get("role").and_then(Value::as_str),
                Some("user" | "developer")
            )
    };
    let mut latest_input: Option<usize> = None;
    for index in (0..input.len()).rev() {
        if is_input_item(&input[index]) {
            latest_input = Some(index);
            break;
        }
    }
    let Some(latest_input) = latest_input else {
        return;
    };
    if latest_input == 0 {
        return;
    }
    for index in (0..latest_input).rev() {
        if !is_input_item(&input[index]) {
            continue;
        }
        let role = input[index].get("role").and_then(Value::as_str);
        if !matches!(role, Some("user" | "developer" | "system")) {
            continue;
        }
        let Some(content) = input[index].get("content") else {
            continue;
        };
        if let Some(text) = content.as_str() {
            let mut block = Map::new();
            block.insert("type".into(), json!("text"));
            block.insert("text".into(), json!(text));
            block.insert(
                "prompt_cache_breakpoint".into(),
                json!({"mode": "explicit"}),
            );
            if let Some(item) = input[index].as_object_mut() {
                item.insert("content".into(), json!([Value::Object(block)]));
            }
            return;
        }
        let Some(blocks) = content.as_array() else {
            continue;
        };
        let target = blocks.iter().rposition(|block| {
            block
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| RESPONSES_CACHEABLE_BLOCK_TYPES.contains(&kind))
        });
        if let Some(target) = target {
            if let Some(block) = input[index]
                .get_mut("content")
                .and_then(Value::as_array_mut)
                .and_then(|blocks| blocks.get_mut(target))
                .and_then(Value::as_object_mut)
            {
                block.insert(
                    "prompt_cache_breakpoint".into(),
                    json!({"mode": "explicit"}),
                );
            }
            return;
        }
    }
}

/// Renders a canonical computer-use result as a Responses `computer_screenshot`.
fn computer_output_for_wire(content: &ToolResultContent) -> Value {
    let parts = match content {
        ToolResultContent::Text(text) => {
            return json!({"type": "computer_screenshot", "image_url": text});
        }
        ToolResultContent::Parts(parts) => parts,
    };
    if let Some(ContentPart::Image { payload }) = parts
        .iter()
        .find(|part| matches!(part, ContentPart::Image { .. }))
    {
        let source = resolve_image_source(payload);
        let mut output = Map::new();
        output.insert("type".into(), json!("computer_screenshot"));
        if let Some(source) = source {
            if let Some(url) = source.url {
                output.insert("image_url".into(), Value::String(url));
            } else if let Some(file_id) = source.file_id {
                output.insert("file_id".into(), Value::String(file_id));
            }
            if let Some(detail) = source.detail {
                output.insert("detail".into(), Value::String(detail));
            }
        }
        return Value::Object(output);
    }
    json!({"type": "computer_screenshot"})
}

fn flush_message(
    input: &mut Vec<Value>,
    pending: &mut Vec<Value>,
    role: Role,
    phase: Option<AssistantItemPhase>,
) {
    if pending.is_empty() {
        return;
    }
    let mut item = Map::new();
    item.insert("type".into(), json!("message"));
    item.insert("role".into(), json!(role_str(role)));
    item.insert("content".into(), Value::Array(std::mem::take(pending)));
    if let Some(phase) = phase {
        item.insert("phase".into(), phase_value(phase));
    }
    input.push(Value::Object(item));
}

fn pending_safety_checks(item_metadata: Option<&Value>, call_id: &str) -> Option<Vec<Value>> {
    let entries = item_metadata?.as_array()?;
    let entry = entries.iter().find(|entry| {
        entry.get("type").and_then(Value::as_str) == Some("computer_call")
            && entry.get("call_id").and_then(Value::as_str) == Some(call_id)
    })?;
    entry
        .get("pending_safety_checks")
        .and_then(Value::as_array)
        .cloned()
}

fn tool_callers_value(callers: &[ToolCaller]) -> Value {
    Value::Array(
        callers
            .iter()
            .map(|caller| {
                json!(match caller {
                    ToolCaller::Direct => "direct",
                    ToolCaller::Programmatic => "programmatic",
                })
            })
            .collect(),
    )
}

fn responses_tool(tool: &ToolDefinition) -> Value {
    if tool.tool_type == Some(ToolType::Custom) {
        let mut custom = Map::new();
        custom.insert("type".into(), json!("custom"));
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
        return Value::Object(custom);
    }
    let is_web_search = tool
        .native_type
        .as_deref()
        .is_some_and(|native| native.starts_with("web_search_"))
        || tool.tool_type == Some(ToolType::WebSearch);
    if is_web_search {
        return json!({"type": "web_search_preview"});
    }
    if tool
        .tool_type
        .is_some_and(|kind| kind != ToolType::Function)
        && is_record(&tool.json_schema)
    {
        return tool.json_schema.clone();
    }
    let mut function = Map::new();
    function.insert("type".into(), json!("function"));
    function.insert("name".into(), json!(tool.name));
    if let Some(description) = &tool.description {
        function.insert("description".into(), json!(description));
    }
    function.insert("parameters".into(), tool.json_schema.clone());
    if tool.strict == Some(true) {
        function.insert("strict".into(), json!(true));
    }
    if let Some(examples) = &tool.input_examples {
        function.insert(
            "input_examples".into(),
            Value::Array(examples.iter().cloned().map(Value::Object).collect()),
        );
    }
    if let Some(defer_loading) = tool.defer_loading {
        function.insert("defer_loading".into(), json!(defer_loading));
    }
    if let Some(callers) = &tool.allowed_callers {
        function.insert("allowed_callers".into(), tool_callers_value(callers));
    }
    Value::Object(function)
}

fn apply_tool_choice(payload: &mut Map<String, Value>, choice: &ToolChoice) {
    let value = match choice {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Tool { name } => json!({"type": "function", "name": name}),
        ToolChoice::Custom { name } => json!({"type": "custom", "name": name}),
        ToolChoice::AllowedTools { mode, names } => {
            let mode = match mode {
                keyla_core::AllowedToolsMode::Auto => "auto",
                keyla_core::AllowedToolsMode::Required => "required",
            };
            json!({
                "type": "allowed_tools",
                "mode": mode,
                "tools": names
                    .iter()
                    .map(|name| json!({"type": "function", "name": name}))
                    .collect::<Vec<_>>(),
            })
        }
    };
    payload.insert("tool_choice".into(), value);
}

fn responses_content_block(part: &ContentPart, is_assistant: bool) -> Option<Value> {
    match part {
        ContentPart::Text { text } => Some(json!({
            "type": if is_assistant { "output_text" } else { "input_text" },
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
                _ => Some(json!({"type": "input_text", "text": "[image: unsupported source]"})),
            }
        }
        ContentPart::File {
            data,
            media_type: _,
            filename,
            file_id,
            url,
        } => {
            let reference_only = url
                .as_deref()
                .is_some_and(|url| data == &Value::String(url.to_owned()));
            let mut block = Map::new();
            block.insert("type".into(), json!("input_file"));
            if let Some(file_id) = file_id {
                block.insert("file_id".into(), json!(file_id));
            } else if let Some(url) = url {
                if reference_only {
                    block.insert("file_url".into(), json!(url));
                }
            }
            if !block.contains_key("file_id") && !block.contains_key("file_url") {
                if let Some(data) = inline_data(data) {
                    block.insert("file_data".into(), data);
                }
            }
            if let Some(filename) = filename {
                block.insert("filename".into(), json!(filename));
            }
            Some(Value::Object(block))
        }
        ContentPart::Document {
            data,
            media_type: _,
            title,
            source_type,
            url,
            file_id,
            ..
        } => {
            if *source_type == Some(DocumentSourceType::Text) {
                if let Some(text) = data.as_str() {
                    return Some(json!({
                        "type": if is_assistant { "output_text" } else { "input_text" },
                        "text": text,
                    }));
                }
            }
            let reference_only = matches!(
                source_type,
                Some(DocumentSourceType::Url | DocumentSourceType::File)
            ) || url
                .as_deref()
                .is_some_and(|url| data == &Value::String(url.to_owned()));
            let mut block = Map::new();
            block.insert("type".into(), json!("input_file"));
            if let Some(file_id) = file_id {
                block.insert("file_id".into(), json!(file_id));
            } else if let Some(url) = url {
                if reference_only {
                    block.insert("file_url".into(), json!(url));
                }
            }
            if !block.contains_key("file_id") && !block.contains_key("file_url") {
                if let Some(data) = inline_data(data) {
                    block.insert("file_data".into(), data);
                }
            }
            if let Some(title) = title {
                block.insert("filename".into(), json!(title));
            }
            Some(Value::Object(block))
        }
        ContentPart::Audio { data, media_type } => Some(json!({
            "type": "input_audio",
            "data": data,
            "media_type": media_type,
        })),
        ContentPart::Refusal { text } => Some(json!({
            "type": if is_assistant { "output_text" } else { "input_text" },
            "text": text,
        })),
        // `extension` (server_tool_use, search_result, …) has no Responses
        // representation and degrades away silently.
        _ => None,
    }
}

fn inline_data(data: &Value) -> Option<Value> {
    match data {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        other => Some(other.clone()),
    }
}

fn push_tool_call(input: &mut Vec<Value>, part: &ContentPart, item_metadata: Option<&Value>) {
    let ContentPart::ToolCall {
        call_id,
        name,
        arguments,
        item_id,
        call_kind,
        ..
    } = part
    else {
        return;
    };
    if *call_kind == Some(keyla_core::CallKind::Computer) {
        let actions = arguments
            .get("actions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut item = Map::new();
        item.insert("type".into(), json!("computer_call"));
        if let Some(item_id) = item_id {
            item.insert("id".into(), json!(item_id));
        }
        item.insert("call_id".into(), json!(call_id));
        item.insert("actions".into(), Value::Array(actions));
        if let Some(checks) = pending_safety_checks(item_metadata, call_id) {
            item.insert("pending_safety_checks".into(), Value::Array(checks));
        }
        item.insert("status".into(), json!("completed"));
        input.push(Value::Object(item));
    } else {
        let mut item = Map::new();
        item.insert("type".into(), json!("function_call"));
        if let Some(item_id) = item_id {
            item.insert("id".into(), json!(item_id));
        }
        item.insert("call_id".into(), json!(call_id));
        item.insert("name".into(), json!(name));
        item.insert(
            "arguments".into(),
            match arguments {
                Value::String(value) => Value::String(value.clone()),
                other => Value::String(json_string(other)),
            },
        );
        input.push(Value::Object(item));
    }
}

fn push_tool_result(input: &mut Vec<Value>, part: &ContentPart) {
    let ContentPart::ToolResult {
        call_id,
        content,
        call_kind,
        item_id,
        ..
    } = part
    else {
        return;
    };
    let is_computer = *call_kind == Some(keyla_core::CallKind::Computer);
    let mut item = Map::new();
    item.insert(
        "type".into(),
        json!(if is_computer {
            "computer_call_output"
        } else {
            "function_call_output"
        }),
    );
    if let Some(item_id) = item_id {
        item.insert("id".into(), json!(item_id));
    }
    item.insert("call_id".into(), json!(call_id));
    item.insert(
        "output".into(),
        if is_computer {
            computer_output_for_wire(content)
        } else {
            match content {
                ToolResultContent::Text(text) => Value::String(text.clone()),
                ToolResultContent::Parts(parts) => Value::String(json_string(
                    &serde_json::to_value(parts).unwrap_or(Value::Null),
                )),
            }
        },
    );
    if is_computer {
        item.insert("status".into(), json!("completed"));
    }
    input.push(Value::Object(item));
}

fn push_reasoning(input: &mut Vec<Value>, part: &ContentPart) {
    let ContentPart::Reasoning {
        payload,
        summary,
        encrypted_content,
        ..
    } = part
    else {
        return;
    };
    if let Some(encrypted_content) = encrypted_content {
        input.push(json!({"type": "reasoning", "encrypted_content": encrypted_content}));
        return;
    }
    let text = summary
        .clone()
        .or_else(|| payload.as_str().map(str::to_owned));
    if let Some(text) = text.filter(|text| !text.is_empty()) {
        input.push(json!({
            "type": "reasoning",
            "summary": [{"type": "summary_text", "text": text}],
        }));
    }
}

fn project_message_content(
    message: &CanonicalMessage,
    input: &mut Vec<Value>,
    item_metadata: Option<&Value>,
) {
    let is_assistant = message.role == Role::Assistant;
    let mut pending: Vec<Value> = Vec::new();
    for part in &message.content {
        match part {
            ContentPart::ToolCall { .. } => {
                flush_message(input, &mut pending, message.role, message.phase);
                push_tool_call(input, part, item_metadata);
            }
            ContentPart::ToolResult { .. } => {
                flush_message(input, &mut pending, message.role, message.phase);
                push_tool_result(input, part);
            }
            ContentPart::Reasoning { .. } => {
                if let ContentPart::Reasoning {
                    encrypted_content: Some(_),
                    ..
                } = part
                {
                    flush_message(input, &mut pending, message.role, message.phase);
                    push_reasoning(input, part);
                } else {
                    let text = match part {
                        ContentPart::Reasoning {
                            payload, summary, ..
                        } => summary
                            .clone()
                            .or_else(|| payload.as_str().map(str::to_owned)),
                        _ => None,
                    };
                    if text.is_some_and(|text| !text.is_empty()) {
                        flush_message(input, &mut pending, message.role, message.phase);
                        push_reasoning(input, part);
                    }
                }
            }
            other => {
                if let Some(block) = responses_content_block(other, is_assistant) {
                    pending.push(block);
                }
            }
        }
    }
    flush_message(input, &mut pending, message.role, message.phase);
}

fn projected_reasoning(request: &CanonicalRequest) -> Option<Value> {
    let reasoning = request.reasoning.as_ref()?;
    let mut projected = Map::new();
    if let Some(requested) = reasoning_effort_from_intent(Some(reasoning)) {
        let supported =
            resolve_supported_reasoning_efforts(Some(&request.model), WireFamily::Responses, None);
        if let Some(effort) = clamp_reasoning_effort(Some(requested), &supported) {
            projected.insert("effort".into(), json!(effort.as_str()));
        }
    }
    if let Some(mode) = reasoning.mode {
        projected.insert("mode".into(), json!(mode));
    }
    if let Some(context) = reasoning.context {
        projected.insert("context".into(), json!(context));
    }
    if let Some(summary_mode) = reasoning.summary_mode {
        projected.insert("summary".into(), json!(summary_mode));
    } else if let Some(summary) = &reasoning.summary {
        projected.insert("summary".into(), json!(summary));
    }
    if projected.is_empty() {
        None
    } else {
        Some(Value::Object(projected))
    }
}

fn project_text(payload: &mut Map<String, Value>, request: &CanonicalRequest) {
    let verbosity = resolve_output_verbosity(Some(&request.generation_controls));
    let format = request.response_format.as_ref();
    if format.is_none() && verbosity.is_none() {
        return;
    }
    let mut text = payload
        .get("text")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(verbosity) = verbosity {
        text.insert("verbosity".into(), Value::String(verbosity));
    }
    match format {
        Some(ResponseFormat::JsonObject { .. }) => {
            text.insert("format".into(), json!({"type": "json_object"}));
        }
        Some(ResponseFormat::JsonSchema {
            schema,
            strict,
            name,
            description,
            ..
        }) => {
            let mut projected = Map::new();
            projected.insert("type".into(), json!("json_schema"));
            if let Some(name) = name {
                projected.insert("name".into(), json!(name));
            }
            projected.insert("schema".into(), schema.clone());
            if let Some(strict) = strict {
                projected.insert("strict".into(), json!(strict));
            }
            if let Some(description) = description {
                projected.insert("description".into(), json!(description));
            }
            text.insert("format".into(), Value::Object(projected));
        }
        None => {}
    }
    payload.insert("text".into(), Value::Object(text));
}

fn picked_controls(request: &CanonicalRequest) -> Map<String, Value> {
    let normalized = normalize_wire_max_tokens(&request.generation_controls);
    let mut picked = Map::new();
    if let Some(temperature) = normalized.temperature {
        picked.insert("temperature".into(), json!(temperature));
    }
    if let Some(top_p) = normalized.top_p {
        picked.insert("top_p".into(), json!(top_p));
    }
    if let Some(parallel_tool_calls) = normalized.parallel_tool_calls {
        picked.insert("parallel_tool_calls".into(), json!(parallel_tool_calls));
    }
    if let Some(service_tier) = &normalized.service_tier {
        picked.insert("service_tier".into(), json!(service_tier));
    }
    if let Some(requested) = normalized.max_output_tokens {
        let bounded = resolve_wire_max_tokens("responses", Some(requested), false, false);
        if let Some(bounded) = bounded {
            picked.insert("max_output_tokens".into(), json!(bounded));
        }
    }
    picked
}

/// Encodes a canonical request as an OpenAI Responses body.
pub fn canonical_to_responses_payload(
    request: &CanonicalRequest,
    options: ResponsesPayloadOptions,
) -> Value {
    let mut input: Vec<Value> = Vec::new();
    let item_metadata = request
        .generation_controls
        .extensions
        .get("extension:responses.item_metadata");

    for (parts, role) in [
        (request.system.as_ref(), "system"),
        (request.instructions.as_ref(), "developer"),
    ] {
        let Some(parts) = parts else {
            continue;
        };
        if parts.is_empty() {
            continue;
        }
        let mut content: Vec<Value> = Vec::new();
        for part in parts {
            if let ContentPart::Text { text } = part {
                if !is_claude_billing_header_text(text) {
                    content.push(json!({"type": "input_text", "text": text}));
                }
            }
        }
        if !content.is_empty() {
            input.push(json!({"type": "message", "role": role, "content": content}));
        }
    }

    for message in &request.messages {
        project_message_content(message, &mut input, item_metadata);
    }

    if options.supports_prompt_caching
        && request
            .cache_hint
            .as_ref()
            .is_some_and(|hint| matches!(hint, keyla_core::CacheHint::Breakpoint { .. }))
        && cache_hint_has_breakpoints(request.cache_hint.as_ref())
    {
        mark_latest_responses_cache_breakpoint(&mut input);
    }

    let mut payload = Map::new();
    payload.insert("model".into(), json!(request.model));
    payload.insert("input".into(), Value::Array(input));
    payload.insert(
        "stream".into(),
        json!(options.stream.unwrap_or(request.stream)),
    );

    if options.supports_prompt_caching {
        if let Some(cache_key) = resolve_prompt_cache_key(Some(&request.generation_controls)) {
            payload.insert("prompt_cache_key".into(), json!(cache_key));
        }
    }

    if let Some(tools) = &request.tools {
        if !tools.is_empty() {
            payload.insert(
                "tools".into(),
                Value::Array(tools.iter().map(responses_tool).collect()),
            );
        }
    }

    if let Some(choice) = &request.tool_choice {
        apply_tool_choice(&mut payload, choice);
    }

    if let Some(conversation) = &request.conversation {
        if let Some(previous_response_id) = &conversation.previous_response_id {
            payload.insert("previous_response_id".into(), json!(previous_response_id));
        }
        if let Some(conversation_id) = &conversation.conversation_id {
            payload.insert("conversation".into(), json!(conversation_id));
        }
    }

    if let Some(metadata) = &request.metadata {
        payload.insert("metadata".into(), Value::Object(metadata.clone()));
    }

    if let Some(reasoning) = projected_reasoning(request) {
        payload.insert("reasoning".into(), reasoning);
    }

    for (key, value) in picked_controls(request) {
        payload.insert(key, value);
    }

    // Responses top-level params carried as `extension:responses.<field>` and
    // forwarded verbatim. Fields with a canonical slot (prompt_cache_key,
    // previous_response_id, conversation, metadata, stream, reasoning) and
    // nested artifacts (verbosity, read under `text` below) are absent because
    // they are re-emitted from `CanonicalRequest` instead.
    const RESPONSES_PASSTHROUGH: [&str; 13] = [
        "store",
        "background",
        "truncation",
        "max_tool_calls",
        "include",
        "prompt_cache_retention",
        "stream_options",
        "top_logprobs",
        "moderation",
        "safety_identifier",
        "prompt",
        "context_management",
        "user",
    ];
    for field in RESPONSES_PASSTHROUGH {
        let scoped = format!("extension:responses.{field}");
        let bare = format!("extension:{field}");
        let value = request
            .generation_controls
            .extensions
            .get(&scoped)
            .or_else(|| {
                // A bare `extension:<field>` fallback exists because the Chat
                // parser files shared top-level params (`store`, `user`,
                // `moderation`, …) under the bare key. `context_management`
                // does not have the same shape on every wire, so only the
                // Responses-spelled key may supply it.
                if field == "context_management" {
                    None
                } else {
                    request.generation_controls.extensions.get(&bare)
                }
            });
        if let Some(value) = value {
            payload.insert(field.into(), value.clone());
        }
    }

    if let Some(store) = options.store {
        payload.insert("store".into(), json!(store));
    }

    project_text(&mut payload, request);

    Value::Object(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{
        AllowedToolsMode, CallKind, CanonicalMessage, ConversationState, ReasoningEffort,
        ReasoningIntent, SourceSurface, SummaryMode,
    };
    use serde_json::json;

    fn request() -> CanonicalRequest {
        CanonicalRequest {
            model: "gpt-5".into(),
            system: Some(vec![ContentPart::Text {
                text: "be nice".into(),
            }]),
            instructions: Some(vec![ContentPart::Text {
                text: "be terse".into(),
            }]),
            messages: vec![
                CanonicalMessage {
                    role: Role::User,
                    content: vec![ContentPart::Text { text: "hi".into() }],
                    phase: None,
                },
                CanonicalMessage {
                    role: Role::Assistant,
                    content: vec![
                        ContentPart::Text {
                            text: "hello".into(),
                        },
                        ContentPart::ToolCall {
                            call_id: "call_1".into(),
                            name: "read".into(),
                            arguments: json!({"path": "a"}),
                            index: None,
                            item_id: Some("fc_1".into()),
                            call_kind: None,
                        },
                    ],
                    phase: None,
                },
                CanonicalMessage {
                    role: Role::Tool,
                    content: vec![ContentPart::ToolResult {
                        call_id: "call_1".into(),
                        content: ToolResultContent::Text("done".into()),
                        is_error: None,
                        call_kind: None,
                        item_id: None,
                    }],
                    phase: None,
                },
            ],
            tools: Some(vec![ToolDefinition {
                name: "read".into(),
                description: Some("Read a file".into()),
                json_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
                strict: Some(true),
                eager_input_streaming: None,
                defer_loading: None,
                input_examples: None,
                tool_type: Some(ToolType::Function),
                native_type: None,
                allowed_callers: None,
            }]),
            tool_choice: Some(ToolChoice::AllowedTools {
                mode: AllowedToolsMode::Required,
                names: vec!["read".into()],
            }),
            generation_controls: keyla_core::GenerationControls {
                temperature: Some(0.5),
                max_output_tokens: Some(8),
                parallel_tool_calls: Some(true),
                service_tier: Some("priority".into()),
                ..Default::default()
            },
            reasoning: Some(ReasoningIntent {
                effort: Some(ReasoningEffort::High),
                summary_mode: Some(SummaryMode::Detailed),
                ..Default::default()
            }),
            response_format: Some(ResponseFormat::JsonSchema {
                kind: keyla_core::JsonSchemaMarker::JsonSchema,
                schema: json!({"type": "object"}),
                strict: Some(true),
                name: Some("answer".into()),
                description: None,
            }),
            cache_hint: Some(keyla_core::CacheHint::StablePrefix),
            conversation: Some(ConversationState {
                previous_response_id: Some("resp_1".into()),
                conversation_id: Some("conv_1".into()),
                ..Default::default()
            }),
            metadata: None,
            provider_options: None,
            session_id: None,
            thread_id: None,
            window_id: None,
            turn_id: None,
            parent_turn_id: None,
            conversation_id: None,
            residency: None,
            stream: true,
            source_surface: SourceSurface::Responses,
        }
    }

    #[test]
    fn projects_items_tools_format_reasoning_and_limits() {
        let payload =
            canonical_to_responses_payload(&request(), ResponsesPayloadOptions::default());
        assert_eq!(payload["model"], "gpt-5");
        assert_eq!(payload["stream"], true);
        assert_eq!(
            payload["input"][0],
            json!({"type": "message", "role": "system", "content": [{"type": "input_text", "text": "be nice"}]})
        );
        assert_eq!(payload["input"][1]["role"], "developer");
        assert_eq!(payload["input"][2]["role"], "user");
        let assistant = &payload["input"][3];
        assert_eq!(assistant["content"][0]["type"], "output_text");
        assert_eq!(payload["input"][4]["type"], "function_call");
        assert_eq!(payload["input"][4]["arguments"], "{\"path\":\"a\"}");
        assert_eq!(payload["input"][5]["type"], "function_call_output");
        assert_eq!(payload["input"][5]["output"], "done");
        assert_eq!(payload["tools"][0]["type"], "function");
        assert_eq!(payload["tools"][0]["strict"], true);
        assert_eq!(
            payload["tool_choice"],
            json!({"type": "allowed_tools", "mode": "required", "tools": [{"type": "function", "name": "read"}]})
        );
        assert_eq!(payload["previous_response_id"], "resp_1");
        assert_eq!(payload["conversation"], "conv_1");
        assert_eq!(payload["reasoning"]["effort"], "high");
        assert_eq!(payload["reasoning"]["summary"], "detailed");
        assert_eq!(payload["temperature"], 0.5);
        assert_eq!(payload["parallel_tool_calls"], true);
        assert_eq!(payload["service_tier"], "priority");
        // The Responses wire clamps to a 16-token floor.
        assert_eq!(payload["max_output_tokens"], 16);
        assert_eq!(payload["text"]["format"]["type"], "json_schema");
        assert_eq!(payload["text"]["format"]["name"], "answer");
    }

    #[test]
    fn options_override_stream_and_store() {
        let payload = canonical_to_responses_payload(
            &request(),
            ResponsesPayloadOptions::default()
                .with_stream(false)
                .with_store(true),
        );
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["store"], true);
    }

    #[test]
    fn computer_calls_keep_actions_and_safety_checks() {
        let mut request = request();
        request.system = None;
        request.instructions = None;
        request.messages = vec![CanonicalMessage {
            role: Role::Assistant,
            content: vec![ContentPart::ToolCall {
                call_id: "call_c".into(),
                name: "computer".into(),
                arguments: json!({"actions": [{"type": "click", "x": 1}]}),
                index: None,
                item_id: None,
                call_kind: Some(CallKind::Computer),
            }],
            phase: Some(AssistantItemPhase::Commentary),
        }];
        request.tool_choice = None;
        request.tools = None;
        request.generation_controls.extensions.insert(
            "extension:responses.item_metadata".into(),
            json!([{"type": "computer_call", "call_id": "call_c", "pending_safety_checks": [{"id": "s1"}]}]),
        );
        let payload = canonical_to_responses_payload(&request, ResponsesPayloadOptions::default());
        assert_eq!(payload["input"][0]["type"], "computer_call");
        assert_eq!(payload["input"][0]["actions"][0]["type"], "click");
        assert_eq!(payload["input"][0]["pending_safety_checks"][0]["id"], "s1");
        assert_eq!(payload["input"][0]["status"], "completed");
    }

    #[test]
    fn reasoning_replay_and_encrypted_items_are_projected() {
        let mut request = request();
        request.system = None;
        request.instructions = None;
        request.messages = vec![CanonicalMessage {
            role: Role::Assistant,
            content: vec![
                ContentPart::Reasoning {
                    payload: serde_json::Value::Null,
                    opaque: Some(true),
                    summary: Some("thought".into()),
                    summary_index: None,
                    signature: None,
                    encrypted_content: Some("cipher".into()),
                },
                ContentPart::Reasoning {
                    payload: json!("readable"),
                    opaque: None,
                    summary: None,
                    summary_index: None,
                    signature: None,
                    encrypted_content: None,
                },
            ],
            phase: None,
        }];
        let payload = canonical_to_responses_payload(&request, ResponsesPayloadOptions::default());
        assert_eq!(payload["input"][0]["type"], "reasoning");
        assert_eq!(payload["input"][0]["encrypted_content"], "cipher");
        assert_eq!(
            payload["input"][1]["summary"][0],
            json!({"type": "summary_text", "text": "readable"})
        );
    }
}
