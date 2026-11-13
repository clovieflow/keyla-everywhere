//! Tool-definition, tool-choice, reasoning, and response-format parsing per
//! wire dialect. Port of `src/transport/surface/dialects.ts`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use keyla_core::{
    AllowedToolsMode, ReasoningContext, ReasoningEffort, ReasoningIntent, ReasoningMode,
    ResponseFormat, SummaryMode, ThinkingType, ToolCaller, ToolChoice, ToolDefinition, ToolType,
};
use serde_json::{Map, Value};

use crate::primitives::{
    complete_required_schema, is_record, read_boolean, read_number, read_string,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolDialect {
    Chat,
    Responses,
    Messages,
}

/// Parses a tool definition from one wire dialect.
pub fn parse_tool_definition(value: &Value, dialect: ToolDialect) -> Option<ToolDefinition> {
    let item = value.as_object()?;
    if dialect == ToolDialect::Messages {
        if let Some(Value::Object(tool)) = item.get("tool") {
            return parse_tool_object(tool, dialect);
        }
        return parse_tool_object(item, dialect);
    }
    parse_tool_object(item, dialect)
}

fn parse_tool_object(item: &Map<String, Value>, dialect: ToolDialect) -> Option<ToolDefinition> {
    let mut name = read_string(item, "name").map(str::to_owned);
    if name.is_none() && dialect == ToolDialect::Responses {
        if let Some(kind) = read_string(item, "type") {
            name = Some(kind.to_owned());
        }
    }
    let chat_wrapper = if dialect == ToolDialect::Chat {
        item.get("function")
            .and_then(Value::as_object)
            .or_else(|| item.get("custom").and_then(Value::as_object))
    } else {
        None
    };
    if let Some(wrapper) = chat_wrapper {
        if let Some(wrapper_name) = read_string(wrapper, "name") {
            name = Some(wrapper_name.to_owned());
        }
    }
    // A hosted tool may be declared as a bare `{"type": "web_search"}`.
    let declared_type = read_string(item, "type");
    if name.is_none() {
        name = declared_type.map(str::to_owned);
    }
    let name = name?;

    let mut description = read_string(item, "description").map(str::to_owned);
    if let Some(wrapper) = chat_wrapper {
        if let Some(wrapper_description) = read_string(wrapper, "description") {
            description = Some(wrapper_description.to_owned());
        }
    }

    let schema = match dialect {
        ToolDialect::Chat => {
            if let Some(custom) = item.get("custom").and_then(Value::as_object) {
                custom
                    .get("format")
                    .or_else(|| custom.get("jsonSchema"))
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new()))
            } else {
                item.get("function")
                    .and_then(Value::as_object)
                    .and_then(|function| {
                        function
                            .get("parameters")
                            .or_else(|| function.get("jsonSchema"))
                    })
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new()))
            }
        }
        ToolDialect::Responses => item
            .get("input_schema")
            .or_else(|| item.get("parameters"))
            .cloned()
            .unwrap_or_else(|| Value::Object(item.clone())),
        ToolDialect::Messages => item
            .get("input_schema")
            .or_else(|| item.get("inputSchema"))
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new())),
    };

    let strict = chat_wrapper
        .and_then(|wrapper| read_boolean(wrapper, "strict"))
        .or_else(|| read_boolean(item, "strict"));

    let json_schema = if is_record(&schema) {
        complete_required_schema(&schema)
    } else {
        Value::Object(Map::new())
    };
    let mut definition = ToolDefinition {
        name,
        description,
        json_schema,
        strict,
        eager_input_streaming: None,
        defer_loading: None,
        input_examples: None,
        tool_type: None,
        native_type: None,
        allowed_callers: None,
    };

    if let Some(Value::Array(examples)) = item.get("input_examples") {
        definition.input_examples = Some(
            examples
                .iter()
                .filter_map(|example| example.as_object().cloned())
                .collect(),
        );
    }
    if let Some(value) = item.get("defer_loading").and_then(Value::as_bool) {
        definition.defer_loading = Some(value);
    }
    if let Some(Value::Array(callers)) = item.get("allowed_callers") {
        definition.allowed_callers = Some(parse_callers(callers));
    }
    if dialect == ToolDialect::Chat {
        if let Some(function) = item.get("function").and_then(Value::as_object) {
            if definition.input_examples.is_none() {
                if let Some(Value::Array(examples)) = function.get("input_examples") {
                    definition.input_examples = Some(
                        examples
                            .iter()
                            .filter_map(|example| example.as_object().cloned())
                            .collect(),
                    );
                }
            }
            if definition.defer_loading.is_none() {
                definition.defer_loading = function.get("defer_loading").and_then(Value::as_bool);
            }
            if definition.allowed_callers.is_none() {
                if let Some(Value::Array(callers)) = function.get("allowed_callers") {
                    definition.allowed_callers = Some(parse_callers(callers));
                }
            }
        }
    }

    if let Some(kind) = declared_type {
        if dialect == ToolDialect::Chat && kind == "custom" {
            definition.tool_type = Some(ToolType::Custom);
        } else if kind != "function" && kind != "tool" {
            definition.tool_type = Some(classify_native_tool_type(kind));
        } else {
            definition.tool_type = Some(ToolType::Function);
        }
        if kind.starts_with("web_search_") {
            definition.native_type = Some(kind.to_owned());
        }
    }
    Some(definition)
}

fn parse_callers(callers: &[Value]) -> Vec<ToolCaller> {
    callers
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|caller| match caller {
            "direct" => Some(ToolCaller::Direct),
            "programmatic" => Some(ToolCaller::Programmatic),
            _ => None,
        })
        .collect()
}

fn classify_native_tool_type(kind: &str) -> ToolType {
    match kind {
        "web_search"
        | "web_search_preview"
        | "web_search_preview_2025_03_11"
        | "web_search_options" => ToolType::WebSearch,
        "file_search" => ToolType::FileSearch,
        "code_interpreter" | "code_execution" => ToolType::CodeExecution,
        "computer_use_preview" => ToolType::ComputerUse,
        "mcp" => ToolType::Mcp,
        _ => ToolType::Provider,
    }
}

pub const CANONICAL_REASONING_EFFORTS: [&str; 7] =
    ["none", "minimal", "low", "medium", "high", "xhigh", "max"];

static CANONICAL_REASONING_EFFORT_SET: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| CANONICAL_REASONING_EFFORTS.into_iter().collect());

pub fn is_reasoning_effort(value: &str) -> Option<ReasoningEffort> {
    if !CANONICAL_REASONING_EFFORT_SET.contains(value) {
        return None;
    }
    Some(match value {
        "none" => ReasoningEffort::None,
        "minimal" => ReasoningEffort::Minimal,
        "low" => ReasoningEffort::Low,
        "medium" => ReasoningEffort::Medium,
        "high" => ReasoningEffort::High,
        "xhigh" => ReasoningEffort::Xhigh,
        _ => ReasoningEffort::Max,
    })
}

pub static SERVICE_TIERS: [&str; 6] = ["auto", "default", "flex", "scale", "priority", "fast"];

static SERVICE_TIER_SET: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| SERVICE_TIERS.into_iter().collect());

pub fn is_service_tier(value: &str) -> bool {
    SERVICE_TIER_SET.contains(value)
}

/// Dialect-unified tool_choice parser. Chat/Responses are lenient (unsupported
/// shapes yield `None`); Messages throws on an unsupported shape.
pub fn parse_tool_choice(
    value: &Value,
    dialect: ToolDialect,
) -> Result<Option<ToolChoice>, keyla_core::GatewayError> {
    if value.is_null() {
        return Ok(None);
    }
    if let Some(simple) = value.as_str() {
        return Ok(match simple {
            "auto" => Some(ToolChoice::Auto),
            "none" => Some(ToolChoice::None),
            "required" => Some(ToolChoice::Required),
            _ => None,
        });
    }
    let Some(map) = value.as_object() else {
        return if dialect == ToolDialect::Messages {
            Err(messages_error(
                "Messages tool_choice must be a string or object",
            ))
        } else {
            Ok(None)
        };
    };
    let kind = read_string(map, "type").unwrap_or_default();
    match kind {
        "auto" => return Ok(Some(ToolChoice::Auto)),
        "none" => return Ok(Some(ToolChoice::None)),
        "any" => return Ok(Some(ToolChoice::Required)),
        _ => {}
    }
    if kind == "allowed_tools" {
        if let Some(Value::Array(tools)) = map.get("tools") {
            let names = tools
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|entry| {
                    let holder = entry
                        .get("function")
                        .and_then(Value::as_object)
                        .unwrap_or(entry);
                    read_string(holder, "name").map(str::to_owned)
                })
                .collect();
            let mode = if read_string(map, "mode") == Some("required") {
                AllowedToolsMode::Required
            } else {
                AllowedToolsMode::Auto
            };
            return Ok(Some(ToolChoice::AllowedTools { mode, names }));
        }
    }
    if kind == "custom" {
        let holder = map.get("custom").and_then(Value::as_object).unwrap_or(map);
        if let Some(name) = read_string(holder, "name") {
            return Ok(Some(ToolChoice::Custom {
                name: name.to_owned(),
            }));
        }
    }
    if kind == "function" || kind == "tool" {
        let holder = map
            .get("function")
            .and_then(Value::as_object)
            .unwrap_or(map);
        if let Some(name) = read_string(holder, "name") {
            return Ok(Some(ToolChoice::Tool {
                name: name.to_owned(),
            }));
        }
    }
    if dialect == ToolDialect::Messages {
        return Err(messages_error(
            "Messages tool_choice has an unsupported type",
        ));
    }
    Ok(None)
}

fn messages_error(message: &str) -> keyla_core::GatewayError {
    keyla_core::GatewayError::new(
        keyla_core::GatewayErrorCode::InvalidRequest,
        400,
        message,
        Map::new(),
    )
}

/// Normalized reasoning parser: nested `reasoning` object plus top-level
/// `reasoning_effort`/`reasoning_level`/`summary_mode` scalars.
pub fn parse_reasoning_intent(body: &Map<String, Value>) -> Option<ReasoningIntent> {
    let reasoning_object = body.get("reasoning").and_then(Value::as_object);
    let raw_effort = match reasoning_object {
        Some(object) => read_string(object, "effort"),
        None => {
            read_string(body, "reasoning_effort").or_else(|| read_string(body, "reasoning_level"))
        }
    };
    let raw_summary_mode = match reasoning_object {
        Some(object) => {
            read_string(object, "summary_mode").or_else(|| read_string(object, "summary"))
        }
        None => read_string(body, "summary_mode"),
    };
    let raw_summary_text = reasoning_object.and_then(|object| read_string(object, "summary"));

    let mut reasoning = ReasoningIntent::default();
    let mut present = false;
    if let Some(effort) = raw_effort.and_then(is_reasoning_effort) {
        reasoning.effort = Some(effort);
        present = true;
    }
    if let Some(object) = reasoning_object {
        if let Some(mode) = read_string(object, "mode") {
            if mode == "standard" || mode == "pro" {
                reasoning.mode = Some(if mode == "pro" {
                    ReasoningMode::Pro
                } else {
                    ReasoningMode::Standard
                });
                present = true;
            }
        }
        if let Some(context) = read_string(object, "context") {
            match context {
                "current_turn" => {
                    reasoning.context = Some(ReasoningContext::CurrentTurn);
                    present = true;
                }
                "all_turns" => {
                    reasoning.context = Some(ReasoningContext::AllTurns);
                    present = true;
                }
                _ => {}
            }
        }
        if let Some(thinking_type) = read_string(object, "thinking_type") {
            let parsed = match thinking_type {
                "enabled" => Some(ThinkingType::Enabled),
                "adaptive" => Some(ThinkingType::Adaptive),
                "disabled" => Some(ThinkingType::Disabled),
                _ => None,
            };
            if let Some(parsed) = parsed {
                reasoning.thinking_type = Some(parsed);
                present = true;
            }
        }
        if let Some(budget) = read_number(object, "budget_tokens") {
            reasoning.budget_tokens = Some(budget as i64);
            present = true;
        }
    }
    if let Some(mode) = raw_summary_mode {
        let parsed = match mode {
            "auto" => Some(SummaryMode::Auto),
            "concise" => Some(SummaryMode::Concise),
            "detailed" => Some(SummaryMode::Detailed),
            _ => None,
        };
        if let Some(parsed) = parsed {
            reasoning.summary_mode = Some(parsed);
            present = true;
        }
    }
    if let Some(text) = raw_summary_text {
        if !matches!(text, "auto" | "concise" | "detailed") {
            reasoning.summary = Some(text.to_owned());
            present = true;
        }
    }
    present.then_some(reasoning)
}

/// Normalized response_format parser; supports `body.response_format` and
/// Responses `body.text.format`.
pub fn parse_response_format(value: &Value) -> Option<ResponseFormat> {
    let map = value.as_object()?;
    match read_string(map, "type")? {
        "json_object" => Some(ResponseFormat::JsonObject {
            kind: keyla_core::JsonObjectMarker::JsonObject,
        }),
        "json_schema" => {
            let schema_object = map
                .get("json_schema")
                .and_then(Value::as_object)
                .unwrap_or(map);
            let schema = schema_object
                .get("schema")
                .or_else(|| schema_object.get("json_schema"))?
                .clone();
            Some(ResponseFormat::JsonSchema {
                kind: keyla_core::JsonSchemaMarker::JsonSchema,
                schema,
                strict: read_boolean(schema_object, "strict"),
                name: read_string(schema_object, "name").map(str::to_owned),
                description: read_string(schema_object, "description").map(str::to_owned),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_tool_definition_unwraps_function_envelope() {
        let tool = json!({
            "type": "function",
            "function": {
                "name": "read",
                "description": "Read a file",
                "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}
            }
        });
        let parsed = parse_tool_definition(&tool, ToolDialect::Chat).unwrap();
        assert_eq!(parsed.name, "read");
        assert_eq!(parsed.description.as_deref(), Some("Read a file"));
        assert_eq!(parsed.tool_type, Some(ToolType::Function));
        assert_eq!(parsed.json_schema["required"], json!(["path"]));
    }

    #[test]
    fn hosted_tool_takes_its_name_from_type() {
        let tool = json!({"type": "web_search"});
        let parsed = parse_tool_definition(&tool, ToolDialect::Chat).unwrap();
        assert_eq!(parsed.name, "web_search");
        assert_eq!(parsed.tool_type, Some(ToolType::WebSearch));
    }

    #[test]
    fn messages_tool_unwraps_tool_envelope() {
        let tool = json!({
            "type": "tool",
            "tool": {"name": "grep", "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}
        });
        let parsed = parse_tool_definition(&tool, ToolDialect::Messages).unwrap();
        assert_eq!(parsed.name, "grep");
        assert_eq!(parsed.json_schema["required"], json!(["q"]));
    }

    #[test]
    fn tool_choice_accepts_all_supported_shapes() {
        assert_eq!(
            parse_tool_choice(&json!("auto"), ToolDialect::Chat).unwrap(),
            Some(ToolChoice::Auto)
        );
        assert_eq!(
            parse_tool_choice(&json!({"type": "any"}), ToolDialect::Messages).unwrap(),
            Some(ToolChoice::Required)
        );
        assert_eq!(
            parse_tool_choice(
                &json!({"type": "function", "function": {"name": "read"}}),
                ToolDialect::Chat
            )
            .unwrap(),
            Some(ToolChoice::Tool {
                name: "read".into()
            })
        );
        let allowed = parse_tool_choice(
            &json!({"type":"allowed_tools","mode":"required","tools":[{"type":"function","function":{"name":"a"}},{"name":"b"}]}),
            ToolDialect::Responses,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            allowed,
            ToolChoice::AllowedTools {
                mode: AllowedToolsMode::Required,
                names: vec!["a".into(), "b".into()]
            }
        );
        assert!(parse_tool_choice(&json!({"type": "weird"}), ToolDialect::Messages).is_err());
    }

    #[test]
    fn reasoning_intent_merges_nested_and_top_level_fields() {
        let body = json!({
            "reasoning": {"effort": "high", "mode": "pro", "budget_tokens": 2048, "summary": "auto"},
            "summary_mode": "detailed"
        });
        let parsed = parse_reasoning_intent(body.as_object().unwrap()).unwrap();
        assert_eq!(parsed.effort, Some(ReasoningEffort::High));
        assert_eq!(parsed.mode, Some(ReasoningMode::Pro));
        assert_eq!(parsed.budget_tokens, Some(2048));
        assert_eq!(parsed.summary_mode, Some(SummaryMode::Auto));
        assert!(parsed.summary.is_none());

        let body = json!({"reasoning": {"summary": "done"}});
        let parsed = parse_reasoning_intent(body.as_object().unwrap()).unwrap();
        assert_eq!(parsed.summary.as_deref(), Some("done"));
    }

    #[test]
    fn response_format_requires_a_schema_for_json_schema() {
        assert!(parse_response_format(&json!({"type": "json_object"})).is_some());
        assert!(
            parse_response_format(&json!({"type": "json_schema", "json_schema": {"name": "x"}}))
                .is_none()
        );
        let parsed = parse_response_format(
            &json!({"type":"json_schema","json_schema":{"name":"x","schema":{"type":"object"}}}),
        )
        .unwrap();
        assert!(matches!(parsed, ResponseFormat::JsonSchema { .. }));
    }
}
