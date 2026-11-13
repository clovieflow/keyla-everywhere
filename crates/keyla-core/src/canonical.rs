//! Canonical vocabulary shared by every wire family.
//!
//! Direct port of `src/transport/canonical-model.ts`. The canonical request is
//! the only shape surface adapters and provider adapters exchange, so the
//! serde field names here are the internal contract between them.

use std::collections::BTreeMap;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

/// Wire protocol families, as a runtime tuple.
pub const WIRE_FAMILIES: [&str; 3] = ["chat", "responses", "messages"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WireFamily {
    Chat,
    Responses,
    Messages,
}

impl WireFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
            Self::Messages => "messages",
        }
    }
}

/// Provider service kinds.
pub const SERVICE_KINDS: [&str; 3] = ["llm", "systemone", "websearch"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Llm,
    Systemone,
    Websearch,
}

impl ServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Llm => "llm",
            Self::Systemone => "systemone",
            Self::Websearch => "websearch",
        }
    }
}

/// Canonical reasoning efforts.
pub const REASONING_EFFORTS: [&str; 7] =
    ["none", "minimal", "low", "medium", "high", "xhigh", "max"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

impl ReasoningEffort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }
}

/// Public request surface from which a canonical request originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceSurface {
    Chat,
    Responses,
    Messages,
    Completion,
}

impl SourceSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
            Self::Messages => "messages",
            Self::Completion => "completion",
        }
    }
}

/// Roles that can occur in an ordered canonical conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    Developer,
    User,
    Assistant,
    Tool,
}

/// Case-insensitive header lookup over a plain string map.
pub fn get_header<'a>(
    headers: Option<&'a BTreeMap<String, String>>,
    name: &str,
) -> Option<&'a str> {
    let headers = headers?;
    if let Some(value) = headers.get(name) {
        return Some(value.as_str());
    }
    let lower = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(key, _)| key.to_ascii_lowercase() == lower)
        .map(|(_, value)| value.as_str())
}

/// Canonical cache intent; provider-specific cache mechanics belong to adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheHint {
    StablePrefix,
    Breakpoint { list: Vec<u32> },
}

impl Serialize for CacheHint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::StablePrefix => serializer.serialize_str("stable_prefix"),
            Self::Breakpoint { list } => {
                let mut map = Map::new();
                map.insert("kind".into(), json!("breakpoint"));
                map.insert("list".into(), json!(list));
                Value::Object(map).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for CacheHint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(_) => Ok(Self::StablePrefix),
            Value::Object(map) => {
                let list = map
                    .get("list")
                    .and_then(Value::as_array)
                    .map(|entries| {
                        entries
                            .iter()
                            .filter_map(Value::as_u64)
                            .map(|entry| entry as u32)
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(Self::Breakpoint { list })
            }
            other => Err(de::Error::custom(format!(
                "cache_hint must be \"stable_prefix\" or a breakpoint object, got {other}"
            ))),
        }
    }
}

/// Provider-native tool family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolType {
    Function,
    Custom,
    WebSearch,
    FileSearch,
    CodeExecution,
    ComputerUse,
    Mcp,
    Provider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCaller {
    Direct,
    Programmatic,
}

/// A provider-neutral tool declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema (or an opaque schema representation) for tool arguments.
    #[serde(rename = "jsonSchema")]
    pub json_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    /// Provider-specific streaming hint: begin executing tool input as it
    /// streams in rather than waiting for the complete arguments blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eager_input_streaming: Option<bool>,
    /// Provider-specific hint deferring tool definition loading until first
    /// invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defer_loading: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_examples: Option<Vec<Map<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_type: Option<ToolType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_callers: Option<Vec<ToolCaller>>,
}

/// Selection policy for model tool invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Tool {
        name: String,
    },
    Custom {
        name: String,
    },
    AllowedTools {
        mode: AllowedToolsMode,
        names: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowedToolsMode {
    Auto,
    Required,
}

impl Serialize for ToolChoice {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::None => serializer.serialize_str("none"),
            Self::Required => serializer.serialize_str("required"),
            Self::Tool { name } => json!({ "type": "tool", "name": name }).serialize(serializer),
            Self::Custom { name } => {
                json!({ "type": "custom", "name": name }).serialize(serializer)
            }
            Self::AllowedTools { mode, names } => json!({
                "type": "allowed_tools",
                "mode": mode,
                "names": names,
            })
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ToolChoice {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match &value {
            Value::String(simple) => match simple.as_str() {
                "auto" => Ok(Self::Auto),
                "none" => Ok(Self::None),
                "required" => Ok(Self::Required),
                other => Err(de::Error::custom(format!(
                    "unknown tool_choice string {other}"
                ))),
            },
            Value::Object(map) => {
                let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
                let name = || {
                    map.get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| de::Error::missing_field("name"))
                };
                match kind {
                    "tool" => Ok(Self::Tool { name: name()? }),
                    "custom" => Ok(Self::Custom { name: name()? }),
                    "allowed_tools" => {
                        let mode = map.get("mode").and_then(Value::as_str).unwrap_or("auto");
                        let mode = if mode == "required" {
                            AllowedToolsMode::Required
                        } else {
                            AllowedToolsMode::Auto
                        };
                        let names = map
                            .get("names")
                            .and_then(Value::as_array)
                            .map(|entries| {
                                entries
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default();
                        Ok(Self::AllowedTools { mode, names })
                    }
                    other => Err(de::Error::custom(format!(
                        "unknown tool_choice type {other}"
                    ))),
                }
            }
            other => Err(de::Error::custom(format!(
                "tool_choice must be a string or object, got {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StopSequence {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verbosity {
    Low,
    Medium,
    High,
}

/// Common generation controls normalized from each wire surface.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GenerationControls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopSequence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_logprobs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbosity: Option<Verbosity>,
    /// Scoped provider controls remain extensions rather than canonical fields.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningMode {
    Standard,
    Pro,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningContext {
    CurrentTurn,
    AllTurns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SummaryMode {
    Auto,
    Concise,
    Detailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThinkingType {
    Enabled,
    Adaptive,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThinkingDisplay {
    Summarized,
    Omitted,
    Updates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefixMismatchBehavior {
    DropBlock,
    Error,
}

/// Model reasoning request intent, including opaque summary handling.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReasoningIntent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<ReasoningEffort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ReasoningMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ReasoningContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_mode: Option<SummaryMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_type: Option<ThinkingType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<i64>,
    /// `output_config.task_budget`, distinct from the token budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_budget: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<ThinkingDisplay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_mismatch_behavior: Option<PrefixMismatchBehavior>,
    /// Provider-native reasoning state, preserved opaquely for replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<String>,
}

/// Structured-output response format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseFormat {
    JsonObject {
        #[serde(rename = "type")]
        kind: JsonObjectMarker,
    },
    JsonSchema {
        #[serde(rename = "type")]
        kind: JsonSchemaMarker,
        schema: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonObjectMarker {
    JsonObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonSchemaMarker {
    JsonSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantItemPhase {
    Commentary,
    FinalAnswer,
}

/// An ordered canonical message and its ordered content parts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMessage {
    pub role: Role,
    pub content: Vec<ContentPart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<AssistantItemPhase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Function,
    Custom,
    Computer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentSourceType {
    Base64,
    Url,
    File,
    Text,
}

/// Canonical content vocabulary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum ContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { payload: Value },
    #[serde(rename = "file")]
    File {
        data: Value,
        media_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        filename: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    #[serde(rename = "audio")]
    Audio { data: Value, media_type: String },
    #[serde(rename = "document")]
    Document {
        data: Value,
        media_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        citations: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_type: Option<DocumentSourceType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file_id: Option<String>,
    },
    #[serde(rename = "refusal")]
    Refusal { text: String },
    #[serde(rename = "toolCall")]
    ToolCall {
        call_id: String,
        name: String,
        /// Arguments stay opaque so adapters own parsing and repair policy.
        arguments: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_kind: Option<CallKind>,
    },
    #[serde(rename = "toolResult")]
    ToolResult {
        call_id: String,
        content: ToolResultContent,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_kind: Option<CallKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
    },
    #[serde(rename = "reasoning")]
    Reasoning {
        /// Opaque payloads are never decrypted or converted to answer text.
        payload: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        opaque: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        summary: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        summary_index: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encrypted_content: Option<String>,
    },
    #[serde(rename = "extension")]
    Extension { name: String, payload: Value },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    Parts(Vec<ContentPart>),
    Text(String),
}

impl ContentPart {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Text { .. } => "text",
            Self::Image { .. } => "image",
            Self::File { .. } => "file",
            Self::Audio { .. } => "audio",
            Self::Document { .. } => "document",
            Self::Refusal { .. } => "refusal",
            Self::ToolCall { .. } => "toolCall",
            Self::ToolResult { .. } => "toolResult",
            Self::Reasoning { .. } => "reasoning",
            Self::Extension { .. } => "extension",
        }
    }
}

/// True when a turn may carry `toolResult` parts: tool answers live in `tool`
/// turns (OpenAI) or in `user` turns (Anthropic re-homes them there).
pub fn can_contain_tool_result(message: &CanonicalMessage) -> bool {
    matches!(message.role, Role::Tool | Role::User)
}

pub fn tool_result_parts(message: &CanonicalMessage) -> impl Iterator<Item = &ContentPart> {
    message
        .content
        .iter()
        .filter(|part| matches!(part, ContentPart::ToolResult { .. }))
}

pub fn tool_call_parts(message: &CanonicalMessage) -> impl Iterator<Item = &ContentPart> {
    message
        .content
        .iter()
        .filter(|part| matches!(part, ContentPart::ToolCall { .. }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TerminalState {
    Complete,
    Failed,
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalStopReason {
    Stop,
    Length,
    ToolUse,
    ContentFilter,
    Refusal,
    Error,
    Cancelled,
    PauseTurn,
}

impl CanonicalStopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Length => "length",
            Self::ToolUse => "tool_use",
            Self::ContentFilter => "content_filter",
            Self::Refusal => "refusal",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::PauseTurn => "pause_turn",
        }
    }
}

/// A reported or explicitly unavailable token count.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TokenCount {
    Number(i64),
    Unavailable,
}

impl TokenCount {
    pub fn value(self) -> Option<i64> {
        match self {
            Self::Number(value) => Some(value),
            Self::Unavailable => None,
        }
    }
}

impl From<i64> for TokenCount {
    fn from(value: i64) -> Self {
        Self::Number(value)
    }
}

impl Serialize for TokenCount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Number(value) => serializer.serialize_i64(*value),
            Self::Unavailable => serializer.serialize_str("unavailable"),
        }
    }
}

impl<'de> Deserialize<'de> for TokenCount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenCountVisitor;

        impl de::Visitor<'_> for TokenCountVisitor {
            type Value = TokenCount;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a token count number or \"unavailable\"")
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(TokenCount::Number(value))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(TokenCount::Number(value as i64))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(TokenCount::Number(value as i64))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value == "unavailable" {
                    Ok(TokenCount::Unavailable)
                } else {
                    Err(E::custom(format!("invalid token count {value}")))
                }
            }
        }

        deserializer.deserialize_any(TokenCountVisitor)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_prediction_tokens: Option<TokenCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_prediction_tokens: Option<TokenCount>,
}

/// Provider-normalized token and cost accounting without double counting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub input_tokens: i64,
    pub cached_input_tokens: TokenCount,
    pub cache_write_tokens: TokenCount,
    pub uncached_input_tokens: TokenCount,
    pub output_tokens: i64,
    pub reasoning_tokens: TokenCount,
    /// Estimated USD cost, or `None` when no price is known. `None` is not
    /// `0`: zero is a real answer, absence says the catalog had no rate.
    pub estimated_cost: Option<f64>,
    /// Provider-billed credits for this turn, when the upstream reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_used: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<TokenCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<UsageDetails>,
}

/// Provider state needed to continue a stateful or opaque conversation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConversationState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_state: Option<Map<String, Value>>,
}

/// Canonical request passed between surface and provider adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalRequest {
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<Vec<ContentPart>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<Vec<ContentPart>>,
    pub messages: Vec<CanonicalMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDefinition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    #[serde(default)]
    pub generation_controls: GenerationControls,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_hint: Option<CacheHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<ConversationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_options: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residency: Option<String>,
    pub stream: bool,
    pub source_surface: SourceSurface,
}

/// An ordered canonical stream event; sequence numbers increase monotonically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CanonicalEvent {
    #[serde(rename = "message_start")]
    MessageStart {
        sequence_number: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        system_fingerprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "response_start")]
    ResponseStart {
        sequence_number: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        system_fingerprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "content_delta")]
    ContentDelta {
        sequence_number: u64,
        content: ContentPart,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_index: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_index: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "tool_call_delta")]
    ToolCallDelta {
        sequence_number: u64,
        call_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        arguments_delta: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_index: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        sequence_number: u64,
        call_id: String,
        content: Vec<ContentPart>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "usage")]
    Usage {
        sequence_number: u64,
        usage: UsageRecord,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "keepalive")]
    Keepalive {
        sequence_number: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "terminal")]
    Terminal {
        sequence_number: u64,
        state: TerminalState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stop_reason: Option<CanonicalStopReason>,
        /// Original provider-native stop/finish-reason string, preserved for
        /// diagnostics. Encoders must not switch on this field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_stop_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stop_details: Option<Map<String, Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<UsageRecord>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    #[serde(rename = "error")]
    Error {
        sequence_number: u64,
        category: String,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retryable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
}

impl CanonicalEvent {
    pub fn sequence_number(&self) -> u64 {
        match self {
            Self::MessageStart {
                sequence_number, ..
            }
            | Self::ResponseStart {
                sequence_number, ..
            }
            | Self::ContentDelta {
                sequence_number, ..
            }
            | Self::ToolCallDelta {
                sequence_number, ..
            }
            | Self::ToolResult {
                sequence_number, ..
            }
            | Self::Usage {
                sequence_number, ..
            }
            | Self::Keepalive {
                sequence_number, ..
            }
            | Self::Terminal {
                sequence_number, ..
            }
            | Self::Error {
                sequence_number, ..
            } => *sequence_number,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }
}

// ─── Request predicates ─────────────────────────────────────────────────────

/// Every content part in the request, in conversation order.
pub fn all_parts(request: &CanonicalRequest) -> Vec<&ContentPart> {
    let mut parts = Vec::new();
    if let Some(system) = &request.system {
        parts.extend(system.iter());
    }
    if let Some(instructions) = &request.instructions {
        parts.extend(instructions.iter());
    }
    for message in &request.messages {
        parts.extend(message.content.iter());
    }
    parts
}

pub fn has_kind(parts: &[&ContentPart], kind: &str) -> bool {
    parts.iter().any(|part| part.kind() == kind)
}

/// Text of the first non-empty text part of the first user turn, or `""`.
pub fn first_user_text(request: &CanonicalRequest) -> String {
    for message in &request.messages {
        if message.role != Role::User {
            continue;
        }
        for part in &message.content {
            if let ContentPart::Text { text } = part {
                if !text.is_empty() {
                    return text.clone();
                }
            }
        }
    }
    String::new()
}

/// One message's text parts joined by newlines, in order.
pub fn join_text_parts(parts: &[ContentPart]) -> String {
    parts
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn has_extension(parts: &[&ContentPart], name: &str) -> bool {
    parts.iter().any(
        |part| matches!(part, ContentPart::Extension { name: part_name, .. } if part_name == name),
    )
}

pub fn has_opaque_reasoning(parts: &[&ContentPart]) -> bool {
    parts.iter().any(|part| {
        matches!(
            part,
            ContentPart::Reasoning {
                opaque: Some(true),
                ..
            }
        )
    })
}

pub fn has_encrypted_reasoning(parts: &[&ContentPart]) -> bool {
    parts.iter().any(|part| {
        matches!(
            part,
            ContentPart::Reasoning {
                encrypted_content: Some(_),
                ..
            }
        )
    })
}

/// Single-pass summary of a request's content parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartSummary {
    pub has_image: bool,
    pub has_document: bool,
    pub has_audio: bool,
    pub has_web_search: bool,
    pub has_tool_activity: bool,
    pub has_opaque_reasoning: bool,
    pub has_encrypted_reasoning: bool,
    pub extension_names: std::collections::BTreeSet<String>,
}

pub fn summarize_parts(request: &CanonicalRequest) -> PartSummary {
    let mut summary = PartSummary::default();
    let mut inspect = |part: &ContentPart| match part {
        ContentPart::Image { .. } => summary.has_image = true,
        ContentPart::Document { .. } | ContentPart::File { .. } => summary.has_document = true,
        ContentPart::Audio { .. } => summary.has_audio = true,
        ContentPart::ToolCall { .. } | ContentPart::ToolResult { .. } => {
            summary.has_tool_activity = true
        }
        ContentPart::Reasoning {
            opaque,
            encrypted_content,
            ..
        } => {
            if *opaque == Some(true) {
                summary.has_opaque_reasoning = true;
            }
            if encrypted_content.is_some() {
                summary.has_encrypted_reasoning = true;
            }
        }
        ContentPart::Extension { name, .. } => {
            summary.extension_names.insert(name.clone());
        }
        _ => {}
    };
    if let Some(system) = &request.system {
        for part in system {
            inspect(part);
        }
    }
    if let Some(instructions) = &request.instructions {
        for part in instructions {
            inspect(part);
        }
    }
    for message in &request.messages {
        for part in &message.content {
            inspect(part);
        }
    }
    summary.has_web_search = request.tools.as_ref().is_some_and(|tools| {
        tools
            .iter()
            .any(|tool| tool.tool_type == Some(ToolType::WebSearch) || tool.name == "web_search")
    });
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_count_round_trips_number_and_unavailable() {
        let number: TokenCount = serde_json::from_value(json!(12)).unwrap();
        assert_eq!(number, TokenCount::Number(12));
        assert_eq!(serde_json::to_value(number).unwrap(), json!(12));

        let unavailable: TokenCount = serde_json::from_value(json!("unavailable")).unwrap();
        assert_eq!(unavailable, TokenCount::Unavailable);
        assert_eq!(
            serde_json::to_value(unavailable).unwrap(),
            json!("unavailable")
        );
        assert!(serde_json::from_value::<TokenCount>(json!("nope")).is_err());
    }

    #[test]
    fn content_parts_use_the_wire_kind_names() {
        let part = ContentPart::ToolCall {
            call_id: "call_1".into(),
            name: "read".into(),
            arguments: json!({"path":"a"}),
            index: Some(0),
            item_id: None,
            call_kind: Some(CallKind::Function),
        };
        let value = serde_json::to_value(&part).unwrap();
        assert_eq!(value["kind"], "toolCall");
        assert_eq!(value["call_id"], "call_1");
        assert_eq!(value["call_kind"], "function");
        let back: ContentPart = serde_json::from_value(value).unwrap();
        assert_eq!(back, part);
    }

    #[test]
    fn tool_result_content_accepts_text_or_parts() {
        let text: ToolResultContent = serde_json::from_value(json!("done")).unwrap();
        assert_eq!(text, ToolResultContent::Text("done".into()));
        let parts: ToolResultContent =
            serde_json::from_value(json!([{"kind":"text","text":"done"}])).unwrap();
        assert!(matches!(parts, ToolResultContent::Parts(items) if items.len() == 1));
    }

    #[test]
    fn tool_choice_round_trips_all_shapes() {
        for choice in [
            ToolChoice::Auto,
            ToolChoice::None,
            ToolChoice::Required,
            ToolChoice::Tool {
                name: "read".into(),
            },
            ToolChoice::Custom {
                name: "grammar".into(),
            },
            ToolChoice::AllowedTools {
                mode: AllowedToolsMode::Required,
                names: vec!["a".into(), "b".into()],
            },
        ] {
            let value = serde_json::to_value(&choice).unwrap();
            let back: ToolChoice = serde_json::from_value(value).unwrap();
            assert_eq!(back, choice);
        }
    }

    #[test]
    fn cache_hint_round_trips_both_shapes() {
        let stable: CacheHint = serde_json::from_value(json!("stable_prefix")).unwrap();
        assert_eq!(stable, CacheHint::StablePrefix);
        let breakpoint: CacheHint =
            serde_json::from_value(json!({"kind":"breakpoint","list":[0,2]})).unwrap();
        assert_eq!(breakpoint, CacheHint::Breakpoint { list: vec![0, 2] });
        assert_eq!(
            serde_json::to_value(&breakpoint).unwrap(),
            json!({"kind":"breakpoint","list":[0,2]})
        );
    }

    #[test]
    fn event_serialization_uses_type_tag_and_inline_terminal() {
        let event = CanonicalEvent::Terminal {
            sequence_number: 7,
            state: TerminalState::Complete,
            stop_reason: Some(CanonicalStopReason::ToolUse),
            provider_stop_reason: None,
            stop_details: None,
            usage: None,
            event_id: None,
            response_id: None,
            timestamp: None,
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["type"], "terminal");
        assert_eq!(value["state"], "complete");
        assert_eq!(value["stop_reason"], "tool_use");
        let back: CanonicalEvent = serde_json::from_value(value).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn response_format_round_trips() {
        let json_object: ResponseFormat =
            serde_json::from_value(json!({"type":"json_object"})).unwrap();
        assert!(matches!(json_object, ResponseFormat::JsonObject { .. }));
        let schema: ResponseFormat = serde_json::from_value(
            json!({"type":"json_schema","schema":{"type":"object"},"name":"out","strict":true}),
        )
        .unwrap();
        assert!(matches!(schema, ResponseFormat::JsonSchema { .. }));
        assert_eq!(serde_json::to_value(&schema).unwrap()["strict"], true);
    }

    #[test]
    fn request_predicates_walk_every_content_source() {
        let request = CanonicalRequest {
            model: "m".into(),
            system: Some(vec![ContentPart::Text {
                text: "system".into(),
            }]),
            instructions: None,
            messages: vec![CanonicalMessage {
                role: Role::User,
                content: vec![
                    ContentPart::Text {
                        text: "hello".into(),
                    },
                    ContentPart::Image {
                        payload: json!("img"),
                    },
                ],
                phase: None,
            }],
            tools: Some(vec![ToolDefinition {
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
            }]),
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
            stream: true,
            source_surface: SourceSurface::Chat,
        };
        assert_eq!(first_user_text(&request), "hello");
        assert_eq!(all_parts(&request).len(), 3);
        let summary = summarize_parts(&request);
        assert!(summary.has_image);
        assert!(summary.has_web_search);
        assert!(!summary.has_tool_activity);
    }
}
