//! Core canonical model, typed gateway errors, and redaction.

pub mod canonical;
pub mod error;
pub mod redaction;

pub use canonical::{
    AllowedToolsMode, AssistantItemPhase, CacheHint, CallKind, CanonicalEvent, CanonicalMessage,
    CanonicalRequest, CanonicalStopReason, ContentPart, ConversationState, DocumentSourceType,
    GenerationControls, JsonObjectMarker, JsonSchemaMarker, PartSummary, PrefixMismatchBehavior,
    REASONING_EFFORTS, ReasoningContext, ReasoningEffort, ReasoningIntent, ReasoningMode,
    ResponseFormat, Role, SERVICE_KINDS, ServiceKind, SourceSurface, StopSequence, SummaryMode,
    TerminalState, ThinkingDisplay, ThinkingType, TokenCount, ToolCaller, ToolChoice,
    ToolDefinition, ToolResultContent, ToolType, UsageDetails, UsageRecord, Verbosity,
    WIRE_FAMILIES, WireFamily, all_parts, can_contain_tool_result, first_user_text, get_header,
    has_encrypted_reasoning, has_extension, has_kind, has_opaque_reasoning, join_text_parts,
    summarize_parts, tool_call_parts, tool_result_parts,
};
pub use error::{
    GatewayError, GatewayErrorCode, GatewayErrorOrigin, capability_unsupported,
    format_public_message, public_details,
};
pub use redaction::{mask_client_ip, redact_text, redact_value};
