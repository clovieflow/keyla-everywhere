//! Capability projection and pre-lease preflight. Port of
//! `src/transport/translation/capabilities.ts` (the route-facing half).

use std::collections::BTreeSet;

use keyla_core::{
    CacheHint, CanonicalRequest, ContentPart, GatewayError, GatewayErrorCode, ResponseFormat,
    ServiceKind, ToolType, WireFamily, summarize_parts,
};
use serde_json::{Map, json};

use crate::model::RouteCandidate;

pub const MAX_CACHE_BREAKPOINTS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequiredCapability {
    Image,
    Document,
    Audio,
    WebSearch,
    Tools,
    ParallelToolCalls,
    Reasoning,
    ReasoningEncryptedContent,
    ResponseFormatJsonObject,
    ResponseFormatJsonSchema,
    PromptCaching,
    GenerationControl(&'static str),
    Extension(String),
}

impl RequiredCapability {
    pub fn as_str(&self) -> String {
        match self {
            Self::Image => "image".into(),
            Self::Document => "document".into(),
            Self::Audio => "audio".into(),
            Self::WebSearch => "web_search".into(),
            Self::Tools => "tools".into(),
            Self::ParallelToolCalls => "parallel_tool_calls".into(),
            Self::Reasoning => "reasoning".into(),
            Self::ReasoningEncryptedContent => "reasoning.encrypted_content".into(),
            Self::ResponseFormatJsonObject => "response_format.json_object".into(),
            Self::ResponseFormatJsonSchema => "response_format.json_schema".into(),
            Self::PromptCaching => "prompt_caching".into(),
            Self::GenerationControl(control) => format!("generation_control:{control}"),
            Self::Extension(name) => format!("extension:{name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteCapabilities {
    pub text: bool,
    pub image: bool,
    pub document: bool,
    pub audio: bool,
    pub web_search: bool,
    pub tools: bool,
    pub parallel_tool_calls: bool,
    pub reasoning: bool,
    pub reasoning_encrypted_content: bool,
    pub response_json_object: bool,
    pub response_json_schema: bool,
    pub prompt_caching: bool,
    pub generation_controls: BTreeSet<&'static str>,
    pub extensions: BTreeSet<String>,
}

fn profile_flag(candidate: &RouteCandidate, name: &str) -> bool {
    candidate
        .capability_profile
        .get(name)
        .copied()
        .unwrap_or(false)
}

fn bespoke_wire(candidate: &RouteCandidate) -> bool {
    profile_flag(candidate, "bespokeWire")
}

const CHAT_CONTROLS: [&str; 11] = [
    "temperature",
    "top_p",
    "n",
    "stop",
    "max_tokens",
    "max_completion_tokens",
    "parallel_tool_calls",
    "service_tier",
    "logprobs",
    "top_logprobs",
    "seed",
];

const RESPONSES_CONTROLS: [&str; 5] = [
    "temperature",
    "top_p",
    "max_output_tokens",
    "parallel_tool_calls",
    "service_tier",
];

const MESSAGES_CONTROLS: [&str; 6] = [
    "temperature",
    "top_p",
    "top_k",
    "stop",
    "max_tokens",
    "parallel_tool_calls",
];

const BESPOKE_CONTROLS: [&str; 13] = [
    "temperature",
    "top_p",
    "top_k",
    "n",
    "stop",
    "max_tokens",
    "max_completion_tokens",
    "max_output_tokens",
    "parallel_tool_calls",
    "service_tier",
    "logprobs",
    "top_logprobs",
    "seed",
];

const MESSAGES_EXTENSIONS: [&str; 3] =
    ["server_tool_use", "search_result", "web_search_tool_result"];

/// Projects a snapshot capability profile onto route capability declarations.
pub fn route_capabilities_for(candidate: &RouteCandidate) -> RouteCapabilities {
    let bespoke = bespoke_wire(candidate);
    let audio_capable_wire = matches!(
        candidate.wire_family,
        WireFamily::Chat | WireFamily::Responses
    );
    let controls: BTreeSet<&'static str> = if bespoke {
        BESPOKE_CONTROLS.into_iter().collect()
    } else {
        match candidate.wire_family {
            WireFamily::Chat => CHAT_CONTROLS.into_iter().collect(),
            WireFamily::Responses => RESPONSES_CONTROLS.into_iter().collect(),
            WireFamily::Messages => MESSAGES_CONTROLS.into_iter().collect(),
        }
    };
    let extensions: BTreeSet<String> = if bespoke {
        BTreeSet::new()
    } else if candidate.wire_family == WireFamily::Messages {
        MESSAGES_EXTENSIONS
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    } else {
        BTreeSet::new()
    };
    RouteCapabilities {
        text: true,
        image: profile_flag(candidate, "image") || !bespoke,
        document: profile_flag(candidate, "document") || !bespoke,
        audio: if bespoke {
            profile_flag(candidate, "audio")
        } else {
            audio_capable_wire
        },
        web_search: profile_flag(candidate, "webSearch"),
        tools: profile_flag(candidate, "tools"),
        parallel_tool_calls: profile_flag(candidate, "parallelToolCalls"),
        reasoning: profile_flag(candidate, "reasoning"),
        reasoning_encrypted_content: profile_flag(candidate, "reasoningEncryptedContent"),
        response_json_object: candidate
            .capability_profile
            .get("responseJsonObject")
            .copied()
            .unwrap_or(true),
        response_json_schema: candidate
            .capability_profile
            .get("responseJsonSchema")
            .copied()
            .unwrap_or(true),
        prompt_caching: candidate
            .capability_profile
            .get("promptCaching")
            .copied()
            .unwrap_or(true),
        generation_controls: controls,
        extensions,
    }
}

fn route_supports(required: &RequiredCapability, capabilities: &RouteCapabilities) -> bool {
    match required {
        RequiredCapability::Image => capabilities.image,
        RequiredCapability::Document => capabilities.document,
        RequiredCapability::Audio => capabilities.audio,
        RequiredCapability::WebSearch => capabilities.web_search,
        RequiredCapability::Tools => capabilities.tools,
        RequiredCapability::ParallelToolCalls => {
            capabilities.tools && capabilities.parallel_tool_calls
        }
        RequiredCapability::Reasoning => capabilities.reasoning,
        RequiredCapability::ReasoningEncryptedContent => {
            capabilities.reasoning && capabilities.reasoning_encrypted_content
        }
        RequiredCapability::ResponseFormatJsonObject => capabilities.response_json_object,
        RequiredCapability::ResponseFormatJsonSchema => capabilities.response_json_schema,
        RequiredCapability::PromptCaching => capabilities.prompt_caching,
        RequiredCapability::GenerationControl(control) => {
            if capabilities.generation_controls.contains(control) {
                return true;
            }
            if matches!(
                *control,
                "max_tokens" | "max_output_tokens" | "max_completion_tokens"
            ) {
                return capabilities.generation_controls.contains("max_tokens")
                    || capabilities
                        .generation_controls
                        .contains("max_output_tokens")
                    || capabilities
                        .generation_controls
                        .contains("max_completion_tokens");
            }
            false
        }
        RequiredCapability::Extension(name) => capabilities.extensions.contains(name),
    }
}

pub fn candidate_supports_request(
    candidate: &RouteCandidate,
    required: &[RequiredCapability],
) -> bool {
    let capabilities = route_capabilities_for(candidate);
    required
        .iter()
        .all(|capability| route_supports(capability, &capabilities))
}

/// True when one declared tool is a hosted web-search tool.
pub fn is_web_search_tool(tool: &keyla_core::ToolDefinition) -> bool {
    tool.native_type
        .as_deref()
        .is_some_and(|native| native.starts_with("web_search_"))
        || tool.tool_type == Some(ToolType::WebSearch)
}

fn generation_control_keys(controls: &keyla_core::GenerationControls) -> Vec<&'static str> {
    let mut keys = Vec::new();
    if controls.temperature.is_some() {
        keys.push("temperature");
    }
    if controls.top_p.is_some() {
        keys.push("top_p");
    }
    if controls.top_k.is_some() {
        keys.push("top_k");
    }
    if controls.n.is_some() {
        keys.push("n");
    }
    if controls.stop.is_some() {
        keys.push("stop");
    }
    if controls.max_tokens.is_some() {
        keys.push("max_tokens");
    }
    if controls.max_completion_tokens.is_some() {
        keys.push("max_completion_tokens");
    }
    if controls.max_output_tokens.is_some() {
        keys.push("max_output_tokens");
    }
    if controls.parallel_tool_calls.is_some() {
        keys.push("parallel_tool_calls");
    }
    if controls.service_tier.is_some() {
        keys.push("service_tier");
    }
    if controls.logprobs.is_some() {
        keys.push("logprobs");
    }
    if controls.top_logprobs.is_some() {
        keys.push("top_logprobs");
    }
    if controls.seed.is_some() {
        keys.push("seed");
    }
    keys
}

/// Derives every semantic requirement from a canonical request.
pub fn derive_required_capabilities(request: &CanonicalRequest) -> Vec<RequiredCapability> {
    let summary = summarize_parts(request);
    let mut required = Vec::new();
    if summary.has_image {
        required.push(RequiredCapability::Image);
    }
    if summary.has_document {
        required.push(RequiredCapability::Document);
    }
    if summary.has_audio {
        required.push(RequiredCapability::Audio);
    }
    if request
        .tools
        .as_ref()
        .is_some_and(|tools| !tools.is_empty())
        || summary.has_tool_activity
    {
        required.push(RequiredCapability::Tools);
    }
    if request.generation_controls.parallel_tool_calls == Some(true) {
        required.push(RequiredCapability::ParallelToolCalls);
    }
    if request.reasoning.is_some() {
        required.push(RequiredCapability::Reasoning);
        if summary.has_encrypted_reasoning {
            required.push(RequiredCapability::ReasoningEncryptedContent);
        }
    }
    match &request.response_format {
        Some(ResponseFormat::JsonObject { .. }) => {
            required.push(RequiredCapability::ResponseFormatJsonObject);
        }
        Some(ResponseFormat::JsonSchema { .. }) => {
            required.push(RequiredCapability::ResponseFormatJsonSchema);
        }
        None => {}
    }
    if request.cache_hint.is_some() {
        required.push(RequiredCapability::PromptCaching);
    }
    for key in generation_control_keys(&request.generation_controls) {
        required.push(RequiredCapability::GenerationControl(key));
    }
    for name in summary.extension_names {
        required.push(RequiredCapability::Extension(name));
    }
    required.sort();
    required.dedup();
    required
}

fn cache_breakpoint_count(hint: Option<&CacheHint>) -> Option<usize> {
    match hint {
        Some(CacheHint::Breakpoint { list }) => Some(list.len()),
        _ => None,
    }
}

/// Pre-lease capability filtering: rejects an over-limit cache hint and any
/// requirement the route cannot serve, returning the derived requirement set.
pub fn project_for_route(
    request: &CanonicalRequest,
    capabilities: &RouteCapabilities,
) -> Result<Vec<RequiredCapability>, GatewayError> {
    if let Some(count) = cache_breakpoint_count(request.cache_hint.as_ref()) {
        if count > MAX_CACHE_BREAKPOINTS {
            let mut details = Map::new();
            details.insert("breakpoint_count".into(), json!(count));
            details.insert("max_breakpoints".into(), json!(MAX_CACHE_BREAKPOINTS));
            return Err(GatewayError::new(
                GatewayErrorCode::InvalidRequest,
                400,
                format!(
                    "cache_hint declares {count} breakpoints; at most {MAX_CACHE_BREAKPOINTS} are supported"
                ),
                details,
            ));
        }
    }
    let required = derive_required_capabilities(request);
    for capability in &required {
        if !route_supports(capability, capabilities) {
            let mut details = Map::new();
            details.insert("capability".into(), json!(capability.as_str()));
            details.insert(
                "source_surface".into(),
                json!(request.source_surface.as_str()),
            );
            return Err(GatewayError::new(
                GatewayErrorCode::CapabilityUnsupported,
                400,
                format!(
                    "The selected route does not support capability: {}",
                    capability.as_str()
                ),
                details,
            ));
        }
    }
    Ok(required)
}

/// Provider-neutral helper: does a request declare or invoke web search?
pub fn request_uses_web_search(request: &CanonicalRequest) -> bool {
    if request
        .tools
        .as_ref()
        .is_some_and(|tools| tools.iter().any(is_web_search_tool))
    {
        return true;
    }
    request.messages.iter().any(|message| {
        message.content.iter().any(|part| match part {
            ContentPart::ToolCall { name, .. } => is_web_search_tool_name(name),
            _ => false,
        })
    })
}

pub fn is_web_search_tool_name(name: &str) -> bool {
    let normalized: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphabetic())
        .collect();
    normalized == "websearch" || normalized == "websearchpreview" || name.starts_with("web_search")
}

/// The `service_kind` a model must carry to serve each API family.
pub fn service_kind_for_endpoint(endpoint: &str) -> ServiceKind {
    match endpoint {
        "search" => ServiceKind::Websearch,
        "systemone" => ServiceKind::Systemone,
        _ => ServiceKind::Llm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RouteCandidate;
    use keyla_core::{
        CacheHint, CanonicalMessage, CanonicalRequest, ContentPart, GenerationControls, Role,
        ToolDefinition, ToolType,
    };
    use std::collections::BTreeMap;

    fn candidate(wire: WireFamily, profile: &[(&str, bool)]) -> RouteCandidate {
        RouteCandidate::new(
            "openai",
            "gpt-test",
            wire,
            ServiceKind::Llm,
            "/v1/chat/completions",
            profile
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    fn request() -> CanonicalRequest {
        CanonicalRequest {
            model: "m".into(),
            system: None,
            instructions: None,
            messages: vec![CanonicalMessage {
                role: Role::User,
                content: vec![ContentPart::Text { text: "hi".into() }],
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
            source_surface: keyla_core::SourceSurface::Chat,
        }
    }

    #[test]
    fn audio_is_narrowed_per_wire_for_codec_routes() {
        let chat = route_capabilities_for(&candidate(WireFamily::Chat, &[]));
        assert!(chat.audio);
        let messages = route_capabilities_for(&candidate(WireFamily::Messages, &[]));
        assert!(!messages.audio);
        let bespoke = route_capabilities_for(&candidate(
            WireFamily::Messages,
            &[("bespokeWire", true), ("audio", true)],
        ));
        assert!(bespoke.audio);
    }

    #[test]
    fn required_capabilities_cover_parts_tools_and_controls() {
        let mut request = request();
        request.messages[0].content.push(ContentPart::Image {
            payload: json!("https://x/y.png"),
        });
        request.tools = Some(vec![ToolDefinition {
            name: "read".into(),
            description: None,
            json_schema: json!({}),
            strict: None,
            eager_input_streaming: None,
            defer_loading: None,
            input_examples: None,
            tool_type: Some(ToolType::Function),
            native_type: None,
            allowed_callers: None,
        }]);
        request.generation_controls.temperature = Some(0.5);
        request.cache_hint = Some(CacheHint::StablePrefix);
        let required = derive_required_capabilities(&request);
        assert!(required.contains(&RequiredCapability::Image));
        assert!(required.contains(&RequiredCapability::Tools));
        assert!(required.contains(&RequiredCapability::PromptCaching));
        assert!(required.contains(&RequiredCapability::GenerationControl("temperature")));
    }

    #[test]
    fn projection_rejects_capabilities_the_route_lacks() {
        let mut request = request();
        request.messages[0].content.push(ContentPart::Audio {
            data: json!("AA"),
            media_type: "audio/mpeg".into(),
        });
        let messages = candidate(WireFamily::Messages, &[]);
        let capabilities = route_capabilities_for(&messages);
        let error = project_for_route(&request, &capabilities).unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::CapabilityUnsupported);
        assert!(error.message.contains("audio"));
    }

    #[test]
    fn over_limit_cache_breakpoints_fail_before_dispatch() {
        let mut request = request();
        request.cache_hint = Some(CacheHint::Breakpoint {
            list: vec![0, 1, 2, 3, 4],
        });
        let capabilities = route_capabilities_for(&candidate(WireFamily::Chat, &[("tools", true)]));
        let error = project_for_route(&request, &capabilities).unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
    }

    #[test]
    fn route_support_respects_parallel_tool_dependency() {
        let no_tools = candidate(WireFamily::Chat, &[("parallelToolCalls", true)]);
        let caps = route_capabilities_for(&no_tools);
        assert!(!route_supports(
            &RequiredCapability::ParallelToolCalls,
            &caps
        ));
        let with_tools = candidate(
            WireFamily::Chat,
            &[("tools", true), ("parallelToolCalls", true)],
        );
        let caps = route_capabilities_for(&with_tools);
        assert!(route_supports(
            &RequiredCapability::ParallelToolCalls,
            &caps
        ));
    }
}
