//! Reasoning ladders, generation-control projection, and cache breakpoints.
//! Port of the parts of `translation/{thinking,capabilities,quirks,cache-controls}.ts`
//! and `providers/reasoning.ts` the Chat wire depends on.

use keyla_core::{
    CacheHint, GenerationControls, ReasoningEffort, ReasoningIntent, StopSequence, WireFamily,
};
use serde_json::{Map, Value, json};

/// Canonical reasoning effort ladder, ordered least to most intensive.
pub const REASONING_EFFORT_LADDER: [&str; 6] = ["minimal", "low", "medium", "high", "xhigh", "max"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EffortLevel {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

impl EffortLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }

    fn from_canonical(effort: ReasoningEffort) -> Option<Self> {
        match effort {
            ReasoningEffort::None => None,
            ReasoningEffort::Minimal => Some(Self::Minimal),
            ReasoningEffort::Low => Some(Self::Low),
            ReasoningEffort::Medium => Some(Self::Medium),
            ReasoningEffort::High => Some(Self::High),
            ReasoningEffort::Xhigh => Some(Self::Xhigh),
            ReasoningEffort::Max => Some(Self::Max),
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Minimal => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Xhigh => 4,
            Self::Max => 5,
        }
    }
}

const RESPONSES_WIRE_SUPPORTED_EFFORTS: [EffortLevel; 5] = [
    EffortLevel::Minimal,
    EffortLevel::Low,
    EffortLevel::Medium,
    EffortLevel::High,
    EffortLevel::Xhigh,
];
const EXTENDED_SUPPORTED_EFFORTS: [EffortLevel; 6] = [
    EffortLevel::Minimal,
    EffortLevel::Low,
    EffortLevel::Medium,
    EffortLevel::High,
    EffortLevel::Xhigh,
    EffortLevel::Max,
];
const BASE_SUPPORTED_EFFORTS: [EffortLevel; 4] = [
    EffortLevel::Minimal,
    EffortLevel::Low,
    EffortLevel::Medium,
    EffortLevel::High,
];
const LOW_TO_MAX_SUPPORTED_EFFORTS: [EffortLevel; 5] = [
    EffortLevel::Low,
    EffortLevel::Medium,
    EffortLevel::High,
    EffortLevel::Xhigh,
    EffortLevel::Max,
];
const GPT55_SUPPORTED_EFFORTS: [EffortLevel; 4] = [
    EffortLevel::Low,
    EffortLevel::Medium,
    EffortLevel::High,
    EffortLevel::Xhigh,
];
const CLAUDE_ADAPTIVE_46_SUPPORTED_EFFORTS: [EffortLevel; 3] =
    [EffortLevel::Low, EffortLevel::Medium, EffortLevel::High];
const MIMO_V26_SUPPORTED_EFFORTS: [EffortLevel; 3] =
    [EffortLevel::Low, EffortLevel::Medium, EffortLevel::High];

/// The level→budget ladder, kept as the single source of truth.
pub fn level_to_budget(level: Option<EffortLevel>) -> i64 {
    match level {
        None => 0,
        Some(EffortLevel::Minimal) => 512,
        Some(EffortLevel::Low) => 1_024,
        Some(EffortLevel::Medium) => 8_192,
        Some(EffortLevel::High) => 24_576,
        Some(EffortLevel::Xhigh) => 32_768,
        Some(EffortLevel::Max) => 128_000,
    }
}

/// Nearest ladder level for a token budget.
pub fn budget_to_level(budget: i64) -> Option<EffortLevel> {
    if budget <= 0 {
        return None;
    }
    const CEILINGS: [(EffortLevel, i64); 5] = [
        (EffortLevel::Minimal, 768),
        (EffortLevel::Low, 4_096),
        (EffortLevel::Medium, 16_384),
        (EffortLevel::High, 28_672),
        (EffortLevel::Xhigh, 80_384),
    ];
    for (level, ceiling) in CEILINGS {
        if budget <= ceiling {
            return Some(level);
        }
    }
    Some(EffortLevel::Max)
}

/// Resolves the valid reasoning effort levels for a model and wire family.
pub fn resolve_supported_reasoning_efforts(
    model_id: Option<&str>,
    wire_family: WireFamily,
    declared: Option<&[String]>,
) -> Vec<EffortLevel> {
    if let Some(declared) = declared {
        let filtered: Vec<EffortLevel> = declared
            .iter()
            .filter_map(|value| match value.as_str() {
                "minimal" => Some(EffortLevel::Minimal),
                "low" => Some(EffortLevel::Low),
                "medium" => Some(EffortLevel::Medium),
                "high" => Some(EffortLevel::High),
                "xhigh" => Some(EffortLevel::Xhigh),
                "max" => Some(EffortLevel::Max),
                _ => None,
            })
            .collect();
        if !filtered.is_empty() {
            return filtered;
        }
    }
    let id = model_id.unwrap_or_default().to_ascii_lowercase();
    if wire_family == WireFamily::Responses {
        if id.contains("gpt-5.5") {
            return GPT55_SUPPORTED_EFFORTS.to_vec();
        }
        if id.contains("gpt-5.6") || id.contains("gpt-6") || id.contains("daybreak") {
            return LOW_TO_MAX_SUPPORTED_EFFORTS.to_vec();
        }
        return RESPONSES_WIRE_SUPPORTED_EFFORTS.to_vec();
    }
    if id.contains("muse") {
        return RESPONSES_WIRE_SUPPORTED_EFFORTS.to_vec();
    }
    if id.contains("gemini") {
        return BASE_SUPPORTED_EFFORTS.to_vec();
    }
    if id.contains("mimo-v2.6") {
        return MIMO_V26_SUPPORTED_EFFORTS.to_vec();
    }
    if id.contains("claude") {
        let claude_id = id.replace('.', "-");
        if claude_id.contains("opus-4-6") || claude_id.contains("sonnet-4-6") {
            return CLAUDE_ADAPTIVE_46_SUPPORTED_EFFORTS.to_vec();
        }
        if claude_id.contains("fable")
            || claude_id.contains("mythos")
            || claude_id.contains("opus-5")
            || claude_id.contains("sonnet-5")
            || claude_id.contains("opus-4-7")
            || claude_id.contains("opus-4-8")
        {
            return LOW_TO_MAX_SUPPORTED_EFFORTS.to_vec();
        }
        if claude_id.contains("opus-4-5")
            || claude_id.contains("sonnet-4-5")
            || claude_id.contains("haiku-4-5")
            || claude_id.contains("opus-4-1")
            || claude_id.contains("opus-4-0")
            || claude_id.contains("sonnet-4-0")
        {
            return RESPONSES_WIRE_SUPPORTED_EFFORTS.to_vec();
        }
    }
    EXTENDED_SUPPORTED_EFFORTS.to_vec()
}

/// Clamps a requested effort against a target's supported ladder.
pub fn clamp_reasoning_effort(
    requested: Option<EffortLevel>,
    supported: &[EffortLevel],
) -> Option<EffortLevel> {
    let requested = requested?;
    if supported.contains(&requested) {
        return Some(requested);
    }
    let requested_index = requested.index();
    let mut clamped = None;
    for level in supported {
        if level.index() > requested_index {
            break;
        }
        clamped = Some(*level);
    }
    clamped.or_else(|| supported.first().copied())
}

/// The effective reasoning effort for an intent, deriving one from an
/// Anthropic-shaped `thinking` block when no explicit effort is set.
pub fn reasoning_effort_from_intent(reasoning: Option<&ReasoningIntent>) -> Option<EffortLevel> {
    let reasoning = reasoning?;
    if reasoning.thinking_type == Some(keyla_core::ThinkingType::Disabled) {
        return None;
    }
    if let Some(effort) = reasoning.effort {
        return EffortLevel::from_canonical(effort);
    }
    if !matches!(
        reasoning.thinking_type,
        Some(keyla_core::ThinkingType::Enabled | keyla_core::ThinkingType::Adaptive)
    ) {
        return None;
    }
    match reasoning.budget_tokens {
        Some(budget) => budget_to_level(budget).or(Some(EffortLevel::High)),
        None => Some(EffortLevel::High),
    }
}

/// Normalizes maximum output tokens so every wire sees a `max_tokens`.
pub fn normalize_wire_max_tokens(controls: &GenerationControls) -> GenerationControls {
    let mut normalized = controls.clone();
    if normalized.max_output_tokens.is_none() && normalized.max_completion_tokens.is_some() {
        normalized.max_output_tokens = normalized.max_completion_tokens;
    }
    if normalized.max_output_tokens.is_none() && normalized.max_tokens.is_some() {
        normalized.max_output_tokens = normalized.max_tokens;
    }
    if normalized.max_tokens.is_none() && normalized.max_output_tokens.is_some() {
        normalized.max_tokens = normalized.max_output_tokens;
    }
    normalized
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WireTokenBound {
    pub min_tokens: Option<i64>,
    pub default_max_tokens: Option<i64>,
    pub tool_call_floor: Option<i64>,
    pub oauth_ceiling: Option<i64>,
    pub ceiling: Option<i64>,
}

fn wire_token_bound(wire: &str) -> Option<WireTokenBound> {
    match wire {
        "chat" => Some(WireTokenBound {
            min_tokens: Some(16),
            ceiling: Some(32_000),
            ..Default::default()
        }),
        "messages" => Some(WireTokenBound {
            min_tokens: Some(16),
            default_max_tokens: Some(4_096),
            tool_call_floor: Some(32_000),
            oauth_ceiling: Some(64_000),
            ..Default::default()
        }),
        "responses" => Some(WireTokenBound {
            min_tokens: Some(16),
            ..Default::default()
        }),
        _ => None,
    }
}

/// Resolves the output-token value for one wire from caller controls.
pub fn resolve_wire_max_tokens(
    wire: &str,
    max_tokens: Option<i64>,
    has_tools: bool,
    is_oauth: bool,
) -> Option<i64> {
    let Some(bound) = wire_token_bound(wire) else {
        return max_tokens;
    };
    let mut value = max_tokens;
    if value.is_none() {
        value = bound.default_max_tokens;
    }
    if let (Some(value_ref), Some(min)) = (value.as_mut(), bound.min_tokens) {
        if *value_ref < min {
            *value_ref = min;
        }
    }
    if let (Some(value_ref), Some(floor)) = (value.as_mut(), bound.tool_call_floor) {
        if has_tools && *value_ref < floor {
            *value_ref = floor;
        }
    }
    if let (Some(value_ref), Some(ceiling)) = (value.as_mut(), bound.oauth_ceiling) {
        if is_oauth && *value_ref > ceiling {
            *value_ref = ceiling;
        }
    }
    if let (Some(value_ref), Some(ceiling)) = (value.as_mut(), bound.ceiling) {
        if *value_ref > ceiling {
            *value_ref = ceiling;
        }
    }
    value
}

/// Applies the controls the Chat wire accepts. Extensions are never copied.
pub fn apply_chat_controls(payload: &mut Map<String, Value>, controls: &GenerationControls) {
    if let Some(value) = controls.temperature {
        payload.insert("temperature".into(), json!(value));
    }
    if let Some(value) = controls.top_p {
        payload.insert("top_p".into(), json!(value));
    }
    if let Some(value) = controls.n {
        payload.insert("n".into(), json!(value));
    }
    if let Some(stop) = &controls.stop {
        payload.insert(
            "stop".into(),
            match stop {
                StopSequence::One(value) => json!(value),
                StopSequence::Many(values) => json!(values),
            },
        );
    }
    if let Some(value) = controls.max_tokens {
        payload.insert("max_tokens".into(), json!(value));
    }
    if let Some(value) = controls.max_completion_tokens {
        payload.insert("max_completion_tokens".into(), json!(value));
    }
    if let Some(value) = controls.parallel_tool_calls {
        payload.insert("parallel_tool_calls".into(), json!(value));
    }
    if let Some(value) = &controls.service_tier {
        payload.insert("service_tier".into(), json!(value));
    }
    if let Some(value) = controls.logprobs {
        payload.insert("logprobs".into(), json!(value));
    }
    if let Some(value) = controls.top_logprobs {
        payload.insert("top_logprobs".into(), json!(value));
    }
    if let Some(value) = controls.seed {
        payload.insert("seed".into(), json!(value));
    }
}

/// Resolves the prompt-cache key from the generation-control extensions.
pub fn resolve_prompt_cache_key(controls: Option<&GenerationControls>) -> Option<String> {
    let controls = controls?;
    for name in [
        "extension:prompt_cache_key",
        "extension:responses.prompt_cache_key",
        "extension:metadata_user_id",
    ] {
        if let Some(Value::String(value)) = controls.extensions.get(name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

/// Marks the latest stable input block with a prompt-cache breakpoint.
pub fn mark_latest_chat_cache_breakpoint(messages: &mut [Value]) {
    fn is_input(item: &Value) -> bool {
        matches!(
            item.get("role").and_then(Value::as_str),
            Some("user" | "developer")
        )
    }
    let mut latest_input: Option<usize> = None;
    for index in (0..messages.len()).rev() {
        if is_input(&messages[index]) {
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
        if !is_input(&messages[index]) {
            continue;
        }
        let role = messages[index].get("role").and_then(Value::as_str);
        if !matches!(role, Some("user" | "developer" | "system")) {
            continue;
        }
        if let Some(text) = messages[index]
            .get("content")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            let marker = json!([{
                "type": "text",
                "text": text,
                "prompt_cache_breakpoint": {"mode": "explicit"},
            }]);
            if let Some(object) = messages[index].as_object_mut() {
                object.insert("content".into(), marker);
            }
            return;
        }
        let Some(blocks) = messages[index].get("content").and_then(Value::as_array) else {
            continue;
        };
        let target = blocks.iter().rposition(|block| {
            block
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "text" | "image_url" | "input_audio" | "file"))
        });
        if let Some(target) = target {
            if let Some(block) = messages[index]
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

/// Milliseconds since the Unix epoch.
pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether a cache hint asks for explicit breakpoints.
pub fn cache_hint_has_breakpoints(hint: Option<&CacheHint>) -> bool {
    matches!(hint, Some(CacheHint::Breakpoint { list }) if !list.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladders_clamp_and_derive_effort() {
        assert_eq!(budget_to_level(500), Some(EffortLevel::Minimal));
        assert_eq!(budget_to_level(4_096), Some(EffortLevel::Low));
        assert_eq!(budget_to_level(100_000), Some(EffortLevel::Max));
        assert_eq!(
            clamp_reasoning_effort(Some(EffortLevel::Max), &BASE_SUPPORTED_EFFORTS),
            Some(EffortLevel::High)
        );
        assert_eq!(
            clamp_reasoning_effort(Some(EffortLevel::Minimal), &LOW_TO_MAX_SUPPORTED_EFFORTS),
            Some(EffortLevel::Low)
        );
        let intent = ReasoningIntent {
            thinking_type: Some(keyla_core::ThinkingType::Enabled),
            budget_tokens: Some(2_000),
            ..Default::default()
        };
        assert_eq!(
            reasoning_effort_from_intent(Some(&intent)),
            Some(EffortLevel::Low)
        );
    }

    #[test]
    fn supported_efforts_follow_model_families() {
        assert_eq!(
            resolve_supported_reasoning_efforts(Some("gemini-3.0-pro"), WireFamily::Chat, None),
            BASE_SUPPORTED_EFFORTS.to_vec()
        );
        assert_eq!(
            resolve_supported_reasoning_efforts(Some("claude-opus-4.6"), WireFamily::Chat, None),
            CLAUDE_ADAPTIVE_46_SUPPORTED_EFFORTS.to_vec()
        );
        assert_eq!(
            resolve_supported_reasoning_efforts(Some("gpt-5.5"), WireFamily::Responses, None),
            GPT55_SUPPORTED_EFFORTS.to_vec()
        );
        assert_eq!(
            resolve_supported_reasoning_efforts(Some("unknown"), WireFamily::Chat, None),
            EXTENDED_SUPPORTED_EFFORTS.to_vec()
        );
    }

    #[test]
    fn max_tokens_are_normalized_and_bounded() {
        let controls = GenerationControls {
            max_output_tokens: Some(100_000),
            ..Default::default()
        };
        let normalized = normalize_wire_max_tokens(&controls);
        assert_eq!(normalized.max_tokens, Some(100_000));
        assert_eq!(
            resolve_wire_max_tokens("chat", Some(100_000), false, false),
            Some(32_000)
        );
        assert_eq!(
            resolve_wire_max_tokens("chat", Some(1), false, false),
            Some(16)
        );
        assert_eq!(resolve_wire_max_tokens("chat", None, false, false), None);
    }

    #[test]
    fn cache_breakpoint_marks_the_block_before_the_latest_input() {
        let mut messages = vec![
            json!({"role":"user","content":"first"}),
            json!({"role":"assistant","content":"reply"}),
            json!({"role":"user","content":[{"type":"text","text":"latest"}]}),
        ];
        mark_latest_chat_cache_breakpoint(&mut messages);
        assert_eq!(
            messages[0]["content"][0]["prompt_cache_breakpoint"]["mode"],
            "explicit"
        );
        assert!(
            messages[2]["content"][0]
                .get("prompt_cache_breakpoint")
                .is_none()
        );
    }
}
