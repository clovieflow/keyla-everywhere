//! Provider usage normalization for the Chat wire. Port of
//! `src/providers/usage.ts` (`usageToChatWire`).

use keyla_core::{TokenCount, UsageRecord};
use serde_json::{Map, Value, json};

pub fn usage_to_chat_wire(usage: &UsageRecord) -> Value {
    let mut prompt_details = Map::new();
    if let TokenCount::Number(cached) = usage.cached_input_tokens {
        prompt_details.insert("cached_tokens".into(), json!(cached));
    }

    let mut completion_details = Map::new();
    if let TokenCount::Number(reasoning) = usage.reasoning_tokens {
        completion_details.insert("reasoning_tokens".into(), json!(reasoning));
    }
    if let Some(details) = &usage.details {
        if let Some(TokenCount::Number(accepted)) = details.accepted_prediction_tokens {
            completion_details.insert("accepted_prediction_tokens".into(), json!(accepted));
        }
        if let Some(TokenCount::Number(rejected)) = details.rejected_prediction_tokens {
            completion_details.insert("rejected_prediction_tokens".into(), json!(rejected));
        }
    }

    let mut result = Map::new();
    result.insert("prompt_tokens".into(), json!(usage.input_tokens));
    result.insert("completion_tokens".into(), json!(usage.output_tokens));
    result.insert(
        "total_tokens".into(),
        json!(usage.input_tokens + usage.output_tokens),
    );
    if !prompt_details.is_empty() {
        result.insert(
            "prompt_tokens_details".into(),
            Value::Object(prompt_details),
        );
    }
    if !completion_details.is_empty() {
        result.insert(
            "completion_tokens_details".into(),
            Value::Object(completion_details),
        );
    }
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_usage_includes_details_only_when_reported() {
        let usage = UsageRecord {
            input_tokens: 10,
            cached_input_tokens: TokenCount::Number(4),
            cache_write_tokens: TokenCount::Unavailable,
            uncached_input_tokens: TokenCount::Number(6),
            output_tokens: 5,
            reasoning_tokens: TokenCount::Unavailable,
            estimated_cost: None,
            credit_used: None,
            total_tokens: None,
            details: None,
        };
        let wire = usage_to_chat_wire(&usage);
        assert_eq!(wire["prompt_tokens"], 10);
        assert_eq!(wire["completion_tokens"], 5);
        assert_eq!(wire["total_tokens"], 15);
        assert_eq!(wire["prompt_tokens_details"]["cached_tokens"], 4);
        assert!(wire.get("completion_tokens_details").is_none());

        let usage = UsageRecord {
            reasoning_tokens: TokenCount::Number(3),
            ..usage
        };
        let wire = usage_to_chat_wire(&usage);
        assert_eq!(wire["completion_tokens_details"]["reasoning_tokens"], 3);
    }
}

use keyla_core::UsageDetails;

fn number(map: &Map<String, Value>, key: &str) -> Option<f64> {
    map.get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

fn non_negative(value: f64) -> i64 {
    if value <= 0.0 { 0 } else { value as i64 }
}

fn details_number(map: &Map<String, Value>, key: &str) -> Option<f64> {
    map.get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

/// Normalizes provider-specific usage data into the canonical record.
///
/// Cost is left unset until the models.dev catalog is ported; the canonical
/// contract keeps "unpriced" distinct from zero, so `estimated_cost` is
/// `None` here rather than a fabricated `0`.
pub fn normalize_usage(input: &Map<String, Value>) -> UsageRecord {
    let mut input_tokens = number(input, "input_tokens")
        .or_else(|| number(input, "prompt_tokens"))
        .map(non_negative)
        .unwrap_or(0);
    let output_tokens = number(input, "output_tokens")
        .or_else(|| number(input, "completion_tokens"))
        .map(non_negative)
        .unwrap_or(0);

    let anthropic_cache_read = number(input, "cache_read_input_tokens");
    let mut cached = anthropic_cache_read
        .map(non_negative)
        .map(TokenCount::Number);

    if let Some(hit) = number(input, "prompt_cache_hit_tokens") {
        cached = Some(TokenCount::Number(non_negative(hit)));
    }
    if cached.is_none() {
        if let Some(details) = input.get("input_tokens_details").and_then(Value::as_object) {
            if let Some(value) = details_number(details, "cached_tokens") {
                cached = Some(TokenCount::Number(non_negative(value)));
            }
        }
    }
    if cached.is_none() {
        if let Some(details) = input
            .get("prompt_tokens_details")
            .and_then(Value::as_object)
        {
            if let Some(value) = details_number(details, "cached_tokens") {
                cached = Some(TokenCount::Number(non_negative(value)));
            }
        }
    }
    if cached.is_none() {
        if let Some(value) = number(input, "cached_tokens") {
            cached = Some(TokenCount::Number(non_negative(value)));
        }
    }
    if cached.is_none() {
        if let Some(value) = number(input, "cachedContentTokenCount") {
            cached = Some(TokenCount::Number(non_negative(value)));
        }
    }

    let mut cache_write = number(input, "cache_creation_input_tokens")
        .map(non_negative)
        .map(TokenCount::Number);
    if cache_write.is_none() {
        if let Some(breakdown) = input.get("cache_creation").and_then(Value::as_object) {
            let short = number(breakdown, "ephemeral_5m_input_tokens").unwrap_or(0.0);
            let long = number(breakdown, "ephemeral_1h_input_tokens").unwrap_or(0.0);
            if short > 0.0 || long > 0.0 {
                cache_write = Some(TokenCount::Number(non_negative(short + long)));
            }
        }
    }

    let has_anthropic_cache_shape = anthropic_cache_read.is_some();
    let mut uncached = TokenCount::Unavailable;
    if let Some(TokenCount::Number(cached_value)) = cached {
        if has_anthropic_cache_shape {
            uncached = TokenCount::Number(input_tokens);
            let written = match &cache_write {
                Some(TokenCount::Number(write)) => *write,
                _ => 0,
            };
            input_tokens += cached_value + written;
        } else {
            uncached = TokenCount::Number((input_tokens - input_tokens.min(cached_value)).max(0));
            cached = Some(TokenCount::Number(input_tokens.min(cached_value)));
        }
    } else if has_anthropic_cache_shape {
        if let Some(TokenCount::Number(write)) = &cache_write {
            input_tokens += *write;
        }
    }

    let mut reasoning = TokenCount::Unavailable;
    let mut usage_details = UsageDetails::default();
    let output_details = input
        .get("output_tokens_details")
        .and_then(Value::as_object)
        .or_else(|| {
            input
                .get("completion_tokens_details")
                .and_then(Value::as_object)
        });
    if let Some(output_details) = output_details {
        if let Some(value) = details_number(output_details, "thinking_tokens") {
            reasoning = TokenCount::Number(non_negative(value));
        } else if let Some(value) = details_number(output_details, "reasoning_tokens") {
            reasoning = TokenCount::Number(non_negative(value));
        }
        if let Some(value) = details_number(output_details, "accepted_prediction_tokens") {
            usage_details.accepted_prediction_tokens =
                Some(TokenCount::Number(non_negative(value)));
        }
        if let Some(value) = details_number(output_details, "rejected_prediction_tokens") {
            usage_details.rejected_prediction_tokens =
                Some(TokenCount::Number(non_negative(value)));
        }
    }
    let has_details = usage_details.accepted_prediction_tokens.is_some()
        || usage_details.rejected_prediction_tokens.is_some();
    let credit_used = number(input, "credit").filter(|value| *value >= 0.0);
    UsageRecord {
        input_tokens,
        cached_input_tokens: cached.unwrap_or(TokenCount::Unavailable),
        cache_write_tokens: cache_write.unwrap_or(TokenCount::Unavailable),
        uncached_input_tokens: uncached,
        output_tokens,
        reasoning_tokens: reasoning,
        estimated_cost: None,
        credit_used,
        total_tokens: None,
        details: has_details.then_some(usage_details),
    }
}

fn has_reported_usage(usage: &UsageRecord) -> bool {
    let positive = |count: TokenCount| matches!(count, TokenCount::Number(value) if value > 0);
    usage.input_tokens > 0
        || usage.output_tokens > 0
        || positive(usage.cached_input_tokens)
        || positive(usage.cache_write_tokens)
        || positive(usage.reasoning_tokens)
}

/// Normalizes a provider usage payload, or `None` when nothing was reported.
pub fn usage_from_provider(raw: Option<&Value>) -> Option<UsageRecord> {
    let raw = raw?.as_object()?;
    let usage = normalize_usage(raw);
    has_reported_usage(&usage).then_some(usage)
}

pub const REASONING_TEXT_KEYS: [&str; 2] = ["reasoning_content", "reasoning"];

/// First string found under a known reasoning-text key, or the concatenated
/// text of `reasoning_details[]` fragments.
pub fn read_reasoning_text(source: &Map<String, Value>) -> Option<String> {
    for key in REASONING_TEXT_KEYS {
        if let Some(value) = source.get(key).and_then(Value::as_str) {
            return Some(value.to_owned());
        }
    }
    if let Some(Value::Array(details)) = source.get("reasoning_details") {
        let text: String = details
            .iter()
            .map(|part| match part {
                Value::String(text) => text.as_str(),
                Value::Object(map) => map.get("text").and_then(Value::as_str).unwrap_or(""),
                _ => "",
            })
            .collect();
        if !text.is_empty() {
            return Some(text);
        }
    }
    None
}

fn details_cached_tokens(usage: &Map<String, Value>) -> i64 {
    usage
        .get("input_tokens_details")
        .and_then(Value::as_object)
        .and_then(|details| details_number(details, "cached_tokens"))
        .map(non_negative)
        .unwrap_or(0)
}

/// Merges split usage frames without letting a later truncated cached count
/// wipe a prior real hit.
pub fn merge_usage(
    current: Option<&Map<String, Value>>,
    update: Option<&Map<String, Value>>,
) -> Option<Map<String, Value>> {
    let Some(update) = update else {
        return current.cloned();
    };
    let Some(current) = current else {
        return Some(update.clone());
    };
    let mut merged = current.clone();
    for (key, value) in update {
        if key == "input_tokens_details" || key == "output_tokens_details" {
            continue;
        }
        merged.insert(key.clone(), value.clone());
    }
    let cached = details_cached_tokens(current).max(details_cached_tokens(update));
    let update_details = update
        .get("input_tokens_details")
        .and_then(Value::as_object);
    let current_details = current
        .get("input_tokens_details")
        .and_then(Value::as_object);
    if update_details.is_some() || current_details.is_some() || cached > 0 {
        let mut details = Map::new();
        if let Some(current_details) = current_details {
            details.extend(current_details.clone());
        }
        if let Some(update_details) = update_details {
            details.extend(update_details.clone());
        }
        details.insert("cached_tokens".into(), serde_json::json!(cached));
        merged.insert("input_tokens_details".into(), Value::Object(details));
    }
    let update_out = update
        .get("output_tokens_details")
        .and_then(Value::as_object);
    let current_out = current
        .get("output_tokens_details")
        .and_then(Value::as_object);
    if update_out.is_some() || current_out.is_some() {
        let mut details = Map::new();
        if let Some(current_out) = current_out {
            details.extend(current_out.clone());
        }
        if let Some(update_out) = update_out {
            details.extend(update_out.clone());
        }
        merged.insert("output_tokens_details".into(), Value::Object(details));
    }
    Some(merged)
}

#[cfg(test)]
mod normalization_tests {
    use super::*;
    use serde_json::json;

    fn map(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn openai_inclusive_usage_derives_uncached_tokens() {
        let usage = normalize_usage(&map(json!({
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": 40},
            "completion_tokens_details": {"reasoning_tokens": 8},
            "credit": 1.5
        })));
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cached_input_tokens, TokenCount::Number(40));
        assert_eq!(usage.uncached_input_tokens, TokenCount::Number(60));
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(usage.reasoning_tokens, TokenCount::Number(8));
        assert_eq!(usage.credit_used, Some(1.5));
        assert_eq!(usage.estimated_cost, None);
    }

    #[test]
    fn anthropic_cache_shape_adds_reads_and_writes_to_the_total() {
        let usage = normalize_usage(&map(json!({
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_input_tokens": 100,
            "cache_creation_input_tokens": 20,
            "output_tokens_details": {"thinking_tokens": 3}
        })));
        assert_eq!(usage.input_tokens, 130);
        assert_eq!(usage.uncached_input_tokens, TokenCount::Number(10));
        assert_eq!(usage.cached_input_tokens, TokenCount::Number(100));
        assert_eq!(usage.cache_write_tokens, TokenCount::Number(20));
        assert_eq!(usage.reasoning_tokens, TokenCount::Number(3));
    }

    #[test]
    fn usage_absence_stays_absent() {
        assert!(usage_from_provider(None).is_none());
        assert!(usage_from_provider(Some(&json!({}))).is_none());
        assert!(usage_from_provider(Some(&json!(null))).is_none());
        assert!(usage_from_provider(Some(&json!({"prompt_tokens": 1}))).is_some());
    }

    #[test]
    fn usage_merge_keeps_the_largest_cached_count() {
        let current =
            map(json!({"input_tokens": 10, "input_tokens_details": {"cached_tokens": 9}}));
        let update = map(json!({"input_tokens": 11, "input_tokens_details": {"cached_tokens": 2}}));
        let merged = merge_usage(Some(&current), Some(&update)).unwrap();
        assert_eq!(merged["input_tokens"], 11);
        assert_eq!(merged["input_tokens_details"]["cached_tokens"], 9);
    }

    #[test]
    fn reasoning_text_reads_side_channel_and_details() {
        assert_eq!(
            read_reasoning_text(&map(json!({"reasoning_content": "a"}))).as_deref(),
            Some("a")
        );
        assert_eq!(
            read_reasoning_text(&map(json!({"reasoning_details": ["a", {"text": "b"}]})))
                .as_deref(),
            Some("ab")
        );
        assert!(read_reasoning_text(&map(json!({}))).is_none());
    }
}
