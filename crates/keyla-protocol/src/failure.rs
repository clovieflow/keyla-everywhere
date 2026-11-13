//! Upstream error classification shared by HTTP and in-stream failures.
//! Port of the classification half of `src/transport/failure-policy.ts` and
//! `src/protocol/stream-error-frames.ts`.

use keyla_core::{GatewayError, GatewayErrorCode, GatewayErrorOrigin};
use serde_json::{Map, Value, json};

const MAX_UPSTREAM_ERROR_BYTES: usize = 500;

static CONTEXT_LENGTH_CODES: &[&str] = &[
    "context_length_exceeded",
    "context_too_large",
    "model_context_window_exceeded",
];
static QUOTA_ERROR_IDENTIFIERS: &[&str] = &[
    "rate_limit_exceeded",
    "rate_limit_error",
    "insufficient_quota",
    "quota_exceeded",
    "usage_limit_reached",
    "usage_not_included",
    "subscription:free-usage-exhausted",
    "resource_exhausted",
];
static CAPACITY_ERROR_IDENTIFIERS: &[&str] = &[
    "overloaded_error",
    "capacity_exhausted",
    "model_at_capacity",
    "server_is_overloaded",
    "model_capacity",
];
static AUTH_ERROR_IDENTIFIERS: &[&str] = &[
    "authentication_error",
    "invalid_api_key",
    "permission_error",
    "insufficient_scope",
    "unauthenticated",
    "permission_denied",
    "permissiondenied",
];
static PLATFORM_ERROR_IDENTIFIERS: &[&str] = &[
    "server_error",
    "internal_error",
    "internal_server_error",
    "api_error",
    "service_unavailable",
    "service_unavailable_error",
    "internal",
    "unavailable",
];
static FRAME_TYPE_IDENTIFIERS: &[&str] = &["error", "response.failed", "response.error"];

/// One classified upstream failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamClassification {
    pub code: GatewayErrorCode,
    pub status: u16,
    pub origin: GatewayErrorOrigin,
    pub credential_evidence: bool,
    pub rate_limit_scope_provider: bool,
}

/// The provider's human-readable message from an upstream error body.
pub fn extract_upstream_message(body: &Value) -> String {
    let mut raw = String::new();
    match body {
        Value::String(text) => raw = text.clone(),
        Value::Object(map) => {
            if let Some(error) = map.get("error").and_then(Value::as_str) {
                if !error.trim().is_empty() {
                    raw = error.to_owned();
                }
            } else {
                let envelope = map.get("error").and_then(Value::as_object).unwrap_or(map);
                if let Some(message) = envelope.get("message").and_then(Value::as_str) {
                    if !message.trim().is_empty() {
                        raw = message.to_owned();
                    }
                }
                if raw.is_empty() {
                    if let Some(code) = envelope.get("code").and_then(Value::as_str) {
                        if !code.trim().is_empty()
                            && !code.trim().bytes().all(|byte| byte.is_ascii_digit())
                        {
                            raw = code.to_owned();
                        }
                    }
                }
                if raw.is_empty() {
                    if let Some(message) = map.get("message").and_then(Value::as_str) {
                        if !message.trim().is_empty() {
                            raw = message.to_owned();
                        }
                    }
                }
                if raw.is_empty() {
                    if let Some(message) = map.get("msg").and_then(Value::as_str) {
                        if !message.trim().is_empty() {
                            raw = message.to_owned();
                        }
                    }
                }
                if raw.is_empty() {
                    if let Some(message) = envelope.get("msg").and_then(Value::as_str) {
                        if !message.trim().is_empty() {
                            raw = message.to_owned();
                        }
                    }
                }
                if raw.is_empty() {
                    if let Some(message) = envelope.get("error").and_then(Value::as_str) {
                        if !message.trim().is_empty() {
                            raw = message.to_owned();
                        }
                    }
                }
                if raw.is_empty() {
                    if let Some(code) = envelope.get("code").and_then(Value::as_str) {
                        if !code.trim().is_empty() {
                            raw = code.to_owned();
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let collapsed: String = raw
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect();
    collapsed
        .trim()
        .chars()
        .take(MAX_UPSTREAM_ERROR_BYTES)
        .collect()
}

/// Finds a machine-readable provider code or type without reading prose.
pub fn upstream_error_identifier(body: &Value) -> Option<String> {
    let map = body.as_object()?;
    let nested = map.get("error").and_then(Value::as_object);
    let ext = map.get("extError").and_then(Value::as_object);
    for candidate in [
        ext.and_then(|value| value.get("code")),
        nested.and_then(|value| value.get("code")),
        map.get("code"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(value) = candidate.as_str() {
            if !value.trim().is_empty() {
                return Some(value.trim().to_owned());
            }
        }
    }
    for candidate in [
        ext.and_then(|value| value.get("type")),
        nested.and_then(|value| value.get("type")),
        map.get("type"),
        ext.and_then(|value| value.get("status")),
        nested.and_then(|value| value.get("status")),
        map.get("status"),
    ]
    .into_iter()
    .flatten()
    {
        let Some(value) = candidate.as_str() else {
            continue;
        };
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        if !FRAME_TYPE_IDENTIFIERS.contains(&normalized.as_str())
            && !(normalized.len() == 3 && normalized.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Some(value.trim().to_owned());
        }
    }
    let numeric = ext
        .and_then(|value| value.get("code"))
        .or_else(|| nested.and_then(|value| value.get("code")))
        .or_else(|| map.get("code"));
    numeric
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .map(|value| (value as i64).to_string())
}

pub fn is_context_length_failure(body: &Value) -> bool {
    let Some(map) = body.as_object() else {
        return false;
    };
    let envelope = map.get("error").and_then(Value::as_object).unwrap_or(map);
    for candidate in [
        envelope.get("code"),
        envelope.get("type"),
        map.get("code"),
        map.get("type"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(value) = candidate.as_str() {
            if CONTEXT_LENGTH_CODES
                .iter()
                .any(|code| *code == value.to_ascii_lowercase())
            {
                return true;
            }
        }
    }
    false
}

/// Maps a status alone onto the shared gateway code.
pub fn status_to_gateway_error_code(status: u16) -> GatewayErrorCode {
    match status {
        401 | 403 => GatewayErrorCode::AuthenticationFailed,
        402 | 429 => GatewayErrorCode::QuotaExceeded,
        404 => GatewayErrorCode::UpstreamNotFound,
        407 => GatewayErrorCode::ProxyAuthRequired,
        408 | 504 => GatewayErrorCode::DeadlineExceeded,
        409 => GatewayErrorCode::UpstreamConflict,
        413 => GatewayErrorCode::RequestTooLarge,
        415 => GatewayErrorCode::UnsupportedMediaType,
        422 => GatewayErrorCode::UpstreamUnprocessable,
        529 => GatewayErrorCode::CapacityExhausted,
        500..=599 => GatewayErrorCode::PlatformUnavailable,
        _ => GatewayErrorCode::InvalidRequest,
    }
}

fn contains(set: &[&str], value: &str) -> bool {
    set.contains(&value)
}

/// Maps a machine-readable provider identifier before falling back to status.
pub fn classify_upstream_error(
    status: Option<u16>,
    identifier: Option<&str>,
) -> UpstreamClassification {
    let normalized = identifier.map(|value| value.trim().to_ascii_lowercase());
    let normalized = normalized.as_deref();
    let upstream_status = status.unwrap_or(502);
    let server_status = status.filter(|status| (500..=599).contains(status));
    let mut classification = UpstreamClassification {
        code: status_to_gateway_error_code(upstream_status),
        status: upstream_status,
        origin: GatewayErrorOrigin::Upstream,
        credential_evidence: false,
        rate_limit_scope_provider: matches!(upstream_status, 429 | 529),
    };
    if classification.code == GatewayErrorCode::AuthenticationFailed {
        classification.credential_evidence = true;
    }
    if upstream_status == 407 {
        return UpstreamClassification {
            code: GatewayErrorCode::ProxyAuthRequired,
            status: 407,
            origin: GatewayErrorOrigin::Network,
            credential_evidence: false,
            rate_limit_scope_provider: false,
        };
    }
    let Some(identifier) = normalized else {
        return classification;
    };
    if identifier == "proxy_auth_required" || identifier == "proxy_authentication_error" {
        return UpstreamClassification {
            code: GatewayErrorCode::ProxyAuthRequired,
            status: 407,
            origin: GatewayErrorOrigin::Network,
            credential_evidence: false,
            rate_limit_scope_provider: false,
        };
    }
    if identifier == "11140" {
        return UpstreamClassification {
            code: GatewayErrorCode::PolicyRejected,
            status: 403,
            origin: GatewayErrorOrigin::Upstream,
            credential_evidence: false,
            rate_limit_scope_provider: false,
        };
    }
    if contains(CONTEXT_LENGTH_CODES, identifier) {
        return UpstreamClassification {
            code: GatewayErrorCode::ContextLengthExceeded,
            status: 413,
            origin: GatewayErrorOrigin::Upstream,
            credential_evidence: false,
            rate_limit_scope_provider: false,
        };
    }
    if contains(QUOTA_ERROR_IDENTIFIERS, identifier) {
        return UpstreamClassification {
            code: GatewayErrorCode::QuotaExceeded,
            status: if matches!(status, Some(402 | 429)) {
                upstream_status
            } else {
                429
            },
            origin: GatewayErrorOrigin::Upstream,
            credential_evidence: false,
            rate_limit_scope_provider: true,
        };
    }
    if contains(AUTH_ERROR_IDENTIFIERS, identifier) {
        let auth_status = match status {
            Some(401 | 403) => upstream_status,
            _ if matches!(
                identifier,
                "permission_error"
                    | "insufficient_scope"
                    | "permission_denied"
                    | "permissiondenied"
            ) =>
            {
                403
            }
            _ => 401,
        };
        return UpstreamClassification {
            code: GatewayErrorCode::AuthenticationFailed,
            status: auth_status,
            origin: GatewayErrorOrigin::Upstream,
            credential_evidence: true,
            rate_limit_scope_provider: false,
        };
    }
    if contains(CAPACITY_ERROR_IDENTIFIERS, identifier) {
        return UpstreamClassification {
            code: GatewayErrorCode::CapacityExhausted,
            status: if matches!(status, Some(503 | 529)) {
                upstream_status
            } else {
                529
            },
            origin: GatewayErrorOrigin::Upstream,
            credential_evidence: false,
            rate_limit_scope_provider: false,
        };
    }
    if contains(PLATFORM_ERROR_IDENTIFIERS, identifier) {
        return UpstreamClassification {
            code: GatewayErrorCode::PlatformUnavailable,
            status: server_status.unwrap_or(502),
            origin: GatewayErrorOrigin::Upstream,
            credential_evidence: false,
            rate_limit_scope_provider: false,
        };
    }
    let mapped = match identifier {
        "model_not_found" => Some((GatewayErrorCode::ModelNotFound, 404)),
        "not_found_error" | "resource_not_found" | "not_found" => {
            Some((GatewayErrorCode::UpstreamNotFound, 404))
        }
        "conflict_error" | "already_exists" => Some((GatewayErrorCode::UpstreamConflict, 409)),
        "request_too_large" | "payload_too_large" => Some((GatewayErrorCode::RequestTooLarge, 413)),
        "unsupported_media_type" | "invalid_content_type" => {
            Some((GatewayErrorCode::UnsupportedMediaType, 415))
        }
        "unprocessable_entity" | "unprocessable_entity_error" => {
            Some((GatewayErrorCode::UpstreamUnprocessable, 422))
        }
        "timeout_error" | "upstream_timeout" | "deadline_exceeded" => {
            Some((GatewayErrorCode::DeadlineExceeded, 504))
        }
        "invalid_request_error" | "invalid_argument" | "invalid_parameter" | "bad_request" => {
            Some((GatewayErrorCode::InvalidRequest, 400))
        }
        _ => None,
    };
    if let Some((code, status)) = mapped {
        classification.code = code;
        classification.status = status;
        classification.origin = GatewayErrorOrigin::Upstream;
        classification.credential_evidence = code == GatewayErrorCode::AuthenticationFailed;
        classification.rate_limit_scope_provider = false;
    }
    classification
}

fn numeric_status(candidates: &[Option<&Value>]) -> Option<u16> {
    for candidate in candidates {
        if let Some(Value::Number(number)) = candidate {
            if let Some(value) = number.as_f64() {
                if value.is_finite() && (value == 202.0 || (400.0..600.0).contains(&value)) {
                    return Some(value as u16);
                }
            }
        }
    }
    None
}

/// Classifies one error envelope pulled out of a 200-OK stream.
pub fn gateway_error_from_stream_error(error: Option<&Value>, label: &str) -> Option<GatewayError> {
    let error = error?;
    if error.is_null() {
        return None;
    }
    if let Some(text) = error.as_str() {
        let message = text.chars().take(500).collect::<String>();
        return Some(
            GatewayError::new(
                GatewayErrorCode::PlatformUnavailable,
                502,
                if message.is_empty() { label } else { &message },
                Map::new(),
            )
            .with_origin(GatewayErrorOrigin::Upstream),
        );
    }
    let map = error.as_object()?;
    let message = extract_upstream_message(error);
    let identifier = upstream_error_identifier(error);
    let explicit_status = numeric_status(&[
        map.get("status"),
        map.get("statusCode"),
        map.get("status_code"),
    ]);
    let classification = classify_upstream_error(explicit_status, identifier.as_deref());
    let mut details = Map::new();
    if let Some(status) = explicit_status {
        details.insert("providerStatus".into(), json!(status));
    }
    if let Some(identifier) = identifier {
        details.insert("providerCode".into(), json!(identifier));
    }
    if classification.credential_evidence {
        details.insert("credentialEvidence".into(), json!(true));
    }
    if classification.rate_limit_scope_provider {
        details.insert("rateLimitScope".into(), json!("provider"));
    }
    Some(
        GatewayError::new(
            classification.code,
            classification.status,
            if message.is_empty() { label } else { &message },
            details,
        )
        .with_origin(classification.origin),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_win_over_status_and_map_to_stable_codes() {
        let classification = classify_upstream_error(Some(400), Some("context_length_exceeded"));
        assert_eq!(classification.code, GatewayErrorCode::ContextLengthExceeded);
        assert_eq!(classification.status, 413);

        let classification = classify_upstream_error(Some(400), Some("rate_limit_error"));
        assert_eq!(classification.code, GatewayErrorCode::QuotaExceeded);
        assert_eq!(classification.status, 429);

        let classification = classify_upstream_error(Some(403), Some("invalid_api_key"));
        assert_eq!(classification.code, GatewayErrorCode::AuthenticationFailed);
        assert!(classification.credential_evidence);

        let classification = classify_upstream_error(Some(503), Some("overloaded_error"));
        assert_eq!(classification.code, GatewayErrorCode::CapacityExhausted);
        assert_eq!(classification.status, 503);
    }

    #[test]
    fn status_alone_maps_to_the_shared_table() {
        assert_eq!(
            status_to_gateway_error_code(401),
            GatewayErrorCode::AuthenticationFailed
        );
        assert_eq!(
            status_to_gateway_error_code(429),
            GatewayErrorCode::QuotaExceeded
        );
        assert_eq!(
            status_to_gateway_error_code(404),
            GatewayErrorCode::UpstreamNotFound
        );
        assert_eq!(
            status_to_gateway_error_code(500),
            GatewayErrorCode::PlatformUnavailable
        );
        assert_eq!(
            status_to_gateway_error_code(400),
            GatewayErrorCode::InvalidRequest
        );
    }

    #[test]
    fn extracts_messages_from_every_known_shape() {
        assert_eq!(
            extract_upstream_message(&json!({"error": {"message": "bad"}})),
            "bad"
        );
        assert_eq!(
            extract_upstream_message(&json!({"error": "Not Found"})),
            "Not Found"
        );
        assert_eq!(
            extract_upstream_message(&json!({"code": "6004", "msg": "reset at 10:00"})),
            "reset at 10:00"
        );
        assert_eq!(
            extract_upstream_message(&Value::String("plain\nline".into())),
            "plain line"
        );
    }

    #[test]
    fn stream_errors_preserve_classification_and_bounds() {
        let error = gateway_error_from_stream_error(
            Some(&json!({"type": "invalid_api_key", "message": "no"})),
            "upstream error",
        )
        .unwrap();
        assert_eq!(error.code, GatewayErrorCode::AuthenticationFailed);
        assert_eq!(error.origin, GatewayErrorOrigin::Upstream);
        assert_eq!(
            error.details.get("providerCode").unwrap(),
            "invalid_api_key"
        );

        let plain =
            gateway_error_from_stream_error(Some(&json!("boom")), "upstream error").unwrap();
        assert_eq!(plain.code, GatewayErrorCode::PlatformUnavailable);
        assert_eq!(plain.status, 502);
        assert!(gateway_error_from_stream_error(None, "x").is_none());
    }
}
