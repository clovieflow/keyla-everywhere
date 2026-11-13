//! Typed gateway failures: the stable public error codes and the sanitized
//! public envelope. Port of `src/transport/gateway-error.ts`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::redaction::{redact_text, redact_value};

/// Stable typed error codes returned at gateway boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayErrorCode {
    CapabilityUnsupported,
    AmbiguousModel,
    ModelNotFound,
    UpstreamNotFound,
    ContextLengthExceeded,
    RequestTooLarge,
    AccountsUnavailable,
    AccountsRateLimited,
    CapacityExhausted,
    ProxyPoolCapacityExceeded,
    ProxyPoolCooldown,
    ProxyPoolUnavailable,
    ProxyPoolUnhealthy,
    InvalidPoolLimits,
    AdmissionUnavailable,
    SlugReserved,
    QuotaExceeded,
    AuthenticationFailed,
    PolicyRejected,
    InvalidRequest,
    NotFound,
    LinkNotFound,
    LinkExpired,
    LinkRevoked,
    LinkDisabled,
    InvalidSequence,
    InvalidLifecycle,
    UnsupportedField,
    UnsupportedMediaType,
    UpstreamConflict,
    UpstreamUnprocessable,
    InternalError,
    TransportUnavailable,
    TunnelSetupFailed,
    PlatformUnavailable,
    TenantCapacityExhausted,
    TlsRejected,
    ProxyAuthRequired,
    DeadlineExceeded,
    TransportClosed,
    MaxConnectionsExceeded,
    ProxyUnreachable,
    ToolCallLoopDetected,
    ClientRouterDenied,
    ModelAbuseBanned,
    ShuttingDown,
    RestartForUpdate,
}

impl GatewayErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityUnsupported => "capability_unsupported",
            Self::AmbiguousModel => "ambiguous_model",
            Self::ModelNotFound => "model_not_found",
            Self::UpstreamNotFound => "upstream_not_found",
            Self::ContextLengthExceeded => "context_length_exceeded",
            Self::RequestTooLarge => "request_too_large",
            Self::AccountsUnavailable => "accounts_unavailable",
            Self::AccountsRateLimited => "accounts_rate_limited",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::ProxyPoolCapacityExceeded => "proxy_pool_capacity_exceeded",
            Self::ProxyPoolCooldown => "proxy_pool_cooldown",
            Self::ProxyPoolUnavailable => "proxy_pool_unavailable",
            Self::ProxyPoolUnhealthy => "proxy_pool_unhealthy",
            Self::InvalidPoolLimits => "invalid_pool_limits",
            Self::AdmissionUnavailable => "admission_unavailable",
            Self::SlugReserved => "slug_reserved",
            Self::QuotaExceeded => "quota_exceeded",
            Self::AuthenticationFailed => "authentication_failed",
            Self::PolicyRejected => "policy_rejected",
            Self::InvalidRequest => "invalid_request",
            Self::NotFound => "not_found",
            Self::LinkNotFound => "link_not_found",
            Self::LinkExpired => "link_expired",
            Self::LinkRevoked => "link_revoked",
            Self::LinkDisabled => "link_disabled",
            Self::InvalidSequence => "invalid_sequence",
            Self::InvalidLifecycle => "invalid_lifecycle",
            Self::UnsupportedField => "unsupported_field",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::UpstreamConflict => "upstream_conflict",
            Self::UpstreamUnprocessable => "upstream_unprocessable",
            Self::InternalError => "internal_error",
            Self::TransportUnavailable => "transport_unavailable",
            Self::TunnelSetupFailed => "tunnel_setup_failed",
            Self::PlatformUnavailable => "platform_unavailable",
            Self::TenantCapacityExhausted => "tenant_capacity_exhausted",
            Self::TlsRejected => "tls_rejected",
            Self::ProxyAuthRequired => "proxy_auth_required",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::TransportClosed => "transport_closed",
            Self::MaxConnectionsExceeded => "max_connections_exceeded",
            Self::ProxyUnreachable => "proxy_unreachable",
            Self::ToolCallLoopDetected => "tool_call_loop_detected",
            Self::ClientRouterDenied => "client_router_denied",
            Self::ModelAbuseBanned => "model_abuse_banned",
            Self::ShuttingDown => "shutting_down",
            Self::RestartForUpdate => "restart_for_update",
        }
    }
}

/// Identifies which boundary produced a safe public error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayErrorOrigin {
    Keyla,
    Upstream,
    Network,
}

impl GatewayErrorOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keyla => "keyla",
            Self::Upstream => "upstream",
            Self::Network => "network",
        }
    }
}

/// Error with a client-safe stable code, origin, and sanitized metadata.
#[derive(Debug, Clone)]
pub struct GatewayError {
    pub code: GatewayErrorCode,
    pub status: u16,
    pub message: String,
    pub details: Map<String, Value>,
    pub origin: GatewayErrorOrigin,
}

impl GatewayError {
    pub fn new(
        code: GatewayErrorCode,
        status: u16,
        message: impl Into<String>,
        details: Map<String, Value>,
    ) -> Self {
        Self {
            code,
            status,
            message: message.into(),
            details,
            origin: GatewayErrorOrigin::Keyla,
        }
    }

    pub fn with_origin(mut self, origin: GatewayErrorOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(GatewayErrorCode::InvalidRequest, 400, message, Map::new())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(GatewayErrorCode::NotFound, 404, message, Map::new())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(GatewayErrorCode::InternalError, 500, message, Map::new())
    }

    /// Public client-facing text: `code: explanatory`.
    pub fn public_message(&self) -> String {
        format_public_message(self.code.as_str(), &self.message)
    }

    /// The same public envelope every transport error uses.
    pub fn public_body(&self) -> Value {
        json!({
            "error": {
                "origin": self.origin,
                "code": self.code,
                "message": self.public_message(),
                "details": public_details(&self.details),
            }
        })
    }
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for GatewayError {}

const LEGACY_ORIGIN_LABELS: [&str; 3] = ["Keyla Error:", "Upstream Error:", "Network Error:"];

fn strip_legacy_origin_label(message: &str) -> &str {
    let trimmed = message.trim();
    for prefix in LEGACY_ORIGIN_LABELS {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.trim_start();
        }
    }
    trimmed
}

/// Public client-facing error text: `code: explanatory`.
pub fn format_public_message(code: &str, message: &str) -> String {
    let explanatory = redact_text(strip_legacy_origin_label(message));
    if explanatory.is_empty() {
        return code.to_owned();
    }
    if explanatory == code || explanatory.starts_with(&format!("{code}:")) {
        return explanatory;
    }
    format!("{code}: {explanatory}")
}

static PUBLIC_ERROR_DETAIL_KEYS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    [
        "accountId",
        "accountScope",
        "available",
        "capacity",
        "configuredPools",
        "cooldownReason",
        "currentInflight",
        "credentialEvidence",
        "model",
        "poolId",
        "pools",
        "providerCode",
        "providerId",
        "providerStatus",
        "providerScope",
        "raw",
        "rateLimitScope",
        "reason",
        "reasons",
        "candidate_count",
        "requestId",
        "retryAfterMs",
        "retryAt",
        "safeMessage",
        "scope",
        "status",
        "upstreamRequestId",
        "upstreamStatus",
        "maxInflight",
        "weight",
    ]
    .into_iter()
    .collect()
});

fn sanitize_public_detail(value: &Value, depth: usize) -> Value {
    match value {
        Value::String(text) => Value::String(text.chars().take(500).collect()),
        Value::Array(entries) => {
            if depth >= 3 {
                return Value::String("[redacted]".into());
            }
            Value::Array(
                entries
                    .iter()
                    .take(32)
                    .map(|entry| sanitize_public_detail(entry, depth + 1))
                    .collect(),
            )
        }
        Value::Object(map) => {
            if depth >= 3 {
                return Value::String("[redacted]".into());
            }
            let mut out = Map::new();
            for (key, entry) in map {
                out.insert(key.clone(), sanitize_public_detail(entry, depth + 1));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Bounded allowlisted details suitable for public error envelopes.
pub fn public_details(details: &Map<String, Value>) -> Map<String, Value> {
    let safe = redact_value(&Value::Object(details.clone()));
    let Value::Object(map) = safe else {
        return Map::new();
    };
    map.into_iter()
        .filter(|(key, _)| PUBLIC_ERROR_DETAIL_KEYS.contains(key.as_str()))
        .map(|(key, value)| (key, sanitize_public_detail(&value, 0)))
        .collect()
}

/// The typed rejection required when a semantic feature is unavailable.
pub fn capability_unsupported(capability: &str, extra: Map<String, Value>) -> GatewayError {
    let mut details = Map::new();
    details.insert("capability".into(), Value::String(capability.into()));
    for (key, value) in extra {
        details.insert(key, value);
    }
    GatewayError::new(
        GatewayErrorCode::CapabilityUnsupported,
        400,
        format!("The selected route does not support capability: {capability}"),
        details,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_strings_are_stable() {
        assert_eq!(GatewayErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(
            GatewayErrorCode::RestartForUpdate.as_str(),
            "restart_for_update"
        );
        assert_eq!(
            serde_json::to_value(GatewayErrorCode::ModelNotFound).unwrap(),
            json!("model_not_found")
        );
    }

    #[test]
    fn public_message_is_prefixed_once_and_scrubbed() {
        assert_eq!(
            format_public_message("invalid_request", "missing model"),
            "invalid_request: missing model"
        );
        assert_eq!(
            format_public_message("invalid_request", "invalid_request: missing model"),
            "invalid_request: missing model"
        );
        assert_eq!(
            format_public_message("authentication_failed", "Keyla Error: bad Bearer abc.def"),
            "authentication_failed: bad Bearer [redacted]"
        );
        assert_eq!(format_public_message("not_found", "   "), "not_found");
    }

    #[test]
    fn public_details_drop_unknown_keys_and_bound_values() {
        let mut details = Map::new();
        details.insert("providerId".into(), json!("openai"));
        details.insert("authorization".into(), json!("Bearer secret"));
        details.insert("raw".into(), json!("x".repeat(600)));
        details.insert("unknown".into(), json!("value"));
        let sanitized = public_details(&details);
        assert_eq!(sanitized.get("providerId").unwrap(), "openai");
        assert_eq!(sanitized.get("raw").unwrap().as_str().unwrap().len(), 500);
        assert!(!sanitized.contains_key("authorization"));
        assert!(!sanitized.contains_key("unknown"));
    }

    #[test]
    fn public_details_mask_secret_shaped_strings() {
        let mut details = Map::new();
        details.insert("reason".into(), json!("upstream said Bearer abc123"));
        let sanitized = public_details(&details);
        assert_eq!(
            sanitized.get("reason").unwrap(),
            "upstream said Bearer [redacted]"
        );
    }

    #[test]
    fn origin_is_structured_not_written_into_the_message() {
        let error = GatewayError::new(
            GatewayErrorCode::UpstreamConflict,
            409,
            "conflict",
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Upstream);
        let body = error.public_body();
        assert_eq!(body["error"]["origin"], "upstream");
        assert_eq!(body["error"]["message"], "upstream_conflict: conflict");
        assert_eq!(body["error"]["details"], json!({}));
    }
}
