//! Runtime settings: per-tenant preference bag with validated literal unions.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const REASONING_SUMMARIES: [&str; 3] = ["auto", "concise", "detailed"];
const PAYLOAD_MODES: [&str; 3] = ["full", "metadata", "none"];
const PAYLOAD_DEPTHS: [&str; 3] = ["minimum", "moderate", "maximum"];
const PRIVACY_MODES: [&str; 2] = ["masked", "full"];
const PONYTAIL_LEVELS: [&str; 3] = ["lite", "full", "ultra"];
const RTK_LEVELS: [&str; 3] = ["lite", "full", "ultra"];

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

fn server_error(error: impl std::fmt::Display) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("database error: {error}"),
    )
}

fn string_pref<'a>(
    prefs: &'a Map<String, Value>,
    key: &str,
    allowed: &[&str],
    fallback: &'a str,
) -> &'a str {
    prefs
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| allowed.contains(value))
        .unwrap_or(fallback)
}

fn settings_response(preferences: &Value, updated_at: Option<DateTime<Utc>>) -> Value {
    let prefs = preferences.as_object().cloned().unwrap_or_default();
    json!({
        "redisBackendActual": "memory",
        "tenantConcurrencyLimit": prefs.get("tenantConcurrencyLimit").and_then(Value::as_i64),
        "thinkingNormalizationEnabled": prefs.get("thinkingNormalizationEnabled").and_then(Value::as_bool).unwrap_or(false),
        "responsesReasoningSummary": string_pref(&prefs, "responsesReasoningSummary", &REASONING_SUMMARIES, "detailed"),
        "telemetryPayloads": string_pref(&prefs, "telemetryPayloads", &PAYLOAD_MODES, "metadata"),
        "telemetryPayloadDepth": match prefs.get("telemetryPayloadDepth").and_then(Value::as_str) {
            Some(value) if PAYLOAD_DEPTHS.contains(&value) => value,
            Some("medium") => "minimum",
            Some("high") => "moderate",
            Some("full") => "maximum",
            _ => "minimum",
        },
        "privacyMode": string_pref(&prefs, "privacyMode", &PRIVACY_MODES, "masked"),
        "rtkPruneEnabled": prefs.get("rtkPruneEnabled").and_then(Value::as_bool).unwrap_or(false),
        "rtkPruneLevel": string_pref(&prefs, "rtkPruneLevel", &RTK_LEVELS, "full"),
        "ponyTailEnabled": prefs.get("ponyTailEnabled").and_then(Value::as_bool).unwrap_or(false),
        "ponyTailLevel": string_pref(&prefs, "ponyTailLevel", &PONYTAIL_LEVELS, "full"),
        "updatedAt": updated_at
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"))
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

async fn load_preferences(
    state: &ConsoleState,
    tenant: &str,
) -> Result<(Value, Option<DateTime<Utc>>), sqlx::Error> {
    let row = sqlx::query(
        "SELECT preferences, updated_at FROM console_settings WHERE tenant_id = $1::uuid",
    )
    .bind(tenant)
    .fetch_optional(&state.pool)
    .await?;
    Ok(match row {
        Some(row) => (
            row.try_get::<Value, _>("preferences")
                .unwrap_or_else(|_| json!({})),
            row.try_get::<DateTime<Utc>, _>("updated_at").ok(),
        ),
        None => (json!({}), None),
    })
}

/// `GET /console/api/settings/runtime`.
pub async fn get_runtime(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    match load_preferences(&state, &tenant).await {
        Ok((preferences, updated_at)) => {
            console_response(StatusCode::OK, settings_response(&preferences, updated_at))
        }
        Err(error) => server_error(error),
    }
}

/// `PATCH /console/api/settings/runtime`.
pub async fn update_runtime(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(patch) = body.as_object() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Request body must be an object",
        );
    };
    let mut stored = Map::new();
    for (key, value) in patch {
        match key.as_str() {
            "tenantConcurrencyLimit" => {
                if value.is_null() {
                    stored.insert(key.clone(), Value::Null);
                } else if let Some(number) = value.as_i64() {
                    if number < 1 {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "tenantConcurrencyLimit must be a positive integer or null",
                        );
                    }
                    stored.insert(key.clone(), json!(number));
                } else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "tenantConcurrencyLimit must be a positive integer or null",
                    );
                }
            }
            "thinkingNormalizationEnabled" | "rtkPruneEnabled" | "ponyTailEnabled" => {
                let Some(flag) = value.as_bool() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        &format!("{key} must be a boolean"),
                    );
                };
                stored.insert(key.clone(), json!(flag));
            }
            "responsesReasoningSummary"
            | "telemetryPayloads"
            | "telemetryPayloadDepth"
            | "privacyMode"
            | "rtkPruneLevel"
            | "ponyTailLevel" => {
                let allowed: &[&str] = match key.as_str() {
                    "responsesReasoningSummary" => &REASONING_SUMMARIES,
                    "telemetryPayloads" => &PAYLOAD_MODES,
                    "telemetryPayloadDepth" => &PAYLOAD_DEPTHS,
                    "privacyMode" => &PRIVACY_MODES,
                    "rtkPruneLevel" => &RTK_LEVELS,
                    _ => &PONYTAIL_LEVELS,
                };
                let Some(text) = value.as_str() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        &format!("Invalid {key}"),
                    );
                };
                if !allowed.contains(&text) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        &format!("Invalid {key}"),
                    );
                }
                stored.insert(key.clone(), json!(text));
            }
            _ => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &format!("Unknown setting: {key}"),
                );
            }
        }
    }
    let row = sqlx::query(
        "INSERT INTO console_settings (tenant_id, preferences, updated_at)
         VALUES ($1::uuid, $2::jsonb, now())
         ON CONFLICT (tenant_id) DO UPDATE
         SET preferences = console_settings.preferences || $2::jsonb, updated_at = now()
         RETURNING preferences, updated_at",
    )
    .bind(&tenant)
    .bind(Value::Object(stored))
    .fetch_one(&state.pool)
    .await;
    match row {
        Ok(row) => console_response(
            StatusCode::OK,
            settings_response(
                &row.try_get::<Value, _>("preferences")
                    .unwrap_or_else(|_| json!({})),
                row.try_get::<DateTime<Utc>, _>("updated_at").ok(),
            ),
        ),
        Err(error) => server_error(error),
    }
}
