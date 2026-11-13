//! Per-tenant Prompt Injection policy.
//!
//! The policy is a trusted operator instruction appended to the canonical
//! request before routing. It is deliberately stored in `console_settings`
//! rather than a new table: the preference is tenant-scoped, backed up with the
//! rest of the console configuration, and read through the same cache path.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const PROMPT_MAX_CHARS: usize = 32_000;
const TARGET_MODEL_MAX: usize = 100;
const PLACEMENTS: [&str; 2] = ["developer", "system"];

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

fn server_error(error: impl std::fmt::Display) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("prompt injection settings failed: {error}"),
    )
}

fn defaults() -> Value {
    json!({
        "enabled": false,
        "prompt": "",
        "targetModels": [],
        "placement": "developer",
    })
}

fn settings_response(preferences: &Value, updated_at: Option<DateTime<Utc>>) -> Value {
    let stored = preferences
        .get("promptInjection")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut settings = defaults();
    let object = settings.as_object_mut().expect("defaults object");
    if let Some(enabled) = stored.get("enabled").and_then(Value::as_bool) {
        object.insert("enabled".into(), json!(enabled));
    }
    if let Some(prompt) = stored.get("prompt").and_then(Value::as_str) {
        object.insert("prompt".into(), json!(prompt));
    }
    if let Some(models) = stored.get("targetModels").and_then(Value::as_array) {
        object.insert("targetModels".into(), json!(models));
    }
    if let Some(placement) = stored
        .get("placement")
        .and_then(Value::as_str)
        .filter(|value| PLACEMENTS.contains(value))
    {
        object.insert("placement".into(), json!(placement));
    }
    object.insert(
        "updatedAt".into(),
        json!(
            updated_at
                .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"))
                .to_rfc3339_opts(SecondsFormat::Millis, true)
        ),
    );
    settings
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

/// `GET /console/api/prompt-injection`.
pub async fn get_settings(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
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

fn validate_prompt(value: &Value) -> Result<String, String> {
    let Some(text) = value.as_str() else {
        return Err("prompt must be a string".into());
    };
    if text.chars().count() > PROMPT_MAX_CHARS {
        return Err(format!(
            "prompt must be at most {PROMPT_MAX_CHARS} characters"
        ));
    }
    Ok(text.to_owned())
}

fn validate_models(value: &Value) -> Result<Vec<String>, String> {
    let Some(entries) = value.as_array() else {
        return Err("targetModels must be an array".into());
    };
    if entries.len() > TARGET_MODEL_MAX {
        return Err(format!(
            "targetModels must contain at most {TARGET_MODEL_MAX} entries"
        ));
    }
    let mut models = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(model) = entry
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Err("targetModels entries must be non-empty strings".into());
        };
        if !models.iter().any(|existing| existing == model) {
            models.push(model.to_owned());
        }
    }
    Ok(models)
}

/// `PATCH /console/api/prompt-injection`.
pub async fn update_settings(
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
    let (preferences, _) = match load_preferences(&state, &tenant).await {
        Ok(value) => value,
        Err(error) => return server_error(error),
    };
    let mut stored = preferences
        .get("promptInjection")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| defaults().as_object().cloned().unwrap_or_else(Map::new));
    for (key, value) in patch {
        match key.as_str() {
            "enabled" => {
                let Some(enabled) = value.as_bool() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "enabled must be a boolean",
                    );
                };
                stored.insert(key.clone(), json!(enabled));
            }
            "prompt" => match validate_prompt(value) {
                Ok(prompt) => {
                    stored.insert(key.clone(), json!(prompt));
                }
                Err(message) => {
                    return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
                }
            },
            "targetModels" => match validate_models(value) {
                Ok(models) => {
                    stored.insert(key.clone(), json!(models));
                }
                Err(message) => {
                    return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
                }
            },
            "placement" => {
                let Some(placement) = value.as_str().filter(|value| PLACEMENTS.contains(value))
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "placement must be developer or system",
                    );
                };
                stored.insert(key.clone(), json!(placement));
            }
            _ => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &format!("Unknown prompt injection setting: {key}"),
                );
            }
        }
    }
    let row = sqlx::query(
        "INSERT INTO console_settings (tenant_id, preferences, updated_at)
         VALUES ($1::uuid, jsonb_build_object('promptInjection', $2::jsonb), now())
         ON CONFLICT (tenant_id) DO UPDATE
         SET preferences = console_settings.preferences
                           || jsonb_build_object('promptInjection', $2::jsonb),
             updated_at = now()
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_are_disabled_and_target_every_model() {
        let response = settings_response(&json!({}), None);
        assert_eq!(response["enabled"], json!(false));
        assert_eq!(response["prompt"], json!(""));
        assert_eq!(response["targetModels"], json!([]));
        assert_eq!(response["placement"], json!("developer"));
    }

    #[test]
    fn stored_policy_round_trips_through_the_response_shape() {
        let response = settings_response(
            &json!({
                "promptInjection": {
                    "enabled": true,
                    "prompt": "Be direct.",
                    "targetModels": ["openai/gpt-test"],
                    "placement": "system"
                }
            }),
            None,
        );
        assert_eq!(response["enabled"], json!(true));
        assert_eq!(response["prompt"], json!("Be direct."));
        assert_eq!(response["targetModels"], json!(["openai/gpt-test"]));
        assert_eq!(response["placement"], json!("system"));
    }

    #[test]
    fn prompt_size_and_model_shape_are_bounded() {
        assert!(validate_prompt(&json!("ok")).is_ok());
        assert!(validate_prompt(&json!(123)).is_err());
        assert!(validate_prompt(&json!("x".repeat(PROMPT_MAX_CHARS + 1))).is_err());

        let models = validate_models(&json!(["a", "a", "b"])).unwrap();
        assert_eq!(models, vec!["a".to_owned(), "b".to_owned()]);
        assert!(validate_models(&json!([1])).is_err());
    }
}
