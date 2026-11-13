//! Console API-key domain: list, detail, create, edit, revoke, reorder.
//!
//! Personal and Bansos keys store an HMAC of the bearer secret; share
//! templates store policy only and issue their children elsewhere. Plaintext
//! is returned exactly once, on create or rotation.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const DEFAULT_PREFIX: &str = "rk_";
const SHARE_POPUP_MAX_BYTES: usize = 2 * 1024 * 1024;

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

fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn optional_iso(row: &PgRow, column: &str) -> Option<String> {
    row.try_get::<Option<DateTime<Utc>>, _>(column)
        .ok()
        .flatten()
        .map(iso)
}

fn optional_i32(row: &PgRow, column: &str) -> Option<i32> {
    row.try_get::<Option<i32>, _>(column).ok().flatten()
}

fn optional_i64(row: &PgRow, column: &str) -> Option<i64> {
    row.try_get::<Option<i64>, _>(column).ok().flatten()
}

fn optional_text(row: &PgRow, column: &str) -> Option<String> {
    row.try_get::<Option<String>, _>(column).ok().flatten()
}

fn optional_json(row: &PgRow, column: &str) -> Option<Value> {
    row.try_get::<Option<Value>, _>(column)
        .ok()
        .flatten()
        .filter(|value| !value.is_null())
}

fn key_response(row: &PgRow) -> Value {
    let mut value = json!({
        "id": row.get::<sqlx::types::Uuid, _>("id").to_string(),
        "label": row.get::<String, _>("label"),
        "enabled": row.get::<bool, _>("enabled"),
        "keyMode": row.get::<String, _>("key_mode"),
        "scopes": row.try_get::<Value, _>("scopes").unwrap_or_else(|_| json!([])),
        "createdAt": iso(row.get::<DateTime<Utc>, _>("created_at")),
        "tokensConsumed": row.get::<i64, _>("lifetime_tokens_consumed"),
    });
    let object = value.as_object_mut().expect("object");
    for (field, column) in [
        ("keyPrefix", "key_prefix"),
        ("modelPrefix", "model_prefix"),
        ("notesTitle", "notes_title"),
        ("notesSubtitle", "notes_subtitle"),
        ("notesBody", "notes_body"),
        ("sharePopupImageMime", "share_popup_image_mime"),
        ("sharePopupTitle", "share_popup_title"),
        ("sharePopupBody", "share_popup_body"),
    ] {
        if let Some(found) = optional_text(row, column) {
            object.insert(field.into(), json!(found));
        }
    }
    if let Ok(Some(parent)) = row.try_get::<Option<sqlx::types::Uuid>, _>("parent_key_id") {
        object.insert("parentKeyId".into(), json!(parent.to_string()));
    }
    for (field, column) in [
        ("requestsPerMinute", "requests_per_minute"),
        ("maxConcurrentRequests", "max_concurrent_requests"),
    ] {
        if let Some(found) = optional_i32(row, column) {
            object.insert(field.into(), json!(found));
        }
    }
    for (field, column) in [
        ("dailyTokenLimit", "daily_token_limit"),
        ("monthlyTokenLimit", "monthly_token_limit"),
        ("lifetimeTokenBudget", "lifetime_token_budget"),
    ] {
        if let Some(found) = optional_i64(row, column) {
            object.insert(field.into(), json!(found));
        }
    }
    for (field, column) in [
        ("modelList", "model_list"),
        ("clientRouterDenylist", "client_router_denylist"),
    ] {
        if let Some(found) = optional_json(row, column) {
            object.insert(field.into(), found);
        }
    }
    let mode = row.get::<String, _>("model_access_mode");
    object.insert("modelAccessMode".into(), json!(mode));
    object.insert(
        "sharePopupEnabled".into(),
        json!(row.get::<bool, _>("share_popup_enabled")),
    );
    if let Some(revoked) = optional_iso(row, "revoked_at") {
        object.insert("revokedAt".into(), json!(revoked));
    }
    if let Some(expires) = optional_iso(row, "expires_at") {
        object.insert("expiresAt".into(), json!(expires));
    }
    if let Ok(Some(enabled)) = row.try_get::<Option<bool>, _>("bansos_enabled") {
        object.insert("bansosEnabled".into(), json!(enabled));
    }
    value
}

fn resolve_prefix(raw: Option<&str>) -> String {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_PREFIX)
        .to_owned()
}

fn valid_scope(scope: &str) -> bool {
    keyla_security::TENANT_KEY_SCOPES.contains(&scope)
}

fn parse_scopes(value: Option<&Value>) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(vec!["routing:invoke".into(), "search:invoke".into()]);
    };
    let Some(list) = value.as_array() else {
        return Err("scopes must be an array".into());
    };
    let mut scopes = Vec::with_capacity(list.len());
    for scope in list {
        let Some(scope) = scope.as_str() else {
            return Err("scopes must contain strings".into());
        };
        if !valid_scope(scope) {
            return Err(format!("Scope is not allowed: {scope}"));
        }
        scopes.push(scope.to_owned());
    }
    Ok(scopes)
}

fn parse_limit(body: &Value, name: &str) -> Result<Option<i64>, String> {
    match body.get(name) {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(value) => {
            let Some(number) = value.as_i64() else {
                return Err(format!("{name} must be a finite positive number"));
            };
            if number < 1 {
                return Err(format!("{name} must be a finite positive number"));
            }
            Ok(Some(number))
        }
    }
}

fn parse_i32_limit(body: &Value, name: &str) -> Result<Option<i32>, String> {
    parse_limit(body, name).map(|value| value.map(|number| number.min(i32::MAX as i64) as i32))
}

fn parse_string_list(body: &Value, name: &str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = body.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(Some(Vec::new()));
    }
    let Some(list) = value.as_array() else {
        return Err(format!("{name} must be an array of strings"));
    };
    let mut output = Vec::with_capacity(list.len());
    for entry in list {
        let Some(text) = entry.as_str() else {
            return Err(format!("{name} must be an array of strings"));
        };
        output.push(text.to_owned());
    }
    Ok(Some(output))
}

fn decode_popup_image(value: &Value) -> Result<Option<(Vec<u8>, String)>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let Some(raw) = value.as_str() else {
        return Err("sharePopupImage must be a data URL".into());
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let Some(rest) = raw.strip_prefix("data:") else {
        return Err("sharePopupImage must be a data URL".into());
    };
    let Some((header, payload)) = rest.split_once(",") else {
        return Err("sharePopupImage must be a data URL".into());
    };
    let Some(mime) = header.strip_suffix(";base64") else {
        return Err("sharePopupImage must be base64-encoded".into());
    };
    let mime = mime.to_ascii_lowercase();
    if !["image/png", "image/jpeg", "image/webp", "image/gif"].contains(&mime.as_str()) {
        return Err("sharePopupImage has an unsupported media type".into());
    }
    let bytes = STANDARD
        .decode(payload)
        .map_err(|_| "sharePopupImage is not valid base64".to_owned())?;
    if bytes.len() > SHARE_POPUP_MAX_BYTES {
        return Err("sharePopupImage exceeds the 2 MiB limit".into());
    }
    Ok(Some((bytes, mime)))
}

#[allow(clippy::result_large_err)]
fn generate_secret(prefix: &str) -> Result<(String, String), Response> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = keyla_security::hash_secret(&secret)
        .map_err(|error| server_error(format!("hash: {error}")))?;
    Ok((secret, hash))
}

#[allow(clippy::result_large_err)]
fn encrypt(secret: &str) -> Result<Vec<u8>, Response> {
    keyla_security::encrypt_credential(secret.as_bytes())
        .map_err(|error| server_error(format!("encrypt: {error}")))
}

async fn load_key(
    pool: &sqlx::PgPool,
    tenant: &str,
    key_id: &str,
) -> Result<Option<PgRow>, sqlx::Error> {
    sqlx::query("SELECT * FROM api_keys WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(tenant)
        .bind(key_id)
        .fetch_optional(pool)
        .await
}

/// `GET /console/api/api-keys`.
pub async fn list_keys(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT * FROM api_keys
         WHERE tenant_id = $1::uuid AND revoked_at IS NULL AND parent_key_id IS NULL
         ORDER BY sort_index, created_at, id",
    )
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return server_error(error),
    };
    let data: Vec<Value> = rows.iter().map(key_response).collect();
    console_response(StatusCode::OK, Value::Array(data))
}

/// `GET /console/api/api-keys/{keyId}`.
pub async fn get_key(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    match load_key(&state.pool, &tenant, &key_id).await {
        Ok(Some(row)) => console_response(StatusCode::OK, key_response(&row)),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/api-keys`.
pub async fn create_key(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    if !body.is_object() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Request body must be an object",
        );
    }
    let key_mode = body
        .get("keyMode")
        .and_then(Value::as_str)
        .unwrap_or("personal");
    if !["personal", "share", "bansos"].contains(&key_mode) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_key_mode",
            "keyMode must be personal, share, or bansos",
        );
    }
    if key_mode == "share" && body.get("key").is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_key_mode",
            "Share templates cannot carry a personal key",
        );
    }
    let scopes = match parse_scopes(body.get("scopes")) {
        Ok(scopes) => scopes,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, "invalid_scope", &message),
    };
    let limits = (
        parse_i32_limit(&body, "requestsPerMinute"),
        parse_limit(&body, "dailyTokenLimit"),
        parse_limit(&body, "monthlyTokenLimit"),
        parse_limit(&body, "lifetimeTokenBudget"),
        parse_i32_limit(&body, "maxConcurrentRequests"),
    );
    let (requests_per_minute, daily_limit, monthly_limit, lifetime_budget, max_concurrent) =
        match limits {
            (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e)) => (a, b, c, d, e),
            (Err(message), ..)
            | (_, Err(message), ..)
            | (_, _, Err(message), ..)
            | (_, _, _, Err(message), _)
            | (_, _, _, _, Err(message)) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid_limits", &message);
            }
        };
    let model_list = match parse_string_list(&body, "modelList") {
        Ok(value) => value,
        Err(message) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
        }
    };
    let client_denylist = match parse_string_list(&body, "clientRouterDenylist") {
        Ok(value) => value,
        Err(message) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
        }
    };
    let popup_image = match body.get("sharePopupImage").map(decode_popup_image) {
        None => Ok(None),
        Some(Ok(value)) => Ok(value),
        Some(Err(message)) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_share_popup", &message);
        }
    };
    let (popup_bytes, popup_mime) = match popup_image {
        Ok(value) => value.unzip(),
        Err(response) => return response,
    };
    let model_access_mode = body
        .get("modelAccessMode")
        .and_then(Value::as_str)
        .unwrap_or("whitelist");
    if !["whitelist", "blacklist"].contains(&model_access_mode) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "modelAccessMode must be whitelist or blacklist",
        );
    }
    let prefix = resolve_prefix(body.get("keyPrefix").and_then(Value::as_str));
    let mut secret: Option<String> = None;
    let mut key_hash: Option<String> = None;
    let mut key_encrypted: Option<Vec<u8>> = None;
    if key_mode != "share" {
        let chosen = match body.get("key").and_then(Value::as_str) {
            Some(custom) if !custom.trim().is_empty() => custom.to_owned(),
            Some(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_key",
                    "Custom key must be a non-empty string",
                );
            }
            None => {
                let (generated, hash) = match generate_secret(&prefix) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                key_hash = Some(hash);
                generated
            }
        };
        if key_hash.is_none() {
            match keyla_security::hash_secret(&chosen) {
                Ok(hash) => key_hash = Some(hash),
                Err(error) => return server_error(format!("hash: {error}")),
            }
        }
        key_encrypted = match encrypt(&chosen) {
            Ok(value) => Some(value),
            Err(response) => return response,
        };
        secret = Some(chosen);
    }
    let label = body
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if key_mode == "share" {
                "Share template".to_owned()
            } else {
                "API key".to_owned()
            }
        });
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let notes = |name: &str| body.get(name).and_then(Value::as_str).map(str::to_owned);
    let popup_title = body
        .get("sharePopupTitle")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let popup_body = body
        .get("sharePopupBody")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let share_popup_enabled = body
        .get("sharePopupEnabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let bansos_enabled = body
        .get("bansosEnabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let expires_at = match body.get("expiresAt") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw)) => match DateTime::parse_from_rfc3339(raw) {
            Ok(value) => Some(value.with_timezone(&Utc)),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "expiresAt must be a valid ISO timestamp",
                );
            }
        },
        Some(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "expiresAt must be a valid ISO timestamp",
            );
        }
    };
    let sort_index: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(sort_index) + 1, 0) FROM api_keys WHERE tenant_id = $1::uuid",
    )
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    let inserted = sqlx::query(
        "INSERT INTO api_keys (
            tenant_id, key_hash, key_mode, label, scopes, key_prefix, key_encrypted,
            requests_per_minute, daily_token_limit, monthly_token_limit, lifetime_token_budget,
            max_concurrent_requests, model_access_mode, model_list, client_router_denylist,
            model_prefix, notes_title, notes_subtitle, notes_body,
            share_popup_enabled, share_popup_image, share_popup_image_mime,
            share_popup_title, share_popup_body, sort_index, enabled,
            bansos_enabled, expires_at
         ) VALUES (
            $1::uuid, $2, $3, $4, $5::jsonb, $6, $7,
            $8, $9, $10, $11,
            $12, $13, $14::jsonb, $15::jsonb,
            $16, $17, $18, $19,
            $20, $21, $22,
            $23, $24, $25, $26,
            $27, $28
         ) RETURNING *",
    )
    .bind(&tenant)
    .bind(&key_hash)
    .bind(key_mode)
    .bind(&label)
    .bind(json!(scopes))
    .bind(&prefix)
    .bind(&key_encrypted)
    .bind(requests_per_minute)
    .bind(daily_limit)
    .bind(monthly_limit)
    .bind(lifetime_budget)
    .bind(max_concurrent)
    .bind(model_access_mode)
    .bind(model_list.as_ref().map(|value| json!(value)))
    .bind(client_denylist.as_ref().map(|value| json!(value)))
    .bind(body.get("modelPrefix").and_then(Value::as_str))
    .bind(notes("notesTitle"))
    .bind(notes("notesSubtitle"))
    .bind(notes("notesBody"))
    .bind(share_popup_enabled)
    .bind(&popup_bytes)
    .bind(&popup_mime)
    .bind(&popup_title)
    .bind(&popup_body)
    .bind(sort_index)
    .bind(enabled)
    .bind(bansos_enabled)
    .bind(expires_at)
    .fetch_one(&state.pool)
    .await;
    match inserted {
        Ok(row) => {
            let mut response = key_response(&row);
            if let Some(secret) = secret {
                response
                    .as_object_mut()
                    .expect("object")
                    .insert("secret".into(), json!(secret));
            }
            console_response(StatusCode::OK, response)
        }
        Err(error) => server_error(error),
    }
}

/// `PATCH /console/api/api-keys/{keyId}`.
pub async fn update_key(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let current = match load_key(&state.pool, &tenant, &key_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
        Err(error) => return server_error(error),
    };
    if current
        .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
        .ok()
        .flatten()
        .is_some()
    {
        return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found");
    }
    if current
        .try_get::<Option<String>, _>("parent_key_id")
        .ok()
        .flatten()
        .is_some()
    {
        return error_response(
            StatusCode::CONFLICT,
            "shared_key_managed_by_parent",
            "Edit or revoke this key through its share parent",
        );
    }
    let current_mode: String = current.get("key_mode");
    let next_mode = body
        .get("keyMode")
        .and_then(Value::as_str)
        .unwrap_or(&current_mode)
        .to_owned();
    if !["personal", "share", "bansos"].contains(&next_mode.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_key_mode",
            "keyMode must be personal, share, or bansos",
        );
    }
    let mode_changed = next_mode != current_mode;
    let scopes = match body.get("scopes") {
        None => current
            .try_get::<Value, _>("scopes")
            .ok()
            .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
            .unwrap_or_else(|| vec!["routing:invoke".into()]),
        Some(value) => match parse_scopes(Some(value)) {
            Ok(scopes) => scopes,
            Err(message) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid_scope", &message);
            }
        },
    };
    let mut label: String = current.get("label");
    if let Some(value) = body.get("label").and_then(Value::as_str) {
        let value = value.trim();
        if !value.is_empty() {
            label = value.to_owned();
        }
    }
    let enabled = body
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| current.get("enabled"));
    let pick_i32 = |name: &str, column: &str| -> Result<Option<i32>, String> {
        if body.get(name).is_some() {
            parse_i32_limit(&body, name)
        } else {
            Ok(optional_i32(&current, column))
        }
    };
    let pick_i64 = |name: &str, column: &str| -> Result<Option<i64>, String> {
        if body.get(name).is_some() {
            parse_limit(&body, name)
        } else {
            Ok(optional_i64(&current, column))
        }
    };
    let (requests_per_minute, daily_limit, monthly_limit, lifetime_budget, max_concurrent) = match (
        pick_i32("requestsPerMinute", "requests_per_minute"),
        pick_i64("dailyTokenLimit", "daily_token_limit"),
        pick_i64("monthlyTokenLimit", "monthly_token_limit"),
        pick_i64("lifetimeTokenBudget", "lifetime_token_budget"),
        pick_i32("maxConcurrentRequests", "max_concurrent_requests"),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e)) => (a, b, c, d, e),
        (Err(message), ..)
        | (_, Err(message), ..)
        | (_, _, Err(message), ..)
        | (_, _, _, Err(message), _)
        | (_, _, _, _, Err(message)) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_limits", &message);
        }
    };
    let pick_list = |name: &str, column: &str| -> Result<Option<Vec<String>>, String> {
        if body.get(name).is_some() {
            parse_string_list(&body, name)
        } else {
            Ok(optional_json(&current, column)
                .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok()))
        }
    };
    let model_list = match pick_list("modelList", "model_list") {
        Ok(value) => value,
        Err(message) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
        }
    };
    let client_denylist = match pick_list("clientRouterDenylist", "client_router_denylist") {
        Ok(value) => value,
        Err(message) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
        }
    };
    let model_access_mode = body
        .get("modelAccessMode")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| current.get("model_access_mode"));
    if !["whitelist", "blacklist"].contains(&model_access_mode.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "modelAccessMode must be whitelist or blacklist",
        );
    }
    let text_field = |name: &str, column: &str| -> Option<String> {
        if let Some(value) = body.get(name) {
            return value.as_str().map(str::to_owned);
        }
        optional_text(&current, column)
    };
    let model_prefix = text_field("modelPrefix", "model_prefix");
    let notes_title = text_field("notesTitle", "notes_title");
    let notes_subtitle = text_field("notesSubtitle", "notes_subtitle");
    let notes_body = text_field("notesBody", "notes_body");
    let popup_title = text_field("sharePopupTitle", "share_popup_title");
    let popup_body = text_field("sharePopupBody", "share_popup_body");
    let share_popup_enabled = body
        .get("sharePopupEnabled")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| current.get("share_popup_enabled"));
    let bansos_enabled = body
        .get("bansosEnabled")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            current
                .try_get::<bool, _>("bansos_enabled")
                .unwrap_or(false)
        });
    let expires_at = match body.get("expiresAt") {
        None => current
            .try_get::<Option<DateTime<Utc>>, _>("expires_at")
            .ok()
            .flatten(),
        Some(Value::Null) => None,
        Some(Value::String(raw)) => match DateTime::parse_from_rfc3339(raw) {
            Ok(value) => Some(value.with_timezone(&Utc)),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "expiresAt must be a valid ISO timestamp",
                );
            }
        },
        Some(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "expiresAt must be a valid ISO timestamp",
            );
        }
    };
    let (popup_bytes, popup_mime, clear_image) = match body.get("sharePopupImage") {
        None => (
            current
                .try_get::<Option<Vec<u8>>, _>("share_popup_image")
                .ok()
                .flatten(),
            optional_text(&current, "share_popup_image_mime"),
            false,
        ),
        Some(value) => match decode_popup_image(value) {
            Ok(Some((bytes, mime))) => (Some(bytes), Some(mime), false),
            Ok(None) => (None, None, true),
            Err(message) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid_share_popup", &message);
            }
        },
    };
    let current_prefix = optional_text(&current, "key_prefix");
    let prefix = resolve_prefix(
        body.get("keyPrefix")
            .and_then(Value::as_str)
            .or(current_prefix.as_deref()),
    );
    let prefix_changed =
        body.get("keyPrefix").is_some() && Some(prefix.as_str()) != current_prefix.as_deref();
    let custom_key = body.get("key").and_then(Value::as_str);
    let mut secret: Option<String> = None;
    let (key_hash, key_encrypted) = if next_mode == "share" {
        (None, None)
    } else if mode_changed || prefix_changed || custom_key.is_some() {
        let chosen = match custom_key {
            Some(custom) if !custom.trim().is_empty() => custom.to_owned(),
            Some(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_key",
                    "Custom key must be a non-empty string",
                );
            }
            None => {
                let (generated, _) = match generate_secret(&prefix) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                generated
            }
        };
        let hash = match keyla_security::hash_secret(&chosen) {
            Ok(hash) => hash,
            Err(error) => return server_error(format!("hash: {error}")),
        };
        let encrypted = match encrypt(&chosen) {
            Ok(value) => value,
            Err(response) => return response,
        };
        secret = Some(chosen);
        (Some(hash), Some(encrypted))
    } else {
        (
            current
                .try_get::<Option<String>, _>("key_hash")
                .ok()
                .flatten(),
            current
                .try_get::<Option<Vec<u8>>, _>("key_encrypted")
                .ok()
                .flatten(),
        )
    };
    let updated = sqlx::query(
        "UPDATE api_keys SET
            key_mode = $3, key_hash = $4, key_encrypted = $5, key_prefix = $6,
            label = $7, enabled = $8, scopes = $9::jsonb,
            requests_per_minute = $10, daily_token_limit = $11, monthly_token_limit = $12,
            lifetime_token_budget = $13, max_concurrent_requests = $14,
            model_access_mode = $15, model_list = $16::jsonb, client_router_denylist = $17::jsonb,
            model_prefix = $18, notes_title = $19, notes_subtitle = $20, notes_body = $21,
            share_popup_enabled = $22, share_popup_title = $23, share_popup_body = $24,
            share_popup_image = $25, share_popup_image_mime = $26,
            bansos_enabled = $27, expires_at = $28
         WHERE tenant_id = $1::uuid AND id = $2::uuid
         RETURNING *",
    )
    .bind(&tenant)
    .bind(&key_id)
    .bind(&next_mode)
    .bind(&key_hash)
    .bind(&key_encrypted)
    .bind(&prefix)
    .bind(&label)
    .bind(enabled)
    .bind(json!(scopes))
    .bind(requests_per_minute)
    .bind(daily_limit)
    .bind(monthly_limit)
    .bind(lifetime_budget)
    .bind(max_concurrent)
    .bind(&model_access_mode)
    .bind(model_list.as_ref().map(|value| json!(value)))
    .bind(client_denylist.as_ref().map(|value| json!(value)))
    .bind(&model_prefix)
    .bind(&notes_title)
    .bind(&notes_subtitle)
    .bind(&notes_body)
    .bind(share_popup_enabled)
    .bind(&popup_title)
    .bind(&popup_body)
    .bind(if clear_image { None } else { popup_bytes })
    .bind(if clear_image { None } else { popup_mime })
    .bind(bansos_enabled)
    .bind(expires_at)
    .fetch_one(&state.pool)
    .await;
    match updated {
        Ok(row) => {
            let mut response = key_response(&row);
            if let Some(secret) = secret {
                response
                    .as_object_mut()
                    .expect("object")
                    .insert("secret".into(), json!(secret));
            }
            console_response(StatusCode::OK, response)
        }
        Err(error) => server_error(error),
    }
}

/// `DELETE /console/api/api-keys/{keyId}` — revokes the key.
pub async fn revoke_key(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let revoked = sqlx::query(
        "UPDATE api_keys SET revoked_at = now()
         WHERE tenant_id = $1::uuid AND id = $2::uuid AND revoked_at IS NULL
         RETURNING id",
    )
    .bind(&tenant)
    .bind(&key_id)
    .fetch_optional(&state.pool)
    .await;
    match revoked {
        Ok(Some(_)) => console_response(StatusCode::OK, json!({"success": true})),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/api-keys/reorder`.
pub async fn reorder_keys(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(key_ids) = body.get("keyIds").and_then(Value::as_array) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "keyIds must be an array",
        );
    };
    let known: Vec<String> = match sqlx::query_scalar(
        "SELECT id::text FROM api_keys
         WHERE tenant_id = $1::uuid AND revoked_at IS NULL AND parent_key_id IS NULL",
    )
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(ids) => ids,
        Err(error) => return server_error(error),
    };
    let mut seen = std::collections::HashSet::new();
    for value in key_ids {
        let Some(id) = value.as_str() else {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                "keyIds must contain strings",
            );
        };
        if !known.iter().any(|known| known == id) {
            return error_response(
                StatusCode::NOT_FOUND,
                "key_not_found",
                &format!("Key not found: {id}"),
            );
        }
        if !seen.insert(id.to_owned()) {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                &format!("Duplicate key id: {id}"),
            );
        }
    }
    if seen.len() != known.len() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "Reorder must list every key exactly once",
        );
    }
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error(error),
    };
    for (index, value) in key_ids.iter().enumerate() {
        let id = value.as_str().unwrap_or_default();
        if let Err(error) = sqlx::query(
            "UPDATE api_keys SET sort_index = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid",
        )
        .bind(&tenant)
        .bind(id)
        .bind(index as i32)
        .execute(&mut *transaction)
        .await
        {
            return server_error(error);
        }
    }
    if let Err(error) = transaction.commit().await {
        return server_error(error);
    }
    console_response(StatusCode::OK, json!({"success": true}))
}

// --- Share links and credential rotation ------------------------------------

use sha2::{Digest, Sha256};

fn hash_share_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn request_origin(headers: &HeaderMap) -> String {
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    format!("{scheme}://{host}")
}

fn share_response(
    id: &str,
    origin: &str,
    token: &str,
    kind: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Value {
    json!({
        "id": id,
        "url": format!("{origin}/share/{token}"),
        "token": token,
        "kind": kind,
        "expiresAt": expires_at.map(iso),
    })
}

async fn current_share_row(
    pool: &sqlx::PgPool,
    key_id: &str,
) -> Result<Option<PgRow>, sqlx::Error> {
    sqlx::query(
        "SELECT id::text AS id, kind, expires_at, token_encrypted
         FROM share_links WHERE api_key_id = $1::uuid AND active = true
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(key_id)
    .fetch_optional(pool)
    .await
}

/// `GET /console/api/api-keys/{keyId}/share`.
pub async fn get_share(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let key = match load_key(&state.pool, &tenant, &key_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
        Err(error) => return server_error(error),
    };
    if key
        .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
        .ok()
        .flatten()
        .is_some()
    {
        return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found");
    }
    let row = match current_share_row(&state.pool, &key_id).await {
        Ok(row) => row,
        Err(error) => return server_error(error),
    };
    let Some(row) = row else {
        return console_response(StatusCode::OK, Value::Null);
    };
    let Some(ciphertext) = row
        .try_get::<Option<Vec<u8>>, _>("token_encrypted")
        .ok()
        .flatten()
    else {
        return console_response(StatusCode::OK, Value::Null);
    };
    let token = match keyla_security::decrypt_credential_to_string(&ciphertext) {
        Ok(token) => token,
        Err(_) => return console_response(StatusCode::OK, Value::Null),
    };
    console_response(
        StatusCode::OK,
        share_response(
            &row.get::<String, _>("id"),
            &request_origin(&headers),
            &token,
            &row.get::<String, _>("kind"),
            row.try_get::<Option<DateTime<Utc>>, _>("expires_at")
                .ok()
                .flatten(),
        ),
    )
}

/// `POST /console/api/api-keys/{keyId}/share`.
pub async fn share_key(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let key = match load_key(&state.pool, &tenant, &key_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
        Err(error) => return server_error(error),
    };
    if key
        .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
        .ok()
        .flatten()
        .is_some()
    {
        return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found");
    }
    if key
        .try_get::<Option<sqlx::types::Uuid>, _>("parent_key_id")
        .ok()
        .flatten()
        .is_some()
    {
        return error_response(
            StatusCode::CONFLICT,
            "key_not_share_parent",
            "Only a top-level key can carry a handoff link",
        );
    }
    let regenerate = body
        .get("regenerate")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let expires_at = match body.get("expiresAt") {
        Some(Value::Null) | None => None,
        Some(Value::String(raw)) => match DateTime::parse_from_rfc3339(raw) {
            Ok(value) => Some(value.with_timezone(&Utc)),
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_share_expiry",
                    "expiresAt must be a valid ISO timestamp",
                );
            }
        },
        Some(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_share_expiry",
                "expiresAt must be a valid ISO timestamp",
            );
        }
    };
    let origin = request_origin(&headers);
    if !regenerate {
        if let Ok(Some(row)) = current_share_row(&state.pool, &key_id).await {
            if let Some(ciphertext) = row
                .try_get::<Option<Vec<u8>>, _>("token_encrypted")
                .ok()
                .flatten()
            {
                if let Ok(token) = keyla_security::decrypt_credential_to_string(&ciphertext) {
                    return console_response(
                        StatusCode::OK,
                        share_response(
                            &row.get::<String, _>("id"),
                            &origin,
                            &token,
                            &row.get::<String, _>("kind"),
                            row.try_get::<Option<DateTime<Utc>>, _>("expires_at")
                                .ok()
                                .flatten(),
                        ),
                    );
                }
            }
        }
    }
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let token_hash = hash_share_token(&token);
    let encrypted = match encrypt(&token) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let kind = if key.get::<String, _>("key_mode") == "share" {
        "enroll"
    } else {
        "handoff"
    };
    let existing = current_share_row(&state.pool, &key_id).await.ok().flatten();
    let saved = match existing {
        Some(row) => {
            let id: String = row.get("id");
            sqlx::query(
                "UPDATE share_links SET token_hash = $2, token_encrypted = $3,
                    expires_at = $4, last_viewed_at = NULL
                 WHERE id = $1::uuid RETURNING id::text AS id, kind, expires_at",
            )
            .bind(&id)
            .bind(&token_hash)
            .bind(&encrypted)
            .bind(expires_at)
            .fetch_one(&state.pool)
            .await
        }
        None => sqlx::query(
            "INSERT INTO share_links (api_key_id, token_hash, token_encrypted, kind, expires_at)
                 VALUES ($1::uuid, $2, $3, $4, $5)
                 RETURNING id::text AS id, kind, expires_at",
        )
        .bind(&key_id)
        .bind(&token_hash)
        .bind(&encrypted)
        .bind(kind)
        .bind(expires_at)
        .fetch_one(&state.pool)
        .await,
    };
    match saved {
        Ok(row) => console_response(
            StatusCode::OK,
            share_response(
                &row.get::<String, _>("id"),
                &origin,
                &token,
                &row.get::<String, _>("kind"),
                row.try_get::<Option<DateTime<Utc>>, _>("expires_at")
                    .ok()
                    .flatten(),
            ),
        ),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/api-keys/{keyId}/regenerate`.
pub async fn regenerate_key(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let current = match load_key(&state.pool, &tenant, &key_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
        Err(error) => return server_error(error),
    };
    if current.get::<String, _>("key_mode") != "personal" {
        return error_response(
            StatusCode::CONFLICT,
            "key_not_personal",
            "Only a personal key can be regenerated; rotate a share template's link instead",
        );
    }
    let prefix = resolve_prefix(optional_text(&current, "key_prefix").as_deref());
    let (secret, hash) = match generate_secret(&prefix) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let encrypted = match encrypt(&secret) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let updated = sqlx::query(
        "UPDATE api_keys SET key_hash = $3, key_encrypted = $4, key_prefix = $5
         WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING id::text AS id",
    )
    .bind(&tenant)
    .bind(&key_id)
    .bind(&hash)
    .bind(&encrypted)
    .bind(&prefix)
    .fetch_optional(&state.pool)
    .await;
    if let Err(error) = updated {
        return server_error(error);
    }
    if updated.ok().flatten().is_none() {
        return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found");
    }
    let origin = request_origin(&headers);
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let token_hash = hash_share_token(&token);
    let encrypted_token = match encrypt(&token) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let existing = current_share_row(&state.pool, &key_id).await.ok().flatten();
    let share = match existing {
        Some(row) => {
            let id: String = row.get("id");
            sqlx::query(
                "UPDATE share_links SET token_hash = $2, token_encrypted = $3,
                    expires_at = NULL, kind = 'handoff', last_viewed_at = NULL
                 WHERE id = $1::uuid RETURNING id::text AS id, kind, expires_at",
            )
            .bind(&id)
            .bind(&token_hash)
            .bind(&encrypted_token)
            .fetch_one(&state.pool)
            .await
            .map(|row| {
                share_response(
                    &row.get::<String, _>("id"),
                    &origin,
                    &token,
                    &row.get::<String, _>("kind"),
                    None,
                )
            })
        }
        None => sqlx::query(
            "INSERT INTO share_links (api_key_id, token_hash, token_encrypted, kind, expires_at)
             VALUES ($1::uuid, $2, $3, 'handoff', NULL)
             RETURNING id::text AS id, kind, expires_at",
        )
        .bind(&key_id)
        .bind(&token_hash)
        .bind(&encrypted_token)
        .fetch_one(&state.pool)
        .await
        .map(|row| {
            share_response(
                &row.get::<String, _>("id"),
                &origin,
                &token,
                &row.get::<String, _>("kind"),
                None,
            )
        }),
    };
    match share {
        Ok(share) => console_response(StatusCode::OK, json!({"secret": secret, "share": share})),
        Err(error) => server_error(error),
    }
}

// --- Share link administration and recipient telemetry ---------------------

fn json_iso(value: Option<DateTime<Utc>>) -> Value {
    match value {
        Some(value) => json!(iso(value)),
        None => Value::Null,
    }
}

/// `GET /console/api/api-keys/{keyId}/shares`.
pub async fn list_shares(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let owns: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM api_keys WHERE id = $1::uuid AND tenant_id = $2::uuid)",
    )
    .bind(&key_id)
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if !owns {
        return error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found");
    }
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, api_key_id::text AS api_key_id, kind, active,
                created_at, expires_at, last_viewed_at
         FROM share_links WHERE api_key_id = $1::uuid ORDER BY created_at DESC",
    )
    .bind(&key_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "apiKeyId": row.get::<String, _>("api_key_id"),
                "kind": row.get::<String, _>("kind"),
                "active": row.get::<bool, _>("active"),
                "createdAt": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
                "expiresAt": json_iso(row.try_get::<Option<DateTime<Utc>>, _>("expires_at").ok().flatten()),
                "lastViewedAt": json_iso(row.try_get::<Option<DateTime<Utc>>, _>("last_viewed_at").ok().flatten()),
            })
        })
        .collect();
    console_response(StatusCode::OK, Value::Array(data))
}

/// `DELETE /console/api/api-keys/{keyId}/shares/{shareId}`.
pub async fn revoke_share(
    State(state): State<ConsoleState>,
    Path((key_id, share_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let updated = sqlx::query(
        "UPDATE share_links SET active = false
         WHERE id = $2::uuid AND active = true
           AND api_key_id IN (SELECT id FROM api_keys WHERE id = $1::uuid AND tenant_id = $3::uuid)
         RETURNING id",
    )
    .bind(&key_id)
    .bind(&share_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => console_response(StatusCode::OK, json!({"success": true})),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "share_not_found",
            "Share link not found",
        ),
        Err(error) => server_error(error),
    }
}

/// `GET /console/api/api-keys/{keyId}/share-popup-image`.
pub async fn share_popup_image(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let row = sqlx::query(
        "SELECT share_popup_image, share_popup_image_mime FROM api_keys
         WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(&key_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    match row {
        Some(row) => {
            let image = row
                .try_get::<Option<Vec<u8>>, _>("share_popup_image")
                .ok()
                .flatten();
            let mime = row
                .try_get::<Option<String>, _>("share_popup_image_mime")
                .ok()
                .flatten();
            match (image, mime) {
                (Some(bytes), Some(mime)) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", mime)
                    .header("cache-control", "private, max-age=300")
                    .header("x-content-type-options", "nosniff")
                    .body(axum::body::Body::from(bytes))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                _ => error_response(
                    StatusCode::NOT_FOUND,
                    "key_not_found",
                    "This key has no popup image",
                ),
            }
        }
        None => error_response(StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
    }
}

/// `GET /console/api/api-keys/{keyId}/shared-keys`.
pub async fn list_shared_keys(
    State(state): State<ConsoleState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let parent = sqlx::query(
        "SELECT id, key_mode FROM api_keys
         WHERE id = $1::uuid AND tenant_id = $2::uuid AND revoked_at IS NULL AND parent_key_id IS NULL",
    )
    .bind(&key_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(parent) = parent else {
        return error_response(
            StatusCode::NOT_FOUND,
            "key_not_found",
            "Share template not found",
        );
    };
    if parent.get::<String, _>("key_mode") != "share" {
        return error_response(
            StatusCode::NOT_FOUND,
            "key_not_found",
            "Share template not found",
        );
    }
    let children: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, label, key_prefix, issued_client_ip, created_at, revoked_at
         FROM api_keys WHERE parent_key_id = $1::uuid ORDER BY created_at DESC",
    )
    .bind(&key_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let ids: Vec<String> = children.iter().map(|row| row.get("id")).collect();
    type LifetimeTotals = (i64, i64, i64, i64, Option<DateTime<Utc>>);
    let totals: std::collections::HashMap<String, LifetimeTotals> = if ids.is_empty() {
        Default::default()
    } else {
        let rows: Vec<PgRow> = sqlx::query(
            "SELECT entity_id::text AS entity_id, requests::bigint AS requests,
                        errors::bigint AS errors, input_tokens::bigint AS input_tokens,
                        output_tokens::bigint AS output_tokens, last_used_at
                 FROM telemetry_usage_totals WHERE tenant_id = $1::uuid
                   AND identity_type = 'api_key' AND entity_id::text = ANY($2)",
        )
        .bind(&tenant)
        .bind(&ids)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        rows.iter()
            .map(|row| {
                (
                    row.get::<String, _>("entity_id"),
                    (
                        row.get("requests"),
                        row.get("errors"),
                        row.get("input_tokens"),
                        row.get("output_tokens"),
                        row.try_get::<Option<DateTime<Utc>>, _>("last_used_at")
                            .ok()
                            .flatten(),
                    ),
                )
            })
            .collect()
    };
    let today: std::collections::HashMap<String, (i64, i64, i64, i64)> = if ids.is_empty() {
        Default::default()
    } else {
        let rows: Vec<PgRow> = sqlx::query(
            "SELECT api_key_id::text AS id, count(*)::bigint AS requests,
                    count(*) FILTER (WHERE status = 'failed')::bigint AS errors,
                    coalesce(sum(input_tokens),0)::bigint AS input_tokens,
                    coalesce(sum(output_tokens),0)::bigint AS output_tokens
             FROM telemetry_events WHERE tenant_id = $1::uuid AND api_key_id::text = ANY($2)
               AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
             GROUP BY api_key_id",
        )
        .bind(&tenant)
        .bind(&ids)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        rows.iter()
            .map(|row| {
                (
                    row.get::<String, _>("id"),
                    (
                        row.get("requests"),
                        row.get("errors"),
                        row.get("input_tokens"),
                        row.get("output_tokens"),
                    ),
                )
            })
            .collect()
    };
    let usage = |row: (i64, i64, i64, i64)| {
        json!({
            "requests": row.0, "errors": row.1, "inputTokens": row.2,
            "outputTokens": row.3, "totalTokens": row.2 + row.3,
        })
    };
    let data: Vec<Value> = children
        .iter()
        .map(|row| {
            let id: String = row.get("id");
            let total = totals.get(&id).copied().unwrap_or((0, 0, 0, 0, None));
            let day = today.get(&id).copied().unwrap_or((0, 0, 0, 0));
            json!({
                "id": id,
                "label": row.get::<String, _>("label"),
                "keyPrefix": row.try_get::<Option<String>, _>("key_prefix").ok().flatten(),
                "issuedClientIp": row.try_get::<Option<String>, _>("issued_client_ip").ok().flatten(),
                "createdAt": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
                "revokedAt": json_iso(row.try_get::<Option<DateTime<Utc>>, _>("revoked_at").ok().flatten()),
                "allTime": usage((total.0, total.1, total.2, total.3)),
                "today": usage(day),
                "lastUsedAt": json_iso(total.4),
            })
        })
        .collect();
    console_response(StatusCode::OK, Value::Array(data)).into_response()
}

/// `GET /console/api/api-keys/{keyId}/shared-keys/{childKeyId}/activity`.
pub async fn shared_key_activity(
    State(state): State<ConsoleState>,
    Path((key_id, child_key_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM api_keys
         WHERE id = $1::uuid AND parent_key_id = $2::uuid AND tenant_id = $3::uuid)",
    )
    .bind(&child_key_id)
    .bind(&key_id)
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if !owned {
        return error_response(
            StatusCode::NOT_FOUND,
            "key_not_found",
            "Shared key not found",
        );
    }
    let model_rows: Vec<PgRow> = sqlx::query(
        "SELECT provider_id, requested_model AS model_id,
                count(*)::bigint AS retained_requests,
                count(*) FILTER (WHERE status = 'failed')::bigint AS retained_errors,
                coalesce(sum(input_tokens + output_tokens),0)::bigint AS retained_tokens,
                count(*) FILTER (WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC'))::bigint AS today_requests,
                count(*) FILTER (WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AND status = 'failed')::bigint AS today_errors,
                coalesce(sum(input_tokens + output_tokens) FILTER (WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')),0)::bigint AS today_tokens
         FROM telemetry_events WHERE tenant_id = $1::uuid AND api_key_id = $2::uuid
         GROUP BY provider_id, requested_model ORDER BY count(*) DESC LIMIT 50",
    )
    .bind(&tenant)
    .bind(&child_key_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let models: Vec<Value> = model_rows
        .iter()
        .map(|row| {
            json!({
                "providerId": row.try_get::<Option<String>, _>("provider_id").ok().flatten(),
                "modelId": row.try_get::<Option<String>, _>("model_id").ok().flatten().unwrap_or_else(|| "unknown".into()),
                "retainedRequests": row.get::<i64, _>("retained_requests"),
                "retainedErrors": row.get::<i64, _>("retained_errors"),
                "retainedTokens": row.get::<i64, _>("retained_tokens"),
                "todayRequests": row.get::<i64, _>("today_requests"),
                "todayErrors": row.get::<i64, _>("today_errors"),
                "todayTokens": row.get::<i64, _>("today_tokens"),
            })
        })
        .collect();
    let request_rows: Vec<PgRow> = sqlx::query(
        "SELECT request_id::text AS request_id, created_at, provider_id, requested_model,
                status::text AS status, http_status, error_category, error_origin,
                client_ip, input_tokens, output_tokens
         FROM telemetry_events WHERE tenant_id = $1::uuid AND api_key_id = $2::uuid
         ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&tenant)
    .bind(&child_key_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let requests: Vec<Value> = request_rows
        .iter()
        .map(|row| {
            let input = row.try_get::<Option<i32>, _>("input_tokens").ok().flatten().unwrap_or(0);
            let output = row.try_get::<Option<i32>, _>("output_tokens").ok().flatten().unwrap_or(0);
            json!({
                "requestId": row.get::<String, _>("request_id"),
                "startedAt": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
                "providerId": row.try_get::<Option<String>, _>("provider_id").ok().flatten(),
                "modelId": row.try_get::<Option<String>, _>("requested_model").ok().flatten(),
                "status": row.get::<String, _>("status"),
                "httpStatus": row.try_get::<Option<i32>, _>("http_status").ok().flatten(),
                "errorCategory": row.try_get::<Option<String>, _>("error_category").ok().flatten(),
                "errorOrigin": row.try_get::<Option<String>, _>("error_origin").ok().flatten(),
                "clientIp": row.try_get::<Option<String>, _>("client_ip").ok().flatten(),
                "inputTokens": input,
                "outputTokens": output,
                "totalTokens": input + output,
            })
        })
        .collect();
    console_response(
        StatusCode::OK,
        json!({"models": models, "requests": requests}),
    )
}
