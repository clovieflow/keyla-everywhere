//! CLI tool registry, host status probe, and per-key model mappings.
//!
//! Static metadata is generated from the shipped registry and embedded, so the
//! Rust console serves the same catalog the dashboard expects.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const REGISTRY_JSON: &str = include_str!("../assets/cli-tools-registry.json");

fn registry() -> &'static Vec<Value> {
    static REGISTRY: OnceLock<Vec<Value>> = OnceLock::new();
    REGISTRY.get_or_init(|| serde_json::from_str(REGISTRY_JSON).unwrap_or_default())
}

fn tool(tool_id: &str) -> Option<&'static Value> {
    registry()
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(tool_id))
}

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

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_owned()
}

fn status_for(entry: &Value) -> Value {
    let tool_id = entry.get("id").and_then(Value::as_str).unwrap_or("");
    let settings = entry.get("settingsFile").and_then(Value::as_str);
    let path = settings.map(expand_home);
    let installed = path
        .as_ref()
        .map(|path| std::path::Path::new(path).exists())
        .unwrap_or(false);
    let mut configured = false;
    let mut current_endpoint = None;
    if installed {
        if let Some(path) = &path {
            if let Ok(content) = std::fs::read_to_string(path) {
                if content.contains("/v1") && content.to_ascii_lowercase().contains("keyla") {
                    configured = true;
                }
                if let Some(index) = content.find("http://").or_else(|| content.find("https://")) {
                    let tail = &content[index..];
                    let end = tail
                        .find(|character: char| {
                            character.is_whitespace() || character == '"' || character == '\''
                        })
                        .unwrap_or(tail.len().min(200));
                    current_endpoint = Some(tail[..end].to_owned());
                }
            }
        }
    }
    json!({
        "toolId": tool_id,
        "installed": installed,
        "configured": configured,
        "settingsPath": path,
        "currentEndpoint": current_endpoint,
        "currentApiKeyPrefix": null,
        "currentModels": null,
        "message": if installed { Value::Null } else { json!("Configuration file not found on this host") },
    })
}

/// `GET /console/api/cli-tools/registry`.
pub async fn list_registry(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    console_response(StatusCode::OK, Value::Array(registry().clone()))
}

/// `GET /console/api/cli-tools/all-statuses`.
pub async fn all_statuses(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    let mut map = Map::new();
    for entry in registry() {
        if let Some(id) = entry.get("id").and_then(Value::as_str) {
            map.insert(id.to_owned(), status_for(entry));
        }
    }
    console_response(StatusCode::OK, Value::Object(map))
}

/// `GET /console/api/cli-tools/{toolId}`.
pub async fn tool_status(
    State(state): State<ConsoleState>,
    Path(tool_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    match tool(&tool_id) {
        Some(entry) => console_response(StatusCode::OK, status_for(entry)),
        None => error_response(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            "CLI tool not found",
        ),
    }
}

#[allow(clippy::result_large_err)]
async fn owned_key(state: &ConsoleState, tenant: &str, key_id: &str) -> Result<(), Response> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM api_keys WHERE tenant_id = $1::uuid AND id = $2::uuid)",
    )
    .bind(tenant)
    .bind(key_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if exists {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::NOT_FOUND,
            "key_not_found",
            &format!("Key not found: {key_id}"),
        ))
    }
}

async fn mapping_view(
    state: &ConsoleState,
    tenant: &str,
    tool_id: &str,
    key_id: &str,
) -> Result<Value, sqlx::Error> {
    let settings = sqlx::query(
        "SELECT mappings_enabled FROM cli_tool_settings
         WHERE tenant_id = $1::uuid AND tool_id = $2 AND api_key_id = $3::uuid",
    )
    .bind(tenant)
    .bind(tool_id)
    .bind(key_id)
    .fetch_optional(&state.pool)
    .await?;
    let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(
        "SELECT slot_key, source_model, target_model, enabled FROM cli_tool_mappings
         WHERE tenant_id = $1::uuid AND tool_id = $2 AND api_key_id = $3::uuid
         ORDER BY slot_key",
    )
    .bind(tenant)
    .bind(tool_id)
    .bind(key_id)
    .fetch_all(&state.pool)
    .await?;
    let mappings: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "slotKey": row.get::<String, _>("slot_key"),
                "sourceModel": row.get::<String, _>("source_model"),
                "targetModel": row.get::<String, _>("target_model"),
                "enabled": row.get::<bool, _>("enabled"),
            })
        })
        .collect();
    Ok(json!({
        "toolId": tool_id,
        "tenantId": tenant,
        "apiKeyId": key_id,
        "enabled": settings
            .as_ref()
            .map(|row| row.get::<bool, _>("mappings_enabled"))
            .unwrap_or(false),
        "mappings": mappings,
    }))
}

/// `GET /console/api/cli-tools/{toolId}/mappings?keyId=`.
pub async fn get_mappings(
    State(state): State<ConsoleState>,
    Path(tool_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    if tool(&tool_id).is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            "CLI tool not found",
        );
    }
    let Some(key_id) = query.get("keyId").filter(|value| !value.is_empty()) else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "keyId query parameter is required",
        );
    };
    if let Err(response) = owned_key(&state, &tenant, key_id).await {
        return response;
    }
    match mapping_view(&state, &tenant, &tool_id, key_id).await {
        Ok(value) => console_response(StatusCode::OK, value),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/cli-tools/{toolId}/mappings`.
pub async fn save_mappings(
    State(state): State<ConsoleState>,
    Path(tool_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(entry) = tool(&tool_id) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            "CLI tool not found",
        );
    };
    let supports_mapping = entry
        .get("mappingSupported")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !supports_mapping {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "This tool does not support persisted model mapping",
        );
    }
    let Some(key_id) = body
        .get("keyId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "keyId is required",
        );
    };
    if let Err(response) = owned_key(&state, &tenant, key_id).await {
        return response;
    }
    let Some(enabled) = body.get("enabled").and_then(Value::as_bool) else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "enabled is required",
        );
    };
    let Some(mappings) = body.get("mappings").and_then(Value::as_array) else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "mappings must be an array",
        );
    };
    let known_slots: HashSet<&str> = entry
        .get("defaultModels")
        .and_then(Value::as_array)
        .map(|models| {
            models
                .iter()
                .filter_map(|model| model.get("alias").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let mut incoming = HashSet::new();
    let mut rows = Vec::new();
    for mapping in mappings {
        let Some(slot) = mapping.get("slotKey").and_then(Value::as_str) else {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                "mapping slotKey is required",
            );
        };
        if !known_slots.contains(slot) {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                &format!("Unknown mapping slot: {slot}"),
            );
        }
        if !incoming.insert(slot.to_owned()) {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                &format!("Duplicate mapping slot: {slot}"),
            );
        }
        let source = mapping
            .get("sourceModel")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let target = mapping
            .get("targetModel")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if source.is_empty() || target.is_empty() {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                "Mapping source and target are required",
            );
        }
        rows.push((
            slot.to_owned(),
            source.to_owned(),
            target.to_owned(),
            mapping
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        ));
    }
    let mode = entry
        .get("mappingMode")
        .and_then(Value::as_str)
        .unwrap_or("remote");
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error(error),
    };
    if let Err(error) = sqlx::query(
        "INSERT INTO cli_tool_settings (tenant_id, tool_id, api_key_id, mappings_enabled, mode, updated_at)
         VALUES ($1::uuid, $2, $3::uuid, $4, $5, now())
         ON CONFLICT (tenant_id, tool_id, api_key_id) DO UPDATE
         SET mappings_enabled = $4, mode = $5, updated_at = now()",
    )
    .bind(&tenant)
    .bind(&tool_id)
    .bind(key_id)
    .bind(enabled)
    .bind(mode)
    .execute(&mut *transaction)
    .await
    {
        return server_error(error);
    }
    if let Err(error) = sqlx::query(
        "DELETE FROM cli_tool_mappings
         WHERE tenant_id = $1::uuid AND tool_id = $2 AND api_key_id = $3::uuid",
    )
    .bind(&tenant)
    .bind(&tool_id)
    .bind(key_id)
    .execute(&mut *transaction)
    .await
    {
        return server_error(error);
    }
    for (slot, source, target, row_enabled) in rows {
        if let Err(error) = sqlx::query(
            "INSERT INTO cli_tool_mappings
                (tenant_id, tool_id, api_key_id, slot_key, source_model, target_model, enabled)
             VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7)",
        )
        .bind(&tenant)
        .bind(&tool_id)
        .bind(key_id)
        .bind(&slot)
        .bind(&source)
        .bind(&target)
        .bind(row_enabled)
        .execute(&mut *transaction)
        .await
        {
            return server_error(error);
        }
    }
    if let Err(error) = transaction.commit().await {
        return server_error(error);
    }
    state.snapshots.invalidate();
    match mapping_view(&state, &tenant, &tool_id, key_id).await {
        Ok(value) => console_response(StatusCode::OK, value),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/cli-tools/{toolId}/mappings/reset`.
pub async fn reset_mappings(
    State(state): State<ConsoleState>,
    Path(tool_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    if tool(&tool_id).is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            "CLI tool not found",
        );
    }
    let Some(key_id) = body
        .get("keyId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "keyId is required",
        );
    };
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error(error),
    };
    let _ = sqlx::query(
        "DELETE FROM cli_tool_mappings WHERE tenant_id = $1::uuid AND tool_id = $2 AND api_key_id = $3::uuid",
    )
    .bind(&tenant)
    .bind(&tool_id)
    .bind(key_id)
    .execute(&mut *transaction)
    .await;
    let _ = sqlx::query(
        "DELETE FROM cli_tool_settings WHERE tenant_id = $1::uuid AND tool_id = $2 AND api_key_id = $3::uuid",
    )
    .bind(&tenant)
    .bind(&tool_id)
    .bind(key_id)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = transaction.commit().await {
        return server_error(error);
    }
    state.snapshots.invalidate();
    match mapping_view(&state, &tenant, &tool_id, key_id).await {
        Ok(value) => console_response(StatusCode::OK, value),
        Err(error) => server_error(error),
    }
}

// --- Apply / download -------------------------------------------------------

#[allow(clippy::result_large_err)]
fn home_dir() -> Result<std::path::PathBuf, Response> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "home_unavailable",
                "HOME is not set; CLI injectors cannot resolve a settings path",
            )
        })
}

fn ensure_v1(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if trimmed.ends_with("/v1") {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/v1")
    }
}

fn strip_v1(endpoint: &str) -> String {
    endpoint
        .trim_end_matches('/')
        .strip_suffix("/v1")
        .unwrap_or(endpoint.trim_end_matches('/'))
        .to_owned()
}

fn read_json(path: &std::path::Path) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| json!({}))
}

#[allow(clippy::result_large_err)]
fn write_file(path: &std::path::Path, content: &str) -> Result<(), Response> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "settings_write_failed",
                &format!("cannot create {}: {error}", parent.display()),
            )
        })?;
    }
    std::fs::write(path, content).map_err(|error| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings_write_failed",
            &format!("cannot write {}: {error}", path.display()),
        )
    })
}

fn model_ids(body: &Value) -> Vec<String> {
    body.get("modelIds")
        .and_then(Value::as_array)
        .map(|models| {
            models
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn claude_model(body: &Value) -> String {
    body.get("activeModel")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("modelSlots")
                .and_then(|slots| slots.get("opus"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            body.get("modelSlots")
                .and_then(|slots| slots.get("sonnet"))
                .and_then(Value::as_str)
        })
        .unwrap_or("opus[1m]")
        .to_owned()
}

#[allow(clippy::result_large_err)]
fn apply_claude(body: &Value) -> Result<(String, String), Response> {
    let home = home_dir()?;
    let path = home.join(".claude/settings.json");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "endpoint is required",
            )
        })?;
    let api_key = body.get("apiKey").and_then(Value::as_str).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "apiKey is required",
        )
    })?;
    let mut settings = read_json(&path);
    let object = settings.as_object_mut().ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings_invalid",
            "settings.json is not an object",
        )
    })?;
    let mut env = object
        .remove("env")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    for key in [
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "ANTHROPIC_DEFAULT_FABLE_MODEL",
        "ANTHROPIC_DEFAULT_MODEL",
        "ANTHROPIC_CUSTOM_MODEL_OPTION",
        "API_TIMEOUT_MS",
    ] {
        env.remove(key);
    }
    env.insert("ANTHROPIC_BASE_URL".into(), json!(strip_v1(endpoint)));
    env.insert("ANTHROPIC_AUTH_TOKEN".into(), json!(api_key));
    object.insert("env".into(), Value::Object(env));
    object.insert("model".into(), json!(claude_model(body)));
    object.insert(
        "permissions".into(),
        json!({"defaultMode": "bypassPermissions"}),
    );
    object.insert(
        "enabledPlugins".into(),
        json!({
            "typescript-lsp@claude-plugins-official": true,
            "pyright-lsp@claude-plugins-official": true,
        }),
    );
    object.insert("effortLevel".into(), json!("medium"));
    object.insert(
        "modelSettings".into(),
        json!({"claude-opus-5.5": {"effortLevel": "medium"}}),
    );
    object.insert("skipDangerousModePermissionPrompt".into(), json!(true));
    object.insert("includeCoAuthoredBy".into(), json!(false));
    object.insert("theme".into(), json!("dark"));
    object.insert("autoCompactWindow".into(), json!(800000));
    object.insert("autoCompactEnabled".into(), json!(true));
    object.insert("autoContinueAtUsageLimit".into(), json!(true));
    object.insert("hasCompletedOnboarding".into(), json!(true));
    let serialized = serde_json::to_string_pretty(&settings).unwrap_or_default();
    write_file(&path, &serialized)?;
    Ok((
        path.display().to_string(),
        "Claude Code settings applied".into(),
    ))
}

#[allow(clippy::result_large_err)]
fn apply_opencode(body: &Value) -> Result<(String, String), Response> {
    let home = home_dir()?;
    let path = home.join(".config/opencode/opencode.json");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "endpoint is required",
            )
        })?;
    let api_key = body.get("apiKey").and_then(Value::as_str).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "apiKey is required",
        )
    })?;
    let mut config = read_json(&path);
    let object = config.as_object_mut().ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings_invalid",
            "opencode.json is not an object",
        )
    })?;
    let mut models = serde_json::Map::new();
    for model in model_ids(body) {
        models.insert(
            model.clone(),
            json!({"name": model, "modalities": {"input": ["text", "image"], "output": ["text"]}}),
        );
    }
    let provider = object
        .entry("provider")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "settings_invalid",
                "provider must be an object",
            )
        })?;
    let prior_models = provider
        .get("keyla")
        .and_then(|entry| entry.get("models"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut merged = prior_models;
    for (key, value) in models {
        merged.insert(key, value);
    }
    provider.insert(
        "keyla".into(),
        json!({
            "npm": "@ai-sdk/openai-compatible",
            "options": {"baseURL": ensure_v1(endpoint), "apiKey": api_key},
            "models": merged,
        }),
    );
    let active = body
        .get("activeModel")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| model_ids(body).into_iter().next())
        .unwrap_or_default();
    object.insert(
        "model".into(),
        json!(if active.is_empty() {
            String::new()
        } else {
            format!("keyla/{active}")
        }),
    );
    let subagent = body
        .get("subagentModel")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| active.clone());
    let agent = object
        .entry("agent")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "settings_invalid",
                "agent must be an object",
            )
        })?;
    agent.insert(
        "explorer".into(),
        json!({"description": "Fast explorer subagent", "mode": "subagent", "model": format!("keyla/{subagent}")}),
    );
    let serialized = serde_json::to_string_pretty(&config).unwrap_or_default();
    write_file(&path, &serialized)?;
    Ok((
        path.display().to_string(),
        "OpenCode settings applied".into(),
    ))
}

fn remove_toml_section(text: &str, section: &str) -> String {
    let header = format!("[{section}]");
    let mut output = String::new();
    let mut skipping = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == header {
            skipping = true;
            continue;
        }
        if skipping && trimmed.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

#[allow(clippy::result_large_err)]
fn apply_codex(body: &Value) -> Result<(String, String), Response> {
    let home = home_dir()?;
    let path = home.join(".codex/config.toml");
    let auth_path = home.join(".codex/auth.json");
    let helper_path = home.join(".codex/keyla-auth.cjs");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "endpoint is required",
            )
        })?;
    let api_key = body.get("apiKey").and_then(Value::as_str).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "apiKey is required",
        )
    })?;
    let ids = model_ids(body);
    let model = body
        .get("modelSlots")
        .and_then(|slots| slots.get("session"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            body.get("activeModel")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| ids.first().cloned())
        .unwrap_or_default();
    let subagent = body
        .get("modelSlots")
        .and_then(|slots| slots.get("subagent"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            body.get("subagentModel")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| model.clone());
    let review = body
        .get("modelSlots")
        .and_then(|slots| slots.get("review"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut text = std::fs::read_to_string(&path).unwrap_or_default();
    for section in [
        "model_providers.keyla",
        "model_providers.keyla.auth",
        "model_providers.cartethyia",
        "model_providers.cartethyia.auth",
    ] {
        text = remove_toml_section(&text, section);
    }
    let mut out = String::new();
    out.push_str(&format!("model = \"{model}\"\n"));
    if let Some(review) = &review {
        out.push_str(&format!("review_model = \"{review}\"\n"));
    }
    out.push_str("model_provider = \"keyla\"\n\n");
    out.push_str("[model_providers.keyla]\n");
    out.push_str("  name = \"Keyla\"\n");
    out.push_str(&format!("  base_url = \"{}\"\n", ensure_v1(endpoint)));
    out.push_str("  wire_api = \"responses\"\n\n");
    out.push_str("[model_providers.keyla.auth]\n");
    out.push_str("  command = \"node\"\n");
    out.push_str(&format!("  args = [\"{}\"]\n", helper_path.display()));
    out.push_str("  timeout_ms = 5000\n  refresh_interval_ms = 0\n\n");
    out.push_str("[agents]\n");
    out.push_str(&format!("  default_subagent_model = \"{subagent}\"\n"));
    out.push_str(&text);
    write_file(&path, &out)?;
    let mut auth = read_json(&auth_path);
    let object = auth.as_object_mut().ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings_invalid",
            "auth.json is not an object",
        )
    })?;
    object.insert("keyla".into(), json!(api_key));
    object.remove("cartethyia");
    write_file(
        &auth_path,
        &serde_json::to_string_pretty(&auth).unwrap_or_default(),
    )?;
    write_file(
        &helper_path,
        "const fs = require('node:fs');\nconst path = require('node:path');\nconst auth = JSON.parse(fs.readFileSync(path.join(__dirname, 'auth.json'), 'utf8'));\nconst key = auth.keyla;\nif (typeof key === 'string') process.stdout.write(key);\n",
    )?;
    Ok((
        path.display().to_string(),
        "Codex CLI settings applied".into(),
    ))
}

#[allow(clippy::result_large_err)]
fn download_payload(tool_id: &str, body: &Value) -> Result<Value, Response> {
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "endpoint is required",
            )
        })?;
    let api_key = body.get("apiKey").and_then(Value::as_str).unwrap_or("");
    match tool_id {
        "claude" => Ok(json!({
            "content": serde_json::to_string_pretty(&json!({
                "permissions": {"defaultMode": "bypassPermissions"},
                "enabledPlugins": {
                    "typescript-lsp@claude-plugins-official": true,
                    "pyright-lsp@claude-plugins-official": true,
                },
                "effortLevel": "medium",
                "model": claude_model(body),
                "env": {
                    "ANTHROPIC_BASE_URL": strip_v1(endpoint),
                    "ANTHROPIC_AUTH_TOKEN": api_key,
                }
            })).unwrap_or_default(),
            "filename": "settings.json",
            "mimeType": "application/json",
        })),
        "opencode" => Ok(json!({
            "content": serde_json::to_string_pretty(&json!({
                "provider": {"keyla": {
                    "npm": "@ai-sdk/openai-compatible",
                    "options": {"baseURL": ensure_v1(endpoint), "apiKey": api_key},
                    "models": model_ids(body).into_iter().map(|model| (model.clone(), json!({"name": model, "modalities": {"input": ["text","image"], "output": ["text"]}}))).collect::<serde_json::Map<String, Value>>(),
                }},
                "model": model_ids(body).first().map(|model| format!("keyla/{model}")).unwrap_or_default(),
            })).unwrap_or_default(),
            "filename": "opencode.json",
            "mimeType": "application/json",
        })),
        "codex" => Ok(json!({
            "content": format!(
                "# config.toml\nmodel = \"{}\"\nmodel_provider = \"keyla\"\n\n[model_providers.keyla]\n  name = \"Keyla\"\n  base_url = \"{}\"\n  wire_api = \"responses\"\n\n# auth.json\n{}\n",
                model_ids(body).first().cloned().unwrap_or_default(),
                ensure_v1(endpoint),
                serde_json::to_string_pretty(&json!({"keyla": api_key})).unwrap_or_default(),
            ),
            "filename": "codex-config.txt",
            "mimeType": "text/plain",
        })),
        "cline" => {
            let model = cli_model(body);
            let state = json!({
                "actModeApiProvider": "openai",
                "planModeApiProvider": "openai",
                "openAiBaseUrl": strip_v1(endpoint),
                "openAiModelId": model,
                "planModeOpenAiModelId": model,
            });
            let secrets = json!({"openAiApiKey": api_key});
            Ok(json!({
                "content": format!(
                    "# ~/.cline/data/globalState.json\n{}\n\n# ~/.cline/data/secrets.json\n{}\n",
                    serde_json::to_string_pretty(&state).unwrap_or_default(),
                    serde_json::to_string_pretty(&secrets).unwrap_or_default()
                ),
                "filename": "cline-config.txt",
                "mimeType": "text/plain",
            }))
        }
        "copilot" => {
            let entry = copilot_entry(body, endpoint, api_key);
            Ok(json!({
                "content": serde_json::to_string_pretty(&json!([entry])).unwrap_or_default(),
                "filename": "chatLanguageModels.json",
                "mimeType": "application/json",
            }))
        }
        "kilo" => {
            let auth = json!({"openai-compatible": {
                "baseUrl": ensure_v1(endpoint),
                "apiKey": api_key,
                "model": cli_model(body),
            }});
            Ok(json!({
                "content": serde_json::to_string_pretty(&auth).unwrap_or_default(),
                "filename": "auth.json",
                "mimeType": "application/json",
            }))
        }
        "cowork" => Ok(json!({
            "content": serde_json::to_string_pretty(&json!({"managedServers": {}})).unwrap_or_default(),
            "filename": "_meta.json",
            "mimeType": "application/json",
        })),
        "grok-build" => {
            let model = cli_model(body);
            Ok(json!({
                "content": format!("[model]\ndefault = \"{model}\"\nbase_url = \"{}\"\nprovider = \"custom\"\napi_key = \"{api_key}\"\n", ensure_v1(endpoint)),
                "filename": "grok-config.toml", "mimeType": "text/plain",
            }))
        }
        "deepseek-tui" => {
            let model = cli_model(body);
            Ok(json!({
                "content": format!("provider = \"openai\"\n\n[providers.openai]\n  base_url = \"{}\"\n  api_key = \"{api_key}\"\n  model = \"{model}\"\n", ensure_v1(endpoint)),
                "filename": "config.toml", "mimeType": "text/plain",
            }))
        }
        "droid" => {
            let base_url = ensure_v1(endpoint);
            let models: Vec<Value> = model_ids(body)
                .into_iter()
                .map(|model| {
                    json!({
                        "id": format!("custom:Keyla:{model}"), "name": model, "baseUrl": base_url,
                        "apiKey": api_key, "provider": "openai",
                    })
                })
                .collect();
            Ok(json!({
                "content": serde_json::to_string_pretty(&json!({"customModels": models})).unwrap_or_default(),
                "filename": "settings.json", "mimeType": "application/json",
            }))
        }
        "hermes" => {
            let model = cli_model(body);
            Ok(json!({
                "content": format!("# ~/.hermes/config.yaml\nmodel:\n  default: \"{model}\"\n  provider: \"custom\"\n  base_url: \"{}\"\n\n# ~/.hermes/.env\nOPENAI_API_KEY={api_key}\n", ensure_v1(endpoint)),
                "filename": "hermes-config.txt", "mimeType": "text/plain",
            }))
        }
        "jcode" => {
            let model = cli_model(body);
            Ok(json!({
                "content": format!("# config.toml\n[providers.keyla]\n  type = \"openai\"\n  base_url = \"{}\"\n  env_file = \"provider-keyla.env\"\n  model = \"{model}\"\n\n# provider-keyla.env\nOPENAI_API_KEY={api_key}\n", ensure_v1(endpoint)),
                "filename": "jcode-config.txt", "mimeType": "text/plain",
            }))
        }
        "openclaw" => {
            let all_models: Vec<String> = {
                let mut ids = model_ids(body);
                if let Some(active) = body.get("activeModel").and_then(Value::as_str) {
                    if !ids.iter().any(|id| id == active) {
                        ids.push(active.to_owned());
                    }
                }
                ids
            };
            let primary = body
                .get("activeModel")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| all_models.first().cloned().unwrap_or_default());
            Ok(json!({
                "content": serde_json::to_string_pretty(&json!({
                    "models": {"providers": {"keyla": {
                        "baseUrl": ensure_v1(endpoint), "apiKey": api_key, "api": "openai-completions",
                        "models": all_models.iter().map(|model| json!({"id": model, "name": model.rsplit('/').next().unwrap_or(model)})).collect::<Vec<_>>(),
                    }}},
                    "agents": {"defaults": {
                        "model": {"primary": format!("keyla/{primary}")},
                        "models": all_models.iter().map(|model| (format!("keyla/{model}"), json!({}))).collect::<serde_json::Map<String, Value>>(),
                    }},
                })).unwrap_or_default(),
                "filename": "openclaw.json", "mimeType": "application/json",
            }))
        }
        _ => Err(error_response(
            StatusCode::NOT_IMPLEMENTED,
            "capability_unsupported",
            "This CLI tool injector is not implemented in the Rust gateway yet",
        )),
    }
}

/// `POST /console/api/cli-tools/{toolId}/apply`.
pub async fn apply_tool(
    State(state): State<ConsoleState>,
    Path(tool_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        return response;
    }
    if tool(&tool_id).is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            "CLI tool not found",
        );
    }
    let result = match tool_id.as_str() {
        "claude" => apply_claude(&body),
        "opencode" => apply_opencode(&body),
        "codex" => apply_codex(&body),
        "cline" => apply_cline(&body),
        "copilot" => apply_copilot(&body),
        "kilo" => apply_kilo(&body),
        "cowork" => apply_cowork(&body),
        "grok-build" => apply_grok_build(&body),
        "deepseek-tui" => apply_deepseek_tui(&body),
        "droid" => apply_droid(&body),
        "hermes" => apply_hermes(&body),
        "jcode" => apply_jcode(&body),
        "openclaw" => apply_openclaw(&body),
        _ => Err(error_response(
            StatusCode::NOT_IMPLEMENTED,
            "capability_unsupported",
            "This CLI tool injector is not implemented in the Rust gateway yet",
        )),
    };
    match result {
        Ok((settings_path, message)) => console_response(
            StatusCode::OK,
            json!({
                "outcome": "file",
                "wroteFile": true,
                "savedRemoteRoute": false,
                "settingsPath": settings_path,
                "message": message,
            }),
        ),
        Err(response) => response,
    }
}

/// `POST /console/api/cli-tools/{toolId}/download`.
pub async fn download_tool(
    State(state): State<ConsoleState>,
    Path(tool_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    if tool(&tool_id).is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            "CLI tool not found",
        );
    }
    match download_payload(&tool_id, &body) {
        Ok(value) => console_response(StatusCode::OK, value),
        Err(response) => response,
    }
}

fn cli_model(body: &Value) -> String {
    body.get("activeModel")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| model_ids(body).into_iter().next())
        .unwrap_or_default()
}

fn copilot_entry(body: &Value, endpoint: &str, api_key: &str) -> Value {
    let url = format!(
        "{}/chat/completions#models.ai.azure.com",
        ensure_v1(endpoint)
    );
    let models: Vec<Value> = model_ids(body)
        .into_iter()
        .map(|id| {
            json!({
                "id": id, "name": id, "url": url, "toolCalling": true,
                "vision": false, "maxInputTokens": 128000, "maxOutputTokens": 16000,
            })
        })
        .collect();
    json!({"name": "Keyla", "vendor": "azure", "apiKey": api_key, "models": models})
}

#[allow(clippy::result_large_err)]
fn cline_paths() -> Result<(std::path::PathBuf, std::path::PathBuf), Response> {
    let home = home_dir()?;
    Ok((
        home.join(".cline/data/globalState.json"),
        home.join(".cline/data/secrets.json"),
    ))
}

#[allow(clippy::result_large_err)]
fn apply_cline(body: &Value) -> Result<(String, String), Response> {
    let (path, secrets_path) = cline_paths()?;
    let model = cli_model(body);
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut state = read_json(&path);
    let object = state.as_object_mut().ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings_write_failed",
            "Cline global state is not an object",
        )
    })?;
    object.insert("actModeApiProvider".into(), json!("openai"));
    object.insert("planModeApiProvider".into(), json!("openai"));
    object.insert("openAiBaseUrl".into(), json!(strip_v1(endpoint)));
    object.insert("openAiModelId".into(), json!(model));
    object.insert("planModeOpenAiModelId".into(), json!(model));
    write_file(
        &path,
        &serde_json::to_string_pretty(&state).unwrap_or_default(),
    )?;
    let mut secrets = read_json(&secrets_path);
    if let Some(object) = secrets.as_object_mut() {
        object.insert("openAiApiKey".into(), json!(api_key));
    }
    write_file(
        &secrets_path,
        &serde_json::to_string_pretty(&secrets).unwrap_or_default(),
    )?;
    Ok((
        path.display().to_string(),
        "Cline settings applied successfully".to_owned(),
    ))
}

#[allow(clippy::result_large_err)]
fn copilot_path() -> Result<std::path::PathBuf, Response> {
    let home = home_dir()?;
    Ok(match std::env::consts::OS {
        "windows" => std::path::PathBuf::from(
            std::env::var("APPDATA").unwrap_or_else(|_| home.display().to_string()),
        )
        .join("Code/User/chatLanguageModels.json"),
        "macos" => home.join("Library/Application Support/Code/User/chatLanguageModels.json"),
        _ => home.join(".config/Code/User/chatLanguageModels.json"),
    })
}

#[allow(clippy::result_large_err)]
fn apply_copilot(body: &Value) -> Result<(String, String), Response> {
    let path = copilot_path()?;
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let entry = copilot_entry(body, endpoint, api_key);
    let mut config = match read_json(&path) {
        Value::Array(items) => items,
        _ => Vec::new(),
    };
    if let Some(existing) = config
        .iter_mut()
        .find(|item| item.get("name").and_then(Value::as_str) == Some("Keyla"))
    {
        *existing = entry;
    } else {
        config.push(entry);
    }
    write_file(
        &path,
        &serde_json::to_string_pretty(&Value::Array(config)).unwrap_or_default(),
    )?;
    Ok((
        path.display().to_string(),
        "Copilot settings applied - reload VS Code to take effect".to_owned(),
    ))
}

#[allow(clippy::result_large_err)]
fn kilo_paths() -> Result<(std::path::PathBuf, std::path::PathBuf), Response> {
    let home = home_dir()?;
    let data = match std::env::consts::OS {
        "windows" => std::path::PathBuf::from(
            std::env::var("LOCALAPPDATA").unwrap_or_else(|_| home.display().to_string()),
        )
        .join("kilo"),
        "macos" => home.join("Library/Application Support/kilo"),
        _ => home.join(".local/share/kilo"),
    };
    let settings = match std::env::consts::OS {
        "windows" => std::path::PathBuf::from(
            std::env::var("APPDATA").unwrap_or_else(|_| home.display().to_string()),
        )
        .join("Code/User/settings.json"),
        "macos" => home.join("Library/Application Support/Code/User/settings.json"),
        _ => home.join(".config/Code/User/settings.json"),
    };
    Ok((data.join("auth.json"), settings))
}

#[allow(clippy::result_large_err)]
fn apply_kilo(body: &Value) -> Result<(String, String), Response> {
    let (path, settings_path) = kilo_paths()?;
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut auth = read_json(&path);
    if let Some(object) = auth.as_object_mut() {
        object.insert(
            "openai-compatible".into(),
            json!({
                "baseUrl": ensure_v1(endpoint),
                "apiKey": api_key,
                "model": cli_model(body),
            }),
        );
    }
    write_file(
        &path,
        &serde_json::to_string_pretty(&auth).unwrap_or_default(),
    )?;
    let mut settings = read_json(&settings_path);
    if let Some(object) = settings.as_object_mut() {
        object.insert(
            "kilo.code.authProviderOverride".into(),
            json!("openai-compatible"),
        );
    }
    write_file(
        &settings_path,
        &serde_json::to_string_pretty(&settings).unwrap_or_default(),
    )?;
    Ok((
        path.display().to_string(),
        "Kilo Code settings applied".to_owned(),
    ))
}

fn upsert_toml_section(text: &str, section: &str, body: &str) -> String {
    let mut output = remove_toml_section(text, section);
    let trimmed = output.trim_end();
    output = if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n\n")
    };
    output.push_str(&format!("[{section}]\n{body}\n"));
    output
}

fn set_root_toml_key(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key} =");
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with(&prefix))
        .map(str::to_owned)
        .collect();
    lines.insert(0, format!("{key} = \"{value}\""));
    lines.join("\n") + "\n"
}

#[allow(clippy::result_large_err)]
fn apply_cowork(_body: &Value) -> Result<(String, String), Response> {
    let home = home_dir()?;
    let path = match std::env::consts::OS {
        "windows" => std::path::PathBuf::from(
            std::env::var("APPDATA").unwrap_or_else(|_| home.display().to_string()),
        )
        .join("Claude/configLibrary/_meta.json"),
        "macos" => home.join("Library/Application Support/Claude/configLibrary/_meta.json"),
        _ => home.join(".config/Claude/configLibrary/_meta.json"),
    };
    let mut meta = read_json(&path);
    if let Some(servers) = meta
        .get_mut("managedServers")
        .and_then(Value::as_object_mut)
    {
        servers.remove("keyla");
    }
    write_file(
        &path,
        &serde_json::to_string_pretty(&meta).unwrap_or_default(),
    )?;
    Ok((
        path.display().to_string(),
        "Claude Cowork settings applied".to_owned(),
    ))
}

#[allow(clippy::result_large_err)]
fn apply_grok_build(body: &Value) -> Result<(String, String), Response> {
    let path = home_dir()?.join(".grok/config.toml");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let body_text = format!(
        "default = \"{}\"\nbase_url = \"{}\"\nprovider = \"custom\"\napi_key = \"{api_key}\"",
        cli_model(body),
        ensure_v1(endpoint)
    );
    write_file(&path, &upsert_toml_section(&text, "model", &body_text))?;
    Ok((
        path.display().to_string(),
        "Grok Build settings applied".to_owned(),
    ))
}

#[allow(clippy::result_large_err)]
fn apply_deepseek_tui(body: &Value) -> Result<(String, String), Response> {
    let path = home_dir()?.join(".deepseek/config.toml");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let text = set_root_toml_key(&text, "provider", "openai");
    let body_text = format!(
        "  base_url = \"{}\"\n  api_key = \"{api_key}\"\n  model = \"{}\"",
        ensure_v1(endpoint),
        cli_model(body)
    );
    write_file(
        &path,
        &upsert_toml_section(&text, "providers.openai", &body_text),
    )?;
    Ok((
        path.display().to_string(),
        "DeepSeek TUI settings applied".to_owned(),
    ))
}

#[allow(clippy::result_large_err)]
fn apply_droid(body: &Value) -> Result<(String, String), Response> {
    let path = home_dir()?.join(".factory/settings.json");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body.get("apiKey").and_then(Value::as_str).unwrap_or("");
    let api_key = if api_key.is_empty() {
        "your_api_key"
    } else {
        api_key
    };
    let base_url = ensure_v1(endpoint);
    let mut settings = read_json(&path);
    let object = settings.as_object_mut().ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings_write_failed",
            "Factory Droid settings is not an object",
        )
    })?;
    let kept: Vec<Value> = object
        .get("customModels")
        .and_then(Value::as_array)
        .map(|models| {
            models
                .iter()
                .filter(|model| {
                    model
                        .get("id")
                        .and_then(Value::as_str)
                        .is_none_or(|id| !id.starts_with("custom:Keyla"))
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let mut models = kept;
    for model in model_ids(body) {
        models.push(json!({
            "id": format!("custom:Keyla:{model}"), "name": model, "baseUrl": base_url,
            "apiKey": api_key, "provider": "openai",
        }));
    }
    object.insert("customModels".into(), Value::Array(models));
    if let Some(active) = body.get("activeModel").and_then(Value::as_str) {
        object.insert("model".into(), json!(active));
    }
    write_file(
        &path,
        &serde_json::to_string_pretty(&settings).unwrap_or_default(),
    )?;
    Ok((
        path.display().to_string(),
        "Factory Droid settings applied".to_owned(),
    ))
}

fn env_upsert(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with(&prefix))
        .map(str::to_owned)
        .collect();
    lines.push(format!("{key}={value}"));
    lines.join("\n") + "\n"
}

fn replace_hermes_model(text: &str, block: &str) -> String {
    let mut output = Vec::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.trim_end() == "model:" {
            skipping = true;
            continue;
        }
        if skipping {
            let is_indented = line.starts_with(' ') || line.starts_with('\t');
            if is_indented || line.trim().is_empty() {
                continue;
            }
            skipping = false;
        }
        output.push(line.to_owned());
    }
    let rest = output.join("\n");
    if rest.trim().is_empty() {
        block.to_owned()
    } else {
        format!("{block}\n{rest}\n")
    }
}

#[allow(clippy::result_large_err)]
fn apply_hermes(body: &Value) -> Result<(String, String), Response> {
    let home = home_dir()?;
    let path = home.join(".hermes/config.yaml");
    let env_path = home.join(".hermes/.env");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let block = format!(
        "model:\n  default: \"{}\"\n  provider: \"custom\"\n  base_url: \"{}\"\n",
        cli_model(body),
        ensure_v1(endpoint)
    );
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    write_file(&path, &replace_hermes_model(&text, &block))?;
    let env_text = std::fs::read_to_string(&env_path).unwrap_or_default();
    write_file(&env_path, &env_upsert(&env_text, "OPENAI_API_KEY", api_key))?;
    Ok((
        path.display().to_string(),
        "Hermes Agent settings applied".to_owned(),
    ))
}

#[allow(clippy::result_large_err)]
fn apply_jcode(body: &Value) -> Result<(String, String), Response> {
    let home = home_dir()?;
    let path = home.join(".jcode/config.toml");
    let env_dir = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| home.join(".config"))
        .join("jcode");
    let env_path = env_dir.join("provider-keyla.env");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let section = format!(
        "  type = \"openai\"\n  base_url = \"{}\"\n  env_file = \"provider-keyla.env\"\n  model = \"{}\"",
        ensure_v1(endpoint),
        cli_model(body)
    );
    write_file(
        &path,
        &upsert_toml_section(&text, "providers.keyla", &section),
    )?;
    let env_text = std::fs::read_to_string(&env_path).unwrap_or_default();
    write_file(&env_path, &env_upsert(&env_text, "OPENAI_API_KEY", api_key))?;
    Ok((
        path.display().to_string(),
        "jcode settings applied".to_owned(),
    ))
}

#[allow(clippy::result_large_err)]
fn apply_openclaw(body: &Value) -> Result<(String, String), Response> {
    let path = home_dir()?.join(".openclaw/openclaw.json");
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let api_key = body
        .get("apiKey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let primary = cli_model(body);
    let all_models: Vec<String> = {
        let mut ids = model_ids(body);
        if !ids.iter().any(|id| id == &primary) {
            ids.push(primary.clone());
        }
        ids
    };
    let mut settings = read_json(&path);
    let root = settings.as_object_mut().ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings_write_failed",
            "Open Claw settings is not an object",
        )
    })?;
    root.insert("models".into(), json!({"providers": {"keyla": {
        "baseUrl": ensure_v1(endpoint), "apiKey": api_key, "api": "openai-completions",
        "models": all_models.iter().map(|model| json!({"id": model, "name": model.rsplit('/').next().unwrap_or(model)})).collect::<Vec<_>>(),
    }}}));
    let defaults = root
        .entry("agents".to_owned())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .and_then(|agents| {
            agents
                .entry("defaults".to_owned())
                .or_insert_with(|| json!({}))
                .as_object_mut()
        })
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "settings_write_failed",
                "Open Claw agents is not an object",
            )
        })?;
    defaults.insert(
        "model".into(),
        json!({"primary": format!("keyla/{primary}")}),
    );
    defaults.insert(
        "models".into(),
        Value::Object(
            all_models
                .iter()
                .map(|model| (format!("keyla/{model}"), json!({})))
                .collect(),
        ),
    );
    write_file(
        &path,
        &serde_json::to_string_pretty(&settings).unwrap_or_default(),
    )?;
    Ok((
        path.display().to_string(),
        "Open Claw settings applied".to_owned(),
    ))
}
