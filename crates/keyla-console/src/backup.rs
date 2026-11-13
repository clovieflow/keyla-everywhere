//! Backup export/restore and destructive tenant resets.
//!
//! Only tenant-owned configuration and metadata telemetry are carried. Every
//! operation re-authenticates the console password carried in the request,
//! because an export contains provider credentials and an import replaces them.

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::access::{console_error_body, console_response, resolve_console_access};
use crate::auth::{
    SESSION_COOKIE_NAME, find_user_by_id, parse_cookie, validate_session, verify_password,
};
use crate::routes::ConsoleState;

const BACKUP_APP: &str = "keyla";
const BACKUP_VERSION: i64 = 1;

/// Child-first config tables; inserts run in reverse.
const CONFIG_TABLES: [&str; 17] = [
    "share_links",
    "provider_oauth_states",
    "tenant_disabled_models",
    "models",
    "provider_routing_settings",
    "provider_accounts",
    "pool_routing_settings",
    "network_pools",
    "providers",
    "model_aliases",
    "model_combos",
    "cli_tool_mappings",
    "cli_tool_settings",
    "console_settings",
    "studio_sessions",
    "api_keys",
    "tenants",
];

const TELEMETRY_TABLES: [&str; 2] = ["telemetry_events", "telemetry_usage_totals"];

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

fn server_error(error: impl std::fmt::Display) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("backup failed: {error}"),
    )
}

/// Ownership predicate for a table. `$1` is always the tenant id.
fn owned_clause(table: &str) -> Option<&'static str> {
    match table {
        "share_links" => Some("api_key_id IN (SELECT id FROM api_keys WHERE tenant_id = $1::uuid)"),
        "provider_oauth_states" => Some(
            "provider_account_id IN (SELECT id FROM provider_accounts WHERE tenant_id = $1::uuid)",
        ),
        "models" => Some(
            "provider_id IN (SELECT id FROM providers WHERE tenant_id = $1::uuid)
             AND (source IS NULL OR source <> 'builtin')",
        ),
        "tenants" => Some("id = $1::uuid"),
        _ => None,
    }
}

fn has_tenant_column(table: &str) -> bool {
    matches!(
        table,
        "tenant_disabled_models"
            | "provider_routing_settings"
            | "provider_accounts"
            | "pool_routing_settings"
            | "network_pools"
            | "providers"
            | "model_aliases"
            | "model_combos"
            | "cli_tool_mappings"
            | "cli_tool_settings"
            | "console_settings"
            | "studio_sessions"
            | "api_keys"
            | "telemetry_events"
            | "telemetry_usage_totals"
    )
}

fn where_clause(table: &str) -> String {
    if has_tenant_column(table) {
        "tenant_id = $1::uuid".to_owned()
    } else {
        owned_clause(table).unwrap_or("false").to_owned()
    }
}

#[allow(clippy::result_large_err)]
async fn verify_console_password(
    state: &ConsoleState,
    headers: &HeaderMap,
    password: &str,
) -> Result<(), Response> {
    let cookie = headers.get("cookie").and_then(|value| value.to_str().ok());
    let token = cookie.and_then(|header| parse_cookie(Some(header), SESSION_COOKIE_NAME));
    let Some(token) = token else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "reauthentication_required",
            "password is incorrect",
        ));
    };
    let session = validate_session(&state.pool, &token).await.ok().flatten();
    let Some(session) = session else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "reauthentication_required",
            "password is incorrect",
        ));
    };
    let user = find_user_by_id(&state.pool, &session.user_id)
        .await
        .ok()
        .flatten();
    match user {
        Some(user) if verify_password(password, &user.password_hash) => Ok(()),
        _ => Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "password is incorrect",
        )),
    }
}

#[allow(clippy::result_large_err)]
async fn authorize(state: &ConsoleState, headers: &HeaderMap) -> Result<String, Response> {
    let Some(access) = resolve_console_access(&state.pool, headers)
        .await
        .ok()
        .flatten()
    else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        ));
    };
    if let Err(error) = crate::access::require_scope(&access, "dashboard:write") {
        let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::FORBIDDEN);
        return Err(error_response(status, "insufficient_scope", &error.message));
    }
    access.tenant_id.ok_or_else(|| {
        error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant isolation required",
        )
    })
}

#[allow(clippy::result_large_err)]
fn parse_sections(raw: Option<&String>) -> Result<Vec<String>, Response> {
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(vec!["config".into()]);
    };
    let mut sections = Vec::new();
    for section in raw.split(',') {
        let section = section.trim();
        if section != "config" && section != "telemetry" {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("unknown backup section \"{section}\""),
            ));
        }
        sections.push(section.to_owned());
    }
    Ok(sections)
}

async fn export_table(
    state: &ConsoleState,
    tenant: &str,
    table: &str,
) -> Result<Vec<Value>, sqlx::Error> {
    let sql = format!(
        "SELECT coalesce(json_agg(row_to_json(t)), '[]'::json) AS rows
         FROM (SELECT * FROM \"{table}\" WHERE {} LIMIT 500000) t",
        where_clause(table)
    );
    let row = sqlx::query(&sql)
        .bind(tenant)
        .fetch_one(&state.pool)
        .await?;
    Ok(row
        .try_get::<Value, _>("rows")
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default())
}

/// `GET /console/api/backup/export?password=&sections=`.
pub async fn export(
    State(state): State<ConsoleState>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(password) = query.get("password") else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "password is incorrect",
        );
    };
    if let Err(response) = verify_console_password(&state, &headers, password).await {
        return response;
    }
    let sections = match parse_sections(query.get("sections")) {
        Ok(sections) => sections,
        Err(response) => return response,
    };
    let mut config = Map::new();
    let mut telemetry = Map::new();
    if sections.iter().any(|section| section == "config") {
        for table in CONFIG_TABLES {
            match export_table(&state, &tenant, table).await {
                Ok(rows) => {
                    config.insert(table.to_owned(), Value::Array(rows));
                }
                Err(error) => return server_error(error),
            }
        }
    }
    if sections.iter().any(|section| section == "telemetry") {
        for table in TELEMETRY_TABLES {
            match export_table(&state, &tenant, table).await {
                Ok(rows) => {
                    telemetry.insert(table.to_owned(), Value::Array(rows));
                }
                Err(error) => return server_error(error),
            }
        }
    }
    let mut sections_value = Map::new();
    if !config.is_empty() {
        sections_value.insert("config".into(), Value::Object(config));
    }
    if !telemetry.is_empty() {
        sections_value.insert("telemetry".into(), Value::Object(telemetry));
    }
    let payload = json!({
        "app": BACKUP_APP,
        "version": BACKUP_VERSION,
        "exportedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "sections": sections_value,
    });
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .header(
            "content-disposition",
            format!(
                "attachment; filename=\"keyla-backup-{}.json\"",
                chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S")
            ),
        )
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

use axum::response::IntoResponse;

/// Normalizes backup cells: accepts this gateway's raw rows and the tagged
/// `{__date}` / `{__bytes}` spelling older exports use.
fn normalize_row(row: &Value) -> Value {
    let Some(object) = row.as_object() else {
        return Value::Null;
    };
    let mut out = Map::new();
    for (key, value) in object {
        let normalized = match value {
            Value::Object(map) => {
                if let Some(date) = map.get("__date").and_then(Value::as_str) {
                    json!(date)
                } else if let Some(bytes) = map.get("__bytes").and_then(Value::as_str) {
                    let hex = STANDARD
                        .decode(bytes)
                        .map(|decoded| {
                            let mut encoded = String::with_capacity(decoded.len() * 2 + 2);
                            encoded.push_str("\\x");
                            for byte in decoded {
                                encoded.push_str(&format!("{byte:02x}"));
                            }
                            encoded
                        })
                        .unwrap_or_default();
                    json!(hex)
                } else {
                    value.clone()
                }
            }
            _ => value.clone(),
        };
        out.insert(key.clone(), normalized);
    }
    Value::Object(out)
}

fn relabeled_row(row: &Value, tenant: &str, table: &str) -> Option<Value> {
    let mut normalized = normalize_row(row);
    let object = normalized.as_object_mut()?;
    if has_tenant_column(table) {
        object.insert("tenant_id".into(), json!(tenant));
    }
    Some(normalized)
}

async fn delete_owned(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    table: &str,
) -> Result<u64, sqlx::Error> {
    let sql = format!("DELETE FROM \"{table}\" WHERE {}", where_clause(table));
    let result = sqlx::query(&sql)
        .bind(tenant)
        .execute(&mut **transaction)
        .await?;
    Ok(result.rows_affected())
}

async fn parent_owned(
    pool: &sqlx::PgPool,
    tenant: &str,
    table: &str,
    row: &Value,
) -> Result<bool, sqlx::Error> {
    match table {
        "share_links" => {
            let Some(id) = row.get("api_key_id").and_then(Value::as_str) else {
                return Ok(false);
            };
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM api_keys WHERE id = $1::uuid AND tenant_id = $2::uuid)",
            )
            .bind(id)
            .bind(tenant)
            .fetch_one(pool)
            .await
        }
        "provider_oauth_states" => {
            let Some(id) = row.get("provider_account_id").and_then(Value::as_str) else {
                return Ok(false);
            };
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM provider_accounts WHERE id = $1::uuid AND tenant_id = $2::uuid)",
            )
            .bind(id)
            .bind(tenant)
            .fetch_one(pool)
            .await
        }
        "models" => {
            let Some(id) = row.get("provider_id").and_then(Value::as_str) else {
                return Ok(false);
            };
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM providers WHERE id = $1 AND tenant_id = $2::uuid)",
            )
            .bind(id)
            .bind(tenant)
            .fetch_one(pool)
            .await
        }
        "tenants" => Ok(false),
        _ => Ok(has_tenant_column(table)),
    }
}

/// `POST /console/api/backup/import` — `{password, backup}`.
pub async fn import(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(password) = body.get("password").and_then(Value::as_str) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "password is incorrect",
        );
    };
    if let Err(response) = verify_console_password(&state, &headers, password).await {
        return response;
    }
    let Some(backup) = body.get("backup") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "backup is required",
        );
    };
    let app = backup.get("app").and_then(Value::as_str).unwrap_or("");
    if app != BACKUP_APP && app != "cartethyia" {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "This file is not a Keyla backup",
        );
    }
    if backup.get("version").and_then(Value::as_i64) != Some(BACKUP_VERSION) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Unsupported backup version",
        );
    }
    let Some(sections) = backup.get("sections").and_then(Value::as_object) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "sections are required",
        );
    };
    let config = sections.get("config").and_then(Value::as_object);
    let telemetry = sections.get("telemetry").and_then(Value::as_object);
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error(error),
    };
    let mut restored: Map<String, Value> = Map::new();
    let mut skipped: Map<String, Value> = Map::new();
    if let Some(config) = config {
        for table in CONFIG_TABLES
            .iter()
            .copied()
            .filter(|table| *table != "tenants")
        {
            if let Err(error) = delete_owned(&mut transaction, &tenant, table).await {
                return server_error(error);
            }
        }
        for table in CONFIG_TABLES
            .iter()
            .rev()
            .copied()
            .filter(|table| *table != "tenants")
        {
            let Some(rows) = config.get(table).and_then(Value::as_array) else {
                continue;
            };
            let mut inserted = 0u64;
            let mut rejected = 0u64;
            for row in rows {
                let Some(row) = relabeled_row(row, &tenant, table) else {
                    rejected += 1;
                    continue;
                };
                if table != "tenants" {
                    match parent_owned(&state.pool, &tenant, table, &row).await {
                        Ok(true) => {}
                        Ok(false) => {
                            rejected += 1;
                            continue;
                        }
                        Err(error) => return server_error(error),
                    }
                }
                let sql = format!(
                    "INSERT INTO \"{table}\" SELECT * FROM jsonb_populate_record(NULL::\"{table}\", $1::jsonb)"
                );
                if let Err(error) = sqlx::query(&sql)
                    .bind(&row)
                    .execute(&mut *transaction)
                    .await
                {
                    rejected += 1;
                    let _ = error;
                } else {
                    inserted += 1;
                }
            }
            restored.insert(table.to_owned(), json!(inserted));
            if rejected > 0 {
                skipped.insert(table.to_owned(), json!(rejected));
            }
        }
    }
    if let Some(telemetry) = telemetry {
        for table in TELEMETRY_TABLES {
            let Some(rows) = telemetry.get(table).and_then(Value::as_array) else {
                continue;
            };
            let mut inserted = 0u64;
            for row in rows {
                let Some(row) = relabeled_row(row, &tenant, table) else {
                    continue;
                };
                let sql = format!(
                    "INSERT INTO \"{table}\" SELECT * FROM jsonb_populate_record(NULL::\"{table}\", $1::jsonb)
                     ON CONFLICT DO NOTHING"
                );
                if sqlx::query(&sql)
                    .bind(&row)
                    .execute(&mut *transaction)
                    .await
                    .is_ok()
                {
                    inserted += 1;
                }
            }
            restored.insert(table.to_owned(), json!(inserted));
        }
    }
    if let Err(error) = transaction.commit().await {
        return server_error(error);
    }
    state.snapshots.invalidate();
    console_response(
        StatusCode::OK,
        json!({"restored": restored, "skipped": skipped, "format": "native"}),
    )
}

/// `POST /console/api/backup/delete-all` — `{password, scopes}`.
pub async fn delete_all(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(password) = body.get("password").and_then(Value::as_str) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "password is incorrect",
        );
    };
    if let Err(response) = verify_console_password(&state, &headers, password).await {
        return response;
    }
    let Some(scopes) = body.get("scopes").and_then(Value::as_array) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "select at least one delete scope",
        );
    };
    let mut selected = std::collections::HashSet::new();
    for scope in scopes {
        match scope.as_str() {
            Some("providers") | Some("proxies") | Some("configuration") => {
                selected.insert(scope.as_str().unwrap_or_default());
            }
            _ => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "unknown delete scope",
                );
            }
        }
    }
    if selected.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "select at least one delete scope",
        );
    }
    let all = selected.contains("configuration");
    let providers = all || selected.contains("providers");
    let proxies = all || selected.contains("proxies");
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error(error),
    };
    let mut deleted: Map<String, Value> = Map::new();
    if providers {
        let tables = [
            "provider_oauth_states",
            "tenant_disabled_models",
            "models",
            "provider_routing_settings",
            "provider_accounts",
            "providers",
        ];
        for table in tables {
            match delete_owned(&mut transaction, &tenant, table).await {
                Ok(count) => {
                    deleted.insert(table.to_owned(), json!(count));
                }
                Err(error) => return server_error(error),
            }
        }
    }
    if proxies {
        for table in ["network_pools", "pool_routing_settings"] {
            match delete_owned(&mut transaction, &tenant, table).await {
                Ok(count) => {
                    deleted.insert(table.to_owned(), json!(count));
                }
                Err(error) => return server_error(error),
            }
        }
    }
    if all {
        let tables = [
            "share_links",
            "cli_tool_mappings",
            "cli_tool_settings",
            "studio_sessions",
            "model_aliases",
            "model_combos",
            "api_keys",
            "console_settings",
        ];
        for table in tables {
            match delete_owned(&mut transaction, &tenant, table).await {
                Ok(count) => {
                    deleted.insert(table.to_owned(), json!(count));
                }
                Err(error) => return server_error(error),
            }
        }
    }
    if let Err(error) = transaction.commit().await {
        return server_error(error);
    }
    state.snapshots.invalidate();
    console_response(StatusCode::OK, json!({"deleted": deleted, "apiKeyIds": []}))
}
