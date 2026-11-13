//! Platform-admin moderation surfaces: audit trail and model-abuse bans.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::Row;

use crate::access::{console_error_body, console_response, require_scope, resolve_console_access};
use crate::routes::ConsoleState;

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

fn server_error(error: impl std::fmt::Display) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("moderation operation failed: {error}"),
    )
}

#[allow(clippy::result_large_err)]
async fn platform_admin(state: &ConsoleState, headers: &HeaderMap) -> Result<String, Response> {
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
    if let Err(error) = require_scope(&access, "platform:admin") {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            &error.message,
        ));
    }
    access.tenant_id.ok_or_else(|| {
        error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        )
    })
}

/// `GET /console/api/audit?limit=&cursor=&action=&actor=`.
pub async fn list_audit(
    State(state): State<ConsoleState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match platform_admin(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let action = query.get("action").filter(|value| !value.is_empty());
    let actor = query.get("actor").filter(|value| !value.is_empty());
    let rows: Vec<sqlx::postgres::PgRow> = match sqlx::query(
        "SELECT a.id::text AS id, a.created_at, a.actor, a.tenant_id::text AS tenant_id,
                a.action, a.target, a.detail,
                coalesce(u.display_name, u.username) AS actor_name
         FROM admin_audit_log a
         LEFT JOIN console_users u ON u.id::text = a.actor
         WHERE (a.tenant_id = $1::uuid OR a.tenant_id IS NULL)
           AND ($2::text IS NULL OR a.action = $2)
           AND ($3::text IS NULL OR a.actor = $3)
         ORDER BY a.created_at DESC, a.id DESC LIMIT $4",
    )
    .bind(&tenant)
    .bind(action)
    .bind(actor)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return server_error(error),
    };
    let entries: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "createdAt": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
                "actor": row.get::<String, _>("actor"),
                "actorName": row.try_get::<Option<String>, _>("actor_name").ok().flatten(),
                "tenantId": row.try_get::<Option<String>, _>("tenant_id").ok().flatten(),
                "action": row.get::<String, _>("action"),
                "target": row.get::<String, _>("target"),
                "detail": row.try_get::<Option<Value>, _>("detail").ok().flatten(),
            })
        })
        .collect();
    console_response(StatusCode::OK, json!({"entries": entries}))
}

/// `GET /console/api/model-bans`.
pub async fn list_model_bans(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = platform_admin(&state, &headers).await {
        return response;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    let bans: Vec<Value> = keyla_security::model_abuse::global()
        .list_bans(now)
        .into_iter()
        .map(|(ip, expires_at)| json!({"ip": ip, "expiresAt": expires_at}))
        .collect();
    console_response(StatusCode::OK, json!({"bans": bans}))
}

/// `DELETE /console/api/model-bans` — `{identity}`.
pub async fn unban_model(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(response) = platform_admin(&state, &headers).await {
        return response;
    }
    let Some(identity) = body
        .get("identity")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "identity is required",
        );
    };
    if keyla_security::model_abuse::global().unban(identity) {
        console_response(StatusCode::OK, json!({"success": true}))
    } else {
        error_response(StatusCode::NOT_FOUND, "ban_not_found", "No such ban")
    }
}
