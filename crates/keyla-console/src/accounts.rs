//! Account-level console operations shared by the quota page: status flips,
//! deletion, quota projections, and explicitly unsupported provider actions.
//!
//! Quota collectors live in the provider layer; until a provider has one, the
//! quota projection reports `null` (the same "untracked" answer the TS console
//! gives collectorless providers) instead of manufacturing an upstream error.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::{
    authorize_tenant, console_error_body, console_response, require_scope, resolve_console_access,
};
use crate::routes::ConsoleState;

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

fn server_error(error: impl std::fmt::Display) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("account operation failed: {error}"),
    )
}

fn optional_iso(row: &PgRow, column: &str) -> Option<String> {
    row.try_get::<Option<DateTime<Utc>>, _>(column)
        .ok()
        .flatten()
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn account_health(row: &PgRow) -> Value {
    let mut health = json!({
        "status": row.get::<String, _>("status"),
        "lastErrorCategory": row.try_get::<Option<String>, _>("last_error_category").ok().flatten(),
        "cooldownUntil": optional_iso(row, "cooldown_until"),
    });
    if let Ok(Some(cooldowns)) = row.try_get::<Option<Value>, _>("model_cooldowns") {
        health
            .as_object_mut()
            .expect("object")
            .insert("modelCooldowns".into(), cooldowns);
    }
    health
}

fn quota_view(row: &PgRow) -> Value {
    let percent = row
        .try_get::<Option<f64>, _>("last_remaining_percent")
        .ok()
        .flatten();
    match percent {
        Some(percent) => json!({
            "source": "account-row",
            "status": "ready",
            "plan": Value::Null,
            "windows": [{
                "kind": "credit",
                "label": "Remaining",
                "remainingPercent": percent,
                "usedPercent": (100.0 - percent).clamp(0.0, 100.0),
                "resetsAt": Value::Null,
                "used": Value::Null,
                "limit": Value::Null,
                "remaining": Value::Null,
                "recurring": false,
            }],
            "fetchedAt": optional_iso(row, "last_success_at"),
            "lastAttemptAt": optional_iso(row, "last_success_at"),
            "lastSuccessAt": optional_iso(row, "last_success_at"),
            "error": Value::Null,
        }),
        None => Value::Null,
    }
}

async fn load_owned_account(
    state: &ConsoleState,
    tenant: &str,
    account_id: &str,
) -> Result<Option<PgRow>, sqlx::Error> {
    sqlx::query(
        "SELECT id::text AS id, provider_id, tenant_id::text AS tenant_id, label,
                credential_kind::text AS credential_kind, status::text AS status,
                last_error, last_error_category, last_success_at, cooldown_until,
                model_cooldowns, last_remaining_percent::float8 AS last_remaining_percent,
                credential_ciphertext, auth_state
         FROM provider_accounts WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(account_id)
    .bind(tenant)
    .fetch_optional(&state.pool)
    .await
}

/// `GET /console/api/accounts/{id}/quota`.
pub async fn get_quota(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    match load_owned_account(&state, &tenant, &account_id).await {
        Ok(Some(row)) => console_response(
            StatusCode::OK,
            json!({
                "accountId": account_id,
                "quota": quota_view(&row),
                "health": account_health(&row),
            }),
        ),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Account {account_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/accounts/{id}/quota/refresh`.
pub async fn refresh_quota(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    match load_owned_account(&state, &tenant, &account_id).await {
        Ok(Some(row)) => {
            let quota = refresh_account_quota(&state, &row, &tenant).await;
            console_response(
                StatusCode::OK,
                json!({
                    "ok": true,
                    "status": 200,
                    "data": {"id": account_id, "quota": quota},
                }),
            )
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Account {account_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `PATCH /console/api/accounts/{id}` — `{active}` or `{status}`.
pub async fn patch_account(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let status = body
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            body.get("active")
                .and_then(Value::as_bool)
                .map(|active| if active { "active" } else { "disabled" }.to_owned())
        });
    let Some(status) = status else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "status or active is required",
        );
    };
    if !["active", "disabled"].contains(&status.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "status must be active or disabled",
        );
    }
    let updated = sqlx::query(
        "UPDATE provider_accounts SET status = $3::health_status
         WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id",
    )
    .bind(&account_id)
    .bind(&tenant)
    .bind(&status)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            console_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Account {account_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `PATCH /console/api/accounts/batch` — `{ids, active}`.
pub async fn patch_accounts_batch(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let ids: Vec<String> = body
        .get("ids")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let Some(active) = body.get("active").and_then(Value::as_bool) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "active is required",
        );
    };
    if ids.is_empty() {
        return console_response(StatusCode::OK, json!({"ok": true, "updated": 0}));
    }
    if ids.len() > 500 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "ids exceeds the limit of 500",
        );
    }
    let status = if active { "active" } else { "disabled" };
    let result = sqlx::query(
        "UPDATE provider_accounts SET status = $3::health_status
         WHERE tenant_id = $1::uuid AND id::text = ANY($2)",
    )
    .bind(&tenant)
    .bind(&ids)
    .bind(status)
    .execute(&state.pool)
    .await;
    match result {
        Ok(result) => {
            state.snapshots.invalidate();
            console_response(
                StatusCode::OK,
                json!({"ok": true, "updated": result.rows_affected()}),
            )
        }
        Err(error) => server_error(error),
    }
}

/// `DELETE /console/api/accounts/{id}`.
pub async fn delete_account(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let deleted = sqlx::query(
        "DELETE FROM provider_accounts WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id",
    )
    .bind(&account_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match deleted {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            console_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Account {account_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/accounts/{id}/checkin` — provider-specific.
pub async fn checkin_unsupported(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    match load_owned_account(&state, &tenant, &account_id).await {
        Ok(Some(row)) => error_response(
            StatusCode::BAD_REQUEST,
            "checkin_unsupported",
            &format!(
                "Daily check-in is not supported for provider {}",
                row.get::<String, _>("provider_id")
            ),
        ),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Account {account_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `GET /console/api/global/accounts` — tenant-less shared accounts.
pub async fn list_global_accounts(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "platform:admin") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, provider_id, label, credential_kind::text AS credential_kind,
                status::text AS status, last_error, last_error_category, last_success_at,
                cooldown_until, model_cooldowns,
                last_remaining_percent::float8 AS last_remaining_percent
         FROM provider_accounts WHERE tenant_id IS NULL ORDER BY provider_id, sort_index, id",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let accounts: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "providerId": row.get::<String, _>("provider_id"),
                "label": row.get::<String, _>("label"),
                "credentialKind": row.get::<String, _>("credential_kind"),
                "status": row.get::<String, _>("status"),
                "lastError": row.try_get::<Option<String>, _>("last_error").ok().flatten(),
                "lastSuccessAt": optional_iso(row, "last_success_at"),
                "cooldownUntil": optional_iso(row, "cooldown_until"),
                "lastRemainingPercent": row.try_get::<Option<f64>, _>("last_remaining_percent").ok().flatten(),
            })
        })
        .collect();
    console_response(StatusCode::OK, json!({"accounts": accounts}))
}

/// `PATCH /console/api/global/accounts/{id}`.
pub async fn patch_global_account(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "platform:admin") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let status = body
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            body.get("active")
                .and_then(Value::as_bool)
                .map(|active| if active { "active" } else { "disabled" }.to_owned())
        });
    let Some(status) = status else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "status or active is required",
        );
    };
    if !["active", "disabled"].contains(&status.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "status must be active or disabled",
        );
    }
    let updated = sqlx::query(
        "UPDATE provider_accounts SET status = $2::health_status
         WHERE id = $1::uuid AND tenant_id IS NULL RETURNING id",
    )
    .bind(&account_id)
    .bind(&status)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            console_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Global account {account_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `DELETE /console/api/global/accounts/{id}`.
pub async fn delete_global_account(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "platform:admin") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let deleted = sqlx::query(
        "DELETE FROM provider_accounts WHERE id = $1::uuid AND tenant_id IS NULL RETURNING id",
    )
    .bind(&account_id)
    .fetch_optional(&state.pool)
    .await;
    match deleted {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            console_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Global account {account_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `POST /console/api/quota/refresh` — `{accountIds}` or `{ids}`.
///
/// Providers without a quota collector have nothing to ask upstream; they are
/// acknowledged as queued with no success/failure rows, matching the
/// collectorless no-op the TS console performs.
pub async fn refresh_many(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let ids: Vec<String> = body
        .get("accountIds")
        .or_else(|| body.get("ids"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "accountIds must be a non-empty array",
        );
    }
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, provider_id, label, credential_ciphertext, credential_kind::text AS credential_kind,
                auth_state, status::text AS status, last_error, last_error_category,
                last_success_at, cooldown_until, model_cooldowns, last_remaining_percent,
                credential_fingerprint
         FROM provider_accounts
         WHERE tenant_id = $1::uuid AND id::text = ANY($2)",
    )
    .bind(&tenant)
    .bind(&ids)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let mut succeeded = 0usize;
    let mut failures = Vec::new();
    for row in &rows {
        let quota = refresh_account_quota(&state, row, &tenant).await;
        if quota.get("error").and_then(Value::as_str).is_none() {
            succeeded += 1;
        } else {
            failures.push(json!({
                "id": row.get::<String, _>("id"),
                "provider": row.get::<String, _>("provider_id"),
                "error": quota.get("error").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    console_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "queued": rows.len(),
            "succeeded": succeeded,
            "failed": failures.len(),
            "failures": failures,
        }),
    )
}

/// `POST /console/api/global/accounts/{id}/quota/refresh`.
pub async fn refresh_global_quota(
    State(state): State<ConsoleState>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "platform:admin") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let row: Option<PgRow> = sqlx::query(
        "SELECT id::text AS id, provider_id, label, credential_ciphertext, credential_kind::text AS credential_kind,
                auth_state, status::text AS status, last_error, last_error_category,
                last_success_at, cooldown_until, model_cooldowns, last_remaining_percent,
                credential_fingerprint
         FROM provider_accounts WHERE id = $1::uuid AND tenant_id IS NULL",
    )
    .bind(&account_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);
    let Some(row) = row else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("Global account {account_id} not found"),
        );
    };
    let quota = refresh_account_quota(&state, &row, "").await;
    console_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "status": 200,
            "data": {"id": account_id, "quota": quota},
        }),
    )
}

async fn refresh_account_quota(state: &ConsoleState, row: &PgRow, tenant: &str) -> Value {
    let provider_id: String = row.get("provider_id");
    let account_id: String = row.get("id");
    let credential_kind: String = row
        .try_get("credential_kind")
        .unwrap_or_else(|_| "none".to_owned());
    let credential = row
        .try_get::<Option<Vec<u8>>, _>("credential_ciphertext")
        .ok()
        .flatten()
        .and_then(|ciphertext| keyla_security::decrypt_credential_to_string(&ciphertext).ok())
        .unwrap_or_default();
    let auth_state = row.try_get::<Option<Value>, _>("auth_state").ok().flatten();
    let quota = crate::quota_fetch::collect(
        &provider_id,
        &credential,
        auth_state.as_ref(),
        &credential_kind,
    )
    .await;
    let (percent, credit) = crate::quota_fetch::summaries(&quota);
    if quota.get("error").and_then(Value::as_str).is_none() {
        let _ = sqlx::query(
            "UPDATE provider_accounts
             SET last_success_at = now(), last_error = NULL, last_error_category = NULL,
                 last_error_at = NULL, last_remaining_percent = $3, last_remaining_credit = $4
             WHERE id = $1::uuid AND ($2 = '' OR tenant_id = $2::uuid)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(percent)
        .bind(credit)
        .execute(&state.pool)
        .await;
    } else {
        let error = quota
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("quota refresh failed")
            .chars()
            .take(500)
            .collect::<String>();
        let _ = sqlx::query(
            "UPDATE provider_accounts
             SET last_error = $3, last_error_category = 'quota_fetch_failed', last_error_at = now()
             WHERE id = $1::uuid AND ($2 = '' OR tenant_id = $2::uuid)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(error)
        .execute(&state.pool)
        .await;
    }
    state.snapshots.invalidate();
    quota
}

/// Provider-specific reset/activity surfaces answer with the typed refusal.
pub async fn provider_action_unsupported() -> Response {
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        "capability_unsupported",
        "This provider-specific account action is not implemented in the Rust gateway yet",
    )
}
