//! Quota overview: provider/account rows joined with cached account health.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

fn optional_iso(row: &PgRow, column: &str) -> Option<String> {
    row.try_get::<Option<DateTime<Utc>>, _>(column)
        .ok()
        .flatten()
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn account_entry(row: &PgRow) -> Value {
    let provider_id: String = row.get("provider_id");
    let provider_name = keyla_providers::provider_display_name(&provider_id);
    let status: String = row.get("status");
    let remaining_percent = row
        .try_get::<Option<f64>, _>("last_remaining_percent")
        .ok()
        .flatten();
    let last_success = optional_iso(row, "last_success_at");
    let quota = remaining_percent.map(|percent| {
        json!({
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
            "fetchedAt": last_success,
            "lastAttemptAt": last_success,
            "lastSuccessAt": last_success,
            "error": Value::Null,
        })
    });
    let mut health = json!({
        "status": status,
        "lastErrorCategory": row.try_get::<Option<String>, _>("last_error_category").ok().flatten(),
        "cooldownUntil": optional_iso(row, "cooldown_until"),
    });
    if let Ok(Some(cooldowns)) = row.try_get::<Option<Value>, _>("model_cooldowns") {
        health
            .as_object_mut()
            .expect("object")
            .insert("modelCooldowns".into(), cooldowns);
    }
    json!({
        "id": row.get::<sqlx::types::Uuid, _>("id").to_string(),
        "provider": provider_id,
        "name": row.get::<String, _>("label"),
        "credentialHint": row.try_get::<Option<String>, _>("credential_fingerprint").ok().flatten().unwrap_or_else(|| "•••".into()),
        "active": status == "active",
        "quota": quota,
        "health": health,
        "providerName": provider_name,
        "providerIcon": provider_id,
    })
}

/// `GET /console/api/quota/overview`.
pub async fn overview(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT a.id, a.provider_id, a.label, a.credential_fingerprint,
                a.status::text AS status, a.last_error, a.last_error_category,
                a.last_success_at, a.cooldown_until, a.model_cooldowns,
                a.last_remaining_percent
         FROM provider_accounts a JOIN providers p ON p.id = a.provider_id
         WHERE a.tenant_id IS NULL OR a.tenant_id = $1::uuid
         ORDER BY a.provider_id, a.sort_index, a.created_at, a.id",
    )
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("quota overview failed: {error}"),
            );
        }
    };
    let mut providers: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut accounts = Vec::new();
    for row in &rows {
        let provider_id: String = row.get("provider_id");
        if seen.insert(provider_id.clone()) {
            let mut summary = Map::new();
            summary.insert("id".into(), json!(provider_id));
            summary.insert(
                "name".into(),
                json!(keyla_providers::provider_display_name(&provider_id)),
            );
            summary.insert("icon".into(), json!(provider_id));
            providers.push(Value::Object(summary));
        }
        accounts.push(account_entry(row));
    }
    console_response(
        StatusCode::OK,
        json!({"providers": providers, "accounts": accounts, "refreshing": 0}),
    )
}
