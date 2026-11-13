//! Public Bansos page: the keys an operator deliberately published.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::console_response;
use crate::routes::ConsoleState;

fn public_origin(headers: &HeaderMap) -> String {
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

fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// `GET /console/api/bansos/public`.
pub async fn public(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant: Option<String> =
        sqlx::query_scalar("SELECT id::text FROM tenants ORDER BY id LIMIT 1")
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let base_url = std::env::var("KEYLA_PUBLIC_ORIGIN")
        .ok()
        .map(|value| value.trim_end_matches('/').to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| public_origin(&headers));
    let Some(tenant) = tenant else {
        return console_response(
            StatusCode::OK,
            json!({
                "baseUrl": base_url,
                "keys": [],
                "totals": {"keys": 0, "tokensConsumed": 0, "tokenBudget": null},
                "models": [],
                "last24h": {"requests": 0, "inputTokens": 0, "outputTokens": 0, "failed": 0},
                "recent": [],
            }),
        );
    };
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, label, key_prefix, key_encrypted, requests_per_minute,
                max_concurrent_requests, daily_token_limit, monthly_token_limit,
                lifetime_token_budget, lifetime_tokens_consumed, model_access_mode,
                model_list, expires_at
         FROM api_keys
         WHERE tenant_id = $1::uuid AND bansos_enabled = true AND enabled = true
           AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
         ORDER BY sort_index, created_at, id",
    )
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let ids: Vec<String> = rows.iter().map(|row| row.get("id")).collect();
    let mut consumed = 0i64;
    let mut budget = 0i64;
    let keys: Vec<Value> = rows
        .iter()
        .map(|row| {
            consumed += row
                .try_get::<Option<i64>, _>("lifetime_tokens_consumed")
                .ok()
                .flatten()
                .unwrap_or(0);
            budget += row
                .try_get::<Option<i64>, _>("lifetime_token_budget")
                .ok()
                .flatten()
                .unwrap_or(0);
            let secret = row
                .try_get::<Option<Vec<u8>>, _>("key_encrypted")
                .ok()
                .flatten()
                .and_then(|ciphertext| {
                    keyla_security::decrypt_credential_to_string(&ciphertext).ok()
                });
            let model_mode: String = row.get("model_access_mode");
            let models: Vec<String> = row
                .try_get::<Option<Value>, _>("model_list")
                .ok()
                .flatten()
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let token_budget = row
                .try_get::<Option<i64>, _>("lifetime_token_budget")
                .ok()
                .flatten();
            let tokens_consumed = row
                .try_get::<Option<i64>, _>("lifetime_tokens_consumed")
                .ok()
                .flatten()
                .unwrap_or(0);
            json!({
                "id": row.get::<String, _>("id"),
                "label": row.get::<String, _>("label"),
                "prefix": row.try_get::<Option<String>, _>("key_prefix").ok().flatten(),
                "secret": secret,
                "models": models,
                "modelRestricted": model_mode == "whitelist" && !models.is_empty(),
                "requestsPerMinute": row.try_get::<Option<i32>, _>("requests_per_minute").ok().flatten(),
                "maxConcurrentRequests": row.try_get::<Option<i32>, _>("max_concurrent_requests").ok().flatten(),
                "dailyTokenLimit": row.try_get::<Option<i64>, _>("daily_token_limit").ok().flatten(),
                "monthlyTokenLimit": row.try_get::<Option<i64>, _>("monthly_token_limit").ok().flatten(),
                "tokenBudget": token_budget,
                "tokensConsumed": tokens_consumed,
                "remaining": token_budget.map(|limit| (limit - tokens_consumed).max(0)),
                "expiresAt": row
                    .try_get::<Option<DateTime<Utc>>, _>("expires_at")
                    .ok()
                    .flatten()
                    .map(iso),
            })
        })
        .collect();
    let mut models: Vec<Value> = Vec::new();
    if !ids.is_empty() {
        let model_rows: Vec<PgRow> = sqlx::query(
            "SELECT DISTINCT m.model_id, p.id AS provider_id, m.context_limit, m.output_limit,
                    m.reasoning, m.tool_call, m.modalities
             FROM models m JOIN providers p ON p.id = m.provider_id
             WHERE m.enabled = true AND p.enabled = true
               AND (p.tenant_id IS NULL OR p.tenant_id = $1::uuid)
             ORDER BY m.model_id LIMIT 500",
        )
        .bind(&tenant)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        models = model_rows
            .iter()
            .map(|row| {
                let modalities = row
                    .try_get::<Option<Value>, _>("modalities")
                    .ok()
                    .flatten()
                    .unwrap_or(Value::Null);
                json!({
                    "name": row.get::<String, _>("model_id"),
                    "provider": row.get::<String, _>("provider_id"),
                    "contextLimit": row.try_get::<Option<i32>, _>("context_limit").ok().flatten(),
                    "outputLimit": row.try_get::<Option<i32>, _>("output_limit").ok().flatten(),
                    "reasoning": row.try_get::<bool, _>("reasoning").unwrap_or(false),
                    "toolCall": row.try_get::<bool, _>("tool_call").unwrap_or(false),
                    "vision": modalities.get("input").and_then(Value::as_array).map(|values| values.iter().any(|value| value.as_str() == Some("image"))).unwrap_or(false),
                })
            })
            .collect();
    }
    let totals = if ids.is_empty() {
        (0i64, 0i64, 0i64, 0i64)
    } else {
        let row = sqlx::query(
            "SELECT count(*)::bigint AS requests,
                    coalesce(sum(input_tokens), 0)::bigint AS input_tokens,
                    coalesce(sum(output_tokens), 0)::bigint AS output_tokens,
                    count(*) FILTER (WHERE status <> 'completed')::bigint AS failed
             FROM telemetry_events
             WHERE api_key_id::text = ANY($1) AND created_at >= now() - interval '24 hours'",
        )
        .bind(&ids)
        .fetch_one(&state.pool)
        .await
        .ok();
        row.map(|row| {
            (
                row.get("requests"),
                row.get("input_tokens"),
                row.get("output_tokens"),
                row.get("failed"),
            )
        })
        .unwrap_or((0, 0, 0, 0))
    };
    let recent: Vec<Value> = if ids.is_empty() {
        Vec::new()
    } else {
        let rows: Vec<PgRow> = sqlx::query(
            "SELECT id::text AS id, created_at, api_key_id::text AS api_key_id,
                    requested_model, status::text AS status, http_status, input_tokens,
                    output_tokens, latency_ms, stream
             FROM telemetry_events WHERE api_key_id::text = ANY($1)
             ORDER BY created_at DESC LIMIT 50",
        )
        .bind(&ids)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        let label_map: std::collections::HashMap<String, String> = keys
            .iter()
            .filter_map(|key| {
                Some((
                    key.get("id")?.as_str()?.to_owned(),
                    key.get("label")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        rows.iter()
            .map(|row| {
                let key_id = row
                    .try_get::<Option<String>, _>("api_key_id")
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                json!({
                    "id": row.get::<String, _>("id"),
                    "at": iso(row.get::<DateTime<Utc>, _>("created_at")),
                    "keyLabel": label_map.get(&key_id).cloned().unwrap_or_else(|| "—".into()),
                    "model": row.try_get::<Option<String>, _>("requested_model").ok().flatten(),
                    "ok": row.try_get::<Option<String>, _>("status").ok().flatten().as_deref() == Some("completed"),
                    "httpStatus": row.try_get::<Option<i32>, _>("http_status").ok().flatten(),
                    "inputTokens": row.try_get::<Option<i32>, _>("input_tokens").ok().flatten().unwrap_or(0),
                    "outputTokens": row.try_get::<Option<i32>, _>("output_tokens").ok().flatten().unwrap_or(0),
                    "latencyMs": row.try_get::<Option<i32>, _>("latency_ms").ok().flatten(),
                    "stream": row.try_get::<Option<bool>, _>("stream").ok().flatten().unwrap_or(false),
                })
            })
            .collect()
    };
    console_response(
        StatusCode::OK,
        json!({
            "baseUrl": base_url,
            "keys": keys,
            "totals": {
                "keys": ids.len(),
                "tokensConsumed": consumed,
                "tokenBudget": if budget == 0 { Value::Null } else { json!(budget) },
            },
            "models": models,
            "last24h": {
                "requests": totals.0,
                "inputTokens": totals.1,
                "outputTokens": totals.2,
                "failed": totals.3,
            },
            "recent": recent,
        }),
    )
}
