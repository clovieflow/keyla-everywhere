//! Network-pool control plane: list, create, update, delete, strategy.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const KINDS: [&str; 4] = ["http", "https", "socks5", "bridge"];
const STATUSES: [&str; 2] = ["active", "disabled"];
const STRATEGIES: [&str; 2] = ["least_loaded", "round_robin"];

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

fn optional_iso(row: &PgRow, column: &str) -> Option<String> {
    row.try_get::<Option<DateTime<Utc>>, _>(column)
        .ok()
        .flatten()
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn split_config(row: &PgRow) -> (String, Option<String>, Map<String, Value>) {
    let config: Value = row
        .try_get::<Value, _>("endpoint_config")
        .unwrap_or_else(|_| json!({}));
    let mut object = config.as_object().cloned().unwrap_or_default();
    let endpoint = object
        .remove("endpoint")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let label = object
        .remove("label")
        .and_then(|value| value.as_str().map(str::to_owned));
    (endpoint, label, object)
}

fn pool_response(row: &PgRow) -> Value {
    let (endpoint, label, config) = split_config(row);
    let max_inflight: Option<i32> = row.try_get("max_inflight").ok().flatten();
    let weight: Option<i32> = row.try_get("weight").ok().flatten();
    let max_inflight = max_inflight.unwrap_or(10);
    let weight = weight.unwrap_or(100);
    let inflight: i64 = 0;
    let mut value = json!({
        "id": row.get::<sqlx::types::Uuid, _>("id").to_string(),
        "kind": row.get::<String, _>("kind_text"),
        "endpoint": endpoint,
        "maxInflight": max_inflight,
        "weight": weight,
        "status": row.get::<String, _>("status_text"),
        "inflight": inflight,
        "available": (max_inflight as i64 - inflight).max(0),
        "utilization": if max_inflight > 0 { (inflight as f64 / max_inflight as f64).min(1.0) } else { 1.0 },
        "consecutiveFailures": row.get::<i32, _>("consecutive_failures"),
        "tenantId": row.get::<sqlx::types::Uuid, _>("tenant_id").to_string(),
        "bytesSentTotal": row.try_get::<i64, _>("bytes_sent_total").unwrap_or(0),
        "bytesReceivedTotal": row.try_get::<i64, _>("bytes_received_total").unwrap_or(0),
    });
    let object = value.as_object_mut().expect("object");
    if let Some(label) = label {
        object.insert("label".into(), json!(label));
    }
    if !config.is_empty() {
        object.insert("config".into(), Value::Object(config));
    }
    if row
        .try_get::<Option<Vec<u8>>, _>("credential_ciphertext")
        .ok()
        .flatten()
        .is_some()
    {
        object.insert("hasCredential".into(), json!(true));
    }
    for (field, column) in [
        ("lastSuccessAt", "last_success_at"),
        ("lastHealthCheckAt", "last_health_check_at"),
        ("lastErrorAt", "last_error_at"),
        ("cooldownUntil", "cooldown_until"),
        ("lastSpeedtestAt", "last_speedtest_at"),
    ] {
        if let Some(value) = optional_iso(row, column) {
            object.insert(field.into(), json!(value));
        }
    }
    for (field, column) in [
        ("lastLatencyMs", "last_latency_ms"),
        ("lastSpeedtestBytes", "last_speedtest_bytes"),
        ("lastSpeedtestDurationMs", "last_speedtest_duration_ms"),
    ] {
        if let Ok(Some(value)) = row.try_get::<Option<i32>, _>(column) {
            object.insert(field.into(), json!(value));
        }
    }
    for (field, column) in [
        ("egressIp", "egress_ip"),
        ("lastErrorCategory", "last_error_category"),
        ("lastError", "last_error"),
        ("lastSpeedtestStatus", "last_speedtest_status"),
        ("lastSpeedtestError", "last_speedtest_error"),
    ] {
        if let Ok(Some(value)) = row.try_get::<Option<String>, _>(column) {
            object.insert(field.into(), json!(value));
        }
    }
    if let Ok(Some(value)) = row.try_get::<Option<i64>, _>("quota_bytes") {
        object.insert("quotaBytes".into(), json!(value));
    }
    value
}

fn validate_endpoint(kind: &str, endpoint: &str) -> Result<(), String> {
    if endpoint.trim().is_empty() {
        return Err("Endpoint is required".into());
    }
    if kind == "socks5" {
        let candidate = if endpoint.contains("://") {
            endpoint.to_owned()
        } else {
            format!("socks5://{endpoint}")
        };
        let parsed = url::Url::parse(&candidate).map_err(|_| "Endpoint must be host:port")?;
        if parsed.host_str().is_none() || parsed.port().is_none() {
            return Err("Endpoint must be host:port".into());
        }
        return Ok(());
    }
    let candidate = if kind == "bridge" && !endpoint.contains("://") {
        format!("https://{endpoint}")
    } else {
        endpoint.to_owned()
    };
    let parsed = url::Url::parse(&candidate).map_err(|_| "Endpoint must be a URL")?;
    if !["http", "https"].contains(&parsed.scheme()) {
        return Err("Endpoint must be an http(s) URL".into());
    }
    Ok(())
}

fn validate_limits(max_inflight: Option<i64>, weight: Option<i64>) -> Result<(), String> {
    if let Some(value) = max_inflight {
        if !(1..=1_000_000).contains(&value) {
            return Err("maxInflight must be an integer between 1 and 1000000".into());
        }
    }
    if let Some(value) = weight {
        if !(1..=1000).contains(&value) {
            return Err("weight must be an integer between 1 and 1000".into());
        }
    }
    Ok(())
}

fn build_endpoint_config(
    endpoint: &str,
    label: Option<&str>,
    config: &Map<String, Value>,
) -> Value {
    let mut object = config.clone();
    object.insert("endpoint".into(), json!(endpoint));
    if let Some(label) = label {
        object.insert("label".into(), json!(label));
    }
    Value::Object(object)
}

/// `GET /console/api/network/pools`.
pub async fn list_pools(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT *, kind::text AS kind_text, status::text AS status_text
         FROM network_pools WHERE tenant_id = $1::uuid ORDER BY created_at, id",
    )
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return server_error(error),
    };
    let data: Vec<Value> = rows.iter().map(pool_response).collect();
    console_response(StatusCode::OK, Value::Array(data))
}

/// `POST /console/api/network/pools`.
pub async fn create_pool(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(request) = body.as_object() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_pool",
            "Request body must be an object",
        );
    };
    let kind = request.get("kind").and_then(Value::as_str).unwrap_or("");
    if !KINDS.contains(&kind) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_pool",
            "Pool kind is required",
        );
    }
    let endpoint = request
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or("");
    if let Err(message) = validate_endpoint(kind, endpoint) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_endpoint", &message);
    }
    let max_inflight = request.get("maxInflight").and_then(Value::as_i64);
    let weight = request.get("weight").and_then(Value::as_i64);
    if let Err(message) = validate_limits(max_inflight, weight) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_pool_limits", &message);
    }
    let status = request
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("active");
    if !STATUSES.contains(&status) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_pool",
            "Pool status is invalid",
        );
    }
    let config = request
        .get("config")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let endpoint_config = build_endpoint_config(
        endpoint,
        request.get("label").and_then(Value::as_str),
        &config,
    );
    let credential = request.get("credential").and_then(Value::as_str);
    let credential_ciphertext = match credential {
        Some(secret) => match keyla_security::encrypt_credential(secret.as_bytes()) {
            Ok(bytes) => Some(bytes),
            Err(error) => return server_error(format!("encrypt: {error}")),
        },
        None => None,
    };
    let quota_bytes = request.get("quotaBytes").and_then(Value::as_i64);
    let inserted = sqlx::query(
        "INSERT INTO network_pools (
            kind, endpoint_config, credential_ciphertext, max_inflight, weight,
            tenant_id, status, quota_bytes
         ) VALUES ($1::network_pool_kind, $2::jsonb, $3, $4, $5, $6::uuid, $7::health_status, $8)
         RETURNING *, kind::text AS kind_text, status::text AS status_text",
    )
    .bind(kind)
    .bind(endpoint_config)
    .bind(&credential_ciphertext)
    .bind(max_inflight.unwrap_or(10) as i32)
    .bind(weight.unwrap_or(100) as i32)
    .bind(&tenant)
    .bind(status)
    .bind(quota_bytes)
    .fetch_one(&state.pool)
    .await;
    match inserted {
        Ok(row) => console_response(StatusCode::OK, pool_response(&row)),
        Err(error) => server_error(error),
    }
}

/// `PATCH /console/api/network/pools/{poolId}`.
pub async fn update_pool(
    State(state): State<ConsoleState>,
    Path(pool_id): Path<String>,
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
            "invalid_pool",
            "Request body must be an object",
        );
    };
    let current = match sqlx::query(
        "SELECT *, kind::text AS kind_text, status::text AS status_text
         FROM network_pools WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&pool_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "pool_not_found",
                &format!("Pool {pool_id} not found"),
            );
        }
        Err(error) => return server_error(error),
    };
    let (current_endpoint, current_label, current_config) = split_config(&current);
    let kind = patch
        .get("kind")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| current.get("kind_text"));
    if !KINDS.contains(&kind.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_pool",
            "Pool kind is invalid",
        );
    }
    let endpoint = patch
        .get("endpoint")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or(current_endpoint);
    if let Err(message) = validate_endpoint(&kind, &endpoint) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_endpoint", &message);
    }
    let label = match patch.get("label") {
        Some(Value::Null) => None,
        Some(value) => Some(value.as_str().unwrap_or_default().to_owned()),
        None => current_label,
    };
    let mut config = current_config;
    if let Some(overrides) = patch.get("config").and_then(Value::as_object) {
        for (key, value) in overrides {
            config.insert(key.clone(), value.clone());
        }
    }
    let max_inflight = match patch.get("maxInflight") {
        Some(value) => value.as_i64(),
        None => current
            .try_get::<Option<i32>, _>("max_inflight")
            .ok()
            .flatten()
            .map(i64::from),
    };
    let weight = match patch.get("weight") {
        Some(value) => value.as_i64(),
        None => current
            .try_get::<Option<i32>, _>("weight")
            .ok()
            .flatten()
            .map(i64::from),
    };
    if let Err(message) = validate_limits(max_inflight, weight) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_pool_limits", &message);
    }
    let status = patch
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| current.get("status_text"));
    if !STATUSES.contains(&status.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_pool",
            "Pool status is invalid",
        );
    }
    let endpoint_config = build_endpoint_config(&endpoint, label.as_deref(), &config);
    let credential_ciphertext = match patch.get("credential") {
        Some(Value::Null) => None,
        Some(value) => {
            let Some(secret) = value.as_str() else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_pool",
                    "credential must be a string",
                );
            };
            match keyla_security::encrypt_credential(secret.as_bytes()) {
                Ok(bytes) => Some(bytes),
                Err(error) => return server_error(format!("encrypt: {error}")),
            }
        }
        None => current
            .try_get::<Option<Vec<u8>>, _>("credential_ciphertext")
            .ok()
            .flatten(),
    };
    let quota_bytes = match patch.get("quotaBytes") {
        Some(Value::Null) => None,
        Some(value) => value.as_i64(),
        None => current
            .try_get::<Option<i64>, _>("quota_bytes")
            .ok()
            .flatten(),
    };
    let updated = sqlx::query(
        "UPDATE network_pools SET
            kind = $3::network_pool_kind, endpoint_config = $4::jsonb, credential_ciphertext = $5,
            max_inflight = $6, weight = $7, status = $8::health_status, quota_bytes = $9
         WHERE tenant_id = $1::uuid AND id = $2::uuid
         RETURNING *, kind::text AS kind_text, status::text AS status_text",
    )
    .bind(&tenant)
    .bind(&pool_id)
    .bind(&kind)
    .bind(endpoint_config)
    .bind(&credential_ciphertext)
    .bind(max_inflight.map(|value| value as i32))
    .bind(weight.map(|value| value as i32))
    .bind(&status)
    .bind(quota_bytes)
    .fetch_one(&state.pool)
    .await;
    match updated {
        Ok(row) => console_response(StatusCode::OK, pool_response(&row)),
        Err(error) => server_error(error),
    }
}

/// `DELETE /console/api/network/pools/{poolId}`.
pub async fn delete_pool(
    State(state): State<ConsoleState>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let deleted = sqlx::query(
        "DELETE FROM network_pools WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING id",
    )
    .bind(&tenant)
    .bind(&pool_id)
    .fetch_optional(&state.pool)
    .await;
    match deleted {
        Ok(Some(_)) => console_response(StatusCode::OK, json!({"success": true})),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "pool_not_found",
            &format!("Pool {pool_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

fn strategy_response(strategy: &str, rotate_count: i32) -> Value {
    json!({"strategy": strategy, "rotateCount": rotate_count})
}

/// `GET /console/api/network/pools/strategy`.
pub async fn get_strategy(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let row = sqlx::query(
        "SELECT strategy::text AS strategy, rotate_count FROM pool_routing_settings WHERE tenant_id = $1::uuid",
    )
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some(row)) => console_response(
            StatusCode::OK,
            strategy_response(
                &row.get::<String, _>("strategy"),
                row.get::<i32, _>("rotate_count"),
            ),
        ),
        Ok(None) => console_response(StatusCode::OK, strategy_response("least_loaded", 1)),
        Err(error) => server_error(error),
    }
}

/// `PATCH /console/api/network/pools/strategy`.
pub async fn update_strategy(
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
            "invalid_pool",
            "Request body must be an object",
        );
    };
    let current = sqlx::query(
        "SELECT strategy::text AS strategy, rotate_count FROM pool_routing_settings WHERE tenant_id = $1::uuid",
    )
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let current_strategy = current
        .as_ref()
        .map(|row| row.get::<String, _>("strategy"))
        .unwrap_or_else(|| "least_loaded".into());
    let current_rotate = current
        .as_ref()
        .map(|row| row.get::<i32, _>("rotate_count"))
        .unwrap_or(1);
    let strategy = patch
        .get("strategy")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or(current_strategy);
    if !STRATEGIES.contains(&strategy.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_pool",
            "Pool strategy is invalid",
        );
    }
    let rotate_count = patch
        .get("rotateCount")
        .and_then(Value::as_i64)
        .map(|value| value as i32)
        .unwrap_or(current_rotate);
    if !(1..=1000).contains(&rotate_count) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_pool_limits",
            "rotateCount must be an integer between 1 and 1000",
        );
    }
    let saved = sqlx::query(
        "INSERT INTO pool_routing_settings (tenant_id, strategy, rotate_count)
         VALUES ($1::uuid, $2::pool_routing_strategy, $3)
         ON CONFLICT (tenant_id) DO UPDATE
         SET strategy = $2::pool_routing_strategy, rotate_count = $3
         RETURNING strategy::text AS strategy, rotate_count",
    )
    .bind(&tenant)
    .bind(&strategy)
    .bind(rotate_count)
    .fetch_one(&state.pool)
    .await;
    match saved {
        Ok(row) => console_response(
            StatusCode::OK,
            strategy_response(
                &row.get::<String, _>("strategy"),
                row.get::<i32, _>("rotate_count"),
            ),
        ),
        Err(error) => server_error(error),
    }
}

/// `GET /console/api/network/pools/{poolId}`.
pub async fn get_pool(
    State(state): State<ConsoleState>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let row = sqlx::query(
        "SELECT *, kind::text AS kind_text, status::text AS status_text
         FROM network_pools WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&pool_id)
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some(row)) => console_response(StatusCode::OK, pool_response(&row)),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "pool_not_found",
            &format!("Pool {pool_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `GET /console/api/network/pools/{poolId}/health-events`.
pub async fn pool_health_events(
    State(state): State<ConsoleState>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM network_pools WHERE id = $1::uuid AND tenant_id = $2::uuid)",
    )
    .bind(&pool_id)
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if !owned {
        return error_response(
            StatusCode::NOT_FOUND,
            "pool_not_found",
            &format!("Pool {pool_id} not found"),
        );
    }
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, network_pool_id::text AS network_pool_id,
                from_status::text AS from_status, to_status::text AS to_status,
                reason, error_category, created_at
         FROM health_events WHERE network_pool_id = $1::uuid
         ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&pool_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let events: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "networkPoolId": row.get::<String, _>("network_pool_id"),
                "fromStatus": row.try_get::<Option<String>, _>("from_status").ok().flatten(),
                "toStatus": row.get::<String, _>("to_status"),
                "reason": row.try_get::<Option<String>, _>("reason").ok().flatten(),
                "errorCategory": row.try_get::<Option<String>, _>("error_category").ok().flatten(),
                "createdAt": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
            })
        })
        .collect();
    console_response(StatusCode::OK, Value::Array(events))
}

/// `POST /console/api/network/pools/{poolId}/recover`.
pub async fn recover_pool(
    State(state): State<ConsoleState>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let updated = sqlx::query(
        "UPDATE network_pools SET status = 'active', consecutive_failures = 0,
            cooldown_until = NULL, last_recovered_at = now()
         WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id",
    )
    .bind(&pool_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => {
            let _ = sqlx::query(
                "INSERT INTO health_events (entity_kind, network_pool_id, to_status, reason)
                 VALUES ('pool', $1::uuid, 'active', 'manual_operator_recovery')",
            )
            .bind(&pool_id)
            .execute(&state.pool)
            .await;
            console_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "pool_not_found",
            &format!("Pool {pool_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// Probe and speed-test endpoints need the outbound proxy agent stack. Answer
/// with the typed capability error until that layer lands.
pub async fn pool_capability_unsupported() -> Response {
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        "capability_unsupported",
        "Proxy probing/speed-test is not implemented in the Rust gateway yet",
    )
}

// --- Health check and speed test -------------------------------------------

async fn pool_proxy_client(
    kind: &str,
    endpoint: &str,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, String> {
    if kind == "bridge" {
        return Err("Bridge pool probing is not implemented in the Rust gateway yet".into());
    }
    let proxy = reqwest::Proxy::all(endpoint)
        .map_err(|error| format!("invalid proxy endpoint: {error}"))?;
    reqwest::Client::builder()
        .proxy(proxy)
        .timeout(timeout)
        .build()
        .map_err(|error| format!("http client: {error}"))
}

/// `POST /console/api/network/pools/{poolId}/health-check`.
pub async fn health_check_pool(
    State(state): State<ConsoleState>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let row = sqlx::query(
        "SELECT kind::text AS kind, endpoint_config FROM network_pools
         WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(&pool_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return error_response(
            StatusCode::NOT_FOUND,
            "pool_not_found",
            &format!("Pool {pool_id} not found"),
        );
    };
    let kind: String = row.get("kind");
    let (endpoint, _, _) = split_config(&row);
    let started = std::time::Instant::now();
    let result = match pool_proxy_client(&kind, &endpoint, std::time::Duration::from_secs(20)).await
    {
        Ok(client) => match client
            .get("https://www.cloudflare.com/cdn-cgi/trace")
            .send()
            .await
        {
            Ok(response) => {
                let latency = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                let status = response.status().as_u16();
                let text = response.text().await.unwrap_or_default();
                let egress = text
                    .lines()
                    .find_map(|line| line.strip_prefix("ip="))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                let mut value = json!({
                    "poolId": pool_id,
                    "status": if (200..300).contains(&status) { "healthy" } else { "unhealthy" },
                    "httpStatus": if status == 402 || status == 407 { json!(status) } else { Value::Null },
                    "latencyMs": latency,
                });
                if let Some(egress) = egress {
                    value
                        .as_object_mut()
                        .expect("object")
                        .insert("egressIp".into(), json!(egress));
                }
                if status == 402 || status == 407 {
                    let _ = sqlx::query("UPDATE network_pools SET status = 'disabled', last_error = $2 WHERE id = $1::uuid")
                        .bind(&pool_id)
                        .bind(format!("proxy authentication/capacity HTTP {status}"))
                        .execute(&state.pool)
                        .await;
                }
                value
            }
            Err(error) => {
                let latency = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                let message = error.to_string();
                let category = if message.to_ascii_lowercase().contains("timed out") {
                    "timeout"
                } else {
                    "unhealthy"
                };
                json!({"poolId": pool_id, "status": category, "latencyMs": latency, "errorMessage": message})
            }
        },
        Err(message) => json!({"poolId": pool_id, "status": "unhealthy", "errorMessage": message}),
    };
    let latency = result.get("latencyMs").and_then(Value::as_i64);
    let egress = result
        .get("egressIp")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let _ = sqlx::query(
        "UPDATE network_pools SET last_health_check_at = now(),
            last_latency_ms = COALESCE($2, last_latency_ms),
            egress_ip = COALESCE($3, egress_ip)
         WHERE id = $1::uuid",
    )
    .bind(&pool_id)
    .bind(latency.map(|value| value as i32))
    .bind(&egress)
    .execute(&state.pool)
    .await;
    console_response(StatusCode::OK, result)
}

/// `POST /console/api/network/pools/{poolId}/speed-test` — `{bytes}`.
pub async fn speed_test_pool(
    State(state): State<ConsoleState>,
    Path(pool_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let bytes = body
        .get("bytes")
        .and_then(Value::as_i64)
        .unwrap_or(5_000_000)
        .clamp(1_000_000, 100_000_000);
    let row = sqlx::query(
        "SELECT kind::text AS kind, endpoint_config FROM network_pools
         WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(&pool_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return error_response(
            StatusCode::NOT_FOUND,
            "pool_not_found",
            &format!("Pool {pool_id} not found"),
        );
    };
    let kind: String = row.get("kind");
    let (endpoint, _, _) = split_config(&row);
    let client =
        match pool_proxy_client(&kind, &endpoint, std::time::Duration::from_secs(120)).await {
            Ok(client) => client,
            Err(message) => {
                return console_response(
                    StatusCode::OK,
                    json!({
                        "poolId": pool_id,
                        "status": "failed",
                        "bytes": 0,
                        "durationMs": 0,
                        "errorMessage": message,
                    }),
                );
            }
        };
    let started = std::time::Instant::now();
    let result = client
        .get(format!("https://speed.cloudflare.com/__down?bytes={bytes}"))
        .send()
        .await;
    match result {
        Ok(response) if response.status().is_success() => {
            let payload = response.bytes().await.unwrap_or_default();
            let duration = started.elapsed().as_millis().max(1);
            let transferred = payload.len() as i64;
            let bps = (transferred as f64 * 1000.0 / duration as f64).round() as i64;
            let _ = sqlx::query(
                "UPDATE network_pools SET last_speedtest_bytes = $2,
                    last_speedtest_duration_ms = $3, last_speedtest_status = 'ok',
                    last_speedtest_error = NULL, last_speedtest_at = now()
                 WHERE id = $1::uuid",
            )
            .bind(&pool_id)
            .bind(transferred as i32)
            .bind(duration as i32)
            .execute(&state.pool)
            .await;
            console_response(
                StatusCode::OK,
                json!({
                    "poolId": pool_id,
                    "status": "ok",
                    "bytes": transferred,
                    "durationMs": duration,
                    "bytesPerSecond": bps,
                    "megabitsPerSecond": ((bps as f64 * 8.0) / 1_000_000.0 * 100.0).round() / 100.0,
                    "measuredAt": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                }),
            )
        }
        Ok(response) => console_response(
            StatusCode::OK,
            json!({
                "poolId": pool_id,
                "status": "failed",
                "bytes": 0,
                "durationMs": started.elapsed().as_millis() as i64,
                "errorMessage": format!("speed test returned HTTP {}", response.status().as_u16()),
            }),
        ),
        Err(error) => console_response(
            StatusCode::OK,
            json!({
                "poolId": pool_id,
                "status": "failed",
                "bytes": 0,
                "durationMs": started.elapsed().as_millis() as i64,
                "errorMessage": error.to_string(),
            }),
        ),
    }
}

/// `POST /console/api/network/pools/test` and `/test-batch` — probe an
/// unsaved pool definition through the same client path.
pub async fn test_pool(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        return response;
    }
    let kind = body.get("kind").and_then(Value::as_str).unwrap_or("http");
    let endpoint = body.get("endpoint").and_then(Value::as_str).unwrap_or("");
    if endpoint.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_endpoint",
            "endpoint is required",
        );
    }
    let started = std::time::Instant::now();
    match pool_proxy_client(kind, endpoint, std::time::Duration::from_secs(20)).await {
        Ok(client) => match client
            .get("https://www.cloudflare.com/cdn-cgi/trace")
            .send()
            .await
        {
            Ok(response) => {
                let latency = started.elapsed().as_millis() as i64;
                let status = response.status().as_u16();
                let text = response.text().await.unwrap_or_default();
                let egress = text
                    .lines()
                    .find_map(|line| line.strip_prefix("ip="))
                    .map(str::trim)
                    .map(str::to_owned);
                console_response(
                    StatusCode::OK,
                    json!({
                        "poolId": body.get("id").and_then(Value::as_str).unwrap_or("candidate"),
                        "status": if (200..300).contains(&status) { "healthy" } else { "unhealthy" },
                        "httpStatus": status,
                        "latencyMs": latency,
                        "egressIp": egress,
                    }),
                )
            }
            Err(error) => console_response(
                StatusCode::OK,
                json!({
                    "poolId": body.get("id").and_then(Value::as_str).unwrap_or("candidate"),
                    "status": "unhealthy",
                    "latencyMs": started.elapsed().as_millis() as i64,
                    "errorMessage": error.to_string(),
                }),
            ),
        },
        Err(message) => console_response(
            StatusCode::OK,
            json!({
                "poolId": body.get("id").and_then(Value::as_str).unwrap_or("candidate"),
                "status": "unhealthy",
                "errorMessage": message,
            }),
        ),
    }
}

/// `POST /console/api/network/pools/test-batch` — `{targets: [...]}`.
pub async fn test_batch(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        return response;
    }
    let targets = body
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if targets.len() > 100 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "targets exceeds the limit of 100",
        );
    }
    let mut results = Vec::new();
    for target in targets {
        let kind = target.get("kind").and_then(Value::as_str).unwrap_or("http");
        let endpoint = target.get("endpoint").and_then(Value::as_str).unwrap_or("");
        let started = std::time::Instant::now();
        let result = match pool_proxy_client(kind, endpoint, std::time::Duration::from_secs(15))
            .await
        {
            Ok(client) => match client
                .get("https://www.cloudflare.com/cdn-cgi/trace")
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let latency = started.elapsed().as_millis() as i64;
                    let text = response.text().await.unwrap_or_default();
                    let egress = text
                        .lines()
                        .find_map(|line| line.strip_prefix("ip="))
                        .map(str::trim)
                        .map(str::to_owned);
                    let mut value = json!({
                        "status": if (200..300).contains(&status) { "healthy" } else { "unhealthy" },
                        "latencyMs": latency,
                        "httpStatus": status,
                    });
                    if let Some(egress) = egress {
                        value
                            .as_object_mut()
                            .expect("object")
                            .insert("egressIp".into(), json!(egress));
                    }
                    value
                }
                Err(error) => json!({
                    "status": "unhealthy",
                    "latencyMs": started.elapsed().as_millis() as i64,
                    "errorMessage": error.to_string(),
                }),
            },
            Err(message) => json!({
                "status": "unhealthy",
                "errorMessage": message,
            }),
        };
        results.push(json!({"endpoint": endpoint, "kind": kind, "result": result}));
    }
    console_response(StatusCode::OK, Value::Array(results))
}
