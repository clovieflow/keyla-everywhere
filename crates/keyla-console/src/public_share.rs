//! Public share-link surface: handoff/enrollment data, issuance, popup art,
//! and family statistics. Mounted at `/share/:token/*`, outside `/console/api`.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};

use crate::access::console_response;
use crate::routes::ConsoleState;

const MIN_TOKEN_LENGTH: usize = 20;

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn not_found() -> Response {
    console_response(
        StatusCode::NOT_FOUND,
        json!({"error": {"code": "link_unavailable", "message": "This link is no longer available"}}),
    )
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, json!({"error": {"code": code, "message": message}}))
}

fn public_security(response: Response) -> Response {
    let mut response = response;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "referrer-policy",
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn resolve_link(pool: &sqlx::PgPool, token: &str) -> Result<Option<PgRow>, sqlx::Error> {
    if token.len() < MIN_TOKEN_LENGTH {
        return Ok(None);
    }
    sqlx::query(
        "SELECT s.id AS share_id, s.kind, s.expires_at,
                k.*
         FROM share_links s JOIN api_keys k ON k.id = s.api_key_id
         WHERE s.token_hash = $1 AND s.active = true
           AND (s.expires_at IS NULL OR s.expires_at > now())
           AND k.revoked_at IS NULL AND k.enabled = true
         LIMIT 1",
    )
    .bind(hash_token(token))
    .fetch_optional(pool)
    .await
}

fn client_ip(headers: &HeaderMap, connect: Option<ConnectInfo<SocketAddr>>) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| connect.map(|ConnectInfo(address)| address.ip().to_string()))
}

fn ip_key(ip: &str) -> String {
    format!("ip:{ip}")
}

async fn allowed_models(pool: &sqlx::PgPool, key: &PgRow) -> Result<Vec<String>, sqlx::Error> {
    let mode: String = key.try_get("model_access_mode").unwrap_or_default();
    let list = key
        .try_get::<Option<Value>, _>("model_list")
        .ok()
        .flatten()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    if mode != "whitelist" {
        return Ok(Vec::new());
    }
    let mut models = Vec::new();
    for value in list {
        if let Some(name) = value.as_str() {
            models.push(name.to_owned());
        }
    }
    if models.is_empty() {
        // An empty whitelist allows the whole catalog; publish what is enabled.
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT m.model_id FROM models m JOIN providers p ON p.id = m.provider_id
             WHERE m.enabled = true AND p.enabled = true ORDER BY m.model_id LIMIT 200",
        )
        .fetch_all(pool)
        .await?;
        return Ok(rows);
    }
    Ok(models)
}

/// `GET /share/:token/data`.
pub async fn data(
    State(state): State<ConsoleState>,
    Path(token): Path<String>,
    ConnectInfo(connect): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let row = match resolve_link(&state.pool, &token).await {
        Ok(Some(row)) => row,
        Ok(None) => return public_security(not_found()),
        Err(_) => return public_security(not_found()),
    };
    let models = allowed_models(&state.pool, &row).await.unwrap_or_default();
    let name: String = row.get("label");
    let key_prefix = row
        .try_get::<Option<String>, _>("key_prefix")
        .ok()
        .flatten();
    let notes_title = row
        .try_get::<Option<String>, _>("notes_title")
        .ok()
        .flatten();
    let notes_subtitle = row
        .try_get::<Option<String>, _>("notes_subtitle")
        .ok()
        .flatten();
    let notes_body = row
        .try_get::<Option<String>, _>("notes_body")
        .ok()
        .flatten();
    let popup_enabled = row.get::<bool, _>("share_popup_enabled");
    let popup_has_image = row
        .try_get::<Option<Vec<u8>>, _>("share_popup_image")
        .ok()
        .flatten()
        .is_some();
    let popup_title = row
        .try_get::<Option<String>, _>("share_popup_title")
        .ok()
        .flatten();
    let popup_body = row
        .try_get::<Option<String>, _>("share_popup_body")
        .ok()
        .flatten();
    let expires_at = row
        .try_get::<Option<DateTime<Utc>>, _>("expires_at")
        .ok()
        .flatten()
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true));
    let kind: String = row.get("kind");
    let mut policy = json!({
        "name": name,
        "keyPrefix": key_prefix,
        "dailyLimit": row.try_get::<Option<i64>, _>("daily_token_limit").ok().flatten(),
        "monthlyLimit": row.try_get::<Option<i64>, _>("monthly_token_limit").ok().flatten(),
        "oneTimeLimit": row.try_get::<Option<i64>, _>("lifetime_token_budget").ok().flatten(),
        "requestsPerMinute": row.try_get::<Option<i32>, _>("requests_per_minute").ok().flatten(),
        "maxConcurrentRequests": row.try_get::<Option<i32>, _>("max_concurrent_requests").ok().flatten(),
        "modelPrefix": row.try_get::<Option<String>, _>("model_prefix").ok().flatten(),
        "models": models,
        "modelInfo": [],
        "notes": {
            "title": notes_title,
            "subtitle": notes_subtitle,
            "body": notes_body,
        },
        "sharePopup": {
            "enabled": popup_enabled,
            "hasImage": popup_has_image,
            "title": popup_title,
            "body": popup_body,
        },
        "expiresAt": expires_at,
    });
    if kind == "handoff" {
        let key = row
            .try_get::<Option<Vec<u8>>, _>("key_encrypted")
            .ok()
            .flatten()
            .and_then(|ciphertext| keyla_security::decrypt_credential_to_string(&ciphertext).ok());
        policy
            .as_object_mut()
            .expect("object")
            .insert("kind".into(), json!("handoff"));
        policy
            .as_object_mut()
            .expect("object")
            .insert("key".into(), json!(key));
        return public_security(console_response(StatusCode::OK, policy));
    }
    let ip = client_ip(&headers, Some(ConnectInfo(connect)));
    let already_issued = match &ip {
        Some(ip) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM api_keys WHERE parent_key_id = $1::uuid
             AND issued_client_ip_key = $2 AND revoked_at IS NULL)",
        )
        .bind(row.get::<sqlx::types::Uuid, _>("id"))
        .bind(ip_key(ip))
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false),
        None => false,
    };
    policy
        .as_object_mut()
        .expect("object")
        .insert("kind".into(), json!("enroll"));
    policy
        .as_object_mut()
        .expect("object")
        .insert("canIssue".into(), json!(ip.is_some() && !already_issued));
    policy
        .as_object_mut()
        .expect("object")
        .insert("alreadyIssued".into(), json!(already_issued));
    public_security(console_response(StatusCode::OK, policy))
}

/// `GET /share/:token/popup-image`.
pub async fn popup_image(State(state): State<ConsoleState>, Path(token): Path<String>) -> Response {
    let Ok(Some(row)) = resolve_link(&state.pool, &token).await else {
        return public_security(not_found());
    };
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
        _ => public_security(not_found()),
    }
}

/// `POST /share/:token/issue` — `{nameHint}`.
pub async fn issue(
    State(state): State<ConsoleState>,
    Path(token): Path<String>,
    ConnectInfo(connect): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let row = match resolve_link(&state.pool, &token).await {
        Ok(Some(row)) => row,
        Ok(None) => return public_security(not_found()),
        Err(_) => return public_security(not_found()),
    };
    if row.get::<String, _>("kind") != "enroll" {
        return public_security(not_found());
    }
    let Some(raw_ip) = client_ip(&headers, Some(ConnectInfo(connect))) else {
        return public_security(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "client_ip_unavailable",
            "Client IP is unavailable",
        ));
    };
    let name_hint = body
        .get("nameHint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(name_hint) = name_hint else {
        return public_security(api_error(
            StatusCode::BAD_REQUEST,
            "name_required",
            "Your name is required",
        ));
    };
    let name_hint: String = name_hint.chars().take(20).collect();
    let ip_key = ip_key(&raw_ip);
    let template_id: sqlx::types::Uuid = row.get("id");
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM api_keys WHERE parent_key_id = $1::uuid
         AND issued_client_ip_key = $2 AND revoked_at IS NULL)",
    )
    .bind(template_id)
    .bind(&ip_key)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if active {
        return public_security(api_error(
            StatusCode::CONFLICT,
            "shared_key_ip_limit",
            "This IP address already has an active shared API key",
        ));
    }
    let prefix = row
        .try_get::<Option<String>, _>("key_prefix")
        .ok()
        .flatten()
        .unwrap_or_else(|| "rk_".into());
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = match keyla_security::hash_secret(&secret) {
        Ok(hash) => hash,
        Err(error) => {
            return public_security(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("hash failed: {error}"),
            ));
        }
    };
    let label = format!("{} · {}", row.get::<String, _>("label"), name_hint);
    let inserted = sqlx::query(
        "INSERT INTO api_keys (
            tenant_id, parent_key_id, key_mode, key_hash, label, scopes, key_prefix,
            requests_per_minute, daily_token_limit, monthly_token_limit, lifetime_token_budget,
            max_concurrent_requests, model_access_mode, model_list, model_prefix,
            issued_client_ip, issued_client_ip_key, enabled, sort_index
         )
         SELECT tenant_id, id, 'share', $2, $3, scopes, $4,
            requests_per_minute, daily_token_limit, monthly_token_limit, lifetime_token_budget,
            max_concurrent_requests, model_access_mode, model_list, model_prefix,
            $5, $6, true,
            (SELECT coalesce(max(sort_index) + 1, 0) FROM api_keys WHERE tenant_id = api_keys.tenant_id)
         FROM api_keys WHERE id = $1::uuid
         RETURNING id::text AS id, key_prefix, created_at",
    )
    .bind(template_id)
    .bind(&hash)
    .bind(&label)
    .bind(&prefix)
    .bind(&raw_ip)
    .bind(&ip_key)
    .fetch_optional(&state.pool)
    .await;
    match inserted {
        Ok(Some(row)) => public_security(console_response(
            StatusCode::CREATED,
            json!({
                "key": secret,
                "keyId": row.get::<String, _>("id"),
                "keyPrefix": row.get::<Option<String>, _>("key_prefix"),
                "createdAt": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
            }),
        )),
        Ok(None) => public_security(not_found()),
        Err(error) => {
            if error
                .as_database_error()
                .map(|database| database.code().as_deref() == Some("23505"))
                .unwrap_or(false)
            {
                return public_security(api_error(
                    StatusCode::CONFLICT,
                    "shared_key_ip_limit",
                    "This IP address already has an active shared API key",
                ));
            }
            public_security(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("issue failed: {error}"),
            ))
        }
    }
}

async fn family_key_ids(
    pool: &sqlx::PgPool,
    template_id: sqlx::types::Uuid,
) -> Vec<sqlx::types::Uuid> {
    let mut ids = vec![template_id];
    if let Ok(rows) = sqlx::query_scalar::<_, sqlx::types::Uuid>(
        "SELECT id FROM api_keys WHERE parent_key_id = $1::uuid",
    )
    .bind(template_id)
    .fetch_all(pool)
    .await
    {
        ids.extend(rows);
    }
    ids
}

fn mask_ip(value: &str) -> String {
    if let Some((prefix, _)) = value.rsplit_once('.') {
        return format!("{prefix}.xxx");
    }
    if let Some((prefix, _)) = value.rsplit_once(':') {
        return format!("{prefix}:xxxx");
    }
    "hidden".to_owned()
}

async fn family_stats(
    state: &ConsoleState,
    template_id: sqlx::types::Uuid,
    key_ids: &[sqlx::types::Uuid],
) -> Value {
    let recipients_total = key_ids.len().saturating_sub(1);
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys WHERE parent_key_id = $1::uuid AND revoked_at IS NULL",
    )
    .bind(template_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    if key_ids.is_empty() {
        return json!({
            "totals": {"requests": 0, "errors": 0, "inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "lastHourRequests": 0, "todayTokens": 0, "monthTokens": 0},
            "recipients": {"total": 0, "active": 0},
            "hourly": [],
            "models": [],
            "clientIps": [],
        });
    }
    let totals_row = match sqlx::query(
        "SELECT count(*)::bigint AS requests,
                count(*) FILTER (WHERE status IN ('failed','truncated'))::bigint AS errors,
                coalesce(sum(input_tokens),0)::bigint AS input_tokens,
                coalesce(sum(output_tokens),0)::bigint AS output_tokens,
                count(*) FILTER (WHERE created_at >= now() - interval '1 hour')::bigint AS last_hour,
                coalesce(sum(input_tokens + output_tokens) FILTER (WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')),0)::bigint AS today_tokens,
                coalesce(sum(input_tokens + output_tokens) FILTER (WHERE created_at >= date_trunc('month', now() AT TIME ZONE 'UTC')),0)::bigint AS month_tokens
         FROM telemetry_events WHERE api_key_id = ANY($1)",
    )
    .bind(key_ids)
    .fetch_one(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(_) => {
            return json!({
                "totals": {"requests": 0, "errors": 0, "inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "lastHourRequests": 0, "todayTokens": 0, "monthTokens": 0},
                "recipients": {"total": recipients_total, "active": active},
                "hourly": [],
                "models": [],
                "clientIps": [],
            });
        }
    };
    let input: i64 = totals_row.try_get("input_tokens").unwrap_or(0);
    let output: i64 = totals_row.try_get("output_tokens").unwrap_or(0);
    let hourly_rows: Vec<PgRow> = sqlx::query(
        "SELECT date_trunc('hour', created_at) AS hour, count(*)::bigint AS requests
         FROM telemetry_events WHERE api_key_id = ANY($1)
           AND created_at >= now() - interval '24 hours'
         GROUP BY 1 ORDER BY 1",
    )
    .bind(key_ids)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let by_hour: HashMap<i64, i64> = hourly_rows
        .iter()
        .filter_map(|row| {
            let hour: DateTime<Utc> = row.try_get("hour").ok()?;
            let requests: i64 = row.try_get("requests").ok()?;
            Some((hour.timestamp_millis(), requests))
        })
        .collect();
    let now = Utc::now();
    let current_hour = now
        .with_minute(0)
        .and_then(|value| value.with_second(0))
        .and_then(|value| value.with_nanosecond(0))
        .unwrap_or(now);
    let hourly: Vec<Value> = (0..24)
        .map(|offset| {
            let hour = current_hour - chrono::Duration::hours(23 - offset);
            json!({
                "hour": hour.to_rfc3339_opts(SecondsFormat::Millis, true),
                "requests": by_hour.get(&hour.timestamp_millis()).copied().unwrap_or(0),
            })
        })
        .collect();
    let model_rows: Vec<PgRow> = sqlx::query(
        "SELECT coalesce(requested_model,'unknown') AS model_id,
                count(*)::bigint AS requests,
                coalesce(sum(input_tokens + output_tokens),0)::bigint AS tokens,
                coalesce(avg(tokens_per_sec) FILTER (WHERE tokens_per_sec IS NOT NULL),0)::float8 AS avg_tps,
                coalesce(avg(ttfb_ms) FILTER (WHERE ttfb_ms IS NOT NULL),0)::float8 AS avg_ttfb
         FROM telemetry_events WHERE api_key_id = ANY($1)
         GROUP BY 1 ORDER BY count(*) DESC LIMIT 50",
    )
    .bind(key_ids)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let models: Vec<Value> = model_rows
        .iter()
        .map(|row| {
            json!({
                "modelId": row.get::<String, _>("model_id"),
                "requests": row.get::<i64, _>("requests"),
                "tokens": row.get::<i64, _>("tokens"),
                "avgTokensPerSec": row.try_get::<f64, _>("avg_tps").ok(),
                "avgTtfbMs": row.try_get::<f64, _>("avg_ttfb").ok(),
            })
        })
        .collect();
    let ip_rows: Vec<PgRow> = sqlx::query(
        "SELECT client_ip, count(*)::bigint AS requests,
                coalesce(sum(input_tokens + output_tokens),0)::bigint AS tokens,
                max(created_at) AS last_seen,
                max(user_agent) AS user_agent
         FROM telemetry_events WHERE api_key_id = ANY($1) AND client_ip IS NOT NULL
         GROUP BY client_ip ORDER BY count(*) DESC LIMIT 50",
    )
    .bind(key_ids)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let client_ips: Vec<Value> = ip_rows
        .iter()
        .map(|row| {
            let ip: String = row.get("client_ip");
            let last_seen: Option<DateTime<Utc>> =
                row.try_get("last_seen").ok();
            let client_type = row
                .try_get::<Option<String>, _>("user_agent")
                .ok()
                .flatten()
                .and_then(|agent| {
                    agent
                        .split_whitespace()
                        .next()
                        .map(|token| token.split('/').next().unwrap_or(token).to_ascii_lowercase())
                });
            json!({
                "ip": mask_ip(&ip),
                "requests": row.get::<i64, _>("requests"),
                "tokens": row.get::<i64, _>("tokens"),
                "lastSeenAt": last_seen.map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
                "clientType": client_type,
            })
        })
        .collect();
    json!({
        "totals": {
            "requests": totals_row.try_get::<i64, _>("requests").unwrap_or(0),
            "errors": totals_row.try_get::<i64, _>("errors").unwrap_or(0),
            "inputTokens": input,
            "outputTokens": output,
            "totalTokens": input + output,
            "lastHourRequests": totals_row.try_get::<i64, _>("last_hour").unwrap_or(0),
            "todayTokens": totals_row.try_get::<i64, _>("today_tokens").unwrap_or(0),
            "monthTokens": totals_row.try_get::<i64, _>("month_tokens").unwrap_or(0),
        },
        "recipients": {"total": recipients_total, "active": active},
        "hourly": hourly,
        "models": models,
        "clientIps": client_ips,
    })
}

/// `GET /share/:token/stats`.
pub async fn stats(State(state): State<ConsoleState>, Path(token): Path<String>) -> Response {
    let Ok(Some(row)) = resolve_link(&state.pool, &token).await else {
        return public_security(not_found());
    };
    let template_id: sqlx::types::Uuid = row.get("id");
    let key_ids = family_key_ids(&state.pool, template_id).await;
    let family = family_stats(&state, template_id, &key_ids).await;
    public_security(console_response(StatusCode::OK, family))
}

/// `GET /share/:token/stats/stream` — initial snapshot then heartbeat.
pub async fn stats_stream(
    State(state): State<ConsoleState>,
    Path(token): Path<String>,
) -> Response {
    let Ok(Some(row)) = resolve_link(&state.pool, &token).await else {
        return public_security(not_found());
    };
    let template_id: sqlx::types::Uuid = row.get("id");
    let key_ids = family_key_ids(&state.pool, template_id).await;
    let initial = family_stats(&state, template_id, &key_ids).await;
    let body = async_stream::stream! {
        yield Ok::<Event, std::convert::Infallible>(
            Event::default().event("stats").json_data(initial).unwrap_or_default(),
        );
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            yield Ok(Event::default().comment("ping"));
        }
    };
    public_security(
        Sse::new(body)
            .keep_alive(KeepAlive::default())
            .into_response(),
    )
}

/// Root-level router for the public share surface.
pub fn public_share_router(pool: sqlx::PgPool) -> Router {
    Router::new()
        .route("/share/{token}/data", get(data))
        .route("/share/{token}/popup-image", get(popup_image))
        .route("/share/{token}/issue", post(issue))
        .route("/share/{token}/stats", get(stats))
        .route("/share/{token}/stats/stream", get(stats_stream))
        .with_state(ConsoleState::new(pool))
}
