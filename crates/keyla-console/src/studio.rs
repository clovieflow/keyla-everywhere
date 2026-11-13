//! Studio playground sessions: list, create, read, update, delete.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::Row;

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn summary(row: &sqlx::postgres::PgRow) -> Value {
    let messages = row
        .try_get::<Value, _>("messages_json")
        .ok()
        .and_then(|value| value.as_array().map(Vec::len))
        .unwrap_or(0);
    json!({
        "id": row.get::<sqlx::types::Uuid, _>("id").to_string(),
        "title": row.get::<String, _>("title"),
        "model": row.get::<String, _>("model"),
        "updatedAt": iso(row.get::<DateTime<Utc>, _>("updated_at")),
        "messageCount": messages,
    })
}

fn view(row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": row.get::<sqlx::types::Uuid, _>("id").to_string(),
        "title": row.get::<String, _>("title"),
        "model": row.get::<String, _>("model"),
        "systemPrompt": row.get::<String, _>("system_prompt"),
        "messages": row.try_get::<Value, _>("messages_json").unwrap_or_else(|_| json!([])),
        "media": row.try_get::<Value, _>("media_json").unwrap_or_else(|_| json!([])),
        "createdAt": iso(row.get::<DateTime<Utc>, _>("created_at")),
        "updatedAt": iso(row.get::<DateTime<Utc>, _>("updated_at")),
    })
}

/// `GET /console/api/studio/sessions`.
pub async fn list_sessions(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let rows: Vec<sqlx::postgres::PgRow> = match sqlx::query(
        "SELECT * FROM studio_sessions WHERE tenant_id = $1::uuid ORDER BY updated_at DESC, id",
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
                &format!("studio sessions failed: {error}"),
            );
        }
    };
    let items: Vec<Value> = rows.iter().map(summary).collect();
    console_response(StatusCode::OK, json!({"items": items}))
}

/// `GET /console/api/studio/sessions/{id}`.
pub async fn get_session(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let row =
        sqlx::query("SELECT * FROM studio_sessions WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(&tenant)
            .bind(&id)
            .fetch_optional(&state.pool)
            .await;
    match row {
        Ok(Some(row)) => console_response(StatusCode::OK, view(&row)),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "session_not_found",
            &format!("Studio session {id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("studio session failed: {error}"),
        ),
    }
}

/// `POST /console/api/studio/sessions`.
pub async fn create_session(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("New session");
    let model = body.get("model").and_then(Value::as_str).unwrap_or("");
    let system_prompt = body
        .get("systemPrompt")
        .and_then(Value::as_str)
        .unwrap_or("");
    let inserted = sqlx::query(
        "INSERT INTO studio_sessions (tenant_id, title, model, system_prompt)
         VALUES ($1::uuid, $2, $3, $4) RETURNING *",
    )
    .bind(&tenant)
    .bind(title)
    .bind(model)
    .bind(system_prompt)
    .fetch_one(&state.pool)
    .await;
    match inserted {
        Ok(row) => console_response(StatusCode::CREATED, view(&row)),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("studio session create failed: {error}"),
        ),
    }
}

/// `PATCH /console/api/studio/sessions/{id}`.
pub async fn update_session(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let current = match sqlx::query(
        "SELECT * FROM studio_sessions WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "session_not_found",
                &format!("Studio session {id} not found"),
            );
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("studio session failed: {error}"),
            );
        }
    };
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| current.get("title"));
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| current.get("model"));
    let system_prompt = body
        .get("systemPrompt")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| current.get("system_prompt"));
    let messages = body.get("messages").cloned().unwrap_or_else(|| {
        current
            .try_get::<Value, _>("messages_json")
            .unwrap_or_else(|_| json!([]))
    });
    let media = body.get("media").cloned().unwrap_or_else(|| {
        current
            .try_get::<Value, _>("media_json")
            .unwrap_or_else(|_| json!([]))
    });
    if !messages.is_array() || !media.is_array() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "messages and media must be arrays",
        );
    }
    let updated = sqlx::query(
        "UPDATE studio_sessions SET title = $3, model = $4, system_prompt = $5,
            messages_json = $6::jsonb, media_json = $7::jsonb, updated_at = now()
         WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING *",
    )
    .bind(&tenant)
    .bind(&id)
    .bind(&title)
    .bind(&model)
    .bind(&system_prompt)
    .bind(messages)
    .bind(media)
    .fetch_one(&state.pool)
    .await;
    match updated {
        Ok(row) => console_response(StatusCode::OK, view(&row)),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("studio session update failed: {error}"),
        ),
    }
}

/// `DELETE /console/api/studio/sessions/{id}`.
pub async fn delete_session(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let deleted = sqlx::query(
        "DELETE FROM studio_sessions WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING id",
    )
    .bind(&tenant)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await;
    match deleted {
        Ok(Some(_)) => console_response(StatusCode::OK, json!({"success": true})),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "session_not_found",
            &format!("Studio session {id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("studio session delete failed: {error}"),
        ),
    }
}

/// `POST /console/api/studio/key` — return a usable default gateway key,
/// minting one when the tenant has none.
pub async fn ensure_key(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let existing = sqlx::query(
        "SELECT id::text AS id, key_prefix, key_encrypted FROM api_keys
         WHERE tenant_id = $1::uuid AND label = 'Default Keyla API key' AND revoked_at IS NULL
         ORDER BY created_at LIMIT 1",
    )
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    if let Some(row) = existing {
        if let Some(ciphertext) = row
            .try_get::<Option<Vec<u8>>, _>("key_encrypted")
            .ok()
            .flatten()
        {
            if let Ok(secret) = keyla_security::decrypt_credential_to_string(&ciphertext) {
                return console_response(
                    StatusCode::OK,
                    json!({
                        "key": secret,
                        "keyId": row.get::<String, _>("id"),
                        "prefix": row.try_get::<Option<String>, _>("key_prefix").ok().flatten().unwrap_or_default(),
                    }),
                );
            }
        }
    }
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let secret = format!(
        "rk_{}",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    );
    let hash = match keyla_security::hash_secret(&secret) {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("hash failed: {error}"),
            );
        }
    };
    let encrypted = match keyla_security::encrypt_credential(secret.as_bytes()) {
        Ok(value) => value,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("encrypt failed: {error}"),
            );
        }
    };
    let scopes: Vec<String> = keyla_security::TENANT_KEY_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect();
    let inserted = sqlx::query(
        "INSERT INTO api_keys (tenant_id, key_mode, key_hash, label, scopes, key_prefix,
            key_encrypted, model_access_mode, enabled, sort_index)
         VALUES ($1::uuid, 'personal', $2, 'Default Keyla API key', $3::jsonb, 'rk_',
            $4, 'whitelist', true,
            (SELECT coalesce(max(sort_index) + 1, 0) FROM api_keys WHERE tenant_id = $1::uuid))
         RETURNING id::text AS id",
    )
    .bind(&tenant)
    .bind(&hash)
    .bind(json!(scopes))
    .bind(&encrypted)
    .fetch_one(&state.pool)
    .await;
    match inserted {
        Ok(row) => console_response(
            StatusCode::OK,
            json!({"key": secret, "keyId": row.get::<String, _>("id"), "prefix": "rk_"}),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("studio key create failed: {error}"),
        ),
    }
}

/// `POST /console/api/studio/web-fetch` — bounded, SSRF-checked page text.
pub async fn web_fetch(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    let Some(raw_url) = body.get("url").and_then(Value::as_str) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "url is required",
        );
    };
    let Ok(url) = url::Url::parse(raw_url) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_url",
            "url must be an absolute http(s) URL",
        );
    };
    if !["http", "https"].contains(&url.scheme()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_url",
            "url must be an absolute http(s) URL",
        );
    }
    let host = url.host_str().unwrap_or_default();
    let private_host = host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|address| match address {
                std::net::IpAddr::V4(address) => {
                    address.is_private() || address.is_loopback() || address.is_link_local()
                }
                std::net::IpAddr::V6(address) => {
                    address.is_loopback()
                        || address.is_unique_local()
                        || address.is_unicast_link_local()
                }
            })
            .unwrap_or(false);
    if private_host || host.ends_with(".internal") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "ssrf_rejected",
            "Private endpoints are not allowed",
        );
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("http client: {error}"),
            );
        }
    };
    let response = match client
        .get(url.clone())
        .header(
            "accept",
            "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
        )
        .header("user-agent", "Keyla-Studio/1.0")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "web_fetch_failed",
                &format!("fetch failed: {error}"),
            );
        }
    };
    if !response.status().is_success() {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "web_fetch_failed",
            &format!("fetch returned HTTP {}", response.status().as_u16()),
        );
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let raw = response.text().await.unwrap_or_default();
    let text = if content_type.contains("html") {
        strip_html(&raw)
    } else {
        raw.split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let max_chars = body
        .get("maxChars")
        .and_then(Value::as_f64)
        .map(|value| value as usize)
        .unwrap_or(200_000)
        .clamp(1_000, 200_000);
    let truncated = text.chars().count() > max_chars;
    let content: String = text.chars().take(max_chars).collect();
    console_response(
        StatusCode::OK,
        json!({
            "url": url.to_string(),
            "contentType": content_type,
            "content": content,
            "truncated": truncated,
        }),
    )
}

fn strip_html(html: &str) -> String {
    let mut output = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut last_space = false;
    for character in html.chars() {
        match character {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                if !last_space {
                    output.push(' ');
                    last_space = true;
                }
            }
            _ if in_tag => {}
            _ if character.is_whitespace() => {
                if !last_space {
                    output.push(' ');
                    last_space = true;
                }
            }
            _ => {
                output.push(character);
                last_space = false;
            }
        }
    }
    output.trim().to_owned()
}
