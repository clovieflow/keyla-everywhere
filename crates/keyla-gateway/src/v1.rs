//! `/v1` route plane: authenticated Chat, Messages, and Responses proxying.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use keyla_core::{CanonicalEvent, CanonicalRequest, GatewayError, GatewayErrorCode, WireFamily};
use keyla_db::dispatch::{load_dispatch_account, load_provider_base_url};
use keyla_protocol::surface::chat::ChatAdapter;
use keyla_protocol::surface::chat_encode::{
    ChatEncodeOptions, ChatStreamEncoder, get_response_id, json_completion,
};
use keyla_protocol::surface::completion::{
    CompletionAdapter, CompletionEncodeOptions, CompletionStreamEncoder, encode_completion_response,
};
use keyla_protocol::surface::messages::{MessagesAdapter, MessagesStreamEncoder};
use keyla_protocol::surface::responses::{ResponsesAdapter, ResponsesStreamEncoder};
use keyla_providers::adapter::{
    DispatchCredential, DispatchOutput, DispatchTarget, dispatch_chat, dispatch_messages,
    dispatch_responses,
};
use keyla_routing::caps::derive_required_capabilities;
use keyla_routing::{
    HealthStatus, PlanInput, Reservation, RouteCandidate, RoutePlan, RoutingEngine,
    request_uses_web_search,
};
use keyla_security::{
    ModelAccessPolicy, model_rejection_reason, request_token, resolve_api_key_authorization,
};
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::app::{AppState, error_response};
use crate::runtime::GatewayRuntime;

const GATEWAY_SECURITY_HEADERS: [(&str, &str); 7] = [
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    ),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    (
        "content-security-policy",
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
    ),
    ("x-frame-options", "DENY"),
];

fn apply_security_headers(builder: axum::http::response::Builder) -> axum::http::response::Builder {
    GATEWAY_SECURITY_HEADERS
        .iter()
        .fold(builder, |builder, (name, value)| {
            builder.header(*name, *value)
        })
}

fn gateway_error_response(error: &GatewayError) -> Response {
    let body = serde_json::to_vec(&error.public_body()).unwrap_or_default();
    let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    apply_security_headers(
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("cache-control", "no-store"),
    )
    .body(Body::from(body))
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn header_map(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

fn json_response(value: &Value) -> Response {
    apply_security_headers(
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("cache-control", "no-store"),
    )
    .body(Body::from(serde_json::to_vec(value).unwrap_or_default()))
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn is_retryable(error: &GatewayError) -> bool {
    matches!(
        error.code,
        GatewayErrorCode::AuthenticationFailed
            | GatewayErrorCode::QuotaExceeded
            | GatewayErrorCode::CapacityExhausted
            | GatewayErrorCode::PlatformUnavailable
            | GatewayErrorCode::TransportUnavailable
            | GatewayErrorCode::DeadlineExceeded
            | GatewayErrorCode::TransportClosed
            | GatewayErrorCode::ProxyUnreachable
            | GatewayErrorCode::ProxyPoolUnavailable
            | GatewayErrorCode::ProxyPoolCooldown
            | GatewayErrorCode::ProxyPoolUnhealthy
            | GatewayErrorCode::ProxyAuthRequired
            | GatewayErrorCode::TenantCapacityExhausted
    )
}

fn jwt_payload(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
            .or_else(|_| {
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, payload)
            })
            .ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn codex_account_id(token: &str) -> Option<String> {
    let claims = jwt_payload(token)?;
    claims
        .get("https://api.openai.com/auth")
        .and_then(|auth| auth.get("chatgpt_account_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

struct OAuthRefreshConfig {
    token_url: &'static str,
    client_id: &'static str,
}

fn oauth_refresh_config(provider_id: &str) -> Option<OAuthRefreshConfig> {
    match provider_id {
        "claude" => Some(OAuthRefreshConfig {
            token_url: "https://api.anthropic.com/v1/oauth/token",
            client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        }),
        "codex" => Some(OAuthRefreshConfig {
            token_url: "https://auth.openai.com/oauth/token",
            client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
        }),
        "xai" | "grok" => Some(OAuthRefreshConfig {
            token_url: "https://auth.x.ai/oauth2/token",
            client_id: "b1a00492-073a-47ea-816f-4c329264a828",
        }),
        _ => None,
    }
}

/// Refreshes an expired OAuth access token and persists the new pair. Returns
/// the new access token, or the old one when the flow has no refresher.
async fn refresh_access_token(
    runtime: &GatewayRuntime,
    provider_id: &str,
    account_id: &str,
) -> Result<Option<String>, GatewayError> {
    let row = sqlx::query(
        "SELECT refresh_ciphertext, expires_at FROM provider_oauth_states
         WHERE provider_account_id = $1::uuid",
    )
    .bind(account_id)
    .fetch_optional(&runtime.pool)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return Ok(None);
    };
    let refresh = row
        .try_get::<Option<Vec<u8>>, _>("refresh_ciphertext")
        .ok()
        .flatten()
        .and_then(|ciphertext| keyla_security::decrypt_credential_to_string(&ciphertext).ok());
    let Some(refresh) = refresh else {
        return Ok(None);
    };
    if provider_id == "github" {
        let response = runtime
            .client
            .get("https://api.github.com/copilot_internal/v2/token")
            .bearer_auth(&refresh)
            .header("user-agent", "GitHubCopilotChat/0.35.0")
            .header("editor-version", "vscode/1.107.0")
            .header("editor-plugin-version", "copilot-chat/0.35.0")
            .header("copilot-integration-id", "vscode-chat")
            .header("x-github-api-version", "2026-06-01")
            .send()
            .await
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::AuthenticationFailed,
                    502,
                    format!("github token mint failed: {error}"),
                    Map::new(),
                )
            })?;
        if !response.status().is_success() {
            return Err(GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                format!(
                    "github token mint rejected with HTTP {}",
                    response.status().as_u16()
                ),
                Map::new(),
            ));
        }
        let payload: Value = response.json().await.map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                502,
                format!("github token mint returned invalid JSON: {error}"),
                Map::new(),
            )
        })?;
        let Some(access) = payload.get("token").and_then(Value::as_str) else {
            return Err(GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                "github token mint omitted token",
                Map::new(),
            ));
        };
        let api_host = access
            .split("proxy-ep=")
            .nth(1)
            .and_then(|tail| tail.split(';').next())
            .map(|host| host.trim().replace("proxy.", "api."))
            .filter(|host| !host.is_empty())
            .unwrap_or_else(|| "api.individual.githubcopilot.com".to_owned());
        let envelope = json!({"access": access, "apiHost": api_host, "github": refresh});
        let encoded = serde_json::to_string(&envelope).unwrap_or_default();
        let encrypted =
            keyla_security::encrypt_credential(encoded.as_bytes()).map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    format!("credential encrypt failed: {error}"),
                    Map::new(),
                )
            })?;
        let expires = payload
            .get("expires_at")
            .and_then(Value::as_i64)
            .map(|seconds| seconds - chrono::Utc::now().timestamp())
            .unwrap_or(1500)
            .max(60);
        let _ = sqlx::query(
            "UPDATE provider_accounts SET credential_ciphertext = $2 WHERE id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted)
        .execute(&runtime.pool)
        .await;
        let _ = sqlx::query(
            "UPDATE provider_oauth_states SET expires_at = now() + make_interval(secs => $2)
             WHERE provider_account_id = $1::uuid",
        )
        .bind(account_id)
        .bind(expires)
        .execute(&runtime.pool)
        .await;
        return Ok(Some(encoded));
    }
    if provider_id == "kimi" {
        let envelope: Value = serde_json::from_str(&refresh).unwrap_or(Value::Null);
        let refresh_token = envelope
            .get("refreshToken")
            .and_then(Value::as_str)
            .unwrap_or(&refresh);
        let device_id = envelope
            .get("deviceId")
            .and_then(Value::as_str)
            .unwrap_or("");
        let host = keyla_config::resolve_kimi_oauth_host(&keyla_config::ProcessEnv);
        let response = runtime
            .client
            .post(format!("{}/api/oauth/token", host.trim_end_matches('/')))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("user-agent", "KimiCLI/1.0.0")
            .header("X-Msh-Device-Id", device_id)
            .form(&[
                ("client_id", "17e5f671-d194-4dfb-9706-5516cb48c098"),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::AuthenticationFailed,
                    502,
                    format!("kimi refresh failed: {error}"),
                    Map::new(),
                )
            })?;
        if !response.status().is_success() {
            return Err(GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                format!(
                    "kimi refresh rejected with HTTP {}",
                    response.status().as_u16()
                ),
                Map::new(),
            ));
        }
        let payload: Value = response.json().await.unwrap_or(Value::Null);
        let Some(access) = payload.get("access_token").and_then(Value::as_str) else {
            return Err(GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                "kimi refresh omitted access_token",
                Map::new(),
            ));
        };
        let next_refresh = payload
            .get("refresh_token")
            .and_then(Value::as_str)
            .unwrap_or(refresh_token);
        let encoded_access = json!({"accessToken": access, "deviceId": device_id}).to_string();
        let encoded_refresh =
            json!({"refreshToken": next_refresh, "deviceId": device_id}).to_string();
        let encrypted =
            keyla_security::encrypt_credential(encoded_access.as_bytes()).map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    format!("encrypt failed: {error}"),
                    Map::new(),
                )
            })?;
        let encrypted_refresh = keyla_security::encrypt_credential(encoded_refresh.as_bytes())
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    format!("encrypt failed: {error}"),
                    Map::new(),
                )
            })?;
        let expires = payload
            .get("expires_in")
            .and_then(Value::as_i64)
            .unwrap_or(86_400);
        let _ = sqlx::query(
            "UPDATE provider_accounts SET credential_ciphertext = $2 WHERE id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted)
        .execute(&runtime.pool)
        .await;
        let _ = sqlx::query("UPDATE provider_oauth_states SET refresh_ciphertext = $2, expires_at = now() + make_interval(secs => $3) WHERE provider_account_id = $1::uuid")
            .bind(account_id).bind(&encrypted_refresh).bind(expires).execute(&runtime.pool).await;
        return Ok(Some(encoded_access));
    }
    if provider_id == "cline" {
        let response = runtime
            .client
            .post("https://api.cline.bot/api/v1/auth/refresh")
            .json(&json!({"refreshToken": refresh, "grantType": "refresh_token"}))
            .send()
            .await
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::AuthenticationFailed,
                    502,
                    format!("cline refresh failed: {error}"),
                    Map::new(),
                )
            })?;
        if !response.status().is_success() {
            return Err(GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                format!(
                    "cline refresh rejected with HTTP {}",
                    response.status().as_u16()
                ),
                Map::new(),
            ));
        }
        let payload: Value = response.json().await.unwrap_or(Value::Null);
        let root = payload.get("data").unwrap_or(&payload);
        let Some(access) = root
            .get("access_token")
            .or_else(|| root.get("accessToken"))
            .or_else(|| root.get("token"))
            .and_then(Value::as_str)
        else {
            return Err(GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                "cline refresh omitted access token",
                Map::new(),
            ));
        };
        let next_refresh = root
            .get("refresh_token")
            .or_else(|| root.get("refreshToken"))
            .and_then(Value::as_str)
            .unwrap_or(&refresh);
        let encrypted = keyla_security::encrypt_credential(access.as_bytes()).map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::InternalError,
                500,
                format!("encrypt failed: {error}"),
                Map::new(),
            )
        })?;
        let encrypted_refresh = keyla_security::encrypt_credential(next_refresh.as_bytes())
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    format!("encrypt failed: {error}"),
                    Map::new(),
                )
            })?;
        let expires = root
            .get("expires_in")
            .or_else(|| root.get("expiresIn"))
            .and_then(Value::as_i64)
            .unwrap_or(3600);
        let _ = sqlx::query(
            "UPDATE provider_accounts SET credential_ciphertext = $2 WHERE id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted)
        .execute(&runtime.pool)
        .await;
        let _ = sqlx::query("UPDATE provider_oauth_states SET refresh_ciphertext = $2, expires_at = now() + make_interval(secs => $3) WHERE provider_account_id = $1::uuid")
            .bind(account_id).bind(&encrypted_refresh).bind(expires).execute(&runtime.pool).await;
        return Ok(Some(access.to_owned()));
    }
    if matches!(provider_id, "cb" | "cbcn" | "workbuddy") {
        let refreshed =
            keyla_providers::buddy::oauth_refresh(&runtime.client, provider_id, &refresh, None)
                .await;
        if refreshed.get("status").and_then(Value::as_str) == Some("failed") {
            return Err(GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                refreshed
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("buddy token refresh failed"),
                Map::new(),
            ));
        }
        let access = refreshed
            .get("access")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GatewayError::new(
                    GatewayErrorCode::AuthenticationFailed,
                    401,
                    "buddy refresh omitted access token",
                    Map::new(),
                )
            })?
            .to_owned();
        let next_refresh = refreshed
            .get("refresh")
            .and_then(Value::as_str)
            .unwrap_or(&refresh);
        let encrypted = keyla_security::encrypt_credential(access.as_bytes()).map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::InternalError,
                500,
                format!("credential encrypt failed: {error}"),
                Map::new(),
            )
        })?;
        let encrypted_refresh = keyla_security::encrypt_credential(next_refresh.as_bytes())
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    format!("credential encrypt failed: {error}"),
                    Map::new(),
                )
            })?;
        let expires = refreshed
            .get("expiresAt")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| (value.timestamp() - chrono::Utc::now().timestamp()).max(60))
            .unwrap_or(3600);
        let _ = sqlx::query(
            "UPDATE provider_accounts SET credential_ciphertext = $2 WHERE id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted)
        .execute(&runtime.pool)
        .await;
        let _ = sqlx::query(
            "UPDATE provider_oauth_states SET refresh_ciphertext = $2,
                expires_at = now() + make_interval(secs => $3)
             WHERE provider_account_id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted_refresh)
        .bind(expires)
        .execute(&runtime.pool)
        .await;
        return Ok(Some(access));
    }
    if provider_id == "kiro" {
        let extra: Option<(Option<Value>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT a.auth_state, o.client_secret_ciphertext
             FROM provider_accounts a
             LEFT JOIN provider_oauth_states o ON o.provider_account_id = a.id
             WHERE a.id = $1::uuid",
        )
        .bind(account_id)
        .fetch_optional(&runtime.pool)
        .await
        .ok()
        .flatten();
        let (auth_state, client_secret_cipher) = extra.unwrap_or((None, None));
        let client_secret = client_secret_cipher
            .and_then(|ciphertext| keyla_security::decrypt_credential_to_string(&ciphertext).ok());
        let refreshed = keyla_providers::kiro_oauth::refresh_kiro_token(
            &runtime.client,
            &refresh,
            auth_state.as_ref(),
            client_secret.as_deref(),
        )
        .await
        .map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                error,
                Map::new(),
            )
        })?;
        let access = refreshed
            .get("access")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GatewayError::new(
                    GatewayErrorCode::AuthenticationFailed,
                    401,
                    "kiro refresh omitted access token",
                    Map::new(),
                )
            })?
            .to_owned();
        let next_refresh = refreshed
            .get("refresh")
            .and_then(Value::as_str)
            .unwrap_or(&refresh);
        let encrypted = keyla_security::encrypt_credential(access.as_bytes()).map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::InternalError,
                500,
                format!("credential encrypt failed: {error}"),
                Map::new(),
            )
        })?;
        let encrypted_refresh = keyla_security::encrypt_credential(next_refresh.as_bytes())
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    format!("credential encrypt failed: {error}"),
                    Map::new(),
                )
            })?;
        let expires = refreshed
            .get("expiresAt")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| (value.timestamp() - chrono::Utc::now().timestamp()).max(60))
            .unwrap_or(3600);
        let _ = sqlx::query(
            "UPDATE provider_accounts SET credential_ciphertext = $2 WHERE id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted)
        .execute(&runtime.pool)
        .await;
        let _ = sqlx::query(
            "UPDATE provider_oauth_states SET refresh_ciphertext = $2,
                expires_at = now() + make_interval(secs => $3)
             WHERE provider_account_id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted_refresh)
        .bind(expires)
        .execute(&runtime.pool)
        .await;
        return Ok(Some(access));
    }
    if provider_id == "antigravity" {
        let refreshed = keyla_providers::antigravity_oauth::refresh_antigravity_token(
            &runtime.client,
            &refresh,
        )
        .await?;
        let access = refreshed
            .get("access")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GatewayError::new(
                    GatewayErrorCode::AuthenticationFailed,
                    401,
                    "antigravity refresh omitted access token",
                    Map::new(),
                )
            })?
            .to_owned();
        let encrypted = keyla_security::encrypt_credential(access.as_bytes()).map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::InternalError,
                500,
                format!("credential encrypt failed: {error}"),
                Map::new(),
            )
        })?;
        let expires = refreshed
            .get("expiresAt")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| (value.timestamp() - chrono::Utc::now().timestamp()).max(60))
            .unwrap_or(3600);
        let _ = sqlx::query(
            "UPDATE provider_accounts SET credential_ciphertext = $2 WHERE id = $1::uuid",
        )
        .bind(account_id)
        .bind(&encrypted)
        .execute(&runtime.pool)
        .await;
        let _ = sqlx::query(
            "UPDATE provider_oauth_states SET expires_at = now() + make_interval(secs => $2)
             WHERE provider_account_id = $1::uuid",
        )
        .bind(account_id)
        .bind(expires)
        .execute(&runtime.pool)
        .await;
        return Ok(Some(access));
    }
    let Some(config) = oauth_refresh_config(provider_id) else {
        return Ok(None);
    };
    let response = runtime
        .client
        .post(config.token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", config.client_id),
        ])
        .send()
        .await
        .map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                502,
                format!("oauth refresh failed: {error}"),
                Map::new(),
            )
        })?;
    if !response.status().is_success() {
        return Err(GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            format!(
                "oauth refresh rejected with HTTP {}",
                response.status().as_u16()
            ),
            Map::new(),
        ));
    }
    let payload: Value = response.json().await.map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            502,
            format!("oauth refresh returned malformed JSON: {error}"),
            Map::new(),
        )
    })?;
    let Some(access) = payload.get("access_token").and_then(Value::as_str) else {
        return Err(GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "oauth refresh response omitted access_token",
            Map::new(),
        ));
    };
    let access = access.to_owned();
    let encrypted = keyla_security::encrypt_credential(access.as_bytes()).map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::InternalError,
            500,
            format!("credential encrypt failed: {error}"),
            Map::new(),
        )
    })?;
    let expires_in = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .unwrap_or(3600);
    let _ =
        sqlx::query("UPDATE provider_accounts SET credential_ciphertext = $2 WHERE id = $1::uuid")
            .bind(account_id)
            .bind(&encrypted)
            .execute(&runtime.pool)
            .await;
    let refresh_update = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .and_then(|token| keyla_security::encrypt_credential(token.as_bytes()).ok());
    if let Some(refresh_update) = refresh_update {
        let _ = sqlx::query(
            "UPDATE provider_oauth_states SET refresh_ciphertext = $2,
                expires_at = now() + make_interval(secs => $3)
             WHERE provider_account_id = $1::uuid",
        )
        .bind(account_id)
        .bind(&refresh_update)
        .bind(expires_in)
        .execute(&runtime.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE provider_oauth_states SET expires_at = now() + make_interval(secs => $2)
             WHERE provider_account_id = $1::uuid",
        )
        .bind(account_id)
        .bind(expires_in)
        .execute(&runtime.pool)
        .await;
    }
    Ok(Some(access))
}

async fn build_credential(
    runtime: &GatewayRuntime,
    candidate: &RouteCandidate,
) -> Result<DispatchCredential, GatewayError> {
    let provider_id = &candidate.provider_id;
    let base_url = match load_provider_base_url(&runtime.pool, provider_id)
        .await
        .ok()
        .flatten()
        .or_else(|| keyla_providers::provider_base_url(provider_id).map(str::to_owned))
    {
        Some(base) => base,
        None => {
            return Err(GatewayError::new(
                GatewayErrorCode::InternalError,
                500,
                format!("provider '{provider_id}' has no base URL"),
                Map::new(),
            ));
        }
    };
    let mut extra_headers = BTreeMap::new();
    let mut auth_state: Option<Value> = None;
    let (credential_kind, secret) = match &candidate.provider_account_id {
        None => ("none".to_owned(), None),
        Some(account_id) => {
            let account = load_dispatch_account(&runtime.pool, account_id)
                .await
                .ok()
                .flatten()
                .ok_or_else(|| {
                    GatewayError::new(
                        GatewayErrorCode::AccountsUnavailable,
                        503,
                        format!("provider account '{account_id}' is unavailable"),
                        Map::new(),
                    )
                })?;
            let secret = match account.credential_ciphertext {
                Some(ciphertext) => Some(
                    keyla_security::decrypt_credential_to_string(&ciphertext).map_err(|error| {
                        GatewayError::new(
                            GatewayErrorCode::InternalError,
                            500,
                            format!("credential decrypt failed: {error}"),
                            Map::new(),
                        )
                    })?,
                ),
                None => None,
            };
            auth_state = account.auth_state.clone();
            let mut secret = secret;
            if account.credential_kind == "oauth" {
                let expires_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
                    "SELECT expires_at FROM provider_oauth_states WHERE provider_account_id = $1::uuid",
                )
                .bind(&account.id)
                .fetch_optional(&runtime.pool)
                .await
                .ok()
                .flatten();
                let expiring = expires_at
                    .map(|expires| expires <= chrono::Utc::now() + chrono::Duration::seconds(60))
                    .unwrap_or(false);
                if expiring {
                    if let Some(refreshed) =
                        refresh_access_token(runtime, provider_id, &account.id).await?
                    {
                        secret = Some(refreshed);
                    }
                }
            }
            (account.credential_kind, secret)
        }
    };
    let mut base_url = base_url;
    let mut secret = secret;
    if provider_id == "github" && credential_kind == "oauth" {
        if let Some(raw) = secret.as_deref() {
            if let Ok(envelope) = serde_json::from_str::<Value>(raw) {
                if let Some(access) = envelope.get("access").and_then(Value::as_str) {
                    secret = Some(access.to_owned());
                }
                if let Some(host) = envelope.get("apiHost").and_then(Value::as_str) {
                    if !host.is_empty() {
                        base_url = format!("https://{host}");
                    }
                }
            }
        }
    }
    if provider_id == "kilo" && credential_kind == "oauth" {
        if let Some(raw) = secret.as_deref() {
            if let Ok(envelope) = serde_json::from_str::<Value>(raw) {
                if let Some(access) = envelope.get("accessToken").and_then(Value::as_str) {
                    secret = Some(access.to_owned());
                }
                if let Some(org) = envelope.get("orgId").and_then(Value::as_str) {
                    extra_headers.insert("X-Kilocode-OrganizationID".into(), org.to_owned());
                }
            }
        }
    }
    if provider_id == "grok" && credential_kind == "oauth" {
        extra_headers.insert("x-xai-token-auth".into(), "xai-grok-cli".into());
        extra_headers.insert("x-grok-client-version".into(), "1.0.0".into());
        extra_headers.insert("x-grok-client-surface".into(), "ui".into());
    }
    if provider_id == "muse" && credential_kind == "oauth" {
        if let Some(raw) = secret.as_deref() {
            if let Ok(envelope) = serde_json::from_str::<Value>(raw) {
                if let Some(api_key) = envelope.get("apiKey").and_then(Value::as_str) {
                    secret = Some(api_key.to_owned());
                }
            }
        }
    }
    if provider_id == "kimi" && credential_kind == "oauth" {
        if let Some(raw) = secret.as_deref() {
            if let Ok(envelope) = serde_json::from_str::<Value>(raw) {
                if let Some(access) = envelope.get("accessToken").and_then(Value::as_str) {
                    secret = Some(access.to_owned());
                }
                if let Some(device_id) = envelope.get("deviceId").and_then(Value::as_str) {
                    extra_headers.insert("user-agent".into(), "KimiCLI/1.0.0".into());
                    extra_headers.insert("X-Msh-Platform".into(), "kimi_cli".into());
                    extra_headers.insert("X-Msh-Version".into(), "1.0.0".into());
                    extra_headers.insert("X-Msh-Device-Name".into(), "keyla".into());
                    extra_headers.insert("X-Msh-Device-Model".into(), "keyla".into());
                    extra_headers.insert("X-Msh-Os-Version".into(), "unknown".into());
                    extra_headers.insert("X-Msh-Device-Id".into(), device_id.to_owned());
                }
            }
        }
    }
    if provider_id == "mimodesktop" {
        let raw = secret.as_deref().unwrap_or_default();
        let parsed = keyla_providers::mimodesktop::parse_credential(raw)?;
        let cookie = keyla_providers::mimodesktop::acquire_session(
            &runtime.client,
            &parsed,
            "https://mimo-server-sgp.xiaomimimo.com",
        )
        .await?;
        secret = None;
        extra_headers.insert("Cookie".into(), cookie);
        extra_headers.insert(
            "User-Agent".into(),
            keyla_providers::mimodesktop::MIMO_API_UA.into(),
        );
        extra_headers.insert("X-Mimo-Source".into(), "mimocode-cli-free".into());
        extra_headers.insert("X-Client-Version".into(), "26.924.240030".into());
    }
    if provider_id == "claude" && credential_kind == "oauth" {
        extra_headers.insert("anthropic-beta".to_owned(), "oauth-2025-04-20".to_owned());
    }
    if provider_id == "codex" && credential_kind == "oauth" {
        extra_headers.insert("originator".to_owned(), "codex_cli_rs".to_owned());
        extra_headers.insert(
            "OpenAI-Beta".to_owned(),
            "responses=experimental".to_owned(),
        );
        if let Some(account_id) = auth_state
            .as_ref()
            .and_then(|state| state.get("chatgptAccountId"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| secret.as_deref().and_then(codex_account_id))
        {
            extra_headers.insert("chatgpt-account-id".to_owned(), account_id);
        }
    }
    Ok(DispatchCredential {
        credential_kind,
        secret,
        base_url,
        user_agent: candidate.user_agent.clone(),
        extra_headers,
        auth_state,
        account_id: candidate.provider_account_id.clone(),
    })
}

fn candidate_plan(plan: &RoutePlan, candidate: &RouteCandidate) -> RoutePlan {
    RoutePlan {
        revision: plan.revision,
        candidates: vec![candidate.clone()],
        requested_model: plan.requested_model.clone(),
        resolved_model: plan.resolved_model.clone(),
        provider_id: candidate.provider_id.clone(),
        fusion: None,
    }
}

struct ReleaseGuard {
    engine: Arc<RoutingEngine>,
    reservation: Option<Reservation>,
}

impl ReleaseGuard {
    fn new(engine: Arc<RoutingEngine>, reservation: Reservation) -> Self {
        Self {
            engine,
            reservation: Some(reservation),
        }
    }
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            let engine = Arc::clone(&self.engine);
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    engine.release(&reservation).await;
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Chat,
    Messages,
    Responses,
    Completion,
}

impl Surface {
    fn parse(self, body: &Value) -> Result<CanonicalRequest, GatewayError> {
        match self {
            Self::Chat => ChatAdapter.parse(body),
            Self::Messages => MessagesAdapter.parse(body),
            Self::Responses => ResponsesAdapter.parse(body),
            Self::Completion => CompletionAdapter.parse(body),
        }
    }

    fn sends_done(self) -> bool {
        matches!(self, Self::Chat | Self::Completion)
    }
}

struct StreamFrames {
    encoder: StreamEncoder,
}

enum StreamEncoder {
    Chat(ChatStreamEncoder),
    Messages(MessagesStreamEncoder),
    Responses(ResponsesStreamEncoder),
    Completion(CompletionStreamEncoder),
}

impl StreamFrames {
    fn new(surface: Surface, model: &str, include_usage: bool) -> Self {
        let encoder = match surface {
            Surface::Chat => StreamEncoder::Chat(ChatStreamEncoder::new(ChatEncodeOptions {
                model: Some(model.to_owned()),
                include_usage: Some(include_usage),
                ..Default::default()
            })),
            Surface::Messages => {
                StreamEncoder::Messages(MessagesStreamEncoder::new(model, include_usage))
            }
            Surface::Responses => StreamEncoder::Responses(ResponsesStreamEncoder::new(model)),
            Surface::Completion => {
                StreamEncoder::Completion(CompletionStreamEncoder::new(CompletionEncodeOptions {
                    model: Some(model.to_owned()),
                    ..Default::default()
                }))
            }
        };
        Self { encoder }
    }

    fn push(&mut self, event: &CanonicalEvent) -> Vec<(Option<String>, Value)> {
        match &mut self.encoder {
            StreamEncoder::Chat(encoder) => encoder
                .push(event)
                .into_iter()
                .map(|chunk| (None, chunk))
                .collect(),
            StreamEncoder::Messages(encoder) => encoder
                .push(event)
                .into_iter()
                .map(|frame| {
                    let name = frame.get("type").and_then(Value::as_str).map(str::to_owned);
                    (name, frame)
                })
                .collect(),
            StreamEncoder::Responses(encoder) => encoder
                .push(event)
                .into_iter()
                .map(|(name, payload)| (Some(name), payload))
                .collect(),
            StreamEncoder::Completion(encoder) => encoder
                .push(event)
                .into_iter()
                .map(|chunk| (None, chunk))
                .collect(),
        }
    }

    fn finish(&mut self) -> Vec<(Option<String>, Value)> {
        match &mut self.encoder {
            StreamEncoder::Chat(encoder) => encoder
                .finish()
                .into_iter()
                .map(|chunk| (None, chunk))
                .collect(),
            StreamEncoder::Messages(encoder) => encoder
                .finish()
                .into_iter()
                .map(|frame| {
                    let name = frame.get("type").and_then(Value::as_str).map(str::to_owned);
                    (name, frame)
                })
                .collect(),
            StreamEncoder::Responses(encoder) => encoder
                .finish()
                .into_iter()
                .map(|(name, payload)| (Some(name), payload))
                .collect(),
            StreamEncoder::Completion(encoder) => encoder
                .finish()
                .into_iter()
                .map(|chunk| (None, chunk))
                .collect(),
        }
    }
}

fn frame_bytes(name: Option<&str>, payload: &Value) -> bytes::Bytes {
    let data = serde_json::to_string(payload).unwrap_or_default();
    match name {
        Some(name) => bytes::Bytes::from(format!("event: {name}\ndata: {data}\n\n")),
        None => bytes::Bytes::from(format!("data: {data}\n\n")),
    }
}

struct KeySlotGuard {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<String, i64>>>,
    key: String,
}

impl Drop for KeySlotGuard {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock() {
            let current = *counts.get(&self.key).unwrap_or(&1);
            if current <= 1 {
                counts.remove(&self.key);
            } else {
                counts.insert(self.key.clone(), current - 1);
            }
        }
    }
}

fn acquire_key_slot(
    runtime: &GatewayRuntime,
    key_id: &str,
    max_concurrent: Option<i64>,
) -> Result<Option<KeySlotGuard>, GatewayError> {
    let Some(limit) = max_concurrent else {
        return Ok(None);
    };
    let mut counts = runtime
        .key_inflight
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current = *counts.get(key_id).unwrap_or(&0);
    if current >= limit {
        return Err(GatewayError::new(
            GatewayErrorCode::TenantCapacityExhausted,
            429,
            "This API key has reached its concurrency limit",
            Map::new(),
        ));
    }
    counts.insert(key_id.to_owned(), current + 1);
    Ok(Some(KeySlotGuard {
        counts: Arc::clone(&runtime.key_inflight),
        key: key_id.to_owned(),
    }))
}

async fn check_key_limits(
    runtime: &GatewayRuntime,
    auth: &keyla_security::ResolvedApiKey,
) -> Result<(), GatewayError> {
    if let (Some(budget), Some(consumed)) = (
        auth.snapshot.lifetime_token_budget,
        auth.snapshot.lifetime_tokens_consumed,
    ) {
        if consumed >= budget {
            return Err(GatewayError::new(
                GatewayErrorCode::QuotaExceeded,
                402,
                "This API key has exhausted its token budget",
                Map::new(),
            ));
        }
    }
    let usage: Option<(i64, i64, i64)> = sqlx::query_as(
        "SELECT
            coalesce(sum(input_tokens + output_tokens) FILTER (
                WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')), 0)::bigint,
            coalesce(sum(input_tokens + output_tokens) FILTER (
                WHERE created_at >= date_trunc('month', now() AT TIME ZONE 'UTC')), 0)::bigint,
            count(*) FILTER (WHERE created_at >= now() - interval '1 minute')::bigint
         FROM telemetry_events WHERE tenant_id = $1::uuid AND api_key_id = $2::uuid",
    )
    .bind(&auth.tenant_id)
    .bind(&auth.id)
    .fetch_optional(&runtime.pool)
    .await
    .ok()
    .flatten();
    let (today, month, last_minute) = usage.unwrap_or((0, 0, 0));
    if let Some(limit) = auth.snapshot.daily_tokens {
        if today >= limit {
            return Err(GatewayError::new(
                GatewayErrorCode::QuotaExceeded,
                429,
                "This API key has reached its daily token limit",
                Map::new(),
            ));
        }
    }
    if let Some(limit) = auth.snapshot.monthly_tokens {
        if month >= limit {
            return Err(GatewayError::new(
                GatewayErrorCode::QuotaExceeded,
                429,
                "This API key has reached its monthly token limit",
                Map::new(),
            ));
        }
    }
    if let Some(limit) = auth.snapshot.rpm {
        if last_minute >= limit {
            return Err(GatewayError::new(
                GatewayErrorCode::QuotaExceeded,
                429,
                "This API key has reached its requests-per-minute limit",
                Map::new(),
            ));
        }
    }
    Ok(())
}

struct RedisLeaseGuard {
    lease: Option<(
        keyla_security::redis_admission::RedisAdmission,
        keyla_security::redis_admission::Reservation,
    )>,
}

impl RedisLeaseGuard {
    fn new(
        lease: Option<(
            keyla_security::redis_admission::RedisAdmission,
            keyla_security::redis_admission::Reservation,
        )>,
    ) -> Self {
        Self { lease }
    }

    async fn reconcile(&mut self, tokens: i64) {
        if let Some((redis, reservation)) = self.lease.take() {
            let _ = redis.reconcile(&reservation, tokens).await;
        }
    }

    async fn release(&mut self) {
        if let Some((redis, reservation)) = self.lease.take() {
            let _ = redis.release(&reservation).await;
        }
    }

    fn finish(&mut self) {
        self.lease = None;
    }
}

impl Drop for RedisLeaseGuard {
    fn drop(&mut self) {
        let Some((redis, reservation)) = self.lease.take() else {
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = redis.release(&reservation).await;
            });
        }
    }
}

fn estimated_input_tokens(request: &CanonicalRequest) -> i64 {
    let mut characters = 0usize;
    if let Some(system) = request.system.as_ref().or(request.instructions.as_ref()) {
        characters += system
            .iter()
            .map(|part| match part {
                keyla_core::ContentPart::Text { text } => text.chars().count(),
                _ => 64,
            })
            .sum::<usize>();
    }
    for message in &request.messages {
        for part in &message.content {
            characters += match part {
                keyla_core::ContentPart::Text { text } => text.chars().count(),
                _ => 128,
            };
        }
    }
    let output = request
        .generation_controls
        .max_output_tokens
        .or(request.generation_controls.max_completion_tokens)
        .or(request.generation_controls.max_tokens)
        .unwrap_or(1024)
        .max(1);
    ((characters / 4) as i64 + output).max(1)
}

async fn reserve_admission(
    runtime: &GatewayRuntime,
    auth: &keyla_security::ResolvedApiKey,
    request: &CanonicalRequest,
) -> Result<RedisLeaseGuard, GatewayError> {
    let Some(redis) = runtime.redis_admission.clone() else {
        return Ok(RedisLeaseGuard::new(None));
    };
    let limits = keyla_security::redis_admission::AdmissionLimits {
        now_ms: chrono::Utc::now().timestamp_millis(),
        estimated_tokens: estimated_input_tokens(request),
        rpm: auth.snapshot.rpm,
        daily_tokens: auth.snapshot.daily_tokens,
        monthly_tokens: auth.snapshot.monthly_tokens,
        lifetime_budget: auth.snapshot.lifetime_token_budget,
        lifetime_consumed: auth.snapshot.lifetime_tokens_consumed.unwrap_or(0),
        concurrency: auth.snapshot.max_concurrent,
        tenant_concurrency: None,
        tenant_id: auth.tenant_id.clone(),
        api_key_id: auth.id.clone(),
    };
    match redis.reserve(&limits).await {
        Ok(reservation) => Ok(RedisLeaseGuard::new(Some((redis, reservation)))),
        Err(keyla_security::redis_admission::AdmissionError::Rejected(reason)) => {
            let (status, message) = match reason {
                "daily_token_limit" => (429, "This API key has reached its daily token limit"),
                "monthly_token_limit" => (429, "This API key has reached its monthly token limit"),
                "lifetime_token_budget" => (402, "This API key has exhausted its token budget"),
                "concurrency_limit" => (429, "This API key has reached its concurrency limit"),
                "tenant_capacity_exhausted" => {
                    (429, "This tenant has reached its concurrency limit")
                }
                _ => (
                    429,
                    "This API key has reached its requests-per-minute limit",
                ),
            };
            Err(GatewayError::new(
                GatewayErrorCode::QuotaExceeded,
                status,
                message,
                Map::new(),
            ))
        }
        Err(error) => Err(GatewayError::new(
            GatewayErrorCode::AdmissionUnavailable,
            503,
            format!("admission store unavailable: {error}"),
            Map::new(),
        )),
    }
}

#[derive(Clone)]
struct TelemetryContext {
    pool: sqlx::PgPool,
    tenant_id: String,
    api_key_id: String,
    source_surface: &'static str,
    requested_model: String,
    provider_id: String,
    account_id: Option<String>,
    endpoint: String,
    user_agent: Option<String>,
    client_ip: Option<String>,
    started: std::time::Instant,
}

fn surface_name(surface: Surface) -> &'static str {
    match surface {
        Surface::Chat => "chat",
        Surface::Messages => "messages",
        Surface::Responses => "responses",
        Surface::Completion => "completion",
    }
}

fn event_usage(event: &CanonicalEvent) -> Option<&keyla_core::UsageRecord> {
    match event {
        CanonicalEvent::Usage { usage, .. } => Some(usage),
        CanonicalEvent::Terminal {
            usage: Some(usage), ..
        } => Some(usage),
        _ => None,
    }
}

fn token_value(value: &keyla_core::TokenCount) -> Option<i64> {
    value.value()
}

#[allow(clippy::too_many_arguments)]
async fn record_telemetry(
    context: &TelemetryContext,
    status: &str,
    http_status: u16,
    error: Option<&GatewayError>,
    stream: bool,
    usage: Option<&keyla_core::UsageRecord>,
) {
    let latency_ms = context.started.elapsed().as_millis().min(i32::MAX as u128) as i32;
    let error_category = error.map(|error| error.code.as_str());
    let error_origin = error.map(|error| error.origin.as_str());
    let (input, cached, output, reasoning, cost) = match usage {
        Some(usage) => (
            Some(usage.input_tokens as i32),
            token_value(&usage.cached_input_tokens).map(|value| value as i32),
            Some(usage.output_tokens as i32),
            token_value(&usage.reasoning_tokens).map(|value| value as i32),
            usage.estimated_cost,
        ),
        None => (None, None, None, None, None),
    };
    let _ = sqlx::query(
        "INSERT INTO telemetry_events (
            request_id, tenant_id, source_surface, requested_model, provider_id, account_id,
            endpoint, api_key_id, user_agent, client_ip, latency_ms, stream, status,
            http_status, error_category, error_origin, input_tokens, cached_input_tokens,
            output_tokens, reasoning_tokens, estimated_cost_usd
         ) VALUES (
            gen_random_uuid(), $1::uuid, $2::telemetry_source_surface, $3, $4, $5::uuid,
            $6, $7::uuid, $8, $9, $10, $11, $12::telemetry_status,
            $13, $14, $15, $16, $17, $18, $19, $20
         )",
    )
    .bind(&context.tenant_id)
    .bind(context.source_surface)
    .bind(&context.requested_model)
    .bind(&context.provider_id)
    .bind(&context.account_id)
    .bind(&context.endpoint)
    .bind(&context.api_key_id)
    .bind(&context.user_agent)
    .bind(&context.client_ip)
    .bind(latency_ms)
    .bind(stream)
    .bind(status)
    .bind(http_status as i32)
    .bind(error_category)
    .bind(error_origin)
    .bind(input)
    .bind(cached)
    .bind(output)
    .bind(reasoning)
    .bind(cost)
    .execute(&context.pool)
    .await;
    if let Some(usage) = usage {
        let tokens = usage.input_tokens + usage.output_tokens;
        if tokens > 0 {
            let _ = sqlx::query(
                "UPDATE api_keys SET lifetime_tokens_consumed = lifetime_tokens_consumed + $2
                 WHERE id = $1::uuid",
            )
            .bind(&context.api_key_id)
            .bind(tokens)
            .execute(&context.pool)
            .await;
        }
        let _ = sqlx::query(
            "INSERT INTO telemetry_usage_totals
                (tenant_id, identity_type, entity_id, requests, errors, input_tokens, output_tokens, last_used_at)
             VALUES ($1::uuid, 'api_key', $2::uuid, 1, $3, $4, $5, now())
             ON CONFLICT (tenant_id, identity_type, entity_id) DO UPDATE SET
                requests = telemetry_usage_totals.requests + 1,
                errors = telemetry_usage_totals.errors + $3,
                input_tokens = telemetry_usage_totals.input_tokens + $4,
                output_tokens = telemetry_usage_totals.output_tokens + $5,
                last_used_at = now(), updated_at = now()",
        )
        .bind(&context.tenant_id)
        .bind(&context.api_key_id)
        .bind(if status == "failed" { 1i64 } else { 0i64 })
        .bind(usage.input_tokens)
        .bind(usage.output_tokens)
        .execute(&context.pool)
        .await;
    }
}

struct StreamTelemetryGuard {
    telemetry: Option<TelemetryContext>,
}

impl StreamTelemetryGuard {
    fn finish(&mut self) {
        self.telemetry = None;
    }
}

impl Drop for StreamTelemetryGuard {
    fn drop(&mut self) {
        let Some(telemetry) = self.telemetry.take() else {
            return;
        };
        // The client left before the stream completed: account the attempt as a
        // client cancellation (499), the same outcome the TS finalizer writes.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                record_telemetry(&telemetry, "cancelled", 499, None, true, None).await;
            });
        }
    }
}

fn stream_response(
    output: futures_util::stream::BoxStream<'static, Result<CanonicalEvent, GatewayError>>,
    surface: Surface,
    model: String,
    include_usage: bool,
    guard: ReleaseGuard,
    telemetry: TelemetryContext,
    mut redis_guard: RedisLeaseGuard,
) -> Response {
    let stream = async_stream::stream! {
        let _guard = guard;
        let mut telemetry_guard = StreamTelemetryGuard {
            telemetry: Some(telemetry.clone()),
        };
        let mut frames = StreamFrames::new(surface, &model, include_usage);
        let mut upstream = output;
        let mut usage = None;
        let mut failure: Option<GatewayError> = None;
        while let Some(item) = upstream.next().await {
            match item {
                Ok(event) => {
                    if let Some(record) = event_usage(&event) {
                        usage = Some(record.clone());
                    }
                    for (name, payload) in frames.push(&event) {
                        yield Ok::<bytes::Bytes, std::io::Error>(frame_bytes(name.as_deref(), &payload));
                    }
                }
                Err(error) => {
                    yield Ok(frame_bytes(Some("error"), &error.public_body()));
                    failure = Some(error);
                    break;
                }
            }
        }
        for (name, payload) in frames.finish() {
            yield Ok(frame_bytes(name.as_deref(), &payload));
        }
        if surface.sends_done() {
            yield Ok(bytes::Bytes::from_static(b"data: [DONE]\n\n"));
        }
        let (status, http_status) = match failure.as_ref() {
            Some(error) => ("failed", error.status),
            None => ("completed", 200),
        };
        record_telemetry(&telemetry, status, http_status, failure.as_ref(), true, usage.as_ref()).await;
        let actual = usage
            .as_ref()
            .map(|usage| usage.input_tokens + usage.output_tokens)
            .unwrap_or(0);
        redis_guard.reconcile(actual).await;
        telemetry_guard.finish();
    };
    apply_security_headers(
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/event-stream")
            .header("connection", "keep-alive")
            .header("cache-control", "no-cache, no-transform")
            .header("x-accel-buffering", "no"),
    )
    .body(Body::from_stream(stream))
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn authenticated(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Arc<GatewayRuntime>, keyla_security::ResolvedApiKey), Box<Response>> {
    let Some(runtime) = state.runtime.clone() else {
        return Err(Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "platform_unavailable",
            "gateway runtime is not configured",
        )));
    };
    let token = match request_token(&header_map(headers)) {
        Ok(token) => token,
        Err(error) => return Err(Box::new(gateway_error_response(&error))),
    };
    match resolve_api_key_authorization(&runtime.pool, &token).await {
        Ok(Some(auth)) => Ok((runtime, auth)),
        Ok(None) => Err(Box::new(gateway_error_response(&GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "invalid or revoked API key",
            Map::new(),
        )))),
        Err(error) => Err(Box::new(gateway_error_response(&GatewayError::new(
            GatewayErrorCode::InternalError,
            500,
            format!("api key lookup failed: {error}"),
            Map::new(),
        )))),
    }
}

async fn proxy(state: AppState, request: Request, surface: Surface) -> Response {
    let headers = request.headers().clone();
    let client_identity = request
        .extensions()
        .get::<crate::model_abuse::ClientIdentity>()
        .map(|identity| identity.0.to_string());
    let now_ms = keyla_protocol::translation::now_millis();
    let peer_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(address)| address.ip().to_string());
    let (runtime, auth) = match authenticated(&state, &headers).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let started = std::time::Instant::now();
    if let Err(error) = check_key_limits(&runtime, &auth).await {
        return gateway_error_response(&error);
    }
    let _key_slot = match acquire_key_slot(&runtime, &auth.id, auth.snapshot.max_concurrent) {
        Ok(guard) => guard,
        Err(error) => return gateway_error_response(&error),
    };
    let body_bytes = match to_bytes(request.into_body(), state.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return gateway_error_response(&GatewayError::new(
                GatewayErrorCode::RequestTooLarge,
                413,
                "request body too large",
                Map::new(),
            ));
        }
    };
    let body: Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(error) => {
            return gateway_error_response(&GatewayError::new(
                GatewayErrorCode::InvalidRequest,
                400,
                format!("Malformed JSON body: {error}"),
                Map::new(),
            ));
        }
    };
    let canonical = match surface.parse(&body) {
        Ok(request) => request,
        Err(error) => return gateway_error_response(&error),
    };
    let snapshot = match runtime.snapshots.get().await {
        Ok(snapshot) => snapshot,
        Err(error) => return gateway_error_response(&error),
    };
    let required = derive_required_capabilities(&canonical);
    let input = PlanInput {
        requested_model: &canonical.model,
        tenant_id: Some(auth.tenant_id.as_str()),
        required_capabilities: (!required.is_empty()).then_some(required.as_slice()),
        allow_cli_mappings: auth
            .scopes
            .iter()
            .any(|scope| scope == "routing:cli_mapping"),
        key_id: Some(auth.id.as_str()),
        web_search: request_uses_web_search(&canonical),
        advance: true,
    };
    let plan = match runtime.engine.plan(&snapshot, input) {
        Ok(plan) => plan,
        Err(error) => {
            if matches!(
                error.code,
                GatewayErrorCode::ModelNotFound | GatewayErrorCode::AmbiguousModel
            ) {
                if let Some(identity) = &client_identity {
                    let (banned, strikes) = state.model_abuse.record_invalid(identity, now_ms);
                    if banned {
                        return gateway_error_response(&GatewayError::new(
                            GatewayErrorCode::ModelAbuseBanned,
                            403,
                            "This address is temporarily blocked for repeated invalid-model requests",
                            Map::new(),
                        ));
                    }
                    let mut details = Map::new();
                    details.insert("warningCount".into(), json!(strikes));
                    let mut with_warning = error;
                    with_warning.details.extend(details);
                    return gateway_error_response(&with_warning);
                }
            }
            return gateway_error_response(&error);
        }
    };
    let policy = ModelAccessPolicy {
        model_access_mode: Some(auth.snapshot.model_access_mode),
        model_list: auth.snapshot.model_list.clone(),
    };
    if let Some(reason) = model_rejection_reason(
        &policy,
        &plan.resolved_model,
        Some(&plan.provider_id),
        Some(&canonical.model),
    ) {
        let mut details = Map::new();
        details.insert("model".into(), json!(canonical.model));
        details.insert("reason".into(), json!(reason.as_str()));
        if let Some(identity) = &client_identity {
            let (banned, strikes) = state.model_abuse.record_invalid(identity, now_ms);
            if banned {
                return gateway_error_response(&GatewayError::new(
                    GatewayErrorCode::ModelAbuseBanned,
                    403,
                    "This address is temporarily blocked for repeated invalid-model requests",
                    Map::new(),
                ));
            }
            details.insert("warningCount".into(), json!(strikes));
        }
        return gateway_error_response(&GatewayError::new(
            GatewayErrorCode::ModelNotFound,
            404,
            format!("Model '{}' not found", canonical.model),
            details,
        ));
    }

    if let Some(identity) = &client_identity {
        state.model_abuse.note_valid(identity);
    }
    let mut redis_guard = match reserve_admission(&runtime, &auth, &canonical).await {
        Ok(guard) => guard,
        Err(error) => return gateway_error_response(&error),
    };
    let include_usage = match surface {
        Surface::Chat => canonical
            .generation_controls
            .extensions
            .get("extension:include_usage")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        Surface::Messages | Surface::Responses => true,
        Surface::Completion => true,
    };
    let chat_options = ChatEncodeOptions {
        include_usage: Some(include_usage),
        service_tier: canonical.generation_controls.service_tier.clone(),
        ..Default::default()
    };

    let mut last_error: Option<GatewayError> = None;
    let candidate_count = plan.candidates.len();
    for (index, candidate) in plan.candidates.iter().enumerate() {
        let single = candidate_plan(&plan, candidate);
        let reservation = match runtime.engine.reserve_with_ttl(&single, 600_000).await {
            Ok(reservation) => reservation,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let credential = match build_credential(&runtime, candidate).await {
            Ok(credential) => credential,
            Err(error) => {
                runtime.engine.release(&reservation).await;
                last_error = Some(error);
                continue;
            }
        };
        let target = DispatchTarget {
            provider_id: candidate.provider_id.clone(),
            model_id: candidate.model_id.clone(),
            endpoint_path: candidate.endpoint.clone(),
        };
        let dispatched = if candidate.provider_id == "kiro" {
            keyla_providers::kiro::dispatch_kiro(&runtime.client, &canonical, &target, &credential)
                .await
        } else if matches!(candidate.provider_id.as_str(), "cb" | "cbcn" | "workbuddy") {
            keyla_providers::buddy::dispatch_buddy(
                &runtime.client,
                &candidate.provider_id,
                &canonical,
                &target,
                &credential,
            )
            .await
        } else if candidate.provider_id == "devin" {
            keyla_providers::devin::dispatch_devin(
                &runtime.client,
                &canonical,
                &target,
                &credential,
            )
            .await
        } else if candidate.provider_id == "antigravity" {
            keyla_providers::antigravity::dispatch_antigravity(
                &runtime.client,
                &canonical,
                &target,
                &credential,
            )
            .await
        } else if candidate.provider_id == "mimodesktop" {
            let mut request = canonical.clone();
            request.model = keyla_providers::mimodesktop::resolve_model(&candidate.model_id);
            dispatch_chat(&runtime.client, &request, &target, &credential).await
        } else if candidate.provider_id == "mimostudio" {
            keyla_providers::mimostudio::dispatch_mimostudio(
                &runtime.client,
                &canonical,
                &target,
                &credential,
            )
            .await
        } else if candidate.provider_id == "qoder" {
            keyla_providers::qoder::dispatch_qoder(
                &runtime.client,
                &canonical,
                &target,
                &credential,
            )
            .await
        } else if candidate.provider_id == "gemini" {
            keyla_providers::gemini::dispatch_gemini(
                &runtime.client,
                &canonical,
                &target,
                &credential,
            )
            .await
        } else {
            match candidate.wire_family {
                WireFamily::Chat => {
                    dispatch_chat(&runtime.client, &canonical, &target, &credential).await
                }
                WireFamily::Messages => {
                    dispatch_messages(&runtime.client, &canonical, &target, &credential).await
                }
                WireFamily::Responses => {
                    dispatch_responses(&runtime.client, &canonical, &target, &credential).await
                }
            }
        };
        match dispatched {
            Ok(output) => {
                let model = plan.resolved_model.clone();
                let telemetry = TelemetryContext {
                    pool: runtime.pool.clone(),
                    tenant_id: auth.tenant_id.clone(),
                    api_key_id: auth.id.clone(),
                    source_surface: surface_name(surface),
                    requested_model: canonical.model.clone(),
                    provider_id: candidate.provider_id.clone(),
                    account_id: candidate.provider_account_id.clone(),
                    endpoint: candidate.endpoint.clone(),
                    user_agent: headers
                        .get("user-agent")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                    client_ip: headers
                        .get("x-forwarded-for")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.split(',').next())
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .or_else(|| peer_ip.clone()),
                    started,
                };
                return match output {
                    DispatchOutput::Events(events) => {
                        runtime.engine.release(&reservation).await;
                        let body = match surface {
                            Surface::Chat => {
                                let options = ChatEncodeOptions {
                                    model: Some(model.clone()),
                                    ..chat_options.clone()
                                };
                                let id = get_response_id(&options, &events);
                                let created = options.created.unwrap_or_else(|| {
                                    keyla_protocol::translation::now_millis() / 1000
                                });
                                json_completion(&events, &options, &model, &id, created)
                            }
                            Surface::Messages => {
                                keyla_protocol::surface::messages::encode_messages_response(
                                    &events,
                                    &model,
                                    include_usage,
                                )
                            }
                            Surface::Responses => {
                                keyla_protocol::surface::responses::encode_responses_response(
                                    &events, &model,
                                )
                            }
                            Surface::Completion => encode_completion_response(
                                &events,
                                &CompletionEncodeOptions {
                                    model: Some(model.clone()),
                                    prompt: canonical
                                        .generation_controls
                                        .extensions
                                        .get("extension:completion.prompt")
                                        .cloned(),
                                    echo: canonical
                                        .generation_controls
                                        .extensions
                                        .get("extension:completion.echo")
                                        .and_then(Value::as_bool)
                                        .unwrap_or(false),
                                    suffix: canonical
                                        .generation_controls
                                        .extensions
                                        .get("extension:completion.suffix")
                                        .and_then(Value::as_str)
                                        .map(str::to_owned),
                                    ..Default::default()
                                },
                            ),
                        };
                        let usage = events.iter().filter_map(event_usage).next_back().cloned();
                        record_telemetry(&telemetry, "completed", 200, None, false, usage.as_ref())
                            .await;
                        let actual = usage
                            .as_ref()
                            .map(|usage| usage.input_tokens + usage.output_tokens)
                            .unwrap_or(0);
                        redis_guard.reconcile(actual).await;
                        redis_guard.finish();
                        json_response(&body)
                    }
                    DispatchOutput::Stream(mut stream) => {
                        // Retry before any byte reaches the client. The HTTP
                        // status has not been committed yet, so a retryable
                        // upstream failure on the first frame can still fail
                        // over to the next candidate instead of surfacing a
                        // 200 stream that immediately errors.
                        match stream.next().await {
                            Some(Err(error))
                                if is_retryable(&error) && index + 1 < candidate_count =>
                            {
                                runtime.engine.release(&reservation).await;
                                last_error = Some(error);
                                continue;
                            }
                            Some(Err(error)) => {
                                runtime.engine.release(&reservation).await;
                                last_error = Some(error);
                                break;
                            }
                            Some(Ok(event)) => {
                                let combined = futures_util::stream::iter(vec![Ok(event)])
                                    .chain(stream)
                                    .boxed();
                                let guard =
                                    ReleaseGuard::new(Arc::clone(&runtime.engine), reservation);
                                stream_response(
                                    combined,
                                    surface,
                                    model,
                                    include_usage,
                                    guard,
                                    telemetry,
                                    redis_guard,
                                )
                            }
                            None => {
                                let guard =
                                    ReleaseGuard::new(Arc::clone(&runtime.engine), reservation);
                                stream_response(
                                    stream,
                                    surface,
                                    model,
                                    include_usage,
                                    guard,
                                    telemetry,
                                    redis_guard,
                                )
                            }
                        }
                    }
                };
            }
            Err(error) => {
                runtime.engine.release(&reservation).await;
                let retryable = is_retryable(&error);
                last_error = Some(error);
                if !retryable || index + 1 >= candidate_count {
                    break;
                }
            }
        }
    }
    let error = last_error.unwrap_or_else(|| {
        GatewayError::new(
            GatewayErrorCode::AccountsUnavailable,
            503,
            "no candidate could serve the request",
            Map::new(),
        )
    });
    let telemetry = TelemetryContext {
        pool: runtime.pool.clone(),
        tenant_id: auth.tenant_id.clone(),
        api_key_id: auth.id.clone(),
        source_surface: surface_name(surface),
        requested_model: canonical.model.clone(),
        provider_id: plan.provider_id.clone(),
        account_id: plan
            .candidates
            .first()
            .and_then(|candidate| candidate.provider_account_id.clone()),
        endpoint: plan
            .candidates
            .first()
            .map(|candidate| candidate.endpoint.clone())
            .unwrap_or_default(),
        user_agent: headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        client_ip: headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| peer_ip.clone()),
        started,
    };
    record_telemetry(
        &telemetry,
        "failed",
        error.status,
        Some(&error),
        false,
        None,
    )
    .await;
    redis_guard.release().await;
    gateway_error_response(&error)
}

/// `POST /v1/completions` (legacy text completions).
pub async fn completions(State(state): State<AppState>, request: Request) -> Response {
    proxy(state, request, Surface::Completion).await
}

/// `POST /v1/chat/completions`.
pub async fn chat_completions(State(state): State<AppState>, request: Request) -> Response {
    proxy(state, request, Surface::Chat).await
}

/// `POST /v1/messages` (Anthropic surface).
pub async fn messages(State(state): State<AppState>, request: Request) -> Response {
    proxy(state, request, Surface::Messages).await
}

/// `POST /v1/responses` (OpenAI Responses surface).
pub async fn responses(State(state): State<AppState>, request: Request) -> Response {
    proxy(state, request, Surface::Responses).await
}

/// `GET /v1/models` — the models this key may use, derived from the same
/// routing snapshot the data plane reads.
pub async fn list_models(State(state): State<AppState>, request: Request) -> Response {
    let headers = request.headers().clone();
    let (runtime, auth) = match authenticated(&state, &headers).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let snapshot = match runtime.snapshots.get().await {
        Ok(snapshot) => snapshot,
        Err(error) => return gateway_error_response(&error),
    };
    let policy = ModelAccessPolicy {
        model_access_mode: Some(auth.snapshot.model_access_mode),
        model_list: auth.snapshot.model_list.clone(),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut data = Vec::new();
    for candidate in &snapshot.candidates {
        if candidate.tenant_id.is_some()
            && candidate.tenant_id.as_deref() != Some(auth.tenant_id.as_str())
        {
            continue;
        }
        if candidate.health_status == Some(HealthStatus::Disabled) {
            continue;
        }
        let id = if snapshot
            .candidates
            .iter()
            .filter(|other| other.model_id == candidate.model_id)
            .map(|other| &other.provider_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1
        {
            format!("{}/{}", candidate.provider_id, candidate.model_id)
        } else {
            candidate.model_id.clone()
        };
        if !seen.insert(id.clone()) {
            continue;
        }
        if model_rejection_reason(
            &policy,
            &candidate.model_id,
            Some(&candidate.provider_id),
            Some(&id),
        )
        .is_some()
        {
            continue;
        }
        data.push(json!({
            "id": id,
            "object": "model",
            "created": 0,
            "owned_by": candidate.provider_id,
        }));
    }
    json_response(&json!({ "object": "list", "data": data }))
}

/// `POST /v1/search` — native web-search route (Exa first).
pub async fn search(State(state): State<AppState>, request: Request) -> Response {
    let headers = request.headers().clone();
    let (runtime, auth) = match authenticated(&state, &headers).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if !auth.scopes.iter().any(|scope| scope == "search:invoke") {
        return gateway_error_response(&GatewayError::new(
            GatewayErrorCode::PolicyRejected,
            403,
            "search:invoke scope is required for this key",
            Map::new(),
        ));
    }
    let body_bytes = match to_bytes(request.into_body(), state.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return gateway_error_response(&GatewayError::new(
                GatewayErrorCode::RequestTooLarge,
                413,
                "request body too large",
                Map::new(),
            ));
        }
    };
    let body: Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(error) => {
            return gateway_error_response(&GatewayError::new(
                GatewayErrorCode::InvalidRequest,
                400,
                format!("Malformed JSON body: {error}"),
                Map::new(),
            ));
        }
    };
    let Some(model) = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return gateway_error_response(&GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            "model is required",
            Map::new(),
        ));
    };
    let Some(query) = body
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return gateway_error_response(&GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            "query is required",
            Map::new(),
        ));
    };
    let snapshot = match runtime.snapshots.get().await {
        Ok(snapshot) => snapshot,
        Err(error) => return gateway_error_response(&error),
    };
    let plan = match runtime.engine.plan(
        &snapshot,
        PlanInput {
            requested_model: model,
            tenant_id: Some(auth.tenant_id.as_str()),
            required_capabilities: None,
            allow_cli_mappings: false,
            key_id: Some(auth.id.as_str()),
            web_search: true,
            advance: false,
        },
    ) {
        Ok(plan) => plan,
        Err(error) => return gateway_error_response(&error),
    };
    let candidates: Vec<&RouteCandidate> = plan
        .candidates
        .iter()
        .filter(|candidate| candidate.service_kind == keyla_core::ServiceKind::Websearch)
        .collect();
    let Some(candidate) = candidates.first() else {
        return gateway_error_response(&GatewayError::new(
            GatewayErrorCode::CapabilityUnsupported,
            400,
            "web search is unavailable for this model",
            Map::new(),
        ));
    };
    let credential = match build_credential(&runtime, candidate).await {
        Ok(credential) => credential,
        Err(error) => return gateway_error_response(&error),
    };
    let max_results = body
        .get("max_results")
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1, 50))
        .unwrap_or(10);
    let domain_filter: Vec<String> = body
        .get("domain_filter")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut includes = Vec::new();
    let mut excludes = Vec::new();
    for entry in domain_filter {
        match entry.strip_prefix('-') {
            Some(rest) => excludes.push(rest.to_owned()),
            None => includes.push(entry),
        }
    }
    if candidate.provider_id == "codex" {
        let endpoint = format!(
            "{}{}",
            credential.base_url.trim_end_matches('/'),
            if candidate.endpoint.starts_with('/') {
                candidate.endpoint.clone()
            } else {
                format!("/{}", candidate.endpoint)
            }
        );
        let payload = json!({
            "model": "gpt-5.6-sol",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": query}]}],
            "tools": [{"type": "web_search"}],
            "max_output_tokens": 1024,
            "stream": false,
        });
        let mut request = runtime.client.post(endpoint).json(&payload);
        if let Some(secret) = &credential.secret {
            request = request.bearer_auth(secret);
        }
        for (name, value) in &credential.extra_headers {
            if let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::try_from(name.as_str()),
                axum::http::HeaderValue::from_str(value),
            ) {
                request = request.header(name, value);
            }
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return gateway_error_response(&GatewayError::new(
                    GatewayErrorCode::TransportUnavailable,
                    502,
                    format!("search upstream failed: {error}"),
                    Map::new(),
                ));
            }
        };
        let status = response.status();
        let payload: Value = response.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let mut details = Map::new();
            details.insert("providerId".into(), json!(candidate.provider_id));
            details.insert("providerStatus".into(), json!(status.as_u16()));
            return gateway_error_response(
                &GatewayError::new(
                    GatewayErrorCode::UpstreamConflict,
                    status.as_u16(),
                    format!("search upstream returned HTTP {}", status.as_u16()),
                    details,
                )
                .with_origin(keyla_core::GatewayErrorOrigin::Upstream),
            );
        }
        let mut citations = Vec::new();
        fn collect_citations(value: &Value, out: &mut Vec<Value>) {
            match value {
                Value::Array(items) => {
                    for item in items {
                        collect_citations(item, out);
                    }
                }
                Value::Object(object) => {
                    if object.get("url").and_then(Value::as_str).is_some() {
                        let kind = object.get("type").and_then(Value::as_str);
                        if kind == Some("url_citation")
                            || object.contains_key("start_index")
                            || (kind.is_none() && object.contains_key("title"))
                        {
                            out.push(value.clone());
                        }
                    }
                    for (key, nested) in object {
                        if key != "url" {
                            collect_citations(nested, out);
                        }
                    }
                }
                _ => {}
            }
        }
        collect_citations(&payload, &mut citations);
        let mut answer = payload
            .get("output_text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if answer.is_empty() {
            if let Some(output) = payload.get("output").and_then(Value::as_array) {
                for item in output {
                    if let Some(content) = item.get("content").and_then(Value::as_array) {
                        for part in content {
                            if let Some(text) = part.get("text").and_then(Value::as_str) {
                                answer.push_str(text);
                            }
                        }
                    }
                }
            }
        }
        let snippet: String = answer.trim().chars().take(400).collect();
        let mut seen = std::collections::HashSet::new();
        let results: Vec<Value> = citations
            .iter()
            .filter_map(|citation| {
                let source = citation.get("url_citation").unwrap_or(citation);
                let url = source.get("url").and_then(Value::as_str)?;
                if !seen.insert(url.to_owned()) {
                    return None;
                }
                Some(json!({
                    "title": source.get("title").and_then(Value::as_str).unwrap_or(""),
                    "url": url,
                    "snippet": snippet,
                    "published_at": Value::Null,
                    "score": Value::Null,
                }))
            })
            .collect();
        let results: Vec<Value> = results.into_iter().take(max_results as usize).collect();
        return apply_security_headers(
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("cache-control", "no-store"),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "provider": candidate.provider_id,
                "model": candidate.model_id,
                "query": query,
                "results": results,
                "total_results": results.len(),
                "usage": {"queries_used": 1},
            }))
            .unwrap_or_default(),
        ))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    if candidate.provider_id == "gemini" {
        let endpoint = format!(
            "{}{}",
            credential.base_url.trim_end_matches('/'),
            if candidate.endpoint.starts_with('/') {
                candidate.endpoint.clone()
            } else {
                format!("/{}", candidate.endpoint)
            }
        );
        let payload = json!({
            "contents": [{"parts": [{"text": query}]}],
            "tools": [{"google_search": {}}],
        });
        let mut request = runtime.client.post(endpoint).json(&payload);
        if let Some(secret) = &credential.secret {
            request = request.header("x-goog-api-key", secret);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return gateway_error_response(&GatewayError::new(
                    GatewayErrorCode::TransportUnavailable,
                    502,
                    format!("search upstream failed: {error}"),
                    Map::new(),
                ));
            }
        };
        let status = response.status();
        let payload: Value = response.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let mut details = Map::new();
            details.insert("providerId".into(), json!(candidate.provider_id));
            details.insert("providerStatus".into(), json!(status.as_u16()));
            return gateway_error_response(
                &GatewayError::new(
                    GatewayErrorCode::UpstreamConflict,
                    status.as_u16(),
                    format!("search upstream returned HTTP {}", status.as_u16()),
                    details,
                )
                .with_origin(keyla_core::GatewayErrorOrigin::Upstream),
            );
        }
        let results: Vec<Value> = payload
            .get("candidates")
            .and_then(Value::as_array)
            .and_then(|candidates| candidates.first())
            .and_then(|candidate| candidate.get("groundingMetadata"))
            .and_then(|metadata| metadata.get("groundingChunks"))
            .and_then(Value::as_array)
            .map(|chunks| {
                chunks
                    .iter()
                    .filter_map(|chunk| {
                        let web = chunk.get("web")?;
                        let url = web.get("uri").and_then(Value::as_str)?;
                        Some(json!({
                            "title": web.get("title").and_then(Value::as_str).unwrap_or(""),
                            "url": url,
                            "snippet": "",
                            "published_at": Value::Null,
                            "score": Value::Null,
                        }))
                    })
                    .collect()
            })
            .unwrap_or_default();
        return apply_security_headers(
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("cache-control", "no-store"),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({
                "provider": candidate.provider_id,
                "model": candidate.model_id,
                "query": query,
                "results": results,
                "total_results": results.len(),
                "usage": {"queries_used": 1},
            }))
            .unwrap_or_default(),
        ))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    let mut upstream_body = json!({
        "query": query,
        "numResults": max_results,
        "type": "auto",
        "text": true,
        "highlights": true,
    });
    if !includes.is_empty() {
        upstream_body
            .as_object_mut()
            .expect("object")
            .insert("includeDomains".into(), json!(includes));
    }
    if !excludes.is_empty() {
        upstream_body
            .as_object_mut()
            .expect("object")
            .insert("excludeDomains".into(), json!(excludes));
    }
    let endpoint = format!(
        "{}{}",
        credential.base_url.trim_end_matches('/'),
        if candidate.endpoint.starts_with('/') {
            candidate.endpoint.clone()
        } else {
            format!("/{}", candidate.endpoint)
        }
    );
    let mut request = runtime.client.post(endpoint).json(&upstream_body);
    if let Some(secret) = &credential.secret {
        request = request.header("x-api-key", secret);
    }
    let started = std::time::Instant::now();
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return gateway_error_response(&GatewayError::new(
                GatewayErrorCode::TransportUnavailable,
                502,
                format!("search upstream failed: {error}"),
                Map::new(),
            ));
        }
    };
    let status = response.status();
    let payload: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let mut details = Map::new();
        details.insert("providerId".into(), json!(candidate.provider_id));
        details.insert("providerStatus".into(), json!(status.as_u16()));
        return gateway_error_response(
            &GatewayError::new(
                GatewayErrorCode::UpstreamConflict,
                status.as_u16(),
                format!("search upstream returned HTTP {}", status.as_u16()),
                details,
            )
            .with_origin(keyla_core::GatewayErrorOrigin::Upstream),
        );
    }
    let results: Vec<Value> = payload
        .get("results")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let url = item.get("url").and_then(Value::as_str)?;
                    let highlights = item
                        .get("highlights")
                        .and_then(Value::as_array)
                        .and_then(|values| values.first())
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let snippet = if !highlights.is_empty() {
                        highlights.to_owned()
                    } else {
                        item.get("text")
                            .and_then(Value::as_str)
                            .map(|text| text.chars().take(300).collect())
                            .unwrap_or_default()
                    };
                    Some(json!({
                        "title": item.get("title").and_then(Value::as_str).unwrap_or(""),
                        "url": url,
                        "snippet": snippet,
                        "published_at": item.get("publishedDate").and_then(Value::as_str),
                        "score": item.get("score").and_then(Value::as_f64).map(|score| score.clamp(0.0, 1.0)),
                    }))
                })
                .collect()
        })
        .unwrap_or_default();
    let request_id = format!("search_{}", started.elapsed().as_nanos());
    apply_security_headers(
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("cache-control", "no-store")
            .header("x-request-id", request_id),
    )
    .body(Body::from(
        serde_json::to_vec(&json!({
            "provider": candidate.provider_id,
            "model": candidate.model_id,
            "query": query,
            "results": results,
            "total_results": results.len(),
            "usage": {"queries_used": 1},
        }))
        .unwrap_or_default(),
    ))
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
