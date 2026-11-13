//! OAuth device-code login for subscription providers (Codex, xAI, GitHub
//! Copilot) plus shared account persistence.
//!
//! Browser PKCE flows and provider-specific import/credential validation are
//! still separate surfaces; this module owns the device half end to end:
//! start, poll, exchange, and persist.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::Utc;
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CODEX_DEVICE_USERCODE: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const CODEX_DEVICE_TOKEN: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const CODEX_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";

const XAI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const XAI_DEVICE_URL: &str = "https://auth.x.ai/oauth2/device/code";
const XAI_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
const XAI_USERINFO_URL: &str = "https://auth.x.ai/oauth2/userinfo";
const XAI_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";

const MUSE_CLIENT_ID: &str = "1031625952748946";
const CLINE_CLIENT_ID: &str = "client_01K3A541FN8TA3EPPHTD2325AR";
const KIMI_CLIENT_ID: &str = "17e5f671-d194-4dfb-9706-5516cb48c098";
const KIMI_OAUTH_HOST: &str = "https://auth.kimi.com";

const GITHUB_CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";
const GITHUB_DEVICE_URL: &str = "https://github.com/login/device/code";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

#[derive(Clone)]
struct DeviceFlow {
    provider_id: String,
    tenant_id: String,
    label: String,
    provider_state: Option<String>,
    expires_at_ms: i64,
}

fn flows() -> &'static Mutex<HashMap<String, DeviceFlow>> {
    static FLOWS: OnceLock<Mutex<HashMap<String, DeviceFlow>>> = OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

#[allow(clippy::result_large_err)]
fn http_client() -> Result<reqwest::Client, Response> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("http client: {error}"),
            )
        })
}

pub(crate) fn jwt_payload(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn codex_profile(access: &str, id_token: Option<&str>) -> (Option<String>, Option<String>) {
    let access_claims = jwt_payload(access);
    let id_claims = id_token.and_then(jwt_payload);
    let auth_key = "https://api.openai.com/auth";
    let profile_key = "https://api.openai.com/profile";
    let account = access_claims
        .as_ref()
        .and_then(|claims| claims.get(auth_key))
        .and_then(|auth| auth.get("chatgpt_account_id"))
        .and_then(Value::as_str)
        .or_else(|| {
            id_claims
                .as_ref()
                .and_then(|claims| claims.get(auth_key))
                .and_then(|auth| auth.get("chatgpt_account_id"))
                .and_then(Value::as_str)
        })
        .map(str::to_owned);
    let email = access_claims
        .as_ref()
        .and_then(|claims| claims.get(profile_key))
        .and_then(|profile| profile.get("email"))
        .and_then(Value::as_str)
        .or_else(|| {
            id_claims
                .as_ref()
                .and_then(|claims| claims.get(profile_key))
                .and_then(|profile| profile.get("email"))
                .and_then(Value::as_str)
        })
        .map(str::to_owned);
    (account, email)
}

struct Exchange {
    access: String,
    refresh: String,
    expires_in: i64,
    label: Option<String>,
    auth_state: Option<Value>,
    client_secret: Option<String>,
}

fn parse_token_payload(
    payload: &Value,
    refresh_fallback: Option<&str>,
) -> Option<(String, String, i64)> {
    let access = payload
        .get("access_token")
        .and_then(Value::as_str)?
        .to_owned();
    let refresh = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| refresh_fallback.map(str::to_owned))?;
    let expires = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .unwrap_or(3600);
    Some((access, refresh, expires))
}

fn poll_backoff(error: Option<&str>, interval: Option<i64>) -> Option<Value> {
    match error {
        Some("authorization_pending") => Some(json!({
            "status": "pending",
            "retryAfterSeconds": interval.filter(|value| *value > 0).unwrap_or(5),
        })),
        Some("slow_down") => Some(json!({
            "status": "slow_down",
            "retryAfterSeconds": interval.filter(|value| *value > 0).unwrap_or(10),
        })),
        _ => None,
    }
}

#[allow(clippy::result_large_err)]
async fn persist_account(
    state: &ConsoleState,
    tenant: &str,
    provider_id: &str,
    label_hint: &str,
    exchange: Exchange,
) -> Result<String, Response> {
    let label = exchange
        .label
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            if label_hint.trim().is_empty() {
                format!("{provider_id} account")
            } else {
                label_hint.to_owned()
            }
        });
    let identity = label.trim().to_owned();
    let fingerprint = keyla_security::hash_secret(if identity.is_empty() {
        &exchange.refresh
    } else {
        &identity
    })
    .map_err(|error| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("hash failed: {error}"),
        )
    })?;
    let access_cipher =
        keyla_security::encrypt_credential(exchange.access.as_bytes()).map_err(|error| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("encrypt failed: {error}"),
            )
        })?;
    let refresh_cipher =
        keyla_security::encrypt_credential(exchange.refresh.as_bytes()).map_err(|error| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("encrypt failed: {error}"),
            )
        })?;
    let client_secret_cipher = match exchange.client_secret.as_deref() {
        Some(secret) => Some(
            keyla_security::encrypt_credential(secret.as_bytes()).map_err(|error| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("encrypt failed: {error}"),
                )
            })?,
        ),
        None => None,
    };
    let expires_at = Utc::now() + chrono::Duration::seconds(exchange.expires_in.max(1));
    let mut transaction = state.pool.begin().await.map_err(|error| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("transaction failed: {error}"),
        )
    })?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id::text FROM provider_accounts
         WHERE provider_id = $1 AND tenant_id = $2::uuid AND credential_fingerprint = $3
         LIMIT 1",
    )
    .bind(provider_id)
    .bind(tenant)
    .bind(&fingerprint)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("account lookup failed: {error}"),
        )
    })?;
    let account_id = match existing {
        Some(id) => {
            sqlx::query(
                "UPDATE provider_accounts SET credential_ciphertext = $2, credential_kind = 'oauth',
                    status = 'active', consecutive_failures = 0, cooldown_until = NULL,
                    model_cooldowns = '{}'::jsonb, last_error = NULL, last_error_category = NULL,
                    last_error_at = NULL, last_recovered_at = NULL, auth_state = $3::jsonb
                 WHERE id = $1::uuid",
            )
            .bind(&id)
            .bind(&access_cipher)
            .bind(&exchange.auth_state)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("account update failed: {error}"),
                )
            })?;
            sqlx::query(
                "UPDATE provider_oauth_states SET refresh_ciphertext = $2, expires_at = $3,
                    client_secret_ciphertext = COALESCE($4, client_secret_ciphertext)
                 WHERE provider_account_id = $1::uuid",
            )
            .bind(&id)
            .bind(&refresh_cipher)
            .bind(expires_at)
            .bind(&client_secret_cipher)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("oauth state update failed: {error}"),
                )
            })?;
            id
        }
        None => {
            let row = sqlx::query(
                "INSERT INTO provider_accounts
                    (provider_id, tenant_id, label, credential_ciphertext, credential_fingerprint,
                     credential_kind, auth_state, status, sort_index)
                 VALUES ($1, $2::uuid, $3, $4, $5, 'oauth', $6::jsonb, 'active',
                    (SELECT coalesce(max(sort_index) + 1, 0) FROM provider_accounts
                     WHERE provider_id = $1 AND tenant_id = $2::uuid))
                 RETURNING id::text AS id",
            )
            .bind(provider_id)
            .bind(tenant)
            .bind(&label)
            .bind(&access_cipher)
            .bind(&fingerprint)
            .bind(&exchange.auth_state)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("account insert failed: {error}"),
                )
            })?;
            let id: String = row.get("id");
            sqlx::query(
                "INSERT INTO provider_oauth_states
                    (provider_account_id, refresh_ciphertext, client_secret_ciphertext, expires_at)
                 VALUES ($1::uuid, $2, $3, $4)",
            )
            .bind(&id)
            .bind(&refresh_cipher)
            .bind(&client_secret_cipher)
            .bind(expires_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("oauth state insert failed: {error}"),
                )
            })?;
            id
        }
    };
    transaction.commit().await.map_err(|error| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("commit failed: {error}"),
        )
    })?;
    state.snapshots.invalidate();
    Ok(account_id)
}

fn supports_device(provider_id: &str) -> bool {
    matches!(
        provider_id,
        "codex"
            | "xai"
            | "grok"
            | "github"
            | "kimi"
            | "cline"
            | "muse"
            | "kilo"
            | "qoder"
            | "kiro"
            | "cb"
            | "cbcn"
            | "workbuddy"
    )
}

async fn start_codex(client: &reqwest::Client) -> Result<Value, String> {
    let response = client
        .post(CODEX_DEVICE_USERCODE)
        .json(&json!({"client_id": CODEX_CLIENT_ID}))
        .send()
        .await
        .map_err(|error| format!("Codex device authorization failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Codex device authorization failed ({})",
            response.status().as_u16()
        ));
    }
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("Codex device authorization returned invalid JSON: {error}"))?;
    let device_auth_id = payload
        .get("device_auth_id")
        .and_then(Value::as_str)
        .ok_or("Codex device authorization omitted device_auth_id")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("Codex device authorization omitted user_code")?;
    let interval = payload.get("interval").and_then(Value::as_i64).unwrap_or(5);
    Ok(json!({
        "verificationUri": "https://auth.openai.com/codex/device",
        "userCode": user_code,
        "deviceAuthId": device_auth_id,
        "intervalSeconds": interval,
        "expiresInSeconds": 900,
    }))
}

async fn poll_codex(
    client: &reqwest::Client,
    device_id: &str,
    user_code: &str,
) -> Result<Value, String> {
    let response = client
        .post(CODEX_DEVICE_TOKEN)
        .json(&json!({"device_auth_id": device_id, "user_code": user_code}))
        .send()
        .await
        .map_err(|error| format!("Codex device polling failed: {error}"))?;
    if response.status() == reqwest::StatusCode::FORBIDDEN
        || response.status() == reqwest::StatusCode::NOT_FOUND
    {
        return Ok(json!({"status": "pending"}));
    }
    if !response.status().is_success() {
        return Err(format!(
            "Codex device polling failed ({})",
            response.status().as_u16()
        ));
    }
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("Codex device polling returned invalid JSON: {error}"))?;
    let Some(code) = payload.get("authorization_code").and_then(Value::as_str) else {
        return Ok(json!({"status": "pending"}));
    };
    let verifier = payload
        .get("code_verifier")
        .and_then(Value::as_str)
        .ok_or("Codex device approval omitted code_verifier")?;
    let exchanged = client
        .post(CODEX_TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .form(&[
            ("client_id", CODEX_CLIENT_ID),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", CODEX_REDIRECT_URI),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(|error| format!("Codex token exchange failed: {error}"))?;
    if !exchanged.status().is_success() {
        return Err(format!(
            "Codex token exchange failed ({})",
            exchanged.status().as_u16()
        ));
    }
    let token: Value = exchanged
        .json()
        .await
        .map_err(|error| format!("Codex token exchange returned invalid JSON: {error}"))?;
    let access = token
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or("Codex token response omitted access_token")?;
    let refresh = token
        .get("refresh_token")
        .and_then(Value::as_str)
        .ok_or("Codex token response omitted refresh_token")?;
    let expires = token
        .get("expires_in")
        .and_then(Value::as_i64)
        .unwrap_or(3600);
    let (account_id, email) = codex_profile(access, token.get("id_token").and_then(Value::as_str));
    let auth_state = account_id.map(|account| json!({"chatgptAccountId": account}));
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": access,
            "refresh": refresh,
            "expires_in": expires,
            "label": email,
            "auth_state": auth_state,
        }
    }))
}

async fn start_xai(client: &reqwest::Client) -> Result<Value, String> {
    let response = client
        .post(XAI_DEVICE_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .form(&[("client_id", XAI_CLIENT_ID), ("scope", XAI_SCOPE)])
        .send()
        .await
        .map_err(|error| format!("xAI device authorization failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("xAI device authorization returned invalid JSON: {error}"))?;
    let device_code = payload
        .get("device_code")
        .and_then(Value::as_str)
        .ok_or("xAI device response omitted device_code")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("xAI device response omitted user_code")?;
    let uri = payload
        .get("verification_uri_complete")
        .or_else(|| payload.get("verification_uri"))
        .and_then(Value::as_str)
        .ok_or("xAI device response omitted verification URI")?;
    Ok(json!({
        "verificationUri": uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": payload.get("interval").and_then(Value::as_i64).unwrap_or(5),
        "expiresInSeconds": payload.get("expires_in").and_then(Value::as_i64).unwrap_or(900),
    }))
}

async fn poll_xai(client: &reqwest::Client, device_id: &str) -> Result<Value, String> {
    let response = client
        .post(XAI_TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_id),
            ("client_id", XAI_CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|error| format!("xAI token polling failed: {error}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("xAI token polling read failed: {error}"))?;
    let payload: Value = serde_json::from_str(&text)
        .map_err(|_| "xAI token endpoint returned invalid JSON".to_owned())?;
    let error = payload.get("error").and_then(Value::as_str);
    if let Some(verdict) = poll_backoff(error, payload.get("interval").and_then(Value::as_i64)) {
        return Ok(verdict);
    }
    if !status.is_success() {
        return Err(payload
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or("xAI token polling failed")
            .to_owned());
    }
    let (access, refresh, expires) = parse_token_payload(&payload, None)
        .ok_or("xAI token response omitted access/refresh token")?;
    let mut label = None;
    let mut auth_state = None;
    if let Ok(info) = client
        .get(XAI_USERINFO_URL)
        .bearer_auth(&access)
        .send()
        .await
    {
        if let Ok(info) = info.json::<Value>().await {
            label = info
                .get("email")
                .or_else(|| info.get("name"))
                .or_else(|| info.get("sub"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            auth_state = info
                .get("sub")
                .and_then(Value::as_str)
                .map(|sub| json!({"sub": sub}));
        }
    }
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": access,
            "refresh": refresh,
            "expires_in": expires,
            "label": label,
            "auth_state": auth_state,
        }
    }))
}

fn kimi_headers(device_id: &str) -> Vec<(&'static str, String)> {
    vec![
        ("accept", "application/json".to_owned()),
        (
            "content-type",
            "application/x-www-form-urlencoded".to_owned(),
        ),
        ("user-agent", "KimiCLI/1.0.0".to_owned()),
        ("X-Msh-Platform", "kimi_cli".to_owned()),
        ("X-Msh-Version", "1.0.0".to_owned()),
        ("X-Msh-Device-Name", "keyla".to_owned()),
        ("X-Msh-Device-Model", "keyla".to_owned()),
        ("X-Msh-Os-Version", "unknown".to_owned()),
        ("X-Msh-Device-Id", device_id.to_owned()),
    ]
}

async fn start_kimi(client: &reqwest::Client) -> Result<Value, String> {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let device_id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut request = client
        .post(format!("{KIMI_OAUTH_HOST}/api/oauth/device_authorization"))
        .form(&[("client_id", KIMI_CLIENT_ID)]);
    for (name, value) in kimi_headers(&device_id) {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("Kimi device authorization failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("Kimi device authorization returned invalid JSON: {error}"))?;
    let device_code = payload
        .get("device_code")
        .and_then(Value::as_str)
        .ok_or("Kimi device response omitted device_code")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("Kimi device response omitted user_code")?;
    let uri = payload
        .get("verification_uri_complete")
        .or_else(|| payload.get("verification_uri"))
        .and_then(Value::as_str)
        .ok_or("Kimi device response omitted verification URI")?;
    Ok(json!({
        "verificationUri": uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": payload.get("interval").and_then(Value::as_i64).unwrap_or(5),
        "expiresInSeconds": payload.get("expires_in").and_then(Value::as_i64).unwrap_or(900),
        "providerState": device_id,
    }))
}

async fn poll_kimi(
    client: &reqwest::Client,
    device_id: &str,
    provider_state: &str,
) -> Result<Value, String> {
    let mut request = client
        .post(format!("{KIMI_OAUTH_HOST}/api/oauth/token"))
        .form(&[
            ("client_id", KIMI_CLIENT_ID),
            ("device_code", device_id),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ]);
    for (name, value) in kimi_headers(provider_state) {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("Kimi device polling failed: {error}"))?;
    let status = response.status();
    let payload: Value = response
        .json()
        .await
        .map_err(|_| "Kimi token endpoint returned invalid JSON".to_owned())?;
    let error = payload.get("error").and_then(Value::as_str);
    if let Some(verdict) = poll_backoff(error, payload.get("interval").and_then(Value::as_i64)) {
        return Ok(verdict);
    }
    if !status.is_success() {
        return Err(payload
            .get("error_description")
            .and_then(Value::as_str)
            .or(error)
            .unwrap_or("Kimi device polling failed")
            .to_owned());
    }
    let (access, refresh, expires) = parse_token_payload(&payload, None)
        .ok_or("Kimi token response omitted access/refresh token")?;
    let label = payload
        .get("user_id")
        .or_else(|| payload.get("sub"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": json!({"accessToken": access, "deviceId": provider_state}).to_string(),
            "refresh": json!({"refreshToken": refresh, "deviceId": provider_state}).to_string(),
            "expires_in": expires,
            "label": label,
            "auth_state": null,
        }
    }))
}

fn nested_payload(payload: &Value) -> &Value {
    payload.get("data").unwrap_or(payload)
}

async fn start_cline(client: &reqwest::Client) -> Result<Value, String> {
    let response = client
        .post("https://api.workos.com/user_management/authorize/device")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .form(&[("client_id", CLINE_CLIENT_ID)])
        .send()
        .await
        .map_err(|error| format!("Cline device authorization failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("Cline device authorization returned invalid JSON: {error}"))?;
    let device_code = payload
        .get("device_code")
        .and_then(Value::as_str)
        .ok_or("Cline device response omitted device_code")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("Cline device response omitted user_code")?;
    let uri = payload
        .get("verification_uri_complete")
        .or_else(|| payload.get("verification_uri"))
        .and_then(Value::as_str)
        .ok_or("Cline device response omitted verification URI")?;
    Ok(json!({
        "verificationUri": uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": payload.get("interval").and_then(Value::as_i64).unwrap_or(5),
        "expiresInSeconds": payload.get("expires_in").and_then(Value::as_i64).unwrap_or(300),
    }))
}

async fn poll_cline(client: &reqwest::Client, device_id: &str) -> Result<Value, String> {
    let response = client
        .post("https://api.workos.com/user_management/authenticate")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_id),
            ("client_id", CLINE_CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|error| format!("Cline device polling failed: {error}"))?;
    let status = response.status();
    let payload: Value = response
        .json()
        .await
        .map_err(|_| "Cline device polling returned invalid JSON".to_owned())?;
    let root = nested_payload(&payload);
    let error = root.get("error").and_then(Value::as_str);
    if let Some(verdict) = poll_backoff(error, root.get("interval").and_then(Value::as_i64)) {
        return Ok(verdict);
    }
    if !status.is_success() {
        return Ok(json!({
            "status": "failed",
            "reason": root
                .get("error_description")
                .and_then(Value::as_str)
                .or(error)
                .unwrap_or("Cline device polling failed"),
        }));
    }
    let access = root
        .get("access_token")
        .or_else(|| root.get("accessToken"))
        .and_then(Value::as_str)
        .ok_or("Cline token response omitted access token")?;
    let refresh = root
        .get("refresh_token")
        .or_else(|| root.get("refreshToken"))
        .and_then(Value::as_str)
        .ok_or("Cline token response omitted refresh token")?;
    // Register with Cline's own API; it returns the tokens the chat wire uses.
    let registered = client
        .post("https://api.cline.bot/api/v1/auth/register")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .json(&json!({"accessToken": access, "refreshToken": refresh}))
        .send()
        .await
        .map_err(|error| format!("Cline token registration failed: {error}"))?;
    if !registered.status().is_success() {
        return Err(format!(
            "Cline token registration failed ({})",
            registered.status().as_u16()
        ));
    }
    let registered: Value = registered
        .json()
        .await
        .map_err(|error| format!("Cline token registration returned invalid JSON: {error}"))?;
    let root = nested_payload(&registered);
    let access = root
        .get("access_token")
        .or_else(|| root.get("accessToken"))
        .or_else(|| root.get("token"))
        .and_then(Value::as_str)
        .ok_or("Cline registration response omitted access token")?;
    let refresh = root
        .get("refresh_token")
        .or_else(|| root.get("refreshToken"))
        .and_then(Value::as_str)
        .unwrap_or(refresh);
    let expires = root
        .get("expires_in")
        .or_else(|| root.get("expiresIn"))
        .and_then(Value::as_i64)
        .unwrap_or(3600);
    let label = root
        .get("email")
        .or_else(|| root.get("userInfo").and_then(|info| info.get("email")))
        .or_else(|| root.get("user").and_then(|user| user.get("email")))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": access,
            "refresh": refresh,
            "expires_in": expires,
            "label": label,
            "auth_state": null,
        }
    }))
}

const GROK_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write";

async fn start_grok(client: &reqwest::Client) -> Result<Value, String> {
    let response = client
        .post(XAI_DEVICE_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("user-agent", "grok-cli/1.0.0")
        .header("x-grok-client-version", "1.0.0")
        .header("x-grok-client-surface", "ui")
        .form(&[
            ("client_id", XAI_CLIENT_ID),
            ("scope", GROK_SCOPE),
            ("referrer", "grok-build"),
        ])
        .send()
        .await
        .map_err(|error| format!("grok device authorization failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("grok device authorization returned invalid JSON: {error}"))?;
    let device_code = payload
        .get("device_code")
        .and_then(Value::as_str)
        .ok_or("grok device response omitted device_code")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("grok device response omitted user_code")?;
    let uri = payload
        .get("verification_uri_complete")
        .or_else(|| payload.get("verification_uri"))
        .and_then(Value::as_str)
        .ok_or("grok device response omitted verification URI")?;
    Ok(json!({
        "verificationUri": uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": payload.get("interval").and_then(Value::as_i64).unwrap_or(5),
        "expiresInSeconds": payload.get("expires_in").and_then(Value::as_i64).unwrap_or(900),
    }))
}

async fn poll_grok(client: &reqwest::Client, device_id: &str) -> Result<Value, String> {
    let response = client
        .post(XAI_TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("user-agent", "grok-cli/1.0.0")
        .header("x-grok-client-version", "1.0.0")
        .header("x-grok-client-surface", "ui")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_id),
            ("client_id", XAI_CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|error| format!("grok device polling failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|_| "grok token endpoint returned invalid JSON".to_owned())?;
    let error = payload.get("error").and_then(Value::as_str);
    if let Some(verdict) = poll_backoff(error, payload.get("interval").and_then(Value::as_i64)) {
        return Ok(verdict);
    }
    if payload
        .get("access_token")
        .and_then(Value::as_str)
        .is_none()
    {
        return Ok(json!({
            "status": "failed",
            "reason": payload.get("error_description").and_then(Value::as_str).or(error).unwrap_or("grok token response omitted access_token"),
        }));
    }
    let (access, refresh, expires) = parse_token_payload(&payload, None)
        .ok_or("grok token response omitted access/refresh token")?;
    let mut label = None;
    let mut auth_state = None;
    if let Ok(info) = client
        .get("https://cli-chat-proxy.grok.com/v1/user")
        .bearer_auth(&access)
        .header("accept", "application/json")
        .header("user-agent", "grok-cli/1.0.0")
        .header("x-xai-token-auth", "xai-grok-cli")
        .header("x-grok-client-version", "1.0.0")
        .send()
        .await
    {
        if let Ok(info) = info.json::<Value>().await {
            let first = info.get("firstName").and_then(Value::as_str).unwrap_or("");
            let last = info.get("lastName").and_then(Value::as_str).unwrap_or("");
            let name = format!("{first} {last}").trim().to_owned();
            label = Some(name)
                .filter(|value| !value.is_empty())
                .or_else(|| info.get("email").and_then(Value::as_str).map(str::to_owned))
                .or_else(|| {
                    info.get("userId")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .or_else(|| {
                    info.get("principalId")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
            let mut state = Map::new();
            for key in ["userId", "principalId", "subscriptionTier"] {
                if let Some(value) = info.get(key).and_then(Value::as_str) {
                    state.insert(key.into(), json!(value));
                }
            }
            if let Some(value) = info.get("hasGrokCodeAccess").and_then(Value::as_bool) {
                state.insert("hasGrokCodeAccess".into(), json!(value));
            }
            if !state.is_empty() {
                auth_state = Some(Value::Object(state));
            }
        }
    }
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": access,
            "refresh": refresh,
            "expires_in": expires,
            "label": label,
            "auth_state": auth_state,
        }
    }))
}

async fn start_kilo(client: &reqwest::Client) -> Result<Value, String> {
    let response = client
        .post("https://api.kilo.ai/api/device-auth/codes")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| format!("Kilo Code device authorization failed: {error}"))?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(
            "Kilo Code has too many pending authorization requests; try again later".into(),
        );
    }
    let payload: Value = response.json().await.map_err(|error| {
        format!("Kilo Code device authorization returned invalid JSON: {error}")
    })?;
    let device_code = payload
        .get("code")
        .and_then(Value::as_str)
        .ok_or("Kilo Code device response omitted code")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .unwrap_or(device_code);
    let uri = payload
        .get("verificationUrl")
        .and_then(Value::as_str)
        .ok_or("Kilo Code device response omitted verification URL")?;
    Ok(json!({
        "verificationUri": uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": 3,
        "expiresInSeconds": payload.get("expiresIn").and_then(Value::as_i64).unwrap_or(600),
        "providerState": device_code,
    }))
}

async fn poll_kilo(
    client: &reqwest::Client,
    _device_id: &str,
    poll_key: &str,
) -> Result<Value, String> {
    let response = client
        .get(format!(
            "https://api.kilo.ai/api/device-auth/codes/{}",
            urlencoding_simple(poll_key)
        ))
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| format!("Kilo Code device polling failed: {error}"))?;
    match response.status().as_u16() {
        202 => return Ok(json!({"status": "pending"})),
        403 => {
            return Ok(
                json!({"status": "failed", "reason": "Kilo Code authorization denied by the user"}),
            );
        }
        410 => {
            return Ok(
                json!({"status": "failed", "reason": "Kilo Code device authorization expired"}),
            );
        }
        _ => {}
    }
    if !response.status().is_success() {
        return Ok(json!({
            "status": "failed",
            "reason": format!("Kilo Code device polling failed ({})", response.status().as_u16()),
        }));
    }
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("Kilo Code device polling returned invalid JSON: {error}"))?;
    let Some(token) = payload.get("token").and_then(Value::as_str) else {
        return Ok(json!({"status": "pending"}));
    };
    if payload.get("status").and_then(Value::as_str) != Some("approved") {
        return Ok(json!({"status": "pending"}));
    }
    let mut org_id = None;
    if let Ok(profile) = client
        .get("https://api.kilo.ai/api/profile")
        .bearer_auth(token)
        .header("accept", "application/json")
        .send()
        .await
    {
        if let Ok(profile) = profile.json::<Value>().await {
            org_id = profile
                .get("organizations")
                .and_then(Value::as_array)
                .and_then(|orgs| orgs.first())
                .and_then(|org| org.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
    }
    let label = payload
        .get("userEmail")
        .or_else(|| payload.get("email"))
        .or_else(|| payload.get("user").and_then(|user| user.get("email")))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut envelope = Map::new();
    envelope.insert("accessToken".into(), json!(token));
    if let Some(org_id) = &org_id {
        envelope.insert("orgId".into(), json!(org_id));
    }
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": Value::Object(envelope).to_string(),
            "refresh": token,
            "expires_in": 31_536_000,
            "label": label,
            "auth_state": null,
        }
    }))
}

fn urlencoding_simple(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

async fn start_muse(client: &reqwest::Client) -> Result<Value, String> {
    let response = client
        .post("https://auth.meta.com/oidc/device/authorization/")
        .header("user-agent", "keyla/0.1")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("x-api-version", "1.0.0")
        .form(&[("client_id", MUSE_CLIENT_ID)])
        .send()
        .await
        .map_err(|error| format!("Muse device authorization failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("Muse device authorization returned invalid JSON: {error}"))?;
    let device_code = payload
        .get("device_code")
        .and_then(Value::as_str)
        .ok_or("Muse device response omitted device_code")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("Muse device response omitted user_code")?;
    let uri = payload
        .get("verification_uri_complete")
        .or_else(|| payload.get("verification_uri"))
        .and_then(Value::as_str)
        .ok_or("Muse device response omitted verification URI")?;
    Ok(json!({
        "verificationUri": uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": payload.get("interval").and_then(Value::as_i64).unwrap_or(5),
        "expiresInSeconds": payload.get("expires_in").and_then(Value::as_i64).unwrap_or(900),
    }))
}

async fn poll_muse(client: &reqwest::Client, device_id: &str) -> Result<Value, String> {
    let response = client
        .post("https://auth.meta.com/oidc/device/token/")
        .header("user-agent", "keyla/0.1")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("x-api-version", "1.0.0")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_id),
            ("client_id", MUSE_CLIENT_ID),
        ])
        .send()
        .await
        .map_err(|error| format!("Muse device polling failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|_| "Muse token endpoint returned invalid JSON".to_owned())?;
    let error = payload.get("error").and_then(Value::as_str);
    if let Some(verdict) = poll_backoff(error, payload.get("interval").and_then(Value::as_i64)) {
        return Ok(verdict);
    }
    if payload
        .get("access_token")
        .and_then(Value::as_str)
        .is_none()
    {
        return Ok(json!({
            "status": "failed",
            "reason": payload
                .get("error_description")
                .and_then(Value::as_str)
                .or(error)
                .unwrap_or("Muse token response omitted access_token"),
        }));
    }
    let Some(oauth_access) = payload.get("access_token").and_then(Value::as_str) else {
        return Ok(json!({"status": "failed", "reason": "missing access token"}));
    };
    let minted = client
        .post("https://api.meta.ai/muse-code/key")
        .header("user-agent", "keyla/0.1")
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .header("x-api-version", "1.0.0")
        .bearer_auth(oauth_access)
        .json(&json!({"onboard": true}))
        .send()
        .await;
    let minted = match minted {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            return Ok(json!({
                "status": "failed",
                "reason": format!("Muse Code key exchange failed ({})", response.status().as_u16()),
            }));
        }
        Err(error) => {
            return Ok(
                json!({"status": "failed", "reason": format!("Muse Code key exchange failed: {error}")}),
            );
        }
    };
    let minted: Value = minted
        .json()
        .await
        .map_err(|error| format!("Muse Code key response was invalid JSON: {error}"))?;
    if minted.get("is_subs_active").and_then(Value::as_bool) == Some(false) {
        return Ok(json!({"status": "failed", "reason": "Muse Code subscription is inactive"}));
    }
    let Some(api_key) = minted.get("api_key").and_then(Value::as_str) else {
        return Ok(
            json!({"status": "failed", "reason": "Muse Code key response is missing api_key"}),
        );
    };
    let label = minted
        .get("user_id")
        .or_else(|| minted.get("user_email"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": json!({"oauthAccessToken": oauth_access, "apiKey": api_key}).to_string(),
            "refresh": oauth_access,
            "expires_in": 31_536_000,
            "label": label,
            "auth_state": null,
        }
    }))
}

async fn start_github(client: &reqwest::Client) -> Result<Value, String> {
    let response = client
        .post(GITHUB_DEVICE_URL)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("user-agent", "GitHubCopilotChat/0.35.0")
        .form(&[("client_id", GITHUB_CLIENT_ID), ("scope", "read:user")])
        .send()
        .await
        .map_err(|error| format!("GitHub device authorization failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("GitHub device authorization returned invalid JSON: {error}"))?;
    let device_code = payload
        .get("device_code")
        .and_then(Value::as_str)
        .ok_or("GitHub device response omitted device_code")?;
    let user_code = payload
        .get("user_code")
        .and_then(Value::as_str)
        .ok_or("GitHub device response omitted user_code")?;
    let uri = payload
        .get("verification_uri")
        .and_then(Value::as_str)
        .ok_or("GitHub device response omitted verification URI")?;
    Ok(json!({
        "verificationUri": uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": payload.get("interval").and_then(Value::as_i64).unwrap_or(5),
        "expiresInSeconds": payload.get("expires_in").and_then(Value::as_i64).unwrap_or(900),
    }))
}

async fn poll_github(client: &reqwest::Client, device_id: &str) -> Result<Value, String> {
    let response = client
        .post(GITHUB_TOKEN_URL)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("user-agent", "GitHubCopilotChat/0.35.0")
        .form(&[
            ("client_id", GITHUB_CLIENT_ID),
            ("device_code", device_id),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .map_err(|error| format!("GitHub device polling failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|_| "GitHub device polling returned invalid JSON".to_owned())?;
    let error = payload.get("error").and_then(Value::as_str);
    if let Some(verdict) = poll_backoff(error, payload.get("interval").and_then(Value::as_i64)) {
        return Ok(verdict);
    }
    let github_token = match payload.get("access_token").and_then(Value::as_str) {
        Some(token) => token.to_owned(),
        None => {
            return Ok(json!({
                "status": "failed",
                "reason": payload
                    .get("error_description")
                    .and_then(Value::as_str)
                    .or(error)
                    .unwrap_or("GitHub device authorization failed"),
            }));
        }
    };
    let minted = client
        .get("https://api.github.com/copilot_internal/v2/token")
        .bearer_auth(&github_token)
        .header("user-agent", "GitHubCopilotChat/0.35.0")
        .header("editor-version", "vscode/1.107.0")
        .header("editor-plugin-version", "copilot-chat/0.35.0")
        .header("copilot-integration-id", "vscode-chat")
        .header("x-github-api-version", "2026-06-01")
        .send()
        .await
        .map_err(|error| format!("GitHub Copilot token mint failed: {error}"))?;
    if !minted.status().is_success() {
        return Err(format!(
            "GitHub Copilot token mint failed ({})",
            minted.status().as_u16()
        ));
    }
    let minted: Value = minted
        .json()
        .await
        .map_err(|error| format!("GitHub Copilot token mint returned invalid JSON: {error}"))?;
    let access = minted
        .get("token")
        .and_then(Value::as_str)
        .ok_or("GitHub Copilot token mint returned no token")?;
    let api_host = access
        .split("proxy-ep=")
        .nth(1)
        .and_then(|tail| tail.split(';').next())
        .map(|host| host.trim().replace("proxy.", "api."))
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| "api.individual.githubcopilot.com".to_owned());
    let expires_at = minted
        .get("expires_at")
        .and_then(Value::as_i64)
        .map(|seconds| seconds - Utc::now().timestamp())
        .unwrap_or(1500)
        .max(60);
    let label = client
        .get("https://api.github.com/user")
        .bearer_auth(&github_token)
        .header("user-agent", "GitHubCopilotChat/0.35.0")
        .send()
        .await
        .ok()
        .filter(|response| response.status().is_success());
    let label = match label {
        Some(response) => response.json::<Value>().await.ok().and_then(|value| {
            value
                .get("login")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }),
        None => None,
    };
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": json!({"access": access, "apiHost": api_host, "github": github_token}).to_string(),
            "refresh": github_token,
            "expires_in": expires_at,
            "label": label,
            "auth_state": Value::Null,
        }
    }))
}

/// `POST /console/api/providers/{providerId}/oauth/device/start`.
pub async fn start_device(
    State(state): State<ConsoleState>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    if !supports_device(&provider_id) {
        return error_response(
            StatusCode::CONFLICT,
            "device_code_not_supported",
            &format!("Provider {provider_id} does not support device-code login"),
        );
    }
    let client = match http_client() {
        Ok(client) => client,
        Err(response) => return response,
    };
    let started = match provider_id.as_str() {
        "codex" => start_codex(&client).await,
        "xai" => start_xai(&client).await,
        "github" => start_github(&client).await,
        "kimi" => start_kimi(&client).await,
        "cline" => start_cline(&client).await,
        "muse" => start_muse(&client).await,
        "grok" => start_grok(&client).await,
        "kilo" => start_kilo(&client).await,
        "qoder" => start_qoder(&client).await,
        "kiro" => {
            match keyla_providers::kiro_oauth::start_kiro_device_auth(
                &client,
                body.get("parameters"),
            )
            .await
            {
                Ok(value) => Ok(value),
                Err(error) => Err(error),
            }
        }
        "cb" | "cbcn" | "workbuddy" => {
            let value = keyla_providers::buddy::oauth_start(&client, &provider_id, None).await;
            if value.get("status").and_then(Value::as_str) == Some("failed") {
                Err(value
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("Buddy device authorization failed")
                    .to_owned())
            } else {
                Ok(value)
            }
        }
        _ => unreachable!(),
    };
    let started = match started {
        Ok(value) => value,
        Err(message) => {
            return error_response(StatusCode::BAD_GATEWAY, "oauth_start_failed", &message);
        }
    };
    let device_id = started
        .get("deviceAuthId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let label = body
        .get("accountLabel")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let expires = started
        .get("expiresInSeconds")
        .and_then(Value::as_i64)
        .unwrap_or(900);
    if let Ok(mut flows) = flows().lock() {
        flows.insert(
            device_id.clone(),
            DeviceFlow {
                provider_id: provider_id.clone(),
                tenant_id: tenant,
                label,
                provider_state: started
                    .get("providerState")
                    .or_else(|| started.get("userCode"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                expires_at_ms: now_ms() + expires * 1000,
            },
        );
    }
    let mut public = started;
    if let Some(object) = public.as_object_mut() {
        object.remove("providerState");
    }
    console_response(StatusCode::OK, public)
}

/// `POST /console/api/providers/{providerId}/oauth/device/poll`.
pub async fn poll_device(
    State(state): State<ConsoleState>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(device_id) = body.get("deviceAuthId").and_then(Value::as_str) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "deviceAuthId is required",
        );
    };
    let flow = flows()
        .lock()
        .ok()
        .and_then(|flows| flows.get(device_id).cloned());
    let Some(flow) = flow else {
        return error_response(
            StatusCode::NOT_FOUND,
            "device_flow_unknown",
            "Unknown or expired device-code flow",
        );
    };
    if flow.provider_id != provider_id || flow.tenant_id != tenant {
        return error_response(
            StatusCode::NOT_FOUND,
            "device_flow_unknown",
            "Unknown or expired device-code flow",
        );
    }
    if flow.expires_at_ms <= now_ms() {
        if let Ok(mut flows) = flows().lock() {
            flows.remove(device_id);
        }
        return console_response(
            StatusCode::OK,
            json!({"status": "failed", "reason": "Device authorization expired"}),
        );
    }
    let client = match http_client() {
        Ok(client) => client,
        Err(response) => return response,
    };
    let polled = match provider_id.as_str() {
        "codex" => {
            poll_codex(
                &client,
                device_id,
                flow.provider_state.as_deref().unwrap_or(""),
            )
            .await
        }
        "xai" => poll_xai(&client, device_id).await,
        "github" => poll_github(&client, device_id).await,
        "kimi" => {
            poll_kimi(
                &client,
                device_id,
                flow.provider_state.as_deref().unwrap_or(""),
            )
            .await
        }
        "cline" => poll_cline(&client, device_id).await,
        "muse" => poll_muse(&client, device_id).await,
        "grok" => poll_grok(&client, device_id).await,
        "kilo" => {
            poll_kilo(
                &client,
                device_id,
                flow.provider_state.as_deref().unwrap_or(device_id),
            )
            .await
        }
        "qoder" => {
            poll_qoder(
                &client,
                device_id,
                flow.provider_state.as_deref().unwrap_or(""),
            )
            .await
        }
        "cb" | "cbcn" | "workbuddy" => {
            let value =
                keyla_providers::buddy::oauth_poll(&client, &provider_id, device_id, None).await;
            if value.get("status").and_then(Value::as_str) != Some("complete") {
                return console_response(StatusCode::OK, value);
            }
            let result = &value["result"];
            let access = result.get("access").and_then(Value::as_str).unwrap_or("");
            let refresh = result
                .get("refresh")
                .and_then(Value::as_str)
                .unwrap_or(access);
            let expires = result
                .get("expiresAt")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| (value.timestamp() - chrono::Utc::now().timestamp()).max(60))
                .unwrap_or(3600);
            Ok(json!({
                "status": "complete",
                "exchange": {
                    "access": access,
                    "refresh": refresh,
                    "expires_in": expires,
                    "label": result.get("accountLabel").cloned().unwrap_or(Value::Null),
                }
            }))
        }
        _ => Err("device flow not supported".to_owned()),
    };
    let polled = match polled {
        Ok(value) => value,
        Err(message) => {
            return console_response(
                StatusCode::OK,
                json!({"status": "failed", "reason": message}),
            );
        }
    };
    if polled.get("status").and_then(Value::as_str) != Some("complete") {
        return console_response(StatusCode::OK, polled);
    }
    let exchange = &polled["exchange"];
    let Some(access) = exchange.get("access").and_then(Value::as_str) else {
        return console_response(
            StatusCode::OK,
            json!({"status": "failed", "reason": "token exchange omitted access"}),
        );
    };
    let Some(refresh) = exchange.get("refresh").and_then(Value::as_str) else {
        return console_response(
            StatusCode::OK,
            json!({"status": "failed", "reason": "token exchange omitted refresh"}),
        );
    };
    let result = Exchange {
        access: access.to_owned(),
        refresh: refresh.to_owned(),
        expires_in: exchange
            .get("expires_in")
            .and_then(Value::as_i64)
            .unwrap_or(3600),
        label: exchange
            .get("label")
            .and_then(Value::as_str)
            .map(str::to_owned),
        auth_state: exchange
            .get("auth_state")
            .filter(|value| !value.is_null())
            .cloned(),
        client_secret: exchange
            .get("client_secret")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    match persist_account(&state, &tenant, &provider_id, &flow.label, result).await {
        Ok(account_id) => {
            if let Ok(mut flows) = flows().lock() {
                flows.remove(device_id);
            }
            console_response(
                StatusCode::OK,
                json!({"status": "complete", "accountId": account_id}),
            )
        }
        Err(response) => response,
    }
}

/// Unsupported OAuth surfaces answer with the typed capability error.
pub async fn capability_unsupported() -> Response {
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        "capability_unsupported",
        "This OAuth login flow is not implemented in the Rust gateway yet",
    )
}

async fn start_qoder(_client: &reqwest::Client) -> Result<Value, String> {
    use base64::Engine as _;
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let nonce = uuid::Uuid::new_v4().to_string();
    let machine_id = uuid::Uuid::new_v4().to_string();
    let query = format!(
        "challenge={challenge}&challenge_method=S256&machine_id={machine_id}&nonce={nonce}"
    );
    Ok(json!({
        "verificationUri": format!("https://qoder.com/device/selectAccounts?{query}"),
        "userCode": "",
        "deviceAuthId": nonce,
        "intervalSeconds": 5,
        "expiresInSeconds": 300,
        "providerState": json!({"verifier": verifier, "machineId": machine_id}).to_string(),
    }))
}

async fn poll_qoder(
    client: &reqwest::Client,
    device_id: &str,
    provider_state: &str,
) -> Result<Value, String> {
    let state: Value = serde_json::from_str(provider_state)
        .map_err(|_| "unknown Qoder device authorization".to_owned())?;
    let verifier = state
        .get("verifier")
        .and_then(Value::as_str)
        .ok_or("unknown Qoder device authorization")?;
    let machine_id = state
        .get("machineId")
        .and_then(Value::as_str)
        .ok_or("unknown Qoder device authorization")?;
    let url = format!(
        "https://openapi.qoder.sh/api/v1/deviceToken/poll?nonce={}&verifier={}&challenge_method=S256",
        percent_encode(device_id),
        percent_encode(verifier)
    );
    let response = client
        .get(url)
        .header("accept", "application/json")
        .header("user-agent", "Go-http-client/2.0")
        .send()
        .await
        .map_err(|error| format!("Qoder device polling failed: {error}"))?;
    if response.status() == reqwest::StatusCode::ACCEPTED
        || response.status() == reqwest::StatusCode::NOT_FOUND
    {
        return Ok(json!({"status": "pending"}));
    }
    let status = response.status();
    let payload: Value = response
        .json()
        .await
        .map_err(|_| "Qoder device polling returned invalid JSON".to_owned())?;
    if !status.is_success() {
        let reason = payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Qoder device polling failed");
        return Ok(json!({"status": "failed", "reason": reason}));
    }
    let access = payload
        .get("token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("Qoder device polling returned no token")?;
    let refresh = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or(access);
    let expires = payload
        .get("expires_at")
        .and_then(Value::as_i64)
        .map(|value| {
            if value > 1_000_000_000_000 {
                value / 1000
            } else {
                value
            }
        })
        .or_else(|| {
            payload
                .get("expires_in")
                .and_then(Value::as_i64)
                .map(|seconds| chrono::Utc::now().timestamp() + seconds)
        })
        .unwrap_or_else(|| chrono::Utc::now().timestamp() + 30 * 24 * 60 * 60);
    let expires_in = (expires - chrono::Utc::now().timestamp()).max(60);
    let mut label = None;
    let mut profile_id = None;
    if let Ok(profile) = client
        .get("https://openapi.qoder.sh/api/v1/userinfo")
        .bearer_auth(access)
        .header("accept", "application/json")
        .header("user-agent", "Go-http-client/2.0")
        .send()
        .await
    {
        if profile.status().is_success() {
            if let Ok(body) = profile.json::<Value>().await {
                label = body
                    .get("name")
                    .or_else(|| body.get("username"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                profile_id = body
                    .get("id")
                    .or_else(|| body.get("userId"))
                    .or_else(|| body.get("user_id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
    }
    let user_id = payload
        .get("user_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or(profile_id)
        .ok_or("Qoder response omitted the account user id")?;
    Ok(json!({
        "status": "complete",
        "exchange": {
            "access": access,
            "refresh": refresh,
            "expires_in": expires_in,
            "label": label,
            "auth_state": {"userId": user_id, "machineId": machine_id},
        }
    }))
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

async fn exchange_refresh(
    client: &reqwest::Client,
    provider_id: &str,
    refresh: &str,
) -> Result<Exchange, String> {
    if provider_id == "mimodesktop" {
        let credentials = keyla_providers::mimodesktop::parse_credential(refresh)
            .map_err(|error| error.message)?;
        keyla_providers::mimodesktop::acquire_session(
            client,
            &credentials,
            "https://mimo-server-sgp.xiaomimimo.com",
        )
        .await
        .map_err(|error| error.message)?;
        let label = credentials
            .user_id
            .as_ref()
            .map(|user| format!("Xiaomi MiMo ({user})"))
            .unwrap_or_else(|| "Xiaomi MiMo Desktop".to_owned());
        return Ok(Exchange {
            access: keyla_providers::mimodesktop::encode_credential(&credentials),
            refresh: credentials.pass_token.clone(),
            expires_in: 30 * 24 * 60 * 60,
            label: Some(label),
            auth_state: None,
            client_secret: None,
        });
    }
    let (token_url, client_id) = match provider_id {
        "codex" => (CODEX_TOKEN_URL, CODEX_CLIENT_ID),
        "claude" => (
            "https://api.anthropic.com/v1/oauth/token",
            "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        ),
        "xai" => (XAI_TOKEN_URL, XAI_CLIENT_ID),
        _ => {
            return Err(format!(
                "Provider {provider_id} does not support refresh-token import"
            ));
        }
    };
    let response = client
        .post(token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
        ])
        .send()
        .await
        .map_err(|error| format!("token refresh failed: {error}"))?;
    let status = response.status();
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("token refresh returned invalid JSON: {error}"))?;
    if !status.is_success() {
        return Err(payload
            .get("error_description")
            .and_then(Value::as_str)
            .or_else(|| payload.get("error").and_then(Value::as_str))
            .unwrap_or("token refresh rejected")
            .to_owned());
    }
    let access = payload
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or("token refresh omitted access_token")?
        .to_owned();
    let refresh = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or(refresh)
        .to_owned();
    let expires_in = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .unwrap_or(3600);
    let mut label = None;
    let mut auth_state = None;
    if provider_id == "codex" {
        let (account_id, email) =
            codex_profile(&access, payload.get("id_token").and_then(Value::as_str));
        label = email;
        auth_state = account_id.map(|account| json!({"chatgptAccountId": account}));
    }
    if provider_id == "xai" {
        if let Ok(info) = client
            .get(XAI_USERINFO_URL)
            .bearer_auth(&access)
            .send()
            .await
        {
            if let Ok(info) = info.json::<Value>().await {
                label = info
                    .get("email")
                    .or_else(|| info.get("name"))
                    .or_else(|| info.get("sub"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                auth_state = info
                    .get("sub")
                    .and_then(Value::as_str)
                    .map(|sub| json!({"sub": sub}));
            }
        }
    }
    Ok(Exchange {
        access,
        refresh,
        expires_in,
        label,
        auth_state,
        client_secret: None,
    })
}

/// `POST /console/api/providers/{providerId}/oauth/import` — validate a
/// pasted refresh token against the provider before storing it.
pub async fn import_credential(
    State(state): State<ConsoleState>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(credential) = body
        .get("credential")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "credential is required",
        );
    };
    let client = match http_client() {
        Ok(client) => client,
        Err(response) => return response,
    };
    let exchange = match exchange_refresh(&client, &provider_id, credential).await {
        Ok(exchange) => exchange,
        Err(message) => {
            return error_response(StatusCode::BAD_GATEWAY, "oauth_import_failed", &message);
        }
    };
    let label = body
        .get("accountLabel")
        .and_then(Value::as_str)
        .unwrap_or("");
    match persist_account(&state, &tenant, &provider_id, label, exchange).await {
        Ok(account_id) => console_response(StatusCode::CREATED, json!({"accountId": account_id})),
        Err(response) => response,
    }
}

// --- Browser PKCE flows -----------------------------------------------------

const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
const CLAUDE_TOKEN_URL: &str = "https://api.anthropic.com/v1/oauth/token";
const CLAUDE_REDIRECT_URI: &str = "http://localhost:54545/callback";
const CLAUDE_SCOPE: &str = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
const CODEX_AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const CODEX_BROWSER_REDIRECT: &str = "http://localhost:1455/auth/callback";
const CODEX_SCOPE: &str =
    "openid profile email offline_access api.connectors.read api.connectors.invoke";

#[derive(Clone)]
struct PendingFlow {
    provider_id: String,
    tenant_id: String,
    label: String,
    verifier: String,
    redirect_uri: String,
    parameters: Option<Value>,
    created_ms: i64,
}

fn pending() -> &'static Mutex<HashMap<String, PendingFlow>> {
    static PENDING: OnceLock<Mutex<HashMap<String, PendingFlow>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buffer);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buffer)
}

fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// `POST /console/api/providers/{providerId}/oauth/authorize`.
pub async fn authorize_browser(
    State(state): State<ConsoleState>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let client = match http_client() {
        Ok(client) => client,
        Err(response) => return response,
    };
    if provider_id == "kiro" {
        let state_token = random_token(32);
        let verifier = random_token(48);
        let challenge = pkce_challenge(&verifier);
        let label = body
            .get("accountLabel")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let mut request = json!({
            "redirectUri": keyla_providers::kiro_oauth::KIRO_SOCIAL_REDIRECT_URI,
            "parameters": body.get("parameters").cloned().unwrap_or_else(|| json!({})),
            "state": state_token,
            "codeChallenge": challenge,
        });
        // prepare registers the Builder ID client and returns updated parameters.
        let prepared =
            match keyla_providers::kiro_oauth::prepare_kiro_authorize(&client, &request).await {
                Ok(value) => value,
                Err(message) => {
                    return error_response(StatusCode::BAD_GATEWAY, "oauth_start_failed", &message);
                }
            };
        request = prepared;
        let redirect_uri = request
            .get("redirectUri")
            .and_then(Value::as_str)
            .unwrap_or(keyla_providers::kiro_oauth::KIRO_SOCIAL_REDIRECT_URI)
            .to_owned();
        let authorize_url = match keyla_providers::kiro_oauth::build_kiro_authorize_url(&request) {
            Ok(value) => value,
            Err(message) => {
                return error_response(StatusCode::BAD_GATEWAY, "oauth_start_failed", &message);
            }
        };
        if let Ok(mut flows) = pending().lock() {
            flows.retain(|_, flow| now_ms() - flow.created_ms < 15 * 60 * 1000);
            flows.insert(
                state_token.clone(),
                PendingFlow {
                    provider_id: provider_id.clone(),
                    tenant_id: tenant,
                    label,
                    verifier,
                    redirect_uri,
                    parameters: request.get("parameters").cloned(),
                    created_ms: now_ms(),
                },
            );
        }
        return console_response(
            StatusCode::OK,
            json!({"authorizeUrl": authorize_url, "state": state_token}),
        );
    }
    let (authorize_url, redirect_uri, scope, extra) = match provider_id.as_str() {
        "claude" => (
            CLAUDE_AUTHORIZE_URL.to_owned(),
            CLAUDE_REDIRECT_URI.to_owned(),
            CLAUDE_SCOPE.to_owned(),
            vec![("code", "true")],
        ),
        "openrouter" => (
            "https://openrouter.ai/auth".to_owned(),
            "http://127.0.0.1:54549/callback".to_owned(),
            String::new(),
            vec![],
        ),
        "codex" => (
            CODEX_AUTHORIZE_URL.to_owned(),
            CODEX_BROWSER_REDIRECT.to_owned(),
            CODEX_SCOPE.to_owned(),
            vec![
                ("originator", "codex_cli_rs"),
                ("id_token_add_organizations", "true"),
                ("codex_cli_simplified_flow", "true"),
            ],
        ),
        "zcode" => (
            "https://chat.z.ai/api/oauth/authorize".to_owned(),
            "zcode://zai-auth/callback".to_owned(),
            String::new(),
            vec![],
        ),
        "mimostudio" => {
            let callback =
                keyla_config::oauth_callback_url(&keyla_config::ProcessEnv, "mimostudio")
                    .unwrap_or_else(|_| {
                        "http://127.0.0.1:12800/console/api/providers/mimostudio/oauth/callback"
                            .to_owned()
                    });
            (callback.clone(), callback, String::new(), vec![])
        }
        "devin" => (
            "https://app.devin.ai/auth/cli/continue".to_owned(),
            "http://127.0.0.1:59653/callback".to_owned(),
            String::new(),
            vec![("prompt", "select_account")],
        ),
        "antigravity" => (
            keyla_providers::antigravity_oauth::ANTIGRAVITY_AUTHORIZE_URL.to_owned(),
            keyla_providers::antigravity_oauth::ANTIGRAVITY_REDIRECT_URI.to_owned(),
            keyla_providers::antigravity_oauth::ANTIGRAVITY_SCOPES.to_owned(),
            vec![("access_type", "offline"), ("prompt", "consent")],
        ),
        "mimodesktop" => {
            let callback =
                keyla_config::oauth_callback_url(&keyla_config::ProcessEnv, "mimodesktop")
                    .unwrap_or_else(|_| {
                        "http://127.0.0.1:12800/console/api/providers/mimodesktop/oauth/callback"
                            .to_owned()
                    });
            (callback.clone(), callback, String::new(), vec![])
        }
        _ => {
            return error_response(
                StatusCode::CONFLICT,
                "browser_code_not_supported",
                &format!("Provider {provider_id} does not support browser-code login"),
            );
        }
    };
    let client_id = if provider_id == "claude" {
        CLAUDE_CLIENT_ID
    } else if provider_id == "openrouter" {
        ""
    } else if provider_id == "zcode" {
        "client_P8X5CMWmlaRO9gyO-KSqtg"
    } else if provider_id == "mimodesktop" {
        "mimocode-desktop"
    } else if provider_id == "antigravity" {
        keyla_providers::antigravity_oauth::antigravity_client_id()
    } else if provider_id == "devin" {
        ""
    } else {
        CODEX_CLIENT_ID
    };
    let state_token = random_token(32);
    let verifier = random_token(48);
    let challenge = pkce_challenge(&verifier);
    let label = body
        .get("accountLabel")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if let Ok(mut flows) = pending().lock() {
        flows.retain(|_, flow| now_ms() - flow.created_ms < 15 * 60 * 1000);
        flows.insert(
            state_token.clone(),
            PendingFlow {
                provider_id: provider_id.clone(),
                tenant_id: tenant,
                label,
                verifier,
                redirect_uri: redirect_uri.clone(),
                parameters: None,
                created_ms: now_ms(),
            },
        );
    }
    let mut url = url::Url::parse(&authorize_url).expect("oauth authorize url");
    if provider_id == "openrouter" {
        let mut query = url.query_pairs_mut();
        query.append_pair("callback_url", &redirect_uri);
        query.append_pair("code_challenge", &challenge);
        query.append_pair("code_challenge_method", "S256");
    } else if provider_id == "zcode" {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client_id);
        query.append_pair("redirect_uri", &redirect_uri);
        query.append_pair("state", &state_token);
    } else if provider_id == "devin" {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("code_challenge", &challenge);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("state", &state_token);
        query.append_pair("redirect_uri", &redirect_uri);
        query.append_pair("prompt", "select_account");
    } else if provider_id == "mimodesktop" {
        let mut query = url.query_pairs_mut();
        query.append_pair("state", &state_token);
        query.append_pair("code", "local-desktop-import");
    } else if provider_id == "mimostudio" {
        let mut query = url.query_pairs_mut();
        query.append_pair("state", &state_token);
        query.append_pair("code", "studio-manual-paste");
    } else {
        let mut query = url.query_pairs_mut();
        query.append_pair("client_id", client_id);
        query.append_pair("redirect_uri", &redirect_uri);
        query.append_pair("response_type", "code");
        query.append_pair("scope", &scope);
        query.append_pair("state", &state_token);
        query.append_pair("code_challenge", &challenge);
        query.append_pair("code_challenge_method", "S256");
        for (name, value) in extra {
            query.append_pair(name, value);
        }
    }
    console_response(
        StatusCode::OK,
        json!({"authorizeUrl": url.to_string(), "state": state_token}),
    )
}

fn zcode_unwrap(value: Value, operation: &str) -> Result<Value, String> {
    let Some(root) = value.as_object() else {
        return Ok(value);
    };
    if root.contains_key("code") || root.contains_key("success") {
        let success = root.get("success").and_then(Value::as_bool);
        let code = root.get("code");
        let ok = code.is_none()
            || matches!(code, Some(Value::Number(value)) if value.as_i64() == Some(0) || value.as_i64() == Some(200))
            || matches!(code, Some(Value::String(value)) if value == "0" || value == "200");
        if success == Some(false) || !ok {
            let message = root.get("msg").and_then(Value::as_str).unwrap_or(operation);
            return Err(format!("Z.AI {message}"));
        }
    }
    Ok(root.get("data").cloned().unwrap_or(value))
}

async fn exchange_zcode(
    client: &reqwest::Client,
    code: &str,
    redirect_uri: &str,
    state: &str,
) -> Result<Exchange, String> {
    // The zcode:// callback is often unreachable without the desktop app. A
    // chat.z.ai session JWT is accepted by the business login endpoint, which
    // mints the durable coding key; the JWT itself is not a coding credential.
    if let Some(claims) = jwt_payload(code).filter(Value::is_object) {
        let durable = mint_zcode_key(client, code).await?;
        let label = claims
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_owned);
        return Ok(Exchange {
            access: durable.clone(),
            refresh: durable,
            expires_in: 365 * 24 * 60 * 60,
            label,
            auth_state: None,
            client_secret: None,
        });
    }
    let response = client
        .post("https://zcode.z.ai/api/v1/oauth/token")
        .json(&json!({
            "provider": "zai",
            "code": code,
            "redirect_uri": redirect_uri,
            "state": state,
        }))
        .send()
        .await
        .map_err(|error| format!("Z.AI token exchange failed: {error}"))?;
    let status = response.status();
    let payload: Value = response
        .json()
        .await
        .map_err(|_| "Z.AI token exchange returned invalid JSON".to_owned())?;
    if !status.is_success() {
        return Err(format!(
            "Z.AI token exchange failed (HTTP {})",
            status.as_u16()
        ));
    }
    let payload = zcode_unwrap(payload, "token exchange failed")?;
    let oauth_access = payload
        .get("zai")
        .and_then(|zai| zai.get("access_token"))
        .and_then(Value::as_str)
        .ok_or("Z.AI token exchange returned no access token")?;
    let label = payload
        .get("user")
        .and_then(|user| user.get("email"))
        .and_then(Value::as_str)
        .or_else(|| payload.get("email").and_then(Value::as_str))
        .map(str::to_owned);
    let durable = mint_zcode_key(client, oauth_access).await?;
    Ok(Exchange {
        access: durable.clone(),
        refresh: durable,
        expires_in: 365 * 24 * 60 * 60,
        label,
        auth_state: None,
        client_secret: None,
    })
}

pub(crate) async fn mint_zcode_key(
    client: &reqwest::Client,
    oauth_access: &str,
) -> Result<String, String> {
    let login: Value = client
        .post("https://api.z.ai/api/auth/z/login")
        .json(&json!({"token": oauth_access}))
        .send()
        .await
        .map_err(|error| format!("Z.AI business login failed: {error}"))?
        .json()
        .await
        .map_err(|_| "Z.AI business login returned invalid JSON".to_owned())?;
    let login = zcode_unwrap(login, "business login failed")?;
    let business = login
        .get("access_token")
        .or_else(|| login.get("accessToken"))
        .and_then(Value::as_str)
        .ok_or("Z.AI business login returned no access token")?;
    let customer: Value = client
        .get("https://api.z.ai/api/biz/customer/getCustomerInfo")
        .bearer_auth(business)
        .send()
        .await
        .map_err(|error| format!("Z.AI customer lookup failed: {error}"))?
        .json()
        .await
        .map_err(|_| "Z.AI customer lookup returned invalid JSON".to_owned())?;
    let customer = zcode_unwrap(customer, "customer lookup failed")?;
    let organizations = customer
        .get("organizations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let organization = organizations
        .iter()
        .find(|entry| entry.get("isDefault").and_then(Value::as_bool) == Some(true))
        .or_else(|| organizations.first())
        .ok_or("Z.AI key provisioning found no organization on the account")?;
    let projects = organization
        .get("projects")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let project = projects
        .iter()
        .find(|entry| entry.get("isDefault").and_then(Value::as_bool) == Some(true))
        .or_else(|| projects.first())
        .ok_or("Z.AI key provisioning found no project on the account")?;
    let organization_id = organization
        .get("organizationId")
        .and_then(Value::as_str)
        .ok_or("Z.AI organization omitted its id")?;
    let project_id = project
        .get("projectId")
        .and_then(Value::as_str)
        .ok_or("Z.AI project omitted its id")?;
    let keys_url = format!(
        "https://api.z.ai/api/biz/v1/organization/{}/projects/{}/api_keys",
        percent_encode(organization_id),
        percent_encode(project_id)
    );
    let listed: Value = client
        .get(&keys_url)
        .bearer_auth(business)
        .send()
        .await
        .map_err(|error| format!("Z.AI api key list failed: {error}"))?
        .json()
        .await
        .map_err(|_| "Z.AI api key list returned invalid JSON".to_owned())?;
    let listed = zcode_unwrap(listed, "api key list failed")?;
    let existing = listed
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("name").and_then(Value::as_str) == Some("keyla"))
        })
        .cloned();
    let created = match existing {
        Some(created) => created,
        None => {
            let created: Value = client
                .post(&keys_url)
                .bearer_auth(business)
                .json(&json!({"name": "keyla"}))
                .send()
                .await
                .map_err(|error| format!("Z.AI api key create failed: {error}"))?
                .json()
                .await
                .map_err(|_| "Z.AI api key create returned invalid JSON".to_owned())?;
            zcode_unwrap(created, "api key create failed")?
        }
    };
    let api_key = created
        .get("apiKey")
        .and_then(Value::as_str)
        .ok_or("Z.AI key provisioning returned no apiKey")?;
    let copied: Value = client
        .get(format!("{keys_url}/copy/{}", percent_encode(api_key)))
        .bearer_auth(business)
        .send()
        .await
        .map_err(|error| format!("Z.AI api key copy failed: {error}"))?
        .json()
        .await
        .map_err(|_| "Z.AI api key copy returned invalid JSON".to_owned())?;
    let copied = zcode_unwrap(copied, "api key copy failed")?;
    let secret = copied
        .get("secretKey")
        .and_then(Value::as_str)
        .ok_or("Z.AI key provisioning returned no secretKey")?;
    Ok(format!("{api_key}.{secret}"))
}

fn callback_page(success: bool, message: &str, wants_json: bool) -> Response {
    if wants_json {
        return if success {
            console_response(StatusCode::OK, json!({"message": message}))
        } else {
            error_response(StatusCode::BAD_REQUEST, "oauth_callback_failed", message)
        };
    }
    let title = if success {
        "Login complete"
    } else {
        "Login failed"
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>\
         <body style=\"font-family:system-ui;padding:2rem\"><h1>{title}</h1><p>{}</p>\
         <p>You can close this window and return to the console.</p></body></html>",
        message.replace('<', "&lt;").replace('>', "&gt;")
    );
    Response::builder()
        .status(if success {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        })
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `GET /console/api/providers/{providerId}/oauth/callback?code=&state=`.
pub async fn browser_callback(
    State(state): State<ConsoleState>,
    Path(provider_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let wants_json = headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains("application/json"))
        .unwrap_or(false);
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        Ok(tenant) => tenant,
        Err(response) => {
            return if wants_json {
                response
            } else {
                callback_page(false, "Console authentication is required", false)
            };
        }
    };
    let Some(code) = query.get("code").filter(|value| !value.is_empty()) else {
        return callback_page(
            false,
            "The provider did not return an authorization code",
            wants_json,
        );
    };
    let Some(state_token) = query.get("state").filter(|value| !value.is_empty()) else {
        return callback_page(
            false,
            "The provider did not return a state value",
            wants_json,
        );
    };
    let flow = pending()
        .lock()
        .ok()
        .and_then(|mut flows| flows.remove(state_token));
    let Some(flow) = flow else {
        return callback_page(false, "Unknown or expired OAuth state", wants_json);
    };
    if flow.provider_id != provider_id || flow.tenant_id != tenant {
        return callback_page(
            false,
            "OAuth state does not belong to this provider",
            wants_json,
        );
    }
    if now_ms() - flow.created_ms > 15 * 60 * 1000 {
        return callback_page(false, "OAuth authorization expired", wants_json);
    }
    let client = match http_client() {
        Ok(client) => client,
        Err(response) => return response,
    };
    let exchange = if provider_id == "openrouter" {
        let response = client
            .post("https://openrouter.ai/api/v1/auth/keys")
            .json(&json!({
                "code": code,
                "code_verifier": flow.verifier,
                "code_challenge_method": "S256",
            }))
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status();
                let payload: Value = response.json().await.unwrap_or(Value::Null);
                let key = payload.get("key").and_then(Value::as_str).unwrap_or("");
                if !status.is_success() || key.is_empty() {
                    return callback_page(
                        false,
                        "OpenRouter key exchange returned no key",
                        wants_json,
                    );
                }
                Ok(Exchange {
                    access: key.to_owned(),
                    refresh: key.to_owned(),
                    expires_in: 31_536_000,
                    label: None,
                    auth_state: None,
                    client_secret: None,
                })
            }
            Err(error) => Err(format!("OpenRouter key exchange failed: {error}")),
        }
    } else if provider_id == "claude" {
        let (authorization_code, fragment_state) = code
            .split_once('#')
            .map(|(code, fragment)| (code, Some(fragment)))
            .unwrap_or((code.as_str(), None));
        let response = client
            .post(CLAUDE_TOKEN_URL)
            .json(&json!({
                "grant_type": "authorization_code",
                "client_id": CLAUDE_CLIENT_ID,
                "code": authorization_code,
                "code_verifier": flow.verifier,
                "redirect_uri": flow.redirect_uri,
                "state": fragment_state.unwrap_or(state_token),
            }))
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status();
                let payload: Value = response.json().await.unwrap_or(Value::Null);
                if !status.is_success() {
                    return callback_page(
                        false,
                        payload
                            .get("error")
                            .and_then(|error| error.get("message"))
                            .and_then(Value::as_str)
                            .or_else(|| payload.get("error_description").and_then(Value::as_str))
                            .unwrap_or("Claude token exchange failed"),
                        wants_json,
                    );
                }
                let Some(access) = payload.get("access_token").and_then(Value::as_str) else {
                    return callback_page(
                        false,
                        "Claude token response omitted access_token",
                        wants_json,
                    );
                };
                let Some(refresh) = payload.get("refresh_token").and_then(Value::as_str) else {
                    return callback_page(
                        false,
                        "Claude token response omitted refresh_token",
                        wants_json,
                    );
                };
                let expires = payload
                    .get("expires_in")
                    .and_then(Value::as_i64)
                    .unwrap_or(3600);
                let label = payload
                    .get("account")
                    .and_then(|account| account.get("email_address"))
                    .and_then(Value::as_str)
                    .or_else(|| {
                        payload
                            .get("organization")
                            .and_then(|organization| organization.get("name"))
                            .and_then(Value::as_str)
                    })
                    .map(str::to_owned);
                Ok(Exchange {
                    access: access.to_owned(),
                    refresh: refresh.to_owned(),
                    expires_in: expires,
                    label,
                    auth_state: None,
                    client_secret: None,
                })
            }
            Err(error) => Err(format!("Claude token exchange failed: {error}")),
        }
    } else if provider_id == "zcode" {
        exchange_zcode(&client, code, &flow.redirect_uri, state_token).await
    } else if provider_id == "kiro" {
        (async {
            let context = json!({
                "parameters": flow.parameters.clone().unwrap_or_else(|| json!({})),
            });
            let exchanged = keyla_providers::kiro_oauth::exchange_kiro_code(
                &client,
                code,
                &flow.verifier,
                &flow.redirect_uri,
                Some(&context),
            )
            .await?;
            let access = exchanged
                .get("access")
                .and_then(Value::as_str)
                .ok_or("Kiro exchange omitted access")?;
            let refresh = exchanged
                .get("refresh")
                .and_then(Value::as_str)
                .ok_or("Kiro exchange omitted refresh")?;
            let expires = exchanged
                .get("expiresAt")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| (value.timestamp() - chrono::Utc::now().timestamp()).max(60))
                .unwrap_or(3600);
            Ok(Exchange {
                access: access.to_owned(),
                refresh: refresh.to_owned(),
                expires_in: expires,
                label: exchanged
                    .get("accountLabel")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                auth_state: exchanged.get("auth_state").cloned(),
                client_secret: exchanged
                    .get("client_secret")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .await
    } else if provider_id == "devin" {
        (async {
            let token =
                keyla_providers::devin::exchange_devin_oauth_code(&client, code, &flow.verifier)
                    .await
                    .map_err(|error| error.message)?;
            let expires = (token.expires_at.timestamp() - chrono::Utc::now().timestamp()).max(60);
            Ok(Exchange {
                access: token.access,
                refresh: token.refresh,
                expires_in: expires,
                label: token.account_label,
                auth_state: None,
                client_secret: None,
            })
        })
        .await
    } else if provider_id == "antigravity" {
        (async {
            let exchanged = keyla_providers::antigravity_oauth::exchange_antigravity_code(
                &client,
                code,
                &flow.verifier,
                &flow.redirect_uri,
            )
            .await
            .map_err(|error| error.message)?;
            let access = exchanged
                .get("access")
                .and_then(Value::as_str)
                .ok_or("Antigravity exchange omitted access")?;
            let refresh = exchanged
                .get("refresh")
                .and_then(Value::as_str)
                .ok_or("Antigravity exchange omitted refresh")?;
            let expires_at = exchanged
                .get("expiresAt")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| (value.timestamp() - chrono::Utc::now().timestamp()).max(60))
                .unwrap_or(3600);
            Ok(Exchange {
                access: access.to_owned(),
                refresh: refresh.to_owned(),
                expires_in: expires_at,
                label: exchanged
                    .get("accountLabel")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                auth_state: None,
                client_secret: None,
            })
        })
        .await
    } else if provider_id == "mimostudio" {
        (async {
            let credentials = keyla_providers::mimostudio::parse_credential(code)
                .map_err(|error| error.message)?;
            let cookie = keyla_providers::mimostudio::cookie_header(&credentials);
            let response = client
                .get("https://aistudio.xiaomimimo.com/open-apis/v1/user/usage")
                .header("cookie", cookie)
                .header("origin", "https://aistudio.xiaomimimo.com")
                .header("referer", "https://aistudio.xiaomimimo.com/")
                .header("user-agent", keyla_providers::mimostudio::USER_AGENT)
                .header("accept", "application/json")
                .send()
                .await
                .map_err(|error| format!("MiMo Studio verification failed: {error}"))?;
            if !response.status().is_success() {
                return Err(format!(
                    "MiMo Studio verification failed: HTTP {}",
                    response.status().as_u16()
                ));
            }
            let label = if credentials.user_id.is_empty() {
                "MiMo Studio".to_owned()
            } else {
                format!("MiMo Studio ({})", credentials.user_id)
            };
            let encoded = keyla_providers::mimostudio::encode_credential(&credentials);
            Ok(Exchange {
                access: encoded.clone(),
                refresh: encoded,
                expires_in: 30 * 24 * 60 * 60,
                label: Some(label),
                auth_state: None,
                client_secret: None,
            })
        })
        .await
    } else if provider_id == "mimodesktop" {
        (async {
            let credentials = keyla_providers::mimodesktop::read_desktop_credentials()
                .map_err(|error| error.message)?
                .ok_or_else(|| {
                    "Xiaomi MiMo Desktop session not found. Log in to MiMo Desktop first, or import a passToken.".to_owned()
                })?;
            keyla_providers::mimodesktop::acquire_session(
                &client,
                &credentials,
                "https://mimo-server-sgp.xiaomimimo.com",
            )
            .await
            .map_err(|error| error.message)?;
            let label = credentials
                .user_id
                .as_ref()
                .map(|user| format!("Xiaomi MiMo ({user})"))
                .unwrap_or_else(|| "Xiaomi MiMo Desktop".to_owned());
            Ok(Exchange {
                access: keyla_providers::mimodesktop::encode_credential(&credentials),
                refresh: credentials.pass_token.clone(),
                expires_in: 30 * 24 * 60 * 60,
                label: Some(label),
                auth_state: None,
                client_secret: None,
            })
        })
        .await
    } else {
        let response = client
            .post(CODEX_TOKEN_URL)
            .header("content-type", "application/x-www-form-urlencoded")
            .form(&[
                ("client_id", CODEX_CLIENT_ID),
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", flow.redirect_uri.as_str()),
                ("code_verifier", flow.verifier.as_str()),
            ])
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status();
                let payload: Value = response.json().await.unwrap_or(Value::Null);
                if !status.is_success() {
                    return callback_page(
                        false,
                        payload
                            .get("error_description")
                            .and_then(Value::as_str)
                            .unwrap_or("Codex token exchange failed"),
                        wants_json,
                    );
                }
                let Some(access) = payload.get("access_token").and_then(Value::as_str) else {
                    return callback_page(
                        false,
                        "Codex token response omitted access_token",
                        wants_json,
                    );
                };
                let Some(refresh) = payload.get("refresh_token").and_then(Value::as_str) else {
                    return callback_page(
                        false,
                        "Codex token response omitted refresh_token",
                        wants_json,
                    );
                };
                let expires = payload
                    .get("expires_in")
                    .and_then(Value::as_i64)
                    .unwrap_or(3600);
                let (account_id, email) =
                    codex_profile(access, payload.get("id_token").and_then(Value::as_str));
                Ok(Exchange {
                    access: access.to_owned(),
                    refresh: refresh.to_owned(),
                    expires_in: expires,
                    label: email,
                    auth_state: account_id.map(|account| json!({"chatgptAccountId": account})),
                    client_secret: None,
                })
            }
            Err(error) => Err(format!("Codex token exchange failed: {error}")),
        }
    };
    let exchange = match exchange {
        Ok(exchange) => exchange,
        Err(message) => return callback_page(false, &message, wants_json),
    };
    match persist_account(&state, &tenant, &provider_id, &flow.label, exchange).await {
        Ok(_) => callback_page(true, "Account connected", wants_json),
        Err(response) => response,
    }
}
