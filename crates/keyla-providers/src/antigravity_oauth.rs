//! Antigravity Google OAuth login/refresh client and quota collector.
//!
//! Google OAuth 2.0 with PKCE against a dedicated Google OAuth application,
//! plus the Cloud Code Assist quota surfaces. Ported from
//! `src/providers/integrations/antigravity/antigravity-oauth.ts` and
//! `antigravity-quota.ts`.

use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use keyla_core::{GatewayError, GatewayErrorCode, GatewayErrorOrigin};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::antigravity::{
    ANTIGRAVITY_BASE_URL, ANTIGRAVITY_SANDBOX_BASE_URL, collapse_antigravity_variant,
    discover_antigravity_project, get_antigravity_user_agent, get_antigravity_version,
    is_antigravity_catalog_model, load_antigravity_project,
};

/// Google OAuth client identity for Antigravity. Configured by the operator
/// because the upstream client credentials are not redistributed with Keyla.
pub fn antigravity_client_id() -> &'static str {
    static ID: LazyLock<String> =
        LazyLock::new(|| std::env::var("KEYLA_ANTIGRAVITY_CLIENT_ID").unwrap_or_default());
    &ID
}
pub const ANTIGRAVITY_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const ANTIGRAVITY_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Loopback callback registered on the Antigravity Google client.
pub const ANTIGRAVITY_REDIRECT_URI: &str = "http://127.0.0.1:51121/oauth-callback";
pub const ANTIGRAVITY_SCOPES: &str = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/cclog https://www.googleapis.com/auth/experimentsandconfigs";
pub const ANTIGRAVITY_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
pub const ANTIGRAVITY_QUOTA_SOURCE: &str = "antigravity";

fn client_secret() -> &'static str {
    static SECRET: LazyLock<String> =
        LazyLock::new(|| std::env::var("KEYLA_ANTIGRAVITY_CLIENT_SECRET").unwrap_or_default());
    &SECRET
}

/// Antigravity Google OAuth client secret, supplied by the operator.
pub fn antigravity_client_secret() -> &'static str {
    client_secret()
}

fn auth_error(status: u16, message: impl Into<String>) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::AuthenticationFailed,
        status,
        message,
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Upstream)
}

/// RFC 7636 S256 challenge for a PKCE verifier.
pub fn antigravity_pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn random_token(bytes: usize) -> String {
    let mut buffer = Vec::with_capacity(bytes);
    while buffer.len() < bytes {
        buffer.extend_from_slice(Uuid::new_v4().as_bytes());
    }
    buffer.truncate(bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buffer)
}

/// Builds the Google authorize URL for a PKCE login.
pub fn antigravity_authorize_url(redirect_uri: &str, state: &str, code_challenge: &str) -> String {
    let mut url = url::Url::parse(ANTIGRAVITY_AUTHORIZE_URL).expect("antigravity authorize url");
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("client_id", antigravity_client_id());
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("response_type", "code");
        query.append_pair("scope", ANTIGRAVITY_SCOPES);
        query.append_pair("state", state);
        query.append_pair("code_challenge", code_challenge);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("access_type", "offline");
        query.append_pair("prompt", "consent");
    }
    url.to_string()
}

/// Starts a browser PKCE login. The caller persists `codeVerifier` keyed by
/// `state` and relays the callback code back for exchange.
pub fn antigravity_oauth_start(redirect_uri: Option<&str>) -> Value {
    let redirect_uri = redirect_uri.unwrap_or(ANTIGRAVITY_REDIRECT_URI);
    let state = random_token(32);
    // 48 random bytes → a 64-character base64url verifier (within RFC 7636's
    // 43..128 range).
    let verifier = random_token(48);
    let challenge = antigravity_pkce_challenge(&verifier);
    json!({
        "authorizeUrl": antigravity_authorize_url(redirect_uri, &state, &challenge),
        "state": state,
        "codeVerifier": verifier,
        "redirectUri": redirect_uri,
        "scopes": ANTIGRAVITY_SCOPES,
    })
}

fn form_body(params: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

async fn read_json_response(
    response: reqwest::Response,
    label: &str,
) -> Result<Value, GatewayError> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| auth_error(400, format!("{label} failed: {error}")))?;
    let parsed = serde_json::from_str::<Value>(&text).map_err(|_| {
        auth_error(
            if status.is_success() { 502 } else { 400 },
            format!("{label} returned invalid JSON"),
        )
    })?;
    if !status.is_success() {
        let message = parsed
            .get("error_description")
            .and_then(Value::as_str)
            .or_else(|| parsed.get("error").and_then(Value::as_str))
            .unwrap_or("token endpoint rejected the request");
        return Err(auth_error(
            status.as_u16().clamp(400, 599),
            format!("{label} failed: {message}"),
        ));
    }
    Ok(parsed)
}

fn token_response_fields(
    body: &Value,
    label: &str,
) -> Result<(String, Option<String>, i64), GatewayError> {
    let access = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| auth_error(400, format!("{label} omitted access token")))?;
    let refresh = body
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| auth_error(400, format!("{label} omitted a valid expires_in")))?;
    Ok((access.to_owned(), refresh, expires_in as i64))
}

fn expires_at(expires_in: i64) -> String {
    (Utc::now() + chrono::Duration::seconds(expires_in))
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Best-effort userinfo email used as the account label.
pub async fn fetch_antigravity_userinfo_email(
    client: &reqwest::Client,
    access_token: &str,
) -> Option<String> {
    let response = client
        .get(ANTIGRAVITY_USERINFO_URL)
        .timeout(Duration::from_secs(15))
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = response.json::<Value>().await.ok()?;
    body.get("email")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Exchanges an authorization code for tokens, returning the console's
/// exchange result shape (`access`, `refresh`, `expiresAt`, `accountLabel`).
pub async fn exchange_antigravity_code(
    client: &reqwest::Client,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<Value, GatewayError> {
    let body = form_body(&[
        ("client_id", antigravity_client_id()),
        ("client_secret", client_secret()),
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ]);
    let response = client
        .post(ANTIGRAVITY_TOKEN_URL)
        .timeout(Duration::from_secs(30))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|error| auth_error(502, format!("Antigravity token exchange failed: {error}")))?;
    let payload = read_json_response(response, "Antigravity token exchange").await?;
    let (access, refresh, expires_in) =
        token_response_fields(&payload, "Antigravity token response")?;
    let refresh = refresh.ok_or_else(|| {
        auth_error(
            400,
            "Antigravity token response omitted access or refresh token",
        )
    })?;
    let email = fetch_antigravity_userinfo_email(client, &access).await;
    // Best-effort project warm: a failure here must not fail the login; the
    // same lookup retries at dispatch.
    let _ = discover_antigravity_project(client, &access, None).await;
    let mut result = Map::new();
    result.insert("access".into(), json!(access));
    result.insert("refresh".into(), json!(refresh));
    result.insert("expiresAt".into(), json!(expires_at(expires_in)));
    if let Some(email) = email {
        result.insert("accountLabel".into(), json!(email));
    }
    Ok(Value::Object(result))
}

/// Refreshes an Antigravity access token, returning `access`, `expiresAt`, and
/// a rotated `refresh` when the upstream supplies one.
pub async fn refresh_antigravity_token(
    client: &reqwest::Client,
    refresh_token: &str,
) -> Result<Value, GatewayError> {
    let body = form_body(&[
        ("client_id", antigravity_client_id()),
        ("client_secret", client_secret()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ]);
    let response = client
        .post(ANTIGRAVITY_TOKEN_URL)
        .timeout(Duration::from_secs(15))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|error| auth_error(502, format!("Antigravity token refresh failed: {error}")))?;
    let payload = read_json_response(response, "Antigravity token refresh").await?;
    let (access, rotated_refresh, expires_in) =
        token_response_fields(&payload, "Antigravity token response")?;
    let mut result = Map::new();
    result.insert("access".into(), json!(access));
    result.insert("expiresAt".into(), json!(expires_at(expires_in)));
    if let Some(refresh) = rotated_refresh {
        result.insert("refresh".into(), json!(refresh));
    }
    Ok(Value::Object(result))
}

// --- Quota ------------------------------------------------------------------

const QUOTA_TOTAL: f64 = 1000.0;

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(raw) => raw.as_f64(),
        Value::String(raw) => raw.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn iso_date(value: Option<&Value>) -> Option<String> {
    if let Some(numeric) = number(value) {
        let milliseconds = if numeric > 1_000_000_000_000.0 {
            numeric
        } else {
            numeric * 1000.0
        };
        return Utc
            .timestamp_millis_opt(milliseconds as i64)
            .single()
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true));
    }
    let raw = text(value)?;
    DateTime::parse_from_rfc3339(&raw).ok().map(|value| {
        value
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Millis, true)
    })
}

fn percent_window(
    kind: &str,
    label: &str,
    used: Option<f64>,
    resets_at: Option<String>,
    used_value: Option<f64>,
    limit: Option<f64>,
) -> Value {
    let used_percent = used.map(|value| value.clamp(0.0, 100.0));
    json!({
        "kind": kind,
        "label": label,
        "usedPercent": used_percent,
        "remainingPercent": used_percent.map(|value| (100.0 - value).max(0.0)),
        "resetsAt": resets_at,
        "used": used_value,
        "limit": limit,
    })
}

fn fraction_window(
    kind: &str,
    label: &str,
    remaining_fraction: f64,
    resets_at: Option<String>,
) -> Value {
    let fraction = remaining_fraction.clamp(0.0, 1.0);
    let used = QUOTA_TOTAL - (QUOTA_TOTAL * fraction).round();
    let mut window = percent_window(
        kind,
        label,
        Some((1.0 - fraction) * 100.0),
        resets_at,
        Some(used),
        Some(QUOTA_TOTAL),
    );
    if let Some(object) = window.as_object_mut() {
        object.insert("recurring".into(), json!(true));
    }
    window
}

fn record(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn quota_record(value: &Value) -> Value {
    let root = record(value).cloned().unwrap_or_default();
    for key in ["data", "result", "usage"] {
        if let Some(nested) = root.get(key).and_then(record) {
            return Value::Object(nested.clone());
        }
    }
    Value::Object(root)
}

fn model_family(model_id: &str) -> (&'static str, &'static str) {
    let lower = model_id.to_ascii_lowercase();
    if lower.starts_with("gemini-") || lower.starts_with("gemini_") || lower.starts_with("tab_") {
        ("google", "Google")
    } else {
        ("claude", "Claude")
    }
}

fn family_label(key: &str) -> &'static str {
    match key {
        "google" => "Gemini (Flash / Pro)",
        "claude" => "Claude (Sonnet / Opus)",
        _ => "Google",
    }
}

fn summary_family(group_name: &str) -> Option<&'static str> {
    let lower = group_name.to_ascii_lowercase();
    if lower.contains("gemini") {
        Some("Gemini")
    } else if lower.contains("claude") || lower.contains("gpt") {
        Some("Claude & GPT")
    } else {
        None
    }
}

fn summary_window_kind(bucket: &Map<String, Value>) -> Option<&'static str> {
    let window_type = text(bucket.get("window"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let bucket_text = format!(
        "{} {}",
        text(bucket.get("bucketId")).unwrap_or_default(),
        text(bucket.get("displayName")).unwrap_or_default()
    )
    .to_ascii_lowercase();
    if window_type == "weekly" || bucket_text.contains("weekly") {
        return Some("weekly");
    }
    if window_type == "5h"
        || window_type == "daily"
        || bucket_text.contains("five hour")
        || bucket_text.contains("5h")
        || bucket_text.contains("daily")
    {
        return Some("session");
    }
    None
}

fn summary_window_label(kind: &str) -> &'static str {
    match kind {
        "session" => "5 Hour",
        _ => "Weekly",
    }
}

fn keep_worse(current: Option<Value>, candidate: Value) -> Value {
    let Some(current) = current else {
        return candidate;
    };
    let current_remaining = current.get("remainingPercent").and_then(Value::as_f64);
    let candidate_remaining = candidate.get("remainingPercent").and_then(Value::as_f64);
    match (current_remaining, candidate_remaining) {
        (None, _) => candidate,
        (_, None) => current,
        (Some(current_remaining), Some(candidate_remaining)) => {
            if candidate_remaining < current_remaining {
                candidate
            } else {
                current
            }
        }
    }
}

fn parse_model_quotas(payload: &Value) -> Vec<Value> {
    let models = payload
        .get("models")
        .and_then(record)
        .or_else(|| payload.get("modelQuotas").and_then(record))
        .or_else(|| payload.get("quota").and_then(record));
    let Some(models) = models else {
        return Vec::new();
    };
    let mut grouped: Vec<(String, Value)> = Vec::new();
    for (model_id, raw) in models {
        let Some(model) = record(raw) else {
            continue;
        };
        if model.get("isInternal") == Some(&Value::Bool(true))
            || !is_antigravity_catalog_model(&collapse_antigravity_variant(model_id))
        {
            continue;
        }
        let Some(quota) = model.get("quotaInfo").and_then(record) else {
            continue;
        };
        let Some(fraction) = number(quota.get("remainingFraction")) else {
            continue;
        };
        let variant = collapse_antigravity_variant(model_id);
        let (family_key, _) = model_family(&variant);
        let label = family_label(family_key);
        let window = fraction_window(
            family_key,
            label,
            fraction,
            iso_date(quota.get("resetTime")),
        );
        let existing = grouped
            .iter()
            .position(|(key, _)| key == family_key)
            .map(|index| grouped.remove(index).1);
        let worse = keep_worse(existing, window);
        grouped.push((family_key.to_owned(), worse));
    }
    grouped.into_iter().map(|(_, window)| window).collect()
}

fn parse_summary_quotas(payload: &Value) -> Vec<Value> {
    let empty = Map::new();
    let summary = payload
        .get("quotaSummary")
        .and_then(record)
        .or_else(|| payload.as_object())
        .unwrap_or(&empty);
    let Some(groups) = summary.get("groups").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut found: Vec<(String, Value)> = Vec::new();
    for raw_group in groups {
        let Some(group) = record(raw_group) else {
            continue;
        };
        let group_name = text(group.get("displayName")).unwrap_or_default();
        let Some(family) = summary_family(&group_name) else {
            continue;
        };
        let Some(buckets) = group.get("buckets").and_then(Value::as_array) else {
            continue;
        };
        for raw_bucket in buckets {
            let Some(bucket) = record(raw_bucket) else {
                continue;
            };
            let Some(kind) = summary_window_kind(bucket) else {
                continue;
            };
            let disabled = bucket.get("disabled") == Some(&Value::Bool(true));
            if disabled && kind == "weekly" {
                continue;
            }
            let fraction = if disabled {
                Some(0.0)
            } else {
                number(bucket.get("remainingFraction"))
            };
            let Some(fraction) = fraction else {
                continue;
            };
            let key = format!("{family}:{kind}");
            if found.iter().any(|(existing, _)| *existing == key) {
                continue;
            }
            let window = fraction_window(
                &format!("{kind}:{family}"),
                &format!("{family} ({})", summary_window_label(kind)),
                fraction,
                iso_date(bucket.get("resetTime")),
            );
            found.push((key, window));
        }
    }
    found.into_iter().map(|(_, window)| window).collect()
}

async fn get_quota_json(
    client: &reqwest::Client,
    url: &str,
    headers: &reqwest::header::HeaderMap,
    project: Option<&str>,
) -> Result<Value, String> {
    let mut builder = client
        .get(url)
        .timeout(Duration::from_secs(15))
        .headers(headers.clone());
    if let Some(project) = project {
        builder = client
            .post(url)
            .timeout(Duration::from_secs(15))
            .headers(headers.clone())
            .json(&json!({"project": project}));
    }
    let response = builder.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    let text_body = response.text().await.unwrap_or_default();
    let parsed: Value = if text_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text_body).unwrap_or(Value::Null)
    };
    if !status.is_success() {
        let detail = text(parsed.get("error"))
            .or_else(|| text(parsed.get("message")))
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        return Err(format!("Quota endpoint rejected request: {detail}"));
    }
    let envelope = record(&parsed);
    if envelope.and_then(|value| value.get("success")) == Some(&Value::Bool(false)) {
        return Err(text(envelope.and_then(|value| value.get("error")))
            .unwrap_or_else(|| "Quota endpoint rejected the request.".to_owned()));
    }
    if envelope.and_then(|value| value.get("success")) == Some(&Value::Bool(true)) {
        if let Some(data) = envelope.and_then(|value| value.get("data")) {
            return Ok(data.clone());
        }
    }
    Ok(parsed)
}

fn credential_fields(credential: &str) -> Value {
    if credential.trim_start().starts_with('{') {
        if let Ok(parsed) = serde_json::from_str::<Value>(credential) {
            if parsed.is_object() {
                return parsed;
            }
        }
    }
    json!({"accessToken": credential})
}

/// Fetches Antigravity model and summary quotas, merging both endpoints. The
/// result matches the console's `ProviderQuotaResult` shape.
pub async fn fetch_antigravity_quota(
    client: &reqwest::Client,
    credential: &str,
    base_url: Option<&str>,
) -> Value {
    let fields = credential_fields(credential);
    let access = text(fields.get("accessToken"))
        .or_else(|| text(fields.get("access_token")))
        .unwrap_or_else(|| credential.to_owned());
    let project = text(fields.get("projectId"))
        .or_else(|| text(fields.get("providerAccountId")))
        .or(load_antigravity_project(client, &access, base_url).await);

    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {access}")) {
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    if let Ok(value) = reqwest::header::HeaderValue::from_str("application/json") {
        headers.insert(reqwest::header::CONTENT_TYPE, value);
    }
    if let Ok(value) = reqwest::header::HeaderValue::from_str(&get_antigravity_user_agent()) {
        headers.insert(reqwest::header::USER_AGENT, value);
    }
    if let Ok(value) = reqwest::header::HeaderValue::from_str("antigravity") {
        headers.insert(
            reqwest::header::HeaderName::from_static("x-client-name"),
            value,
        );
    }
    if let Ok(value) = reqwest::header::HeaderValue::from_str(&get_antigravity_version()) {
        headers.insert(
            reqwest::header::HeaderName::from_static("x-client-version"),
            value,
        );
    }

    let primary = base_url
        .unwrap_or(ANTIGRAVITY_BASE_URL)
        .trim_end_matches('/')
        .to_owned();
    let mut hosts = vec![primary];
    if hosts[0] != ANTIGRAVITY_SANDBOX_BASE_URL {
        hosts.push(ANTIGRAVITY_SANDBOX_BASE_URL.to_owned());
    }

    let mut windows: Vec<Value> = Vec::new();
    let mut plan: Option<String> = None;
    for host in &hosts {
        let summary = match get_quota_json(
            client,
            &format!("{host}/v1internal:retrieveUserQuotaSummary"),
            &headers,
            project.as_deref(),
        )
        .await
        {
            Ok(value) => quota_record(&value),
            Err(_) => continue,
        };
        windows.extend(parse_summary_quotas(&summary));
        if plan.is_none() {
            plan = text(summary.get("tier")).or_else(|| text(summary.get("plan")));
        }
        if !windows.is_empty() {
            break;
        }
    }
    for host in &hosts {
        let models = match get_quota_json(
            client,
            &format!("{host}/v1internal:fetchAvailableModels"),
            &headers,
            project.as_deref(),
        )
        .await
        {
            Ok(value) => quota_record(&value),
            Err(_) => continue,
        };
        windows.extend(parse_model_quotas(&models));
        if plan.is_none() {
            plan = text(models.get("tier")).or_else(|| text(models.get("plan")));
        }
        break;
    }

    json!({
        "source": ANTIGRAVITY_QUOTA_SOURCE,
        "plan": plan.unwrap_or_else(|| "Antigravity".to_owned()),
        "windows": windows,
        "error": Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc_vector() {
        // RFC 7636 appendix B.
        assert_eq!(
            antigravity_pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn oauth_start_carries_pkce_and_offline_consent() {
        let start = antigravity_oauth_start(Some("http://127.0.0.1:51121/oauth-callback"));
        let url = url::Url::parse(start["authorizeUrl"].as_str().unwrap()).unwrap();
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        assert_eq!(url.path(), "/o/oauth2/v2/auth");
        let params: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert!(params.contains_key("client_id"));
        assert_eq!(
            params.get("redirect_uri").unwrap(),
            "http://127.0.0.1:51121/oauth-callback"
        );
        assert_eq!(params.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(params.get("access_type").unwrap(), "offline");
        assert_eq!(params.get("prompt").unwrap(), "consent");
        let verifier = start["codeVerifier"].as_str().unwrap();
        assert_eq!(
            params.get("code_challenge").unwrap(),
            &antigravity_pkce_challenge(verifier)
        );
        assert_eq!(
            params.get("state").unwrap(),
            start["state"].as_str().unwrap()
        );
    }

    #[test]
    fn model_quotas_collapse_variants_and_keep_worst() {
        let payload = json!({
            "models": {
                "gemini-3.8-flash-low": {
                    "quotaInfo": {"remainingFraction": 0.9, "resetTime": "2026-11-12T00:00:00Z"}
                },
                "gemini-3.8-flash-high": {
                    "quotaInfo": {"remainingFraction": 0.2, "resetTime": "2026-11-12T00:00:00Z"}
                },
                "gemini-2.5-pro": {
                    "quotaInfo": {"remainingFraction": 0.1}
                },
                "chat_20706": {
                    "quotaInfo": {"remainingFraction": 0.1}
                },
                "internal": {
                    "isInternal": true,
                    "quotaInfo": {"remainingFraction": 0.1}
                },
                "claude-sonnet-4-6": {
                    "quotaInfo": {"remainingFraction": 0.5, "resetTime": 1_800_000_000}
                }
            }
        });
        let windows = parse_model_quotas(&payload);
        assert_eq!(windows.len(), 2);
        let google = windows
            .iter()
            .find(|window| window["kind"] == json!("google"))
            .unwrap();
        assert_eq!(google["label"], json!("Gemini (Flash / Pro)"));
        assert_eq!(google["remainingPercent"], json!(20.0));
        assert_eq!(google["used"], json!(800.0));
        assert_eq!(google["limit"], json!(1000.0));
        assert_eq!(google["recurring"], json!(true));
        let claude = windows
            .iter()
            .find(|window| window["kind"] == json!("claude"))
            .unwrap();
        assert_eq!(claude["remainingPercent"], json!(50.0));
        assert!(claude["resetsAt"].as_str().unwrap().starts_with("2027-"));
    }

    #[test]
    fn summary_quotas_read_session_and_weekly_buckets() {
        let payload = json!({
            "quotaSummary": {
                "groups": [
                    {
                        "displayName": "Gemini Models",
                        "buckets": [
                            {
                                "bucketId": "gemini-5h",
                                "window": "5h",
                                "remainingFraction": 0.75,
                                "resetTime": "2026-11-12T05:00:00Z"
                            },
                            {
                                "bucketId": "gemini-weekly",
                                "window": "weekly",
                                "remainingFraction": 0.5
                            }
                        ]
                    },
                    {
                        "displayName": "Claude and GPT",
                        "buckets": [
                            {
                                "bucketId": "claude-5h",
                                "window": "5h",
                                "disabled": true
                            },
                            {
                                "bucketId": "claude-weekly",
                                "window": "weekly",
                                "disabled": true
                            }
                        ]
                    },
                    {
                        "displayName": "Other",
                        "buckets": [{"bucketId": "ignored", "window": "weekly", "remainingFraction": 1}]
                    }
                ]
            }
        });
        let windows = parse_summary_quotas(&payload);
        assert_eq!(windows.len(), 3);
        let gemini_session = windows
            .iter()
            .find(|window| window["kind"] == json!("session:Gemini"))
            .unwrap();
        assert_eq!(gemini_session["label"], json!("Gemini (5 Hour)"));
        assert_eq!(gemini_session["remainingPercent"], json!(75.0));
        assert!(
            windows
                .iter()
                .any(|window| window["kind"] == json!("weekly:Gemini"))
        );
        let claude_session = windows
            .iter()
            .find(|window| window["kind"] == json!("session:Claude & GPT"))
            .unwrap();
        // Disabled session bucket is kept at 0%; the disabled weekly one is
        // dropped entirely.
        assert_eq!(claude_session["remainingPercent"], json!(0.0));
        assert!(
            !windows
                .iter()
                .any(|window| window["kind"] == json!("weekly:Claude & GPT"))
        );
    }

    #[test]
    fn quota_record_unwraps_nested_envelopes() {
        let nested = json!({"data": {"models": {}}});
        assert!(quota_record(&nested).get("models").is_some());
        let wrapped = json!({"result": {"tier": "free-tier"}});
        assert_eq!(quota_record(&wrapped)["tier"], json!("free-tier"));
        assert_eq!(quota_record(&json!(null)), json!({}));
    }

    #[test]
    fn iso_date_handles_seconds_millis_and_strings() {
        assert!(
            iso_date(Some(&json!(1_800_000_000)))
                .unwrap()
                .starts_with("2027-")
        );
        assert!(
            iso_date(Some(&json!(1_800_000_000_000i64)))
                .unwrap()
                .starts_with("2027-")
        );
        assert_eq!(
            iso_date(Some(&json!("2026-11-12T00:00:00Z"))).unwrap(),
            "2026-11-12T00:00:00.000Z"
        );
        assert!(iso_date(Some(&json!("not a date"))).is_none());
    }
}
