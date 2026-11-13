//! Kiro (AWS CodeWhisperer) authentication and account helpers.
//!
//! Ported from `src/providers/integrations/kiro/kiro-oauth.ts`,
//! `kiro-quota.ts` (quota lives with dispatch in `kiro.rs`), and the shared
//! OAuth primitives it consumes.
//!
//! Kiro has no single sign-in: AWS Builder ID, an Identity Center organization,
//! Google/GitHub social sign-in, an imported refresh token, an enterprise
//! Microsoft identity provider, and a plain API key all reach the same
//! subscription but differ in where the token comes from, how it refreshes, and
//! which host accepts it. The account-side configuration every later request
//! needs (profile, region, sign-in family, frozen device id) travels in
//! `auth_state` beside the tokens.
//!
//! Every public flow returns `serde_json::Value` in the camelCase shape the
//! TypeScript console consumes, so the parent can wire these functions without
//! another translation layer. Flow failures are plain `String`s, matching the
//! console's existing `Result<Value, String>` provider flows.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{DateTime, NaiveDate, NaiveDateTime};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::kiro::{
    KIRO_IDE_VERSION, build_kiro_amz_user_agent, build_kiro_sso_amz_user_agent,
    build_kiro_sso_user_agent, build_kiro_user_agent, derive_api_key_machine_id,
    derive_oauth_machine_id, is_aws_region, normalize_machine_id,
};

/// The vendor's own sign-in and refresh service for the social families.
pub const KIRO_AUTH_SERVICE: &str = "https://prod.us-east-1.auth.desktop.kiro.dev";
/// Redirect URI the vendor's identity provider allowlists.
pub const KIRO_SOCIAL_REDIRECT_URI: &str = "kiro://kiro.kiroAgent/authenticate-success";
/// Organization entry point the device flow starts from by default.
pub const KIRO_DEFAULT_START_URL: &str = "https://view.awsapps.com/start";
/// AWS Builder ID issuer used by the browser flow.
pub const KIRO_BUILDER_ID_ISSUER: &str = "https://view.awsapps.com/start";

const DEFAULT_REGION: &str = "us-east-1";
const KIRO_SCOPES: [&str; 3] = [
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
];
const KIRO_GRANT_TYPES: [&str; 2] = [
    "urn:ietf:params:oauth:grant-type:device_code",
    "refresh_token",
];
const KIRO_BROWSER_GRANT_TYPES: [&str; 2] = ["authorization_code", "refresh_token"];
const KIRO_OIDC_CLIENT_NAME: &str = "Kiro IDE";
const MICROSOFT_TOKEN_HOSTS: [&str; 3] = [
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.windows.net",
];

// ─── Auth state ─────────────────────────────────────────────────────────────

/// The account-side configuration carried in `auth_state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KiroOAuthState {
    pub auth_method: String,
    pub region: String,
    pub profile_arn: Option<String>,
    pub start_url: Option<String>,
    pub client_id: Option<String>,
    pub token_endpoint: Option<String>,
    pub scope: Option<String>,
    pub machine_id: Option<String>,
}

/// Rejects a region that is not an AWS region before it reaches a URL.
pub fn assert_aws_region(region: &str) -> Result<String, String> {
    if !is_aws_region(region) {
        return Err("Kiro region must be a valid AWS region".to_owned());
    }
    Ok(region.to_owned())
}

/// Normalizes a stored region, falling back to the default.
pub fn normalize_region(value: Option<&Value>) -> String {
    let region = value.and_then(Value::as_str).map(str::trim).unwrap_or("");
    if is_aws_region(region) {
        region.to_owned()
    } else {
        DEFAULT_REGION.to_owned()
    }
}

/// Reads the account's `auth_state` back into a typed value.
pub fn parse_kiro_auth_state(value: Option<&Value>) -> Option<KiroOAuthState> {
    let raw = record(value?)?;
    let auth_method = non_empty_string(raw.get("authMethod"))?;
    if !is_kiro_auth_method(auth_method) {
        return None;
    }
    let field = |key: &str| non_empty_trimmed(raw.get(key));
    Some(KiroOAuthState {
        auth_method: auth_method.to_owned(),
        region: normalize_region(raw.get("region")),
        profile_arn: field("profileArn"),
        start_url: field("startUrl"),
        client_id: field("clientId"),
        token_endpoint: field("tokenEndpoint"),
        scope: field("scope"),
        machine_id: normalize_machine_id(raw.get("machineId")),
    })
}

fn is_kiro_auth_method(value: &str) -> bool {
    matches!(
        value,
        "builder-id" | "idc" | "google" | "github" | "imported" | "external_idp" | "api_key"
    )
}

/// The `auth_state` object to persist for one flow.
pub fn auth_state_value(state: &KiroOAuthState) -> Value {
    let mut map = Map::new();
    map.insert("authMethod".into(), json!(state.auth_method.as_str()));
    map.insert("region".into(), json!(state.region.as_str()));
    if let Some(value) = &state.profile_arn {
        map.insert("profileArn".into(), json!(value.as_str()));
    }
    if let Some(value) = &state.start_url {
        map.insert("startUrl".into(), json!(value.as_str()));
    }
    if let Some(value) = &state.client_id {
        map.insert("clientId".into(), json!(value.as_str()));
    }
    if let Some(value) = &state.token_endpoint {
        map.insert("tokenEndpoint".into(), json!(value.as_str()));
    }
    if let Some(value) = &state.scope {
        map.insert("scope".into(), json!(value.as_str()));
    }
    if let Some(value) = &state.machine_id {
        map.insert("machineId".into(), json!(value.as_str()));
    }
    Value::Object(map)
}

// ─── Small helpers ──────────────────────────────────────────────────────────

fn record(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn safe_json(value: &str) -> Option<Value> {
    serde_json::from_str(value).ok()
}

fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    value?.as_str().filter(|text| !text.is_empty())
}

fn non_empty_trimmed(value: Option<&Value>) -> Option<String> {
    value?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn number_value(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite())
            }
        }
        _ => None,
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn expiry_value(millis: i64) -> Value {
    let text = DateTime::from_timestamp_millis(millis)
        .map(|value| value.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default();
    Value::String(text)
}

fn calculate_expiry(expires_in: Option<&Value>, fallback_seconds: i64) -> i64 {
    let seconds = match expires_in {
        Some(Value::Number(number)) => number
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0),
        _ => None,
    }
    .unwrap_or(fallback_seconds as f64);
    now_ms() + (seconds.max(0.0) as i64) * 1000
}

fn read_expiry(raw: &Map<String, Value>) -> Option<i64> {
    let explicit = raw
        .get("expired")
        .or_else(|| raw.get("expires_at"))
        .or_else(|| raw.get("expiresAt"));
    if let Some(text) = explicit.and_then(Value::as_str).map(str::trim) {
        if !text.is_empty() {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(text) {
                return Some(parsed.timestamp_millis());
            }
            if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
                return date
                    .and_hms_opt(0, 0, 0)
                    .map(|value| value.and_utc().timestamp_millis());
            }
            if let Ok(date) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
                return Some(date.and_utc().timestamp_millis());
            }
        }
    }
    let expires_in = number_value(raw.get("expires_in").or_else(|| raw.get("expiresIn")))?;
    if expires_in > 0.0 {
        Some(now_ms() + (expires_in as i64) * 1000)
    } else {
        None
    }
}

fn normalize_scope(value: Option<&Value>) -> String {
    match value {
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        Some(Value::String(text)) => text.trim().to_owned(),
        _ => String::new(),
    }
}

/// Best-effort display label for a credential.
pub fn kiro_account_label(access_token: &str) -> Option<String> {
    let payload = decode_jwt_payload(access_token)?;
    for key in ["email", "preferred_username", "upn", "sub"] {
        if let Some(value) = non_empty_trimmed(payload.get(key)) {
            return Some(value);
        }
    }
    None
}

/// Decodes a JWT payload without verifying it, for display only.
pub fn decode_jwt_payload(token: &str) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| URL_SAFE.decode(parts[1]))
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.as_object().cloned()
}

/// Validates an enterprise identity-provider token endpoint.
pub fn validate_microsoft_token_endpoint(raw: Option<&Value>) -> Result<String, String> {
    let endpoint = raw.and_then(Value::as_str).map(str::trim).unwrap_or("");
    if endpoint.is_empty() {
        return Err("token_endpoint is required".to_owned());
    }
    let parsed =
        url::Url::parse(endpoint).map_err(|_| "token_endpoint must be a valid URL".to_owned())?;
    if parsed.scheme() != "https" {
        return Err("token_endpoint must use https".to_owned());
    }
    let host = parsed.host_str().unwrap_or("").to_lowercase();
    if !MICROSOFT_TOKEN_HOSTS.contains(&host.as_str()) {
        return Err("token_endpoint must be a Microsoft login endpoint".to_owned());
    }
    Ok(parsed.to_string())
}

fn query_string(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn apply_headers(
    builder: reqwest::RequestBuilder,
    headers: Vec<(String, String)>,
) -> reqwest::RequestBuilder {
    let mut builder = builder;
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
}

// ─── Headers ────────────────────────────────────────────────────────────────

fn sso_oidc_headers() -> Vec<(String, String)> {
    vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
        ("connection".to_owned(), "close".to_owned()),
        ("amz-sdk-request".to_owned(), "attempt=1; max=4".to_owned()),
        (
            "amz-sdk-invocation-id".to_owned(),
            Uuid::new_v4().to_string(),
        ),
        ("user-agent".to_owned(), build_kiro_sso_user_agent()),
        (
            "x-amz-user-agent".to_owned(),
            build_kiro_sso_amz_user_agent(),
        ),
    ]
}

fn social_service_headers(machine_id: Option<&str>) -> Vec<(String, String)> {
    let device = match machine_id {
        Some(machine_id) => format!("KiroIDE-{KIRO_IDE_VERSION}-{machine_id}"),
        None => "KiroIDE".to_owned(),
    };
    vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
        ("connection".to_owned(), "close".to_owned()),
        ("user-agent".to_owned(), device.clone()),
        ("x-amz-user-agent".to_owned(), device),
    ]
}

fn browser_registration_headers() -> Vec<(String, String)> {
    vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
        ("user-agent".to_owned(), build_kiro_sso_user_agent()),
        (
            "x-amz-user-agent".to_owned(),
            build_kiro_sso_amz_user_agent(),
        ),
        ("amz-sdk-request".to_owned(), "attempt=1; max=4".to_owned()),
        (
            "amz-sdk-invocation-id".to_owned(),
            Uuid::new_v4().to_string(),
        ),
    ]
}

// ─── HTTP helpers ───────────────────────────────────────────────────────────

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

async fn read_json_response(response: reqwest::Response, label: &str) -> Result<Value, String> {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "{label} request failed ({}): {}",
            status.as_u16(),
            truncate(&text, 500)
        ));
    }
    serde_json::from_str(&text).map_err(|_| format!("{label} returned invalid JSON"))
}

async fn read_json_body(response: reqwest::Response) -> Map<String, Value> {
    let text = response.text().await.unwrap_or_default();
    if text.trim().is_empty() {
        return Map::new();
    }
    safe_json(&text)
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn flow_error(message: impl Into<String>) -> String {
    message.into()
}

// ─── Exchange results ───────────────────────────────────────────────────────

fn exchange_result(
    access: &str,
    refresh: &str,
    expires_at_ms: i64,
    auth_state: Value,
    account_label: Option<&str>,
    client_secret: Option<&str>,
) -> Value {
    let mut map = Map::new();
    map.insert("access".into(), json!(access));
    map.insert("refresh".into(), json!(refresh));
    map.insert("expiresAt".into(), expiry_value(expires_at_ms));
    if let Some(label) = account_label {
        map.insert("accountLabel".into(), json!(label));
    }
    map.insert("auth_state".into(), auth_state);
    if let Some(secret) = client_secret {
        map.insert("client_secret".into(), json!(secret));
    }
    Value::Object(map)
}

// ─── Login field declarations ───────────────────────────────────────────────

/// Fields the browser flow asks the operator for.
pub fn browser_login_fields() -> Value {
    json!([
        {
            "key": "idp",
            "label": "Identity provider",
            "required": true,
            "defaultValue": "google",
            "options": [
                {"value": "google", "label": "Google"},
                {"value": "github", "label": "GitHub"},
                {"value": "builder-id", "label": "AWS Builder ID"},
            ],
        }
    ])
}

/// Fields the device flow asks the operator for.
pub fn device_login_fields() -> Value {
    json!([
        {
            "key": "authMethod",
            "label": "Sign-in method",
            "required": true,
            "defaultValue": "builder-id",
            "options": [
                {"value": "builder-id", "label": "AWS Builder ID (personal)"},
                {"value": "idc", "label": "IAM Identity Center (organization)"},
            ],
        },
        {
            "key": "region",
            "label": "AWS region",
            "required": true,
            "defaultValue": DEFAULT_REGION,
            "placeholder": DEFAULT_REGION,
        },
        {
            "key": "startUrl",
            "label": "Organization start URL",
            "defaultValue": KIRO_DEFAULT_START_URL,
            "placeholder": KIRO_DEFAULT_START_URL,
        }
    ])
}

/// Fields the import flow asks the operator for.
pub fn import_fields() -> Value {
    json!([
        {
            "key": "authMethod",
            "label": "Credential type",
            "required": true,
            "defaultValue": "imported",
            "options": [
                {"value": "imported", "label": "Refresh token (Kiro social session)"},
                {"value": "idc", "label": "Refresh token (IAM Identity Center)"},
                {"value": "external_idp", "label": "Enterprise IdP export (JSON)"},
                {"value": "api_key", "label": "API key"},
            ],
        },
        {"key": "region", "label": "AWS region", "defaultValue": DEFAULT_REGION, "placeholder": DEFAULT_REGION},
        {"key": "clientId", "label": "OIDC client id (Identity Center only)"},
        {"key": "clientSecret", "label": "OIDC client secret (Identity Center only)", "secret": true},
        {"key": "profileArn", "label": "Profile ARN (optional)"},
    ])
}

// ─── Client registration ────────────────────────────────────────────────────

async fn register_client(
    client: &reqwest::Client,
    region: &str,
    redirect_uri: Option<&str>,
) -> Result<(String, String), String> {
    let url = format!("https://oidc.{region}.amazonaws.com/client/register");
    let mut body = Map::new();
    body.insert("clientName".into(), json!(KIRO_OIDC_CLIENT_NAME));
    body.insert("clientType".into(), json!("public"));
    body.insert("scopes".into(), json!(KIRO_SCOPES));
    body.insert(
        "grantTypes".into(),
        json!(if redirect_uri.is_some() {
            KIRO_BROWSER_GRANT_TYPES
        } else {
            KIRO_GRANT_TYPES
        }),
    );
    let headers = if let Some(redirect_uri) = redirect_uri {
        body.insert("issuerUrl".into(), json!(KIRO_BUILDER_ID_ISSUER));
        body.insert("redirectUris".into(), json!([redirect_uri]));
        browser_registration_headers()
    } else {
        sso_oidc_headers()
    };
    let builder = client.post(url).json(&Value::Object(body));
    let response = apply_headers(builder, headers)
        .send()
        .await
        .map_err(|error| flow_error(format!("Kiro client registration failed: {error}")))?;
    let label = if redirect_uri.is_some() {
        "kiro browser client registration"
    } else {
        "kiro client registration"
    };
    let payload = read_json_response(response, label).await?;
    let raw = payload.as_object();
    let client_id = non_empty_string(raw.and_then(|value| value.get("clientId")))
        .ok_or_else(|| flow_error("Kiro client registration omitted credentials"))?;
    let client_secret = non_empty_string(raw.and_then(|value| value.get("clientSecret")))
        .ok_or_else(|| flow_error("Kiro client registration omitted credentials"))?;
    Ok((client_id.to_owned(), client_secret.to_owned()))
}

// ─── Device flow ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DeviceFlowRegistration {
    client_id: String,
    client_secret: String,
    region: String,
    start_url: String,
    auth_method: String,
}

fn parameter<'a>(parameters: Option<&'a Value>, key: &str) -> Option<&'a str> {
    parameters?.get(key)?.as_str()
}

/// Registers a client and starts device authorization.
pub async fn start_kiro_device_auth(
    client: &reqwest::Client,
    parameters: Option<&Value>,
) -> Result<Value, String> {
    let region = normalize_region(parameters.and_then(|value| value.get("region")));
    let start_url = parameter(parameters, "startUrl")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(KIRO_DEFAULT_START_URL)
        .to_owned();
    let auth_method = if parameter(parameters, "authMethod") == Some("idc") {
        "idc"
    } else {
        "builder-id"
    };
    assert_aws_region(&region)?;

    let (client_id, client_secret) = register_client(client, &region, None).await?;
    let body = json!({
        "clientId": client_id,
        "clientSecret": client_secret,
        "startUrl": start_url,
    });
    let builder = client
        .post(format!(
            "https://oidc.{region}.amazonaws.com/device_authorization"
        ))
        .json(&body);
    let response = apply_headers(builder, sso_oidc_headers())
        .send()
        .await
        .map_err(|error| flow_error(format!("kiro device authorization failed: {error}")))?;
    let payload = read_json_response(response, "kiro device authorization").await?;
    let raw = payload.as_object().cloned().unwrap_or_default();
    let device_code = non_empty_string(raw.get("deviceCode"))
        .ok_or_else(|| flow_error("Kiro device authorization response omitted required fields"))?;
    let user_code = non_empty_string(raw.get("userCode"))
        .ok_or_else(|| flow_error("Kiro device authorization response omitted required fields"))?;
    let verification_uri = non_empty_string(raw.get("verificationUriComplete"))
        .or_else(|| non_empty_string(raw.get("verificationUri")))
        .ok_or_else(|| flow_error("Kiro device authorization response omitted required fields"))?;
    let interval = number_value(raw.get("interval"))
        .filter(|value| *value > 0.0)
        .map(|value| value.floor() as i64)
        .unwrap_or(5);
    let expires_in = number_value(raw.get("expiresIn"))
        .filter(|value| *value > 0.0)
        .map(|value| value.floor() as i64)
        .unwrap_or(900);
    let provider_state = json!({
        "clientId": client_id,
        "clientSecret": client_secret,
        "region": region,
        "startUrl": start_url,
        "authMethod": auth_method,
    })
    .to_string();
    Ok(json!({
        "verificationUri": verification_uri,
        "userCode": user_code,
        "deviceAuthId": device_code,
        "intervalSeconds": interval,
        "expiresInSeconds": expires_in,
        "providerState": provider_state,
    }))
}

fn parse_registration(value: Option<&Value>) -> Option<DeviceFlowRegistration> {
    let raw = record(value?)?;
    let client_id = non_empty_string(raw.get("clientId"))?.to_owned();
    let client_secret = non_empty_string(raw.get("clientSecret"))?.to_owned();
    let region = normalize_region(raw.get("region"));
    let start_url =
        non_empty_trimmed(raw.get("startUrl")).unwrap_or_else(|| KIRO_DEFAULT_START_URL.to_owned());
    let auth_method = if raw.get("authMethod").and_then(Value::as_str) == Some("idc") {
        "idc"
    } else {
        "builder-id"
    };
    Some(DeviceFlowRegistration {
        client_id,
        client_secret,
        region,
        start_url,
        auth_method: auth_method.to_owned(),
    })
}

/// Polls the AWS SSO OIDC token endpoint for the device flow.
pub async fn poll_kiro_device_auth(
    client: &reqwest::Client,
    device_auth_id: &str,
    provider_state: Option<&str>,
) -> Result<Value, String> {
    let registration = provider_state
        .and_then(safe_json)
        .as_ref()
        .and_then(|value| parse_registration(Some(value)));
    let Some(registration) = registration else {
        return Ok(json!({
            "status": "failed",
            "reason": "Kiro device flow is missing its client registration",
        }));
    };
    let body = json!({
        "clientId": registration.client_id,
        "clientSecret": registration.client_secret,
        "deviceCode": device_auth_id,
        "grantType": "urn:ietf:params:oauth:grant-type:device_code",
    });
    let builder = client
        .post(format!(
            "https://oidc.{}.amazonaws.com/token",
            registration.region
        ))
        .json(&body);
    let response = apply_headers(builder, sso_oidc_headers())
        .send()
        .await
        .map_err(|error| flow_error(format!("Kiro token polling failed: {error}")))?;
    let status = response.status();
    let payload = read_json_body(response).await;
    let error = non_empty_string(payload.get("error")).map(str::to_owned);
    let interval = number_value(payload.get("interval"));
    if error.as_deref() == Some("authorization_pending") {
        let mut verdict = Map::new();
        verdict.insert("status".into(), json!("pending"));
        if let Some(interval) = interval.filter(|value| *value > 0.0) {
            verdict.insert("retryAfterSeconds".into(), json!(interval));
        }
        return Ok(Value::Object(verdict));
    }
    if error.as_deref() == Some("slow_down") {
        let mut verdict = Map::new();
        verdict.insert("status".into(), json!("slow_down"));
        if let Some(interval) = interval.filter(|value| *value > 0.0) {
            verdict.insert("retryAfterSeconds".into(), json!(interval));
        }
        return Ok(Value::Object(verdict));
    }
    if !status.is_success() {
        let reason = non_empty_string(payload.get("error_description"))
            .map(str::to_owned)
            .or_else(|| error.clone())
            .unwrap_or_else(|| format!("token polling failed ({})", status.as_u16()));
        return Ok(json!({"status": "failed", "reason": reason}));
    }
    let Some(access) = non_empty_string(payload.get("accessToken")).map(str::to_owned) else {
        let reason = non_empty_string(payload.get("error_description"))
            .map(str::to_owned)
            .unwrap_or_else(|| "Kiro token response omitted accessToken".to_owned());
        return Ok(json!({"status": "failed", "reason": reason}));
    };
    let refresh = non_empty_string(payload.get("refreshToken"))
        .unwrap_or_default()
        .to_owned();
    let reported = non_empty_string(payload.get("profileArn")).map(str::to_owned);
    let profile_arn = match reported {
        Some(profile) => Some(profile),
        None => {
            fetch_kiro_profile_arn(
                client,
                &access,
                Some(registration.region.as_str()),
                Some(registration.auth_method.as_str()),
            )
            .await
        }
    };
    let state = KiroOAuthState {
        auth_method: registration.auth_method,
        region: registration.region,
        profile_arn,
        start_url: Some(registration.start_url),
        client_id: Some(registration.client_id),
        token_endpoint: None,
        scope: None,
        machine_id: Some(derive_oauth_machine_id(&refresh)),
    };
    let label = kiro_account_label(&access);
    Ok(json!({
        "status": "complete",
        "result": exchange_result(
            &access,
            &refresh,
            calculate_expiry(payload.get("expiresIn"), 3600),
            auth_state_value(&state),
            label.as_deref(),
            Some(&registration.client_secret),
        ),
    }))
}

// ─── Browser flow ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizeIdp {
    BuilderId,
    Github,
    Google,
}

fn read_authorize_idp(request: &Value) -> AuthorizeIdp {
    let parameters = request.get("parameters");
    let idp = parameters
        .and_then(|value| value.get("idp").or_else(|| value.get("provider")))
        .and_then(Value::as_str);
    match idp {
        Some("builder-id") => AuthorizeIdp::BuilderId,
        Some("github") => AuthorizeIdp::Github,
        _ => AuthorizeIdp::Google,
    }
}

fn read_exchange_idp(context: Option<&Value>) -> AuthorizeIdp {
    let parameters = context.and_then(|value| value.get("parameters"));
    if parameters
        .and_then(|value| value.get("idp"))
        .and_then(Value::as_str)
        == Some("builder-id")
    {
        AuthorizeIdp::BuilderId
    } else {
        AuthorizeIdp::Google
    }
}

fn builder_id_loopback_redirect(redirect_uri: &str) -> Result<String, String> {
    let url = url::Url::parse(redirect_uri)
        .map_err(|_| flow_error("Kiro redirect URI must be a valid URL"))?;
    let port = url
        .port()
        .map(|port| port.to_string())
        .unwrap_or_else(|| "80".to_owned());
    Ok(format!("http://127.0.0.1:{port}"))
}

/// Completes the provider-specific half of an authorize request.
pub async fn prepare_kiro_authorize(
    client: &reqwest::Client,
    request: &Value,
) -> Result<Value, String> {
    if read_authorize_idp(request) != AuthorizeIdp::BuilderId {
        return Ok(request.clone());
    }
    let parameters = request.get("parameters");
    let region = normalize_region(parameters.and_then(|value| value.get("region")));
    assert_aws_region(&region)?;
    let redirect_uri = request
        .get("redirectUri")
        .and_then(Value::as_str)
        .ok_or_else(|| flow_error("Kiro authorize request is missing redirectUri"))?;
    let loopback = builder_id_loopback_redirect(redirect_uri)?;
    let (client_id, client_secret) = register_client(client, &region, Some(&loopback)).await?;

    let mut updated = request.as_object().cloned().unwrap_or_default();
    updated.insert("redirectUri".into(), json!(loopback));
    let mut parameters = parameters
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    parameters.insert("idp".into(), json!("builder-id"));
    parameters.insert("region".into(), json!(region));
    parameters.insert("startUrl".into(), json!(KIRO_BUILDER_ID_ISSUER));
    parameters.insert("builderIdClientId".into(), json!(client_id));
    parameters.insert("builderIdClientSecret".into(), json!(client_secret));
    updated.insert("parameters".into(), Value::Object(parameters));
    Ok(Value::Object(updated))
}

/// Builds the authorize URL for the selected identity provider.
pub fn build_kiro_authorize_url(request: &Value) -> Result<String, String> {
    match read_authorize_idp(request) {
        AuthorizeIdp::BuilderId => build_builder_id_authorize_url(request),
        AuthorizeIdp::Github => build_social_authorize_url(request, "Github"),
        AuthorizeIdp::Google => build_social_authorize_url(request, "Google"),
    }
}

fn build_social_authorize_url(request: &Value, idp: &str) -> Result<String, String> {
    let code_challenge = request
        .get("codeChallenge")
        .and_then(Value::as_str)
        .ok_or_else(|| flow_error("Kiro authorize request is missing codeChallenge"))?;
    let state = request
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| flow_error("Kiro authorize request is missing state"))?;
    let query = query_string(&[
        ("idp", idp),
        ("redirect_uri", KIRO_SOCIAL_REDIRECT_URI),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("prompt", "select_account"),
    ]);
    Ok(format!("{KIRO_AUTH_SERVICE}/login?{query}"))
}

fn build_builder_id_authorize_url(request: &Value) -> Result<String, String> {
    let parameters = request.get("parameters");
    let client_id = parameters
        .and_then(|value| value.get("builderIdClientId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            flow_error("Kiro Builder ID authorize is missing its client registration")
        })?;
    let region = assert_aws_region(&normalize_region(
        parameters.and_then(|value| value.get("region")),
    ))?;
    let redirect_uri = request
        .get("redirectUri")
        .and_then(Value::as_str)
        .ok_or_else(|| flow_error("Kiro authorize request is missing redirectUri"))?;
    let state = request
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| flow_error("Kiro authorize request is missing state"))?;
    let code_challenge = request
        .get("codeChallenge")
        .and_then(Value::as_str)
        .ok_or_else(|| flow_error("Kiro authorize request is missing codeChallenge"))?;

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("client_id", client_id);
    serializer.append_pair("response_type", "code");
    serializer.append_pair("redirect_uri", redirect_uri);
    serializer.append_pair("state", state);
    serializer.append_pair("code_challenge", code_challenge);
    serializer.append_pair("code_challenge_method", "S256");
    for scope in KIRO_SCOPES {
        serializer.append_pair("scope", scope);
    }
    Ok(format!(
        "https://oidc.{region}.amazonaws.com/authorize?{}",
        serializer.finish()
    ))
}

/// Exchanges the pasted authorization code for tokens.
pub async fn exchange_kiro_code(
    client: &reqwest::Client,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    context: Option<&Value>,
) -> Result<Value, String> {
    if read_exchange_idp(context) == AuthorizeIdp::BuilderId {
        return exchange_builder_id_code(client, code, code_verifier, redirect_uri, context).await;
    }
    exchange_kiro_social_code(client, code, code_verifier).await
}

/// Exchanges a social authorization code for tokens.
pub async fn exchange_kiro_social_code(
    client: &reqwest::Client,
    code: &str,
    code_verifier: &str,
) -> Result<Value, String> {
    let body = json!({
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": KIRO_SOCIAL_REDIRECT_URI,
    });
    let builder = client
        .post(format!("{KIRO_AUTH_SERVICE}/oauth/token"))
        .json(&body);
    let response = apply_headers(builder, social_service_headers(None))
        .send()
        .await
        .map_err(|error| flow_error(format!("kiro social token exchange failed: {error}")))?;
    let payload = read_json_response(response, "kiro social token exchange").await?;
    let raw = payload.as_object().cloned().unwrap_or_default();
    let Some(access) = non_empty_string(raw.get("accessToken")).map(str::to_owned) else {
        let detail = non_empty_string(raw.get("error_description"))
            .or_else(|| non_empty_string(raw.get("error")))
            .map(|value| format!(": {value}"))
            .unwrap_or_default();
        return Err(flow_error(format!(
            "Kiro token exchange omitted accessToken{detail}"
        )));
    };
    let refresh = non_empty_string(raw.get("refreshToken"))
        .unwrap_or_default()
        .to_owned();
    let profile_arn = non_empty_string(raw.get("profileArn")).map(str::to_owned);
    let state = KiroOAuthState {
        auth_method: "google".to_owned(),
        region: DEFAULT_REGION.to_owned(),
        profile_arn,
        start_url: None,
        client_id: None,
        token_endpoint: None,
        scope: None,
        machine_id: Some(derive_oauth_machine_id(&refresh)),
    };
    let label = kiro_account_label(&access);
    Ok(exchange_result(
        &access,
        &refresh,
        calculate_expiry(raw.get("expiresIn"), 3600),
        auth_state_value(&state),
        label.as_deref(),
        None,
    ))
}

async fn exchange_builder_id_code(
    client: &reqwest::Client,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    context: Option<&Value>,
) -> Result<Value, String> {
    let parameters = context.and_then(|value| value.get("parameters"));
    let client_id = parameters
        .and_then(|value| value.get("builderIdClientId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| flow_error("Kiro Builder ID exchange is missing its client registration"))?;
    let client_secret = parameters
        .and_then(|value| value.get("builderIdClientSecret"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| flow_error("Kiro Builder ID exchange is missing its client registration"))?;
    let region = assert_aws_region(&normalize_region(
        parameters.and_then(|value| value.get("region")),
    ))?;
    let body = json!({
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": "authorization_code",
        "code": code,
        "redirectUri": redirect_uri,
        "codeVerifier": code_verifier,
    });
    let builder = client
        .post(format!("https://oidc.{region}.amazonaws.com/token"))
        .json(&body)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("user-agent", build_kiro_sso_user_agent());
    let response = builder
        .send()
        .await
        .map_err(|error| flow_error(format!("kiro Builder ID token exchange failed: {error}")))?;
    let payload = read_json_response(response, "kiro Builder ID token exchange").await?;
    let raw = payload.as_object().cloned().unwrap_or_default();
    let Some(access) = non_empty_string(raw.get("accessToken")).map(str::to_owned) else {
        let detail = non_empty_string(raw.get("error_description"))
            .or_else(|| non_empty_string(raw.get("error")))
            .map(|value| format!(": {value}"))
            .unwrap_or_default();
        return Err(flow_error(format!(
            "Kiro Builder ID token exchange omitted accessToken{detail}"
        )));
    };
    let refresh = non_empty_string(raw.get("refreshToken"))
        .unwrap_or_default()
        .to_owned();
    let profile_arn = non_empty_string(raw.get("profileArn")).map(str::to_owned);
    let state = KiroOAuthState {
        auth_method: "builder-id".to_owned(),
        region,
        profile_arn,
        start_url: Some(KIRO_BUILDER_ID_ISSUER.to_owned()),
        client_id: Some(client_id.to_owned()),
        token_endpoint: None,
        scope: None,
        machine_id: Some(derive_oauth_machine_id(&refresh)),
    };
    let label = kiro_account_label(&access);
    Ok(exchange_result(
        &access,
        &refresh,
        calculate_expiry(raw.get("expiresIn"), 3600),
        auth_state_value(&state),
        label.as_deref(),
        Some(client_secret),
    ))
}

// ─── Imports ────────────────────────────────────────────────────────────────

/// Completes a login from pasted credential material.
pub async fn import_kiro_credential(
    client: &reqwest::Client,
    credential: &str,
    fields: &Value,
) -> Result<Value, String> {
    let auth_method =
        non_empty_trimmed(fields.get("authMethod")).unwrap_or_else(|| "imported".to_owned());
    let credential = credential.trim();
    if credential.is_empty() {
        return Err(flow_error("Kiro credential material is required"));
    }
    match auth_method.as_str() {
        "api_key" => {
            validate_kiro_api_key(
                client,
                credential,
                fields.get("region").and_then(Value::as_str),
            )
            .await
        }
        "external_idp" => import_kiro_external_idp(&Value::String(credential.to_owned())),
        "idc" => {
            let options = json!({
                "clientId": non_empty_trimmed(fields.get("clientId")),
                "clientSecret": non_empty_trimmed(fields.get("clientSecret")),
                "region": fields.get("region").cloned().unwrap_or(Value::Null),
                "profileArn": non_empty_trimmed(fields.get("profileArn")),
            });
            import_kiro_refresh_token(client, credential, &options).await
        }
        "imported" => {
            let options = json!({
                "region": fields.get("region").cloned().unwrap_or(Value::Null),
                "profileArn": non_empty_trimmed(fields.get("profileArn")),
            });
            import_kiro_refresh_token(client, credential, &options).await
        }
        other => Err(flow_error(format!(
            "Unsupported Kiro credential type: {other}"
        ))),
    }
}

/// Imports a refresh token pasted from an existing Kiro session.
pub async fn import_kiro_refresh_token(
    client: &reqwest::Client,
    refresh_token: &str,
    options: &Value,
) -> Result<Value, String> {
    let refresh_token = refresh_token.trim();
    if refresh_token.is_empty() {
        return Err(flow_error("refresh token is required"));
    }
    let options = options.as_object();
    let client_id = options
        .and_then(|value| value.get("clientId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let client_secret = options
        .and_then(|value| value.get("clientSecret"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let is_idc = client_id.is_some() && client_secret.is_some();
    let region = normalize_region(options.and_then(|value| value.get("region")));
    let supplied_profile = options
        .and_then(|value| value.get("profileArn"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    let refreshed = if is_idc {
        refresh_oidc(
            client,
            refresh_token,
            client_id.unwrap_or_default(),
            client_secret.unwrap_or_default(),
            &region,
        )
        .await?
    } else {
        let machine_id = options
            .and_then(|value| value.get("machineId"))
            .and_then(|value| normalize_machine_id(Some(value)));
        refresh_social(client, refresh_token, machine_id.as_deref()).await?
    };
    let reported = match &refreshed.profile_arn {
        Some(profile) => Some(profile.clone()),
        None if is_idc => {
            fetch_kiro_profile_arn(client, &refreshed.access, Some(&region), Some("idc")).await
        }
        None => None,
    };
    let profile_arn = supplied_profile.or(reported);
    let state = KiroOAuthState {
        auth_method: if is_idc { "idc" } else { "imported" }.to_owned(),
        region,
        profile_arn,
        start_url: None,
        client_id: None,
        token_endpoint: None,
        scope: None,
        machine_id: Some(derive_oauth_machine_id(&refreshed.refresh)),
    };
    let label = kiro_account_label(&refreshed.access);
    Ok(exchange_result(
        &refreshed.access,
        &refreshed.refresh,
        refreshed.expires_at_ms,
        auth_state_value(&state),
        label.as_deref(),
        if is_idc { client_secret } else { None },
    ))
}

/// Imports an enterprise identity-provider credential from exported JSON.
pub fn import_kiro_external_idp(raw_auth: &Value) -> Result<Value, String> {
    let owned;
    let input = if let Value::String(text) = raw_auth {
        owned = safe_json(text).ok_or_else(|| flow_error("CLIProxyAPI auth JSON is invalid"))?;
        &owned
    } else {
        raw_auth
    };
    let raw = record(input).ok_or_else(|| flow_error("CLIProxyAPI auth JSON is required"))?;
    let auth_method = non_empty_trimmed(raw.get("auth_method").or_else(|| raw.get("authMethod")));
    if let Some(auth_method) = auth_method {
        if auth_method != "external_idp" {
            return Err(flow_error(
                "Only external_idp Kiro auth is supported by this importer",
            ));
        }
    }
    let access = non_empty_trimmed(raw.get("access_token").or_else(|| raw.get("accessToken")));
    let refresh = non_empty_trimmed(raw.get("refresh_token").or_else(|| raw.get("refreshToken")));
    let client_id = non_empty_trimmed(raw.get("client_id").or_else(|| raw.get("clientId")));
    let token_endpoint = validate_microsoft_token_endpoint(
        raw.get("token_endpoint")
            .or_else(|| raw.get("tokenEndpoint")),
    )?;
    let profile_arn = non_empty_trimmed(raw.get("profile_arn").or_else(|| raw.get("profileArn")));
    let region = normalize_region(raw.get("region"));
    let scope = normalize_scope(raw.get("scopes").or_else(|| raw.get("scope")));
    let access = access.ok_or_else(|| flow_error("access_token is required"))?;
    let refresh = refresh.ok_or_else(|| flow_error("refresh_token is required"))?;
    let client_id = client_id.ok_or_else(|| flow_error("client_id is required"))?;
    if scope.is_empty() {
        return Err(flow_error("scopes is required"));
    }
    let profile_arn = profile_arn.ok_or_else(|| flow_error("profile_arn is required"))?;
    let state = KiroOAuthState {
        auth_method: "external_idp".to_owned(),
        region,
        profile_arn: Some(profile_arn),
        start_url: None,
        client_id: Some(client_id),
        token_endpoint: Some(token_endpoint),
        scope: Some(scope),
        machine_id: Some(derive_oauth_machine_id(&refresh)),
    };
    let expires_at_ms = read_expiry(raw).unwrap_or_else(|| calculate_expiry(None, 3600));
    let label = kiro_account_label(&access);
    Ok(exchange_result(
        &access,
        &refresh,
        expires_at_ms,
        auth_state_value(&state),
        label.as_deref(),
        None,
    ))
}

/// Validates an API key against the surface it will actually be used on.
pub async fn validate_kiro_api_key(
    client: &reqwest::Client,
    api_key: &str,
    region: Option<&str>,
) -> Result<Value, String> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err(flow_error("API key is required"));
    }
    let region = match region {
        Some(region) => normalize_region(Some(&Value::String(region.to_owned()))),
        None => DEFAULT_REGION.to_owned(),
    };
    let region = assert_aws_region(&region)?;
    let machine_id = derive_api_key_machine_id(api_key);
    let body = format!(
        "https://q.{region}.amazonaws.com/ListAvailableModels?{}",
        query_string(&[("origin", "AI_EDITOR")])
    );
    let builder = client
        .get(body)
        .timeout(Duration::from_secs(15))
        .header("authorization", format!("Bearer {api_key}"))
        .header("tokentype", "API_KEY")
        .header("accept", "application/json")
        .header("connection", "close")
        .header("amz-sdk-request", "attempt=1; max=1")
        .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
        .header("x-amzn-kiro-agent-mode", "vibe")
        .header("x-amzn-codewhisperer-optout", "true")
        .header(
            "user-agent",
            build_kiro_user_agent(KIRO_IDE_VERSION, &machine_id),
        )
        .header(
            "x-amz-user-agent",
            build_kiro_amz_user_agent(KIRO_IDE_VERSION, &machine_id),
        );
    let response = builder
        .send()
        .await
        .map_err(|error| flow_error(format!("API key validation failed: {error}")))?;
    if !response.status().is_success() {
        return Err(flow_error(format!(
            "API key validation failed ({})",
            response.status().as_u16()
        )));
    }
    let payload: Value = response
        .json()
        .await
        .map_err(|_| flow_error("API key validation returned invalid JSON"))?;
    let models = payload.get("models").and_then(Value::as_array);
    if !models.is_some_and(|models| !models.is_empty()) {
        return Err(flow_error("API key returned no available models"));
    }
    let state = KiroOAuthState {
        auth_method: "api_key".to_owned(),
        region,
        profile_arn: None,
        start_url: None,
        client_id: None,
        token_endpoint: None,
        scope: None,
        machine_id: Some(machine_id),
    };
    Ok(exchange_result(
        api_key,
        "",
        now_ms() + 365 * 24 * 60 * 60 * 1000,
        auth_state_value(&state),
        None,
        None,
    ))
}

// ─── Profile resolution ─────────────────────────────────────────────────────

/// Resolves the profile ARN an account is bound to, via the CodeWhisperer
/// `ListAvailableProfiles` surface.
pub async fn fetch_kiro_profile_arn(
    client: &reqwest::Client,
    access_token: &str,
    region: Option<&str>,
    auth_method: Option<&str>,
) -> Option<String> {
    if auth_method == Some("builder-id") {
        return None;
    }
    let region = match region {
        Some(region) => normalize_region(Some(&Value::String(region.to_owned()))),
        None => DEFAULT_REGION.to_owned(),
    };
    let region = assert_aws_region(&region).ok()?;
    let response = client
        .post(format!("https://codewhisperer.{region}.amazonaws.com/"))
        .timeout(Duration::from_secs(15))
        .header("authorization", format!("Bearer {access_token}"))
        .header("content-type", "application/x-amz-json-1.0")
        .header(
            "x-amz-target",
            "AmazonCodeWhispererService.ListAvailableProfiles",
        )
        .header("accept", "application/json")
        .header("connection", "close")
        .header("amz-sdk-request", "attempt=1; max=1")
        .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
        .json(&json!({"maxResults": 10}))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let payload: Value = response.json().await.ok()?;
    let profiles = payload.get("profiles").and_then(Value::as_array)?;
    let mut fallback: Option<String> = None;
    for entry in profiles {
        let profile = entry.as_object();
        let arn = profile
            .and_then(|value| value.get("arn").or_else(|| value.get("profileArn")))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(arn) = arn else {
            continue;
        };
        if arn.contains(&format!(":{region}:")) {
            return Some(arn.to_owned());
        }
        if fallback.is_none() {
            fallback = Some(arn.to_owned());
        }
    }
    fallback
}

// ─── Refresh ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Refreshed {
    access: String,
    refresh: String,
    expires_at_ms: i64,
    profile_arn: Option<String>,
}

/// Refreshes an account's access token.
pub async fn refresh_kiro_token(
    client: &reqwest::Client,
    refresh_token: &str,
    auth_state: Option<&Value>,
    client_secret: Option<&str>,
) -> Result<Value, String> {
    let state = parse_kiro_auth_state(auth_state);
    if state.as_ref().map(|state| state.auth_method.as_str()) == Some("external_idp") {
        let state = state.expect("checked above");
        let endpoint_value = state.token_endpoint.clone().map(Value::String);
        let token_endpoint = validate_microsoft_token_endpoint(endpoint_value.as_ref())?;
        let client_id = state.client_id.ok_or_else(|| {
            flow_error("Kiro enterprise refresh is missing its client configuration")
        })?;
        let scope = state.scope.ok_or_else(|| {
            flow_error("Kiro enterprise refresh is missing its client configuration")
        })?;
        let body = query_string(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("refresh_token", refresh_token),
            ("scope", scope.as_str()),
        ]);
        let response = client
            .post(&token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| {
                flow_error(format!("kiro enterprise token refresh failed: {error}"))
            })?;
        let payload = read_json_response(response, "kiro enterprise token refresh").await?;
        let raw = payload.as_object().cloned().unwrap_or_default();
        let access = non_empty_string(raw.get("access_token"))
            .map(str::to_owned)
            .ok_or_else(|| flow_error("Kiro enterprise refresh omitted access_token"))?;
        let refresh = non_empty_string(raw.get("refresh_token")).map(str::to_owned);
        let mut result = Map::new();
        result.insert("access".into(), json!(access));
        if let Some(refresh) = refresh {
            result.insert("refresh".into(), json!(refresh));
        }
        result.insert(
            "expiresAt".into(),
            expiry_value(calculate_expiry(raw.get("expires_in"), 3600)),
        );
        return Ok(Value::Object(result));
    }

    if matches!(
        state.as_ref().map(|state| state.auth_method.as_str()),
        Some("idc") | Some("builder-id")
    ) {
        let state = state.expect("checked above");
        let client_id = state.client_id.clone().ok_or_else(|| {
            flow_error("Kiro device-flow refresh is missing its client registration")
        })?;
        let client_secret = client_secret.ok_or_else(|| {
            flow_error("Kiro device-flow refresh is missing its client registration")
        })?;
        let refreshed = refresh_oidc(
            client,
            refresh_token,
            &client_id,
            client_secret,
            &state.region,
        )
        .await?;
        let profile_arn = refreshed
            .profile_arn
            .clone()
            .or_else(|| state.profile_arn.clone());
        let next_state = KiroOAuthState {
            profile_arn,
            ..state
        };
        let mut result = Map::new();
        result.insert("access".into(), json!(refreshed.access));
        result.insert("refresh".into(), json!(refreshed.refresh));
        result.insert("expiresAt".into(), expiry_value(refreshed.expires_at_ms));
        result.insert("auth_state".into(), auth_state_value(&next_state));
        return Ok(Value::Object(result));
    }

    let refreshed = refresh_social(
        client,
        refresh_token,
        state.as_ref().and_then(|state| state.machine_id.as_deref()),
    )
    .await?;
    let mut result = Map::new();
    result.insert("access".into(), json!(refreshed.access));
    result.insert("refresh".into(), json!(refreshed.refresh));
    result.insert("expiresAt".into(), expiry_value(refreshed.expires_at_ms));
    if let Some(state) = state {
        let profile_arn = refreshed
            .profile_arn
            .clone()
            .or_else(|| state.profile_arn.clone());
        let next_state = KiroOAuthState {
            profile_arn,
            ..state
        };
        result.insert("auth_state".into(), auth_state_value(&next_state));
    }
    Ok(Value::Object(result))
}

async fn refresh_oidc(
    client: &reqwest::Client,
    refresh_token: &str,
    client_id: &str,
    client_secret: &str,
    region: &str,
) -> Result<Refreshed, String> {
    let region = assert_aws_region(region)?;
    let headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
        ("user-agent".to_owned(), build_kiro_sso_user_agent()),
        (
            "x-amz-user-agent".to_owned(),
            build_kiro_sso_amz_user_agent(),
        ),
        ("amz-sdk-request".to_owned(), "attempt=1; max=4".to_owned()),
        (
            "amz-sdk-invocation-id".to_owned(),
            Uuid::new_v4().to_string(),
        ),
    ];
    let body = json!({
        "clientId": client_id,
        "clientSecret": client_secret,
        "refreshToken": refresh_token,
        "grantType": "refresh_token",
    });
    let builder = client
        .post(format!("https://oidc.{region}.amazonaws.com/token"))
        .json(&body);
    let response = apply_headers(builder, headers)
        .send()
        .await
        .map_err(|error| flow_error(format!("kiro token refresh failed: {error}")))?;
    let payload = read_json_response(response, "kiro token refresh").await?;
    let raw = payload.as_object().cloned().unwrap_or_default();
    let access = non_empty_string(raw.get("accessToken"))
        .map(str::to_owned)
        .ok_or_else(|| flow_error("Kiro token refresh omitted accessToken"))?;
    Ok(Refreshed {
        access,
        refresh: non_empty_string(raw.get("refreshToken"))
            .unwrap_or(refresh_token)
            .to_owned(),
        expires_at_ms: calculate_expiry(raw.get("expiresIn"), 3600),
        profile_arn: non_empty_string(raw.get("profileArn")).map(str::to_owned),
    })
}

async fn refresh_social(
    client: &reqwest::Client,
    refresh_token: &str,
    machine_id: Option<&str>,
) -> Result<Refreshed, String> {
    let builder = client
        .post(format!("{KIRO_AUTH_SERVICE}/refreshToken"))
        .json(&json!({"refreshToken": refresh_token}));
    let response = apply_headers(builder, social_service_headers(machine_id))
        .send()
        .await
        .map_err(|error| flow_error(format!("kiro token refresh failed: {error}")))?;
    let payload = read_json_response(response, "kiro token refresh").await?;
    let raw = payload.as_object().cloned().unwrap_or_default();
    let access = non_empty_string(raw.get("accessToken"))
        .map(str::to_owned)
        .ok_or_else(|| flow_error("Kiro token refresh omitted accessToken"))?;
    Ok(Refreshed {
        access,
        refresh: non_empty_string(raw.get("refreshToken"))
            .unwrap_or(refresh_token)
            .to_owned(),
        expires_at_ms: calculate_expiry(raw.get("expiresIn"), 3600),
        profile_arn: non_empty_string(raw.get("profileArn")).map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_aws_regions() {
        assert_eq!(
            normalize_region(Some(&json!("eu-west-2"))),
            "eu-west-2".to_owned()
        );
        assert_eq!(
            normalize_region(Some(&json!("not-a-region"))),
            "us-east-1".to_owned()
        );
        assert!(assert_aws_region("us-east-1").is_ok());
        assert!(assert_aws_region("us-east-1.evil").is_err());
    }

    #[test]
    fn parses_the_account_auth_state() {
        let state = parse_kiro_auth_state(Some(&json!({
            "authMethod": "idc",
            "region": "eu-central-1",
            "profileArn": "arn:profile",
            "clientId": "client",
            "startUrl": "https://example.awsapps.com/start",
            "machineId": "a".repeat(64),
        })))
        .expect("state parses");
        assert_eq!(state.auth_method, "idc");
        assert_eq!(state.region, "eu-central-1");
        assert_eq!(state.profile_arn.as_deref(), Some("arn:profile"));
        let expected_machine = "a".repeat(64);
        assert_eq!(state.machine_id.as_deref(), Some(expected_machine.as_str()));
        assert!(parse_kiro_auth_state(Some(&json!({"authMethod": "nope"}))).is_none());
    }

    #[test]
    fn validates_microsoft_token_endpoints() {
        assert_eq!(
            validate_microsoft_token_endpoint(Some(&json!(
                "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
            )))
            .expect("allowed"),
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
        );
        assert!(
            validate_microsoft_token_endpoint(Some(&json!(
                "http://login.microsoftonline.com/token"
            )))
            .is_err()
        );
        assert!(
            validate_microsoft_token_endpoint(Some(&json!("https://attacker.example/token")))
                .is_err()
        );
        assert!(validate_microsoft_token_endpoint(None).is_err());
    }

    #[test]
    fn builds_social_and_builder_authorize_urls() {
        let social = json!({
            "state": "state-1",
            "codeChallenge": "challenge",
            "redirectUri": "http://127.0.0.1:1455/cb",
            "parameters": {"idp": "github"},
        });
        let url = build_kiro_authorize_url(&social).expect("social url");
        assert!(url.starts_with("https://prod.us-east-1.auth.desktop.kiro.dev/login?"));
        assert!(url.contains("idp=Github"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("prompt=select_account"));

        let builder = json!({
            "state": "state-1",
            "codeChallenge": "challenge",
            "redirectUri": "http://127.0.0.1:1455",
            "parameters": {
                "idp": "builder-id",
                "region": "eu-west-1",
                "builderIdClientId": "client",
            },
        });
        let url = build_kiro_authorize_url(&builder).expect("builder url");
        assert!(url.starts_with("https://oidc.eu-west-1.amazonaws.com/authorize?"));
        assert!(url.contains("scope=codewhisperer%3Acompletions"));
    }

    #[test]
    fn derives_the_builder_id_loopback_redirect() {
        assert_eq!(
            builder_id_loopback_redirect("http://127.0.0.1:1455/cb").expect("valid"),
            "http://127.0.0.1:1455"
        );
        assert_eq!(
            builder_id_loopback_redirect("http://127.0.0.1/cb").expect("valid"),
            "http://127.0.0.1:80"
        );
    }

    #[test]
    fn decodes_a_jwt_label() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"email":"person@example.com"}"#);
        let token = format!("header.{payload}.signature");
        assert_eq!(
            kiro_account_label(&token).as_deref(),
            Some("person@example.com")
        );
        assert!(kiro_account_label("not-a-jwt").is_none());
    }

    #[test]
    fn imports_an_enterprise_auth_export() {
        let result = import_kiro_external_idp(&json!({
            "auth_method": "external_idp",
            "access_token": "access",
            "refresh_token": "refresh",
            "client_id": "client",
            "token_endpoint": "https://login.microsoftonline.com/tenant/token",
            "profile_arn": "arn:profile",
            "region": "eu-west-1",
            "scope": "openid offline_access",
        }))
        .expect("import succeeds");
        assert_eq!(result["access"], json!("access"));
        assert_eq!(result["refresh"], json!("refresh"));
        assert_eq!(result["auth_state"]["authMethod"], json!("external_idp"));
        assert_eq!(result["auth_state"]["region"], json!("eu-west-1"));
        assert_eq!(
            result["auth_state"]["tokenEndpoint"],
            json!("https://login.microsoftonline.com/tenant/token")
        );
        assert!(result["expiresAt"].as_str().is_some());
    }

    #[test]
    fn rejects_an_incomplete_enterprise_export() {
        let error = import_kiro_external_idp(&json!({
            "access_token": "access",
            "client_id": "client",
            "token_endpoint": "https://login.microsoftonline.com/tenant/token",
            "profile_arn": "arn:profile",
            "scope": "openid",
        }))
        .expect_err("incomplete export is refused");
        assert!(error.contains("refresh_token is required"));
    }

    #[test]
    fn normalizes_scope_lists() {
        assert_eq!(
            normalize_scope(Some(&json!(["openid", " offline_access ", 7]))),
            "openid offline_access"
        );
        assert_eq!(
            normalize_scope(Some(&json!(" openid offline_access "))),
            "openid offline_access"
        );
    }

    #[test]
    fn reads_relative_and_absolute_expiry() {
        let relative = read_expiry(&Map::from_iter([("expires_in".to_owned(), json!(60))]))
            .expect("relative expiry");
        assert!(relative > now_ms());
        let absolute = read_expiry(&Map::from_iter([(
            "expires_at".to_owned(),
            json!("2030-01-01T00:00:00Z"),
        )]))
        .expect("absolute expiry");
        assert!(absolute > now_ms());
    }
}
