//! Upstream quota collectors used by the console refresh routes.
//!
//! Codex, Claude, and Grok expose billing/usage surfaces; every other
//! credential-bearing provider is checked against its OpenAI-compatible
//! `/models` endpoint, which validates the key without inventing windows.

use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(15);

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|error| format!("quota client: {error}"))
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn number(value: Option<&Value>) -> Option<f64> {
    value.and_then(|value| value.as_f64().or_else(|| value.as_str()?.parse().ok()))
}

fn iso(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(raw) => DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|value| value.with_timezone(&Utc).to_rfc3339()),
        Value::Number(raw) => {
            let seconds = raw.as_i64()?;
            if seconds > 1_000_000_000_000 {
                Utc.timestamp_millis_opt(seconds)
                    .single()
                    .map(|value| value.to_rfc3339())
            } else {
                Utc.timestamp_opt(seconds, 0)
                    .single()
                    .map(|value| value.to_rfc3339())
            }
        }
        _ => None,
    }
}

fn percent_window(kind: &str, label: &str, used: Option<f64>, resets: Option<String>) -> Value {
    let used = used.map(|value| value.clamp(0.0, 100.0));
    json!({
        "kind": kind,
        "label": label,
        "usedPercent": used,
        "remainingPercent": used.map(|value| 100.0 - value),
        "resetsAt": resets,
        "used": Value::Null,
        "limit": Value::Null,
        "remaining": Value::Null,
        "recurring": true,
    })
}

fn access_token(credential: &str) -> String {
    serde_json::from_str::<Value>(credential)
        .ok()
        .and_then(|value| {
            text(value.get("accessToken"))
                .or_else(|| text(value.get("access_token")))
                .or_else(|| text(value.get("token")))
        })
        .unwrap_or_else(|| credential.to_owned())
}

fn jwt_account_id(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    text(value.get("chatgpt_account_id")).or_else(|| {
        value
            .get("https://api.openai.com/auth")
            .and_then(|auth| text(auth.get("chatgpt_account_id")))
    })
}

fn result(source: &str, plan: Option<String>, windows: Vec<Value>, error: Option<String>) -> Value {
    json!({"source": source, "plan": plan, "windows": windows, "error": error})
}

async fn get_json(
    client: &reqwest::Client,
    url: &str,
    headers: &[(&str, String)],
) -> Result<(reqwest::StatusCode, Value), String> {
    let mut request = client.get(url).header("accept", "application/json");
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("quota request: {error}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let value = serde_json::from_str(&body).unwrap_or(Value::Null);
    Ok((status, value))
}

fn windows_from_codex(body: &Value) -> Vec<Value> {
    let now = Utc::now();
    let mut windows = Vec::new();
    let rate = body.get("rate_limit").unwrap_or(body);
    for (key, fallback) in [
        ("primary_window", "Primary"),
        ("secondary_window", "Secondary"),
    ] {
        let Some(window) = rate.get(key) else {
            continue;
        };
        let used = number(window.get("used_percent"));
        let duration = number(window.get("limit_window_seconds"));
        let reset = iso(window.get("reset_at")).or_else(|| {
            let seconds = number(window.get("reset_after_seconds"))?;
            Some((now + chrono::Duration::milliseconds((seconds * 1000.0) as i64)).to_rfc3339())
        });
        if used.is_none() && reset.is_none() {
            continue;
        }
        let kind = match duration {
            Some(value) if value <= 21_600.0 => "session",
            Some(value) if value <= 86_400.0 => "daily",
            _ => "weekly",
        };
        let label = duration
            .map(|value| format!("{} Hour", (value / 3600.0).round().max(1.0) as i64))
            .unwrap_or_else(|| fallback.to_owned());
        windows.push(percent_window(kind, &label, used, reset));
    }
    windows
}

fn windows_from_claude(body: &Value) -> Vec<Value> {
    let fixed = [
        ("five_hour", "session", "5 Hour"),
        ("seven_day", "weekly", "7 Day"),
        ("seven_day_opus", "weekly_opus", "7 Day (Opus)"),
        ("seven_day_sonnet", "weekly_sonnet", "7 Day (Sonnet)"),
    ];
    let mut windows = Vec::new();
    for (key, kind, label) in fixed {
        let Some(window) = body.get(key) else {
            continue;
        };
        let used = number(window.get("utilization")).or_else(|| number(window.get("percent")));
        let reset = iso(window.get("resets_at"));
        if used.is_some() || reset.is_some() {
            windows.push(percent_window(kind, label, used, reset));
        }
    }
    if let Some(limits) = body.get("limits").and_then(Value::as_array) {
        for limit in limits {
            let kind = text(limit.get("kind")).unwrap_or_else(|| "limit".to_owned());
            let used = number(limit.get("percent")).or_else(|| number(limit.get("utilization")));
            let reset = iso(limit.get("resets_at"));
            windows.push(percent_window(&kind, &kind.replace('_', " "), used, reset));
        }
    }
    windows
}

fn windows_from_grok(body: &Value) -> Vec<Value> {
    let payload = body.get("config").unwrap_or(body);
    let mut windows = Vec::new();
    if let Some(period) = payload.get("currentPeriod") {
        let start = iso(period.get("start"));
        let end = iso(period.get("end"));
        if start.is_some() && end.is_some() {
            let used = number(payload.get("creditUsagePercent"));
            windows.push(percent_window("1w", "SuperGrok Weekly Credits", used, end));
        }
    }
    let limit = number(payload.get("monthlyLimit"));
    let used = number(payload.get("used"));
    if let (Some(limit), Some(used)) = (limit, used) {
        if limit > 0.0 && used >= 0.0 {
            windows.push(percent_window(
                "1mo",
                "SuperGrok Monthly Included",
                Some((used / limit) * 100.0),
                iso(payload.get("billingPeriodEnd")),
            ));
        }
    }
    windows
}

pub async fn collect(
    provider_id: &str,
    credential: &str,
    auth_state: Option<&Value>,
    credential_kind: &str,
) -> Value {
    let client = match client() {
        Ok(client) => client,
        Err(error) => return result(provider_id, None, Vec::new(), Some(error)),
    };
    match provider_id {
        "codex" => {
            let credential = access_token(credential);
            let accounted = credential.as_str();
            let account = auth_state
                .and_then(|state| text(state.get("providerAccountId")))
                .or_else(|| auth_state.and_then(|state| text(state.get("accountId"))))
                .or_else(|| jwt_account_id(accounted));
            let mut headers = vec![("authorization", format!("Bearer {credential}"))];
            if let Some(account) = account {
                headers.push(("chatgpt-account-id", account));
            }
            match get_json(
                &client,
                "https://chatgpt.com/backend-api/wham/usage",
                &headers,
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let plan = text(body.get("plan_type"));
                    result("codex", plan, windows_from_codex(&body), None)
                }
                Ok((status, _)) => result(
                    "codex",
                    None,
                    Vec::new(),
                    Some(format!("quota endpoint returned HTTP {status}")),
                ),
                Err(error) => result("codex", None, Vec::new(), Some(error)),
            }
        }
        "claude" => {
            let credential = access_token(credential);
            let headers = vec![
                ("authorization", format!("Bearer {credential}")),
                ("anthropic-beta", "oauth-2025-04-20".to_owned()),
                ("anthropic-version", "2023-06-01".to_owned()),
                ("x-app", "cli".to_owned()),
            ];
            match get_json(
                &client,
                "https://api.anthropic.com/api/oauth/usage",
                &headers,
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let plan = text(body.get("plan_type")).or_else(|| text(body.get("plan")));
                    result("claude", plan, windows_from_claude(&body), None)
                }
                Ok((status, _)) => result(
                    "claude",
                    None,
                    Vec::new(),
                    Some(format!("quota endpoint returned HTTP {status}")),
                ),
                Err(error) => result("claude", None, Vec::new(), Some(error)),
            }
        }
        "grok" | "xai" => {
            let credential = access_token(credential);
            let headers = vec![
                ("authorization", format!("Bearer {credential}")),
                ("x-xai-token-auth", "xai-grok-cli".to_owned()),
            ];
            match get_json(
                &client,
                "https://cli-chat-proxy.grok.com/v1/billing?format=credits",
                &headers,
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    result("grok", None, windows_from_grok(&body), None)
                }
                Ok((status, _)) => result(
                    "grok",
                    None,
                    Vec::new(),
                    Some(format!("quota endpoint returned HTTP {status}")),
                ),
                Err(error) => result("grok", None, Vec::new(), Some(error)),
            }
        }
        "kiro" => keyla_providers::kiro::fetch_kiro_quota(&client, credential, auth_state).await,
        "cb" | "cbcn" | "workbuddy" => {
            keyla_providers::buddy::fetch_quota(&client, provider_id, credential, auth_state).await
        }
        "devin" => match keyla_providers::devin::fetch_devin_quota(&client, credential).await {
            Ok(value) => value,
            Err(error) => result("devin", None, Vec::new(), Some(error.message)),
        },
        "antigravity" => {
            keyla_providers::antigravity_oauth::fetch_antigravity_quota(&client, credential, None)
                .await
        }
        "mimostudio" => {
            let parsed = match keyla_providers::mimostudio::parse_credential(credential) {
                Ok(value) => value,
                Err(error) => {
                    return result(
                        "mimostudio",
                        Some("MiMo Studio".to_owned()),
                        Vec::new(),
                        Some(error.message),
                    );
                }
            };
            let cookie = keyla_providers::mimostudio::cookie_header(&parsed);
            let headers = vec![
                ("cookie", cookie),
                ("origin", "https://aistudio.xiaomimimo.com".to_owned()),
                ("referer", "https://aistudio.xiaomimimo.com/".to_owned()),
                (
                    "user-agent",
                    keyla_providers::mimostudio::USER_AGENT.to_owned(),
                ),
            ];
            match get_json(
                &client,
                "https://aistudio.xiaomimimo.com/open-apis/v1/user/usage",
                &headers,
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let mut quota = keyla_providers::mimostudio::parse_usage(&body);
                    if quota
                        .get("windows")
                        .and_then(Value::as_array)
                        .is_none_or(|windows| windows.is_empty())
                    {
                        quota["error"] =
                            json!("Unexpected response format from MiMo Studio usage endpoint");
                    }
                    quota
                }
                Ok((status, _)) => result(
                    "mimostudio",
                    Some("MiMo Studio".to_owned()),
                    Vec::new(),
                    Some(format!("MiMo Studio usage returned HTTP {status}")),
                ),
                Err(error) => result(
                    "mimostudio",
                    Some("MiMo Studio".to_owned()),
                    Vec::new(),
                    Some(error),
                ),
            }
        }
        "mimodesktop" => {
            let parsed = match keyla_providers::mimodesktop::parse_credential(credential) {
                Ok(value) => value,
                Err(error) => {
                    return result(
                        "mimodesktop",
                        Some("Xiaomi MiMo Desktop".to_owned()),
                        Vec::new(),
                        Some(error.message),
                    );
                }
            };
            let cookie = match keyla_providers::mimodesktop::acquire_session(
                &client,
                &parsed,
                "https://mimo-server-sgp.xiaomimimo.com",
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    return result(
                        "mimodesktop",
                        Some("Xiaomi MiMo Desktop".to_owned()),
                        Vec::new(),
                        Some(error.message),
                    );
                }
            };
            let headers = vec![
                ("cookie", cookie),
                (
                    "user-agent",
                    keyla_providers::mimodesktop::MIMO_API_UA.to_owned(),
                ),
                ("x-mimo-source", "mimocode-cli-free".to_owned()),
            ];
            match get_json(
                &client,
                "https://mimo-server-sgp.xiaomimimo.com/api/user/usage",
                &headers,
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    keyla_providers::mimodesktop::parse_usage(&body)
                }
                Ok((status, _)) => result(
                    "mimodesktop",
                    Some("Xiaomi MiMo Desktop".to_owned()),
                    Vec::new(),
                    Some(format!("Usage API returned HTTP {status}")),
                ),
                Err(error) => result(
                    "mimodesktop",
                    Some("Xiaomi MiMo Desktop".to_owned()),
                    Vec::new(),
                    Some(error),
                ),
            }
        }
        _ => {
            let Some(base) = keyla_providers::provider_base_url(provider_id) else {
                return result(
                    provider_id,
                    None,
                    Vec::new(),
                    Some(
                        "No quota collector or API base URL is configured for this provider."
                            .to_owned(),
                    ),
                );
            };
            if credential_kind == "none" {
                return result(
                    provider_id,
                    None,
                    Vec::new(),
                    Some("No credential is stored for this account.".to_owned()),
                );
            }
            match get_json(
                &client,
                &format!("{base}/models"),
                &[("authorization", format!("Bearer {credential}"))],
            )
            .await
            {
                Ok((status, _)) if status.is_success() => {
                    result(provider_id, None, Vec::new(), None)
                }
                Ok((status, _))
                    if status == reqwest::StatusCode::UNAUTHORIZED
                        || status == reqwest::StatusCode::FORBIDDEN =>
                {
                    result(
                        provider_id,
                        None,
                        Vec::new(),
                        Some("API key is invalid or revoked.".to_owned()),
                    )
                }
                Ok((status, _)) => result(
                    provider_id,
                    None,
                    Vec::new(),
                    Some(format!("Connectivity check failed: HTTP {status}.")),
                ),
                Err(error) => result(provider_id, None, Vec::new(), Some(error)),
            }
        }
    }
}

/// Lowest remaining percent across percent windows, and total absolute credit.
pub fn summaries(quota: &Value) -> (Option<f64>, Option<f64>) {
    let windows = quota.get("windows").and_then(Value::as_array);
    let mut percent: Option<f64> = None;
    let mut credit: Option<f64> = None;
    for window in windows.into_iter().flatten() {
        if let Some(value) = number(window.get("remainingPercent")) {
            percent = Some(percent.map_or(value, |current| current.min(value)));
        }
        let limit = number(window.get("limit")).filter(|value| *value > 0.0);
        if let Some(limit) = limit {
            let remaining = number(window.get("remaining"))
                .or_else(|| number(window.get("used")).map(|used| limit - used));
            if let Some(remaining) = remaining {
                credit = Some(credit.unwrap_or(0.0) + remaining.clamp(0.0, limit));
            }
        }
    }
    (percent, credit)
}

#[cfg(test)]
mod tests {
    use super::{summaries, windows_from_claude, windows_from_codex, windows_from_grok};
    use serde_json::json;

    #[test]
    fn codex_windows_map_duration_to_kind() {
        let windows = windows_from_codex(&json!({
            "plan_type": "plus",
            "rate_limit": {
                "primary_window": {"used_percent": 25, "limit_window_seconds": 18000, "reset_at": "2026-11-12T00:00:00Z"},
                "secondary_window": {"used_percent": 80, "limit_window_seconds": 604800}
            }
        }));
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0]["kind"], "session");
        assert_eq!(windows[0]["remainingPercent"], 75.0);
        assert_eq!(windows[1]["kind"], "weekly");
    }

    #[test]
    fn claude_fixed_windows_and_limits_are_emitted() {
        let windows = windows_from_claude(&json!({
            "five_hour": {"utilization": 10, "resets_at": "2026-11-12T00:00:00Z"},
            "seven_day": {"utilization": 40},
            "limits": [{"kind": "weekly_all", "percent": 55}]
        }));
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0]["kind"], "session");
        assert_eq!(windows[1]["remainingPercent"], 60.0);
        assert_eq!(windows[2]["kind"], "weekly_all");
    }

    #[test]
    fn grok_monthly_used_maps_to_percent_and_credit() {
        let windows = windows_from_grok(&json!({
            "billingPeriodEnd": "2026-12-01T00:00:00Z",
            "monthlyLimit": 100,
            "used": 25
        }));
        assert_eq!(windows[0]["usedPercent"], 25.0);
        let quota = json!({"windows": windows});
        let (percent, credit) = summaries(&quota);
        assert_eq!(percent, Some(75.0));
        assert_eq!(credit, None);
    }
}
