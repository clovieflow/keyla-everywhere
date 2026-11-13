//! Xiaomi MiMo Desktop credential and SSO session handshake.
//!
//! The inference endpoint authenticates with an SSO cookie jar, never a bearer
//! token: a stored `passToken` is exchanged through Xiaomi's passport service
//! for `serviceToken` plus session cookies. Ported from
//! `src/providers/integrations/xiaomi-mimo/mimodesktop-*`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use keyla_core::{GatewayError, GatewayErrorCode};
use reqwest::header::LOCATION;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use uuid::Uuid;

pub const MIMO_API_UA: &str = "miNative PC/Normal Windows_NT/10.0.19045 SDKV/1.0.0 DEVT/PC DEVS/Windows APP/miaccount_desktop APPV/0.1.0";
const MIMO_SSO_UA: &str = "MiClaw/1.0";
const CACHE_TTL: Duration = Duration::from_secs(25 * 60);

#[derive(Debug, Clone)]
pub struct Credentials {
    pub pass_token: String,
    pub user_id: Option<String>,
}

pub fn parse_credential(raw: &str) -> Result<Credentials, GatewayError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(auth_error("MiMo passToken is empty"));
    }
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let target = value
            .get("xiaomi")
            .filter(|nested| nested.is_object())
            .unwrap_or(&value);
        let pass = [
            "passToken",
            "passtoken",
            "pass_token",
            "refresh_token",
            "key",
            "token",
        ]
        .iter()
        .find_map(|key| target.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty());
        if let Some(pass) = pass {
            let user_id = ["userId", "userid", "uid"]
                .iter()
                .find_map(|key| target.get(*key))
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string().trim_matches('"').to_owned())
                });
            return Ok(Credentials {
                pass_token: pass.to_owned(),
                user_id,
            });
        }
    }
    Ok(Credentials {
        pass_token: trimmed.to_owned(),
        user_id: None,
    })
}

fn auth_error(message: &str) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::AuthenticationFailed,
        401,
        message,
        serde_json::Map::new(),
    )
}

fn signature(nonce: &str, ssecurity: Option<&str>) -> String {
    let mut material = format!("nonce={nonce}");
    if let Some(ssecurity) = ssecurity.filter(|value| !value.trim().is_empty()) {
        material.push('&');
        material.push_str(ssecurity);
    }
    let digest = Sha1::digest(material.as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
    percent_encode(&encoded)
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

fn cookie_header(jar: &HashMap<String, String>) -> String {
    jar.iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn absorb(response: &reqwest::Response, jar: &mut HashMap<String, String>) {
    for value in response.headers().get_all(reqwest::header::SET_COOKIE) {
        if let Ok(raw) = value.to_str() {
            if let Some((name, rest)) = raw.split_once('=') {
                let value = rest.split(';').next().unwrap_or("");
                jar.insert(name.trim().to_owned(), value.to_owned());
            }
        }
    }
}

fn json_body(text: &str) -> Result<Value, GatewayError> {
    let cleaned = text.strip_prefix("&&&START&&&").unwrap_or(text);
    serde_json::from_str(cleaned).map_err(|_| auth_error("Xiaomi SSO returned invalid JSON"))
}

fn cache() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn acquire_session(
    client: &reqwest::Client,
    credentials: &Credentials,
    api_base: &str,
) -> Result<String, GatewayError> {
    let api_base = api_base.trim_end_matches('/');
    let key = format!(
        "{:x}",
        Sha256::digest(format!("{api_base}:{}", credentials.pass_token).as_bytes())
    );
    {
        let store = cache().lock().unwrap_or_else(|error| error.into_inner());
        if let Some((cookie, expires)) = store.get(&key) {
            if *expires > Instant::now() {
                return Ok(cookie.clone());
            }
        }
    }
    let mut jar = HashMap::new();
    jar.insert("passToken".to_owned(), credentials.pass_token.clone());
    if let Some(user) = &credentials.user_id {
        jar.insert("userId".to_owned(), user.clone());
    }
    let response = client
        .get(format!("{api_base}/api/user/xiaomi/me"))
        .header("user-agent", MIMO_API_UA)
        .header("cookie", cookie_header(&jar))
        .send()
        .await
        .map_err(|error| auth_error(&format!("Xiaomi SSO Step 1 failed: {error}")))?;
    let redirect = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| auth_error("Xiaomi SSO Step 1 failed: missing redirect from me endpoint"))?;
    let parsed = url::Url::parse(&redirect)
        .map_err(|_| auth_error("Xiaomi SSO Step 1 returned an invalid redirect"))?;
    let sts_callback = parsed
        .query_pairs()
        .find(|(key, _)| key == "callback")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| auth_error("Xiaomi SSO Step 1 failed: missing callback query parameter"))?;
    let sid = parsed
        .query_pairs()
        .find(|(key, _)| key == "sid")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| "mimosgp".to_owned());
    let phase1 = client
        .get("https://account.xiaomi.com/pass/serviceLogin?sid=passportapi&_json=true")
        .header("cookie", cookie_header(&jar))
        .header("user-agent", MIMO_SSO_UA)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| auth_error(&format!("Xiaomi SSO Phase 1 failed: {error}")))?;
    let body1 = json_body(&phase1.text().await.unwrap_or_default())?;
    let nonce = body1
        .get("nonce")
        .map(|value| value.to_string().trim_matches('"').to_owned())
        .or_else(|| {
            body1
                .get("location")
                .and_then(Value::as_str)
                .and_then(|location| {
                    url::Url::parse(location)
                        .ok()?
                        .query_pairs()
                        .find(|(key, _)| key == "nonce")
                        .map(|(_, value)| value.into_owned())
                })
        })
        .ok_or_else(|| {
            auth_error(&format!(
                "Xiaomi SSO Phase 1 failed: code={}",
                body1
                    .get("code")
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ))
        })?;
    let ssecurity = body1.get("ssecurity").and_then(Value::as_str);
    let location = body1
        .get("location")
        .and_then(Value::as_str)
        .ok_or_else(|| auth_error("Xiaomi SSO Phase 1 failed: missing location"))?;
    let phase2_url = format!("{location}&clientSign={}", signature(&nonce, ssecurity));
    let phase2 = client
        .get(phase2_url)
        .header("cookie", cookie_header(&jar))
        .header("user-agent", MIMO_SSO_UA)
        .send()
        .await
        .map_err(|error| auth_error(&format!("Xiaomi SSO Phase 2 failed: {error}")))?;
    absorb(&phase2, &mut jar);
    let phase3 = client
        .get(format!(
            "https://account.xiaomi.com/pass/serviceLogin?sid={}&callback={}&_json=true",
            percent_encode(&sid),
            percent_encode(&sts_callback)
        ))
        .header("cookie", cookie_header(&jar))
        .header("user-agent", MIMO_SSO_UA)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| auth_error(&format!("Xiaomi SSO Phase 3 failed: {error}")))?;
    let body3 = json_body(&phase3.text().await.unwrap_or_default())?;
    let location3 = body3
        .get("location")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            auth_error(&format!(
                "Xiaomi SSO Phase 3 failed: code={}",
                body3
                    .get("code")
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ))
        })?;
    let sts = client
        .get(location3)
        .header("user-agent", MIMO_API_UA)
        .header("cookie", cookie_header(&jar))
        .send()
        .await
        .map_err(|error| auth_error(&format!("Xiaomi SSO callback failed: {error}")))?;
    absorb(&sts, &mut jar);
    let filtered: HashMap<String, String> = jar
        .into_iter()
        .filter(|(name, value)| {
            !value.is_empty()
                && (name.contains("serviceToken")
                    || name.contains("slh")
                    || name.contains("ph")
                    || name == "userId")
        })
        .collect();
    if !filtered.contains_key("serviceToken") {
        return Err(auth_error(
            "Xiaomi SSO failed to acquire serviceToken cookie",
        ));
    }
    let cookie = cookie_header(&filtered);
    cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(key, (cookie.clone(), Instant::now() + CACHE_TTL));
    Ok(cookie)
}

/// Reads passToken and identity cookies from the local MiMo Desktop profile.
///
/// The Electron client keeps its cookie database locked while running, so the
/// file is copied before opening. Missing columns/rows or a locked file return
/// `None`/an auth error rather than guessing a credential.
pub fn read_desktop_credentials() -> Result<Option<Credentials>, GatewayError> {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = if cfg!(target_os = "windows") {
        std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
            .join("Xiaomi MiMo AI/Partitions/xiaomi-account/Network/Cookies")
    } else if cfg!(target_os = "macos") {
        std::path::PathBuf::from(&home).join(
            "Library/Application Support/Xiaomi MiMo AI/Partitions/xiaomi-account/Network/Cookies",
        )
    } else {
        std::path::PathBuf::from(&home)
            .join(".config/Xiaomi MiMo AI/Partitions/xiaomi-account/Network/Cookies")
    };
    if !path.exists() {
        return Ok(None);
    }
    let temporary = std::env::temp_dir().join(format!(
        "mimo-cookies-{}-{}.db",
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    std::fs::copy(&path, &temporary).map_err(|_| {
        auth_error("Xiaomi MiMo AI Desktop is holding its session database locked. Quit MiMo Desktop completely, then retry.")
    })?;
    let result = (|| -> Result<Option<Credentials>, GatewayError> {
        let connection = rusqlite::Connection::open_with_flags(
            &temporary,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|error| auth_error(&format!("cannot read MiMo Desktop cookies: {error}")))?;
        let mut statement = connection
            .prepare("SELECT name, value FROM cookies WHERE host_key LIKE '%account.xiaomi.com'")
            .map_err(|error| auth_error(&format!("cannot query MiMo Desktop cookies: {error}")))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| auth_error(&format!("cannot read MiMo Desktop cookies: {error}")))?;
        let mut jar = std::collections::HashMap::new();
        for row in rows.flatten() {
            jar.insert(row.0, row.1);
        }
        let Some(pass_token) = jar
            .get("passToken")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        Ok(Some(Credentials {
            pass_token,
            user_id: jar
                .get("userId")
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
        }))
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

pub fn encode_credential(credentials: &Credentials) -> String {
    serde_json::json!({
        "passToken": credentials.pass_token,
        "userId": credentials.user_id,
    })
    .to_string()
}

pub fn parse_usage(payload: &Value) -> Value {
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let remaining = data.get("percent").and_then(Value::as_f64);
    let used = remaining.map(|value| ((100.0 - value).clamp(0.0, 100.0) * 10.0).round() / 10.0);
    let reset = data
        .get("resetAt")
        .and_then(Value::as_f64)
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds as i64, 0))
        .map(|value| value.to_rfc3339())
        .or_else(|| {
            data.get("resetDate")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let windows = if used.is_some() || reset.is_some() {
        vec![json!({
            "kind": "weekly", "label": "Weekly Quota",
            "usedPercent": used,
            "remainingPercent": used.map(|value| 100.0 - value),
            "resetsAt": reset, "used": Value::Null, "limit": Value::Null,
            "remaining": Value::Null, "recurring": true,
        })]
    } else {
        Vec::new()
    };
    json!({"source": "mimodesktop", "plan": "Xiaomi MiMo Desktop", "windows": windows, "error": Value::Null})
}

pub fn resolve_model(requested: &str) -> String {
    match requested.trim() {
        "mimo-x-flash" | "MiMo-X-Flash-Preview" | "mimo-flash" => "mimo-v2.6-flash",
        "mimo-x-pro" | "MiMo-X-Pro-Preview" | "mimo-pro" | "mimo-auto" => "mimo-v2.6-pro",
        other => other,
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{encode_credential, parse_credential, parse_usage, resolve_model};
    use serde_json::json;

    #[test]
    fn parses_raw_and_nested_credentials() {
        assert_eq!(parse_credential("pass-1").unwrap().pass_token, "pass-1");
        let parsed = parse_credential(r#"{"xiaomi":{"passToken":"pass-2","userId":9}}"#).unwrap();
        assert_eq!(parsed.pass_token, "pass-2");
        assert_eq!(parsed.user_id.as_deref(), Some("9"));
        assert!(encode_credential(&parsed).contains("pass-2"));
    }

    #[test]
    fn maps_desktop_aliases() {
        assert_eq!(resolve_model("mimo-x-pro"), "mimo-v2.6-pro");
        assert_eq!(resolve_model("MiMo-X-Flash-Preview"), "mimo-v2.6-flash");
        assert_eq!(resolve_model("custom"), "custom");
    }

    #[test]
    fn parses_remaining_percent_as_used_window() {
        let quota = parse_usage(&json!({"data": {"percent": 75, "resetAt": 1764547200}}));
        assert_eq!(quota["windows"][0]["usedPercent"], 25.0);
        assert_eq!(quota["windows"][0]["remainingPercent"], 75.0);
    }
}
