//! Credential redaction at publication/storage boundaries, never on the
//! provider wire. Port of `src/observability/redaction.ts`.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

const REDACTED: &str = "[redacted]";

static SECRET_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:authorization|proxyauthorization|cookie|setcookie|xapikey|apikey|secret|clientsecret|password|passwd|credential|accesstoken|refreshtoken|idtoken|bearer|token|keyencrypted)$",
    )
    .expect("secret field pattern is valid")
});
static BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+").expect("bearer pattern is valid")
});
static PREFIXED_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sk-|rk-|gh[pousr]_|github_pat_)[A-Za-z0-9_-]{8,}\b")
        .expect("prefixed key pattern is valid")
});
static GOOGLE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bAIza[A-Za-z0-9_-]{20,}\b").expect("google key pattern is valid")
});
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
        .expect("jwt pattern is valid")
});
static URL_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\bhttps?://)[^/?@\s]+@").expect("url userinfo pattern is valid")
});
static KEY_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(\b(?:api[-_ ]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|client[-_]?secret|password|secret)\b["']?\s*[:=]\s*["']?)[^\s"',;}&]+"#,
    )
    .expect("key assignment pattern is valid")
});
static COOKIE_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\b(?:set-)?cookie:\s*)[^\r\n]+").expect("cookie pattern is valid")
});

/// Preserve diagnostic text while removing credential-bearing substrings.
pub fn redact_text(value: &str) -> String {
    let mut text = BEARER
        .replace_all(value, |captures: &regex::Captures<'_>| {
            format!("{} {REDACTED}", &captures[1])
        })
        .into_owned();
    text = PREFIXED_KEY.replace_all(&text, REDACTED).into_owned();
    text = GOOGLE_KEY.replace_all(&text, REDACTED).into_owned();
    text = JWT.replace_all(&text, REDACTED).into_owned();
    text = URL_USERINFO
        .replace_all(&text, "${1}[redacted]@")
        .into_owned();
    text = KEY_ASSIGNMENT
        .replace_all(&text, |captures: &regex::Captures<'_>| {
            format!("{}{REDACTED}", &captures[1])
        })
        .into_owned();
    COOKIE_HEADER
        .replace_all(&text, |captures: &regex::Captures<'_>| {
            format!("{}{REDACTED}", &captures[1])
        })
        .into_owned()
}

fn is_secret_field(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|ch| !matches!(ch, '-' | '_' | ' '))
        .collect();
    SECRET_FIELD.is_match(&normalized)
}

/// Copy only diagnostic data; sensitive fields and excessive depth cannot
/// cross the boundary.
pub fn redact_value(value: &Value) -> Value {
    redact_value_at(value, 0)
}

fn redact_value_at(value: &Value, depth: usize) -> Value {
    match value {
        Value::String(text) => Value::String(redact_text(text)),
        Value::Array(entries) => {
            if depth > 16 {
                return Value::String("[truncated]".into());
            }
            Value::Array(
                entries
                    .iter()
                    .map(|entry| redact_value_at(entry, depth + 1))
                    .collect(),
            )
        }
        Value::Object(map) => {
            if depth > 16 {
                return Value::String("[truncated]".into());
            }
            let mut out = Map::new();
            for (key, entry) in map {
                out.insert(
                    key.clone(),
                    if is_secret_field(key) {
                        Value::String(REDACTED.into())
                    } else {
                        redact_value_at(entry, depth + 1)
                    },
                );
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Masks a client IP for presentation: IPv4 keeps the first three octets
/// (`203.0.113.xxx`), IPv6 the first four hextets. Unparseable input is fully
/// masked; empty input stays empty.
pub fn mask_client_ip(value: Option<&str>) -> Option<String> {
    let value = value?;
    let ip = value.trim();
    if ip.is_empty() {
        return Some(ip.to_owned());
    }
    let last_colon = ip.rfind(':');
    let tail = last_colon.map(|index| &ip[index + 1..]).unwrap_or("");
    if tail.contains('.') {
        let octets: Vec<&str> = tail.split('.').collect();
        if octets.len() == 4 && octets.iter().all(|part| is_ipv4_octet(part)) {
            let prefix = last_colon.map(|index| &ip[..=index]).unwrap_or("");
            return Some(format!("{}{}.xxx", prefix, octets[..3].join(".")));
        }
        return Some("***".into());
    }
    if ip.contains(':') {
        let parts: Vec<&str> = ip.split(':').collect();
        return Some(if parts.len() >= 4 {
            format!("{}:xxxx", parts[..4].join(":"))
        } else {
            "xxxx".into()
        });
    }
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() == 4 && octets.iter().all(|part| is_ipv4_octet(part)) {
        return Some(format!("{}.xxx", octets[..3].join(".")));
    }
    Some("***".into())
}

fn is_ipv4_octet(part: &str) -> bool {
    !part.is_empty() && part.len() <= 3 && part.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bearer_and_prefixed_keys_are_redacted() {
        assert_eq!(
            redact_text("Authorization: Bearer abc.def-_123"),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(
            redact_text("key sk-abcdefghijkl leaked"),
            "key [redacted] leaked"
        );
        assert_eq!(
            redact_text("token github_pat_11ABCDEFG0123456789"),
            "token [redacted]"
        );
        assert_eq!(redact_text("AIzaSyA1234567890abcdefghij"), "[redacted]");
    }

    #[test]
    fn jwt_and_url_userinfo_are_redacted() {
        assert_eq!(redact_text("eyJhbGciOi.eyJzdWIiOi.sig_part"), "[redacted]");
        assert_eq!(
            redact_text("fetch https://user:pass@example.test/x"),
            "fetch https://[redacted]@example.test/x"
        );
    }

    #[test]
    fn key_assignments_and_cookies_are_redacted() {
        assert_eq!(redact_text("api_key=super-secret"), "api_key=[redacted]");
        assert_eq!(
            redact_text("password: \"hunter2\""),
            "password: \"[redacted]\""
        );
        assert_eq!(
            redact_text("Cookie: session=abcdef; theme=dark"),
            "Cookie: [redacted]"
        );
    }

    #[test]
    fn secret_object_fields_are_masked_recursively() {
        let value = json!({
            "authorization": "Bearer abc",
            "nested": {"client-secret": "xyz", "safe": "sk-123456789abc"},
            "list": [{"apiKey": "k"}, 3, true]
        });
        let redacted = redact_value(&value);
        assert_eq!(redacted["authorization"], "[redacted]");
        assert_eq!(redacted["nested"]["client-secret"], "[redacted]");
        assert_eq!(redacted["nested"]["safe"], "[redacted]");
        assert_eq!(redacted["list"][0]["apiKey"], "[redacted]");
        assert_eq!(redacted["list"][1], 3);
    }

    #[test]
    fn client_ip_masking_keeps_the_readable_prefix() {
        assert_eq!(
            mask_client_ip(Some("203.0.113.7")).as_deref(),
            Some("203.0.113.xxx")
        );
        assert_eq!(
            mask_client_ip(Some("::ffff:203.0.113.7")).as_deref(),
            Some("::ffff:203.0.113.xxx")
        );
        assert_eq!(
            mask_client_ip(Some("2001:db8:85a3:8d3:1319:8a2e")).as_deref(),
            Some("2001:db8:85a3:8d3:xxxx")
        );
        assert_eq!(mask_client_ip(Some("not-an-ip")).as_deref(), Some("***"));
        assert_eq!(mask_client_ip(None), None);
    }
}
