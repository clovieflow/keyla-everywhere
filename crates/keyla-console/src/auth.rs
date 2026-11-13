//! Console authentication primitives: argon2 passwords, hashed session
//! tokens, login lockouts, first-boot setup, and cookie mechanics.
//! Port of `src/console/auth/service.ts` and the pure part of
//! `src/security/csrf.ts`.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use keyla_core::GatewayError;
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Map, Value, json};
use sqlx::postgres::PgPool;
use sqlx::{Row, postgres::PgRow};

use keyla_security::hash_secret;

pub const SESSION_COOKIE_NAME: &str = "session_token";
pub const CSRF_COOKIE_NAME: &str = "csrf_token";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";
pub const SESSION_MAX_AGE_SECONDS: u64 = 48 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCookiePolicy {
    pub max_age: u64,
    pub http_only: bool,
    pub same_site: &'static str,
    pub secure: bool,
}

pub fn default_session_cookie_policy(public_origin: Option<&str>) -> SessionCookiePolicy {
    let secure = public_origin.is_some_and(|origin| origin.starts_with("https://"));
    SessionCookiePolicy {
        max_age: SESSION_MAX_AGE_SECONDS,
        http_only: true,
        same_site: "Lax",
        secure,
    }
}

pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("setup already completed")]
    SetupAlreadyCompleted,
    #[error(transparent)]
    Crypto(#[from] keyla_security::CryptoError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("{0}")]
    Hash(String),
}

/// Hashes a console password with argon2id (64 MiB, t=3), matching the
/// parameters Bun's native implementation uses.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    if password.is_empty() {
        return Err(AuthError::EmptyPassword);
    }
    let salt = SaltString::generate(&mut OsRng);
    let params =
        Params::new(65_536, 3, 1, None).map_err(|error| AuthError::Hash(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::Hash(error.to_string()))
}

/// Constant-time verification against an argon2id PHC string. Anything else —
/// malformed, foreign scheme, undecodable — is an ordinary failed login.
pub fn verify_password(password: &str, hash: &str) -> bool {
    if !hash.starts_with("$argon2id$") {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[derive(Debug, Clone)]
pub struct ConsoleUser {
    pub id: String,
    pub tenant_id: String,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub is_platform_admin: bool,
    pub is_first_boot: bool,
}

#[derive(Debug, Clone)]
pub struct ConsoleSession {
    pub id: String,
    pub user_id: String,
    pub expires_at_ms: i64,
}

fn user_from_row(row: &PgRow) -> ConsoleUser {
    ConsoleUser {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        username: row.get("username"),
        email: row.get("email"),
        password_hash: row.get("password_hash"),
        display_name: row.get("display_name"),
        is_active: row.get("is_active"),
        is_platform_admin: row.get("is_platform_admin"),
        is_first_boot: row.get("is_first_boot"),
    }
}

const USER_COLUMNS: &str = "id::text AS id, tenant_id::text AS tenant_id, username, email,
    password_hash, display_name, is_active, is_platform_admin, is_first_boot";

pub async fn find_user_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<ConsoleUser>, sqlx::Error> {
    let sql = format!("SELECT {USER_COLUMNS} FROM console_users WHERE username = $1 LIMIT 1");
    let row = sqlx::query(&sql)
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(user_from_row))
}

pub async fn find_user_by_id(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<ConsoleUser>, sqlx::Error> {
    let sql = format!("SELECT {USER_COLUMNS} FROM console_users WHERE id = $1::uuid LIMIT 1");
    let row = sqlx::query(&sql).bind(user_id).fetch_optional(pool).await?;
    Ok(row.as_ref().map(user_from_row))
}

pub async fn has_any_user(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM console_users")
        .fetch_one(pool)
        .await?;
    Ok(count > 0)
}

pub async fn create_session(
    pool: &PgPool,
    user_id: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    policy: SessionCookiePolicy,
) -> Result<(String, ConsoleSession), AuthError> {
    let raw_token = new_token();
    let token_hash = hash_secret(&raw_token)?;
    let id = new_uuid();
    let expires_at_ms = now_millis() + (policy.max_age as i64) * 1000;
    sqlx::query(
        "INSERT INTO console_sessions
           (id, user_id, session_token, ip_address, user_agent, expires_at)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, to_timestamp($6::double precision / 1000))",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(ip_address)
    .bind(user_agent)
    .bind(expires_at_ms)
    .execute(pool)
    .await?;
    Ok((
        raw_token,
        ConsoleSession {
            id,
            user_id: user_id.to_owned(),
            expires_at_ms,
        },
    ))
}

pub async fn validate_session(
    pool: &PgPool,
    session_token: &str,
) -> Result<Option<ConsoleSession>, AuthError> {
    if session_token.is_empty() {
        return Ok(None);
    }
    let token_hash = hash_secret(session_token)?;
    let row = sqlx::query(
        "SELECT id::text AS id, user_id::text AS user_id,
                (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint AS expires_at_ms
         FROM console_sessions
         WHERE session_token = $1 AND expires_at > now()
         LIMIT 1",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| ConsoleSession {
        id: row.get("id"),
        user_id: row.get("user_id"),
        expires_at_ms: row.get("expires_at_ms"),
    }))
}

pub async fn delete_session(pool: &PgPool, session_token: &str) -> Result<(), AuthError> {
    if session_token.is_empty() {
        return Ok(());
    }
    let token_hash = hash_secret(session_token)?;
    sqlx::query("DELETE FROM console_sessions WHERE session_token = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_other_sessions(
    pool: &PgPool,
    user_id: &str,
    except_session_id: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM console_sessions
         WHERE user_id = $1::uuid AND id <> $2::uuid",
    )
    .bind(user_id)
    .bind(except_session_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn remaining_lock_seconds(pool: &PgPool, key: &str) -> Result<u64, sqlx::Error> {
    let locked_until: Option<f64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM locked_until) * 1000)::float8
         FROM console_lockouts WHERE ip = $1 LIMIT 1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?
    .flatten();
    let Some(locked_until) = locked_until else {
        return Ok(0);
    };
    let remaining = locked_until - now_millis() as f64;
    Ok(if remaining > 0.0 {
        (remaining / 1000.0).ceil() as u64
    } else {
        0
    })
}

/// Records one failure, returning `true` when this failure locked the key.
pub async fn record_failure(
    pool: &PgPool,
    key: &str,
    reason: &str,
    max_failures: i64,
    failure_window_ms: i64,
    lockout_ms: i64,
) -> Result<bool, sqlx::Error> {
    if remaining_lock_seconds(pool, key).await? > 0 {
        return Ok(true);
    }
    let now = now_millis();
    let window_until = now + failure_window_ms;
    let count: i64 = sqlx::query_scalar(
        "INSERT INTO console_lockouts (ip, failure_count, window_until, reason, updated_at)
         VALUES ($1, 1, to_timestamp($2::double precision / 1000), $3, now())
         ON CONFLICT (ip) DO UPDATE SET
           failure_count = CASE
             WHEN console_lockouts.window_until > now() THEN console_lockouts.failure_count + 1
             ELSE 1 END,
           window_until = CASE
             WHEN console_lockouts.window_until > now() THEN console_lockouts.window_until
             ELSE excluded.window_until END,
           reason = excluded.reason,
           updated_at = now()
         RETURNING failure_count::bigint",
    )
    .bind(key)
    .bind(window_until)
    .bind(reason)
    .fetch_one(pool)
    .await?;
    if count < max_failures {
        return Ok(false);
    }
    let locked_until = now + lockout_ms;
    sqlx::query(
        "UPDATE console_lockouts
         SET locked_until = to_timestamp($2::double precision / 1000), updated_at = now()
         WHERE ip = $1",
    )
    .bind(key)
    .bind(locked_until)
    .execute(pool)
    .await?;
    let mut detail = Map::new();
    detail.insert("ip".into(), json!(key));
    detail.insert("reason".into(), json!(reason));
    detail.insert("failed_attempts".into(), json!(count));
    detail.insert("ttl_seconds".into(), json!(lockout_ms / 1000));
    detail.insert("banned_until".into(), json!(locked_until));
    detail.insert("enforcement".into(), json!("full_network_lockout"));
    let _ = sqlx::query(
        "INSERT INTO admin_audit_log (actor, action, target, detail)
         VALUES ('system:ip_guard', 'security.ip_banned', $1, $2)",
    )
    .bind(format!("ip:{key}"))
    .bind(Value::Object(detail))
    .execute(pool)
    .await;
    Ok(true)
}

pub async fn clear_failures(pool: &PgPool, key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM console_lockouts WHERE ip = $1")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

pub const DEFAULT_API_KEY_LABEL: &str = "Default";
pub const TENANT_KEY_SCOPES: [&str; 9] = [
    "routing:invoke",
    "routing:cli_mapping",
    "search:invoke",
    "dashboard:read",
    "dashboard:write",
    "providers:read",
    "providers:write",
    "models:read",
    "models:write",
];

/// First-boot initialization under an advisory transaction lock.
pub async fn complete_setup(
    pool: &PgPool,
    password: &str,
    username: Option<&str>,
    display_name: Option<&str>,
    default_api_key: Option<&str>,
) -> Result<(), AuthError> {
    if password.is_empty() {
        return Err(AuthError::EmptyPassword);
    }
    let password_hash = hash_password(password)?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('keyla:first_boot_setup'))")
        .execute(&mut *transaction)
        .await?;
    let existing: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM console_users")
        .fetch_one(&mut *transaction)
        .await?;
    if existing > 0 {
        return Err(AuthError::SetupAlreadyCompleted);
    }
    let tenant_id: Option<String> = sqlx::query_scalar("SELECT id::text FROM tenants LIMIT 1")
        .fetch_optional(&mut *transaction)
        .await?;
    let tenant_id = match tenant_id {
        Some(id) => id,
        None => {
            let id = new_uuid();
            sqlx::query(
                "INSERT INTO tenants (id, name, status) VALUES ($1::uuid, 'Default', 'active')",
            )
            .bind(&id)
            .execute(&mut *transaction)
            .await?;
            id
        }
    };
    let admin_username = username
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("admin");
    let user_id = new_uuid();
    sqlx::query(
        "INSERT INTO console_users
           (id, tenant_id, username, email, password_hash, display_name, is_first_boot,
            is_active, is_platform_admin)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, false, true, true)",
    )
    .bind(&user_id)
    .bind(&tenant_id)
    .bind(admin_username)
    .bind(format!("{admin_username}@localhost"))
    .bind(&password_hash)
    .bind(
        display_name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("Administrator"),
    )
    .execute(&mut *transaction)
    .await?;
    if let Some(api_key) = default_api_key.filter(|key| !key.is_empty()) {
        let key_hash = hash_secret(api_key)?;
        let exists: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM api_keys WHERE tenant_id = $1::uuid AND key_hash = $2",
        )
        .bind(&tenant_id)
        .bind(&key_hash)
        .fetch_one(&mut *transaction)
        .await?;
        if exists == 0 {
            let encrypted = keyla_security::encrypt_credential(api_key.as_bytes())?;
            let prefix: String = api_key.chars().take(3).collect();
            sqlx::query(
                "INSERT INTO api_keys
                   (id, tenant_id, key_hash, label, scopes, key_prefix, key_encrypted,
                    requests_per_minute)
                 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, 240)",
            )
            .bind(new_uuid())
            .bind(&tenant_id)
            .bind(&key_hash)
            .bind(DEFAULT_API_KEY_LABEL)
            .bind(serde_json::to_value(TENANT_KEY_SCOPES).unwrap_or(Value::Array(Vec::new())))
            .bind(&prefix)
            .bind(&encrypted)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    Ok(())
}

// ─── Cookies ────────────────────────────────────────────────────────────────

pub fn parse_cookie(header: Option<&str>, name: &str) -> Option<String> {
    let header = header?;
    for part in header.split(';') {
        let Some(index) = part.find('=') else {
            continue;
        };
        if part[..index].trim() == name {
            let value = part[index + 1..].trim();
            return (!value.is_empty()).then(|| value.to_owned());
        }
    }
    None
}

pub fn session_cookie(policy: SessionCookiePolicy, value: &str) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}={value}; Path=/; Max-Age={}; HttpOnly; SameSite={}",
        policy.max_age, policy.same_site
    );
    if policy.secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_session_cookie(policy: SessionCookiePolicy) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; \
         HttpOnly; SameSite={}",
        policy.same_site
    );
    if policy.secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn csrf_cookie(policy: SessionCookiePolicy, value: &str) -> String {
    let mut cookie = format!(
        "{CSRF_COOKIE_NAME}={value}; Path=/; Max-Age={}; SameSite={}",
        policy.max_age, policy.same_site
    );
    if policy.secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_csrf_cookie(policy: SessionCookiePolicy) -> String {
    let mut cookie = format!(
        "{CSRF_COOKIE_NAME}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; \
         SameSite={}",
        policy.same_site
    );
    if policy.secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Double-submit validation: header must equal the cookie, timing-safe.
pub fn csrf_valid(cookie_header: Option<&str>, csrf_header: Option<&str>) -> bool {
    let Some(cookie) = parse_cookie(cookie_header, CSRF_COOKIE_NAME) else {
        return false;
    };
    let Some(header) = csrf_header else {
        return false;
    };
    let a = cookie.as_bytes();
    let b = header.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Console route error envelope (`{"error": {...}}` via GatewayError).
pub fn console_error(message: impl Into<String>) -> GatewayError {
    GatewayError::new(
        keyla_core::GatewayErrorCode::InvalidRequest,
        400,
        message,
        Map::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_round_trip_and_reject_foreign_hashes() {
        let hash = hash_password("123456").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("123456", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("123456", "sha256:abc"));
        assert!(!verify_password("123456", "not-a-hash"));
    }

    #[test]
    fn cookies_parse_and_secure_policy_is_explicit() {
        let header = "a=1; session_token=abc; csrf_token=xyz";
        assert_eq!(
            parse_cookie(Some(header), SESSION_COOKIE_NAME).as_deref(),
            Some("abc")
        );
        assert!(parse_cookie(Some(header), "missing").is_none());
        let policy = default_session_cookie_policy(Some("https://example.test"));
        assert!(policy.secure);
        assert!(session_cookie(policy, "v").contains("Secure"));
        assert!(clear_session_cookie(policy).contains("Max-Age=0"));
        assert!(!default_session_cookie_policy(None).secure);
    }

    #[test]
    fn csrf_requires_an_exact_match() {
        let cookie = "csrf_token=abc";
        assert!(csrf_valid(Some(cookie), Some("abc")));
        assert!(!csrf_valid(Some(cookie), Some("abd")));
        assert!(!csrf_valid(Some(cookie), None));
        assert!(!csrf_valid(None, Some("abc")));
    }
}
