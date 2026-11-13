//! API-key authentication: token extraction, hashed lookup, authorization
//! snapshot, and the short-lived cache. Port of `src/security/api-key-auth.ts`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use keyla_core::{GatewayError, GatewayErrorCode};
use serde_json::{Map, Value};
use sqlx::postgres::PgPool;
use sqlx::{Row, postgres::PgRow};

use crate::crypto::{CryptoError, hash_secret};
use crate::model_access::ModelAccessMode;

const AUTH_CACHE_TTL: Duration = Duration::from_secs(3);
const AUTH_CACHE_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub struct ApiKeyAuthorizationSnapshot {
    pub api_key_id: String,
    pub tenant_id: String,
    pub admission_identity: String,
    pub model_access_mode: ModelAccessMode,
    pub model_list: Option<Vec<String>>,
    pub client_router_denylist: Option<Vec<String>>,
    pub rpm: Option<i64>,
    pub daily_tokens: Option<i64>,
    pub monthly_tokens: Option<i64>,
    pub lifetime_token_budget: Option<i64>,
    pub lifetime_tokens_consumed: Option<i64>,
    pub max_concurrent: Option<i64>,
    pub scopes: Vec<String>,
}

impl ApiKeyAuthorizationSnapshot {
    pub fn admission_identity(&self) -> &str {
        &self.admission_identity
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedApiKey {
    pub id: String,
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub snapshot: ApiKeyAuthorizationSnapshot,
    pub model_prefix: Option<String>,
    pub cli_mapping_owner_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApiKeyRow {
    pub id: String,
    pub tenant_id: String,
    pub key_mode: String,
    pub parent_key_id: Option<String>,
    pub label: String,
    pub scopes: Vec<String>,
    pub requests_per_minute: Option<i64>,
    pub daily_token_limit: Option<i64>,
    pub monthly_token_limit: Option<i64>,
    pub lifetime_token_budget: Option<i64>,
    pub lifetime_tokens_consumed: i64,
    pub max_concurrent_requests: Option<i64>,
    pub model_prefix: Option<String>,
    pub model_access_mode: ModelAccessMode,
    pub model_list: Option<Vec<String>>,
    pub client_router_denylist: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

fn string_list(value: Option<Value>) -> Option<Vec<String>> {
    value.and_then(|value| match value {
        Value::Array(entries) => Some(
            entries
                .into_iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect(),
        ),
        Value::Null => None,
        _ => None,
    })
}

fn row_to_key(row: &PgRow) -> ApiKeyRow {
    ApiKeyRow {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        key_mode: row.get("key_mode"),
        parent_key_id: row.get("parent_key_id"),
        label: row.get("label"),
        scopes: string_list(row.get::<Option<Value>, _>("scopes")).unwrap_or_default(),
        requests_per_minute: row.get("requests_per_minute"),
        daily_token_limit: row.get("daily_token_limit"),
        monthly_token_limit: row.get("monthly_token_limit"),
        lifetime_token_budget: row.get("lifetime_token_budget"),
        lifetime_tokens_consumed: row.get("lifetime_tokens_consumed"),
        max_concurrent_requests: row.get("max_concurrent_requests"),
        model_prefix: row.get("model_prefix"),
        model_access_mode: ModelAccessMode::parse(Some(
            row.get::<String, _>("model_access_mode").as_str(),
        )),
        model_list: string_list(row.get("model_list")),
        client_router_denylist: string_list(row.get("client_router_denylist")),
    }
}

const KEY_COLUMNS: &str = "id::text AS id, tenant_id::text AS tenant_id, key_mode,
    parent_key_id::text AS parent_key_id, label, scopes,
    requests_per_minute::bigint AS requests_per_minute,
    daily_token_limit, monthly_token_limit, lifetime_token_budget,
    lifetime_tokens_consumed, max_concurrent_requests::bigint AS max_concurrent_requests,
    model_prefix, model_access_mode, model_list, client_router_denylist";

async fn find_active_by_hash(pool: &PgPool, hash: &str) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {KEY_COLUMNS} FROM api_keys
         WHERE key_hash = $1 AND enabled = true AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > now())
         LIMIT 1"
    );
    let row = sqlx::query(&sql).bind(hash).fetch_optional(pool).await?;
    Ok(row.as_ref().map(row_to_key))
}

async fn find_active_by_id(pool: &PgPool, key_id: &str) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {KEY_COLUMNS} FROM api_keys
         WHERE id = $1::uuid AND enabled = true AND revoked_at IS NULL
         LIMIT 1"
    );
    let row = sqlx::query(&sql).bind(key_id).fetch_optional(pool).await?;
    Ok(row.as_ref().map(row_to_key))
}

async fn sum_children_consumed(pool: &PgPool, parent_key_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT coalesce(sum(lifetime_tokens_consumed), 0)::bigint
         FROM api_keys WHERE parent_key_id = $1::uuid",
    )
    .bind(parent_key_id)
    .fetch_one(pool)
    .await
}

struct AuthCache {
    entries: HashMap<String, (Instant, ResolvedApiKey)>,
    by_key: HashMap<String, HashSet<String>>,
    order: VecDeque<String>,
}

static AUTH_CACHE: Mutex<Option<AuthCache>> = Mutex::new(None);

fn with_cache<T>(f: impl FnOnce(&mut AuthCache) -> T) -> T {
    let mut guard = AUTH_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = guard.get_or_insert_with(|| AuthCache {
        entries: HashMap::new(),
        by_key: HashMap::new(),
        order: VecDeque::new(),
    });
    f(cache)
}

/// Invalidates every cached authorization entry for one key, or the whole
/// cache when `key_id` is omitted.
pub fn invalidate_api_key_cache(key_id: Option<&str>) {
    with_cache(|cache| match key_id {
        None => {
            cache.entries.clear();
            cache.by_key.clear();
            cache.order.clear();
        }
        Some(key_id) => {
            if let Some(hashes) = cache.by_key.remove(key_id) {
                for hash in hashes {
                    cache.entries.remove(&hash);
                }
            }
        }
    });
}

fn cache_lookup(hash: &str) -> Option<ResolvedApiKey> {
    with_cache(|cache| {
        let (at, value) = cache.entries.get(hash)?;
        if at.elapsed() < AUTH_CACHE_TTL {
            return Some(value.clone());
        }
        cache.entries.remove(hash);
        None
    })
}

fn cache_store(hash: &str, value: &ResolvedApiKey) {
    with_cache(|cache| {
        if !cache.entries.contains_key(hash) {
            cache.order.push_back(hash.to_owned());
        }
        cache
            .entries
            .insert(hash.to_owned(), (Instant::now(), value.clone()));
        cache
            .by_key
            .entry(value.id.clone())
            .or_default()
            .insert(hash.to_owned());
        while cache.order.len() > AUTH_CACHE_MAX_ENTRIES {
            if let Some(oldest) = cache.order.pop_front() {
                cache.entries.remove(&oldest);
            }
        }
    });
}

/// Resolves an inbound bearer token to its persisted API key and builds the
/// immutable authorization snapshot.
pub async fn resolve_api_key_authorization(
    pool: &PgPool,
    token: &str,
) -> Result<Option<ResolvedApiKey>, AuthError> {
    let hash = hash_secret(token)?;
    if let Some(cached) = cache_lookup(&hash) {
        return Ok(Some(cached));
    }
    let Some(row) = find_active_by_hash(pool, &hash).await? else {
        return Ok(None);
    };
    let parent = match &row.parent_key_id {
        Some(parent_id) => match find_active_by_id(pool, parent_id).await? {
            Some(parent) => Some(parent),
            None => return Ok(None),
        },
        None => None,
    };
    let policy = parent.as_ref().unwrap_or(&row);
    let children = sum_children_consumed(pool, &policy.id).await?;
    let consumed = if policy.id == row.id {
        row.lifetime_tokens_consumed
    } else {
        policy.lifetime_tokens_consumed
    } + children;

    let snapshot = ApiKeyAuthorizationSnapshot {
        api_key_id: row.id.clone(),
        tenant_id: row.tenant_id.clone(),
        admission_identity: parent
            .as_ref()
            .map(|p| p.id.clone())
            .unwrap_or_else(|| row.id.clone()),
        model_access_mode: policy.model_access_mode,
        model_list: policy.model_list.clone(),
        client_router_denylist: policy.client_router_denylist.clone(),
        rpm: policy.requests_per_minute,
        daily_tokens: policy.daily_token_limit,
        monthly_tokens: policy.monthly_token_limit,
        lifetime_token_budget: policy.lifetime_token_budget,
        lifetime_tokens_consumed: Some(consumed),
        max_concurrent: policy.max_concurrent_requests,
        scopes: policy.scopes.clone(),
    };
    let value = ResolvedApiKey {
        id: row.id.clone(),
        tenant_id: row.tenant_id.clone(),
        scopes: policy.scopes.clone(),
        snapshot,
        model_prefix: policy.model_prefix.clone(),
        cli_mapping_owner_id: parent
            .as_ref()
            .filter(|parent| parent.key_mode == "share")
            .map(|parent| parent.id.clone()),
    };
    cache_store(&hash, &value);
    Ok(Some(value))
}

/// Extracts exactly one supported credential source, preserving public auth
/// statuses.
pub fn request_token(headers: &BTreeMap<String, String>) -> Result<String, GatewayError> {
    let get = |name: &str| {
        headers.get(name).cloned().or_else(|| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        })
    };
    let authorization = get("authorization")
        .map(|value| value.trim().to_owned())
        .unwrap_or_default();
    let api_key = get("x-api-key")
        .map(|value| value.trim().to_owned())
        .unwrap_or_default();
    let bearer = parse_bearer(&authorization);
    let has_authorization = !authorization.is_empty();
    let has_api_key = !api_key.is_empty();
    if has_authorization && has_api_key {
        if bearer.as_deref() == Some(api_key.as_str()) {
            return Ok(api_key);
        }
        return Err(invalid_request("conflicting credential headers"));
    }
    if has_api_key {
        return Ok(api_key);
    }
    if let Some(token) = bearer {
        return Ok(token);
    }
    Err(GatewayError::new(
        GatewayErrorCode::InvalidRequest,
        401,
        "missing or malformed Authorization header",
        Map::new(),
    ))
}

fn parse_bearer(value: &str) -> Option<String> {
    let split = value.find(char::is_whitespace)?;
    let scheme = &value[..split];
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = value[split..].trim();
    if token.is_empty() || token.contains(char::is_whitespace) {
        return None;
    }
    Some(token.to_owned())
}

fn invalid_request(message: &str) -> GatewayError {
    GatewayError::new(GatewayErrorCode::InvalidRequest, 400, message, Map::new())
}

pub fn get_admission_identity(snapshot: &ApiKeyAuthorizationSnapshot) -> &str {
    &snapshot.admission_identity
}

/// Hashes a token the way the authentication lookup expects, for seeding and
/// tests.
pub fn token_hash(token: &str) -> Result<String, CryptoError> {
    hash_secret(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn token_extraction_accepts_one_source_and_matching_pairs() {
        assert_eq!(
            request_token(&headers(&[("authorization", "Bearer abc")])).unwrap(),
            "abc"
        );
        assert_eq!(
            request_token(&headers(&[("x-api-key", "abc")])).unwrap(),
            "abc"
        );
        assert_eq!(
            request_token(&headers(&[
                ("authorization", "Bearer abc"),
                ("x-api-key", "abc")
            ]))
            .unwrap(),
            "abc"
        );
        assert_eq!(
            request_token(&headers(&[
                ("authorization", "Bearer abc"),
                ("x-api-key", "other")
            ]))
            .unwrap_err()
            .code,
            GatewayErrorCode::InvalidRequest
        );
        assert_eq!(request_token(&headers(&[])).unwrap_err().status, 401);
    }
}
