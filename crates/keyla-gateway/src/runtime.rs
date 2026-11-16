//! Production runtime wiring for the gateway route plane.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keyla_config::Env;
use keyla_core::{GatewayError, GatewayErrorCode};
use keyla_routing::{InMemoryAdmissionController, RouteCandidate, RoutingEngine};
use reqwest::Client;
use serde_json::Map;
use sqlx::postgres::PgPool;

/// Everything the `/v1` route plane needs, owned once per process.
pub struct GatewayRuntime {
    pub pool: PgPool,
    pub engine: Arc<RoutingEngine>,
    pub snapshots: Arc<keyla_db::snapshot::SnapshotService>,
    pub client: Client,
    /// Process-local in-flight count per API key, for `max_concurrent_requests`.
    pub key_inflight: Arc<Mutex<HashMap<String, i64>>>,
    /// Redis-backed admission when `REDIS_URL` is configured.
    pub redis_admission: Option<keyla_security::redis_admission::RedisAdmission>,
    /// Tenant Prompt Injection policy, read on the request path with a short
    /// in-process cache.
    pub prompt_injection: Arc<crate::prompt_injection::PromptInjectionCache>,
    /// Round-robin cursors and clients for provider-scoped egress pools.
    pool_cursors: Mutex<HashMap<String, usize>>,
    proxy_clients: Mutex<HashMap<String, Client>>,
}

fn opencode_proxy_urls() -> Vec<String> {
    keyla_config::ProcessEnv
        .get("KEYLA_OPENCODE_PROXY_URLS")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_warp_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("socks5://{endpoint}")
    }
}

fn next_rotation_index(cursor: &mut usize, len: usize) -> usize {
    let index = *cursor % len;
    *cursor = cursor.wrapping_add(1);
    index
}

impl GatewayRuntime {
    pub fn new(
        pool: PgPool,
        redis_admission: Option<keyla_security::redis_admission::RedisAdmission>,
    ) -> Result<Self, GatewayError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    format!("http client: {error}"),
                    Map::new(),
                )
            })?;
        let prompt_injection = Arc::new(crate::prompt_injection::PromptInjectionCache::new(
            pool.clone(),
        ));
        Ok(Self {
            snapshots: keyla_db::snapshot::SnapshotService::new(
                pool.clone(),
                Duration::from_secs(30),
            )
            .shared(),
            pool,
            engine: Arc::new(RoutingEngine::new(Arc::new(
                InMemoryAdmissionController::new(),
            ))),
            client,
            key_inflight: Arc::new(Mutex::new(HashMap::new())),
            redis_admission,
            prompt_injection,
            pool_cursors: Mutex::new(HashMap::new()),
            proxy_clients: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the client for one dispatch attempt. IP-scoped providers with
    /// assigned network pools rotate across them per request. OpenCode Free
    /// also accepts an operator-supplied WARP/proxy list via
    /// `KEYLA_OPENCODE_PROXY_URLS` when no pool is configured.
    pub async fn dispatch_client(
        &self,
        candidate: &RouteCandidate,
    ) -> Result<Client, GatewayError> {
        if !keyla_providers::provider_rate_limit_is_ip_scoped(Some(&candidate.provider_id)) {
            return Ok(self.client.clone());
        }
        if !candidate.network_pool_ids.is_empty() {
            let tenant = candidate.tenant_id.as_deref().ok_or_else(|| {
                GatewayError::new(
                    GatewayErrorCode::InternalError,
                    500,
                    "network pool selected without a tenant",
                    Map::new(),
                )
            })?;
            let cursor_key = format!("{tenant}::{}", candidate.provider_id);
            let start = {
                let mut cursors = self
                    .pool_cursors
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                next_rotation_index(
                    cursors.entry(cursor_key).or_insert(0),
                    candidate.network_pool_ids.len(),
                )
            };
            for offset in 0..candidate.network_pool_ids.len() {
                let pool_id = &candidate.network_pool_ids
                    [(start + offset) % candidate.network_pool_ids.len()];
                let Some(pool) = keyla_db::dispatch::load_network_pool(&self.pool, pool_id, tenant)
                    .await
                    .map_err(|error| {
                        GatewayError::new(
                            GatewayErrorCode::ProxyPoolUnavailable,
                            502,
                            format!("network pool lookup failed: {error}"),
                            Map::new(),
                        )
                    })?
                else {
                    continue;
                };
                let endpoint = match normalize_proxy_endpoint(&pool.kind, &pool.endpoint) {
                    Ok(endpoint) => endpoint,
                    Err(_) => continue,
                };
                if let Ok(client) =
                    self.proxy_client(&format!("{}::{endpoint}", pool.id), &endpoint)
                {
                    return Ok(client);
                }
            }
            return Err(GatewayError::new(
                GatewayErrorCode::ProxyPoolUnavailable,
                502,
                "no active network pool is available for this route",
                Map::new(),
            ));
        }
        let warp_urls = opencode_proxy_urls();
        if warp_urls.is_empty() {
            return Ok(self.client.clone());
        }
        let cursor_key = format!(
            "{}::{}::warp",
            candidate.tenant_id.as_deref().unwrap_or("__global__"),
            candidate.provider_id
        );
        let start = {
            let mut cursors = self
                .pool_cursors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            next_rotation_index(cursors.entry(cursor_key).or_insert(0), warp_urls.len())
        };
        for offset in 0..warp_urls.len() {
            let endpoint = normalize_warp_endpoint(&warp_urls[(start + offset) % warp_urls.len()]);
            if let Ok(client) = self.proxy_client(&format!("warp::{endpoint}"), &endpoint) {
                return Ok(client);
            }
        }
        Err(GatewayError::new(
            GatewayErrorCode::ProxyPoolUnavailable,
            502,
            "no usable OpenCode proxy endpoint is configured",
            Map::new(),
        ))
    }

    fn proxy_client(&self, cache_key: &str, endpoint: &str) -> Result<Client, GatewayError> {
        if let Some(client) = self
            .proxy_clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(cache_key)
            .cloned()
        {
            return Ok(client);
        }
        let proxy = reqwest::Proxy::all(endpoint).map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::ProxyPoolUnavailable,
                502,
                format!("proxy endpoint rejected: {error}"),
                Map::new(),
            )
        })?;
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .pool_idle_timeout(Duration::from_secs(60))
            .proxy(proxy)
            .build()
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::ProxyPoolUnavailable,
                    502,
                    format!("proxy client failed: {error}"),
                    Map::new(),
                )
            })?;
        self.proxy_clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(cache_key.to_owned(), client.clone());
        Ok(client)
    }
}

fn normalize_proxy_endpoint(kind: &str, endpoint: &str) -> Result<String, GatewayError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(GatewayError::new(
            GatewayErrorCode::ProxyPoolUnavailable,
            502,
            "network pool has an empty endpoint",
            Map::new(),
        ));
    }
    match kind {
        "socks5" => {
            if endpoint.contains("://") {
                Ok(endpoint.to_owned())
            } else {
                Ok(format!("socks5://{endpoint}"))
            }
        }
        "http" | "https" => Ok(endpoint.to_owned()),
        "bridge" => Err(GatewayError::new(
            GatewayErrorCode::ProxyPoolUnavailable,
            502,
            "bridge network pools are not implemented in the Rust gateway",
            Map::new(),
        )),
        other => Err(GatewayError::new(
            GatewayErrorCode::ProxyPoolUnavailable,
            502,
            format!("unsupported network pool kind: {other}"),
            Map::new(),
        )),
    }
}

/// Readiness probe backed by a live pool, the migration ledger, and the
/// optional external Redis admission backend.
pub struct DatabaseReadiness {
    pool: PgPool,
    redis: Option<keyla_security::redis_admission::RedisAdmission>,
    redis_configured: bool,
}

impl DatabaseReadiness {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            redis: None,
            redis_configured: false,
        }
    }

    pub fn with_redis(
        mut self,
        redis: Option<keyla_security::redis_admission::RedisAdmission>,
        configured: bool,
    ) -> Self {
        self.redis = redis;
        self.redis_configured = configured;
        self
    }
}

impl crate::app::ReadinessProbe for DatabaseReadiness {
    fn check(&self) -> crate::app::ReadinessFuture<'_> {
        Box::pin(async move {
            let connected = sqlx::query("SELECT 1").execute(&self.pool).await.is_ok();
            if !connected {
                return crate::app::Readiness {
                    db: crate::app::DependencyStatus::Disconnected,
                    redis: crate::app::DependencyStatus::Disconnected,
                    migrations: Some(crate::app::MigrationStatus::Pending),
                };
            }
            let applied = keyla_db::ledger_status_embedded(&self.pool)
                .await
                .unwrap_or(false);
            let redis = if !self.redis_configured {
                crate::app::DependencyStatus::Connected
            } else {
                match &self.redis {
                    Some(admission) if admission.ping().await => {
                        crate::app::DependencyStatus::Connected
                    }
                    _ => crate::app::DependencyStatus::Disconnected,
                }
            };
            crate::app::Readiness {
                db: crate::app::DependencyStatus::Connected,
                redis,
                migrations: Some(if applied {
                    crate::app::MigrationStatus::Applied
                } else {
                    crate::app::MigrationStatus::Pending
                }),
            }
        })
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn socks_endpoints_get_a_scheme_but_http_endpoints_do_not() {
        assert_eq!(
            normalize_proxy_endpoint("socks5", "127.0.0.1:1080").unwrap(),
            "socks5://127.0.0.1:1080"
        );
        assert_eq!(
            normalize_proxy_endpoint("socks5", "socks5://user:pass@127.0.0.1:1080").unwrap(),
            "socks5://user:pass@127.0.0.1:1080"
        );
        assert_eq!(
            normalize_proxy_endpoint("http", "http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalize_proxy_endpoint("https", "https://proxy.example:443").unwrap(),
            "https://proxy.example:443"
        );
    }

    #[test]
    fn rotation_visits_every_endpoint_and_wraps() {
        let mut cursor = 0;
        let indexes: Vec<usize> = (0..5)
            .map(|_| next_rotation_index(&mut cursor, 3))
            .collect();
        assert_eq!(indexes, vec![0, 1, 2, 0, 1]);
    }

    #[test]
    fn warp_endpoints_without_a_scheme_default_to_socks5() {
        assert_eq!(
            normalize_warp_endpoint("127.0.0.1:40000"),
            "socks5://127.0.0.1:40000"
        );
        assert_eq!(
            normalize_warp_endpoint("socks5://127.0.0.1:40000"),
            "socks5://127.0.0.1:40000"
        );
        assert_eq!(
            normalize_warp_endpoint("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn bridge_and_empty_pools_are_rejected() {
        assert_eq!(
            normalize_proxy_endpoint("bridge", "bridge.example")
                .unwrap_err()
                .code,
            GatewayErrorCode::ProxyPoolUnavailable
        );
        assert_eq!(
            normalize_proxy_endpoint("http", "   ").unwrap_err().code,
            GatewayErrorCode::ProxyPoolUnavailable
        );
    }
}
