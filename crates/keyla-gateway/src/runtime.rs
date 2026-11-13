//! Production runtime wiring for the gateway route plane.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keyla_core::{GatewayError, GatewayErrorCode};
use keyla_routing::{InMemoryAdmissionController, RoutingEngine};
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
        })
    }
}

/// Readiness probe backed by a live pool and the migration ledger.
pub struct DatabaseReadiness {
    pool: PgPool,
}

impl DatabaseReadiness {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
            crate::app::Readiness {
                db: crate::app::DependencyStatus::Connected,
                redis: crate::app::DependencyStatus::Connected,
                migrations: Some(if applied {
                    crate::app::MigrationStatus::Applied
                } else {
                    crate::app::MigrationStatus::Pending
                }),
            }
        })
    }
}
