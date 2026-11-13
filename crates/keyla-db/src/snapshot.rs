//! Per-process route snapshot cache with a TTL and explicit invalidation.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keyla_core::{GatewayError, GatewayErrorCode};
use keyla_routing::RouteSnapshot;
use serde_json::Map;
use sqlx::postgres::PgPool;

use crate::catalog::load_route_catalog;

pub struct SnapshotService {
    pool: PgPool,
    ttl: Duration,
    cache: Mutex<Option<(Instant, RouteSnapshot)>>,
}

impl SnapshotService {
    pub fn new(pool: PgPool, ttl: Duration) -> Self {
        Self {
            pool,
            ttl,
            cache: Mutex::new(None),
        }
    }

    pub async fn get(&self) -> Result<RouteSnapshot, GatewayError> {
        if let Some((at, snapshot)) = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            if self.ttl > Duration::ZERO && at.elapsed() < self.ttl {
                return Ok(snapshot.clone());
            }
        }
        let snapshot = load_route_catalog(&self.pool, None)
            .await
            .map_err(|error| {
                GatewayError::new(
                    GatewayErrorCode::PlatformUnavailable,
                    503,
                    format!("routing catalog unavailable: {error}"),
                    Map::new(),
                )
            })?;
        *self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((Instant::now(), snapshot.clone()));
        Ok(snapshot)
    }

    pub fn invalidate(&self) {
        *self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}
