//! Dispatch lookups: provider base URLs and account credentials.

use serde_json::Value;
use sqlx::postgres::PgPool;
use sqlx::{Row, postgres::PgRow};

use crate::DbResult;

#[derive(Debug, Clone)]
pub struct DispatchAccount {
    pub id: String,
    pub provider_id: String,
    pub label: String,
    pub credential_kind: String,
    pub credential_ciphertext: Option<Vec<u8>>,
    pub auth_state: Option<Value>,
}

/// The provider row's own base URL (BYOK); built-ins fall back to metadata.
pub async fn load_provider_base_url(pool: &PgPool, provider_id: &str) -> DbResult<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT base_url FROM providers WHERE id = $1")
            .bind(provider_id)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .and_then(|(base_url,)| base_url)
        .filter(|value| !value.is_empty()))
}

pub async fn load_dispatch_account(
    pool: &PgPool,
    account_id: &str,
) -> DbResult<Option<DispatchAccount>> {
    let row: Option<PgRow> = sqlx::query(
        "SELECT id::text AS id, provider_id, label, credential_kind::text AS credential_kind,
                credential_ciphertext, auth_state
         FROM provider_accounts WHERE id = $1::uuid",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| DispatchAccount {
        id: row.get("id"),
        provider_id: row.get("provider_id"),
        label: row.get("label"),
        credential_kind: row.get("credential_kind"),
        credential_ciphertext: row.get("credential_ciphertext"),
        auth_state: row.get("auth_state"),
    }))
}

#[derive(Debug, Clone)]
pub struct DispatchNetworkPool {
    pub id: String,
    pub kind: String,
    pub endpoint: String,
}

/// Loads an active egress pool by id, scoped to the tenant that owns it.
pub async fn load_network_pool(
    pool: &PgPool,
    pool_id: &str,
    tenant_id: &str,
) -> DbResult<Option<DispatchNetworkPool>> {
    let row: Option<PgRow> = sqlx::query(
        "SELECT id::text AS id, kind::text AS kind,
                endpoint_config->>'endpoint' AS endpoint
         FROM network_pools
         WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'active'",
    )
    .bind(pool_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|row| {
        let endpoint: Option<String> = row.get("endpoint");
        let endpoint = endpoint.filter(|value| !value.trim().is_empty())?;
        Some(DispatchNetworkPool {
            id: row.get("id"),
            kind: row.get("kind"),
            endpoint,
        })
    }))
}
