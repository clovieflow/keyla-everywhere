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
