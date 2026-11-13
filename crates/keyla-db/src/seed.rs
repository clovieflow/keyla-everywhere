//! Bundled catalog materialization: providers and model definitions.
//!
//! Provider identity comes from `keyla-providers`; the model catalog is the
//! exact output of the shipped TypeScript catalog loaders, captured to JSON so
//! every bundled model/route survives the port without hand transcription.

use std::collections::BTreeMap;

use keyla_providers::BUNDLED_PROVIDERS;
use serde_json::Value;
use sqlx::postgres::PgPool;

use crate::DbResult;

const BUNDLED_MODELS_JSON: &str = include_str!("../assets/bundled-models.json");

/// Idempotently materializes every shipped provider.
pub async fn seed_bundled_providers(pool: &PgPool) -> DbResult<()> {
    for provider in BUNDLED_PROVIDERS {
        let compatibility = provider.compatibility.map(|compatibility| {
            let mut map = serde_json::Map::new();
            if let Some(chat) = compatibility.chat {
                map.insert("chat".into(), Value::String(chat.into()));
            }
            if let Some(responses) = compatibility.responses {
                map.insert("responses".into(), Value::String(responses.into()));
            }
            if let Some(messages) = compatibility.messages {
                map.insert("messages".into(), Value::String(messages.into()));
            }
            Value::Object(map)
        });
        sqlx::query(
            "INSERT INTO providers (id, wire_family_default, compatibility_profile, enabled, requires_account)
             VALUES ($1, $2::wire_family, $3, true, $4)
             ON CONFLICT (id) DO UPDATE SET
               wire_family_default = excluded.wire_family_default,
               requires_account = excluded.requires_account,
               compatibility_profile = COALESCE(providers.compatibility_profile, '{}'::jsonb)
                                       || COALESCE(excluded.compatibility_profile, '{}'::jsonb)",
        )
        .bind(provider.id)
        .bind(provider.wire_family_default.as_str())
        .bind(compatibility)
        .bind(provider.requires_account)
        .execute(pool)
        .await?;
    }
    Ok(())
}

struct ModelRow {
    model_id: String,
    wire_family: String,
    service_kind: String,
    endpoint_path: String,
    context_limit: Option<i64>,
    output_limit: Option<i64>,
    modalities: Value,
    reasoning: bool,
    tool_call: bool,
    cost: Value,
}

fn parse_catalog() -> BTreeMap<String, Vec<ModelRow>> {
    let parsed: Value =
        serde_json::from_str(BUNDLED_MODELS_JSON).expect("bundled model catalog is valid JSON");
    let mut out = BTreeMap::new();
    let Some(providers) = parsed.as_object() else {
        return out;
    };
    for (provider_id, definitions) in providers {
        let Some(definitions) = definitions.as_array() else {
            continue;
        };
        let rows = definitions
            .iter()
            .filter_map(|definition| {
                let definition = definition.as_object()?;
                let model_id = definition.get("modelId")?.as_str()?.to_owned();
                let wire_family = definition
                    .get("wireFamily")
                    .and_then(Value::as_str)
                    .unwrap_or("chat")
                    .to_owned();
                let service_kind = definition
                    .get("serviceKind")
                    .and_then(Value::as_str)
                    .unwrap_or("llm")
                    .to_owned();
                let endpoint_path = definition.get("endpointPath")?.as_str()?.to_owned();
                Some(ModelRow {
                    model_id,
                    wire_family,
                    service_kind,
                    endpoint_path,
                    context_limit: definition.get("contextLimit").and_then(Value::as_i64),
                    output_limit: definition.get("outputLimit").and_then(Value::as_i64),
                    modalities: definition
                        .get("modalities")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({"input": [], "output": []})),
                    reasoning: definition
                        .get("reasoning")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    tool_call: definition
                        .get("toolCall")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    cost: definition.get("cost").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        out.insert(provider_id.clone(), rows);
    }
    out
}

/// Persists the bundled model catalog and prunes rows the catalog retired.
/// `enabled` is operator-owned and is never reset here.
pub async fn seed_bundled_models(pool: &PgPool) -> DbResult<()> {
    let catalog = parse_catalog();
    let mut transaction = pool.begin().await?;
    for (provider_id, rows) in &catalog {
        if rows.is_empty() {
            continue;
        }
        let existing: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id::text, model_id, endpoint_path FROM models
             WHERE provider_id = $1 AND source = 'builtin'",
        )
        .bind(provider_id)
        .fetch_all(&mut *transaction)
        .await?;
        let wanted: std::collections::BTreeSet<(String, String)> = rows
            .iter()
            .map(|row| (row.model_id.clone(), row.endpoint_path.clone()))
            .collect();
        for (id, model_id, endpoint_path) in existing {
            if !wanted.contains(&(model_id, endpoint_path)) {
                sqlx::query("DELETE FROM models WHERE id = $1::uuid")
                    .bind(id)
                    .execute(&mut *transaction)
                    .await?;
            }
        }
        for row in rows {
            sqlx::query(
                "INSERT INTO models
                   (provider_id, model_id, wire_family, service_kind, endpoint_path,
                    context_limit, output_limit, modalities, reasoning, tool_call, cost,
                    source, source_updated_at, enabled)
                 VALUES ($1, $2, $3::wire_family, $4, $5, $6, $7, $8, $9, $10, $11,
                         'builtin', now(), true)
                 ON CONFLICT (provider_id, model_id, endpoint_path) DO UPDATE SET
                   wire_family = excluded.wire_family,
                   service_kind = excluded.service_kind,
                   context_limit = excluded.context_limit,
                   output_limit = excluded.output_limit,
                   modalities = excluded.modalities,
                   reasoning = excluded.reasoning,
                   tool_call = excluded.tool_call,
                   cost = excluded.cost,
                   source = 'builtin',
                   source_updated_at = excluded.source_updated_at",
            )
            .bind(provider_id)
            .bind(&row.model_id)
            .bind(&row.wire_family)
            .bind(&row.service_kind)
            .bind(&row.endpoint_path)
            .bind(row.context_limit)
            .bind(row.output_limit)
            .bind(&row.modalities)
            .bind(row.reasoning)
            .bind(row.tool_call)
            .bind(&row.cost)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    Ok(())
}

/// Runs both catalog seeders in boot order.
pub async fn seed_bundled_catalog(pool: &PgPool) -> DbResult<()> {
    seed_bundled_providers(pool).await?;
    seed_bundled_models(pool).await
}

/// Removes global provider rows the bundle no longer declares. Tenant-owned
/// rows are out of scope by construction.
pub async fn retire_unbundled_providers(pool: &PgPool) -> DbResult<u64> {
    let ids: Vec<&str> = BUNDLED_PROVIDERS
        .iter()
        .map(|provider| provider.id)
        .collect();
    let result =
        sqlx::query("DELETE FROM providers WHERE tenant_id IS NULL AND NOT (id = ANY($1))")
            .bind(&ids)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

/// Number of model rows the embedded catalog carries, by provider.
pub fn bundled_model_counts() -> BTreeMap<String, usize> {
    parse_catalog()
        .into_iter()
        .map(|(provider, rows)| (provider, rows.len()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_matches_the_shipped_loaders() {
        let counts = bundled_model_counts();
        assert_eq!(counts.values().sum::<usize>(), 466);
        assert_eq!(counts.get("openai"), Some(&17));
        assert_eq!(counts.get("claude"), Some(&15));
        assert_eq!(counts.get("inferhub"), Some(&57));
        assert_eq!(counts.get("exa"), Some(&1));
    }

    #[test]
    fn every_provider_has_valid_wire_and_endpoint_rows() {
        for (provider, rows) in parse_catalog() {
            for row in rows {
                assert!(
                    matches!(row.wire_family.as_str(), "chat" | "responses" | "messages"),
                    "{provider}/{} has wire {}",
                    row.model_id,
                    row.wire_family
                );
                assert!(
                    row.endpoint_path.starts_with('/'),
                    "{provider}/{} has endpoint {}",
                    row.model_id,
                    row.endpoint_path
                );
            }
        }
    }
}
