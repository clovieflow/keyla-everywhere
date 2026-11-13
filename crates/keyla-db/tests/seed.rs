//! Catalog seeding against a real cluster: providers, models, prunes, and
//! operator-owned flags surviving a reseed.

use std::path::Path;

use keyla_db::apply_sql_migrations;
use keyla_db::seed::{retire_unbundled_providers, seed_bundled_catalog};
use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use sqlx::postgres::PgPoolOptions;

const TENANT: &str = "11111111-1111-1111-1111-111111111111";

#[tokio::test(flavor = "multi_thread")]
async fn catalog_seeding_is_complete_idempotent_and_non_destructive() {
    let mut postgresql = PostgreSQL::new(
        SettingsBuilder::new()
            .temporary(true)
            .username("postgres")
            .password("keyla")
            .build(),
    );
    postgresql.setup().await.unwrap();
    postgresql.start().await.unwrap();
    let url = postgresql.settings().url("postgres");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("migrations");
    apply_sql_migrations(&pool, &migrations).await.unwrap();

    seed_bundled_catalog(&pool).await.unwrap();
    let providers: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM providers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(providers, 45);
    let models: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM models")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(models, 466);
    let opencode_compat: Option<String> = sqlx::query_scalar(
        "SELECT compatibility_profile->>'chat' FROM providers WHERE id = 'opencodezen'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(opencode_compat.as_deref(), Some("/zen/v1/chat/completions"));

    // Second run is a no-op.
    seed_bundled_catalog(&pool).await.unwrap();
    let models_again: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM models")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(models_again, 466);

    // A stale builtin row is pruned; operator `enabled` is preserved while
    // catalog-owned metadata is reconciled.
    sqlx::query(
        "INSERT INTO models (provider_id, model_id, wire_family, service_kind, endpoint_path, source)
         VALUES ('openai', 'retired-model', 'chat', 'llm', '/v1/chat/completions', 'builtin')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let reasoning_model: String = sqlx::query_scalar(
        "SELECT model_id FROM models
         WHERE provider_id = 'openai' AND reasoning = true
         ORDER BY model_id LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE models SET enabled = false, reasoning = false, source = 'discovered'
         WHERE provider_id = 'openai' AND model_id = $1",
    )
    .bind(&reasoning_model)
    .execute(&pool)
    .await
    .unwrap();
    seed_bundled_catalog(&pool).await.unwrap();
    let retired: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM models WHERE model_id = 'retired-model'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retired, 0);
    let (enabled, reasoning, source): (bool, bool, String) = sqlx::query_as(
        "SELECT enabled, reasoning, source FROM models
         WHERE provider_id = 'openai' AND model_id = $1",
    )
    .bind(&reasoning_model)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!enabled, "operator disable must survive a reseed");
    assert!(reasoning, "catalog metadata is reconciled");
    assert_eq!(source, "builtin");

    // Retirement only touches global rows the bundle does not declare.
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1::uuid, 't', 'active')")
        .bind(TENANT)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO providers (id, tenant_id, requires_account, enabled)
         VALUES ('orphan-global', NULL, true, true),
                ('tenant-byok', $1::uuid, true, true)",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();
    let retired = retire_unbundled_providers(&pool).await.unwrap();
    assert_eq!(retired, 1);
    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT id FROM providers WHERE id IN ('orphan-global','tenant-byok')")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, vec!["tenant-byok".to_owned()]);

    pool.close().await;
    postgresql.stop().await.unwrap();
}
