//! API-key authentication against a real cluster: hashed lookup, revocation,
//! expiry, policy inheritance, quota aggregation, and cache invalidation.

use std::path::Path;

use keyla_db::apply_sql_migrations;
use keyla_security::{
    invalidate_api_key_cache, resolve_api_key_authorization,
    set_credential_encryption_key_for_testing, token_hash,
};
use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use sqlx::postgres::PgPoolOptions;

const TENANT: &str = "11111111-1111-1111-1111-111111111111";

#[tokio::test(flavor = "multi_thread")]
async fn api_key_authentication_inherits_parent_policy_and_honours_expiry() {
    set_credential_encryption_key_for_testing(Some([7u8; 32]));
    invalidate_api_key_cache(None);

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

    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1::uuid, 'test', 'active')")
        .bind(TENANT)
        .execute(&pool)
        .await
        .unwrap();

    let hash = token_hash("sk-test-token").unwrap();
    sqlx::query(
        "INSERT INTO api_keys
           (id, tenant_id, key_hash, key_mode, label, scopes, enabled,
            model_access_mode, model_list, requests_per_minute, daily_token_limit,
            lifetime_tokens_consumed)
         VALUES ('aaaaaaaa-0000-0000-0000-000000000001', $1::uuid, $2, 'personal',
                 'primary', '[\"routing:invoke\",\"models:read\"]'::jsonb, true,
                 'whitelist', '[\"gpt-test\"]'::jsonb, 10, 1000, 5)",
    )
    .bind(TENANT)
    .bind(&hash)
    .execute(&pool)
    .await
    .unwrap();

    let resolved = resolve_api_key_authorization(&pool, "sk-test-token")
        .await
        .unwrap()
        .expect("personal key resolves");
    assert_eq!(resolved.id, "aaaaaaaa-0000-0000-0000-000000000001");
    assert_eq!(resolved.tenant_id, TENANT);
    assert_eq!(
        resolved.scopes,
        vec!["routing:invoke".to_owned(), "models:read".to_owned()]
    );
    assert_eq!(resolved.snapshot.rpm, Some(10));
    assert_eq!(resolved.snapshot.daily_tokens, Some(1000));
    assert_eq!(resolved.snapshot.lifetime_tokens_consumed, Some(5));
    assert_eq!(
        resolved.snapshot.model_list,
        Some(vec!["gpt-test".to_owned()])
    );
    assert_eq!(resolved.snapshot.admission_identity, resolved.id);

    assert!(
        resolve_api_key_authorization(&pool, "unknown")
            .await
            .unwrap()
            .is_none()
    );

    // The cache serves the previous snapshot until invalidated.
    sqlx::query(
        "UPDATE api_keys SET requests_per_minute = 20 WHERE id = 'aaaaaaaa-0000-0000-0000-000000000001'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let cached = resolve_api_key_authorization(&pool, "sk-test-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cached.snapshot.rpm, Some(10), "cache is warm");
    invalidate_api_key_cache(Some("aaaaaaaa-0000-0000-0000-000000000001"));
    let refreshed = resolve_api_key_authorization(&pool, "sk-test-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refreshed.snapshot.rpm, Some(20), "invalidation refreshes");

    // Expiry is enforced by the lookup query.
    sqlx::query(
        "UPDATE api_keys SET expires_at = now() - interval '1 minute'
         WHERE id = 'aaaaaaaa-0000-0000-0000-000000000001'",
    )
    .execute(&pool)
    .await
    .unwrap();
    invalidate_api_key_cache(None);
    assert!(
        resolve_api_key_authorization(&pool, "sk-test-token")
            .await
            .unwrap()
            .is_none()
    );

    // Restore, then verify revocation.
    sqlx::query(
        "UPDATE api_keys SET expires_at = NULL, revoked_at = now()
         WHERE id = 'aaaaaaaa-0000-0000-0000-000000000001'",
    )
    .execute(&pool)
    .await
    .unwrap();
    invalidate_api_key_cache(None);
    assert!(
        resolve_api_key_authorization(&pool, "sk-test-token")
            .await
            .unwrap()
            .is_none()
    );

    // Parent/child share keys inherit the parent's live policy and quota.
    sqlx::query(
        "INSERT INTO api_keys
           (id, tenant_id, key_hash, key_mode, parent_key_id, issued_client_ip,
            issued_client_ip_key, label, scopes, enabled, model_access_mode,
            model_list, requests_per_minute, lifetime_token_budget,
            lifetime_tokens_consumed)
         VALUES ('bbbbbbbb-0000-0000-0000-000000000001', $1::uuid, NULL, 'share', NULL,
                 NULL, NULL, 'template', '[\"routing:invoke\"]'::jsonb, true,
                 'blacklist', '[\"blocked-model\"]'::jsonb, 30, 5000, 100)",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();
    let child_one_hash = token_hash("sk-child-one").unwrap();
    let child_two_hash = token_hash("sk-child-two").unwrap();
    sqlx::query(
        "INSERT INTO api_keys
           (id, tenant_id, key_hash, key_mode, parent_key_id, issued_client_ip,
            issued_client_ip_key, label, scopes, enabled, lifetime_tokens_consumed)
         VALUES ('bbbbbbbb-0000-0000-0000-000000000002', $1::uuid, $2, 'share',
                 'bbbbbbbb-0000-0000-0000-000000000001', '203.0.113.7', 'ip-key-1',
                 'child-1', '[]'::jsonb, true, 7),
                ('bbbbbbbb-0000-0000-0000-000000000003', $1::uuid, $3, 'share',
                 'bbbbbbbb-0000-0000-0000-000000000001', '203.0.113.8', 'ip-key-2',
                 'child-2', '[]'::jsonb, true, 3)",
    )
    .bind(TENANT)
    .bind(&child_one_hash)
    .bind(&child_two_hash)
    .execute(&pool)
    .await
    .unwrap();

    let child = resolve_api_key_authorization(&pool, "sk-child-one")
        .await
        .unwrap()
        .expect("child resolves");
    assert_eq!(child.id, "bbbbbbbb-0000-0000-0000-000000000002");
    assert_eq!(
        child.snapshot.admission_identity,
        "bbbbbbbb-0000-0000-0000-000000000001"
    );
    assert_eq!(child.snapshot.lifetime_tokens_consumed, Some(110));
    assert_eq!(child.snapshot.rpm, Some(30));
    assert_eq!(
        child.snapshot.model_list,
        Some(vec!["blocked-model".to_owned()])
    );
    assert_eq!(
        child.cli_mapping_owner_id.as_deref(),
        Some("bbbbbbbb-0000-0000-0000-000000000001")
    );

    pool.close().await;
    postgresql.stop().await.unwrap();
}
