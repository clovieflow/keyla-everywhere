//! Real-database migration parity: a fresh cluster runs the shipped SQL, the
//! ledger records every file, and a second run is a no-op.

use std::path::Path;

use keyla_db::{apply_sql_migrations, ledger_status};
use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use sqlx::postgres::PgPoolOptions;

#[tokio::test(flavor = "multi_thread")]
async fn migrations_apply_to_a_fresh_cluster_and_are_idempotent() {
    let mut postgresql = PostgreSQL::new(
        SettingsBuilder::new()
            .temporary(true)
            .username("postgres")
            .password("keyla")
            .build(),
    );
    postgresql.setup().await.expect("embedded postgres install");
    postgresql.start().await.expect("embedded postgres start");

    let url = postgresql.settings().url("postgres");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to embedded postgres");

    let folder = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("migrations");
    assert!(folder.is_dir(), "migrations folder missing: {folder:?}");

    apply_sql_migrations(&pool, &folder)
        .await
        .expect("apply migrations");

    let expected: i64 = {
        let mut count = 0;
        for entry in std::fs::read_dir(&folder).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            if name.len() > 8
                && name.ends_with(".sql")
                && name.as_bytes()[..4].iter().all(u8::is_ascii_digit)
            {
                count += 1;
            }
        }
        count
    };

    let applied: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM keyla_schema_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(applied, expected, "every shipped migration is recorded");

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for table in [
        "tenants",
        "providers",
        "provider_accounts",
        "provider_oauth_states",
        "models",
        "model_aliases",
        "model_combos",
        "api_keys",
        "console_users",
        "console_sessions",
        "telemetry_events",
        "telemetry_payloads",
        "network_pools",
    ] {
        assert!(
            tables.iter().any(|existing| existing == table),
            "missing table {table}; present: {tables:?}"
        );
    }

    apply_sql_migrations(&pool, &folder)
        .await
        .expect("second run is a no-op");
    let applied_again: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM keyla_schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(applied_again, expected);

    assert!(ledger_status(&pool, &folder).await.unwrap());

    pool.close().await;
    postgresql.stop().await.expect("embedded postgres stop");
}
