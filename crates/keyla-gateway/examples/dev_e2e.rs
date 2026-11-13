//! Development server for browser E2E: embedded PostgreSQL, seeded catalog, the
//! built dashboard, and the full gateway shell on one port.
//!
//! Run from the repository root:
//!   cargo run -p keyla-gateway --example dev_e2e

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use keyla_db::apply_sql_migrations;
use keyla_db::seed::seed_bundled_catalog;
use keyla_gateway::runtime::{DatabaseReadiness, GatewayRuntime};
use keyla_gateway::{AppState, StaticAssets, build_app};
use keyla_security::set_credential_encryption_key_for_testing;
use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    set_credential_encryption_key_for_testing(Some([7u8; 32]));
    let mut postgresql = PostgreSQL::new(
        SettingsBuilder::new()
            .temporary(true)
            .username("postgres")
            .password("keyla")
            .build(),
    );
    postgresql.setup().await?;
    postgresql.start().await?;
    let url = postgresql.settings().url("postgres");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await?;

    let migrations = PathBuf::from("migrations");
    apply_sql_migrations(&pool, &migrations).await?;
    seed_bundled_catalog(&pool).await?;

    // First boot: an operator account the browser test can sign in with.
    keyla_console::auth::complete_setup(
        &pool,
        "admin123",
        Some("admin"),
        Some("Administrator"),
        None,
    )
    .await
    .map_err(|error| anyhow::anyhow!("console setup failed: {error}"))?;

    // One configured provider so the providers page has real data.
    sqlx::query(
        "INSERT INTO provider_accounts (provider_id, tenant_id, label, credential_kind, status)
         VALUES ('openai', NULL, 'demo', 'none', 'active')",
    )
    .execute(&pool)
    .await?;

    let runtime = Arc::new(GatewayRuntime::new(pool.clone(), None)?);
    let dashboard_dist =
        std::env::var("DASHBOARD_DIST").unwrap_or_else(|_| "dist/dashboard".to_owned());
    let state = AppState::new(
        StaticAssets::new(&dashboard_dist),
        Arc::new(DatabaseReadiness::new(pool.clone())),
    )
    .with_runtime(runtime);
    let app = build_app(state);

    let address = SocketAddr::from(([127, 0, 0, 1], 18_990));
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("READY http://{address}/console");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
