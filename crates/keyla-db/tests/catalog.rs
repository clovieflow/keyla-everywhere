//! Catalog projection against a real PostgreSQL cluster: persisted rows become
//! routing candidates, aliases, combos, provider routing, and tenant scoping.

use std::path::Path;

use keyla_db::apply_sql_migrations;
use keyla_db::catalog::load_route_catalog;
use keyla_routing::{CooldownKind, HealthStatus, PlanInput, RoutingEngine};
use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use sqlx::postgres::PgPoolOptions;

const TENANT: &str = "11111111-1111-1111-1111-111111111111";

#[tokio::test(flavor = "multi_thread")]
async fn catalog_projects_persisted_rows_into_routing_snapshot() {
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
        .expect("connect");

    let migrations = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("migrations");
    apply_sql_migrations(&pool, &migrations)
        .await
        .expect("migrate");

    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1::uuid, 'test', 'active')")
        .bind(TENANT)
        .execute(&pool)
        .await
        .unwrap();

    for (id, tenant, requires_account) in [
        ("openai", None::<&str>, true),
        ("publicprov", None, false),
        ("byok", Some(TENANT), true),
    ] {
        sqlx::query(
            "INSERT INTO providers (id, tenant_id, requires_account, enabled)
             VALUES ($1, $2::uuid, $3, true)",
        )
        .bind(id)
        .bind(tenant)
        .bind(requires_account)
        .execute(&pool)
        .await
        .unwrap();
    }

    for (provider, model, wire, endpoint) in [
        ("openai", "gpt-test", "chat", "/v1/chat/completions"),
        ("openai", "gpt-nocool", "chat", "/v1/chat/completions"),
        ("openai", "gpt-disabled", "chat", "/v1/chat/completions"),
        ("publicprov", "free-model", "chat", "/v1/chat/completions"),
        ("byok", "own-model", "chat", "/v1/chat/completions"),
    ] {
        sqlx::query(
            "INSERT INTO models (provider_id, model_id, wire_family, service_kind, endpoint_path)
             VALUES ($1, $2, $3::wire_family, 'llm', $4)",
        )
        .bind(provider)
        .bind(model)
        .bind(wire)
        .bind(endpoint)
        .execute(&pool)
        .await
        .unwrap();
    }

    // A: global healthy; B: global hard cooldown; C: tenant-owned healthy;
    // D: tenant-owned with a per-model cooldown for gpt-nocool.
    sqlx::query(
        "INSERT INTO provider_accounts (id, provider_id, tenant_id, label, credential_kind, status)
         VALUES
           ('aaaaaaaa-0000-0000-0000-000000000001', 'openai', NULL, 'A', 'none', 'active'),
           ('aaaaaaaa-0000-0000-0000-000000000002', 'openai', NULL, 'B', 'none', 'cooldown'),
           ('aaaaaaaa-0000-0000-0000-000000000003', 'openai', $1::uuid, 'C', 'none', 'active'),
           ('aaaaaaaa-0000-0000-0000-000000000004', 'openai', $1::uuid, 'D', 'none', 'active')",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE provider_accounts
         SET cooldown_until = now() + interval '1 hour', last_error_category = 'rate_limited'
         WHERE label = 'B'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE provider_accounts
         SET model_cooldowns = '{\"gpt-nocool\":\"2999-01-01T00:00:00Z\"}'::jsonb
         WHERE label = 'D'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO provider_accounts (id, provider_id, tenant_id, label, credential_kind, status)
         VALUES ('bbbbbbbb-0000-0000-0000-000000000001', 'byok', $1::uuid, 'own', 'none', 'active')",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO model_aliases (tenant_id, alias, target_model)
         VALUES ($1::uuid, 'fast', 'gpt-test')",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO model_combos (tenant_id, name, members, strategy)
         VALUES ($1::uuid, 'best', '[\"gpt-test\",\"own-model\"]'::jsonb, 'fallback')",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tenant_disabled_models (tenant_id, provider_id, model_id, endpoint_path)
         VALUES ($1::uuid, 'openai', 'gpt-disabled', '/v1/chat/completions')",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO network_pools (id, kind, endpoint_config, max_inflight, weight, tenant_id, status)
         VALUES ('cccccccc-0000-0000-0000-000000000001', 'http',
                 '{\"url\":\"http://127.0.0.1:8080\"}'::jsonb, 5, 100, $1::uuid, 'active')",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO provider_routing_settings
           (provider_id, tenant_id, strategy, rotate_count, max_inflight, enabled, bypass_proxy)
         VALUES ('openai', $1::uuid, 'round_robin', 1, 3, true, false),
                ('openai', NULL, 'fallback', 1, NULL, false, true)",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();

    // Global snapshot sees every tenant.
    let global = load_route_catalog(&pool, None).await.unwrap();
    assert!(!global.candidates.is_empty());
    assert_eq!(
        global
            .aliases
            .get(TENANT)
            .and_then(|map| map.get("fast"))
            .map(String::as_str),
        Some("gpt-test")
    );
    assert_eq!(
        global
            .combos
            .get(TENANT)
            .and_then(|map| map.get("best"))
            .map(|combo| combo.members.clone()),
        Some(vec!["gpt-test".to_owned(), "own-model".to_owned()])
    );
    let tenant_routing = global
        .provider_routing
        .as_ref()
        .and_then(|map| map.get(TENANT))
        .and_then(|map| map.get("openai"))
        .expect("tenant routing");
    assert_eq!(tenant_routing.max_inflight, Some(3));
    assert!(!tenant_routing.bypass_proxy);
    let global_routing = global
        .provider_routing
        .as_ref()
        .and_then(|map| map.get("__global__"))
        .and_then(|map| map.get("openai"))
        .expect("global routing");
    assert!(global_routing.bypass_proxy);

    let candidate_for = |snapshot: &keyla_routing::RouteSnapshot, model: &str, label: &str| {
        snapshot
            .candidates
            .iter()
            .find(|candidate| {
                candidate.model_id == model
                    && candidate.provider_account_label.as_deref() == Some(label)
            })
            .cloned()
    };
    let b = candidate_for(&global, "gpt-test", "B").expect("cooldown candidate");
    assert_eq!(b.health_status, Some(HealthStatus::Cooldown));
    assert_eq!(b.cooldown_kind, Some(CooldownKind::Soft));
    let a = candidate_for(&global, "gpt-test", "A").expect("healthy candidate");
    assert_eq!(a.health_status, None);
    assert_eq!(a.max_inflight, None); // global row has null max_inflight
    let c = candidate_for(&global, "gpt-test", "C").expect("tenant candidate");
    assert_eq!(c.max_inflight, Some(3));
    assert_eq!(c.user_agent.as_deref(), Some("codex_cli_rs/0.156.1"));
    assert_eq!(
        c.network_pool_ids,
        vec!["cccccccc-0000-0000-0000-000000000001".to_owned()]
    );
    assert!(
        global
            .candidates
            .iter()
            .any(|candidate| candidate.model_id == "free-model"
                && candidate.requires_account == Some(false)
                && candidate.provider_account_id.is_none())
    );

    // Tenant snapshot suppresses that tenant's disabled model and excludes
    // other tenants' rows.
    let scoped = load_route_catalog(&pool, Some(TENANT)).await.unwrap();
    assert!(
        !scoped.candidates.iter().any(|candidate| {
            candidate.model_id == "gpt-disabled"
                && matches!(candidate.provider_account_label.as_deref(), Some("C" | "D"))
        }),
        "tenant-owned rows for a tenant-disabled model must be suppressed"
    );
    assert!(
        scoped
            .candidates
            .iter()
            .all(|candidate| candidate.tenant_id.is_none()
                || candidate.tenant_id.as_deref() == Some(TENANT))
    );

    // Model cooldown excludes D for that model only.
    let engine = RoutingEngine::new(std::sync::Arc::new(
        keyla_routing::InMemoryAdmissionController::new(),
    ));
    let mut input = PlanInput::new("gpt-nocool");
    input.tenant_id = Some(TENANT);
    let plan = engine.plan(&scoped, input).unwrap();
    assert!(
        plan.candidates
            .iter()
            .all(|candidate| candidate.provider_account_label.as_deref() != Some("D"))
    );

    // Alias resolution + cooling order through the real engine.
    let mut input = PlanInput::new("fast");
    input.tenant_id = Some(TENANT);
    let plan = engine.plan(&scoped, input).unwrap();
    assert_eq!(plan.resolved_model, "gpt-test");
    assert_eq!(
        plan.candidates
            .last()
            .and_then(|candidate| candidate.provider_account_label.as_deref()),
        Some("B"),
        "cooling account is tried last"
    );

    pool.close().await;
    postgresql.stop().await.expect("stop");
}
