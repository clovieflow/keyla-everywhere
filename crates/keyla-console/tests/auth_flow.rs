//! Console auth flow against a real cluster: first boot, login, cookies,
//! session, CSRF-protected password rotation, logout, and lockout.

use std::net::SocketAddr;
use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use keyla_console::auth::{
    CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, SessionCookiePolicy, parse_cookie,
};
use keyla_console::console_router_with_policy;
use keyla_db::apply_sql_migrations;
use keyla_db::seed::seed_bundled_catalog;
use keyla_security::set_credential_encryption_key_for_testing;
use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::util::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    cookies: Option<&str>,
    csrf: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value, Vec<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookies) = cookies {
        builder = builder.header("cookie", cookies);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let mut request = builder.body(body).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 55_555))));
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let cookies = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, headers, value, cookies)
}

fn cookie_value(cookies: &[String], name: &str) -> Option<String> {
    cookies
        .iter()
        .find_map(|cookie| parse_cookie(Some(cookie), name))
}

#[tokio::test(flavor = "multi_thread")]
async fn console_auth_flow_end_to_end() {
    set_credential_encryption_key_for_testing(Some([7u8; 32]));
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
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("migrations");
    apply_sql_migrations(&pool, &migrations).await.unwrap();
    seed_bundled_catalog(&pool).await.unwrap();

    let policy = SessionCookiePolicy {
        max_age: 48 * 60 * 60,
        http_only: true,
        same_site: "Lax",
        secure: false,
    };
    let app = console_router_with_policy(pool.clone(), Some(policy));

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/auth/first-boot",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["requires_setup"], true);

    let (status, _, body, _) = call(
        &app,
        "POST",
        "/console/api/auth/setup",
        None,
        None,
        Some(json!({"password": "123456", "username": "operator"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "success");

    // A second setup is refused.
    let (status, _, body, _) = call(
        &app,
        "POST",
        "/console/api/auth/setup",
        None,
        None,
        Some(json!({"password": "abcdef"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Setup already completed");

    let (status, _, body, _) = call(
        &app,
        "POST",
        "/console/api/auth/login",
        None,
        None,
        Some(json!({"username": "operator", "password": "wrong"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["message"], "Invalid credentials");

    let (status, _, body, cookies) = call(
        &app,
        "POST",
        "/console/api/auth/login",
        None,
        None,
        Some(json!({"username": "operator", "password": "123456"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "success");
    let session_token = cookie_value(&cookies, SESSION_COOKIE_NAME).expect("session cookie");
    let csrf_token = cookie_value(&cookies, CSRF_COOKIE_NAME).expect("csrf cookie");
    assert!(cookies.iter().any(|cookie| cookie.contains("HttpOnly")));
    let cookie_header =
        format!("{SESSION_COOKIE_NAME}={session_token}; {CSRF_COOKIE_NAME}={csrf_token}");

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/auth/session",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "authenticated");
    assert_eq!(body["username"], "operator");
    assert_eq!(body["is_platform_admin"], true);

    // CSRF is enforced on mutations.
    let (status, _, _, _) = call(
        &app,
        "POST",
        "/console/api/auth/change-password",
        Some(&cookie_header),
        None,
        Some(json!({"currentPassword": "123456", "newPassword": "abcdef"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, body, _) = call(
        &app,
        "POST",
        "/console/api/auth/change-password",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"currentPassword": "123456", "newPassword": "abcdef"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "success");

    let (status, _, _, _) = call(
        &app,
        "POST",
        "/console/api/auth/login",
        None,
        None,
        Some(json!({"username": "operator", "password": "123456"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old password is retired");
    let (status, _, _, _) = call(
        &app,
        "POST",
        "/console/api/auth/login",
        None,
        None,
        Some(json!({"username": "operator", "password": "abcdef"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "new password works");

    // Provider catalog reads: built-in metadata, custom rows, and flat model
    // visibility gated on an active account.
    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let providers = body.as_array().expect("provider array");
    let openai = providers
        .iter()
        .find(|entry| entry["providerId"] == "openai")
        .expect("openai row");
    assert_eq!(openai["isBuiltIn"], true);
    assert_eq!(openai["requiresAccount"], true);
    assert_eq!(openai["displayName"], "OpenAI");
    let gemini = providers
        .iter()
        .find(|entry| entry["providerId"] == "gemini")
        .expect("gemini row");
    assert_eq!(gemini["supportsWebSearch"], true);

    // Without an active account, a requires-account provider contributes no
    // flat model entries.
    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers/models/flat",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["qualified"].as_str())
        .collect();
    assert!(
        before.iter().all(|id| !id.starts_with("openai/")),
        "{before:?}"
    );

    sqlx::query(
        "INSERT INTO provider_accounts
           (provider_id, tenant_id, label, credential_kind, status)
         VALUES ('openai', NULL, 'reader', 'none', 'active')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers/models/flat",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after = body.as_array().unwrap();
    assert!(after.iter().any(|entry| entry["providerId"] == "openai"
        && entry["kind"] == "model"
        && entry["entry"]["source"] == "builtin"));

    // Routing reads + the read-only simulator.
    let model_id: String = sqlx::query_scalar(
        "SELECT model_id FROM models WHERE provider_id = 'openai' ORDER BY model_id LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO model_aliases (tenant_id, alias, target_model)
         VALUES ((SELECT tenant_id FROM console_users LIMIT 1), 'fast', $1)",
    )
    .bind(format!("openai/{model_id}"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO model_combos (tenant_id, name, members, strategy)
         VALUES ((SELECT tenant_id FROM console_users LIMIT 1), 'both', $1, 'fallback')",
    )
    .bind(serde_json::json!([
        format!("openai/{model_id}"),
        format!("openai/{model_id}")
    ]))
    .execute(&pool)
    .await
    .unwrap();

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/routing/aliases",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let aliases = body.as_array().unwrap();
    assert_eq!(aliases[0]["alias"], "fast");
    assert_eq!(aliases[0]["targetModel"], format!("openai/{model_id}"));
    assert!(aliases[0]["contextLimit"].as_i64().unwrap() > 0);

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/routing/combos",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.as_array().unwrap()[0]["name"], "both");
    assert!(
        body.as_array().unwrap()[0]["contextLimit"]
            .as_i64()
            .unwrap()
            > 0
    );

    let (status, _, body, _) = call(
        &app,
        "POST",
        "/console/api/routing/simulate",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"model": "fast", "endpoint": "chat.completions"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["readOnly"], true);
    assert_eq!(body["resolvedModel"], format!("openai/{model_id}"));
    assert!(!body["candidates"].as_array().unwrap().is_empty());
    assert_eq!(body["selectedIsDeterministic"], true);
    assert!(!body["notes"].as_array().unwrap().is_empty());

    // Provider detail, models, accounts, and routing settings.
    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers/openai",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["providerId"], "openai");
    assert_eq!(body["displayName"], "OpenAI");

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers/openai/models",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let models = body.as_array().unwrap();
    assert!(!models.is_empty());
    assert!(models[0].get("modelId").is_some());
    assert_eq!(models[0]["provider"], "openai");

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers/openai/accounts",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let accounts = body.as_array().unwrap();
    assert_eq!(accounts[0]["label"], "reader");
    assert_eq!(accounts[0]["credentialKind"], "none");
    assert_eq!(accounts[0]["usageToday"]["totalTokens"], 0);

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers/openai/routing",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["strategy"], "fallback");
    assert_eq!(body["bypassProxy"], false);

    let (status, _, body, _) = call(
        &app,
        "PATCH",
        "/console/api/providers/openai/routing",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(
            json!({"strategy": "round_robin", "rotateCount": 2, "maxInflight": 3, "enabled": true}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["strategy"], "round_robin");
    assert_eq!(body["rotateCount"], 2);
    assert_eq!(body["maxInflight"], 3);
    assert_eq!(body["enabled"], true);

    let (status, _, body, _) = call(
        &app,
        "GET",
        "/console/api/providers/openai/account-inflight",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.as_array().unwrap().len(), 0);

    // System health and usage analytics are readable for the dashboard.
    let (status, _, health, _) = call(
        &app,
        "GET",
        "/console/api/system/health",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{health}");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["database_healthy"], true);
    assert!(!health["version"].as_str().unwrap_or_default().is_empty());

    let (status, _, summary, _) = call(
        &app,
        "GET",
        "/console/api/system/usage/summary?period=24h",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["period"], "24h");
    assert_eq!(summary["totals"]["requests"], 0);
    assert_eq!(summary["totals"]["errors"], 0);

    let (status, _, chart, _) = call(
        &app,
        "GET",
        "/console/api/system/usage/chart?period=24h",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{chart}");
    assert!(!chart["buckets"].as_array().unwrap().is_empty());

    let (status, _, invalid, _) = call(
        &app,
        "GET",
        "/console/api/system/usage/summary?period=bogus",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid["error"]["code"], "invalid_period");

    // API-key CRUD: list, create (plaintext once), edit, reorder, revoke.
    let (status, _, keys, _) = call(
        &app,
        "GET",
        "/console/api/api-keys",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{keys}");
    assert_eq!(keys.as_array().unwrap().len(), 0);

    let (status, _, created, _) = call(
        &app,
        "POST",
        "/console/api/api-keys",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({
            "label": "CI key",
            "scopes": ["routing:invoke"],
            "requestsPerMinute": 60,
            "dailyTokenLimit": 1000,
            "modelAccessMode": "whitelist",
            "modelList": ["claude-sonnet-4"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["label"], "CI key");
    assert_eq!(created["keyMode"], "personal");
    assert_eq!(created["enabled"], true);
    assert_eq!(created["scopes"], json!(["routing:invoke"]));
    assert_eq!(created["requestsPerMinute"], 60);
    assert_eq!(created["modelList"], json!(["claude-sonnet-4"]));
    assert!(created["secret"].as_str().unwrap().starts_with("rk_"));
    let key_id = created["id"].as_str().unwrap().to_owned();

    let (status, _, listed, _) = call(
        &app,
        "GET",
        "/console/api/api-keys",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["id"], key_id);
    assert!(listed[0].get("secret").is_none());

    let (status, _, patched, _) = call(
        &app,
        "PATCH",
        &format!("/console/api/api-keys/{key_id}"),
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"label": "CI key 2", "enabled": false, "dailyTokenLimit": null})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(patched["label"], "CI key 2");
    assert_eq!(patched["enabled"], false);
    assert!(patched.get("dailyTokenLimit").is_none());

    let (status, _, reordered, _) = call(
        &app,
        "POST",
        "/console/api/api-keys/reorder",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"keyIds": [key_id]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reordered}");
    assert_eq!(reordered["success"], true);

    let (status, _, revoked, _) = call(
        &app,
        "DELETE",
        &format!("/console/api/api-keys/{key_id}"),
        Some(&cookie_header),
        Some(&csrf_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(revoked["success"], true);

    let (status, _, after, _) = call(
        &app,
        "GET",
        "/console/api/api-keys",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after.as_array().unwrap().len(), 0);

    let (status, _, requests, _) = call(
        &app,
        "GET",
        "/console/api/system/usage/requests?period=24h&limit=10",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{requests}");
    assert_eq!(requests["items"].as_array().unwrap().len(), 0);

    let (status, _, by_model, _) = call(
        &app,
        "GET",
        "/console/api/system/usage/by-model?period=24h",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{by_model}");
    assert_eq!(by_model["rows"].as_array().unwrap().len(), 0);

    let (status, _, bad_dimension, _) = call(
        &app,
        "GET",
        "/console/api/system/usage/by-nope?period=24h",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(bad_dimension["error"]["code"], "invalid_dimension");

    let (status, _, readiness, _) = call(
        &app,
        "GET",
        "/console/api/system/readiness",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{readiness}");
    assert_eq!(readiness["ready"], false);
    let checks = readiness["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 5);
    assert_eq!(checks[0]["id"], "admin_created");
    assert_eq!(checks[0]["ok"], true);
    assert_eq!(checks[3]["ok"], false);

    // A session-cookie mutation without the double-submit token is refused.
    let (status, _, csrf_refusal, _) = call(
        &app,
        "PATCH",
        "/console/api/settings/runtime",
        Some(&cookie_header),
        None,
        Some(json!({"telemetryPayloads": "none"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(csrf_refusal["error"]["code"], "csrf_invalid");

    // Runtime settings: defaults, merge, and invalid literal rejection.
    let (status, _, settings, _) = call(
        &app,
        "GET",
        "/console/api/settings/runtime",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(settings["telemetryPayloads"], "metadata");
    assert_eq!(settings["privacyMode"], "masked");

    let (status, _, patched_settings, _) = call(
        &app,
        "PATCH",
        "/console/api/settings/runtime",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"telemetryPayloads": "none", "tenantConcurrencyLimit": 7})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched_settings}");
    assert_eq!(patched_settings["telemetryPayloads"], "none");
    assert_eq!(patched_settings["tenantConcurrencyLimit"], 7);

    let (status, _, invalid_settings, _) = call(
        &app,
        "PATCH",
        "/console/api/settings/runtime",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"privacyMode": "nope"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_settings["error"]["code"], "invalid_request");

    // Network pools: create, list, strategy, live snapshot.
    let (status, _, pool_body, _) = call(
        &app,
        "POST",
        "/console/api/network/pools",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"kind": "http", "label": "test pool", "endpoint": "http://127.0.0.1:3128", "maxInflight": 5})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pool_body}");
    assert_eq!(pool_body["kind"], "http");
    assert_eq!(pool_body["label"], "test pool");
    assert_eq!(pool_body["maxInflight"], 5);
    let pool_id = pool_body["id"].as_str().unwrap().to_owned();

    let (status, _, pools, _) = call(
        &app,
        "GET",
        "/console/api/network/pools",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pools}");
    assert_eq!(pools.as_array().unwrap().len(), 1);

    let (status, _, strategy, _) = call(
        &app,
        "PATCH",
        "/console/api/network/pools/strategy",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"strategy": "round_robin", "rotateCount": 3})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{strategy}");
    assert_eq!(strategy["strategy"], "round_robin");

    let (status, _, live_pools, _) = call(
        &app,
        "GET",
        "/console/api/live/pools",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{live_pools}");
    assert_eq!(live_pools["pools"].as_array().unwrap().len(), 1);

    let (status, _, inflight, _) = call(
        &app,
        "GET",
        "/console/api/live/in-flight",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inflight["inFlight"], 0);

    // Custom provider with one BYOK model, then model disable/delete.
    let (status, _, provider, _) = call(
        &app,
        "POST",
        "/console/api/providers",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({
            "providerId": "smoketest",
            "baseUrl": "http://127.0.0.1:9999",
            "wireFamily": "chat",
            "models": ["smoke-model"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{provider}");
    assert_eq!(provider["modelCount"], 1);
    assert_eq!(provider["isBuiltIn"], false);

    let (status, _, provider_models, _) = call(
        &app,
        "GET",
        "/console/api/providers/smoketest/models",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{provider_models}");
    assert_eq!(provider_models.as_array().unwrap().len(), 1);
    assert_eq!(provider_models[0]["modelId"], "smoke-model");

    let (status, _, model_patch, _) = call(
        &app,
        "PATCH",
        "/console/api/providers/smoketest/models",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"modelId": "smoke-model", "route": "/v1/chat/completions", "enabled": false})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{model_patch}");
    assert_eq!(model_patch["success"], true);

    let (status, _, provider_deleted, _) = call(
        &app,
        "DELETE",
        "/console/api/providers/smoketest",
        Some(&cookie_header),
        Some(&csrf_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{provider_deleted}");
    assert_eq!(provider_deleted["success"], true);

    // Provider account lifecycle on a built-in provider.
    let (status, _, account, _) = call(
        &app,
        "POST",
        "/console/api/providers/anthropic/accounts",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"label": "test account", "credentialKind": "api_key", "secret": "sk-test"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    assert_eq!(account["label"], "test account");
    assert_eq!(account["status"], "active");
    let account_id = account["id"].as_str().unwrap().to_owned();

    let (status, _, account_patch, _) = call(
        &app,
        "PATCH",
        &format!("/console/api/providers/anthropic/accounts/{account_id}"),
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"label": "test account 2", "status": "disabled", "staticToken": true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{account_patch}");
    assert_eq!(account_patch["label"], "test account 2");
    assert_eq!(account_patch["status"], "disabled");
    assert_eq!(account_patch["staticToken"], true);

    let (status, _, recovered, _) = call(
        &app,
        "POST",
        &format!("/console/api/providers/anthropic/accounts/{account_id}/recover"),
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{recovered}");
    assert_eq!(recovered["success"], true);

    let (status, _, events, _) = call(
        &app,
        "GET",
        &format!("/console/api/providers/anthropic/accounts/{account_id}/health-events"),
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{events}");
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(events[0]["toStatus"], "active");

    let (status, _, quota, _) = call(
        &app,
        "GET",
        "/console/api/quota/overview",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{quota}");
    assert!(!quota["accounts"].as_array().unwrap().is_empty());
    assert!(!quota["providers"].as_array().unwrap().is_empty());

    // Studio session lifecycle.
    let (status, _, studio, _) = call(
        &app,
        "POST",
        "/console/api/studio/sessions",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"title": "test session", "model": "opencodeft/big-pickle"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{studio}");
    assert_eq!(studio["title"], "test session");
    let session_id = studio["id"].as_str().unwrap().to_owned();

    let (status, _, sessions, _) = call(
        &app,
        "GET",
        "/console/api/studio/sessions",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sessions}");
    assert_eq!(sessions["items"].as_array().unwrap().len(), 1);

    let (status, _, updated_session, _) = call(
        &app,
        "PATCH",
        &format!("/console/api/studio/sessions/{session_id}"),
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({"messages": [{"role": "user", "content": "hi", "ts": "2026-01-01T00:00:00.000Z"}]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated_session}");
    assert_eq!(updated_session["messages"].as_array().unwrap().len(), 1);

    let (status, _, deleted_session, _) = call(
        &app,
        "DELETE",
        &format!("/console/api/studio/sessions/{session_id}"),
        Some(&cookie_header),
        Some(&csrf_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted_session}");
    assert_eq!(deleted_session["success"], true);

    // Console logs snapshot and clear.
    let (status, _, logs, _) = call(
        &app,
        "GET",
        "/console/api/logs?limit=10",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{logs}");
    assert!(logs["lines"].is_array());

    let (status, _, cleared, _) = call(
        &app,
        "DELETE",
        "/console/api/logs",
        Some(&cookie_header),
        Some(&csrf_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert_eq!(cleared["success"], true);

    let (status, _, pool_deleted, _) = call(
        &app,
        "DELETE",
        &format!("/console/api/network/pools/{pool_id}"),
        Some(&cookie_header),
        Some(&csrf_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pool_deleted}");
    assert_eq!(pool_deleted["success"], true);

    // New console surfaces answer with valid empty/aggregate shapes.
    let (status, _, audit, _) = call(
        &app,
        "GET",
        "/console/api/audit",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    assert!(audit["entries"].is_array());

    let (status, _, bans, _) = call(
        &app,
        "GET",
        "/console/api/model-bans",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bans}");
    assert!(bans["bans"].is_array());

    let (status, _, quota_one, _) = call(
        &app,
        "GET",
        &format!("/console/api/accounts/{account_id}/quota"),
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{quota_one}");
    assert_eq!(quota_one["accountId"], account_id);

    let (status, _, performance, _) = call(
        &app,
        "GET",
        "/console/api/system/performance",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{performance}");
    assert!(performance["memory_bytes"].is_object());

    let (status, _, legacy_usage, _) = call(
        &app,
        "GET",
        "/console/api/system/usage?period=24h",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{legacy_usage}");
    assert_eq!(legacy_usage["period"], "24h");

    let (status, _, cache, _) = call(
        &app,
        "GET",
        "/console/api/system/usage/cache?period=24h",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cache}");
    assert!(cache["inputTokens"].is_number());

    let (status, _, shares, _) = call(
        &app,
        "GET",
        "/console/api/api-keys/share-template/shares",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    // The unknown id is a clean 404, not a panic or 500.
    assert_eq!(status, StatusCode::NOT_FOUND, "{shares}");

    let (status, _, registry, _) = call(
        &app,
        "GET",
        "/console/api/cli-tools/registry",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{registry}");
    assert_eq!(registry.as_array().unwrap().len(), 17);

    let (status, _, statuses, _) = call(
        &app,
        "GET",
        "/console/api/cli-tools/all-statuses",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{statuses}");
    assert_eq!(statuses.as_object().unwrap().len(), 17);

    let (status, _, download, _) = call(
        &app,
        "POST",
        "/console/api/cli-tools/claude/download",
        Some(&cookie_header),
        Some(&csrf_token),
        Some(json!({
            "endpoint": "http://127.0.0.1:12800",
            "apiKey": "rk_test",
            "modelIds": ["model-a"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{download}");
    assert!(
        download["content"]
            .as_str()
            .unwrap()
            .contains("ANTHROPIC_BASE_URL")
    );

    // Unknown-user failures accumulate to a lockout for the same key.
    let mut last_status = StatusCode::OK;
    for _ in 0..5 {
        let (status, _, _, _) = call(
            &app,
            "POST",
            "/console/api/auth/login",
            None,
            None,
            Some(json!({"username": "ghost", "password": "x"})),
        )
        .await;
        last_status = status;
    }
    assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
    let (status, headers, _, _) = call(
        &app,
        "POST",
        "/console/api/auth/login",
        None,
        None,
        Some(json!({"username": "ghost", "password": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.get("retry-after").is_some());

    // Logout clears the cookie and invalidates the session server-side.
    let (status, _, body, cleared) = call(
        &app,
        "POST",
        "/console/api/auth/logout",
        Some(&cookie_header),
        Some(&csrf_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(cleared.iter().any(|cookie| cookie.contains("Max-Age=0")));
    let (_, _, body, _) = call(
        &app,
        "GET",
        "/console/api/auth/session",
        Some(&cookie_header),
        None,
        None,
    )
    .await;
    assert_eq!(body["status"], "unauthenticated");

    pool.close().await;
    postgresql.stop().await.unwrap();
}
