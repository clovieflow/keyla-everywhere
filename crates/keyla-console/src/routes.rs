//! Console auth routes: login, session, logout, first boot, setup, and
//! password rotation. Port of `src/console/auth/session.ts` onto axum.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use sqlx::postgres::PgPool;

use crate::auth::{
    CSRF_HEADER_NAME, SESSION_COOKIE_NAME, SessionCookiePolicy, clear_csrf_cookie,
    clear_session_cookie, complete_setup, create_session, csrf_cookie, csrf_valid,
    default_session_cookie_policy, delete_other_sessions, delete_session, find_user_by_id,
    find_user_by_username, has_any_user, hash_password, new_token, parse_cookie, record_failure,
    remaining_lock_seconds, session_cookie, validate_session, verify_password,
};

#[derive(Clone)]
pub struct ConsoleState {
    pub pool: PgPool,
    pub policy: SessionCookiePolicy,
    pub snapshots: Arc<keyla_db::snapshot::SnapshotService>,
    pub engine: Arc<keyla_routing::RoutingEngine>,
    pub started: std::time::Instant,
}

impl ConsoleState {
    pub fn new(pool: PgPool) -> Self {
        let env = keyla_config::ProcessEnv;
        let origin = keyla_config::require_public_origin(&env).ok();
        Self {
            snapshots: keyla_db::snapshot::SnapshotService::new(
                pool.clone(),
                std::time::Duration::from_secs(30),
            )
            .shared(),
            engine: crate::routing::simulator_engine(),
            started: std::time::Instant::now(),
            pool,
            policy: default_session_cookie_policy(origin.as_deref()),
        }
    }

    pub fn with_policy(pool: PgPool, policy: SessionCookiePolicy) -> Self {
        Self {
            snapshots: keyla_db::snapshot::SnapshotService::new(
                pool.clone(),
                std::time::Duration::from_secs(30),
            )
            .shared(),
            engine: crate::routing::simulator_engine(),
            started: std::time::Instant::now(),
            pool,
            policy,
        }
    }
}

/// Enforces the double-submit CSRF contract for session-cookie mutations.
/// Bearer-key requests carry no ambient browser credential and are exempt.
async fn csrf_guard(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let method = request.method().clone();
    if matches!(
        method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        return next.run(request).await;
    }
    let headers = request.headers();
    let cookie_header = headers.get("cookie").and_then(|value| value.to_str().ok());
    let has_session = cookie_header
        .and_then(|header| parse_cookie(Some(header), SESSION_COOKIE_NAME))
        .is_some();
    if has_session {
        let csrf_header = headers
            .get(crate::auth::CSRF_HEADER_NAME)
            .and_then(|value| value.to_str().ok());
        if !csrf_valid(cookie_header, csrf_header) {
            return crate::access::console_response(
                StatusCode::FORBIDDEN,
                crate::access::console_error_body(
                    "csrf_invalid",
                    "A valid CSRF token is required for this request",
                ),
            );
        }
    }
    next.run(request).await
}

/// Full console API router, mounted at `/console/api`.
pub fn console_router(pool: PgPool) -> Router {
    console_router_with_policy(pool, None)
}

pub fn console_router_with_policy(pool: PgPool, policy: Option<SessionCookiePolicy>) -> Router {
    let state = match policy {
        Some(policy) => ConsoleState::with_policy(pool, policy),
        None => ConsoleState::new(pool),
    };
    Router::new()
        .route("/console/api/auth/login", post(login))
        .route("/console/api/auth/session", get(session))
        .route("/console/api/auth/logout", post(logout))
        .route("/console/api/auth/first-boot", get(first_boot))
        .route("/console/api/auth/setup", post(setup))
        .route("/console/api/auth/change-password", post(change_password))
        .route(
            "/console/api/providers",
            get(crate::providers::list_providers).post(crate::providers::create_provider),
        )
        .route(
            "/console/api/providers/models/flat",
            get(crate::providers::list_flat_models),
        )
        .route(
            "/console/api/providers/platform/global/{providerId}",
            axum::routing::patch(crate::providers::update_global_provider)
                .delete(crate::providers::delete_global_provider),
        )
        .route(
            "/console/api/providers/connection-test",
            post(crate::providers::test_byok_connection),
        )
        .route(
            "/console/api/providers/{providerId}",
            get(crate::providers::get_provider_detail)
                .patch(crate::providers::update_provider)
                .delete(crate::providers::delete_provider),
        )
        .route(
            "/console/api/providers/{providerId}/oauth/device/start",
            post(crate::oauth::start_device),
        )
        .route(
            "/console/api/providers/{providerId}/oauth/device/poll",
            post(crate::oauth::poll_device),
        )
        .route(
            "/console/api/providers/{providerId}/oauth/authorize",
            post(crate::oauth::authorize_browser),
        )
        .route(
            "/console/api/providers/{providerId}/oauth/callback",
            get(crate::oauth::browser_callback),
        )
        .route(
            "/console/api/providers/{providerId}/oauth/import",
            post(crate::oauth::import_credential),
        )
        .route(
            "/console/api/providers/{providerId}/accounts",
            post(crate::providers::create_provider_account),
        )
        .route(
            "/console/api/providers/{providerId}/accounts/{accountId}",
            axum::routing::patch(crate::providers::update_provider_account),
        )
        .route(
            "/console/api/providers/{providerId}/accounts/{accountId}/recover",
            post(crate::providers::recover_provider_account),
        )
        .route(
            "/console/api/providers/{providerId}/accounts/export",
            post(crate::providers::export_provider_accounts),
        )
        .route(
            "/console/api/providers/{providerId}/accounts/probe",
            post(crate::providers::probe_accounts),
        )
        .route(
            "/console/api/providers/{providerId}/accounts/{accountId}/health-events",
            get(crate::providers::account_health_events),
        )
        .route(
            "/console/api/providers/{providerId}/models/probe",
            post(crate::providers::probe_model),
        )
        .route(
            "/console/api/providers/{providerId}/models/test-models",
            post(crate::providers::probe_all_models),
        )
        .route(
            "/console/api/providers/{providerId}/models/bulk",
            axum::routing::delete(crate::providers::bulk_delete_provider_models),
        )
        .route(
            "/console/api/providers/{providerId}/models/sync",
            post(crate::providers::sync_provider_models),
        )
        .route(
            "/console/api/providers/{providerId}/models",
            get(crate::providers::list_provider_models)
                .post(crate::providers::register_provider_models)
                .patch(crate::providers::set_provider_model_enabled)
                .delete(crate::providers::delete_provider_model),
        )
        .route(
            "/console/api/providers/{providerId}/accounts",
            get(crate::providers::list_provider_accounts),
        )
        .route(
            "/console/api/providers/{providerId}/routing",
            get(crate::providers::get_provider_routing)
                .patch(crate::providers::update_provider_routing),
        )
        .route(
            "/console/api/providers/{providerId}/account-inflight",
            get(crate::providers::account_inflight),
        )
        .route(
            "/console/api/api-keys",
            get(crate::keys::list_keys).post(crate::keys::create_key),
        )
        .route(
            "/console/api/api-keys/reorder",
            post(crate::keys::reorder_keys),
        )
        .route(
            "/console/api/api-keys/{keyId}/share",
            get(crate::keys::get_share).post(crate::keys::share_key),
        )
        .route(
            "/console/api/api-keys/{keyId}/shares",
            get(crate::keys::list_shares),
        )
        .route(
            "/console/api/api-keys/{keyId}/shares/{shareId}",
            axum::routing::delete(crate::keys::revoke_share),
        )
        .route(
            "/console/api/api-keys/{keyId}/share-popup-image",
            get(crate::keys::share_popup_image),
        )
        .route(
            "/console/api/api-keys/{keyId}/shared-keys",
            get(crate::keys::list_shared_keys),
        )
        .route(
            "/console/api/api-keys/{keyId}/shared-keys/{childKeyId}/activity",
            get(crate::keys::shared_key_activity),
        )
        .route(
            "/console/api/api-keys/{keyId}/regenerate",
            post(crate::keys::regenerate_key),
        )
        .route(
            "/console/api/api-keys/{keyId}",
            get(crate::keys::get_key)
                .patch(crate::keys::update_key)
                .delete(crate::keys::revoke_key),
        )
        .route(
            "/console/api/logs",
            get(crate::logs::list_logs).delete(crate::logs::clear_logs),
        )
        .route("/console/api/logs/stream", get(crate::logs::stream_logs))
        .route(
            "/console/api/accounts/batch",
            axum::routing::patch(crate::accounts::patch_accounts_batch),
        )
        .route(
            "/console/api/accounts/{accountId}",
            axum::routing::patch(crate::accounts::patch_account)
                .delete(crate::accounts::delete_account),
        )
        .route(
            "/console/api/accounts/{accountId}/quota",
            get(crate::accounts::get_quota),
        )
        .route(
            "/console/api/accounts/{accountId}/quota/refresh",
            post(crate::accounts::refresh_quota),
        )
        .route(
            "/console/api/accounts/{accountId}/activity-report",
            post(crate::accounts::provider_action_unsupported),
        )
        .route(
            "/console/api/accounts/{accountId}/reset",
            post(crate::accounts::provider_action_unsupported),
        )
        .route(
            "/console/api/accounts/{accountId}/resets",
            get(crate::accounts::provider_action_unsupported),
        )
        .route(
            "/console/api/quota/refresh",
            post(crate::accounts::refresh_many),
        )
        .route(
            "/console/api/accounts/{accountId}/checkin",
            post(crate::accounts::checkin_unsupported),
        )
        .route(
            "/console/api/global/accounts",
            get(crate::accounts::list_global_accounts),
        )
        .route(
            "/console/api/global/accounts/{accountId}/quota/refresh",
            post(crate::accounts::refresh_global_quota),
        )
        .route(
            "/console/api/global/accounts/{accountId}",
            axum::routing::patch(crate::accounts::patch_global_account)
                .delete(crate::accounts::delete_global_account),
        )
        .route("/console/api/bansos/public", get(crate::bansos::public))
        .route("/console/api/backup/export", get(crate::backup::export))
        .route("/console/api/backup/import", post(crate::backup::import))
        .route(
            "/console/api/backup/delete-all",
            post(crate::backup::delete_all),
        )
        .route("/console/api/audit", get(crate::moderation::list_audit))
        .route(
            "/console/api/model-bans",
            get(crate::moderation::list_model_bans).delete(crate::moderation::unban_model),
        )
        .route(
            "/console/api/cli-tools/registry",
            get(crate::cli_tools::list_registry),
        )
        .route(
            "/console/api/cli-tools/all-statuses",
            get(crate::cli_tools::all_statuses),
        )
        .route(
            "/console/api/cli-tools/{toolId}/apply",
            post(crate::cli_tools::apply_tool),
        )
        .route(
            "/console/api/cli-tools/{toolId}/download",
            post(crate::cli_tools::download_tool),
        )
        .route(
            "/console/api/cli-tools/{toolId}/mappings",
            get(crate::cli_tools::get_mappings).post(crate::cli_tools::save_mappings),
        )
        .route(
            "/console/api/cli-tools/{toolId}/mappings/reset",
            post(crate::cli_tools::reset_mappings),
        )
        .route(
            "/console/api/cli-tools/{toolId}",
            get(crate::cli_tools::tool_status),
        )
        .route("/console/api/quota/overview", get(crate::quota::overview))
        .route(
            "/console/api/studio/sessions",
            get(crate::studio::list_sessions).post(crate::studio::create_session),
        )
        .route("/console/api/studio/key", post(crate::studio::ensure_key))
        .route(
            "/console/api/studio/web-fetch",
            post(crate::studio::web_fetch),
        )
        .route(
            "/console/api/studio/sessions/{id}",
            get(crate::studio::get_session)
                .patch(crate::studio::update_session)
                .delete(crate::studio::delete_session),
        )
        .route("/console/api/live/in-flight", get(crate::live::in_flight))
        .route(
            "/console/api/live/in-flight/stream",
            get(crate::live::in_flight_stream),
        )
        .route("/console/api/live/pools", get(crate::live::pools))
        .route(
            "/console/api/live/pools/stream",
            get(crate::live::pools_stream),
        )
        .route(
            "/console/api/network/pools",
            get(crate::network::list_pools).post(crate::network::create_pool),
        )
        .route(
            "/console/api/network/pools/strategy",
            get(crate::network::get_strategy).patch(crate::network::update_strategy),
        )
        .route(
            "/console/api/network/pools/{poolId}",
            get(crate::network::get_pool)
                .patch(crate::network::update_pool)
                .delete(crate::network::delete_pool),
        )
        .route(
            "/console/api/network/pools/{poolId}/health-events",
            get(crate::network::pool_health_events),
        )
        .route(
            "/console/api/network/pools/{poolId}/recover",
            post(crate::network::recover_pool),
        )
        .route(
            "/console/api/network/pools/{poolId}/health-check",
            post(crate::network::health_check_pool),
        )
        .route(
            "/console/api/network/pools/{poolId}/speed-test",
            post(crate::network::speed_test_pool),
        )
        .route(
            "/console/api/network/pools/test",
            post(crate::network::test_pool),
        )
        .route(
            "/console/api/network/pools/relay/deploy",
            post(crate::network::pool_capability_unsupported),
        )
        .route(
            "/console/api/network/pools/{poolId}/cooldowns/clear",
            post(crate::network::pool_capability_unsupported),
        )
        .route(
            "/console/api/settings/runtime",
            get(crate::settings::get_runtime).patch(crate::settings::update_runtime),
        )
        .route(
            "/console/api/prompt-injection",
            get(crate::prompt_injection::get_settings)
                .patch(crate::prompt_injection::update_settings),
        )
        .route(
            "/console/api/system/health",
            get(crate::observability::system_health),
        )
        .route(
            "/console/api/system/health/stream",
            get(crate::observability::system_health_stream),
        )
        .route(
            "/console/api/system/update",
            get(crate::observability::update_status),
        )
        .route(
            "/console/api/system/usage",
            get(crate::observability::usage),
        )
        .route(
            "/console/api/system/performance",
            get(crate::observability::performance),
        )
        .route(
            "/console/api/system/usage/summary",
            get(crate::observability::usage_summary),
        )
        .route(
            "/console/api/system/usage/cache",
            get(crate::observability::usage_cache),
        )
        .route(
            "/console/api/telemetry/events",
            get(crate::observability::telemetry_events),
        )
        .route(
            "/console/api/telemetry/events/{eventId}",
            get(crate::observability::telemetry_event_detail),
        )
        .route(
            "/console/api/system/usage/chart",
            get(crate::observability::usage_chart),
        )
        .route(
            "/console/api/system/usage/requests",
            get(crate::observability::usage_requests),
        )
        .route(
            "/console/api/system/usage/requests/{requestId}",
            get(crate::observability::usage_request_detail),
        )
        .route(
            "/console/api/system/usage/by-{dimension}",
            get(crate::observability::usage_by),
        )
        .route(
            "/console/api/system/readiness",
            get(crate::observability::readiness),
        )
        .route(
            "/console/api/routing/aliases",
            get(crate::routing::list_aliases).post(crate::routing::create_alias),
        )
        .route(
            "/console/api/routing/aliases/reorder",
            post(crate::routing::reorder_aliases),
        )
        .route(
            "/console/api/routing/aliases/{id}",
            axum::routing::patch(crate::routing::update_alias).delete(crate::routing::delete_alias),
        )
        .route(
            "/console/api/routing/combos",
            get(crate::routing::list_combos).post(crate::routing::create_combo),
        )
        .route(
            "/console/api/routing/combos/reorder",
            post(crate::routing::reorder_combos),
        )
        .route(
            "/console/api/routing/combos/{id}",
            axum::routing::patch(crate::routing::update_combo).delete(crate::routing::delete_combo),
        )
        .route(
            "/console/api/routing/combos/{id}/clone",
            post(crate::routing::clone_combo),
        )
        .route(
            "/console/api/routing/simulate",
            post(crate::routing::simulate),
        )
        .layer(axum::middleware::from_fn(csrf_guard))
        .with_state(state)
}

fn json_response(status: StatusCode, value: Value, cookies: &[String]) -> Response {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store");
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            builder = builder.header("set-cookie", value);
        }
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

use axum::response::IntoResponse;

fn failure(status: StatusCode, message: &str) -> Response {
    json_response(status, json!({"status": "failed", "message": message}), &[])
}

fn cookie_header(headers: &HeaderMap) -> Option<&str> {
    headers.get("cookie").and_then(|value| value.to_str().ok())
}

async fn login(
    State(state): State<ConsoleState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(password) = body.get("password").and_then(Value::as_str) else {
        return failure(StatusCode::BAD_REQUEST, "Missing username or password");
    };
    let username = body
        .get("username")
        .and_then(Value::as_str)
        .or_else(|| body.get("email").and_then(Value::as_str))
        .map(str::trim)
        .filter(|username| !username.is_empty());
    let Some(username) = username else {
        return failure(StatusCode::BAD_REQUEST, "Missing username or password");
    };
    let client_ip = peer.ip().to_string();
    let lockout_key = format!("{}:{client_ip}", username.to_ascii_lowercase());
    let remaining = remaining_lock_seconds(&state.pool, &lockout_key)
        .await
        .unwrap_or(0);
    if remaining > 0 {
        let mut response = failure(
            StatusCode::TOO_MANY_REQUESTS,
            "This login is temporarily blocked due to repeated authentication failures.",
        );
        if let Ok(value) = HeaderValue::from_str(&remaining.to_string()) {
            response.headers_mut().insert("retry-after", value);
        }
        return response;
    }
    let user = find_user_by_username(&state.pool, username)
        .await
        .ok()
        .flatten();
    let Some(user) = user.filter(|user| user.is_active) else {
        let locked = record_failure(
            &state.pool,
            &lockout_key,
            "unknown_user",
            5,
            15 * 60 * 1000,
            60 * 60 * 1000,
        )
        .await
        .unwrap_or(false);
        if locked {
            return failure(
                StatusCode::TOO_MANY_REQUESTS,
                "This login has been blocked due to repeated failed authentication attempts.",
            );
        }
        return failure(StatusCode::UNAUTHORIZED, "Invalid credentials");
    };
    if !verify_password(password, &user.password_hash) {
        let locked = record_failure(
            &state.pool,
            &lockout_key,
            "invalid_password",
            5,
            15 * 60 * 1000,
            60 * 60 * 1000,
        )
        .await
        .unwrap_or(false);
        if locked {
            return failure(
                StatusCode::TOO_MANY_REQUESTS,
                "This login has been blocked due to repeated failed authentication attempts.",
            );
        }
        return failure(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }
    let _ = crate::auth::clear_failures(&state.pool, &lockout_key).await;
    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let (raw_session, _session) = match create_session(
        &state.pool,
        &user.id,
        Some(&client_ip),
        Some(user_agent),
        state.policy,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create a console session",
            );
        }
    };
    let csrf = new_token();
    json_response(
        StatusCode::OK,
        json!({
            "status": "success",
            "user_id": user.id,
            "requires_setup": user.is_first_boot,
        }),
        &[
            session_cookie(state.policy, &raw_session),
            csrf_cookie(state.policy, &csrf),
        ],
    )
}

async fn session(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let Some(token) =
        cookie_header(&headers).and_then(|header| parse_cookie(Some(header), SESSION_COOKIE_NAME))
    else {
        return json_response(StatusCode::OK, json!({"status": "unauthenticated"}), &[]);
    };
    let resolved = validate_session(&state.pool, &token).await.ok().flatten();
    let Some(session) = resolved else {
        return json_response(StatusCode::OK, json!({"status": "unauthenticated"}), &[]);
    };
    let user = find_user_by_id(&state.pool, &session.user_id)
        .await
        .ok()
        .flatten();
    let Some(user) = user.filter(|user| user.is_active) else {
        let _ = delete_session(&state.pool, &token).await;
        return json_response(
            StatusCode::OK,
            json!({"status": "unauthenticated"}),
            &[
                clear_session_cookie(state.policy),
                clear_csrf_cookie(state.policy),
            ],
        );
    };
    let expires_at = chrono::DateTime::from_timestamp_millis(session.expires_at_ms)
        .map(|value| value.to_rfc3339())
        .unwrap_or_default();
    json_response(
        StatusCode::OK,
        json!({
            "status": "authenticated",
            "user_id": user.id,
            "username": user.username,
            "email": user.email.clone().unwrap_or_else(|| user.username.clone()),
            "display_name": user.display_name,
            "is_first_boot": user.is_first_boot,
            "session_expires_at": expires_at,
            "is_platform_admin": user.is_platform_admin,
        }),
        &[],
    )
}

async fn logout(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let cookie = cookie_header(&headers);
    let token = cookie.and_then(|header| parse_cookie(Some(header), SESSION_COOKIE_NAME));
    let csrf_header = headers
        .get(CSRF_HEADER_NAME)
        .and_then(|value| value.to_str().ok());
    if token.is_some() && !csrf_valid(cookie, csrf_header) {
        return failure(StatusCode::FORBIDDEN, "Invalid CSRF token");
    }
    if let Some(token) = &token {
        let _ = delete_session(&state.pool, token).await;
    }
    json_response(
        StatusCode::OK,
        json!({"status": "success"}),
        &[
            clear_session_cookie(state.policy),
            clear_csrf_cookie(state.policy),
        ],
    )
}

async fn first_boot(State(state): State<ConsoleState>) -> Response {
    let requires = has_any_user(&state.pool)
        .await
        .map(|present| !present)
        .unwrap_or(false);
    json_response(StatusCode::OK, json!({"requires_setup": requires}), &[])
}

async fn setup(State(state): State<ConsoleState>, Json(body): Json<Value>) -> Response {
    let Some(password) = body.get("password").and_then(Value::as_str) else {
        return failure(StatusCode::BAD_REQUEST, "Password is required");
    };
    if password.is_empty() {
        return failure(StatusCode::BAD_REQUEST, "Password is required");
    }
    if has_any_user(&state.pool).await.unwrap_or(true) {
        return failure(StatusCode::BAD_REQUEST, "Setup already completed");
    }
    let username = body.get("username").and_then(Value::as_str);
    let display_name = body.get("display_name").and_then(Value::as_str);
    let env = keyla_config::ProcessEnv;
    let default_api_key = keyla_config::resolve_default_gateway_api_key(&env);
    match complete_setup(
        &state.pool,
        password,
        username,
        display_name,
        default_api_key.as_deref(),
    )
    .await
    {
        Ok(()) => json_response(
            StatusCode::OK,
            json!({"status": "success", "message": "Setup completed"}),
            &[],
        ),
        Err(crate::auth::AuthError::SetupAlreadyCompleted) => {
            failure(StatusCode::BAD_REQUEST, "Setup already completed")
        }
        Err(error) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Setup failed: {error}"),
        ),
    }
}

async fn change_password(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let cookie = cookie_header(&headers);
    let csrf_header = headers
        .get(CSRF_HEADER_NAME)
        .and_then(|value| value.to_str().ok());
    let Some(token) = cookie.and_then(|header| parse_cookie(Some(header), SESSION_COOKIE_NAME))
    else {
        return failure(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    if !csrf_valid(cookie, csrf_header) {
        return failure(StatusCode::FORBIDDEN, "Invalid CSRF token");
    }
    let session = validate_session(&state.pool, &token).await.ok().flatten();
    let Some(session) = session else {
        return failure(StatusCode::UNAUTHORIZED, "Session expired");
    };
    let user = find_user_by_id(&state.pool, &session.user_id)
        .await
        .ok()
        .flatten();
    let Some(user) = user.filter(|user| user.is_active) else {
        return failure(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    let current = body
        .get("currentPassword")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let new = body
        .get("newPassword")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if new.chars().count() < 6 {
        return failure(
            StatusCode::BAD_REQUEST,
            "New password must be at least 6 characters",
        );
    }
    if !verify_password(current, &user.password_hash) {
        return failure(StatusCode::UNAUTHORIZED, "Current password is incorrect");
    }
    let hash = match hash_password(new) {
        Ok(hash) => hash,
        Err(error) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Password hashing failed: {error}"),
            );
        }
    };
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => {
            return failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Password change failed: {error}"),
            );
        }
    };
    let updated = sqlx::query(
        "UPDATE console_users SET password_hash = $2, updated_at = now() WHERE id = $1::uuid",
    )
    .bind(&user.id)
    .bind(&hash)
    .execute(&mut *transaction)
    .await;
    if updated.is_err() {
        return failure(StatusCode::INTERNAL_SERVER_ERROR, "Password change failed");
    }
    let invalidated = delete_other_sessions(&state.pool, &user.id, &session.id)
        .await
        .unwrap_or(0);
    let _ = sqlx::query(
        "INSERT INTO admin_audit_log (actor, action, target, detail)
         VALUES ($1, 'console.password_changed', $1, $2)",
    )
    .bind(&user.id)
    .bind(json!({"sessionsInvalidated": invalidated}))
    .execute(&mut *transaction)
    .await;
    let _ = transaction.commit().await;
    json_response(StatusCode::OK, json!({"status": "success"}), &[])
}

/// Shared console state for other domain routers.
pub type SharedConsoleState = Arc<ConsoleState>;
