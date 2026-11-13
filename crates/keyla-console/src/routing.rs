//! Routing control-plane reads and the read-only route simulator.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use keyla_providers::provider_display_name;
use keyla_routing::{
    CooldownKind, EligibilityReason, HealthStatus, InMemoryAdmissionController, RoutingEngine,
    SIMULATOR_ENDPOINTS,
};
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::{console_error_body, require_scope, resolve_console_access};
use crate::routes::ConsoleState;

fn json_response(status: StatusCode, value: Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(serde_json::to_vec(&value).unwrap_or_default()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

use axum::response::IntoResponse;

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, console_error_body(code, message))
}

async fn require_dashboard_read(
    state: &ConsoleState,
    headers: &HeaderMap,
) -> Result<
    (
        String,
        Arc<keyla_db::snapshot::SnapshotService>,
        Arc<RoutingEngine>,
    ),
    Box<Response>,
> {
    let Some(access) = resolve_console_access(&state.pool, headers)
        .await
        .ok()
        .flatten()
    else {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        )));
    };
    if let Err(error) = require_scope(&access, "dashboard:read") {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            &error.message,
        )));
    }
    let Some(tenant) = access.tenant_id else {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        )));
    };
    Ok((
        tenant,
        Arc::clone(&state.snapshots),
        Arc::clone(&state.engine),
    ))
}

async fn model_limits(pool: &sqlx::PgPool, tenant_id: &str, model_id: &str) -> (i64, i64) {
    let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT max(context_limit)::bigint, max(output_limit)::bigint
         FROM models m JOIN providers p ON p.id = m.provider_id
         WHERE m.model_id = $1 AND (p.tenant_id IS NULL OR p.tenant_id = $2::uuid)",
    )
    .bind(model_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    match row {
        Some((context, output)) => (context.unwrap_or(200_000), output.unwrap_or(64_192)),
        None => (200_000, 64_192),
    }
}

/// `GET /console/api/routing/aliases`.
pub async fn list_aliases(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let (tenant, _, _) = match require_dashboard_read(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, alias, target_model,
                created_at, updated_at
         FROM model_aliases WHERE tenant_id = $1::uuid
         ORDER BY sort_index, created_at, id",
    )
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("alias list failed: {error}"),
            );
        }
    };
    let mut data = Vec::new();
    for row in rows {
        let target: String = row.get("target_model");
        let (context, output) = model_limits(&state.pool, &tenant, &target).await;
        data.push(json!({
            "id": row.get::<String, _>("id"),
            "tenantId": row.get::<String, _>("tenant_id"),
            "alias": row.get::<String, _>("alias"),
            "targetModel": target,
            "contextLimit": context,
            "outputLimit": output,
            "createdAt": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "updatedAt": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }));
    }
    json_response(StatusCode::OK, Value::Array(data))
}

/// `GET /console/api/routing/combos`.
pub async fn list_combos(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let (tenant, _, _) = match require_dashboard_read(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, members,
                strategy::text AS strategy, created_at, updated_at
         FROM model_combos WHERE tenant_id = $1::uuid
         ORDER BY sort_index, created_at, id",
    )
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("combo list failed: {error}"),
            );
        }
    };
    let mut data = Vec::new();
    for row in rows {
        let members: Vec<String> = row
            .get::<Option<Value>, _>("members")
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let mut context = i64::MAX;
        let mut output = i64::MAX;
        for member in &members {
            let (member_context, member_output) = model_limits(&state.pool, &tenant, member).await;
            context = context.min(member_context);
            output = output.min(member_output);
        }
        if members.is_empty() {
            context = 200_000;
            output = 64_192;
        }
        data.push(json!({
            "id": row.get::<String, _>("id"),
            "tenantId": row.get::<String, _>("tenant_id"),
            "name": row.get::<String, _>("name"),
            "members": members,
            "strategy": row.get::<String, _>("strategy"),
            "contextLimit": context,
            "outputLimit": output,
            "createdAt": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "updatedAt": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }));
    }
    json_response(StatusCode::OK, Value::Array(data))
}

fn reason_message(code: &str) -> &'static str {
    match code {
        "healthy" => "Eligible and healthy.",
        "cooldown" => "Cooling down after a recent failure; ordered behind healthy candidates.",
        "cooldown_hard" => "Excluded: a hard cooldown is still in effect.",
        "model_cooldown" => "Excluded: this exact account+model pair is cooling down.",
        "credit_floor_reached" => {
            "Excluded: remaining balance is at or below the configured floor."
        }
        "quota_exhausted" => "Excluded: the account's quota is exhausted.",
        "locked" => "Excluded: the account is locked.",
        "disabled" => "Excluded: an operator disabled this account.",
        "service_kind_mismatch" => "This model is not served on the requested endpoint family.",
        _ => "Unknown eligibility reason.",
    }
}

/// `POST /console/api/routing/simulate`.
pub async fn simulate(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let (tenant, snapshots, engine) = match require_dashboard_read(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Some(model) = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
    else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "model is required",
        );
    };
    let endpoint = body
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or("chat.completions");
    if !SIMULATOR_ENDPOINTS.contains(&endpoint) {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            &format!(
                "endpoint must be one of: {}",
                SIMULATOR_ENDPOINTS.join(", ")
            ),
        );
    }
    let snapshot = match snapshots.get().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "platform_unavailable",
                &error.message,
            );
        }
    };
    let result = match engine.simulate(model, endpoint, &snapshot, Some(&tenant)) {
        Ok(result) => result,
        Err(error) => {
            return json_response(
                StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
                error.public_body(),
            );
        }
    };
    let candidates: Vec<Value> = result
        .candidates
        .iter()
        .enumerate()
        .map(|(priority, entry)| {
            let candidate = &entry.candidate;
            let reasons = if entry.endpoint_supported {
                vec![json!({
                    "code": entry.reason.as_str(),
                    "message": reason_message(entry.reason.as_str()),
                })]
            } else {
                vec![json!({
                    "code": "service_kind_mismatch",
                    "message": format!(
                        "{} (this model serves '{}').",
                        reason_message("service_kind_mismatch"),
                        candidate.service_kind.as_str()
                    ),
                })]
            };
            let quota =
                if candidate.credit_limit_enabled.is_none() && candidate.credit_limit.is_none() {
                    Value::Null
                } else {
                    let status = if candidate.last_remaining_credit.is_none()
                        && candidate.last_remaining_percent.is_none()
                    {
                        "unknown"
                    } else if entry.reason == EligibilityReason::CreditFloorReached {
                        "below_floor"
                    } else {
                        "ok"
                    };
                    let mut value = serde_json::Map::new();
                    value.insert("status".into(), json!(status));
                    if let Some(enabled) = candidate.credit_limit_enabled {
                        value.insert("creditLimitEnabled".into(), json!(enabled));
                    }
                    if let Some(limit) = candidate.credit_limit {
                        value.insert("creditLimit".into(), json!(limit));
                    }
                    if let Some(credit) = candidate.last_remaining_credit {
                        value.insert("lastRemainingCredit".into(), json!(credit));
                    }
                    if let Some(percent) = candidate.last_remaining_percent {
                        value.insert("lastRemainingPercent".into(), json!(percent));
                    }
                    Value::Object(value)
                };
            let provider_routing = entry.provider_routing.as_ref().map(|setting| {
                json!({
                    "strategy": setting.strategy.as_str(),
                    "rotateCount": setting.rotate_count,
                    "enabled": setting.enabled,
                    "bypassProxy": setting.bypass_proxy,
                })
            });
            let mut value = serde_json::Map::new();
            value.insert("providerId".into(), json!(candidate.provider_id));
            value.insert(
                "providerLabel".into(),
                json!(provider_display_name(&candidate.provider_id)),
            );
            value.insert("modelId".into(), json!(candidate.model_id));
            if let Some(account) = &candidate.provider_account_id {
                value.insert("accountId".into(), json!(account));
            }
            if let Some(label) = &candidate.provider_account_label {
                value.insert("accountLabel".into(), json!(label));
            }
            value.insert("wireFamily".into(), json!(candidate.wire_family.as_str()));
            value.insert("serviceKind".into(), json!(candidate.service_kind.as_str()));
            value.insert("upstreamEndpoint".into(), json!(candidate.endpoint));
            value.insert("eligible".into(), json!(entry.eligible));
            value.insert("reasons".into(), Value::Array(reasons));
            value.insert("priority".into(), json!(priority));
            if let Some(kind) = candidate.cooldown_kind {
                value.insert(
                    "cooldownKind".into(),
                    json!(match kind {
                        CooldownKind::Hard => "hard",
                        CooldownKind::Soft => "soft",
                    }),
                );
            }
            if let Some(until) = &candidate.cooldown_until {
                value.insert("cooldownUntil".into(), json!(until));
            }
            if let Some(until) = &candidate.model_cooldown_until {
                value.insert("modelCooldownUntil".into(), json!(until));
            }
            if let Some(max) = candidate.max_inflight {
                value.insert("maxInflight".into(), json!(max));
            }
            if !quota.is_null() {
                value.insert("quota".into(), quota);
            }
            if let Some(routing) = provider_routing {
                value.insert("providerRouting".into(), routing);
            }
            Value::Object(value)
        })
        .collect();
    let selected = result.selected.as_ref().map(|candidate| {
        let mut value = serde_json::Map::new();
        value.insert("providerId".into(), json!(candidate.provider_id));
        value.insert("modelId".into(), json!(candidate.model_id));
        if let Some(account) = &candidate.provider_account_id {
            value.insert("accountId".into(), json!(account));
        }
        Value::Object(value)
    });
    let mut notes = Vec::new();
    if result.rotation_active {
        notes.push("More than one candidate can serve this request; the first is chosen at dispatch time by the rotation cursor.");
    }
    match result.outcome {
        keyla_routing::RouteSimulationOutcome::AccountsRateLimited => {
            notes.push("Every eligible account is rate limited or cooling down.");
        }
        keyla_routing::RouteSimulationOutcome::AccountsUnavailable => {
            notes.push("No account serving this model is currently usable.");
        }
        keyla_routing::RouteSimulationOutcome::ServiceKindUnsupported => {
            notes.push("No candidate serves this endpoint family for this model.");
        }
        _ => {}
    }
    if !result.unmatched_members.is_empty() {
        notes.push("Some combo members matched no candidate and were not evaluated.");
    }
    notes.push("Nothing was dispatched, reserved, or decrypted to produce this result.");
    let fusion = result
        .fusion
        .as_ref()
        .map(|fusion| json!({"panel": fusion.panel, "judge": fusion.judge}));
    json_response(
        StatusCode::OK,
        json!({
            "model": result.requested_model,
            "resolvedModel": result.resolved_model,
            "resolutionChain": result.resolution_chain,
            "revision": result.revision,
            "readOnly": true,
            "strategy": result.strategy,
            "strategySource": result.strategy_source,
            "rotationActive": result.rotation_active,
            "outcome": result.outcome.as_str(),
            "candidates": candidates,
            "selected": selected,
            "selectedIsDeterministic": selected.is_some(),
            "fusion": fusion,
            "unmatchedMembers": result.unmatched_members,
            "notes": notes,
        }),
    )
}

/// Shared engine constructor for the console's read-only simulator.
pub fn simulator_engine() -> Arc<RoutingEngine> {
    Arc::new(RoutingEngine::new(Arc::new(
        InMemoryAdmissionController::new(),
    )))
}

/// The eligibility tag used when a candidate is healthy but excluded by a
/// health stamp; kept for parity with the dashboard's stable reason tone.
pub fn health_reason(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Cooldown => "cooldown",
        HealthStatus::ModelCooldown => "model_cooldown",
        HealthStatus::CreditFloorReached => "credit_floor_reached",
        HealthStatus::Disabled => "disabled",
    }
}

// --- Alias and combo mutations ---------------------------------------------

use axum::Json;
use axum::extract::Path;

async fn require_dashboard_write(
    state: &ConsoleState,
    headers: &HeaderMap,
) -> Result<String, Box<Response>> {
    let Some(access) = resolve_console_access(&state.pool, headers)
        .await
        .ok()
        .flatten()
    else {
        return Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        )));
    };
    if let Err(error) = require_scope(&access, "dashboard:write") {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            &error.message,
        )));
    }
    access.tenant_id.ok_or_else(|| {
        Box::new(error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        ))
    })
}

fn server_error(label: &str, error: impl std::fmt::Display) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("{label}: {error}"),
    )
}

async fn alias_entries(
    state: &ConsoleState,
    tenant: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let rows: Vec<PgRow> =
        sqlx::query("SELECT alias, target_model FROM model_aliases WHERE tenant_id = $1::uuid")
            .bind(tenant)
            .fetch_all(&state.pool)
            .await?;
    Ok(rows
        .iter()
        .map(|row| (row.get("alias"), row.get("target_model")))
        .collect())
}

async fn combo_names(state: &ConsoleState, tenant: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT name FROM model_combos WHERE tenant_id = $1::uuid")
        .bind(tenant)
        .fetch_all(&state.pool)
        .await
}

async fn known_models(
    state: &ConsoleState,
    tenant: &str,
    names: &[String],
) -> Result<std::collections::HashSet<String>, sqlx::Error> {
    let mut known = std::collections::HashSet::new();
    for name in names {
        let (provider, model) = match name.split_once('/') {
            Some((provider, model)) if !provider.is_empty() && !model.is_empty() => {
                (Some(provider), model)
            }
            Some(_) => continue,
            None => (None, name.as_str()),
        };
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM models m JOIN providers p ON p.id = m.provider_id
                WHERE m.model_id = $1
                  AND ($2::text IS NULL OR p.id = $2)
                  AND m.enabled = true AND p.enabled = true
                  AND (p.tenant_id IS NULL OR p.tenant_id = $3::uuid)
            )",
        )
        .bind(model)
        .bind(provider)
        .bind(tenant)
        .fetch_one(&state.pool)
        .await?;
        if exists {
            known.insert(name.clone());
        }
    }
    Ok(known)
}

fn alias_cycle(existing: &[(String, String)], alias: &str, target: &str) -> bool {
    let by_alias: std::collections::HashMap<&str, &str> = existing
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut current = target;
    for _ in 0..16 {
        if current == alias {
            return true;
        }
        let Some(next) = by_alias.get(current) else {
            return false;
        };
        current = next;
    }
    true
}

async fn target_resolves(
    state: &ConsoleState,
    tenant: &str,
    target: &str,
    existing: &[(String, String)],
    combos: &[String],
) -> Result<bool, sqlx::Error> {
    let by_alias: std::collections::HashMap<&str, &str> = existing
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut current = target;
    for _ in 0..16 {
        if combos.iter().any(|name| name == current) {
            return Ok(true);
        }
        let Some(next) = by_alias.get(current) else {
            let found = known_models(state, tenant, &[current.to_owned()]).await?;
            return Ok(!found.is_empty());
        };
        current = next;
    }
    Ok(false)
}

async fn alias_row(state: &ConsoleState, tenant: &str, id: &str) -> Option<Value> {
    let row = sqlx::query(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, alias, target_model, created_at, updated_at
         FROM model_aliases WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()?;
    let target: String = row.get("target_model");
    let (context, output) = model_limits(&state.pool, tenant, &target).await;
    Some(json!({
        "id": row.get::<String, _>("id"),
        "tenantId": row.get::<String, _>("tenant_id"),
        "alias": row.get::<String, _>("alias"),
        "targetModel": target,
        "contextLimit": context,
        "outputLimit": output,
        "createdAt": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "updatedAt": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
}

async fn combo_row(state: &ConsoleState, tenant: &str, id: &str) -> Option<Value> {
    let row = sqlx::query(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, name, members,
                strategy::text AS strategy, created_at, updated_at
         FROM model_combos WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()?;
    let members: Vec<String> = row
        .get::<Option<Value>, _>("members")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut context = i64::MAX;
    let mut output = i64::MAX;
    for member in &members {
        let (member_context, member_output) = model_limits(&state.pool, tenant, member).await;
        context = context.min(member_context);
        output = output.min(member_output);
    }
    if members.is_empty() {
        context = 200_000;
        output = 64_192;
    }
    Some(json!({
        "id": row.get::<String, _>("id"),
        "tenantId": row.get::<String, _>("tenant_id"),
        "name": row.get::<String, _>("name"),
        "members": members,
        "strategy": row.get::<String, _>("strategy"),
        "contextLimit": context,
        "outputLimit": output,
        "createdAt": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "updatedAt": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
}

fn invalid(code: &str, status: StatusCode, message: &str) -> Response {
    error_response(status, code, message)
}

/// `POST /console/api/routing/aliases`.
pub async fn create_alias(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let alias = body
        .get("alias")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let target = body
        .get("targetModel")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if alias.is_empty() || target.is_empty() {
        return invalid(
            "invalid_request",
            StatusCode::UNPROCESSABLE_ENTITY,
            "alias and targetModel are required",
        );
    }
    if alias == target {
        return invalid(
            "self_reference",
            StatusCode::UNPROCESSABLE_ENTITY,
            "alias cannot target itself",
        );
    }
    let existing = match alias_entries(&state, &tenant).await {
        Ok(rows) => rows,
        Err(error) => return server_error("alias list failed", error),
    };
    if existing.iter().any(|(name, _)| name == alias) {
        return invalid(
            "alias_conflict",
            StatusCode::CONFLICT,
            &format!("Alias {alias} already exists for this tenant"),
        );
    }
    if alias_cycle(&existing, alias, target) {
        return invalid(
            "alias_cycle",
            StatusCode::UNPROCESSABLE_ENTITY,
            "alias target introduces a cycle",
        );
    }
    let combos = match combo_names(&state, &tenant).await {
        Ok(names) => names,
        Err(error) => return server_error("combo list failed", error),
    };
    match target_resolves(&state, &tenant, target, &existing, &combos).await {
        Ok(true) => {}
        Ok(false) => {
            return invalid(
                "unresolved_target",
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("targetModel {target} does not resolve to a known model or combo"),
            );
        }
        Err(error) => return server_error("model lookup failed", error),
    }
    let inserted = sqlx::query(
        "INSERT INTO model_aliases (tenant_id, alias, target_model, sort_index)
         VALUES ($1::uuid, $2, $3,
           (SELECT coalesce(max(sort_index) + 1, 0) FROM model_aliases WHERE tenant_id = $1::uuid))
         RETURNING id::text AS id",
    )
    .bind(&tenant)
    .bind(alias)
    .bind(target)
    .fetch_one(&state.pool)
    .await;
    match inserted {
        Ok(row) => {
            let id: String = row.get("id");
            let Some(value) = alias_row(&state, &tenant, &id).await else {
                return invalid(
                    StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "alias readback failed",
                );
            };
            state.snapshots.invalidate();
            json_response(StatusCode::OK, value)
        }
        Err(error) => server_error("alias insert failed", error),
    }
}

/// `PATCH /console/api/routing/aliases/{id}`.
pub async fn update_alias(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let current = match alias_row(&state, &tenant, &id).await {
        Some(value) => value,
        None => {
            return invalid(
                "alias_not_found",
                StatusCode::NOT_FOUND,
                &format!("Alias {id} not found"),
            );
        }
    };
    let current_alias = current["alias"].as_str().unwrap_or("").to_owned();
    let current_target = current["targetModel"].as_str().unwrap_or("").to_owned();
    let next_alias = body
        .get("alias")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&current_alias)
        .to_owned();
    let next_target = body
        .get("targetModel")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&current_target)
        .to_owned();
    if next_alias == next_target {
        return invalid(
            "self_reference",
            StatusCode::UNPROCESSABLE_ENTITY,
            "alias cannot target itself",
        );
    }
    let existing = match alias_entries(&state, &tenant).await {
        Ok(rows) => rows,
        Err(error) => return server_error("alias list failed", error),
    };
    if next_alias != current_alias && existing.iter().any(|(name, _)| name == &next_alias) {
        return invalid(
            "alias_conflict",
            StatusCode::CONFLICT,
            &format!("Alias {next_alias} already exists for this tenant"),
        );
    }
    let validation: Vec<(String, String)> = existing
        .iter()
        .map(|(name, target)| {
            if name == &current_alias {
                (next_alias.clone(), next_target.clone())
            } else {
                (name.clone(), target.clone())
            }
        })
        .collect();
    if alias_cycle(&validation, &next_alias, &next_target) {
        return invalid(
            "alias_cycle",
            StatusCode::UNPROCESSABLE_ENTITY,
            "alias target introduces a cycle",
        );
    }
    let combos = match combo_names(&state, &tenant).await {
        Ok(names) => names,
        Err(error) => return server_error("combo list failed", error),
    };
    match target_resolves(&state, &tenant, &next_target, &validation, &combos).await {
        Ok(true) => {}
        Ok(false) => {
            return invalid(
                "unresolved_target",
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("targetModel {next_target} does not resolve to a known model or combo"),
            );
        }
        Err(error) => return server_error("model lookup failed", error),
    }
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error("transaction failed", error),
    };
    if let Err(error) = sqlx::query(
        "UPDATE model_aliases SET alias = $3, target_model = $4, updated_at = now()
         WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&id)
    .bind(&next_alias)
    .bind(&next_target)
    .execute(&mut *transaction)
    .await
    {
        return server_error("alias update failed", error);
    }
    if next_alias != current_alias {
        let _ = sqlx::query(
            "UPDATE model_aliases SET target_model = $3, updated_at = now()
             WHERE tenant_id = $1::uuid AND target_model = $4 AND id <> $2::uuid",
        )
        .bind(&tenant)
        .bind(&id)
        .bind(&next_alias)
        .bind(&current_alias)
        .execute(&mut *transaction)
        .await;
        let _ = sqlx::query(
            "UPDATE model_combos SET members = (
                 SELECT coalesce(jsonb_agg(CASE WHEN value = $3 THEN $4::jsonb ELSE to_jsonb(value) END), '[]'::jsonb)
                 FROM jsonb_array_elements_text(members) AS value
             ), updated_at = now()
             WHERE tenant_id = $1::uuid
               AND members @> jsonb_build_array($3::text)",
        )
        .bind(&tenant)
        .bind(&id)
        .bind(&current_alias)
        .bind(&next_alias)
        .execute(&mut *transaction)
        .await;
    }
    if let Err(error) = transaction.commit().await {
        return server_error("commit failed", error);
    }
    state.snapshots.invalidate();
    match alias_row(&state, &tenant, &id).await {
        Some(value) => json_response(StatusCode::OK, value),
        None => invalid("alias_not_found", StatusCode::NOT_FOUND, "Alias not found"),
    }
}

/// `DELETE /console/api/routing/aliases/{id}`.
pub async fn delete_alias(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let deleted = sqlx::query(
        "DELETE FROM model_aliases WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING id",
    )
    .bind(&tenant)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await;
    match deleted {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            json_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => invalid(
            "alias_not_found",
            StatusCode::NOT_FOUND,
            &format!("Alias {id} not found"),
        ),
        Err(error) => server_error("alias delete failed", error),
    }
}

/// `POST /console/api/routing/aliases/reorder`.
pub async fn reorder_aliases(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    reorder_rows(&state, &tenant, &body, "model_aliases").await
}

async fn reorder_rows(state: &ConsoleState, tenant: &str, body: &Value, table: &str) -> Response {
    let Some(ids) = body.get("ids").and_then(Value::as_array) else {
        return invalid(
            "invalid_request",
            StatusCode::UNPROCESSABLE_ENTITY,
            "ids must be an array",
        );
    };
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error("transaction failed", error),
    };
    for (index, value) in ids.iter().enumerate() {
        let Some(id) = value.as_str() else {
            return invalid(
                "invalid_request",
                StatusCode::UNPROCESSABLE_ENTITY,
                "ids must contain strings",
            );
        };
        let statement = format!(
            "UPDATE {table} SET sort_index = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid"
        );
        if let Err(error) = sqlx::query(&statement)
            .bind(tenant)
            .bind(id)
            .bind(index as i32)
            .execute(&mut *transaction)
            .await
        {
            return server_error("reorder failed", error);
        }
    }
    if let Err(error) = transaction.commit().await {
        return server_error("commit failed", error);
    }
    state.snapshots.invalidate();
    json_response(StatusCode::OK, json!({"success": true}))
}

fn combo_strategy(value: Option<&Value>, fallback: &str) -> Result<String, String> {
    let Some(value) = value else {
        return Ok(fallback.to_owned());
    };
    let Some(strategy) = value.as_str() else {
        return Err("strategy is invalid".into());
    };
    if !["fallback", "round_robin", "fusion"].contains(&strategy) {
        return Err("strategy is invalid".into());
    }
    Ok(strategy.to_owned())
}

fn parse_members(body: &Value) -> Result<Vec<String>, String> {
    let Some(members) = body.get("members").and_then(Value::as_array) else {
        return Err("members must be a non-empty array".into());
    };
    if members.is_empty() {
        return Err("members must be a non-empty array".into());
    }
    let mut output = Vec::with_capacity(members.len());
    for member in members {
        let Some(member) = member.as_str().map(str::trim) else {
            return Err("members cannot be empty".into());
        };
        if member.is_empty() {
            return Err("members cannot be empty".into());
        }
        output.push(member.to_owned());
    }
    Ok(output)
}

/// `POST /console/api/routing/combos`.
pub async fn create_combo(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return invalid(
            "invalid_request",
            StatusCode::UNPROCESSABLE_ENTITY,
            "name is required",
        );
    }
    let members = match parse_members(&body) {
        Ok(members) => members,
        Err(message) => {
            return invalid(
                "invalid_request",
                StatusCode::UNPROCESSABLE_ENTITY,
                &message,
            );
        }
    };
    let strategy = match combo_strategy(body.get("strategy"), "fallback") {
        Ok(strategy) => strategy,
        Err(message) => {
            return invalid(
                "invalid_request",
                StatusCode::UNPROCESSABLE_ENTITY,
                &message,
            );
        }
    };
    let combos = match combo_names(&state, &tenant).await {
        Ok(names) => names,
        Err(error) => return server_error("combo list failed", error),
    };
    if combos.iter().any(|existing| existing == name) {
        return invalid(
            "combo_conflict",
            StatusCode::CONFLICT,
            &format!("Combo {name} already exists for this tenant"),
        );
    }
    let aliases = match alias_entries(&state, &tenant).await {
        Ok(entries) => entries,
        Err(error) => return server_error("alias list failed", error),
    };
    let alias_set: std::collections::HashSet<&str> =
        aliases.iter().map(|(alias, _)| alias.as_str()).collect();
    let combo_set: std::collections::HashSet<&str> = combos.iter().map(String::as_str).collect();
    let needing_db: Vec<String> = members
        .iter()
        .filter(|member| {
            member.as_str() != name
                && !alias_set.contains(member.as_str())
                && !combo_set.contains(member.as_str())
        })
        .cloned()
        .collect();
    let known = match known_models(&state, &tenant, &needing_db).await {
        Ok(known) => known,
        Err(error) => return server_error("model lookup failed", error),
    };
    for member in &members {
        if member == name {
            return invalid(
                "unresolved_member",
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("member {member} does not resolve to a known alias, combo, or model"),
            );
        }
        if alias_set.contains(member.as_str())
            || combo_set.contains(member.as_str())
            || known.contains(member)
        {
            continue;
        }
        return invalid(
            "unresolved_member",
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("member {member} does not resolve to a known alias, combo, or model"),
        );
    }
    let inserted = sqlx::query(
        "INSERT INTO model_combos (tenant_id, name, members, strategy, sort_index)
         VALUES ($1::uuid, $2, $3::jsonb, $4::model_combo_strategy,
           (SELECT coalesce(max(sort_index) + 1, 0) FROM model_combos WHERE tenant_id = $1::uuid))
         RETURNING id::text AS id",
    )
    .bind(&tenant)
    .bind(name)
    .bind(json!(members))
    .bind(&strategy)
    .fetch_one(&state.pool)
    .await;
    match inserted {
        Ok(row) => {
            let id: String = row.get("id");
            state.snapshots.invalidate();
            match combo_row(&state, &tenant, &id).await {
                Some(value) => json_response(StatusCode::OK, value),
                None => invalid("combo_not_found", StatusCode::NOT_FOUND, "Combo not found"),
            }
        }
        Err(error) => server_error("combo insert failed", error),
    }
}

/// `PATCH /console/api/routing/combos/{id}`.
pub async fn update_combo(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let current = match combo_row(&state, &tenant, &id).await {
        Some(value) => value,
        None => {
            return invalid(
                "combo_not_found",
                StatusCode::NOT_FOUND,
                &format!("Combo {id} not found"),
            );
        }
    };
    let current_name = current["name"].as_str().unwrap_or("").to_owned();
    let next_name = body
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&current_name)
        .to_owned();
    let next_members = match body.get("members") {
        None => current["members"]
            .as_array()
            .map(|members| {
                members
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        Some(_) => match parse_members(&body) {
            Ok(members) => members,
            Err(message) => {
                return invalid(
                    "invalid_request",
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &message,
                );
            }
        },
    };
    let current_strategy = current["strategy"].as_str().unwrap_or("fallback");
    let strategy = match combo_strategy(body.get("strategy"), current_strategy) {
        Ok(strategy) => strategy,
        Err(message) => {
            return invalid(
                "invalid_request",
                StatusCode::UNPROCESSABLE_ENTITY,
                &message,
            );
        }
    };
    let combos = match combo_names(&state, &tenant).await {
        Ok(names) => names,
        Err(error) => return server_error("combo list failed", error),
    };
    if next_name != current_name && combos.iter().any(|name| name == &next_name) {
        return invalid(
            "combo_conflict",
            StatusCode::CONFLICT,
            &format!("Combo {next_name} already exists for this tenant"),
        );
    }
    if next_members.iter().any(|member| member == &next_name) {
        return invalid(
            "unresolved_member",
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("member {next_name} does not resolve to a known alias, combo, or model"),
        );
    }
    let aliases = match alias_entries(&state, &tenant).await {
        Ok(entries) => entries,
        Err(error) => return server_error("alias list failed", error),
    };
    let alias_set: std::collections::HashSet<&str> =
        aliases.iter().map(|(alias, _)| alias.as_str()).collect();
    let combo_set: std::collections::HashSet<&str> = combos.iter().map(String::as_str).collect();
    let needing_db: Vec<String> = next_members
        .iter()
        .filter(|member| {
            member.as_str() != next_name
                && !alias_set.contains(member.as_str())
                && !combo_set.contains(member.as_str())
        })
        .cloned()
        .collect();
    let known = match known_models(&state, &tenant, &needing_db).await {
        Ok(known) => known,
        Err(error) => return server_error("model lookup failed", error),
    };
    for member in &next_members {
        if alias_set.contains(member.as_str())
            || combo_set.contains(member.as_str())
            || known.contains(member)
        {
            continue;
        }
        return invalid(
            "unresolved_member",
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("member {member} does not resolve to a known alias, combo, or model"),
        );
    }
    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return server_error("transaction failed", error),
    };
    if let Err(error) = sqlx::query(
        "UPDATE model_combos SET name = $3, members = $4::jsonb, strategy = $5::model_combo_strategy, updated_at = now()
         WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&id)
    .bind(&next_name)
    .bind(json!(next_members))
    .bind(&strategy)
    .execute(&mut *transaction)
    .await
    {
        return server_error("combo update failed", error);
    }
    if next_name != current_name {
        let _ = sqlx::query(
            "UPDATE model_aliases SET target_model = $3, updated_at = now()
             WHERE tenant_id = $1::uuid AND target_model = $4",
        )
        .bind(&tenant)
        .bind(&id)
        .bind(&next_name)
        .bind(&current_name)
        .execute(&mut *transaction)
        .await;
        let _ = sqlx::query(
            "UPDATE model_combos SET members = (
                 SELECT coalesce(jsonb_agg(CASE WHEN value = $3 THEN $4::jsonb ELSE to_jsonb(value) END), '[]'::jsonb)
                 FROM jsonb_array_elements_text(members) AS value
             ), updated_at = now()
             WHERE tenant_id = $1::uuid AND id <> $2::uuid
               AND members @> jsonb_build_array($3::text)",
        )
        .bind(&tenant)
        .bind(&id)
        .bind(&current_name)
        .bind(&next_name)
        .execute(&mut *transaction)
        .await;
    }
    if let Err(error) = transaction.commit().await {
        return server_error("commit failed", error);
    }
    state.snapshots.invalidate();
    match combo_row(&state, &tenant, &id).await {
        Some(value) => json_response(StatusCode::OK, value),
        None => invalid("combo_not_found", StatusCode::NOT_FOUND, "Combo not found"),
    }
}

/// `DELETE /console/api/routing/combos/{id}`.
pub async fn delete_combo(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let deleted = sqlx::query(
        "DELETE FROM model_combos WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING id",
    )
    .bind(&tenant)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await;
    match deleted {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            json_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => invalid(
            "combo_not_found",
            StatusCode::NOT_FOUND,
            &format!("Combo {id} not found"),
        ),
        Err(error) => server_error("combo delete failed", error),
    }
}

/// `POST /console/api/routing/combos/reorder`.
pub async fn reorder_combos(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    reorder_rows(&state, &tenant, &body, "model_combos").await
}

/// `POST /console/api/routing/combos/{id}/clone`.
pub async fn clone_combo(
    State(state): State<ConsoleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match require_dashboard_write(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let current = match combo_row(&state, &tenant, &id).await {
        Some(value) => value,
        None => {
            return invalid(
                "combo_not_found",
                StatusCode::NOT_FOUND,
                &format!("Combo {id} not found"),
            );
        }
    };
    let current_name = current["name"].as_str().unwrap_or("combo");
    let members: Vec<String> = current["members"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let strategy = current["strategy"].as_str().unwrap_or("fallback");
    let existing = match combo_names(&state, &tenant).await {
        Ok(names) => names,
        Err(error) => return server_error("combo list failed", error),
    };
    let mut name = format!("{current_name} (copy)");
    let mut suffix = 2;
    while existing.iter().any(|existing| existing == &name) {
        name = format!("{current_name} (copy {suffix})");
        suffix += 1;
    }
    let aliases = match alias_entries(&state, &tenant).await {
        Ok(entries) => entries,
        Err(error) => return server_error("alias list failed", error),
    };
    let alias_set: std::collections::HashSet<&str> =
        aliases.iter().map(|(alias, _)| alias.as_str()).collect();
    let combo_set: std::collections::HashSet<&str> = existing.iter().map(String::as_str).collect();
    let needing_db: Vec<String> = members
        .iter()
        .filter(|member| {
            !alias_set.contains(member.as_str()) && !combo_set.contains(member.as_str())
        })
        .cloned()
        .collect();
    let known = match known_models(&state, &tenant, &needing_db).await {
        Ok(known) => known,
        Err(error) => return server_error("model lookup failed", error),
    };
    let (kept, skipped): (Vec<String>, Vec<String>) = members.into_iter().partition(|member| {
        alias_set.contains(member.as_str())
            || combo_set.contains(member.as_str())
            || known.contains(member)
    });
    let inserted = sqlx::query(
        "INSERT INTO model_combos (tenant_id, name, members, strategy, sort_index)
         VALUES ($1::uuid, $2, $3::jsonb, $4::model_combo_strategy,
           (SELECT coalesce(max(sort_index) + 1, 0) FROM model_combos WHERE tenant_id = $1::uuid))
         RETURNING id::text AS id",
    )
    .bind(&tenant)
    .bind(&name)
    .bind(json!(kept))
    .bind(strategy)
    .fetch_one(&state.pool)
    .await;
    match inserted {
        Ok(row) => {
            let new_id: String = row.get("id");
            state.snapshots.invalidate();
            let combo = combo_row(&state, &tenant, &new_id).await;
            match combo {
                Some(combo) => json_response(
                    StatusCode::OK,
                    json!({"combo": combo, "skippedMembers": skipped}),
                ),
                None => invalid("combo_not_found", StatusCode::NOT_FOUND, "Combo not found"),
            }
        }
        Err(error) => server_error("combo clone failed", error),
    }
}
