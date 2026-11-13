//! Provider and model catalog read endpoints for the console.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::{DateTime, SecondsFormat, Utc};
use keyla_providers::{
    is_bundled_provider, provider_display_name, provider_has_adapter_user_agent, provider_metadata,
    provider_service_kinds, provider_supports_web_search,
};
use serde_json::{Map, Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::{authorize_tenant, console_error_body, require_scope, resolve_console_access};
use crate::routes::ConsoleState;

static PROVIDER_CAPABILITIES: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../assets/provider-capabilities.json"))
        .unwrap_or(Value::Null)
});

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

fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn capability_entry(provider_id: &str) -> Option<&'static Value> {
    PROVIDER_CAPABILITIES.get(provider_id)
}

fn bundled_supported_families(provider_id: &str, default: &str) -> Vec<String> {
    let mut families = Vec::new();
    if let Some(entry) = capability_entry(provider_id) {
        if let Some(paths) = entry.get("endpointPaths").and_then(Value::as_object) {
            for family in paths.keys() {
                families.push(family.clone());
            }
        }
    }
    if !families.iter().any(|family| family == default) {
        families.push(default.to_owned());
    }
    families
}

fn oauth_flows(provider_id: &str) -> Option<Value> {
    capability_entry(provider_id)
        .and_then(|entry| entry.get("oauth"))
        .cloned()
}

struct ProviderRow {
    id: String,
    tenant_id: Option<String>,
    enabled: bool,
    requires_account: bool,
    wire_family_default: Option<String>,
    base_url: Option<String>,
    compatibility_profile: Option<Value>,
}

async fn load_provider_rows(
    pool: &sqlx::PgPool,
    tenant_id: &str,
) -> Result<Vec<ProviderRow>, sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id, tenant_id::text AS tenant_id, enabled, requires_account,
                wire_family_default::text AS wire_family_default, base_url, compatibility_profile
         FROM providers
         WHERE tenant_id IS NULL OR tenant_id = $1::uuid
         ORDER BY id",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ProviderRow {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            enabled: row.get("enabled"),
            requires_account: row.get("requires_account"),
            wire_family_default: row.get("wire_family_default"),
            base_url: row.get("base_url"),
            compatibility_profile: row.get("compatibility_profile"),
        })
        .collect())
}

async fn account_counts(
    pool: &sqlx::PgPool,
    tenant_id: &str,
) -> Result<(HashMap<String, i64>, HashMap<String, i64>), sqlx::Error> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT provider_id,
                count(*)::bigint AS total,
                count(*) FILTER (WHERE status = 'active')::bigint AS active
         FROM provider_accounts
         WHERE tenant_id IS NULL OR tenant_id = $1::uuid
         GROUP BY provider_id",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    let mut total = HashMap::new();
    let mut active = HashMap::new();
    for row in rows {
        total.insert(row.get::<String, _>("provider_id"), row.get("total"));
        active.insert(row.get::<String, _>("provider_id"), row.get("active"));
    }
    Ok((total, active))
}

fn provider_response(row: &ProviderRow, configured: bool) -> Value {
    let is_builtin = is_bundled_provider(&row.id);
    let metadata = provider_metadata(&row.id);
    let default_family = row
        .wire_family_default
        .clone()
        .unwrap_or_else(|| "chat".into());
    let mut response = Map::new();
    response.insert("providerId".into(), json!(row.id));
    response.insert(
        "serviceKinds".into(),
        json!(
            provider_service_kinds(&row.id)
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>()
        ),
    );
    response.insert("displayName".into(), json!(provider_display_name(&row.id)));
    response.insert("enabled".into(), json!(row.enabled));
    response.insert("isBuiltIn".into(), json!(is_builtin));
    response.insert("configured".into(), json!(configured));
    response.insert(
        "requiresAccount".into(),
        json!(
            metadata
                .map(|metadata| metadata.requires_account)
                .unwrap_or(row.requires_account)
        ),
    );
    response.insert(
        "hasAdapterUserAgent".into(),
        json!(provider_has_adapter_user_agent(&row.id)),
    );
    response.insert(
        "supportsWebSearch".into(),
        json!(provider_supports_web_search(&row.id)),
    );
    if let Some(metadata) = metadata {
        if let Some(url) = metadata.credential_url {
            response.insert("credentialUrl".into(), json!(url));
        }
        if let Some(hint) = metadata.credential_hint {
            response.insert("credentialHint".into(), json!(hint));
        }
    }
    let supports_discovery = if is_builtin {
        capability_entry(&row.id)
            .and_then(|entry| entry.get("supportsModelDiscovery"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    } else {
        true
    };
    response.insert("supportsModelDiscovery".into(), json!(supports_discovery));
    if let Some(flows) = oauth_flows(&row.id) {
        response.insert("oauthFlows".into(), flows);
    }
    response.insert("wireFamilyDefault".into(), json!(default_family));
    let supported = if is_builtin {
        bundled_supported_families(&row.id, &default_family)
    } else {
        let mut families: Vec<String> = row
            .compatibility_profile
            .as_ref()
            .and_then(|profile| profile.get("endpoint_paths_by_wire_family"))
            .and_then(Value::as_object)
            .map(|paths| paths.keys().cloned().collect())
            .unwrap_or_default();
        if !families.iter().any(|family| family == &default_family) {
            families.push(default_family.clone());
        }
        families
    };
    response.insert("supportedWireFamilies".into(), json!(supported));
    let _ = (
        &row.base_url,
        &row.compatibility_profile,
        row.tenant_id.is_some(),
    );
    Value::Object(response)
}

/// `GET /console/api/providers`.
pub async fn list_providers(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant_id) = access.tenant_id.as_deref() else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let rows = match load_provider_rows(&state.pool, tenant_id).await {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("provider list failed: {error}"),
            );
        }
    };
    let (configured, _) = match account_counts(&state.pool, tenant_id).await {
        Ok(counts) => counts,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("account list failed: {error}"),
            );
        }
    };
    let data: Vec<Value> = rows
        .iter()
        .map(|row| provider_response(row, configured.get(&row.id).copied().unwrap_or(0) > 0))
        .collect();
    json_response(StatusCode::OK, Value::Array(data))
}

struct ModelRow {
    provider_id: String,
    model_id: String,
    wire_family: String,
    service_kind: String,
    endpoint_path: String,
    context_limit: Option<i64>,
    output_limit: Option<i64>,
    modalities: Option<Value>,
    reasoning: bool,
    tool_call: bool,
    cost: Option<Value>,
    source: Option<String>,
    source_updated_at: Option<DateTime<Utc>>,
    enabled: bool,
    requires_account: bool,
}

fn model_modalities(modalities: &Value) -> (Vec<String>, Vec<String>) {
    let input = modalities
        .get("input")
        .map(|value| string_list(Some(value)))
        .unwrap_or_default();
    let output = modalities
        .get("output")
        .map(|value| string_list(Some(value)))
        .unwrap_or_default();
    (input, output)
}

fn model_entry(row: &ModelRow, disabled: bool) -> Value {
    let (input, output) = row
        .modalities
        .as_ref()
        .map(model_modalities)
        .unwrap_or_default();
    json!({
        "modelId": row.model_id.clone(),
        "route": row.endpoint_path.clone(),
        "provider": row.provider_id.clone(),
        "wireFamily": row.wire_family.clone(),
        "serviceKind": row.service_kind.clone(),
        "enabled": if disabled { false } else { row.enabled },
        "contextLimit": row.context_limit,
        "outputLimit": row.output_limit,
        "reasoning": row.reasoning,
        "toolCall": row.tool_call,
        "vision": input.iter().any(|kind| kind == "image"),
        "document": input.iter().any(|kind| kind == "document"),
        "audio": input.iter().any(|kind| kind == "audio"),
        "mediaGeneration": output.iter().any(|kind| kind == "image"),
        "cost": row.cost,
        "source": row.source.clone(),
        "sourceUpdatedAt": row.source_updated_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
    })
}

fn synthetic_entry(id: &str, source: &str) -> Value {
    json!({
        "modelId": id,
        "route": "",
        "provider": "",
        "wireFamily": "chat",
        "serviceKind": "llm",
        "enabled": true,
        "contextLimit": null,
        "outputLimit": null,
        "reasoning": false,
        "toolCall": false,
        "vision": false,
        "document": false,
        "audio": false,
        "mediaGeneration": false,
        "cost": null,
        "source": source,
        "sourceUpdatedAt": null,
    })
}

/// `GET /console/api/providers/models/flat`.
pub async fn list_flat_models(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "models:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant_id) = access.tenant_id.as_deref() else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };

    let disabled_rows: Vec<PgRow> = match sqlx::query(
        "SELECT provider_id, model_id, endpoint_path FROM tenant_disabled_models
         WHERE tenant_id = $1::uuid",
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("disabled model list failed: {error}"),
            );
        }
    };
    let disabled: BTreeSet<String> = disabled_rows
        .iter()
        .map(|row| {
            format!(
                "{}::{}::{}",
                row.get::<String, _>("provider_id"),
                row.get::<String, _>("model_id"),
                row.get::<String, _>("endpoint_path")
            )
        })
        .collect();

    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT m.provider_id, m.model_id, m.wire_family::text AS wire_family,
                m.service_kind, m.endpoint_path,
                m.context_limit::bigint AS context_limit,
                m.output_limit::bigint AS output_limit,
                m.modalities, m.reasoning, m.tool_call, m.cost, m.source,
                m.source_updated_at, m.enabled, p.requires_account
         FROM models m
         JOIN providers p ON p.id = m.provider_id
         WHERE p.tenant_id IS NULL OR p.tenant_id = $1::uuid",
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("model list failed: {error}"),
            );
        }
    };
    let (_, active_accounts) = match account_counts(&state.pool, tenant_id).await {
        Ok(counts) => counts,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("account list failed: {error}"),
            );
        }
    };

    let mut by_qualified: BTreeMap<String, (i64, ModelRow)> = BTreeMap::new();
    for row in rows {
        let model = ModelRow {
            provider_id: row.get("provider_id"),
            model_id: row.get("model_id"),
            wire_family: row.get("wire_family"),
            service_kind: row.get("service_kind"),
            endpoint_path: row.get("endpoint_path"),
            context_limit: row.get("context_limit"),
            output_limit: row.get("output_limit"),
            modalities: row.get("modalities"),
            reasoning: row.get("reasoning"),
            tool_call: row.get("tool_call"),
            cost: row.get("cost"),
            source: row.get("source"),
            source_updated_at: row.get("source_updated_at"),
            enabled: row.get("enabled"),
            requires_account: row.get("requires_account"),
        };
        if model.requires_account
            && active_accounts
                .get(&model.provider_id)
                .copied()
                .unwrap_or(0)
                == 0
        {
            continue;
        }
        let key = format!("{}::{}", model.provider_id, model.model_id);
        let rank = (if model.source.as_deref() == Some("builtin") {
            2
        } else {
            0
        }) + model.context_limit.unwrap_or(0);
        match by_qualified.get(&key) {
            Some((existing_rank, _)) if *existing_rank >= rank => {}
            _ => {
                by_qualified.insert(key, (rank, model));
            }
        }
    }

    let mut seen: BTreeMap<String, Value> = BTreeMap::new();
    for (_, model) in by_qualified.values() {
        let qualified = format!("{}/{}", model.provider_id, model.model_id);
        let disabled_key = format!(
            "{}::{}::{}",
            model.provider_id, model.model_id, model.endpoint_path
        );
        let entry = model_entry(model, disabled.contains(&disabled_key));
        if entry.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        seen.insert(
            qualified.clone(),
            json!({
                "providerId": model.provider_id.clone(),
                "providerLabel": model.provider_id.clone(),
                "modelId": model.model_id.clone(),
                "qualified": qualified,
                "entry": entry,
                "kind": "model",
            }),
        );
    }

    if let Ok(alias_rows) =
        sqlx::query("SELECT alias, target_model FROM model_aliases WHERE tenant_id = $1::uuid")
            .bind(tenant_id)
            .fetch_all(&state.pool)
            .await
    {
        for row in alias_rows {
            let alias: String = row.get("alias");
            let target: String = row.get("target_model");
            let entry = seen
                .get(&target)
                .and_then(|value| value.get("entry"))
                .cloned()
                .unwrap_or_else(|| synthetic_entry(&alias, "alias"));
            if seen.contains_key(&alias) {
                continue;
            }
            seen.insert(
                alias.clone(),
                json!({
                    "providerId": "",
                    "providerLabel": format!("alias → {target}"),
                    "modelId": alias,
                    "qualified": alias,
                    "entry": entry,
                    "kind": "alias",
                }),
            );
        }
    }
    if let Ok(combo_rows) =
        sqlx::query("SELECT name, members FROM model_combos WHERE tenant_id = $1::uuid")
            .bind(tenant_id)
            .fetch_all(&state.pool)
            .await
    {
        for row in combo_rows {
            let name: String = row.get("name");
            let members = row
                .get::<Option<Value>, _>("members")
                .as_ref()
                .map(|value| string_list(Some(value)))
                .unwrap_or_default();
            if seen.contains_key(&name) {
                continue;
            }
            seen.insert(
                name.clone(),
                json!({
                    "providerId": "",
                    "providerLabel": format!("combo · {} members", members.len()),
                    "modelId": name,
                    "qualified": name,
                    "entry": synthetic_entry(&name, "combo"),
                    "kind": "combo",
                }),
            );
        }
    }

    json_response(StatusCode::OK, Value::Array(seen.into_values().collect()))
}

// ─── Provider detail, models, accounts ──────────────────────────────────────

async fn load_provider_row(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    provider_id: &str,
) -> Result<Option<ProviderRow>, sqlx::Error> {
    let row: Option<PgRow> = sqlx::query(
        "SELECT id, tenant_id::text AS tenant_id, enabled, requires_account,
                wire_family_default::text AS wire_family_default, base_url, compatibility_profile
         FROM providers
         WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)",
    )
    .bind(provider_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| ProviderRow {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        enabled: row.get("enabled"),
        requires_account: row.get("requires_account"),
        wire_family_default: row.get("wire_family_default"),
        base_url: row.get("base_url"),
        compatibility_profile: row.get("compatibility_profile"),
    }))
}

/// `GET /console/api/providers/:providerId`.
pub async fn get_provider_detail(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let row = match load_provider_row(&state.pool, &tenant, &provider_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "provider_not_found",
                &format!("Provider {provider_id} not found"),
            );
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("provider detail failed: {error}"),
            );
        }
    };
    let mut response = provider_response(&row, false);
    if let Some(object) = response.as_object_mut() {
        if let Some(profile) = &row.compatibility_profile {
            object.insert("compatibilityProfile".into(), profile.clone());
        }
        if let Some(base_url) = &row.base_url {
            object.insert("baseUrl".into(), json!(base_url));
        }
    }
    json_response(StatusCode::OK, response)
}

/// `GET /console/api/providers/:providerId/models`.
pub async fn list_provider_models(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "models:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let disabled_rows: Vec<PgRow> = sqlx::query(
        "SELECT model_id, endpoint_path FROM tenant_disabled_models
         WHERE tenant_id = $1::uuid AND provider_id = $2",
    )
    .bind(&tenant)
    .bind(&provider_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let disabled: BTreeSet<String> = disabled_rows
        .iter()
        .map(|row| {
            format!(
                "{}::{}",
                row.get::<String, _>("model_id"),
                row.get::<String, _>("endpoint_path")
            )
        })
        .collect();
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT m.provider_id, m.model_id, m.wire_family::text AS wire_family,
                m.service_kind, m.endpoint_path, m.context_limit::bigint AS context_limit,
                m.output_limit::bigint AS output_limit, m.modalities, m.reasoning,
                m.tool_call, m.cost, m.source, m.source_updated_at, m.enabled,
                p.requires_account
         FROM models m
         JOIN providers p ON p.id = m.provider_id
         WHERE m.provider_id = $1 AND (p.tenant_id IS NULL OR p.tenant_id = $2::uuid)
         ORDER BY m.model_id, m.endpoint_path",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("model list failed: {error}"),
            );
        }
    };
    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            let model = ModelRow {
                provider_id: row.get("provider_id"),
                model_id: row.get("model_id"),
                wire_family: row.get("wire_family"),
                service_kind: row.get("service_kind"),
                endpoint_path: row.get("endpoint_path"),
                context_limit: row.get("context_limit"),
                output_limit: row.get("output_limit"),
                modalities: row.get("modalities"),
                reasoning: row.get("reasoning"),
                tool_call: row.get("tool_call"),
                cost: row.get("cost"),
                source: row.get("source"),
                source_updated_at: row.get("source_updated_at"),
                enabled: row.get("enabled"),
                requires_account: row.get("requires_account"),
            };
            let is_disabled =
                disabled.contains(&format!("{}::{}", model.model_id, model.endpoint_path));
            model_entry(&model, is_disabled)
        })
        .collect();
    json_response(StatusCode::OK, Value::Array(data))
}

fn account_usage(requests: i64, errors: i64, input: i64, output: i64) -> Value {
    json!({
        "requests": requests,
        "errors": errors,
        "inputTokens": input,
        "outputTokens": output,
        "totalTokens": input + output,
    })
}

fn live_model_cooldowns(value: &Value) -> Option<Value> {
    let map = value.as_object()?;
    let now = chrono::Utc::now();
    let mut live = Map::new();
    for (model, timestamp) in map {
        let Some(timestamp) = timestamp.as_str() else {
            continue;
        };
        let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(timestamp) else {
            continue;
        };
        if parsed > now {
            live.insert(model.clone(), json!(timestamp));
        }
    }
    (!live.is_empty()).then(|| Value::Object(live))
}

/// `GET /console/api/providers/:providerId/accounts`.
pub async fn list_provider_accounts(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT id::text AS id, provider_id, tenant_id::text AS tenant_id, label,
                credential_kind::text AS credential_kind, auth_state, status::text AS status,
                consecutive_failures::bigint AS consecutive_failures,
                last_success_at, last_error, last_error_category, last_error_at,
                cooldown_until, model_cooldowns, last_recovered_at, created_at,
                sort_index::bigint AS sort_index, static_token,
                last_remaining_credit::float8 AS last_remaining_credit,
                last_remaining_percent::float8 AS last_remaining_percent
         FROM provider_accounts
         WHERE provider_id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)
         ORDER BY sort_index, created_at, id",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("account list failed: {error}"),
            );
        }
    };
    if rows.is_empty() {
        return json_response(StatusCode::OK, Value::Array(Vec::new()));
    }
    let ids: Vec<String> = rows.iter().map(|row| row.get::<String, _>("id")).collect();
    let today_rows: Vec<PgRow> = sqlx::query(
        "SELECT account_id::text AS account_id, count(*)::bigint AS requests,
                count(*) FILTER (WHERE status = 'failed' OR http_status >= 400)::bigint AS errors,
                coalesce(sum(input_tokens), 0)::bigint AS input_tokens,
                coalesce(sum(output_tokens), 0)::bigint AS output_tokens
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND account_id = ANY($2::uuid[])
           AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC')
         GROUP BY account_id",
    )
    .bind(&tenant)
    .bind(&ids)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let today: HashMap<String, (i64, i64, i64, i64)> = today_rows
        .into_iter()
        .filter_map(|row| {
            let account_id: Option<String> = row.get("account_id");
            account_id.map(|account_id| {
                (
                    account_id,
                    (
                        row.get("requests"),
                        row.get("errors"),
                        row.get("input_tokens"),
                        row.get("output_tokens"),
                    ),
                )
            })
        })
        .collect();
    let total_rows: Vec<PgRow> = sqlx::query(
        "SELECT entity_id::text AS entity_id, requests, errors, input_tokens, output_tokens
         FROM telemetry_usage_totals
         WHERE tenant_id = $1::uuid AND identity_type = 'account'
           AND entity_id = ANY($2::uuid[])",
    )
    .bind(&tenant)
    .bind(&ids)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let totals: HashMap<String, (i64, i64, i64, i64)> = total_rows
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("entity_id"),
                (
                    row.get("requests"),
                    row.get("errors"),
                    row.get("input_tokens"),
                    row.get("output_tokens"),
                ),
            )
        })
        .collect();

    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            let id: String = row.get("id");
            let auth_state = row.get::<Option<Value>, _>("auth_state");
            let credential_mode = auth_state
                .as_ref()
                .and_then(|value| value.get("credentialMode"))
                .and_then(Value::as_str)
                .filter(|mode| matches!(*mode, "auto" | "jwt" | "api_key"));
            let token_expires_at = auth_state
                .as_ref()
                .and_then(|value| value.get("tokenExpiresAt"))
                .and_then(Value::as_str);
            let (today_req, today_err, today_in, today_out) =
                today.get(&id).copied().unwrap_or((0, 0, 0, 0));
            let (total_req, total_err, total_in, total_out) =
                totals.get(&id).copied().unwrap_or((0, 0, 0, 0));
            let mut value = Map::new();
            value.insert("id".into(), json!(id));
            value.insert(
                "providerId".into(),
                json!(row.get::<String, _>("provider_id")),
            );
            value.insert(
                "tenantId".into(),
                json!(row.get::<Option<String>, _>("tenant_id")),
            );
            value.insert("label".into(), json!(row.get::<String, _>("label")));
            value.insert(
                "credentialKind".into(),
                json!(row.get::<String, _>("credential_kind")),
            );
            if let Some(mode) = credential_mode {
                value.insert("credentialMode".into(), json!(mode));
            }
            if let Some(expires) = token_expires_at {
                value.insert("tokenExpiresAt".into(), json!(expires));
            }
            value.insert("status".into(), json!(row.get::<String, _>("status")));
            value.insert(
                "usageToday".into(),
                account_usage(today_req, today_err, today_in, today_out),
            );
            value.insert(
                "usageAllTime".into(),
                account_usage(total_req, total_err, total_in, total_out),
            );
            value.insert(
                "consecutiveFailures".into(),
                json!(row.get::<i64, _>("consecutive_failures")),
            );
            for (field, column) in [
                ("lastSuccessAt", "last_success_at"),
                ("lastErrorAt", "last_error_at"),
                ("cooldownUntil", "cooldown_until"),
                ("lastRecoveredAt", "last_recovered_at"),
            ] {
                if let Some(timestamp) = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(column)
                {
                    value.insert(
                        field.into(),
                        json!(timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)),
                    );
                }
            }
            if let Some(message) = row.get::<Option<String>, _>("last_error") {
                value.insert("lastError".into(), json!(message));
            }
            if let Some(category) = row.get::<Option<String>, _>("last_error_category") {
                value.insert("lastErrorCategory".into(), json!(category));
            }
            let cooldowns = row
                .get::<Option<Value>, _>("model_cooldowns")
                .unwrap_or(Value::Object(Map::new()));
            if let Some(live) = live_model_cooldowns(&cooldowns) {
                value.insert("modelCooldowns".into(), live);
            }
            value.insert(
                "createdAt".into(),
                json!(
                    row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .to_rfc3339_opts(SecondsFormat::Millis, true)
                ),
            );
            value.insert("sortIndex".into(), json!(row.get::<i64, _>("sort_index")));
            if row.get::<bool, _>("static_token") {
                value.insert("staticToken".into(), json!(true));
            }
            value.insert(
                "lastRemainingCredit".into(),
                json!(row.get::<Option<f64>, _>("last_remaining_credit")),
            );
            value.insert(
                "lastRemainingPercent".into(),
                json!(row.get::<Option<f64>, _>("last_remaining_percent")),
            );
            Value::Object(value)
        })
        .collect();
    json_response(StatusCode::OK, Value::Array(data))
}

// ─── Provider routing settings ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn routing_response(
    provider_id: &str,
    tenant_id: &str,
    strategy: &str,
    rotate_count: i64,
    max_inflight: Option<i64>,
    credit_limit_enabled: bool,
    credit_limit: f64,
    enabled: bool,
    bypass_proxy: bool,
    user_agent: &str,
) -> Value {
    json!({
        "providerId": provider_id,
        "tenantId": tenant_id,
        "strategy": strategy,
        "rotateCount": rotate_count,
        "maxInflight": max_inflight,
        "creditLimitEnabled": credit_limit_enabled,
        "creditLimit": credit_limit,
        "enabled": enabled,
        "bypassProxy": bypass_proxy,
        "userAgent": user_agent,
    })
}

struct RoutingRow {
    strategy: String,
    rotate_count: i64,
    max_inflight: Option<i64>,
    credit_limit_enabled: bool,
    credit_limit: f64,
    enabled: bool,
    bypass_proxy: bool,
    user_agent: String,
}

async fn load_routing_row(
    pool: &sqlx::PgPool,
    provider_id: &str,
    tenant_id: Option<&str>,
) -> Result<Option<RoutingRow>, sqlx::Error> {
    let row: Option<PgRow> = match tenant_id {
        Some(tenant) => {
            sqlx::query(
                "SELECT strategy::text AS strategy, rotate_count::bigint AS rotate_count,
                    max_inflight::bigint AS max_inflight, credit_limit_enabled,
                    credit_limit::float8 AS credit_limit, enabled, bypass_proxy, user_agent
             FROM provider_routing_settings
             WHERE provider_id = $1 AND tenant_id = $2::uuid",
            )
            .bind(provider_id)
            .bind(tenant)
            .fetch_optional(pool)
            .await?
        }
        None => {
            sqlx::query(
                "SELECT strategy::text AS strategy, rotate_count::bigint AS rotate_count,
                    max_inflight::bigint AS max_inflight, credit_limit_enabled,
                    credit_limit::float8 AS credit_limit, enabled, bypass_proxy, user_agent
             FROM provider_routing_settings
             WHERE provider_id = $1 AND tenant_id IS NULL",
            )
            .bind(provider_id)
            .fetch_optional(pool)
            .await?
        }
    };
    Ok(row.map(|row| RoutingRow {
        strategy: row.get("strategy"),
        rotate_count: row.get("rotate_count"),
        max_inflight: row.get("max_inflight"),
        credit_limit_enabled: row.get("credit_limit_enabled"),
        credit_limit: row.get("credit_limit"),
        enabled: row.get("enabled"),
        bypass_proxy: row.get("bypass_proxy"),
        user_agent: row.get("user_agent"),
    }))
}

/// `GET /console/api/providers/:providerId/routing`.
pub async fn get_provider_routing(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "dashboard:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let specific = match load_routing_row(&state.pool, &provider_id, Some(&tenant)).await {
        Ok(row) => row,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("routing read failed: {error}"),
            );
        }
    };
    let resolved = match specific {
        Some(row) => Some(row),
        None => match load_routing_row(&state.pool, &provider_id, None).await {
            Ok(row) => row,
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("routing read failed: {error}"),
                );
            }
        },
    };
    let response = match resolved {
        Some(row) => routing_response(
            &provider_id,
            &tenant,
            &row.strategy,
            row.rotate_count,
            row.max_inflight,
            row.credit_limit_enabled,
            row.credit_limit,
            row.enabled,
            row.bypass_proxy,
            &row.user_agent,
        ),
        None => routing_response(
            &provider_id,
            &tenant,
            "fallback",
            1,
            None,
            false,
            50.0,
            false,
            keyla_providers::default_proxy_bypass_provider_ids().contains(provider_id.as_str()),
            keyla_routing::DEFAULT_PROVIDER_USER_AGENT,
        ),
    };
    json_response(StatusCode::OK, response)
}

/// `PATCH /console/api/providers/:providerId/routing`.
pub async fn update_provider_routing(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "dashboard:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let Some(body) = body.as_object() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Body must be an object",
        );
    };
    let strategy = body.get("strategy").and_then(Value::as_str);
    if let Some(strategy) = strategy {
        if !matches!(strategy, "fallback" | "round_robin") {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid strategy",
            );
        }
    }
    let rotate = body.get("rotateCount").and_then(Value::as_i64);
    if let Some(rotate) = rotate {
        if !(1..=1000).contains(&rotate) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_rotate_count",
                "rotateCount must be 1-1000",
            );
        }
    }
    let max_inflight = match body.get("maxInflight") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(value) => match value.as_i64() {
            Some(limit) if (1..=10_000).contains(&limit) => Some(Some(limit)),
            _ => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_max_inflight",
                    "maxInflight must be an integer between 1 and 10000, or null",
                );
            }
        },
    };
    let credit_limit = body.get("creditLimit").and_then(Value::as_i64);
    if let Some(limit) = credit_limit {
        if !(0..=1_000_000_000).contains(&limit) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_credit_limit",
                "creditLimit must be an integer between 0 and 1000000000",
            );
        }
    }
    let user_agent = body.get("userAgent").and_then(Value::as_str);
    if let Some(agent) = user_agent {
        if agent.trim().is_empty()
            || agent.chars().count() > 4096
            || agent.chars().any(|ch| ch.is_control())
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "userAgent must be a non-empty header value up to 4096 characters",
            );
        }
    }
    let _ = (
        max_inflight,
        body.get("creditLimitEnabled").and_then(Value::as_bool),
        body.get("enabled").and_then(Value::as_bool),
        body.get("bypassProxy").and_then(Value::as_bool),
    );

    let defaults = routing_response(
        &provider_id,
        &tenant,
        "fallback",
        1,
        None,
        false,
        50.0,
        false,
        keyla_providers::default_proxy_bypass_provider_ids().contains(provider_id.as_str()),
        keyla_routing::DEFAULT_PROVIDER_USER_AGENT,
    );
    let existing = load_routing_row(&state.pool, &provider_id, Some(&tenant))
        .await
        .ok()
        .flatten()
        .or(load_routing_row(&state.pool, &provider_id, None)
            .await
            .ok()
            .flatten());
    let base = match &existing {
        Some(row) => routing_response(
            &provider_id,
            &tenant,
            &row.strategy,
            row.rotate_count,
            row.max_inflight,
            row.credit_limit_enabled,
            row.credit_limit,
            row.enabled,
            row.bypass_proxy,
            &row.user_agent,
        ),
        None => defaults,
    };
    let mut values = base.as_object().cloned().unwrap_or_default();
    for key in [
        "strategy",
        "rotateCount",
        "maxInflight",
        "creditLimitEnabled",
        "creditLimit",
        "enabled",
        "bypassProxy",
        "userAgent",
    ] {
        if let Some(value) = body.get(key) {
            values.insert(key.into(), value.clone());
        }
    }
    let strategy = values
        .get("strategy")
        .and_then(Value::as_str)
        .unwrap_or("fallback")
        .to_owned();
    let rotate_count = values
        .get("rotateCount")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let max_inflight = match values.get("maxInflight") {
        Some(Value::Number(number)) => number.as_i64(),
        _ => None,
    };
    let credit_limit_enabled = values
        .get("creditLimitEnabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let credit_limit = values
        .get("creditLimit")
        .and_then(Value::as_f64)
        .unwrap_or(50.0);
    let enabled = values
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let bypass_proxy = values
        .get("bypassProxy")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            keyla_providers::default_proxy_bypass_provider_ids().contains(provider_id.as_str())
        });
    let user_agent = values
        .get("userAgent")
        .and_then(Value::as_str)
        .unwrap_or(keyla_routing::DEFAULT_PROVIDER_USER_AGENT)
        .to_owned();

    let set_clauses = [
        "strategy = $4::provider_routing_strategy",
        "rotate_count = $5",
        "max_inflight = $6",
        "credit_limit_enabled = $7",
        "credit_limit = $8",
        "enabled = $9",
        "bypass_proxy = $10",
        "user_agent = $11",
    ];
    let on_conflict = format!(
        "ON CONFLICT (tenant_id, provider_id) DO UPDATE SET {}",
        set_clauses.join(", ")
    );
    let insert = format!(
        "INSERT INTO provider_routing_settings
           (provider_id, tenant_id, strategy, rotate_count, max_inflight,
            credit_limit_enabled, credit_limit, enabled, bypass_proxy, user_agent)
         VALUES ($1, $2::uuid, $3::provider_routing_strategy, $5, $6, $7, $8, $9, $10, $11)
         {on_conflict}"
    );
    if let Err(error) = sqlx::query(&insert)
        .bind(&provider_id)
        .bind(&tenant)
        .bind(&strategy)
        .bind(&strategy)
        .bind(rotate_count)
        .bind(max_inflight)
        .bind(credit_limit_enabled)
        .bind(credit_limit)
        .bind(enabled)
        .bind(bypass_proxy)
        .bind(&user_agent)
        .execute(&state.pool)
        .await
    {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("routing update failed: {error}"),
        );
    }
    state.snapshots.invalidate();
    let refreshed = load_routing_row(&state.pool, &provider_id, Some(&tenant))
        .await
        .ok()
        .flatten();
    let response = match refreshed {
        Some(row) => routing_response(
            &provider_id,
            &tenant,
            &row.strategy,
            row.rotate_count,
            row.max_inflight,
            row.credit_limit_enabled,
            row.credit_limit,
            row.enabled,
            row.bypass_proxy,
            &row.user_agent,
        ),
        None => json_response_placeholder(&provider_id, &tenant),
    };
    json_response(StatusCode::OK, response)
}

fn json_response_placeholder(provider_id: &str, tenant_id: &str) -> Value {
    routing_response(
        provider_id,
        tenant_id,
        "fallback",
        1,
        None,
        false,
        50.0,
        false,
        false,
        keyla_routing::DEFAULT_PROVIDER_USER_AGENT,
    )
}

/// `GET /console/api/providers/:providerId/account-inflight`.
pub async fn account_inflight(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "dashboard:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let readings = state.engine.account_inflight_snapshot().await;
    let prefix = format!("{provider_id}:");
    let mut data = Vec::new();
    for (key, inflight) in readings {
        let Some(rest) = key.strip_prefix(&prefix) else {
            continue;
        };
        let Some((_, account)) = rest.rsplit_once(':') else {
            continue;
        };
        data.push(json!({"accountId": account, "inflight": inflight}));
    }
    json_response(StatusCode::OK, Value::Array(data))
}

// --- Provider account mutations --------------------------------------------

fn account_response(row: &PgRow) -> Value {
    let auth_state = row.try_get::<Option<Value>, _>("auth_state").ok().flatten();
    let credential_mode = auth_state
        .as_ref()
        .and_then(|value| value.get("credentialMode"))
        .and_then(Value::as_str);
    let token_expires_at = auth_state
        .as_ref()
        .and_then(|value| value.get("tokenExpiresAt"))
        .and_then(Value::as_str);
    let mut value = json!({
        "id": row.get::<String, _>("id"),
        "providerId": row.get::<String, _>("provider_id"),
        "tenantId": row.get::<Option<String>, _>("tenant_id"),
        "label": row.get::<String, _>("label"),
        "credentialKind": row.get::<String, _>("credential_kind"),
        "status": row.get::<String, _>("status"),
        "usageToday": {"requests": 0, "errors": 0, "inputTokens": 0, "outputTokens": 0, "totalTokens": 0},
        "usageAllTime": {"requests": 0, "errors": 0, "inputTokens": 0, "outputTokens": 0, "totalTokens": 0},
        "consecutiveFailures": row.try_get::<i64, _>("consecutive_failures").unwrap_or(0),
        "createdAt": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
        "lastRemainingCredit": row.try_get::<Option<f64>, _>("last_remaining_credit").ok().flatten(),
        "lastRemainingPercent": row.try_get::<Option<f64>, _>("last_remaining_percent").ok().flatten(),
        "sortIndex": row.try_get::<i64, _>("sort_index").unwrap_or(0),
    });
    let object = value.as_object_mut().expect("object");
    if let Some(mode) = credential_mode {
        object.insert("credentialMode".into(), json!(mode));
    }
    if let Some(expires) = token_expires_at {
        object.insert("tokenExpiresAt".into(), json!(expires));
    }
    for (field, column) in [
        ("lastSuccessAt", "last_success_at"),
        ("lastErrorAt", "last_error_at"),
        ("cooldownUntil", "cooldown_until"),
        ("lastRecoveredAt", "last_recovered_at"),
    ] {
        if let Ok(Some(timestamp)) = row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(column)
        {
            object.insert(
                field.into(),
                json!(timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)),
            );
        }
    }
    for (field, column) in [
        ("lastError", "last_error"),
        ("lastErrorCategory", "last_error_category"),
    ] {
        if let Ok(Some(text)) = row.try_get::<Option<String>, _>(column) {
            object.insert(field.into(), json!(text));
        }
    }
    if let Ok(Some(cooldowns)) = row.try_get::<Option<Value>, _>("model_cooldowns") {
        object.insert("modelCooldowns".into(), cooldowns);
    }
    if row.try_get::<bool, _>("static_token").unwrap_or(false) {
        object.insert("staticToken".into(), json!(true));
    }
    value
}

fn account_columns(id: &str) -> String {
    format!(
        "SELECT id::text AS id, provider_id, tenant_id::text AS tenant_id, label,
                credential_kind::text AS credential_kind, auth_state, status::text AS status,
                consecutive_failures::bigint AS consecutive_failures,
                last_success_at, last_error, last_error_category, last_error_at,
                cooldown_until, model_cooldowns, last_recovered_at, created_at,
                sort_index::bigint AS sort_index, static_token,
                last_remaining_credit::float8 AS last_remaining_credit,
                last_remaining_percent::float8 AS last_remaining_percent
         FROM provider_accounts WHERE id = '{id}'::uuid"
    )
}

async fn ensure_provider(
    pool: &sqlx::PgPool,
    tenant: &str,
    provider_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM providers WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid))",
    )
    .bind(provider_id)
    .bind(tenant)
    .fetch_one(pool)
    .await
}

/// `POST /console/api/providers/{providerId}/accounts`.
pub async fn create_provider_account(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    match ensure_provider(&state.pool, &tenant, &provider_id).await {
        Ok(true) => {}
        Ok(false) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "provider_not_found",
                &format!("Provider {provider_id} not found"),
            );
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("provider lookup failed: {error}"),
            );
        }
    }
    let credential_kind = body
        .get("credentialKind")
        .and_then(Value::as_str)
        .unwrap_or("api_key");
    if !["api_key", "oauth", "none"].contains(&credential_kind) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "credentialKind must be api_key, oauth, or none",
        );
    }
    let secret = body.get("secret").and_then(Value::as_str).unwrap_or("");
    if credential_kind != "none" && secret.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "secret is required for this credential kind",
        );
    }
    let auth_state = body
        .get("authState")
        .filter(|value| value.is_object())
        .cloned();
    let ciphertext = if credential_kind == "none" {
        None
    } else {
        match keyla_security::encrypt_credential(secret.as_bytes()) {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("encrypt failed: {error}"),
                );
            }
        }
    };
    let fingerprint = if credential_kind == "none" {
        None
    } else {
        keyla_security::hash_secret(secret)
            .ok()
            .map(|hash| format!("{}…", &hash[..8]))
    };
    let label = body
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| keyla_providers::provider_display_name(&provider_id).to_string());
    let inserted = sqlx::query(
        "INSERT INTO provider_accounts (
            provider_id, tenant_id, label, credential_ciphertext, credential_fingerprint,
            credential_kind, auth_state, status, sort_index
         ) VALUES ($1, $2::uuid, $3, $4, $5, $6::credential_kind, $7::jsonb, 'active',
           (SELECT coalesce(max(sort_index) + 1, 0) FROM provider_accounts
            WHERE provider_id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)))
         RETURNING id::text AS id",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .bind(&label)
    .bind(&ciphertext)
    .bind(&fingerprint)
    .bind(credential_kind)
    .bind(&auth_state)
    .fetch_one(&state.pool)
    .await;
    let id: String = match inserted {
        Ok(row) => row.get("id"),
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("account insert failed: {error}"),
            );
        }
    };
    let row = sqlx::query(&account_columns(&id))
        .bind::<&str>(&provider_id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    match row {
        Some(row) => json_response(StatusCode::CREATED, account_response(&row)),
        None => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "account readback failed",
        ),
    }
}

/// `PATCH /console/api/providers/{providerId}/accounts/{accountId}`.
pub async fn update_provider_account(
    State(state): State<ConsoleState>,
    axum::extract::Path((provider_id, account_id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let current = sqlx::query(&account_columns(&account_id))
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    let Some(current) = current else {
        return error_response(
            StatusCode::NOT_FOUND,
            "account_not_found",
            &format!("Account {account_id} not found"),
        );
    };
    if current.get::<String, _>("provider_id") != provider_id
        || current
            .try_get::<Option<String>, _>("tenant_id")
            .ok()
            .flatten()
            .as_deref()
            != Some(tenant.as_str())
    {
        return error_response(
            StatusCode::NOT_FOUND,
            "account_not_found",
            &format!("Account {account_id} not found"),
        );
    }
    let label = body
        .get("label")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| current.get("label"));
    let status = body
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("active");
    if !["active", "disabled"].contains(&status) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "status must be active or disabled",
        );
    }
    let static_token = body
        .get("staticToken")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| current.try_get::<bool, _>("static_token").unwrap_or(false));
    let (ciphertext, fingerprint) = match body.get("secret").and_then(Value::as_str) {
        Some(secret) if !secret.trim().is_empty() => {
            let encrypted = match keyla_security::encrypt_credential(secret.as_bytes()) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        &format!("encrypt failed: {error}"),
                    );
                }
            };
            let hash = keyla_security::hash_secret(secret)
                .ok()
                .map(|hash| format!("{}…", &hash[..8]));
            (Some(encrypted), hash)
        }
        _ => (
            current
                .try_get::<Option<Vec<u8>>, _>("credential_ciphertext")
                .ok()
                .flatten(),
            current
                .try_get::<Option<String>, _>("credential_fingerprint")
                .ok()
                .flatten(),
        ),
    };
    let updated = sqlx::query(
        "UPDATE provider_accounts SET label = $3, status = $4::health_status,
            static_token = $5, credential_ciphertext = $6, credential_fingerprint = $7
         WHERE id = $1::uuid AND provider_id = $2 AND tenant_id = $8::uuid
         RETURNING id::text AS id",
    )
    .bind(&account_id)
    .bind(&provider_id)
    .bind(&label)
    .bind(status)
    .bind(static_token)
    .bind(&ciphertext)
    .bind(&fingerprint)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => {
            let row = sqlx::query(&account_columns(&account_id))
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten();
            match row {
                Some(row) => json_response(StatusCode::OK, account_response(&row)),
                None => error_response(
                    StatusCode::NOT_FOUND,
                    "account_not_found",
                    "Account not found",
                ),
            }
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "account_not_found",
            &format!("Account {account_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("account update failed: {error}"),
        ),
    }
}

/// `POST /console/api/providers/{providerId}/accounts/{accountId}/recover`.
pub async fn recover_provider_account(
    State(state): State<ConsoleState>,
    axum::extract::Path((provider_id, account_id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let recovered = sqlx::query(
        "UPDATE provider_accounts
         SET status = 'active', consecutive_failures = 0, cooldown_until = NULL,
             model_cooldowns = '{}'::jsonb, last_recovered_at = now()
         WHERE id = $1::uuid AND provider_id = $2 AND tenant_id = $3::uuid
         RETURNING id",
    )
    .bind(&account_id)
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match recovered {
        Ok(Some(_)) => {
            let _ = sqlx::query(
                "INSERT INTO health_events (entity_kind, account_id, to_status, reason)
                 VALUES ('account', $1::uuid, 'active', 'manual_operator_recovery')",
            )
            .bind(&account_id)
            .execute(&state.pool)
            .await;
            json_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "account_not_found",
            &format!("Account {account_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("account recovery failed: {error}"),
        ),
    }
}

/// `GET /console/api/providers/{providerId}/accounts/{accountId}/health-events`.
pub async fn account_health_events(
    State(state): State<ConsoleState>,
    axum::extract::Path((provider_id, account_id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:read") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM provider_accounts
         WHERE id = $1::uuid AND provider_id = $2 AND (tenant_id IS NULL OR tenant_id = $3::uuid))",
    )
    .bind(&account_id)
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if !owned {
        return error_response(
            StatusCode::NOT_FOUND,
            "account_not_found",
            &format!("Account {account_id} not found"),
        );
    }
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, account_id::text AS account_id,
                from_status::text AS from_status, to_status::text AS to_status,
                reason, error_category, model_id, created_at
         FROM health_events WHERE account_id = $1::uuid
         ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&account_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "accountId": row.get::<String, _>("account_id"),
                "fromStatus": row.try_get::<Option<String>, _>("from_status").ok().flatten(),
                "toStatus": row.get::<String, _>("to_status"),
                "reason": row.try_get::<Option<String>, _>("reason").ok().flatten(),
                "errorCategory": row.try_get::<Option<String>, _>("error_category").ok().flatten(),
                "modelId": row.try_get::<Option<String>, _>("model_id").ok().flatten(),
                "createdAt": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339_opts(SecondsFormat::Millis, true),
            })
        })
        .collect();
    json_response(StatusCode::OK, Value::Array(data))
}

// --- Custom providers and model registration --------------------------------

fn provider_capabilities(body: &Value) -> Option<Value> {
    body.get("capabilityProfile")
        .filter(|value| value.is_object())
        .cloned()
}

fn wire_family(value: Option<&str>) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some("chat") => Ok(Some("chat".into())),
        Some("messages") => Ok(Some("messages".into())),
        Some("responses") => Ok(Some("responses".into())),
        Some(_) => Err("wireFamily must be chat, messages, or responses".into()),
    }
}

fn endpoint_for_family(family: &str) -> &'static str {
    match family {
        "messages" => "/v1/messages",
        "responses" => "/v1/responses",
        _ => "/v1/chat/completions",
    }
}

/// `POST /console/api/providers` — register a custom provider.
pub async fn create_provider(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let provider_id = body
        .get("providerId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if provider_id.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "providerId is required",
        );
    }
    let family = match wire_family(body.get("wireFamily").and_then(Value::as_str)) {
        Ok(family) => family.unwrap_or_else(|| "chat".into()),
        Err(message) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
        }
    };
    let base_url = body
        .get("baseUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(base_url) = base_url else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "baseUrl is required",
        );
    };
    if url::Url::parse(base_url).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "baseUrl must be a valid URL",
        );
    }
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let compatibility = body
        .get("compatibilityProfile")
        .filter(|value| value.is_object())
        .cloned();
    let inserted = sqlx::query(
        "INSERT INTO providers (
            id, tenant_id, wire_family_default, capability_profile, base_url,
            compatibility_profile, enabled, requires_account
         ) VALUES ($1, $2::uuid, $3::wire_family, $4::jsonb, $5, $6::jsonb, $7, true)
         ON CONFLICT (id) DO NOTHING
         RETURNING id",
    )
    .bind(provider_id)
    .bind(&tenant)
    .bind(&family)
    .bind(provider_capabilities(&body))
    .bind(base_url)
    .bind(&compatibility)
    .bind(enabled)
    .fetch_optional(&state.pool)
    .await;
    match inserted {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_response(
                StatusCode::CONFLICT,
                "provider_exists",
                &format!("Provider {provider_id} already exists"),
            );
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("provider insert failed: {error}"),
            );
        }
    }
    if let Some(models) = body.get("models").and_then(Value::as_array) {
        for model in models {
            let Some(model_id) = model
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let _ = sqlx::query(
                "INSERT INTO models (provider_id, model_id, wire_family, endpoint_path, enabled)
                 VALUES ($1, $2, $3::wire_family, $4, true)
                 ON CONFLICT (provider_id, model_id, endpoint_path) DO NOTHING",
            )
            .bind(provider_id)
            .bind(model_id)
            .bind(&family)
            .bind(endpoint_for_family(&family))
            .execute(&state.pool)
            .await;
        }
    }
    state.snapshots.invalidate();
    match provider_detail_value(&state.pool, &tenant, provider_id).await {
        Ok(value) => json_response(StatusCode::CREATED, value),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("provider readback failed: {error}"),
        ),
    }
}

async fn provider_detail_value(
    pool: &sqlx::PgPool,
    tenant: &str,
    provider_id: &str,
) -> Result<Value, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, tenant_id::text AS tenant_id, enabled, requires_account,
                wire_family_default::text AS wire_family_default, base_url,
                capability_profile, compatibility_profile
         FROM providers WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)",
    )
    .bind(provider_id)
    .bind(tenant)
    .fetch_optional(pool)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    let configured: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM provider_accounts WHERE provider_id = $1 AND tenant_id = $2::uuid)",
    )
    .bind(provider_id)
    .bind(tenant)
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    let model_count: i64 = sqlx::query_scalar("SELECT count(*) FROM models WHERE provider_id = $1")
        .bind(provider_id)
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let mut value = json!({
        "providerId": provider_id,
        "serviceKinds": ["llm"],
        "displayName": keyla_providers::provider_display_name(provider_id),
        "enabled": row.get::<bool, _>("enabled"),
        "isBuiltIn": keyla_providers::bundled_provider_ids().contains(&provider_id),
        "configured": configured,
        "requiresAccount": row.get::<bool, _>("requires_account"),
        "hasAdapterUserAgent": false,
        "hasHostedWebSearch": false,
        "wireFamilyDefault": row.get::<Option<String>, _>("wire_family_default"),
        "baseUrl": row.get::<Option<String>, _>("base_url"),
        "accountCount": 0,
        "modelCount": model_count,
    });
    if let Some(label) = row
        .try_get::<Option<Value>, _>("capability_profile")
        .ok()
        .flatten()
        .and_then(|value| {
            value
                .get("label")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
    {
        value
            .as_object_mut()
            .expect("object")
            .insert("label".into(), json!(label));
    }
    if let Some(capability) = row
        .try_get::<Option<Value>, _>("capability_profile")
        .ok()
        .flatten()
    {
        value
            .as_object_mut()
            .expect("object")
            .insert("capabilityProfile".into(), capability);
    }
    if let Some(profile) = row
        .try_get::<Option<Value>, _>("compatibility_profile")
        .ok()
        .flatten()
    {
        value
            .as_object_mut()
            .expect("object")
            .insert("compatibilityProfile".into(), profile);
    }
    Ok(value)
}

/// `PATCH /console/api/providers/{providerId}` — edit a tenant custom provider.
pub async fn update_provider(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let current = sqlx::query(
        "SELECT tenant_id::text AS tenant_id, enabled, base_url FROM providers WHERE id = $1",
    )
    .bind(&provider_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(current) = current else {
        return error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Provider {provider_id} not found"),
        );
    };
    let tenant_owned = current
        .try_get::<Option<String>, _>("tenant_id")
        .ok()
        .flatten()
        .as_deref()
        == Some(tenant.as_str());
    if !tenant_owned {
        return error_response(
            StatusCode::FORBIDDEN,
            "provider_not_custom",
            "Only tenant-owned custom providers can be edited",
        );
    }
    let enabled = body
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| current.get("enabled"));
    let base_url = body
        .get("baseUrl")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            current
                .try_get::<Option<String>, _>("base_url")
                .ok()
                .flatten()
        });
    let capability = provider_capabilities(&body).or_else(|| {
        current
            .try_get::<Option<Value>, _>("capability_profile")
            .ok()
            .flatten()
    });
    let compatibility = body
        .get("compatibilityProfile")
        .filter(|value| value.is_object())
        .cloned()
        .or_else(|| {
            current
                .try_get::<Option<Value>, _>("compatibility_profile")
                .ok()
                .flatten()
        });
    let updated = sqlx::query(
        "UPDATE providers SET enabled = $2, base_url = $3,
            capability_profile = $4::jsonb, compatibility_profile = $5::jsonb
         WHERE id = $1 AND tenant_id = $6::uuid RETURNING id",
    )
    .bind(&provider_id)
    .bind(enabled)
    .bind(&base_url)
    .bind(&capability)
    .bind(&compatibility)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            match provider_detail_value(&state.pool, &tenant, &provider_id).await {
                Ok(value) => json_response(StatusCode::OK, value),
                Err(error) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("provider readback failed: {error}"),
                ),
            }
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Provider {provider_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("provider update failed: {error}"),
        ),
    }
}

/// `DELETE /console/api/providers/{providerId}` — removes a custom provider.
pub async fn delete_provider(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    if keyla_providers::bundled_provider_ids().contains(&provider_id.as_str()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "provider_builtin",
            "Built-in providers cannot be deleted",
        );
    }
    let deleted =
        sqlx::query("DELETE FROM providers WHERE id = $1 AND tenant_id = $2::uuid RETURNING id")
            .bind(&provider_id)
            .bind(&tenant)
            .fetch_optional(&state.pool)
            .await;
    match deleted {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            json_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Provider {provider_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("provider delete failed: {error}"),
        ),
    }
}

/// `PATCH /console/api/providers/{providerId}/models` — routing enable flag.
pub async fn set_provider_model_enabled(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "models:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let model_id = body.get("modelId").and_then(Value::as_str).unwrap_or("");
    let route = body.get("route").and_then(Value::as_str).unwrap_or("");
    let Some(enabled) = body.get("enabled").and_then(Value::as_bool) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "enabled is required",
        );
    };
    let updated = sqlx::query(
        "UPDATE models m SET enabled = $4
         FROM providers p
         WHERE p.id = m.provider_id AND m.provider_id = $1 AND m.model_id = $2
           AND m.endpoint_path = $3 AND (p.tenant_id IS NULL OR p.tenant_id = $5::uuid)
         RETURNING m.model_id",
    )
    .bind(&provider_id)
    .bind(model_id)
    .bind(route)
    .bind(enabled)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            json_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            &format!("Model {model_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("model update failed: {error}"),
        ),
    }
}

/// `DELETE /console/api/providers/{providerId}/models` — unregister a model.
pub async fn delete_provider_model(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "models:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let model_id = body.get("modelId").and_then(Value::as_str).unwrap_or("");
    let route = body.get("route").and_then(Value::as_str).unwrap_or("");
    let deleted = sqlx::query(
        "DELETE FROM models m USING providers p
         WHERE p.id = m.provider_id AND p.tenant_id = $4::uuid
           AND m.provider_id = $1 AND m.model_id = $2 AND m.endpoint_path = $3
         RETURNING m.model_id",
    )
    .bind(&provider_id)
    .bind(model_id)
    .bind(route)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await;
    match deleted {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            json_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            &format!("Model {model_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("model delete failed: {error}"),
        ),
    }
}

/// `POST /console/api/providers/connection-test` — probe an unsaved BYOK
/// endpoint's `GET /models` with the credential header its wire family reads.
pub async fn test_byok_connection(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "providers:write").await {
        return response;
    }
    let Some(base_url) = body
        .get("baseUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "baseUrl is required",
        );
    };
    let Some(api_key) = body.get("apiKey").and_then(Value::as_str) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "apiKey is required",
        );
    };
    let wire_family = body
        .get("wireFamily")
        .and_then(Value::as_str)
        .unwrap_or("chat");
    if !["chat", "responses", "messages"].contains(&wire_family) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "wireFamily must be chat, responses, or messages",
        );
    }
    let Ok(parsed) = url::Url::parse(base_url) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_endpoint",
            "baseUrl must be a valid URL",
        );
    };
    if !["http", "https"].contains(&parsed.scheme()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_endpoint",
            "baseUrl must be an http(s) URL",
        );
    }
    let mut endpoint = parsed;
    let path = endpoint.path().trim_end_matches('/').to_owned();
    endpoint.set_path(&format!("{path}/models"));
    let started = std::time::Instant::now();
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("http client: {error}"),
            );
        }
    };
    let mut request = client.get(endpoint.clone());
    if wire_family == "messages" {
        request = request
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01");
    } else {
        request = request.bearer_auth(api_key);
    }
    if body
        .get("cliIdentity")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let user_agent = match wire_family {
            "messages" => "claude-cli/2.1.0",
            "responses" => "codex_cli_rs/0.156.1",
            _ => "opencode/1.0",
        };
        request = request.header("user-agent", user_agent);
    }
    if let Some(extra) = body.get("extraHeaders").and_then(Value::as_object) {
        for (name, value) in extra {
            if let (Ok(name), Some(value)) = (
                axum::http::HeaderName::try_from(name.as_str()),
                value.as_str(),
            ) {
                request = request.header(name, value);
            }
        }
    }
    let response = request.send().await;
    let latency = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u64;
    match response {
        Ok(response) => {
            let status = response.status();
            let payload: Value = response.json().await.unwrap_or(Value::Null);
            let model_count = payload
                .get("data")
                .and_then(Value::as_array)
                .map(|models| models.len())
                .or_else(|| {
                    payload
                        .get("models")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                });
            let mut value = json!({
                "ok": status.is_success(),
                "latencyMs": latency,
                "statusCode": status.as_u16(),
            });
            let object = value.as_object_mut().expect("object");
            if let Some(count) = model_count {
                object.insert("modelCount".into(), json!(count));
            }
            if !status.is_success() {
                object.insert(
                    "error".into(),
                    json!(format!("upstream returned HTTP {}", status.as_u16())),
                );
            }
            json_response(StatusCode::OK, value)
        }
        Err(error) => json_response(
            StatusCode::OK,
            json!({
                "ok": false,
                "latencyMs": latency,
                "error": error.to_string(),
            }),
        ),
    }
}

/// `POST /console/api/providers/{providerId}/models/sync` — discover models
/// from an API-key provider's `GET /models` and register the new rows.
pub async fn sync_provider_models(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "providers:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let provider = sqlx::query(
        "SELECT base_url, wire_family_default::text AS wire_family_default
         FROM providers WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(provider) = provider else {
        return error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Provider {provider_id} not found"),
        );
    };
    let base_url = provider
        .try_get::<Option<String>, _>("base_url")
        .ok()
        .flatten()
        .or_else(|| keyla_providers::provider_base_url(&provider_id).map(str::to_owned));
    let Some(base_url) = base_url else {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "provider_not_discoverable",
            "This provider has no configured base URL",
        );
    };
    let family = provider
        .try_get::<Option<String>, _>("wire_family_default")
        .ok()
        .flatten()
        .unwrap_or_else(|| "chat".into());
    let account = sqlx::query(
        "SELECT credential_ciphertext, credential_kind::text AS credential_kind
         FROM provider_accounts
         WHERE provider_id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)
           AND status <> 'disabled'
         ORDER BY sort_index, created_at LIMIT 1",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let secret = account.and_then(|row| {
        row.try_get::<Option<Vec<u8>>, _>("credential_ciphertext")
            .ok()
            .flatten()
            .and_then(|ciphertext| keyla_security::decrypt_credential_to_string(&ciphertext).ok())
    });
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("http client: {error}"),
            );
        }
    };
    let endpoint = format!("{}/models", base_url.trim_end_matches('/'));
    let mut request = client.get(endpoint);
    if let Some(secret) = &secret {
        request = if family == "messages" {
            request
                .header("x-api-key", secret)
                .header("anthropic-version", "2023-06-01")
        } else {
            request.bearer_auth(secret)
        };
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "discovery_failed",
                &format!("model discovery failed: {error}"),
            );
        }
    };
    if !response.status().is_success() {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "discovery_failed",
            &format!("upstream returned HTTP {}", response.status().as_u16()),
        );
    }
    let payload: Value = response.json().await.unwrap_or(Value::Null);
    let entries = payload
        .get("data")
        .or_else(|| payload.get("models"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut model_ids = Vec::new();
    for entry in entries {
        let id = entry
            .get("id")
            .or_else(|| entry.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(id) = id.filter(|value| !value.is_empty()) {
            model_ids.push(id);
        }
    }
    model_ids.sort();
    model_ids.dedup();
    let endpoint_path = endpoint_for_family(&family);
    let mut synced = 0u64;
    for model_id in &model_ids {
        let result = sqlx::query(
            "INSERT INTO models (provider_id, model_id, wire_family, endpoint_path, enabled, source)
             VALUES ($1, $2, $3::wire_family, $4, true, 'discovered')
             ON CONFLICT (provider_id, model_id, endpoint_path) DO NOTHING",
        )
        .bind(&provider_id)
        .bind(model_id)
        .bind(&family)
        .bind(endpoint_path)
        .execute(&state.pool)
        .await;
        if result
            .map(|result| result.rows_affected() > 0)
            .unwrap_or(false)
        {
            synced += 1;
        }
    }
    state.snapshots.invalidate();
    json_response(StatusCode::OK, json!({"synced": synced}))
}

/// `PATCH /console/api/providers/platform/global/{providerId}` — enable or
/// disable a shared builtin provider for the whole platform.
pub async fn update_global_provider(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "platform:admin") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let Some(enabled) = body.get("enabled").and_then(Value::as_bool) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "enabled is required",
        );
    };
    let updated = sqlx::query(
        "UPDATE providers SET enabled = $2 WHERE id = $1 AND tenant_id IS NULL RETURNING id",
    )
    .bind(&provider_id)
    .bind(enabled)
    .fetch_optional(&state.pool)
    .await;
    match updated {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            match provider_detail_value(&state.pool, &tenant, &provider_id).await {
                Ok(value) => json_response(StatusCode::OK, value),
                Err(error) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    &format!("provider readback failed: {error}"),
                ),
            }
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Global provider {provider_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("provider update failed: {error}"),
        ),
    }
}

/// `POST /console/api/providers/{providerId}/accounts/export`.
pub async fn export_provider_accounts(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "providers:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let Some(account_ids) = body.get("accountIds").and_then(Value::as_array) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "accountIds is required",
        );
    };
    let ids: Vec<String> = account_ids
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, provider_id, label, credential_kind::text AS credential_kind,
                status::text AS status, credential_ciphertext, auth_state
         FROM provider_accounts
         WHERE provider_id = $1 AND tenant_id = $2::uuid AND id::text = ANY($3)
         ORDER BY sort_index, created_at",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .bind(&ids)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            let access_token = row
                .try_get::<Option<Vec<u8>>, _>("credential_ciphertext")
                .ok()
                .flatten()
                .and_then(|ciphertext| {
                    keyla_security::decrypt_credential_to_string(&ciphertext).ok()
                })
                .unwrap_or_default();
            let mut value = json!({
                "id": row.get::<String, _>("id"),
                "providerId": row.get::<String, _>("provider_id"),
                "label": row.get::<String, _>("label"),
                "credentialKind": row.get::<String, _>("credential_kind"),
                "status": row.get::<String, _>("status"),
                "accessToken": access_token,
            });
            if let Ok(Some(auth_state)) = row.try_get::<Option<Value>, _>("auth_state") {
                value
                    .as_object_mut()
                    .expect("object")
                    .insert("authState".into(), auth_state);
            }
            value
        })
        .collect();
    json_response(StatusCode::OK, Value::Array(data))
}

/// `DELETE /console/api/providers/{providerId}/models/bulk`.
pub async fn bulk_delete_provider_models(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "models:write") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let Some(tenant) = access.tenant_id else {
        return error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "Tenant is required",
        );
    };
    let Some(items) = body.get("items").and_then(Value::as_array) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "items is required",
        );
    };
    let mut deleted = 0u64;
    for item in items {
        let model_id = item.get("modelId").and_then(Value::as_str).unwrap_or("");
        let route = item.get("route").and_then(Value::as_str).unwrap_or("");
        if model_id.is_empty() || route.is_empty() {
            continue;
        }
        let result = sqlx::query(
            "DELETE FROM models m USING providers p
             WHERE p.id = m.provider_id AND p.tenant_id = $4::uuid
               AND m.provider_id = $1 AND m.model_id = $2 AND m.endpoint_path = $3",
        )
        .bind(&provider_id)
        .bind(model_id)
        .bind(route)
        .bind(&tenant)
        .execute(&state.pool)
        .await;
        if result
            .map(|result| result.rows_affected() > 0)
            .unwrap_or(false)
        {
            deleted += 1;
        }
    }
    state.snapshots.invalidate();
    json_response(StatusCode::OK, json!({"success": true, "deleted": deleted}))
}

/// Probe endpoints are not part of the Rust provider layer yet; answer with
/// the typed capability error instead of a bare 404.
pub async fn probe_unsupported() -> Response {
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        "capability_unsupported",
        "Provider probing is not implemented in the Rust gateway yet",
    )
}

/// `POST /console/api/providers/{providerId}/models` — register model ids.
pub async fn register_provider_models(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "models:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(model_ids) = body.get("modelIds").and_then(Value::as_array) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "modelIds is required",
        );
    };
    let family = match wire_family(body.get("wireFamily").and_then(Value::as_str)) {
        Ok(Some(family)) => family,
        Ok(None) => "chat".to_owned(),
        Err(message) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
        }
    };
    let owns: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM providers WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid))",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    if !owns {
        return error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Provider {provider_id} not found"),
        );
    }
    let endpoint = endpoint_for_family(&family);
    let mut registered = 0u64;
    let mut models = Vec::new();
    for model in model_ids {
        let Some(model_id) = model
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let result = sqlx::query(
            "INSERT INTO models (provider_id, model_id, wire_family, endpoint_path, enabled)
             VALUES ($1, $2, $3::wire_family, $4, true)
             ON CONFLICT (provider_id, model_id, endpoint_path) DO NOTHING",
        )
        .bind(&provider_id)
        .bind(model_id)
        .bind(&family)
        .bind(endpoint)
        .execute(&state.pool)
        .await;
        if result
            .map(|result| result.rows_affected() > 0)
            .unwrap_or(false)
        {
            registered += 1;
            models.push(json!({"modelId": model_id, "route": endpoint}));
        }
    }
    state.snapshots.invalidate();
    json_response(
        StatusCode::OK,
        json!({"registered": registered, "models": models}),
    )
}

/// `DELETE /console/api/providers/platform/global/{providerId}`.
pub async fn delete_global_provider(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(access) = resolve_console_access(&state.pool, &headers)
        .await
        .ok()
        .flatten()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid or revoked API key",
        );
    };
    if let Err(error) = require_scope(&access, "platform:admin") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    if keyla_providers::bundled_provider_ids().contains(&provider_id.as_str()) {
        return error_response(
            StatusCode::FORBIDDEN,
            "provider_is_builtin",
            "Built-in provider cannot be deleted",
        );
    }
    let deleted =
        sqlx::query("DELETE FROM providers WHERE id = $1 AND tenant_id IS NULL RETURNING id")
            .bind(&provider_id)
            .fetch_optional(&state.pool)
            .await;
    match deleted {
        Ok(Some(_)) => {
            state.snapshots.invalidate();
            json_response(StatusCode::OK, json!({"success": true}))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Provider {provider_id} not found"),
        ),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("provider delete failed: {error}"),
        ),
    }
}

// --- Model and account probes ----------------------------------------------

struct ProbeTarget {
    base_url: String,
    route: String,
    wire_family: String,
    account_id: Option<String>,
    secret: Option<String>,
    credential_kind: String,
}

#[allow(clippy::result_large_err)]
async fn resolve_probe_target(
    state: &ConsoleState,
    tenant: &str,
    provider_id: &str,
    body: &Value,
) -> Result<ProbeTarget, Response> {
    let provider = sqlx::query(
        "SELECT base_url, wire_family_default::text AS wire_family_default
         FROM providers WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)",
    )
    .bind(provider_id)
    .bind(tenant)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .ok_or_else(|| {
        error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            &format!("Provider {provider_id} not found"),
        )
    })?;
    let base_url = provider
        .try_get::<Option<String>, _>("base_url")
        .ok()
        .flatten()
        .or_else(|| keyla_providers::provider_base_url(provider_id).map(str::to_owned))
        .ok_or_else(|| {
            error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "provider_not_discoverable",
                "This provider has no configured base URL",
            )
        })?;
    let model_id = body
        .get("modelId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let wire_family = body
        .get("wireFamily")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            provider
                .try_get::<Option<String>, _>("wire_family_default")
                .ok()
                .flatten()
        })
        .unwrap_or_else(|| "chat".into());
    let route = body
        .get("route")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| match wire_family.as_str() {
            "messages" => "/v1/messages".into(),
            "responses" => "/v1/responses".into(),
            _ => "/v1/chat/completions".into(),
        });
    let account_filter = body.get("accountId").and_then(Value::as_str);
    let account = if let Some(account_id) = account_filter {
        sqlx::query(
            "SELECT id::text AS id, credential_ciphertext, credential_kind::text AS credential_kind
             FROM provider_accounts WHERE id = $1::uuid AND provider_id = $2
               AND (tenant_id IS NULL OR tenant_id = $3::uuid)",
        )
        .bind(account_id)
        .bind(provider_id)
        .bind(tenant)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
    } else {
        sqlx::query(
            "SELECT id::text AS id, credential_ciphertext, credential_kind::text AS credential_kind
             FROM provider_accounts WHERE provider_id = $1 AND (tenant_id IS NULL OR tenant_id = $2::uuid)
               AND status <> 'disabled' ORDER BY sort_index, created_at LIMIT 1",
        )
        .bind(provider_id)
        .bind(tenant)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
    };
    let account_id = account
        .as_ref()
        .and_then(|row| row.try_get::<String, _>("id").ok());
    let secret = account.as_ref().and_then(|row| {
        row.try_get::<Option<Vec<u8>>, _>("credential_ciphertext")
            .ok()
            .flatten()
            .and_then(|ciphertext| keyla_security::decrypt_credential_to_string(&ciphertext).ok())
    });
    let credential_kind = account
        .as_ref()
        .and_then(|row| row.try_get::<String, _>("credential_kind").ok())
        .unwrap_or_else(|| "none".into());
    if model_id.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "modelId is required",
        ));
    }
    Ok(ProbeTarget {
        base_url,
        route,
        wire_family,
        account_id,
        secret,
        credential_kind,
    })
}

async fn probe_target(
    _state: &ConsoleState,
    provider_id: &str,
    model_id: &str,
    body: &Value,
    target: &ProbeTarget,
) -> Value {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return json!({"ok": false, "latencyMs": 0, "error": format!("http client: {error}")});
        }
    };
    let prompt = body
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or("Reply with the single word: ok");
    let max_tokens = body
        .get("maxOutputTokens")
        .and_then(Value::as_i64)
        .unwrap_or(16);
    let payload = match target.wire_family.as_str() {
        "messages" => json!({
            "model": model_id,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }),
        "responses" => json!({
            "model": model_id,
            "max_output_tokens": max_tokens,
            "input": [{"role": "user", "content": prompt}],
        }),
        _ => json!({
            "model": model_id,
            "max_tokens": max_tokens,
            "stream": false,
            "messages": [{"role": "user", "content": prompt}],
        }),
    };
    let url = format!(
        "{}{}",
        target.base_url.trim_end_matches('/'),
        if target.route.starts_with('/') {
            target.route.clone()
        } else {
            format!("/{}", target.route)
        }
    );
    let started = std::time::Instant::now();
    let mut request = client.post(&url).json(&payload);
    if let Some(secret) = &target.secret {
        if target.wire_family == "messages" && target.credential_kind != "oauth" {
            request = request
                .header("x-api-key", secret)
                .header("anthropic-version", "2023-06-01");
        } else {
            request = request.bearer_auth(secret);
        }
    }
    if provider_id == "claude" && target.credential_kind == "oauth" {
        request = request.header("anthropic-beta", "oauth-2025-04-20");
    }
    if provider_id == "codex" && target.credential_kind == "oauth" {
        request = request
            .header("originator", "codex_cli_rs")
            .header("OpenAI-Beta", "responses=experimental");
    }
    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let latency = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u64;
            let text = response.text().await.unwrap_or_default();
            let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let sample = parsed
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|choices| choices.first())
                .and_then(|choice| choice.get("message"))
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
                .or_else(|| {
                    parsed
                        .get("content")
                        .and_then(Value::as_array)
                        .and_then(|parts| parts.first())
                        .and_then(|part| part.get("text"))
                        .and_then(Value::as_str)
                })
                .or_else(|| parsed.get("output_text").and_then(Value::as_str))
                .map(|sample| sample.chars().take(200).collect::<String>());
            let error = parsed
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let mut value = json!({
                "accountId": target.account_id,
                "ok": (200..300).contains(&status),
                "latencyMs": latency,
                "statusCode": status,
            });
            let object = value.as_object_mut().expect("object");
            if let Some(sample) = sample {
                object.insert("sample".into(), json!(sample));
            }
            if let Some(error) = error {
                object.insert("error".into(), json!(error));
            } else if status >= 300 {
                object.insert(
                    "error".into(),
                    json!(text.chars().take(200).collect::<String>()),
                );
            }
            value
        }
        Err(error) => json!({
            "accountId": target.account_id,
            "ok": false,
            "latencyMs": started.elapsed().as_millis().min(u128::from(u32::MAX)) as u64,
            "error": error.to_string(),
        }),
    }
}

/// `POST /console/api/providers/{providerId}/models/probe`.
pub async fn probe_model(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "providers:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let model_id = body
        .get("modelId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let target = match resolve_probe_target(&state, &tenant, &provider_id, &body).await {
        Ok(target) => target,
        Err(response) => return response,
    };
    let value = probe_target(&state, &provider_id, &model_id, &body, &target).await;
    json_response(StatusCode::OK, value)
}

/// `POST /console/api/providers/{providerId}/accounts/probe`.
pub async fn probe_accounts(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "providers:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(model_id) = body.get("modelId").and_then(Value::as_str) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "modelId is required",
        );
    };
    let base = match resolve_probe_target(&state, &tenant, &provider_id, &body).await {
        Ok(target) => target,
        Err(response) => return response,
    };
    let accounts: Vec<String> = sqlx::query_scalar(
        "SELECT id::text FROM provider_accounts WHERE provider_id = $1
           AND (tenant_id IS NULL OR tenant_id = $2::uuid)
         ORDER BY sort_index, created_at",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let mut results = Vec::new();
    for account_id in accounts {
        let mut probe_body = body.clone();
        probe_body
            .as_object_mut()
            .expect("object")
            .insert("accountId".into(), json!(account_id));
        if let Ok(target) = resolve_probe_target(&state, &tenant, &provider_id, &probe_body).await {
            results.push(probe_target(&state, &provider_id, model_id, &probe_body, &target).await);
        }
    }
    let _ = base;
    json_response(
        StatusCode::OK,
        json!({"providerId": provider_id, "modelId": model_id, "results": results}),
    )
}

/// `POST /console/api/providers/{providerId}/models/test-models`.
pub async fn probe_all_models(
    State(state): State<ConsoleState>,
    axum::extract::Path(provider_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "providers:write").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let models: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT m.model_id, m.endpoint_path, m.wire_family::text
         FROM models m JOIN providers p ON p.id = m.provider_id
         WHERE m.provider_id = $1 AND (p.tenant_id IS NULL OR p.tenant_id = $2::uuid)
           AND m.enabled = true ORDER BY m.model_id LIMIT 25",
    )
    .bind(&provider_id)
    .bind(&tenant)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let mut results = Vec::new();
    for (model_id, route, wire_family) in models {
        let body = json!({
            "modelId": model_id,
            "route": route,
            "wireFamily": wire_family,
        });
        if let Ok(target) = resolve_probe_target(&state, &tenant, &provider_id, &body).await {
            let probe = probe_target(&state, &provider_id, &model_id, &body, &target).await;
            results.push(json!({
                "modelId": model_id,
                "ok": probe.get("ok").and_then(Value::as_bool).unwrap_or(false),
                "latencyMs": probe.get("latencyMs").cloned().unwrap_or(json!(0)),
                "error": probe.get("error").cloned(),
            }));
        }
    }
    json_response(
        StatusCode::OK,
        json!({"providerId": provider_id, "results": results}),
    )
}
