//! Route catalog snapshot builder: persisted rows to `RouteSnapshot`.
//! Port of `src/transport/routing/route-catalog.ts`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use keyla_core::{ServiceKind, WireFamily};
use keyla_providers::{
    default_proxy_bypass_provider_ids, provider_has_adapter_user_agent,
    provider_supports_web_search, provider_uses_bespoke_wire,
};
use keyla_routing::{
    ComboDefinition, ComboStrategy, DEFAULT_PROVIDER_USER_AGENT, PoolRoutingSetting,
    ProviderRoutingSetting, ProviderRoutingStrategy, RouteCandidate, RouteSnapshot,
};
use serde_json::Value;
use sqlx::postgres::PgPool;
use sqlx::{Row, postgres::PgRow};

use crate::DbResult;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_wire_family(value: &str) -> WireFamily {
    match value {
        "responses" => WireFamily::Responses,
        "messages" => WireFamily::Messages,
        _ => WireFamily::Chat,
    }
}

fn parse_service_kind(value: &str) -> ServiceKind {
    match value {
        "systemone" => ServiceKind::Systemone,
        "websearch" => ServiceKind::Websearch,
        _ => ServiceKind::Llm,
    }
}

fn parse_pool_strategy(value: &str) -> ProviderRoutingStrategy {
    if value == "round_robin" {
        ProviderRoutingStrategy::RoundRobin
    } else {
        ProviderRoutingStrategy::Fallback
    }
}

fn as_string_array(value: &Value) -> Vec<String> {
    match value {
        Value::Array(entries) => entries
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Projects one model row's metadata into the capability gates the router
/// filters candidates by.
pub fn build_capability_profile(
    provider_id: &str,
    modalities: Option<&Value>,
    reasoning: bool,
    tool_call: bool,
) -> BTreeMap<String, bool> {
    let (input, output) = match modalities {
        Some(Value::Object(map)) => {
            let input = map.get("input").map(as_string_array).unwrap_or_default();
            let output = map.get("output").map(as_string_array).unwrap_or_default();
            (input, output)
        }
        _ => (Vec::new(), Vec::new()),
    };
    let bespoke = provider_uses_bespoke_wire(provider_id);
    let codec_encodes_rich = !bespoke;
    let _ = (reasoning, tool_call);
    BTreeMap::from([
        ("bespokeWire".to_owned(), bespoke),
        (
            "image".to_owned(),
            input.iter().any(|kind| kind == "image") || codec_encodes_rich,
        ),
        (
            "document".to_owned(),
            input.iter().any(|kind| kind == "document") || codec_encodes_rich,
        ),
        (
            "audio".to_owned(),
            input.iter().any(|kind| kind == "audio") || codec_encodes_rich,
        ),
        (
            "mediaGeneration".to_owned(),
            output.iter().any(|kind| kind == "image"),
        ),
        ("tools".to_owned(), true),
        ("parallelToolCalls".to_owned(), true),
        ("reasoning".to_owned(), true),
        ("reasoningEncryptedContent".to_owned(), true),
        (
            "webSearch".to_owned(),
            provider_supports_web_search(provider_id),
        ),
        ("responseJsonObject".to_owned(), true),
        ("responseJsonSchema".to_owned(), true),
        ("promptCaching".to_owned(), true),
    ])
}

fn resolve_tenant_override<T: Clone>(tenant: Option<T>, global: Option<T>, default: T) -> T {
    tenant.or(global).unwrap_or(default)
}

fn resolve_route_user_agent(
    provider_id: &str,
    tenant_user_agent: Option<String>,
    global_user_agent: Option<String>,
) -> Option<String> {
    if keyla_providers::is_bundled_provider(provider_id)
        && !provider_has_adapter_user_agent(provider_id)
    {
        Some(resolve_tenant_override(
            tenant_user_agent,
            global_user_agent,
            DEFAULT_PROVIDER_USER_AGENT.to_owned(),
        ))
    } else {
        None
    }
}

fn hard_cooldown_category(category: Option<&str>) -> bool {
    matches!(
        category,
        Some("quota_exhausted" | "policy_blocked" | "auth_invalidated")
    )
}

fn cli_mapping_source_keys(tool_id: &str, source_model: &str) -> Vec<String> {
    if tool_id != "claude" {
        return vec![source_model.to_owned()];
    }
    let normalized = source_model.trim().to_ascii_lowercase();
    let family = if ["opus", "sonnet", "haiku", "fable", "mythos"].contains(&normalized.as_str()) {
        Some(normalized.clone())
    } else {
        normalized
            .strip_prefix("claude-")
            .and_then(|rest| rest.split('-').next())
            .filter(|family| ["opus", "sonnet", "haiku", "fable", "mythos"].contains(family))
            .map(str::to_owned)
    };
    let Some(family) = family else {
        return vec![source_model.to_owned()];
    };
    if normalized.contains('/') {
        return vec![source_model.to_owned()];
    }
    let mut keys = vec![
        source_model.to_owned(),
        family.clone(),
        format!("claude-{family}-5"),
        format!("claude-{family}-5-1"),
        format!("claude-{family}-5-5"),
        format!("claude-{family}-4-6"),
        format!("claude-{family}-4-5"),
    ];
    keys.dedup();
    keys
}

struct ProviderRow {
    id: String,
    tenant_id: Option<String>,
    requires_account: bool,
}

struct ModelRow {
    provider_id: String,
    model_id: String,
    wire_family: WireFamily,
    service_kind: ServiceKind,
    endpoint_path: String,
    modalities: Option<Value>,
    reasoning: bool,
    tool_call: bool,
}

struct AccountRow {
    id: String,
    provider_id: String,
    tenant_id: Option<String>,
    label: String,
    status: String,
    cooldown_until_ms: Option<f64>,
    model_cooldowns: Value,
    last_error_category: Option<String>,
    last_remaining_credit: Option<f64>,
    last_remaining_percent: Option<f64>,
}

struct AliasRow {
    tenant_id: String,
    alias: String,
    target_model: String,
}

struct ComboRow {
    tenant_id: String,
    name: String,
    members: Vec<String>,
    strategy: ComboStrategy,
}

struct RoutingRow {
    provider_id: String,
    tenant_id: Option<String>,
    strategy: ProviderRoutingStrategy,
    rotate_count: i64,
    max_inflight: Option<i64>,
    credit_limit_enabled: bool,
    credit_limit: Option<f64>,
    enabled: bool,
    bypass_proxy: bool,
    user_agent: String,
}

struct PoolRow {
    id: String,
    tenant_id: String,
    status: String,
    max_inflight: Option<i64>,
    weight: Option<i64>,
}

struct CliMappingRow {
    tenant_id: String,
    api_key_id: String,
    tool_id: String,
    source_model: String,
    target_model: String,
    enabled: bool,
}

struct CliSettingRow {
    tenant_id: String,
    api_key_id: String,
    mappings_enabled: bool,
}

struct PoolSettingRow {
    tenant_id: String,
    strategy: String,
    rotate_count: i64,
}

async fn load_providers(pool: &PgPool) -> DbResult<Vec<ProviderRow>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id, tenant_id::text AS tenant_id, requires_account FROM providers WHERE enabled = true",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ProviderRow {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            requires_account: row.get("requires_account"),
        })
        .collect())
}

async fn load_models(pool: &PgPool) -> DbResult<Vec<ModelRow>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT provider_id, model_id, wire_family::text AS wire_family, service_kind,
                endpoint_path, modalities, reasoning, tool_call, enabled
         FROM models",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|row| row.get::<bool, _>("enabled"))
        .map(|row| ModelRow {
            provider_id: row.get("provider_id"),
            model_id: row.get("model_id"),
            wire_family: parse_wire_family(&row.get::<String, _>("wire_family")),
            service_kind: parse_service_kind(&row.get::<String, _>("service_kind")),
            endpoint_path: row.get("endpoint_path"),
            modalities: row.get("modalities"),
            reasoning: row.get("reasoning"),
            tool_call: row.get("tool_call"),
        })
        .collect())
}

async fn load_accounts(pool: &PgPool) -> DbResult<Vec<AccountRow>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, provider_id, tenant_id::text AS tenant_id, label,
                status::text AS status,
                (EXTRACT(EPOCH FROM cooldown_until) * 1000)::float8 AS cooldown_until_ms,
                model_cooldowns, last_error_category,
                last_remaining_credit::float8 AS last_remaining_credit,
                last_remaining_percent::float8 AS last_remaining_percent
         FROM provider_accounts
         WHERE status <> 'disabled'
         ORDER BY status, created_at, id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| AccountRow {
            id: row.get("id"),
            provider_id: row.get("provider_id"),
            tenant_id: row.get("tenant_id"),
            label: row.get("label"),
            status: row.get("status"),
            cooldown_until_ms: row.get("cooldown_until_ms"),
            model_cooldowns: row
                .get::<Option<Value>, _>("model_cooldowns")
                .unwrap_or(Value::Object(Default::default())),
            last_error_category: row.get("last_error_category"),
            last_remaining_credit: row.get("last_remaining_credit"),
            last_remaining_percent: row.get("last_remaining_percent"),
        })
        .collect())
}

async fn load_aliases(pool: &PgPool) -> DbResult<Vec<AliasRow>> {
    let rows: Vec<PgRow> =
        sqlx::query("SELECT tenant_id::text AS tenant_id, alias, target_model FROM model_aliases")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|row| AliasRow {
            tenant_id: row.get("tenant_id"),
            alias: row.get("alias"),
            target_model: row.get("target_model"),
        })
        .collect())
}

async fn load_combos(pool: &PgPool) -> DbResult<Vec<ComboRow>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT tenant_id::text AS tenant_id, name, members, strategy::text AS strategy
         FROM model_combos",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ComboRow {
            tenant_id: row.get("tenant_id"),
            name: row.get("name"),
            members: row
                .get::<Option<Value>, _>("members")
                .as_ref()
                .map(as_string_array)
                .unwrap_or_default(),
            strategy: ComboStrategy::parse(&row.get::<String, _>("strategy")),
        })
        .collect())
}

async fn load_routing_settings(pool: &PgPool) -> DbResult<Vec<RoutingRow>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT provider_id, tenant_id::text AS tenant_id, strategy::text AS strategy,
                rotate_count::bigint AS rotate_count, max_inflight::bigint AS max_inflight, credit_limit_enabled,
                credit_limit::float8 AS credit_limit, enabled, bypass_proxy, user_agent
         FROM provider_routing_settings",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| RoutingRow {
            provider_id: row.get("provider_id"),
            tenant_id: row.get("tenant_id"),
            strategy: ProviderRoutingStrategy::parse(&row.get::<String, _>("strategy")),
            rotate_count: row.get("rotate_count"),
            max_inflight: row.get("max_inflight"),
            credit_limit_enabled: row.get("credit_limit_enabled"),
            credit_limit: row.get("credit_limit"),
            enabled: row.get("enabled"),
            bypass_proxy: row.get("bypass_proxy"),
            user_agent: row.get("user_agent"),
        })
        .collect())
}

async fn load_pools(pool: &PgPool) -> DbResult<Vec<PoolRow>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, status::text AS status,
                max_inflight::bigint AS max_inflight, weight::bigint AS weight
         FROM network_pools",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PoolRow {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            status: row.get("status"),
            max_inflight: row.get("max_inflight"),
            weight: row.get("weight"),
        })
        .collect())
}

async fn load_disabled_models(pool: &PgPool) -> DbResult<BTreeSet<String>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT tenant_id::text AS tenant_id, provider_id, model_id, endpoint_path
         FROM tenant_disabled_models",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            format!(
                "{}:{}:{}:{}",
                row.get::<String, _>("tenant_id"),
                row.get::<String, _>("provider_id"),
                row.get::<String, _>("model_id"),
                row.get::<String, _>("endpoint_path")
            )
        })
        .collect())
}

async fn load_cli_mappings(pool: &PgPool) -> DbResult<(Vec<CliMappingRow>, Vec<CliSettingRow>)> {
    let mapping_rows: Vec<PgRow> = sqlx::query(
        "SELECT tenant_id::text AS tenant_id, api_key_id::text AS api_key_id, tool_id,
                source_model, target_model, enabled
         FROM cli_tool_mappings",
    )
    .fetch_all(pool)
    .await?;
    let setting_rows: Vec<PgRow> = sqlx::query(
        "SELECT tenant_id::text AS tenant_id, api_key_id::text AS api_key_id, mappings_enabled
         FROM cli_tool_settings",
    )
    .fetch_all(pool)
    .await?;
    Ok((
        mapping_rows
            .into_iter()
            .map(|row| CliMappingRow {
                tenant_id: row.get("tenant_id"),
                api_key_id: row.get("api_key_id"),
                tool_id: row.get("tool_id"),
                source_model: row.get("source_model"),
                target_model: row.get("target_model"),
                enabled: row.get("enabled"),
            })
            .collect(),
        setting_rows
            .into_iter()
            .map(|row| CliSettingRow {
                tenant_id: row.get("tenant_id"),
                api_key_id: row.get("api_key_id"),
                mappings_enabled: row.get("mappings_enabled"),
            })
            .collect(),
    ))
}

async fn load_pool_settings(pool: &PgPool) -> DbResult<Vec<PoolSettingRow>> {
    let rows: Vec<PgRow> = sqlx::query(
        "SELECT tenant_id::text AS tenant_id, strategy::text AS strategy, rotate_count::bigint AS rotate_count
         FROM pool_routing_settings",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PoolSettingRow {
            tenant_id: row.get("tenant_id"),
            strategy: row.get("strategy"),
            rotate_count: row.get("rotate_count"),
        })
        .collect())
}

/// Loads and projects the routing catalog. `tenant_id = None` builds the
/// unfiltered snapshot used by the live data plane; `Some` builds a
/// tenant-scoped one.
pub async fn load_route_catalog(pool: &PgPool, tenant_id: Option<&str>) -> DbResult<RouteSnapshot> {
    let providers = load_providers(pool).await?;
    let models = load_models(pool).await?;
    let accounts = load_accounts(pool).await?;
    let aliases_rows = load_aliases(pool).await?;
    let combos_rows = load_combos(pool).await?;
    let routing_rows = load_routing_settings(pool).await?;
    let pool_rows = load_pools(pool).await?;
    let disabled_keys = load_disabled_models(pool).await?;
    let (cli_mapping_rows, cli_setting_rows) = load_cli_mappings(pool).await?;
    let pool_setting_rows = load_pool_settings(pool).await?;

    let now = now_ms();
    let tenant_matches = |row_tenant: Option<&str>| match tenant_id {
        None => true,
        Some(tenant) => row_tenant.is_none() || row_tenant == Some(tenant),
    };
    let filter_matches = |row_tenant: &str| tenant_id.is_none_or(|tenant| row_tenant == tenant);

    let provider_tenant: HashMap<String, Option<String>> = providers
        .iter()
        .map(|provider| (provider.id.clone(), provider.tenant_id.clone()))
        .collect();
    let requires_account: HashMap<String, bool> = providers
        .iter()
        .map(|provider| (provider.id.clone(), provider.requires_account))
        .collect();

    // Per-tenant active pools.
    let mut active_pools: HashMap<String, Vec<(&str, i64, i64)>> = HashMap::new();
    let mut configured_pool_tenants: BTreeSet<String> = BTreeSet::new();
    for pool in &pool_rows {
        configured_pool_tenants.insert(pool.tenant_id.clone());
        if pool.status != "active" {
            continue;
        }
        active_pools
            .entry(pool.tenant_id.clone())
            .or_default()
            .push((
                &pool.id,
                pool.max_inflight.unwrap_or(10),
                pool.weight.unwrap_or(100),
            ));
    }

    let mut pool_routing: HashMap<String, PoolRoutingSetting> = HashMap::new();
    for row in &pool_setting_rows {
        if filter_matches(&row.tenant_id) {
            pool_routing.insert(
                row.tenant_id.clone(),
                PoolRoutingSetting {
                    strategy: parse_pool_strategy(&row.strategy),
                    rotate_count: row.rotate_count,
                },
            );
        }
    }

    // Provider routing: global settings under the "__global__" sentinel.
    let mut provider_routing: HashMap<String, HashMap<String, ProviderRoutingSetting>> =
        HashMap::new();
    for row in &routing_rows {
        let tenant_key = row
            .tenant_id
            .clone()
            .unwrap_or_else(|| "__global__".to_owned());
        provider_routing.entry(tenant_key).or_default().insert(
            row.provider_id.clone(),
            ProviderRoutingSetting {
                strategy: row.strategy,
                rotate_count: row.rotate_count,
                max_inflight: row.max_inflight,
                credit_limit_enabled: Some(row.credit_limit_enabled),
                credit_limit: row.credit_limit,
                enabled: row.enabled,
                user_agent: Some(row.user_agent.clone()),
                bypass_proxy: row.bypass_proxy,
            },
        );
    }

    let bypass_defaults = default_proxy_bypass_provider_ids();
    let routing_setting = |provider_id: &str, tenant: Option<&str>| {
        tenant
            .and_then(|tenant| provider_routing.get(tenant))
            .and_then(|bucket| bucket.get(provider_id))
    };
    let global_setting = |provider_id: &str| {
        provider_routing
            .get("__global__")
            .and_then(|bucket| bucket.get(provider_id))
    };

    let resolve_bypass = |provider_id: &str, tenant: Option<&str>| -> bool {
        let tenant_setting = routing_setting(provider_id, tenant);
        let global = global_setting(provider_id);
        resolve_tenant_override(
            tenant_setting.map(|setting| setting.bypass_proxy),
            global.map(|setting| setting.bypass_proxy),
            bypass_defaults.contains(provider_id),
        )
    };
    let resolve_user_agent = |provider_id: &str, tenant: Option<&str>| -> Option<String> {
        resolve_route_user_agent(
            provider_id,
            routing_setting(provider_id, tenant).and_then(|setting| setting.user_agent.clone()),
            global_setting(provider_id).and_then(|setting| setting.user_agent.clone()),
        )
    };
    let resolve_max_inflight = |provider_id: &str, tenant: Option<&str>| -> Option<i64> {
        routing_setting(provider_id, tenant)
            .and_then(|setting| setting.max_inflight)
            .or_else(|| global_setting(provider_id).and_then(|setting| setting.max_inflight))
    };
    let resolve_credit = |provider_id: &str, tenant: Option<&str>| -> (bool, f64) {
        let tenant_setting = routing_setting(provider_id, tenant);
        let global = global_setting(provider_id);
        let enabled = tenant_setting
            .and_then(|setting| setting.credit_limit_enabled)
            .or_else(|| global.and_then(|setting| setting.credit_limit_enabled))
            .unwrap_or(false);
        let limit = tenant_setting
            .and_then(|setting| setting.credit_limit)
            .or_else(|| global.and_then(|setting| setting.credit_limit))
            .unwrap_or(50.0);
        (enabled, limit)
    };
    struct NetworkPools {
        ids: Vec<String>,
        limits: BTreeMap<String, i64>,
        weights: BTreeMap<String, i64>,
        routing: Option<PoolRoutingSetting>,
    }
    let resolve_network_pools = |provider_id: &str, tenant: Option<&str>| -> Option<NetworkPools> {
        let tenant = tenant?;
        if resolve_bypass(provider_id, Some(tenant)) {
            return None;
        }
        if !configured_pool_tenants.contains(tenant) {
            return None;
        }
        let pools = active_pools.get(tenant).cloned().unwrap_or_default();
        let ids = pools.iter().map(|(id, _, _)| (*id).to_owned()).collect();
        let limits = pools
            .iter()
            .map(|(id, limit, _)| ((*id).to_owned(), *limit))
            .collect();
        let weights = pools
            .iter()
            .map(|(id, _, weight)| ((*id).to_owned(), *weight))
            .collect();
        Some(NetworkPools {
            ids,
            limits,
            weights,
            routing: pool_routing.get(tenant).cloned(),
        })
    };

    let mut accounts_by_provider: HashMap<String, Vec<&AccountRow>> = HashMap::new();
    for account in &accounts {
        if account.status == "disabled" {
            continue;
        }
        accounts_by_provider
            .entry(account.provider_id.clone())
            .or_default()
            .push(account);
    }

    let mut candidates: Vec<RouteCandidate> = Vec::new();
    for model in &models {
        let Some(provider_tenant_id) = provider_tenant.get(&model.provider_id).cloned() else {
            continue;
        };
        let provider_accounts = accounts_by_provider
            .get(&model.provider_id)
            .cloned()
            .unwrap_or_default();
        let capability = build_capability_profile(
            &model.provider_id,
            model.modalities.as_ref(),
            model.reasoning,
            model.tool_call,
        );
        if provider_accounts.is_empty() {
            let requires = requires_account
                .get(&model.provider_id)
                .copied()
                .unwrap_or(true);
            if !requires {
                for candidate_tenant in &configured_pool_tenants {
                    if let Some(pools) =
                        resolve_network_pools(&model.provider_id, Some(candidate_tenant))
                    {
                        let mut candidate = RouteCandidate::new(
                            model.provider_id.clone(),
                            model.model_id.clone(),
                            model.wire_family,
                            model.service_kind,
                            model.endpoint_path.clone(),
                            capability.clone(),
                        );
                        candidate.tenant_id = Some(candidate_tenant.clone());
                        candidate.requires_account = Some(false);
                        candidate.network_pool_ids = pools.ids;
                        candidate.network_pool_required = true;
                        candidate.network_pool_limits = pools.limits;
                        candidate.network_pool_weights = pools.weights;
                        candidate.network_pool_routing = pools.routing;
                        if tenant_id.is_none_or(|tenant| tenant == candidate_tenant) {
                            candidates.push(candidate);
                        }
                    }
                }
            }
            let network_pools = if requires {
                None
            } else {
                resolve_network_pools(&model.provider_id, provider_tenant_id.as_deref())
            };
            let mut candidate = RouteCandidate::new(
                model.provider_id.clone(),
                model.model_id.clone(),
                model.wire_family,
                model.service_kind,
                model.endpoint_path.clone(),
                capability.clone(),
            );
            candidate.tenant_id = provider_tenant_id.clone();
            if requires {
                candidate.health_status = Some(keyla_routing::HealthStatus::Disabled);
            } else {
                candidate.requires_account = Some(false);
            }
            if let Some(pools) = network_pools {
                candidate.network_pool_ids = pools.ids;
                candidate.network_pool_required = true;
                candidate.network_pool_limits = pools.limits;
                candidate.network_pool_weights = pools.weights;
                candidate.network_pool_routing = pools.routing;
            }
            if tenant_matches(candidate.tenant_id.as_deref()) {
                candidates.push(candidate);
            }
            continue;
        }
        for account in provider_accounts {
            let row_tenant = account
                .tenant_id
                .clone()
                .or_else(|| provider_tenant_id.clone());
            if let Some(row_tenant_id) = &row_tenant {
                if disabled_keys.contains(&format!(
                    "{}:{}:{}:{}",
                    row_tenant_id, model.provider_id, model.model_id, model.endpoint_path
                )) {
                    continue;
                }
            }
            let network_pools = resolve_network_pools(&model.provider_id, row_tenant.as_deref());
            let user_agent = resolve_user_agent(&model.provider_id, row_tenant.as_deref());
            let (credit_enabled, credit_limit) =
                resolve_credit(&model.provider_id, row_tenant.as_deref());
            let mut candidate = RouteCandidate::new(
                model.provider_id.clone(),
                model.model_id.clone(),
                model.wire_family,
                model.service_kind,
                model.endpoint_path.clone(),
                capability.clone(),
            );
            candidate.tenant_id = row_tenant.clone();
            candidate.provider_account_id = Some(account.id.clone());
            candidate.provider_account_label = Some(account.label.clone());
            candidate.user_agent = user_agent;
            candidate.credit_limit_enabled = Some(credit_enabled);
            candidate.credit_limit = Some(credit_limit);
            candidate.last_remaining_credit = account.last_remaining_credit;
            candidate.last_remaining_percent = account.last_remaining_percent;
            candidate.max_inflight =
                resolve_max_inflight(&model.provider_id, row_tenant.as_deref());
            if let Some(pools) = network_pools {
                candidate.network_pool_required = true;
                candidate.network_pool_ids = pools.ids;
                candidate.network_pool_limits = pools.limits;
                candidate.network_pool_weights = pools.weights;
                candidate.network_pool_routing = pools.routing;
            }
            if account.status == "cooldown"
                && account
                    .cooldown_until_ms
                    .is_some_and(|until| until > now as f64)
            {
                candidate.health_status = Some(keyla_routing::HealthStatus::Cooldown);
                candidate.cooldown_kind = Some(
                    if hard_cooldown_category(account.last_error_category.as_deref()) {
                        keyla_routing::CooldownKind::Hard
                    } else {
                        keyla_routing::CooldownKind::Soft
                    },
                );
            }
            let model_cooldown_until = account
                .model_cooldowns
                .as_object()
                .and_then(|map| map.get(&model.model_id))
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.timestamp_millis());
            if model_cooldown_until.is_some_and(|until| until > now) {
                candidate.health_status = Some(keyla_routing::HealthStatus::ModelCooldown);
            }
            if tenant_matches(candidate.tenant_id.as_deref()) {
                candidates.push(candidate);
            }
        }
    }

    let mut aliases: HashMap<String, HashMap<String, String>> = HashMap::new();
    for row in &aliases_rows {
        if filter_matches(&row.tenant_id) {
            aliases
                .entry(row.tenant_id.clone())
                .or_default()
                .insert(row.alias.clone(), row.target_model.clone());
        }
    }

    let mut cli_aliases: HashMap<String, HashMap<String, String>> = HashMap::new();
    let enabled_buckets: BTreeSet<String> = cli_setting_rows
        .iter()
        .filter(|row| row.mappings_enabled)
        .map(|row| format!("{}:{}", row.tenant_id, row.api_key_id))
        .collect();
    for row in &cli_mapping_rows {
        if !row.enabled {
            continue;
        }
        if !enabled_buckets.contains(&format!("{}:{}", row.tenant_id, row.api_key_id)) {
            continue;
        }
        if !filter_matches(&row.tenant_id) {
            continue;
        }
        let bucket_key = format!("{}:{}", row.tenant_id, row.api_key_id);
        let bucket = cli_aliases.entry(bucket_key).or_default();
        for source_key in cli_mapping_source_keys(&row.tool_id, &row.source_model) {
            bucket.insert(source_key, row.target_model.clone());
        }
    }

    let mut combos: HashMap<String, HashMap<String, ComboDefinition>> = HashMap::new();
    for row in &combos_rows {
        if filter_matches(&row.tenant_id) {
            combos.entry(row.tenant_id.clone()).or_default().insert(
                row.name.clone(),
                ComboDefinition {
                    members: row.members.clone(),
                    strategy: row.strategy,
                },
            );
        }
    }

    Ok(RouteSnapshot {
        revision: 0,
        candidates,
        aliases,
        cli_aliases,
        combos,
        created_at: now,
        provider_routing: (!provider_routing.is_empty()).then_some(provider_routing),
        pool_routing: (!pool_routing.is_empty()).then_some(pool_routing),
    })
}
