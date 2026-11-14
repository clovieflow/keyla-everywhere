//! Observability reads for the console: system health and usage analytics.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::{DateTime, SecondsFormat, Utc};
use keyla_config::Env;
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const HEALTH_WINDOW_HOURS: i64 = 24;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const UPDATE_RELEASE_URL: &str =
    "https://api.github.com/repos/clovieflow/keyla-everywhere/releases/latest";
const UPDATE_CACHE_TTL: Duration = Duration::from_secs(15 * 60);

const GATEWAY_ERROR_PREDICATE: &str = "(status IN ('failed','truncated') AND (http_status IS NULL OR (http_status >= 500 AND http_status NOT IN (503,529))))";

const EFFECTIVE_STATUS: &str = "coalesce(http_status, CASE status WHEN 'completed' THEN 200 WHEN 'cancelled' THEN 499 WHEN 'truncated' THEN 502 ELSE 500 END)";

fn json_response(status: StatusCode, value: Value) -> Response {
    console_response(status, value)
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, console_error_body(code, message))
}

fn server_error(error: impl std::fmt::Display) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        &format!("database error: {error}"),
    )
}

fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

struct ProcessMetrics {
    rss: u64,
    virtual_memory: u64,
    cpu_percent: f64,
    total_memory: u64,
    used_memory: u64,
    available_memory: u64,
    cores: usize,
    threads: u64,
    load_average: (f64, f64, f64),
}

fn process_metrics() -> ProcessMetrics {
    use std::sync::OnceLock;
    use sysinfo::{Pid, ProcessesToUpdate, System};

    static SYSTEM: OnceLock<Mutex<System>> = OnceLock::new();
    let mut system = SYSTEM
        .get_or_init(|| Mutex::new(System::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    system.refresh_processes(ProcessesToUpdate::All, true);
    system.refresh_memory();
    system.refresh_cpu_all();
    let pid = Pid::from_u32(std::process::id());
    let process = system.process(pid);
    let rss = process.map(|process| process.memory()).unwrap_or(0);
    let virtual_memory = process.map(|process| process.virtual_memory()).unwrap_or(0);
    let cpu = process
        .map(|process| f64::from(process.cpu_usage()))
        .unwrap_or(0.0);
    let threads = process
        .and_then(|process| process.tasks().map(|tasks| tasks.len() as u64))
        .unwrap_or(0);
    let load = System::load_average();
    let total_memory = system.total_memory();
    let used_memory = system.used_memory();
    let reported_available = system.available_memory();
    let available_memory = if reported_available == 0 {
        total_memory.saturating_sub(used_memory)
    } else {
        reported_available
    };
    ProcessMetrics {
        rss,
        virtual_memory,
        cpu_percent: cpu,
        total_memory,
        used_memory,
        available_memory,
        cores: system.cpus().len().max(1),
        threads,
        load_average: (load.one, load.five, load.fifteen),
    }
}

struct HealthStats {
    total: i64,
    errors: i64,
    avg: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    cached_tokens: i64,
    input_tokens: i64,
    output_tokens: i64,
    tokens_per_sec: f64,
}

struct ReleaseCache {
    fetched_at: Instant,
    value: Value,
}

static RELEASE_CACHE: OnceLock<Mutex<Option<ReleaseCache>>> = OnceLock::new();

fn version_parts(value: &str) -> (Vec<u64>, Option<String>) {
    let value = value.trim().trim_start_matches(['v', 'V']);
    let (core, suffix) = value
        .split_once('-')
        .map(|(core, suffix)| (core, Some(suffix.to_owned())))
        .unwrap_or((value, None));
    (
        core.split('+')
            .next()
            .unwrap_or_default()
            .split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect(),
        suffix,
    )
}

fn version_is_newer(latest: &str, current: &str) -> bool {
    let (latest_core, latest_suffix) = version_parts(latest);
    let (current_core, current_suffix) = version_parts(current);
    for index in 0..latest_core.len().max(current_core.len()) {
        let left = latest_core.get(index).copied().unwrap_or(0);
        let right = current_core.get(index).copied().unwrap_or(0);
        if left != right {
            return left > right;
        }
    }
    match (latest_suffix.as_deref(), current_suffix.as_deref()) {
        (None, None) => false,
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(latest), Some(current)) => latest > current,
    }
}

fn update_check_disabled() -> bool {
    keyla_config::ProcessEnv
        .get("KEYLA_UPDATE_CHECK")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off" | "no"
            )
        })
        .unwrap_or(false)
}

async fn release_status() -> Value {
    if update_check_disabled() {
        return json!({
            "latestVersion": null,
            "updateAvailable": false,
            "checkDisabled": true,
        });
    }
    {
        let cache = RELEASE_CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache.lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.fetched_at.elapsed() < UPDATE_CACHE_TTL {
                    return cached.value.clone();
                }
            }
        }
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return json!({
                "latestVersion": null,
                "updateAvailable": false,
                "checkFailed": true,
                "error": error.to_string(),
            });
        }
    };
    let value = match client
        .get(UPDATE_RELEASE_URL)
        .header(reqwest::header::USER_AGENT, "keyla-everywhere-update-check")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
    {
        Ok(response) if response.status() == reqwest::StatusCode::NOT_FOUND => json!({
            "latestVersion": null,
            "updateAvailable": false,
        }),
        Ok(response) if response.status().is_success() => {
            let payload: Value = response.json().await.unwrap_or(Value::Null);
            let latest = payload
                .get("tag_name")
                .and_then(Value::as_str)
                .map(|tag| tag.trim_start_matches(['v', 'V']).to_owned());
            let available = latest
                .as_deref()
                .is_some_and(|latest| version_is_newer(latest, VERSION));
            json!({
                "latestVersion": latest,
                "updateAvailable": available,
                "releaseUrl": payload.get("html_url").cloned().unwrap_or(Value::Null),
                "releaseName": payload.get("name").cloned().unwrap_or(Value::Null),
                "publishedAt": payload.get("published_at").cloned().unwrap_or(Value::Null),
            })
        }
        Ok(response) => json!({
            "latestVersion": null,
            "updateAvailable": false,
            "checkFailed": true,
            "statusCode": response.status().as_u16(),
        }),
        Err(error) => json!({
            "latestVersion": null,
            "updateAvailable": false,
            "checkFailed": true,
            "error": error.to_string(),
        }),
    };
    let cache = RELEASE_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = cache.lock() {
        *guard = Some(ReleaseCache {
            fetched_at: Instant::now(),
            value: value.clone(),
        });
    }
    value
}

/// `GET /console/api/system/update` — cached latest GitHub release status.
pub async fn update_status(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    let release = release_status().await;
    let latest = release.get("latestVersion").and_then(Value::as_str);
    let update_available = latest.is_some_and(|latest| version_is_newer(latest, VERSION));
    console_response(
        StatusCode::OK,
        json!({
            "currentVersion": VERSION,
            "latestVersion": latest,
            "updateAvailable": update_available,
            "releaseUrl": release.get("releaseUrl").cloned().unwrap_or(Value::Null),
            "releaseName": release.get("releaseName").cloned().unwrap_or(Value::Null),
            "publishedAt": release.get("publishedAt").cloned().unwrap_or(Value::Null),
            "checkFailed": release.get("checkFailed").and_then(Value::as_bool).unwrap_or(false),
            "checkDisabled": release.get("checkDisabled").and_then(Value::as_bool).unwrap_or(false),
            "checkedAt": iso(Utc::now()),
        }),
    )
}

/// `GET /console/api/system/health`.
pub async fn system_health(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    json_response(StatusCode::OK, health_value(&state, &tenant).await)
}

/// `GET /console/api/system/health/stream` — the same snapshot pushed before
/// the browser can render a poll interval. A single authenticated stream owns
/// one DB connection for its lifetime; it ends when the client disconnects.
pub async fn system_health_stream(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let initial = health_value(&state, &tenant).await;
    let state = state.clone();
    let body = async_stream::stream! {
        yield Ok::<Event, std::convert::Infallible>(
            Event::default().event("init").json_data(initial).unwrap_or_default(),
        );
        let mut ticker = tokio::time::interval(Duration::from_millis(2_000));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let value = health_value(&state, &tenant).await;
            yield Ok(Event::default().event("health").json_data(value).unwrap_or_default());
        }
    };
    Sse::new(body)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn health_value(state: &ConsoleState, tenant: &str) -> Value {
    let process = process_metrics();
    let configured_limit =
        keyla_config::resolve_memory_limit_override_bytes(&keyla_config::ProcessEnv)
            .ok()
            .flatten()
            .map(|value| value as u64);
    let memory_limit = configured_limit.unwrap_or(process.total_memory).max(1);
    let memory_percent = ((process.rss as f64 / memory_limit as f64) * 10_000.0).round() / 100.0;

    let since = Utc::now() - chrono::Duration::hours(HEALTH_WINDOW_HOURS);
    let database_started = Instant::now();
    let row: Result<PgRow, sqlx::Error> = sqlx::query(&format!(
        "SELECT count(*)::bigint AS total,
                count(*) FILTER (WHERE {GATEWAY_ERROR_PREDICATE})::bigint AS errors,
                coalesce(avg(latency_ms), 0)::float8 AS avg,
                coalesce(percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms), 0)::float8 AS p50,
                coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::float8 AS p95,
                coalesce(percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms), 0)::float8 AS p99,
                coalesce(sum(cached_input_tokens) FILTER (WHERE cached_input_tokens IS NOT NULL), 0)::bigint AS cached_tokens,
                coalesce(sum(input_tokens), 0)::bigint AS input_tokens,
                coalesce(sum(output_tokens), 0)::bigint AS output_tokens,
                coalesce(avg(tokens_per_sec) FILTER (WHERE tokens_per_sec IS NOT NULL), 0)::float8 AS avg_tokens_per_sec
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND created_at >= $2"
    ))
    .bind(tenant)
    .bind(since)
    .fetch_one(&state.pool)
    .await;
    let database_latency_ms =
        (database_started.elapsed().as_secs_f64() * 1_000.0 * 100.0).round() / 100.0;
    let (database_healthy, stats) = match row {
        Ok(row) => {
            let input_tokens: i64 = row.get("input_tokens");
            let cached_tokens: i64 = row.get("cached_tokens");
            (
                true,
                HealthStats {
                    total: row.get("total"),
                    errors: row.get("errors"),
                    avg: row.get("avg"),
                    p50: row.get("p50"),
                    p95: row.get("p95"),
                    p99: row.get("p99"),
                    cached_tokens,
                    input_tokens,
                    output_tokens: row.get("output_tokens"),
                    tokens_per_sec: row.get::<f64, _>("avg_tokens_per_sec").max(0.0),
                },
            )
        }
        Err(_) => (
            false,
            HealthStats {
                total: 0,
                errors: 0,
                avg: 0.0,
                p50: 0.0,
                p95: 0.0,
                p99: 0.0,
                cached_tokens: 0,
                input_tokens: 0,
                output_tokens: 0,
                tokens_per_sec: 0.0,
            },
        ),
    };
    let cache_hit = if stats.input_tokens > 0 {
        (((stats.cached_tokens as f64 / stats.input_tokens as f64) * 100.0).min(100.0) * 100.0)
            .round()
            / 100.0
    } else {
        0.0
    };
    let error_rate = if stats.total > 0 {
        ((stats.errors as f64 / stats.total as f64) * 10_000.0).round() / 100.0
    } else {
        0.0
    };
    let success_count = (stats.total - stats.errors).max(0);
    let redis_configured = keyla_config::ProcessEnv
        .get("REDIS_URL")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    // Lite mode runs on the in-process admission backend; an external Redis is
    // reported as configured here and its live status by `/health/ready`.
    let redis_healthy = true;
    let status = if !database_healthy {
        "unhealthy"
    } else if !redis_healthy {
        "degraded"
    } else {
        "healthy"
    };
    let version = std::env::var("KEYLA_VERSION").unwrap_or_else(|_| VERSION.to_owned());
    json!({
        "version": version,
        "status": status,
        "window_hours": HEALTH_WINDOW_HOURS,
        "uptime_seconds": state.started.elapsed().as_secs(),
        "database_healthy": database_healthy,
        "database_latency_ms": database_latency_ms,
        "database_pool_size": state.pool.size(),
        "database_pool_idle": state.pool.num_idle(),
        "redis_healthy": redis_healthy,
        "redis_configured": redis_configured,
        "redis_mode": if redis_configured { "external" } else { "in-memory" },
        "memory_bytes": process.rss,
        "virtual_memory_bytes": process.virtual_memory,
        "memory_percent": memory_percent,
        "memory_limit_bytes": memory_limit,
        "system_memory_bytes": process.total_memory,
        "system_memory_used_bytes": process.used_memory,
        "system_memory_available_bytes": process.available_memory,
        "heap_used_bytes": 0,
        "heap_total_bytes": 0,
        "external_bytes": 0,
        "cpu_percent": (process.cpu_percent * 100.0).round() / 100.0,
        "cpu_cores": process.cores,
        "thread_count": process.threads,
        "load_average_1": (process.load_average.0 * 100.0).round() / 100.0,
        "load_average_5": (process.load_average.1 * 100.0).round() / 100.0,
        "load_average_15": (process.load_average.2 * 100.0).round() / 100.0,
        "pid": std::process::id(),
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "request_count": stats.total,
        "success_count": success_count,
        "error_count": stats.errors,
        "error_rate_percent": error_rate,
        "latency_avg_ms": stats.avg.round() as i64,
        "latency_p50_ms": stats.p50.round() as i64,
        "latency_p95_ms": stats.p95.round() as i64,
        "latency_p99_ms": stats.p99.round() as i64,
        "cache_hit_rate_percent": cache_hit,
        "input_tokens": stats.input_tokens,
        "cached_tokens": stats.cached_tokens,
        "output_tokens": stats.output_tokens,
        "avg_tokens_per_sec": (stats.tokens_per_sec * 100.0).round() / 100.0,
    })
}

/// Parses a usage period into its start instant; `None` means "all".
fn period_start(period: &str) -> Result<Option<DateTime<Utc>>, ()> {
    if period == "all" {
        return Ok(None);
    }
    let split = period.find(['h', 'd']).ok_or(())?;
    let (amount, unit) = period.split_at(split);
    let amount: i64 = amount.parse().map_err(|_| ())?;
    if amount <= 0 {
        return Err(());
    }
    let hours = if unit == "d" { amount * 24 } else { amount };
    Ok(Some(Utc::now() - chrono::Duration::hours(hours)))
}

fn chart_bucket_seconds(period: &str) -> i64 {
    let Some(since) = period_start(period).ok().flatten() else {
        return 86_400;
    };
    let window_ms = (Utc::now() - since).num_milliseconds();
    if window_ms <= 2 * 3_600_000 {
        300
    } else if window_ms <= 2 * 86_400_000 {
        3_600
    } else if window_ms <= 10 * 86_400_000 {
        21_600
    } else {
        86_400
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// `GET /console/api/system/usage/summary?period=`.
pub async fn usage_summary(
    State(state): State<ConsoleState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let period = query.get("period").map(String::as_str).unwrap_or("24h");
    let since = match period_start(period) {
        Ok(since) => since,
        Err(()) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_period",
                &format!(
                    "Unsupported usage period: {period}. Use \"24h\", \"7d\", \"30d\", or \"all\"."
                ),
            );
        }
    };
    let row: Result<PgRow, sqlx::Error> = sqlx::query(&format!(
        "SELECT count(*)::bigint AS requests,
                coalesce(sum(input_tokens), 0)::bigint AS input_tokens,
                coalesce(sum(cached_input_tokens), 0)::bigint AS cached_tokens,
                coalesce(sum(input_tokens) FILTER (WHERE cached_input_tokens IS NOT NULL), 0)::bigint AS cache_reporting_input,
                coalesce(sum(output_tokens), 0)::bigint AS output_tokens,
                count(*) FILTER (WHERE {GATEWAY_ERROR_PREDICATE})::bigint AS errors,
                count(*) FILTER (WHERE status = 'cancelled')::bigint AS cancelled,
                count(*) FILTER (WHERE status = 'truncated')::bigint AS truncated,
                coalesce(avg(latency_ms), 0)::float8 AS avg_duration_ms,
                coalesce(sum(estimated_cost_usd), 0)::float8 AS estimated_cost_usd,
                count(*) FILTER (WHERE status = 'completed' AND estimated_cost_usd IS NULL)::bigint AS unpriced,
                coalesce(avg(tokens_per_sec) FILTER (WHERE tokens_per_sec IS NOT NULL), 0)::float8 AS avg_tokens_per_sec
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR created_at >= $2)"
    ))
    .bind(&tenant)
    .bind(since)
    .fetch_one(&state.pool)
    .await;
    let row = match row {
        Ok(row) => row,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("usage summary failed: {error}"),
            );
        }
    };
    let status_rows: Vec<PgRow> = sqlx::query(&format!(
        "SELECT {EFFECTIVE_STATUS} AS status, count(*)::bigint AS count
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR created_at >= $2)
         GROUP BY 1 ORDER BY 1",
    ))
    .bind(&tenant)
    .bind(since)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let status_counts: Vec<Value> = status_rows
        .iter()
        .map(|row| json!({"status": row.get::<i32, _>("status"), "count": row.get::<i64, _>("count")}))
        .collect();
    let requests: i64 = row.get("requests");
    let input_tokens: i64 = row.get("input_tokens");
    let cached_tokens: i64 = row.get("cached_tokens");
    let cache_reporting_input: i64 = row.get("cache_reporting_input");
    let output_tokens: i64 = row.get("output_tokens");
    let errors: i64 = row.get("errors");
    let cancelled: i64 = row.get("cancelled");
    let truncated: i64 = row.get("truncated");
    let avg_duration_ms: f64 = row.get("avg_duration_ms");
    let estimated_cost_usd: f64 = row.get("estimated_cost_usd");
    let unpriced: i64 = row.get("unpriced");
    let avg_tokens_per_sec: f64 = row.get("avg_tokens_per_sec");
    let cache_hit_rate = if cache_reporting_input > 0 {
        round2((cached_tokens as f64 / cache_reporting_input as f64) * 100.0)
    } else {
        0.0
    };
    json_response(
        StatusCode::OK,
        json!({
            "period": period,
            "totals": {
                "requests": requests,
                "inputTokens": input_tokens,
                "cachedTokens": cached_tokens,
                "outputTokens": output_tokens,
                "errors": errors,
                "cancelled": cancelled,
                "truncated": truncated,
                "statusCounts": status_counts,
                "avgDurationMs": round2(avg_duration_ms),
                "estimatedCostUsd": estimated_cost_usd,
                "partial": unpriced > 0,
                "cacheHitRate": cache_hit_rate,
                "avgTokensPerSec": round2(avg_tokens_per_sec),
            },
        }),
    )
}

/// `GET /console/api/system/usage/chart?period=`.
pub async fn usage_chart(
    State(state): State<ConsoleState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let period = query.get("period").map(String::as_str).unwrap_or("24h");
    let since = match period_start(period) {
        Ok(since) => since,
        Err(()) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_period",
                &format!("Unsupported usage period: {period}."),
            );
        }
    };
    let bucket_seconds = chart_bucket_seconds(period);
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT to_timestamp(floor(extract(epoch FROM created_at) / $3) * $3) AS bucket,
                count(*)::bigint AS requests,
                coalesce(sum(input_tokens), 0)::bigint AS input,
                coalesce(sum(cached_input_tokens), 0)::bigint AS cached,
                coalesce(sum(output_tokens), 0)::bigint AS output
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR created_at >= $2)
         GROUP BY 1 ORDER BY 1",
    )
    .bind(&tenant)
    .bind(since)
    .bind(bucket_seconds)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &format!("usage chart failed: {error}"),
            );
        }
    };
    let mut by_time: HashMap<i64, Value> = HashMap::new();
    let mut first: Option<i64> = None;
    for row in &rows {
        let bucket: DateTime<Utc> = row.get("bucket");
        let start = bucket.timestamp_millis();
        let start = (start / (bucket_seconds * 1000)) * (bucket_seconds * 1000);
        first = Some(first.map_or(start, |existing: i64| existing.min(start)));
        by_time.insert(
            start,
            json!({
                "t": DateTime::<Utc>::from_timestamp_millis(start)
                    .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
                    .unwrap_or_default(),
                "requests": row.get::<i64, _>("requests"),
                "input": row.get::<i64, _>("input"),
                "cached": row.get::<i64, _>("cached"),
                "output": row.get::<i64, _>("output"),
            }),
        );
    }
    let start_ms = since.map(|value| value.timestamp_millis()).or(first);
    let Some(start_ms) = start_ms else {
        return json_response(StatusCode::OK, json!({"buckets": []}));
    };
    let step = bucket_seconds * 1000;
    let aligned = (start_ms / step) * step;
    let now = Utc::now().timestamp_millis();
    let mut buckets = Vec::new();
    let mut at = aligned;
    while at <= now {
        buckets.push(by_time.remove(&at).unwrap_or_else(|| {
            json!({
                "t": DateTime::<Utc>::from_timestamp_millis(at)
                    .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
                    .unwrap_or_default(),
                "requests": 0,
                "input": 0,
                "cached": 0,
                "output": 0,
            })
        }));
        at += step;
    }
    json_response(StatusCode::OK, json!({"buckets": buckets}))
}

fn client_name(user_agent: Option<&str>) -> Option<String> {
    let raw = user_agent?.trim();
    if raw.is_empty() {
        return Some("unknown".into());
    }
    if raw.to_ascii_lowercase().starts_with("mozilla/") {
        return Some("Browser".into());
    }
    let product = raw.split_whitespace().next().unwrap_or("");
    let Some((name, version)) = product.split_once('/') else {
        return Some(product.to_owned());
    };
    let version = version.split([';', ',', ')']).next().unwrap_or("");
    Some(format!("{name}/{version}"))
}

fn request_item(row: &PgRow) -> Value {
    let input: i64 = row
        .try_get::<Option<i32>, _>("input_tokens")
        .ok()
        .flatten()
        .unwrap_or(0) as i64;
    let output: i64 = row
        .try_get::<Option<i32>, _>("output_tokens")
        .ok()
        .flatten()
        .unwrap_or(0) as i64;
    let mut item = json!({
        "requestId": row.get::<String, _>("request_id"),
        "status": row.try_get::<Option<String>, _>("status").ok().flatten().unwrap_or_else(|| "unknown".into()),
        "mode": if row.try_get::<Option<bool>, _>("stream").ok().flatten().unwrap_or(false) { "stream" } else { "non_stream" },
        "startedAt": iso(row.get::<DateTime<Utc>, _>("created_at")),
    });
    let object = item.as_object_mut().expect("object");
    let optional_text = |column: &str| row.try_get::<Option<String>, _>(column).ok().flatten();
    let optional_i32 = |column: &str| row.try_get::<Option<i32>, _>(column).ok().flatten();
    let optional_i64 = |column: &str| row.try_get::<Option<i64>, _>(column).ok().flatten();
    let optional_f64 = |column: &str| row.try_get::<Option<f64>, _>(column).ok().flatten();
    if let Some(surface) = optional_text("source_surface") {
        object.insert("surface".into(), json!(surface));
    }
    if let Some(provider) = optional_text("provider_id") {
        object.insert("providerId".into(), json!(provider));
    }
    if let Some(account) = optional_text("account_id") {
        object.insert("accountId".into(), json!(account));
    }
    if let Some(model) = optional_text("requested_model") {
        let model = match optional_text("requested_effort") {
            Some(effort) => format!("{model} ({effort})"),
            None => model,
        };
        object.insert("model".into(), json!(model));
    }
    if let Some(endpoint) = optional_text("endpoint") {
        object.insert("endpoint".into(), json!(endpoint));
    }
    if let Some(api_key_id) = optional_text("api_key_id") {
        object.insert("apiKeyId".into(), json!(api_key_id));
    }
    if let Some(label) = optional_text("api_key_label") {
        object.insert("apiKeyLabel".into(), json!(label));
    }
    if let Some(user_agent) = optional_text("user_agent") {
        let client = client_name(Some(&user_agent));
        object.insert("userAgent".into(), json!(user_agent));
        if let Some(client) = client {
            object.insert("clientName".into(), json!(client));
        }
    }
    if let Some(ip) = optional_text("client_ip") {
        object.insert("clientIp".into(), json!(ip));
    }
    if let Some(error) = optional_text("error_category") {
        object.insert("errorKind".into(), json!(error));
    }
    if let Some(origin) = optional_text("error_origin") {
        object.insert("errorOrigin".into(), json!(origin));
    }
    let http_status =
        optional_i32("http_status").unwrap_or_else(|| match optional_text("status").as_deref() {
            Some("completed") => 200,
            Some("cancelled") => 499,
            Some("truncated") => 502,
            _ => 500,
        });
    object.insert("httpStatus".into(), json!(http_status));
    if let Some(latency) = optional_i32("latency_ms") {
        object.insert("durationMs".into(), json!(latency));
    }
    if let Some(value) = optional_i32("input_tokens") {
        object.insert("inputTokens".into(), json!(value));
    }
    if let Some(value) = optional_i32("output_tokens") {
        object.insert("outputTokens".into(), json!(value));
    }
    if let Some(value) = optional_i32("cached_input_tokens") {
        object.insert("cachedTokens".into(), json!(value));
    }
    if let Some(value) = optional_i32("reasoning_tokens") {
        object.insert("reasoningTokens".into(), json!(value));
    }
    if input + output > 0 {
        object.insert("totalTokens".into(), json!(input + output));
    }
    if let Some(value) = optional_i32("ttfb_ms") {
        object.insert("ttfbMs".into(), json!(value));
    }
    if let Some(value) = optional_f64("tokens_per_sec") {
        object.insert("tokensPerSec".into(), json!(value));
    }
    if let Some(value) = optional_i64("first_content_delta_at_ms") {
        object.insert("firstContentDeltaAtMs".into(), json!(value));
    }
    if let Some(value) = optional_i64("last_event_at_ms") {
        object.insert("lastEventAtMs".into(), json!(value));
    }
    if let Some(value) = optional_f64("estimated_cost_usd") {
        object.insert("estimatedCost".into(), json!(value));
    }
    if let Some(value) = optional_f64("credit_used") {
        object.insert("creditUsed".into(), json!(value));
    }
    if let Some(value) = optional_i32("resolve_ms") {
        object.insert("resolveMs".into(), json!(value));
    }
    item
}

const REQUEST_COLUMNS: &str =
    "e.request_id::text AS request_id, e.source_surface::text AS source_surface,
    e.provider_id, e.account_id::text AS account_id, e.requested_model, e.requested_effort,
    e.endpoint, e.api_key_id::text AS api_key_id, k.label AS api_key_label, e.user_agent,
    e.client_ip, e.latency_ms, e.ttfb_ms, e.stream, e.status::text AS status, e.http_status,
    e.error_category, e.error_origin, e.input_tokens, e.cached_input_tokens, e.output_tokens,
    e.reasoning_tokens, e.estimated_cost_usd::float8 AS estimated_cost_usd,
    e.credit_used::float8 AS credit_used, e.resolve_ms, e.tokens_per_sec::float8 AS tokens_per_sec,
    e.first_content_delta_at_ms, e.last_event_at_ms, e.created_at";

/// `GET /console/api/system/usage/requests?period=&limit=&httpStatus=`.
pub async fn usage_requests(
    State(state): State<ConsoleState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let period = query.get("period").map(String::as_str).unwrap_or("24h");
    let since = match period_start(period) {
        Ok(since) => since,
        Err(()) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_period", "Invalid period");
        }
    };
    let limit: i64 = query
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    let http_status = match query.get("httpStatus") {
        None => None,
        Some(raw) => match raw.parse::<i32>() {
            Ok(status) if (100..=599).contains(&status) => Some(status),
            _ => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid HTTP status filter",
                );
            }
        },
    };
    let rows: Vec<PgRow> = match sqlx::query(&format!(
        "SELECT {REQUEST_COLUMNS}
         FROM telemetry_events e
         LEFT JOIN api_keys k ON k.id = e.api_key_id
         WHERE e.tenant_id = $1::uuid
           AND ($2::timestamptz IS NULL OR e.created_at >= $2)
           AND ($3::int IS NULL OR {EFFECTIVE_STATUS} = $3)
         ORDER BY e.created_at DESC, e.id DESC
         LIMIT $4"
    ))
    .bind(&tenant)
    .bind(since)
    .bind(http_status)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return server_error(error),
    };
    let items: Vec<Value> = rows.iter().map(request_item).collect();
    console_response(StatusCode::OK, json!({"items": items}))
}

/// `GET /console/api/system/usage/requests/{requestId}`.
pub async fn usage_request_detail(
    State(state): State<ConsoleState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let row: Result<Option<PgRow>, sqlx::Error> = sqlx::query(&format!(
        "SELECT {REQUEST_COLUMNS}
         FROM telemetry_events e
         LEFT JOIN api_keys k ON k.id = e.api_key_id
         WHERE e.tenant_id = $1::uuid AND e.request_id = $2::uuid
         ORDER BY e.created_at DESC, e.id DESC LIMIT 1"
    ))
    .bind(&tenant)
    .bind(&request_id)
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some(row)) => {
            let mut item = request_item(&row);
            let object = item.as_object_mut().expect("object");
            object.insert("proxy".into(), json!("direct"));
            object.insert("payloads".into(), Value::Null);
            object.insert(
                "payloadSignals".into(),
                json!({"toolCalls": 0, "images": 0, "attachments": 0}),
            );
            console_response(StatusCode::OK, item)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "request_not_found",
            &format!("Request {request_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `GET /console/api/system/usage/by-{dimension}?period=`.
pub async fn usage_by(
    State(state): State<ConsoleState>,
    Path(dimension): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let column = match dimension.as_str() {
        "model" => "e.requested_model",
        "provider" => "e.provider_id",
        "key" => "e.api_key_id::text",
        "client" => "e.user_agent",
        "client_ip" => "e.client_ip",
        _ => {
            return error_response(
                StatusCode::NOT_FOUND,
                "invalid_dimension",
                &format!(
                    "Unknown usage dimension: {dimension}. Use \"model\", \"provider\", \"key\", \"client\", or \"client_ip\"."
                ),
            );
        }
    };
    let period = query.get("period").map(String::as_str).unwrap_or("24h");
    let since = match period_start(period) {
        Ok(since) => since,
        Err(()) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_period", "Invalid period");
        }
    };
    let not_empty = if dimension == "key" {
        format!("AND {column} IS NOT NULL")
    } else {
        format!("AND {column} IS NOT NULL AND {column} <> ''")
    };
    let rows: Vec<PgRow> = match sqlx::query(&format!(
        "SELECT {column} AS name,
                count(*)::bigint AS requests,
                coalesce(sum(e.input_tokens), 0)::bigint AS input,
                coalesce(sum(e.output_tokens), 0)::bigint AS output,
                coalesce(sum(e.cached_input_tokens), 0)::bigint AS cached,
                coalesce(sum(e.input_tokens) FILTER (WHERE e.cached_input_tokens IS NOT NULL), 0)::bigint AS cache_reporting_input,
                count(*) FILTER (WHERE {GATEWAY_ERROR_PREDICATE})::bigint AS errors,
                sum(e.estimated_cost_usd)::float8 AS cost,
                coalesce(avg(e.tokens_per_sec) FILTER (WHERE e.tokens_per_sec IS NOT NULL), 0)::float8 AS avg_tokens_per_sec
         FROM telemetry_events e
         WHERE e.tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR e.created_at >= $2)
           {not_empty}
         GROUP BY {column}
         ORDER BY count(*) DESC
         LIMIT 100"
    ))
    .bind(&tenant)
    .bind(since)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return server_error(error),
    };
    let mut labels: HashMap<String, String> = HashMap::new();
    if dimension == "key" {
        let key_ids: Vec<String> = rows
            .iter()
            .filter_map(|row| row.try_get::<String, _>("name").ok())
            .collect();
        if !key_ids.is_empty() {
            let label_rows: Vec<PgRow> = sqlx::query(
                "SELECT id::text AS id, label FROM api_keys WHERE tenant_id = $1::uuid AND id::text = ANY($2)",
            )
            .bind(&tenant)
            .bind(&key_ids)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
            for row in label_rows {
                if let (Ok(id), Ok(label)) = (
                    row.try_get::<String, _>("id"),
                    row.try_get::<String, _>("label"),
                ) {
                    labels.insert(id, label);
                }
            }
        }
    }
    let data: Vec<Value> = rows
        .iter()
        .filter_map(|row| {
            let raw_name: String = row.try_get("name").ok()?;
            if raw_name.is_empty() {
                return None;
            }
            let input: i64 = row.try_get("input").unwrap_or(0);
            let output: i64 = row.try_get("output").unwrap_or(0);
            let cached: i64 = row.try_get("cached").unwrap_or(0);
            let reporting: i64 = row.try_get("cache_reporting_input").unwrap_or(0);
            let name = if dimension == "client" {
                client_name(Some(&raw_name)).unwrap_or(raw_name.clone())
            } else {
                raw_name.clone()
            };
            let mut row_value = json!({
                "name": name,
                "requests": row.try_get::<i64, _>("requests").unwrap_or(0),
                "input": input,
                "output": output,
                "cached": cached,
                "total": input + output,
                "errors": row.try_get::<i64, _>("errors").unwrap_or(0),
                "costUsd": row.try_get::<Option<f64>, _>("cost").ok().flatten(),
                "cacheHitRate": if reporting > 0 { round2((cached as f64 / reporting as f64) * 100.0) } else { 0.0 },
                "avgTokensPerSec": round2(row.try_get::<f64, _>("avg_tokens_per_sec").unwrap_or(0.0)),
            });
            if dimension == "key" {
                if let Some(label) = labels.get(&raw_name) {
                    row_value
                        .as_object_mut()
                        .expect("object")
                        .insert("label".into(), json!(label));
                }
            }
            Some(row_value)
        })
        .collect();
    console_response(StatusCode::OK, json!({"rows": data}))
}

/// `GET /console/api/system/readiness`.
pub async fn readiness(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let admin: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM console_users WHERE tenant_id = $1::uuid AND is_active = true)",
    )
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);
    let providers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM providers p
         WHERE p.enabled = true
           AND (p.tenant_id IS NULL OR p.tenant_id = $1::uuid)
           AND (p.requires_account = false OR EXISTS (
             SELECT 1 FROM provider_accounts a WHERE a.provider_id = p.id
           ))",
    )
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    let models: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM models m JOIN providers p ON p.id = m.provider_id
         WHERE m.enabled = true AND p.enabled = true
           AND (p.tenant_id IS NULL OR p.tenant_id = $1::uuid)",
    )
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    let keys: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys
         WHERE tenant_id = $1::uuid AND enabled = true AND revoked_at IS NULL",
    )
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    let requests: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM telemetry_events
         WHERE tenant_id = $1::uuid AND created_at >= now() - interval '24 hours'",
    )
    .bind(&tenant)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    let checks = vec![
        json!({"id": "admin_created", "ok": admin, "detail": if admin { "Administrator account exists" } else { "No administrator account" }}),
        json!({"id": "provider_connected", "ok": providers > 0, "detail": format!("{providers} provider(s) connected")}),
        json!({"id": "model_available", "ok": models > 0, "detail": format!("{models} routable model(s)")}),
        json!({"id": "api_key_issued", "ok": keys > 0, "detail": format!("{keys} active key(s)")}),
        json!({"id": "first_request_seen", "ok": requests > 0, "detail": format!("{requests} request(s) in 24h")}),
    ];
    let ready = admin && providers > 0 && models > 0 && keys > 0;
    console_response(
        StatusCode::OK,
        json!({
            "ready": ready,
            "generatedAt": iso(Utc::now()),
            "checks": checks,
        }),
    )
}

/// `GET /console/api/system/usage/cache?period=`.
pub async fn usage_cache(
    State(state): State<ConsoleState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let period = query.get("period").map(String::as_str).unwrap_or("24h");
    let since = match period_start(period) {
        Ok(since) => since,
        Err(()) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_period", "Invalid period");
        }
    };
    let row: Result<PgRow, sqlx::Error> = sqlx::query(
        "SELECT coalesce(sum(input_tokens), 0)::bigint AS input_tokens,
                coalesce(sum(cached_input_tokens), 0)::bigint AS cached_tokens,
                coalesce(sum(input_tokens) FILTER (WHERE cached_input_tokens IS NOT NULL), 0)::bigint AS reporting
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR created_at >= $2)",
    )
    .bind(&tenant)
    .bind(since)
    .fetch_one(&state.pool)
    .await;
    let row = match row {
        Ok(row) => row,
        Err(error) => return server_error(error),
    };
    let input: i64 = row.get("input_tokens");
    let cached: i64 = row.get("cached_tokens");
    let reporting: i64 = row.get("reporting");
    json_response(
        StatusCode::OK,
        json!({
            "period": period,
            "inputTokens": input,
            "cachedTokens": cached,
            "cacheWriteTokens": 0,
            "hitRate": if reporting > 0 { round2((cached as f64 / reporting as f64) * 100.0) } else { 0.0 },
        }),
    )
}

fn telemetry_event_view(row: &PgRow) -> Value {
    let mut value = json!({
        "id": row.get::<String, _>("id"),
        "createdAt": iso(row.get::<DateTime<Utc>, _>("created_at")),
        "tenantId": row.get::<String, _>("tenant_id"),
        "requestId": row.get::<String, _>("request_id"),
    });
    let object = value.as_object_mut().expect("object");
    for (field, column) in [
        ("sourceSurface", "source_surface"),
        ("requestedModel", "requested_model"),
        ("providerId", "provider_id"),
        ("status", "status"),
    ] {
        if let Ok(Some(text)) = row.try_get::<Option<String>, _>(column) {
            object.insert(field.into(), json!(text));
        }
    }
    for (field, column) in [
        ("latencyMs", "latency_ms"),
        ("inputTokens", "input_tokens"),
        ("outputTokens", "output_tokens"),
    ] {
        if let Ok(Some(number)) = row.try_get::<Option<i32>, _>(column) {
            object.insert(field.into(), json!(number));
        }
    }
    if let Ok(Some(cost)) = row.try_get::<Option<f64>, _>("estimated_cost_usd") {
        object.insert("estimatedCost".into(), json!(cost));
    }
    for (field, column) in [
        ("firstContentDeltaAtMs", "first_content_delta_at_ms"),
        ("lastEventAtMs", "last_event_at_ms"),
    ] {
        if let Ok(Some(number)) = row.try_get::<Option<i64>, _>(column) {
            object.insert(field.into(), json!(number));
        }
    }
    value
}

/// `GET /console/api/telemetry/events?limit=&cursor=`.
pub async fn telemetry_events(
    State(state): State<ConsoleState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 100);
    let rows: Vec<PgRow> = match sqlx::query(
        "SELECT id::text AS id, created_at, tenant_id::text AS tenant_id,
                request_id::text AS request_id, source_surface::text AS source_surface,
                requested_model, provider_id, latency_ms, status::text AS status,
                input_tokens, output_tokens, estimated_cost_usd::float8 AS estimated_cost_usd,
                first_content_delta_at_ms, last_event_at_ms
         FROM telemetry_events WHERE tenant_id = $1::uuid
         ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(&tenant)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => return server_error(error),
    };
    let entries: Vec<Value> = rows.iter().map(telemetry_event_view).collect();
    json_response(StatusCode::OK, json!({"entries": entries}))
}

/// `GET /console/api/telemetry/events/{eventId}`.
pub async fn telemetry_event_detail(
    State(state): State<ConsoleState>,
    Path(event_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let include_payload = query
        .get("includePayload")
        .map(|value| value == "true")
        .unwrap_or(false);
    let row: Result<Option<PgRow>, sqlx::Error> = sqlx::query(
        "SELECT id::text AS id, created_at, tenant_id::text AS tenant_id,
                request_id::text AS request_id, source_surface::text AS source_surface,
                requested_model, provider_id, latency_ms, status::text AS status,
                input_tokens, output_tokens, estimated_cost_usd::float8 AS estimated_cost_usd,
                first_content_delta_at_ms, last_event_at_ms
         FROM telemetry_events WHERE tenant_id = $1::uuid AND id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&event_id)
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some(row)) => {
            let mut value = telemetry_event_view(&row);
            if include_payload {
                value.as_object_mut().expect("object").insert(
                    "payload".into(),
                    json!({"requestBody": Value::Null, "responseBody": Value::Null}),
                );
            }
            json_response(StatusCode::OK, value)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "event_not_found",
            &format!("Event {event_id} not found"),
        ),
        Err(error) => server_error(error),
    }
}

/// `GET /console/api/system/usage?period=` — legacy aggregate view.
pub async fn usage(
    State(state): State<ConsoleState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let period = query.get("period").map(String::as_str).unwrap_or("24h");
    let since = match period_start(period) {
        Ok(since) => since,
        Err(()) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_period", "Invalid period");
        }
    };
    let row: Result<PgRow, sqlx::Error> = sqlx::query(
        "SELECT count(*)::bigint AS total,
                count(*) FILTER (WHERE status = 'completed')::bigint AS succeeded,
                count(*) FILTER (WHERE status = 'failed')::bigint AS failed,
                coalesce(sum(input_tokens + output_tokens), 0)::bigint AS tokens,
                coalesce(sum(estimated_cost_usd), 0)::float8 AS cost
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR created_at >= $2)",
    )
    .bind(&tenant)
    .bind(since)
    .fetch_one(&state.pool)
    .await;
    let row = match row {
        Ok(row) => row,
        Err(error) => return server_error(error),
    };
    let models: Vec<PgRow> = sqlx::query(
        "SELECT requested_model AS model_id, count(*)::bigint AS count
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR created_at >= $2)
           AND requested_model IS NOT NULL
         GROUP BY requested_model ORDER BY count(*) DESC LIMIT 10",
    )
    .bind(&tenant)
    .bind(since)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let providers: Vec<PgRow> = sqlx::query(
        "SELECT provider_id, count(*)::bigint AS count
         FROM telemetry_events
         WHERE tenant_id = $1::uuid AND ($2::timestamptz IS NULL OR created_at >= $2)
           AND provider_id IS NOT NULL
         GROUP BY provider_id ORDER BY count(*) DESC LIMIT 10",
    )
    .bind(&tenant)
    .bind(since)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    json_response(
        StatusCode::OK,
        json!({
            "tenantId": tenant,
            "period": period,
            "requestsTotal": row.get::<i64, _>("total"),
            "requestsSucceeded": row.get::<i64, _>("succeeded"),
            "requestsFailed": row.get::<i64, _>("failed"),
            "tokensUsed": row.get::<i64, _>("tokens"),
            "estimatedCost": row.get::<f64, _>("cost"),
            "topModels": models
                .iter()
                .map(|row| json!({"modelId": row.get::<String, _>("model_id"), "count": row.get::<i64, _>("count")}))
                .collect::<Vec<_>>(),
            "topProviders": providers
                .iter()
                .map(|row| json!({"providerId": row.get::<String, _>("provider_id"), "count": row.get::<i64, _>("count")}))
                .collect::<Vec<_>>(),
        }),
    )
}

/// `GET /console/api/system/performance` — bounded counter snapshot.
pub async fn performance(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let Some(access) = crate::access::resolve_console_access(&state.pool, &headers)
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
    if let Err(error) = crate::access::require_scope(&access, "platform:admin") {
        return error_response(StatusCode::FORBIDDEN, "insufficient_scope", &error.message);
    }
    let process = process_metrics();
    json_response(
        StatusCode::OK,
        json!({
            "adapter_load_ms": {},
            "model_catalog_load_ms": {},
            "network_call_latency_ms": {},
            "memory_bytes": {"process": process.rss},
        }),
    )
}

#[cfg(test)]
mod update_tests {
    use super::version_is_newer;

    #[test]
    fn compares_release_versions_without_floating_point_or_pre_release_suffixes() {
        assert!(version_is_newer("2.4.0", "2.3.0"));
        assert!(version_is_newer("v2.3.1", "2.3.0-keyla.1"));
        assert!(version_is_newer("3.0", "2.9.9"));
        assert!(version_is_newer("2.3.0", "2.3.0-keyla.1"));
        assert!(version_is_newer("2.3.0-keyla.2", "2.3.0-keyla.1"));
        assert!(!version_is_newer("2.2.9", "2.3.0"));
        assert!(!version_is_newer("not-a-version", "2.3.0"));
    }
}
