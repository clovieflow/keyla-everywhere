//! HTTP composition root for the gateway shell.
//!
//! Phase 1 surface: `/health`, `/health/ready`, `/metrics`, the operator drain
//! endpoint, and the dashboard static routes. Every response header, status,
//! and body here is part of the frozen wire contract.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use keyla_observability::METRICS;
use serde_json::json;
use std::time::Instant;
use tokio::sync::watch;

use crate::static_assets::{
    API_CONTENT_SECURITY_POLICY, StaticAssets, StaticResult, X_FRAME_OPTIONS,
};

/// Why a drain began. `Update` is delivered by `SIGUSR2` before an in-place
/// image swap, so callers are told the replacement is seconds away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    Sigint,
    Sigterm,
    Update,
}

impl ShutdownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sigint => "SIGINT",
            Self::Sigterm => "SIGTERM",
            Self::Update => "update",
        }
    }

    /// The public termination code a client sees.
    pub fn notice_code(self) -> &'static str {
        match self {
            Self::Update => "restart_for_update",
            Self::Sigint | Self::Sigterm => "shutting_down",
        }
    }
}

/// Drain state shared by the readiness probe, the request gate, and the
/// operator endpoint.
#[derive(Debug)]
pub struct DrainState {
    draining: AtomicBool,
    reason: Mutex<Option<ShutdownReason>>,
    sender: watch::Sender<bool>,
}

impl Default for DrainState {
    fn default() -> Self {
        Self::new()
    }
}

impl DrainState {
    pub fn new() -> Self {
        let (sender, _receiver) = watch::channel(false);
        Self {
            draining: AtomicBool::new(false),
            reason: Mutex::new(None),
            sender,
        }
    }

    /// Begins the drain once. Returns `true` when this call made the
    /// transition.
    pub fn begin(&self, reason: ShutdownReason) -> bool {
        if self.draining.swap(true, Ordering::SeqCst) {
            return false;
        }
        *self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(reason);
        let _ = self.sender.send(true);
        true
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    pub fn reason(&self) -> Option<ShutdownReason> {
        *self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Subscribes to the drain transition for shutdown coordination.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }

    /// Resolves once the drain has begun.
    pub async fn wait(&self) {
        let mut receiver = self.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyStatus {
    Connected,
    Disconnected,
}

impl DependencyStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    Applied,
    Pending,
}

impl MigrationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Pending => "pending",
        }
    }
}

/// One readiness observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readiness {
    pub db: DependencyStatus,
    pub redis: DependencyStatus,
    /// `None` when the composition has no migration state to report, in which
    /// case the field is omitted from the response exactly like the original.
    pub migrations: Option<MigrationStatus>,
}

pub type ReadinessFuture<'a> = Pin<Box<dyn Future<Output = Readiness> + Send + 'a>>;

/// The dependency probe behind `/health/ready`.
pub trait ReadinessProbe: Send + Sync {
    fn check(&self) -> ReadinessFuture<'_>;
}

/// The Phase 1 composition: no database or Redis is wired, so both report
/// disconnected and the gateway is not ready. A real probe replaces this in
/// Phase 2 without changing the route contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableDependencies;

impl ReadinessProbe for UnavailableDependencies {
    fn check(&self) -> ReadinessFuture<'_> {
        Box::pin(async {
            Readiness {
                db: DependencyStatus::Disconnected,
                redis: DependencyStatus::Disconnected,
                migrations: None,
            }
        })
    }
}

/// Tracks requests that are still being served, so the drain can close the
/// listener only after they finish rather than cutting them off.
#[derive(Debug)]
pub struct InFlight {
    count: AtomicUsize,
    sender: watch::Sender<usize>,
}

impl Default for InFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl InFlight {
    pub fn new() -> Self {
        let (sender, _receiver) = watch::channel(0);
        Self {
            count: AtomicUsize::new(0),
            sender,
        }
    }

    fn begin(self: &Arc<Self>) -> InFlightGuard {
        let count = self.count.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.sender.send(count);
        InFlightGuard {
            inner: Arc::clone(self),
        }
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Resolves once no tracked request is in flight.
    pub async fn wait_idle(&self) {
        let mut receiver = self.sender.subscribe();
        while *receiver.borrow_and_update() != 0 {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

struct InFlightGuard {
    inner: Arc<InFlight>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let count = self.inner.count.fetch_sub(1, Ordering::AcqRel) - 1;
        let _ = self.inner.sender.send(count);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub runtime: Option<Arc<crate::runtime::GatewayRuntime>>,
    pub drain: Arc<DrainState>,
    pub in_flight: Arc<InFlight>,
    pub assets: Arc<StaticAssets>,
    pub readiness: Arc<dyn ReadinessProbe>,
    pub drain_token: Option<Arc<str>>,
    pub max_body_bytes: usize,
    pub ip_abuse: Arc<crate::ip_abuse::IpAbuse>,
    pub model_abuse: Arc<crate::model_abuse::ModelAbuse>,
}

impl AppState {
    pub fn new(assets: StaticAssets, readiness: Arc<dyn ReadinessProbe>) -> Self {
        Self {
            runtime: None,
            drain: Arc::new(DrainState::new()),
            in_flight: Arc::new(InFlight::new()),
            assets: Arc::new(assets),
            readiness,
            drain_token: None,
            max_body_bytes: 8 * 1024 * 1024,
            ip_abuse: Arc::new(crate::ip_abuse::IpAbuse::from_env()),
            model_abuse: crate::model_abuse::global(),
        }
    }

    pub fn with_drain_token(mut self, token: impl Into<Arc<str>>) -> Self {
        self.drain_token = Some(token.into());
        self
    }

    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }

    pub fn with_runtime(mut self, runtime: Arc<crate::runtime::GatewayRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }
}

/// Builds the route table. Registration order is part of the contract: the
/// static catch-all is last, and the reserved API namespaces never fall
/// through to it.
pub fn build_app(state: AppState) -> Router {
    let max_body_bytes = state.max_body_bytes;
    let drain_enabled = state.drain_token.is_some();
    let runtime_enabled = state.runtime.is_some();
    let console_pool = state.runtime.as_ref().map(|runtime| runtime.pool.clone());
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .fallback(fallback);
    if runtime_enabled {
        router = router
            .route("/v1/chat/completions", post(crate::v1::chat_completions))
            .route("/v1/completions", post(crate::v1::completions))
            .route("/v1/messages", post(crate::v1::messages))
            .route("/v1/responses", post(crate::v1::responses))
            .route("/v1/models", get(crate::v1::list_models))
            .route("/v1/search", post(crate::v1::search));
    }
    if drain_enabled {
        router = router.route("/admin/drain", post(drain));
    }
    let mut app = router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            track_in_flight,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_ip_abuse,
        ))
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body_bytes));
    if let Some(pool) = console_pool {
        app = app
            .merge(keyla_console::console_router(pool.clone()))
            .merge(keyla_console::public_share::public_share_router(pool));
    }
    app.layer(axum::middleware::from_fn(log_gateway_requests))
}

/// Logs every data-plane HTTP request into the console ring. It sits outside
/// the proxy so authentication failures and malformed bodies are visible too;
/// those are precisely the failures an operator opens the log page to find.
async fn log_gateway_requests(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if !path.starts_with("/v1/") {
        return next.run(request).await;
    }
    let method = request.method().as_str().to_owned();
    let request_id = uuid::Uuid::new_v4().to_string();
    let user_agent = request
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(address)| address.ip().to_string())
        });
    keyla_console::logs::record_line(json!({
        "level": "info",
        "event": "request_start",
        "requestId": request_id,
        "method": method,
        "endpoint": path,
        "clientIp": client_ip,
        "userAgent": user_agent,
        "msg": format!("{method} {path}"),
    }));
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let level = if status >= 500 {
        "error"
    } else if status >= 400 {
        "warn"
    } else {
        "info"
    };
    keyla_console::logs::record_line(json!({
        "level": level,
        "event": "request_complete",
        "requestId": request_id,
        "method": method,
        "endpoint": path,
        "clientIp": client_ip,
        "userAgent": user_agent,
        "status": status,
        "durationMs": started.elapsed().as_millis().min(u32::MAX as u128) as u64,
        "msg": format!("{method} {path} {status}"),
    }));
    response
}

/// Applies the per-IP window/ban only to `/v1/*`; console auth has its own
/// database-backed lockout with a lower threshold.
async fn enforce_ip_abuse(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if !path.starts_with("/v1/") {
        return next.run(request).await;
    }
    // The serving listener always inserts ConnectInfo. In-process callers
    // (tests, embedded compositions) may not, so they share the loopback
    // identity instead of failing every /v1 request.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let boundary = keyla_config::resolve_trusted_proxy_boundary(&keyla_config::ProcessEnv);
    let identity = crate::ip_abuse::client_identity(peer, request.headers(), &boundary);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    if state.model_abuse.is_banned(&identity.to_string(), now) {
        return error_response(
            StatusCode::FORBIDDEN,
            "model_abuse_banned",
            "This address is temporarily blocked for repeated invalid-model requests",
        );
    }
    let mut request = request;
    request
        .extensions_mut()
        .insert(crate::model_abuse::ClientIdentity(identity));
    if let Err(error) = state.ip_abuse.check(&identity.to_string(), &path, now) {
        let retry = error
            .details
            .get("retryAfterMs")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);
        let mut response = error_response(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
            error.code.as_str(),
            &error.message,
        );
        if retry > 0 {
            let seconds = ((retry + 999) / 1000).max(1);
            if let Ok(value) = axum::http::HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert("retry-after", value);
            }
        }
        return response;
    }
    next.run(request).await
}

/// Counts work that a drain must not interrupt. Health, readiness, and metrics
/// probes are excluded: they are the surface an orchestrator polls while
/// draining and must never hold the process open.
async fn track_in_flight(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if matches!(path, "/health" | "/health/ready" | "/metrics") {
        return next.run(request).await;
    }
    let _guard = state.in_flight.begin();
    next.run(request).await
}

async fn health() -> Response {
    json_response(StatusCode::OK, json!({ "status": "ok" }))
}

async fn ready(State(state): State<AppState>) -> Response {
    if state.drain.is_draining() {
        let code = state
            .drain
            .reason()
            .map(ShutdownReason::notice_code)
            .unwrap_or("shutting_down");
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "status": "not_ready", "reason": code }),
        );
    }

    let readiness = state.readiness.check().await;
    let db_ok = readiness.db == DependencyStatus::Connected;
    let redis_ok = readiness.redis == DependencyStatus::Connected;
    let migrations_ok = readiness.migrations != Some(MigrationStatus::Pending);

    if db_ok && redis_ok && migrations_ok {
        return json_response(
            StatusCode::OK,
            json!({
                "status": "ready",
                "db": readiness.db.as_str(),
                "redis": readiness.redis.as_str(),
                "migrations": readiness.migrations.map(MigrationStatus::as_str),
            }),
        );
    }

    let mut body = json!({
        "status": "not_ready",
        "db": readiness.db.as_str(),
        "redis": readiness.redis.as_str(),
    });
    if let Some(migrations) = readiness.migrations {
        body["migrations"] = json!(migrations.as_str());
    }
    body["reason"] = json!(if migrations_ok {
        "dependency not ready"
    } else {
        "database migrations pending"
    });
    json_response(StatusCode::SERVICE_UNAVAILABLE, body)
}

async fn metrics() -> Response {
    // The in-process memory coordination backend is always up; a real Redis
    // client reports its own readiness once the composition wires one.
    METRICS.keyla_redis_up.set(1.0, &[]);
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    (StatusCode::OK, headers, METRICS.render()).into_response()
}

/// The operator drain endpoint: loopback peer + constant-time token match.
/// The route exists only when `KEYLA_DRAIN_TOKEN` is set.
async fn drain(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(expected) = state.drain_token.as_deref() else {
        return error_response(StatusCode::NOT_FOUND, "not_found", "Route not found");
    };

    if !is_loopback(peer.ip()) {
        return error_response(
            StatusCode::FORBIDDEN,
            "invalid_request",
            "drain is only available from loopback",
        );
    }

    let provided = headers
        .get("x-drain-token")
        .and_then(|value| value.to_str().ok());
    if !tokens_match(provided, expected) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_request",
            "invalid drain token",
        );
    }

    // Acknowledge before draining: the response must be on the wire before the
    // shutdown path starts closing sockets.
    let drain = Arc::clone(&state.drain);
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        drain.begin(ShutdownReason::Sigterm);
    });

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    (
        StatusCode::ACCEPTED,
        headers,
        Body::from(r#"{"status":"draining"}"#),
    )
        .into_response()
}

/// Root catch-all. Non-document namespaces (`/v1`, `/health`, `/metrics`)
/// keep their JSON 404 so an unknown API path can never be answered with the
/// SPA document; everything else resolves through the static handler.
async fn fallback(State(state): State<AppState>, request: Request) -> Response {
    let pathname = request.uri().path();
    // A draining process refuses new work on the API namespaces so callers
    // retry against the replacement instead of starting a doomed request. The
    // reason distinguishes a stop from an in-place update.
    if state.drain.is_draining()
        && (pathname.starts_with("/v1/") || pathname.starts_with("/console/api/"))
    {
        let reason = state.drain.reason();
        let (code, message) = match reason {
            Some(ShutdownReason::Update) => {
                ("restart_for_update", "system will be back in a minute")
            }
            _ => ("shutting_down", "Service is shutting down"),
        };
        return error_response(StatusCode::SERVICE_UNAVAILABLE, code, message);
    }
    let reserved = ["/v1", "/health", "/metrics"]
        .iter()
        .any(|prefix| pathname == *prefix || pathname.starts_with(&format!("{prefix}/")));
    if reserved {
        let mut response = error_response(StatusCode::NOT_FOUND, "not_found", "Route not found");
        let headers = response.headers_mut();
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(API_CONTENT_SECURITY_POLICY),
        );
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static(X_FRAME_OPTIONS),
        );
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        return response;
    }
    into_response(state.assets.serve(pathname).await)
}

fn into_response(result: StaticResult) -> Response {
    let mut headers = HeaderMap::new();
    for (name, value) in result.headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static(name), value);
        }
    }
    let status = StatusCode::from_u16(result.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = result.body.map(Body::from).unwrap_or_else(Body::empty);
    (status, headers, body).into_response()
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (status, headers, body.to_string()).into_response()
}

/// The public error envelope: `{"error":{origin,code,message,details}}`.
pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let explanatory = if message == code || message.starts_with(&format!("{code}:")) {
        message.to_owned()
    } else if message.is_empty() {
        code.to_owned()
    } else {
        format!("{code}: {message}")
    };
    json_response(
        status,
        json!({
            "error": {
                "origin": "keyla",
                "code": code,
                "message": explanatory,
                "details": {},
            }
        }),
    )
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(|mapped| mapped.is_loopback())
            .unwrap_or_else(|| address.is_loopback()),
    }
}

/// Constant-time token comparison; length mismatch short-circuits safely.
fn tokens_match(provided: Option<&str>, expected: &str) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    if provided.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in provided.iter().zip(expected.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_transition_is_idempotent() {
        let drain = DrainState::new();
        assert!(drain.begin(ShutdownReason::Update));
        assert!(!drain.begin(ShutdownReason::Sigterm));
        assert!(drain.is_draining());
        assert_eq!(drain.reason(), Some(ShutdownReason::Update));
        assert_eq!(drain.reason().unwrap().notice_code(), "restart_for_update");
    }

    #[test]
    fn loopback_covers_ipv4_mapped_ipv6() {
        assert!(is_loopback(IpAddr::from([127, 0, 0, 1])));
        assert!(is_loopback("::1".parse().unwrap()));
        assert!(is_loopback("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_loopback(IpAddr::from([192, 0, 2, 1])));
    }

    #[test]
    fn token_compare_requires_an_exact_match() {
        assert!(tokens_match(Some("secret"), "secret"));
        assert!(!tokens_match(Some("secreT"), "secret"));
        assert!(!tokens_match(Some("secret "), "secret"));
        assert!(!tokens_match(None, "secret"));
    }
}
