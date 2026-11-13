//! HTTP contract tests for the Phase 1 shell.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use keyla_gateway::{
    AppState, DependencyStatus, MigrationStatus, Readiness, ReadinessFuture, ReadinessProbe,
    StaticAssets, UnavailableDependencies, build_app,
};
use serde_json::Value;
use tower::util::ServiceExt;

const INDEX: &str = r#"<!doctype html><html><head><meta name="description" content="landing" /><title>Keyla</title><!-- keyla:social-meta:start --><!-- keyla:social-meta:end --></head><body><script>window.__theme='dark'</script></body></html>"#;

struct Fixture {
    _dir: tempfile::TempDir,
    app: Router,
    drain: Arc<keyla_gateway::DrainState>,
}

fn fixture(readiness: Arc<dyn ReadinessProbe>, drain_token: Option<&str>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), INDEX).unwrap();
    std::fs::create_dir_all(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("assets/app.abc123def.js"), "console.log(1)").unwrap();

    let mut state = AppState::new(StaticAssets::new(dir.path()), readiness);
    if let Some(token) = drain_token {
        state = state.with_drain_token(token);
    }
    let drain = Arc::clone(&state.drain);
    Fixture {
        _dir: dir,
        app: build_app(state),
        drain,
    }
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn loopback() -> String {
    SocketAddr::from(([127, 0, 0, 1], 49_152)).to_string()
}

#[tokio::test]
async fn health_is_ok() {
    let fixture = fixture(Arc::new(UnavailableDependencies), None);
    let (status, headers, body) = call(&fixture.app, get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    assert_eq!(body, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn readiness_reports_each_dependency() {
    let fixture = fixture(Arc::new(UnavailableDependencies), None);
    let (status, _, body) = call(&fixture.app, get("/health/ready")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        r#"{"status":"not_ready","db":"disconnected","redis":"disconnected","reason":"dependency not ready"}"#
    );
}

struct ReadyProbe;

impl ReadinessProbe for ReadyProbe {
    fn check(&self) -> ReadinessFuture<'_> {
        Box::pin(async {
            Readiness {
                db: DependencyStatus::Connected,
                redis: DependencyStatus::Connected,
                migrations: Some(MigrationStatus::Applied),
            }
        })
    }
}

struct PendingMigrations;

impl ReadinessProbe for PendingMigrations {
    fn check(&self) -> ReadinessFuture<'_> {
        Box::pin(async {
            Readiness {
                db: DependencyStatus::Connected,
                redis: DependencyStatus::Connected,
                migrations: Some(MigrationStatus::Pending),
            }
        })
    }
}

#[tokio::test]
async fn ready_probe_reports_ready_without_extra_fields() {
    let fixture = fixture(Arc::new(ReadyProbe), None);
    let (status, _, body) = call(&fixture.app, get("/health/ready")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"ready","db":"connected"}"#);
}

#[tokio::test]
async fn pending_migrations_block_readiness() {
    let fixture = fixture(Arc::new(PendingMigrations), None);
    let (status, _, body) = call(&fixture.app, get("/health/ready")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains(r#""migrations":"pending""#));
    assert!(body.contains(r#""reason":"database migrations pending""#));
}

#[tokio::test]
async fn metrics_use_the_prometheus_content_type() {
    let fixture = fixture(Arc::new(UnavailableDependencies), None);
    let (status, headers, body) = call(&fixture.app, get("/metrics")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/plain; version=0.0.4"
    );
    assert!(body.contains("# TYPE proxy_requests_total counter"));
    assert!(body.contains("keyla_redis_up 1"));
}

#[tokio::test]
async fn dashboard_documents_assets_and_reserved_namespaces() {
    let fixture = fixture(Arc::new(UnavailableDependencies), None);

    let (status, headers, body) = call(&fixture.app, get("/console/settings")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        headers.get("cache-control").unwrap(),
        "no-store, no-cache, must-revalidate"
    );
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("'sha256-"));
    assert!(body.contains("window.__theme"));

    let (status, headers, _) = call(&fixture.app, get("/console/assets/app.abc123def.js")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("content-type").unwrap(),
        "application/javascript; charset=utf-8"
    );
    assert_eq!(
        headers.get("cache-control").unwrap(),
        "public, max-age=31536000, immutable"
    );

    let (status, headers, _) = call(&fixture.app, get("/console/api/keys")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers.get("content-type").unwrap(), "application/json");

    let (status, headers, body) = call(&fixture.app, get("/v1/unknown")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    assert!(body.contains(r#""code":"not_found""#));
}

#[tokio::test]
async fn share_routes_swap_the_social_card() {
    let fixture = fixture(Arc::new(UnavailableDependencies), None);
    let (status, _, body) = call(&fixture.app, get("/share/token-123")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("og:title"));
    assert!(body.contains("Akses bersama"));
    assert!(!body.contains("content=\"landing\""));
}

#[tokio::test]
async fn drain_requires_loopback_and_an_exact_token() {
    let fixture = fixture(Arc::new(UnavailableDependencies), Some("drain-secret"));

    let mut request = Request::builder()
        .method("POST")
        .uri("/admin/drain")
        .header("x-drain-token", "wrong")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 49_152))));
    let (status, _, body) = call(&fixture.app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains(r#""code":"invalid_request""#));
    assert!(!fixture.drain.is_draining());

    let mut request = Request::builder()
        .method("POST")
        .uri("/admin/drain")
        .header("x-drain-token", "drain-secret")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 49_152))));
    let (status, _, _) = call(&fixture.app, request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!fixture.drain.is_draining());

    let mut request = Request::builder()
        .method("POST")
        .uri("/admin/drain")
        .header("x-drain-token", "drain-secret")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 49_152))));
    let (status, headers, body) = call(&fixture.app, request).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    assert_eq!(body, r#"{"status":"draining"}"#);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(fixture.drain.is_draining());

    let (status, _, body) = call(&fixture.app, get("/health/ready")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, r#"{"status":"not_ready","reason":"shutting_down"}"#);

    let (status, _, body) = call(&fixture.app, get("/v1/chat/completions")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains(r#""code":"shutting_down""#));

    let (status, _, _) = call(&fixture.app, get("/health")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn drain_route_does_not_exist_without_a_token() {
    let fixture = fixture(Arc::new(UnavailableDependencies), None);
    let mut request = Request::builder()
        .method("POST")
        .uri("/admin/drain")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(loopback().parse::<SocketAddr>().unwrap()));
    let (status, _, _) = call(&fixture.app, request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn data_plane_requests_reach_the_console_log_ring() {
    let fixture = fixture(Arc::new(UnavailableDependencies), None);
    let request = Request::builder()
        .method("GET")
        .uri("/v1/models")
        .header("user-agent", "openai-node/4.77.0")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = call(&fixture.app, request).await;
    // No runtime in this fixture, so the route falls through to the JSON 404.
    // The log layer still has to record both lifecycle lines.
    assert_eq!(status, StatusCode::NOT_FOUND);

    let lines: Vec<Value> = keyla_console::logs::snapshot()
        .into_iter()
        .filter(|line| line.get("endpoint").and_then(Value::as_str) == Some("/v1/models"))
        .collect();
    let start = lines
        .iter()
        .find(|line| line.get("event").and_then(Value::as_str) == Some("request_start"))
        .expect("request_start log line");
    assert_eq!(start.get("method").and_then(Value::as_str), Some("GET"));
    assert_eq!(
        start.get("userAgent").and_then(Value::as_str),
        Some("openai-node/4.77.0")
    );
    assert!(start.get("requestId").and_then(Value::as_str).is_some());

    let complete = lines
        .iter()
        .find(|line| line.get("event").and_then(Value::as_str) == Some("request_complete"))
        .expect("request_complete log line");
    assert_eq!(complete.get("status").and_then(Value::as_u64), Some(404));
    assert_eq!(
        complete.get("requestId"),
        start.get("requestId"),
        "start and completion share one request id"
    );
}
