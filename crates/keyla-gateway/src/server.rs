//! Server bootstrap shared by the `keyla-gateway` binary and the CLI.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::{
    AppState, DrainState, ShutdownReason, StaticAssets, UnavailableDependencies, build_app,
    runtime::{DatabaseReadiness, GatewayRuntime},
};
use anyhow::{Context, Result};
use keyla_config::{
    Env, ProcessEnv, resolve_bind_host, resolve_drain_token, resolve_max_body_bytes, resolve_port,
    resolve_shutdown_drain_window_ms,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Runs the gateway until a drain signal completes.
pub async fn run() -> Result<()> {
    let env = ProcessEnv;
    init_tracing(&env);

    let port = resolve_port(&env).context("invalid PORT")?;
    let host = resolve_bind_host(&env);
    let dashboard_dist = keyla_config::resolve_dashboard_dist(&env);
    let max_body_bytes = resolve_max_body_bytes(&env).context("invalid body limit")?;
    let drain_window = Duration::from_millis(
        resolve_shutdown_drain_window_ms(&env).context("invalid drain window")?,
    );

    let database_configured = [
        "DATABASE_URL",
        "DATABASE_PRIVATE_URL",
        "DATABASE_PUBLIC_URL",
        "PGHOST",
    ]
    .iter()
    .any(|name| env.get(name).is_some_and(|value| !value.trim().is_empty()));

    let mut state = if database_configured {
        let pool = keyla_db::connect_pool(&env)
            .await
            .context("cannot connect to PostgreSQL")?;
        keyla_db::apply_embedded_migrations(&pool)
            .await
            .context("database migrations failed")?;
        keyla_db::seed::seed_bundled_catalog(&pool)
            .await
            .context("bundled catalog seeding failed")?;
        let redis_admission = match env.get("REDIS_URL") {
            Some(url) if !url.trim().is_empty() => {
                match keyla_security::redis_admission::RedisAdmission::connect(url.trim()).await {
                    Ok(admission) => {
                        tracing::info!("Redis admission connected");
                        Some(admission)
                    }
                    Err(error) => {
                        tracing::warn!(
                            "Redis admission unavailable; using in-process limits: {error}"
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        let runtime = Arc::new(
            GatewayRuntime::new(pool.clone(), redis_admission)
                .context("cannot build gateway runtime")?,
        );
        tracing::info!(
            "PostgreSQL runtime ready; {} bundled providers and {} model rows seeded",
            keyla_providers::bundled_provider_ids().len(),
            keyla_db::seed::bundled_model_counts()
                .values()
                .sum::<usize>()
        );
        if env.get("KEYLA_ENCRYPTION_KEY").is_none() {
            tracing::warn!(
                "KEYLA_ENCRYPTION_KEY is unset; provider credentials cannot be decrypted"
            );
        }
        AppState::new(
            StaticAssets::new(&dashboard_dist),
            Arc::new(DatabaseReadiness::new(pool)),
        )
        .with_runtime(runtime)
    } else {
        tracing::warn!("no PostgreSQL configuration found; serving the shell without /v1 routes");
        AppState::new(
            StaticAssets::new(&dashboard_dist),
            Arc::new(UnavailableDependencies),
        )
    }
    .with_max_body_bytes(max_body_bytes);
    if let Some(token) = resolve_drain_token(&env) {
        state = state.with_drain_token(token);
    }
    let drain = Arc::clone(&state.drain);
    let in_flight = Arc::clone(&state.in_flight);
    let app = build_app(state);

    let address = resolve_socket_addr(&host, port)
        .await
        .with_context(|| format!("cannot resolve bind host {host}"))?;
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("cannot bind {address}"))?;

    tracing::info!("Keyla Everywhere listening on {address} (Rust, dashboard {dashboard_dist})");

    spawn_force_exit_watcher(Arc::clone(&drain), drain_window);
    spawn_signal_watcher(Arc::clone(&drain));

    // Drain sequencing: stop admitting new work (readiness turns 503 and the
    // API gate refuses), give in-flight requests the window to finish, then
    // close the listener. The short floor keeps the 503 observable before an
    // idle process closes.
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let drain_watch = Arc::clone(&drain);
    tokio::spawn(async move {
        drain_watch.wait().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        in_flight.wait_idle().await;
        let _ = shutdown_tx.send(true);
    });

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        while !*shutdown_rx.borrow_and_update() {
            if shutdown_rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await
    .context("server failed")?;

    tracing::info!("[shutdown] drain complete");
    Ok(())
}

fn init_tracing(env: &impl Env) {
    let level = env
        .get("LOG_LEVEL")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "info".to_owned());
    let filter = EnvFilter::try_new(format!(
        "keyla={level},keyla_gateway={level},axum=warn,hyper=warn"
    ))
    .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(keyla_console::logs::ConsoleLogLayer)
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();
}

async fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let address = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .with_context(|| format!("{host} resolved to no addresses"))?;
    Ok(address)
}

/// Forced exit after the drain budget. A wedged stream must not keep the old
/// process alive while its replacement is already serving.
fn spawn_force_exit_watcher(drain: Arc<DrainState>, window: Duration) {
    let mut receiver = drain.subscribe();
    tokio::spawn(async move {
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
        tokio::time::sleep(window).await;
        tracing::error!("[shutdown] forced exit after drain budget elapsed");
        std::process::exit(1);
    });
}

/// Signal watcher. SIGUSR2 means an in-place update: the old process drains
/// with the `update` reason so callers know a replacement is seconds away.
fn spawn_signal_watcher(drain: Arc<DrainState>) {
    tokio::spawn(async move {
        let reason = wait_for_signal().await;
        tracing::info!("[shutdown] {} received, draining...", reason.as_str());
        drain.begin(reason);
    });
}

#[cfg(unix)]
async fn wait_for_signal() -> ShutdownReason {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler");
    let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut update = signal(SignalKind::user_defined2()).expect("SIGUSR2 handler");
    tokio::select! {
        _ = interrupt.recv() => ShutdownReason::Sigint,
        _ = terminate.recv() => ShutdownReason::Sigterm,
        _ = update.recv() => ShutdownReason::Update,
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() -> ShutdownReason {
    let _ = tokio::signal::ctrl_c().await;
    ShutdownReason::Sigint
}
