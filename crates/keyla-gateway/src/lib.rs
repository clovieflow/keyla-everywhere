//! Gateway shell library: HTTP composition and static asset serving.

pub mod app;
pub mod ip_abuse;
pub mod model_abuse;
pub mod runtime;
pub mod server;
pub mod static_assets;
pub mod v1;

pub use app::{
    AppState, DependencyStatus, DrainState, InFlight, MigrationStatus, Readiness, ReadinessFuture,
    ReadinessProbe, ShutdownReason, UnavailableDependencies, build_app,
};
pub use runtime::GatewayRuntime;
pub use static_assets::StaticAssets;
