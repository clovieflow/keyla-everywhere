//! Environment contract and path resolution.
//!
//! This is a direct port of `src/config.ts` and `src/persistence/db-mode.ts`.
//! `CONFIG_SPEC` stays the single declaration of every variable this module
//! owns; resolvers are thin readers over it, so a new knob cannot be added
//! without declaring it here.
//!
//! Persisted names are frozen: the current `KEYLA_*` spelling wins, and the
//! pre-rename `CARTETHYIA_*` spelling is honoured when the current one is
//! absent. Renaming these breaks every existing installation's `.env`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use thiserror::Error;

/// A 256-bit credential-encryption key.
pub const ENCRYPTION_KEY_LENGTH: usize = 32;
/// `Number.MAX_SAFE_INTEGER`, the upper bound the TypeScript spec permits.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

const CURRENT_PREFIX: &str = "KEYLA_";
// Assembled, not literal: a codebase-wide rename once rewrote this constant
// into the current prefix, which silently made every fallback lookup an
// identity mapping.
const LEGACY_PREFIX: &str = "CARTETHYIA_";

const DEFAULT_DASHBOARD_DIST: &str = "./dist/dashboard";
const DEFAULT_KIMI_OAUTH_HOST: &str = "https://auth.kimi.com";
const DEFAULT_KIMI_QUOTA_BASE_URL: &str = "https://api.kimi.com/coding/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{name} must be an integer between {min} and {max}")]
    InvalidInt { name: String, min: i64, max: i64 },
    #[error("{0}")]
    Required(String),
    #[error(
        "KEYLA_ENCRYPTION_KEY must decode to exactly {expected} bytes (got {actual}); \
         provide a base64 or hex encoded 256-bit key"
    )]
    EncryptionKeyLength { expected: usize, actual: usize },
    #[error("KEYLA_ENCRYPTION_KEY is not valid base64 or hexadecimal")]
    EncryptionKeyEncoding,
}

// ─── Environment source ─────────────────────────────────────────────────────

/// Read-only view of the process environment.
///
/// Tests construct [`MapEnv`]; production uses [`ProcessEnv`]. Resolvers read
/// through this trait so every lookup — including the legacy fallback — is
/// exercised without touching real process state.
pub trait Env {
    fn get(&self, name: &str) -> Option<String>;
}

/// The real process environment.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// A fixed environment, for tests and for callers that build one from a file.
#[derive(Debug, Default, Clone)]
pub struct MapEnv {
    values: BTreeMap<String, String>,
}

impl MapEnv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.values.insert(name.into(), value.into());
        self
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut env = Self::new();
        for (key, value) in pairs {
            env = env.set(key, value);
        }
        env
    }
}

impl Env for MapEnv {
    fn get(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }
}

// ─── Config spec ────────────────────────────────────────────────────────────

/// How one environment variable is read and bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigEntry {
    Int {
        default: i64,
        min: i64,
        max: i64,
    },
    Text {
        default: &'static str,
    },
    /// Absent, empty, or whitespace means "no value".
    OptionalText,
    /// Absent or empty means "unset"; consumers apply their own fallback.
    OptionalInt {
        min: i64,
        max: i64,
    },
    Required {
        error: &'static str,
    },
    /// Enabled unless the literal `"false"` is set.
    Flag,
    /// Comma-separated; empty entries are dropped.
    List,
}

/// One declared variable.
#[derive(Debug, Clone, Copy)]
pub struct SpecEntry {
    pub name: &'static str,
    pub entry: ConfigEntry,
}

const fn int(name: &'static str, default: i64, min: i64, max: i64) -> SpecEntry {
    SpecEntry {
        name,
        entry: ConfigEntry::Int { default, min, max },
    }
}

const fn text(name: &'static str, default: &'static str) -> SpecEntry {
    SpecEntry {
        name,
        entry: ConfigEntry::Text { default },
    }
}

const fn optional_text(name: &'static str) -> SpecEntry {
    SpecEntry {
        name,
        entry: ConfigEntry::OptionalText,
    }
}

const fn optional_int(name: &'static str, min: i64, max: i64) -> SpecEntry {
    SpecEntry {
        name,
        entry: ConfigEntry::OptionalInt { min, max },
    }
}

const fn required(name: &'static str, error: &'static str) -> SpecEntry {
    SpecEntry {
        name,
        entry: ConfigEntry::Required { error },
    }
}

const fn flag(name: &'static str) -> SpecEntry {
    SpecEntry {
        name,
        entry: ConfigEntry::Flag,
    }
}

const fn list(name: &'static str) -> SpecEntry {
    SpecEntry {
        name,
        entry: ConfigEntry::List,
    }
}

/// The canonical declaration of every variable this module owns.
pub const CONFIG_SPEC: &[SpecEntry] = &[
    // HTTP listener + dashboard runtime
    int("PORT", 12_800, 1, 65_535),
    text("KEYLA_BIND_HOST", "127.0.0.1"),
    text("DASHBOARD_DIST", DEFAULT_DASHBOARD_DIST),
    optional_text("KEYLA_API_KEY"),
    int(
        "KEYLA_SERVER_MAX_BODY_BYTES",
        8 * 1024 * 1024,
        1024,
        MAX_SAFE_INTEGER,
    ),
    int("KEYLA_SERVER_IDLE_TIMEOUT", 60, 0, 86_400),
    // Graceful-shutdown drain: how long in-flight requests may finish
    // naturally before the drain aborts the stragglers.
    int("KEYLA_SHUTDOWN_DRAIN_WINDOW_MS", 20_000, 0, 600_000),
    // Optional secret for the operator drain endpoint. Unset = the route does
    // not exist.
    optional_text("KEYLA_DRAIN_TOKEN"),
    // Network policy (trusted proxy + SSRF)
    list("TRUSTED_PROXY_CIDRS"),
    flag("KEYLA_ALLOW_PRIVATE_UPSTREAMS"),
    list("KEYLA_ALLOWED_NETWORKS"),
    optional_int("KEYLA_MAX_REDIRECTS", 0, 10),
    // Runtime memory
    optional_int("KEYLA_MEMORY_LIMIT_BYTES", 1, MAX_SAFE_INTEGER),
    // Durable, metadata-only request telemetry retention
    int("KEYLA_TELEMETRY_RETENTION_DAYS", 30, 3, 365),
    int(
        "KEYLA_TELEMETRY_PAYLOAD_MAX_BYTES",
        32 * 1024 * 1024,
        1024 * 1024,
        256 * 1024 * 1024,
    ),
    // Upstream request timeout + retry backoff
    int("KEYLA_UPSTREAM_TIMEOUT_MS", 120_000, 5_000, 600_000),
    int("KEYLA_STREAM_STALL_TIMEOUT_MS", 360_000, 60_000, 600_000),
    int(
        "KEYLA_STREAM_FIRST_CHUNK_TIMEOUT_MS",
        200_000,
        30_000,
        300_000,
    ),
    int("KEYLA_FALLBACK_RETRY_BASE_MS", 100, 0, 60_000),
    int("KEYLA_FALLBACK_RETRY_CAP_MS", 2_000, 0, 300_000),
    int("KEYLA_ROUTE_MAX_ATTEMPTS", 8, 1, 64),
    // Account/pool health cooldown delays (fallbacks when the upstream states
    // no explicit reset window).
    int(
        "KEYLA_ACCOUNT_RATE_LIMIT_COOLDOWN_MS",
        900_000,
        0,
        86_400_000,
    ),
    int("KEYLA_ACCOUNT_QUOTA_COOLDOWN_MS", 3_600_000, 0, 86_400_000),
    int(
        "KEYLA_ACCOUNT_MODEL_CAPACITY_COOLDOWN_MS",
        120_000,
        0,
        86_400_000,
    ),
    int("KEYLA_ACCOUNT_TRANSIENT_COOLDOWN_MS", 30_000, 0, 86_400_000),
    int(
        "KEYLA_ACCOUNT_UNCLASSIFIED_COOLDOWN_MS",
        60_000,
        0,
        86_400_000,
    ),
    int("KEYLA_POOL_COOLDOWN_MS", 120_000, 0, 86_400_000),
    // Proxy pool agents
    int("KEYLA_PROXY_MAX_SOCKETS", 100, 1, 100_000),
    int("KEYLA_PROXY_MAX_FREE_SOCKETS", 20, 0, 100_000),
    // Security (encryption key, public origin, abuse ceiling)
    int("IP_RATE_MAX_PER_WINDOW", 240, 1, MAX_SAFE_INTEGER),
    // Graduated model-abuse strikes. The default threshold is above any
    // reachable count, so no ban is ever recorded unless an operator opts in.
    int("KEYLA_MODEL_STRIKE_THRESHOLD", 1_000_000, 1, 1_000_000),
    int("KEYLA_MODEL_STRIKE_WINDOW_MS", 300_000, 1_000, 86_400_000),
    int("KEYLA_MODEL_BAN_TTL_MS", 3_600_000, 1_000, 604_800_000),
    // Pins the OpenCode client version sent as `user-agent`; empty follows the
    // npm registry's latest.
    optional_text("KEYLA_OPENCODE_VERSION"),
    required(
        "KEYLA_ENCRYPTION_KEY",
        "KEYLA_ENCRYPTION_KEY is required to encrypt credentials and hash API keys",
    ),
    required(
        "KEYLA_PUBLIC_ORIGIN",
        "KEYLA_PUBLIC_ORIGIN is required to build OAuth redirect URIs (e.g. https://keyla.example.com)",
    ),
    // Provider OAuth hosts
    text("KEYLA_KIMI_OAUTH_HOST", DEFAULT_KIMI_OAUTH_HOST),
    text("KEYLA_KIMI_QUOTA_BASE_URL", DEFAULT_KIMI_QUOTA_BASE_URL),
    text("KEYLA_GITHUB_ENTERPRISE_DOMAIN", ""),
];

/// Looks up a declared variable by name.
pub fn spec(name: &str) -> Option<&'static ConfigEntry> {
    CONFIG_SPEC
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| &entry.entry)
}

fn declared(name: &str) -> &'static ConfigEntry {
    spec(name).unwrap_or_else(|| panic!("config: {name} is not declared in CONFIG_SPEC"))
}

// ─── Readers ────────────────────────────────────────────────────────────────

/// The pre-rename name of a variable, when one exists.
pub fn legacy_name(name: &str) -> Option<String> {
    name.strip_prefix(CURRENT_PREFIX)
        .map(|suffix| format!("{LEGACY_PREFIX}{suffix}"))
}

/// Reads `name`, falling back to its pre-rename spelling.
pub fn env_value(env: &dyn Env, name: &str) -> Option<String> {
    if let Some(current) = env.get(name) {
        return Some(current);
    }
    legacy_name(name).and_then(|legacy| env.get(&legacy))
}

/// Parses the subset of JavaScript `Number()` this contract accepts: decimal
/// integers and integer-valued scientific notation.
fn parse_integer(raw: &str) -> Option<f64> {
    let value: f64 = raw.trim().parse().ok()?;
    if value.is_finite() && value.fract() == 0.0 {
        Some(value)
    } else {
        None
    }
}

fn read_int(
    env: &dyn Env,
    name: &str,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, ConfigError> {
    let Some(raw) = env_value(env, name) else {
        return Ok(default);
    };
    if raw.trim().is_empty() {
        return Ok(default);
    }
    parse_integer(&raw)
        .filter(|value| *value >= min as f64 && *value <= max as f64)
        .map(|value| value as i64)
        .ok_or_else(|| ConfigError::InvalidInt {
            name: name.to_owned(),
            min,
            max,
        })
}

fn read_text(env: &dyn Env, name: &str, default: &str) -> String {
    match env_value(env, name) {
        Some(raw) if !raw.trim().is_empty() => raw.trim().to_owned(),
        _ => default.to_owned(),
    }
}

fn read_optional_text(env: &dyn Env, name: &str) -> Option<String> {
    env_value(env, name)
        .map(|raw| raw.trim().to_owned())
        .filter(|raw| !raw.is_empty())
}

fn read_optional_int(
    env: &dyn Env,
    name: &str,
    min: i64,
    max: i64,
) -> Result<Option<i64>, ConfigError> {
    let Some(raw) = env_value(env, name) else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    parse_integer(&raw)
        .filter(|value| *value >= min as f64 && *value <= max as f64)
        .map(|value| Some(value as i64))
        .ok_or_else(|| ConfigError::InvalidInt {
            name: name.to_owned(),
            min,
            max,
        })
}

fn read_required(env: &dyn Env, name: &str, error: &str) -> Result<String, ConfigError> {
    match env_value(env, name) {
        Some(raw) if !raw.is_empty() => Ok(raw),
        _ => Err(ConfigError::Required(error.to_owned())),
    }
}

fn read_flag(env: &dyn Env, name: &str) -> bool {
    match env_value(env, name) {
        None => true,
        Some(raw) => raw != "false",
    }
}

fn read_list(env: &dyn Env, name: &str) -> Option<Vec<String>> {
    let entries: Vec<String> = env_value(env, name)?
        .split(',')
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect();
    (!entries.is_empty()).then_some(entries)
}

// ─── HTTP listener + dashboard runtime ──────────────────────────────────────

pub fn resolve_port(env: &dyn Env) -> Result<u16, ConfigError> {
    let entry = declared("PORT");
    let ConfigEntry::Int { default, min, max } = entry else {
        unreachable!("PORT is declared as int");
    };
    Ok(read_int(env, "PORT", *default, *min, *max)? as u16)
}

/// Private-first listener; container/reverse-proxy exposure is explicit.
pub fn resolve_bind_host(env: &dyn Env) -> String {
    read_text(env, "KEYLA_BIND_HOST", "127.0.0.1")
}

pub fn resolve_dashboard_dist(env: &dyn Env) -> String {
    read_text(env, "DASHBOARD_DIST", DEFAULT_DASHBOARD_DIST)
}

/// The configured default gateway API key, if one is set.
pub fn resolve_default_gateway_api_key(env: &dyn Env) -> Option<String> {
    read_optional_text(env, "KEYLA_API_KEY")
}

pub fn resolve_max_body_bytes(env: &dyn Env) -> Result<usize, ConfigError> {
    let entry = declared("KEYLA_SERVER_MAX_BODY_BYTES");
    let ConfigEntry::Int { default, min, max } = entry else {
        unreachable!("KEYLA_SERVER_MAX_BODY_BYTES is declared as int");
    };
    Ok(read_int(env, "KEYLA_SERVER_MAX_BODY_BYTES", *default, *min, *max)? as usize)
}

/// Listener idle-socket timeout in seconds.
pub fn resolve_idle_timeout(env: &dyn Env) -> Result<u64, ConfigError> {
    let entry = declared("KEYLA_SERVER_IDLE_TIMEOUT");
    let ConfigEntry::Int { default, min, max } = entry else {
        unreachable!("KEYLA_SERVER_IDLE_TIMEOUT is declared as int");
    };
    Ok(read_int(env, "KEYLA_SERVER_IDLE_TIMEOUT", *default, *min, *max)? as u64)
}

/// Graceful-shutdown drain window in milliseconds.
pub fn resolve_shutdown_drain_window_ms(env: &dyn Env) -> Result<u64, ConfigError> {
    let entry = declared("KEYLA_SHUTDOWN_DRAIN_WINDOW_MS");
    let ConfigEntry::Int { default, min, max } = entry else {
        unreachable!("KEYLA_SHUTDOWN_DRAIN_WINDOW_MS is declared as int");
    };
    Ok(read_int(env, "KEYLA_SHUTDOWN_DRAIN_WINDOW_MS", *default, *min, *max)? as u64)
}

/// The operator drain token, or `None` when the drain route is disabled.
pub fn resolve_drain_token(env: &dyn Env) -> Option<String> {
    read_optional_text(env, "KEYLA_DRAIN_TOKEN")
}

// ─── Network policy (trusted proxy + SSRF) ──────────────────────────────────

/// How much of the inbound forwarding chain is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedProxyMode {
    /// The raw TCP peer is the client; forwarded headers are ignored.
    Disabled,
    /// The peer must match `allowlist` before its headers are read.
    Trusted { allowlist: Vec<String> },
    /// A PaaS edge that cannot be allowlisted. Opt-in only.
    Platform,
}

/// The one `TRUSTED_PROXY_CIDRS` value that selects platform mode.
pub const TRUSTED_PROXY_PLATFORM_TOKEN: &str = "platform";

/// Outbound SSRF policy shared by direct and provider-backed requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsrfPolicy {
    pub allow_private: Option<bool>,
    pub allowed_networks: Option<Vec<String>>,
    pub max_redirects: Option<i64>,
}

pub fn resolve_trusted_proxy_boundary(env: &dyn Env) -> TrustedProxyMode {
    let Some(allowlist) = read_list(env, "TRUSTED_PROXY_CIDRS") else {
        return TrustedProxyMode::Disabled;
    };
    // The platform token is checked case-insensitively and only when it is the
    // whole value: a list that also names CIDRs is a real allowlist.
    if allowlist.len() == 1 && allowlist[0].eq_ignore_ascii_case(TRUSTED_PROXY_PLATFORM_TOKEN) {
        return TrustedProxyMode::Platform;
    }
    TrustedProxyMode::Trusted { allowlist }
}

pub fn resolve_ssrf_policy(env: &dyn Env) -> Result<SsrfPolicy, ConfigError> {
    let entry = declared("KEYLA_MAX_REDIRECTS");
    let ConfigEntry::OptionalInt { min, max } = entry else {
        unreachable!("KEYLA_MAX_REDIRECTS is declared as optional-int");
    };
    Ok(SsrfPolicy {
        allow_private: read_flag(env, "KEYLA_ALLOW_PRIVATE_UPSTREAMS").then_some(true),
        allowed_networks: read_list(env, "KEYLA_ALLOWED_NETWORKS"),
        // Unset means "use the egress default", distinct from an explicit 0.
        max_redirects: read_optional_int(env, "KEYLA_MAX_REDIRECTS", *min, *max)?,
    })
}

// ─── Runtime memory ─────────────────────────────────────────────────────────

/// Explicit process memory limit; `None` means auto-detect (cgroups).
pub fn resolve_memory_limit_override_bytes(env: &dyn Env) -> Result<Option<i64>, ConfigError> {
    let entry = declared("KEYLA_MEMORY_LIMIT_BYTES");
    let ConfigEntry::OptionalInt { min, max } = entry else {
        unreachable!("KEYLA_MEMORY_LIMIT_BYTES is declared as optional-int");
    };
    read_optional_int(env, "KEYLA_MEMORY_LIMIT_BYTES", *min, *max)
}

// ─── Timeouts, retries, cooldowns ───────────────────────────────────────────

macro_rules! int_resolver {
    ($fn_name:ident, $var:literal) => {
        pub fn $fn_name(env: &dyn Env) -> Result<u64, ConfigError> {
            let entry = declared($var);
            let ConfigEntry::Int { default, min, max } = entry else {
                unreachable!(concat!($var, " is declared as int"));
            };
            Ok(read_int(env, $var, *default, *min, *max)? as u64)
        }
    };
}

int_resolver!(resolve_upstream_timeout_ms, "KEYLA_UPSTREAM_TIMEOUT_MS");
int_resolver!(
    resolve_stream_stall_timeout_ms,
    "KEYLA_STREAM_STALL_TIMEOUT_MS"
);
int_resolver!(
    resolve_stream_first_chunk_timeout_ms,
    "KEYLA_STREAM_FIRST_CHUNK_TIMEOUT_MS"
);
int_resolver!(
    resolve_fallback_retry_base_ms,
    "KEYLA_FALLBACK_RETRY_BASE_MS"
);
int_resolver!(resolve_fallback_retry_cap_ms, "KEYLA_FALLBACK_RETRY_CAP_MS");
int_resolver!(resolve_route_max_attempts, "KEYLA_ROUTE_MAX_ATTEMPTS");
int_resolver!(
    resolve_account_rate_limit_cooldown_ms,
    "KEYLA_ACCOUNT_RATE_LIMIT_COOLDOWN_MS"
);
int_resolver!(
    resolve_account_quota_cooldown_ms,
    "KEYLA_ACCOUNT_QUOTA_COOLDOWN_MS"
);
int_resolver!(
    resolve_account_model_capacity_cooldown_ms,
    "KEYLA_ACCOUNT_MODEL_CAPACITY_COOLDOWN_MS"
);
int_resolver!(
    resolve_account_transient_cooldown_ms,
    "KEYLA_ACCOUNT_TRANSIENT_COOLDOWN_MS"
);
int_resolver!(
    resolve_account_unclassified_cooldown_ms,
    "KEYLA_ACCOUNT_UNCLASSIFIED_COOLDOWN_MS"
);
int_resolver!(resolve_pool_cooldown_ms, "KEYLA_POOL_COOLDOWN_MS");
int_resolver!(resolve_proxy_max_sockets, "KEYLA_PROXY_MAX_SOCKETS");
int_resolver!(
    resolve_proxy_max_free_sockets,
    "KEYLA_PROXY_MAX_FREE_SOCKETS"
);
int_resolver!(resolve_ip_rate_limit, "IP_RATE_MAX_PER_WINDOW");
int_resolver!(
    resolve_model_strike_threshold,
    "KEYLA_MODEL_STRIKE_THRESHOLD"
);
int_resolver!(
    resolve_model_strike_window_ms,
    "KEYLA_MODEL_STRIKE_WINDOW_MS"
);
int_resolver!(resolve_model_ban_ttl_ms, "KEYLA_MODEL_BAN_TTL_MS");
int_resolver!(
    resolve_telemetry_retention_days,
    "KEYLA_TELEMETRY_RETENTION_DAYS"
);
int_resolver!(
    resolve_telemetry_payload_max_bytes,
    "KEYLA_TELEMETRY_PAYLOAD_MAX_BYTES"
);

/// Crash-recovery TTL for a distributed inflight slot. It must exceed the
/// longest legitimate hold — the request deadline plus the stream stall
/// budget — or a long healthy request expires its own key mid-flight.
pub fn resolve_inflight_ttl_seconds(env: &dyn Env) -> Result<u64, ConfigError> {
    const INFLIGHT_TTL_BUFFER_SECONDS: u64 = 120;
    let total_ms = resolve_upstream_timeout_ms(env)? + resolve_stream_stall_timeout_ms(env)?;
    Ok(total_ms.div_ceil(1000) + INFLIGHT_TTL_BUFFER_SECONDS)
}

// ─── Security ───────────────────────────────────────────────────────────────

pub fn resolve_opencode_version_override(env: &dyn Env) -> Option<String> {
    read_optional_text(env, "KEYLA_OPENCODE_VERSION")
}

/// Reads the application encryption key without caching it.
pub fn require_encryption_key_env(env: &dyn Env) -> Result<String, ConfigError> {
    read_required(
        env,
        "KEYLA_ENCRYPTION_KEY",
        "KEYLA_ENCRYPTION_KEY is required to encrypt credentials and hash API keys",
    )
}

/// Base64 decoding as Node's `Buffer.from(raw, "base64")` behaves for the
/// values this contract accepts: standard alphabet, padding optional.
fn base64_decode_lenient(raw: &str) -> Option<Vec<u8>> {
    let engine: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    engine.decode(raw).ok()
}

/// Decodes and validates a base64 or hexadecimal 256-bit encryption key.
pub fn decode_encryption_key(raw: &str) -> Result<[u8; ENCRYPTION_KEY_LENGTH], ConfigError> {
    let candidate = raw.trim();
    let bytes = if candidate.len() == 64 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut out = Vec::with_capacity(ENCRYPTION_KEY_LENGTH);
        let digits = candidate.as_bytes();
        for pair in digits.chunks_exact(2) {
            let high = (pair[0] as char).to_digit(16).expect("hex digit checked");
            let low = (pair[1] as char).to_digit(16).expect("hex digit checked");
            out.push((high * 16 + low) as u8);
        }
        out
    } else {
        base64_decode_lenient(candidate).ok_or(ConfigError::EncryptionKeyEncoding)?
    };
    let actual = bytes.len();
    let key: [u8; ENCRYPTION_KEY_LENGTH] =
        bytes
            .try_into()
            .map_err(|_| ConfigError::EncryptionKeyLength {
                expected: ENCRYPTION_KEY_LENGTH,
                actual,
            })?;
    Ok(key)
}

/// Reads and normalizes the public OAuth origin.
pub fn require_public_origin(env: &dyn Env) -> Result<String, ConfigError> {
    let raw = read_required(
        env,
        "KEYLA_PUBLIC_ORIGIN",
        "KEYLA_PUBLIC_ORIGIN is required to build OAuth redirect URIs (e.g. https://keyla.example.com)",
    )?;
    Ok(raw.trim_end_matches('/').to_owned())
}

/// The fixed OAuth callback URL for a provider id.
pub fn oauth_callback_url(env: &dyn Env, provider_id: &str) -> Result<String, ConfigError> {
    Ok(format!(
        "{}/console/api/providers/{provider_id}/oauth/callback",
        require_public_origin(env)?
    ))
}

/// Browser-authorize redirect URI registered with Devin and Codex.
pub fn browser_authorize_redirect_uri() -> &'static str {
    "http://127.0.0.1:59653/callback"
}

pub fn resolve_kimi_oauth_host(env: &dyn Env) -> String {
    read_text(env, "KEYLA_KIMI_OAUTH_HOST", DEFAULT_KIMI_OAUTH_HOST)
}

pub fn resolve_kimi_quota_base_url(env: &dyn Env) -> String {
    read_text(
        env,
        "KEYLA_KIMI_QUOTA_BASE_URL",
        DEFAULT_KIMI_QUOTA_BASE_URL,
    )
}

/// GitHub Enterprise domain for the Copilot device login, or `""` for
/// github.com. Normalized to a bare hostname.
pub fn resolve_github_enterprise_domain(env: &dyn Env) -> String {
    let raw = read_text(env, "KEYLA_GITHUB_ENTERPRISE_DOMAIN", "");
    if raw.is_empty() {
        return String::new();
    }
    let candidate = if raw.contains("://") {
        raw
    } else {
        format!("https://{raw}")
    };
    url::Url::parse(&candidate)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

// ─── Data directory ─────────────────────────────────────────────────────────

/// Writable root for gateway-owned on-disk state.
///
/// `KEYLA_DATA_DIR` wins; otherwise the per-OS convention. The pre-rename
/// `Cartethyia` directory is *moved* to the new name once, at startup, when
/// the new name does not exist. The move is attempted and never fatal: a
/// read-only home, a cross-device layout, or an existing `Keyla` falls back
/// to using the old directory as it is.
pub fn resolve_data_dir(env: &dyn Env) -> PathBuf {
    resolve_data_dir_for(
        env,
        &std::env::var("HOME").unwrap_or_default(),
        std::env::consts::OS,
    )
}

fn resolve_data_dir_for(env: &dyn Env, home: &str, os: &str) -> PathBuf {
    if let Some(override_path) = read_optional_text(env, "KEYLA_DATA_DIR") {
        return PathBuf::from(override_path);
    }
    let base = match os {
        "windows" => env
            .get("APPDATA")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| home.to_owned()),
        "macos" => Path::new(&home)
            .join("Library")
            .join("Application Support")
            .to_string_lossy()
            .into_owned(),
        _ => env
            .get("XDG_DATA_HOME")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                Path::new(&home)
                    .join(".local")
                    .join("share")
                    .to_string_lossy()
                    .into_owned()
            }),
    };
    let base = PathBuf::from(base);
    let preferred = base.join("Keyla");
    let legacy = base.join("Cartethyia");
    if preferred.exists() || !legacy.exists() {
        return preferred;
    }
    match std::fs::rename(&legacy, &preferred) {
        Ok(()) => preferred,
        Err(_) => legacy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> MapEnv {
        MapEnv::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn spec_names_are_unique() {
        let mut names: Vec<&str> = CONFIG_SPEC.iter().map(|entry| entry.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "CONFIG_SPEC declares a duplicate name");
    }

    #[test]
    fn current_name_wins_over_legacy() {
        let env = env(&[
            ("KEYLA_BIND_HOST", "0.0.0.0"),
            ("CARTETHYIA_BIND_HOST", "192.0.2.1"),
        ]);
        assert_eq!(resolve_bind_host(&env), "0.0.0.0");
    }

    #[test]
    fn legacy_name_is_honoured() {
        let env = env(&[("CARTETHYIA_BIND_HOST", "192.0.2.1")]);
        assert_eq!(resolve_bind_host(&env), "192.0.2.1");
    }

    #[test]
    fn empty_value_falls_back_to_default() {
        let env = env(&[("KEYLA_BIND_HOST", "   ")]);
        assert_eq!(resolve_bind_host(&env), "127.0.0.1");
    }

    #[test]
    fn port_defaults_and_rejects_out_of_range() {
        assert_eq!(resolve_port(&env(&[])).unwrap(), 12_800);
        assert_eq!(resolve_port(&env(&[("PORT", "12800")])).unwrap(), 12_800);
        assert_eq!(
            resolve_port(&env(&[("PORT", "0")])),
            Err(ConfigError::InvalidInt {
                name: "PORT".into(),
                min: 1,
                max: 65_535
            })
        );
        assert!(resolve_port(&env(&[("PORT", "abc")])).is_err());
    }

    #[test]
    fn required_values_fail_closed() {
        assert_eq!(
            require_encryption_key_env(&env(&[])),
            Err(ConfigError::Required(
                "KEYLA_ENCRYPTION_KEY is required to encrypt credentials and hash API keys".into()
            ))
        );
        assert_eq!(
            require_public_origin(&env(&[("KEYLA_PUBLIC_ORIGIN", "https://example.test///")]))
                .unwrap(),
            "https://example.test"
        );
    }

    #[test]
    fn encryption_key_accepts_hex_and_base64() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let from_hex = decode_encryption_key(hex).unwrap();
        assert_eq!(from_hex[0], 0x00);
        assert_eq!(from_hex[31], 0x1f);

        let encoded = base64::engine::general_purpose::STANDARD.encode(from_hex);
        assert_eq!(decode_encryption_key(&encoded).unwrap(), from_hex);
        assert_eq!(
            decode_encryption_key(encoded.trim_end_matches('=')).unwrap(),
            from_hex
        );

        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(matches!(
            decode_encryption_key(&short),
            Err(ConfigError::EncryptionKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn trusted_proxy_modes() {
        assert_eq!(
            resolve_trusted_proxy_boundary(&env(&[])),
            TrustedProxyMode::Disabled
        );
        assert_eq!(
            resolve_trusted_proxy_boundary(&env(&[("TRUSTED_PROXY_CIDRS", "Platform")])),
            TrustedProxyMode::Platform
        );
        assert_eq!(
            resolve_trusted_proxy_boundary(&env(&[(
                "TRUSTED_PROXY_CIDRS",
                "10.0.0.0/8, 192.168.0.0/16"
            )])),
            TrustedProxyMode::Trusted {
                allowlist: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()]
            }
        );
    }

    #[test]
    fn ssrf_policy_distinguishes_unset_from_zero_redirects() {
        let unset = resolve_ssrf_policy(&env(&[])).unwrap();
        assert_eq!(unset.max_redirects, None);
        // `readFlag` is on unless the literal "false" is set, so private
        // upstreams are permitted by default. This is the existing contract.
        assert_eq!(unset.allow_private, Some(true));

        let zero = resolve_ssrf_policy(&env(&[("KEYLA_MAX_REDIRECTS", "0")])).unwrap();
        assert_eq!(zero.max_redirects, Some(0));

        let private = resolve_ssrf_policy(&env(&[
            ("KEYLA_ALLOW_PRIVATE_UPSTREAMS", "false"),
            ("KEYLA_ALLOWED_NETWORKS", "10.0.0.0/8"),
        ]))
        .unwrap();
        assert_eq!(private.allow_private, None);
        assert_eq!(private.allowed_networks, Some(vec!["10.0.0.0/8".into()]));
    }

    #[test]
    fn inflight_ttl_is_derived_from_the_two_timeouts() {
        let env = env(&[
            ("KEYLA_UPSTREAM_TIMEOUT_MS", "120000"),
            ("KEYLA_STREAM_STALL_TIMEOUT_MS", "360000"),
        ]);
        assert_eq!(resolve_inflight_ttl_seconds(&env).unwrap(), 600);
    }

    #[test]
    fn github_enterprise_domain_is_normalized() {
        assert_eq!(resolve_github_enterprise_domain(&env(&[])), "");
        assert_eq!(
            resolve_github_enterprise_domain(&env(&[(
                "KEYLA_GITHUB_ENTERPRISE_DOMAIN",
                "https://company.ghe.com/"
            )])),
            "company.ghe.com"
        );
        assert_eq!(
            resolve_github_enterprise_domain(&env(&[(
                "KEYLA_GITHUB_ENTERPRISE_DOMAIN",
                "company.ghe.com"
            )])),
            "company.ghe.com"
        );
    }

    #[test]
    fn data_dir_override_wins() {
        let env = env(&[("KEYLA_DATA_DIR", "/tmp/keyla-test")]);
        assert_eq!(resolve_data_dir(&env), PathBuf::from("/tmp/keyla-test"));
    }

    #[test]
    fn legacy_data_dir_is_renamed_once() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("Cartethyia")).unwrap();
        let env = env(&[("XDG_DATA_HOME", root.path().to_str().unwrap())]);

        let resolved = resolve_data_dir_for(&env, "/home/operator", "linux");
        assert_eq!(resolved, root.path().join("Keyla"));
        assert!(resolved.is_dir());
        assert!(!root.path().join("Cartethyia").exists());

        // A second boot leaves the preferred directory alone.
        assert_eq!(
            resolve_data_dir_for(&env, "/home/operator", "linux"),
            root.path().join("Keyla")
        );
    }

    #[test]
    fn platform_data_dir_defaults() {
        let env = env(&[]);
        assert_eq!(
            resolve_data_dir_for(&env, "/home/operator", "linux"),
            PathBuf::from("/home/operator/.local/share/Keyla")
        );
        assert_eq!(
            resolve_data_dir_for(&env, "/Users/operator", "macos"),
            PathBuf::from("/Users/operator/Library/Application Support/Keyla")
        );
    }
}
