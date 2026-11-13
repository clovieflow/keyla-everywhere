//! Routing contracts: candidates, snapshots, eligibility, admission, and
//! reservations. Port of `src/transport/routing/route-model.ts` and the
//! admission half of `router.ts`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use keyla_core::{GatewayError, GatewayErrorCode, ServiceKind, WireFamily};
use serde_json::Map;

pub type RoutingRevision = u64;
pub type CapabilityProfile = BTreeMap<String, bool>;

pub const DEFAULT_PROVIDER_USER_AGENT: &str = "codex_cli_rs/0.156.1";
pub const ROUTING_STRATEGIES: [&str; 2] = ["fallback", "round_robin"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRoutingStrategy {
    Fallback,
    RoundRobin,
}

impl ProviderRoutingStrategy {
    pub fn parse(value: &str) -> Self {
        if value == "round_robin" {
            Self::RoundRobin
        } else {
            Self::Fallback
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fallback => "fallback",
            Self::RoundRobin => "round_robin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComboStrategy {
    Fallback,
    RoundRobin,
    Fusion,
}

impl ComboStrategy {
    pub fn parse(value: &str) -> Self {
        match value {
            "round_robin" => Self::RoundRobin,
            "fusion" => Self::Fusion,
            _ => Self::Fallback,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownKind {
    Hard,
    Soft,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Cooldown,
    ModelCooldown,
    CreditFloorReached,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchRoute {
    Native,
    Fallback,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoolRoutingSetting {
    pub strategy: ProviderRoutingStrategy,
    pub rotate_count: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderRoutingSetting {
    pub strategy: ProviderRoutingStrategy,
    pub rotate_count: i64,
    pub max_inflight: Option<i64>,
    pub credit_limit_enabled: Option<bool>,
    pub credit_limit: Option<f64>,
    pub enabled: bool,
    pub user_agent: Option<String>,
    pub bypass_proxy: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComboDefinition {
    pub members: Vec<String>,
    pub strategy: ComboStrategy,
}

/// One routable provider/model/account triple.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteCandidate {
    pub provider_id: String,
    pub model_id: String,
    pub wire_family: WireFamily,
    pub service_kind: ServiceKind,
    pub endpoint: String,
    pub capability_profile: CapabilityProfile,
    pub user_agent: Option<String>,
    pub max_inflight: Option<i64>,
    pub provider_account_id: Option<String>,
    pub cooldown_kind: Option<CooldownKind>,
    pub cooldown_until: Option<String>,
    pub model_cooldown_until: Option<String>,
    pub credit_limit_enabled: Option<bool>,
    pub credit_limit: Option<f64>,
    pub last_remaining_credit: Option<f64>,
    pub last_remaining_percent: Option<f64>,
    pub provider_account_label: Option<String>,
    pub network_pool_ids: Vec<String>,
    pub network_pool_required: bool,
    pub network_pool_limits: BTreeMap<String, i64>,
    pub network_pool_weights: BTreeMap<String, i64>,
    pub network_pool_routing: Option<PoolRoutingSetting>,
    pub tenant_id: Option<String>,
    pub requires_account: Option<bool>,
    pub health_status: Option<HealthStatus>,
    pub account_locked: bool,
    pub search_route: Option<SearchRoute>,
}

impl RouteCandidate {
    pub fn new(
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        wire_family: WireFamily,
        service_kind: ServiceKind,
        endpoint: impl Into<String>,
        capability_profile: CapabilityProfile,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            model_id: model_id.into(),
            wire_family,
            service_kind,
            endpoint: endpoint.into(),
            capability_profile,
            user_agent: None,
            max_inflight: None,
            provider_account_id: None,
            cooldown_kind: None,
            cooldown_until: None,
            model_cooldown_until: None,
            credit_limit_enabled: None,
            credit_limit: None,
            last_remaining_credit: None,
            last_remaining_percent: None,
            provider_account_label: None,
            network_pool_ids: Vec::new(),
            network_pool_required: false,
            network_pool_limits: BTreeMap::new(),
            network_pool_weights: BTreeMap::new(),
            network_pool_routing: None,
            tenant_id: None,
            requires_account: None,
            health_status: None,
            account_locked: false,
            search_route: None,
        }
    }

    pub fn service_kind(&self) -> ServiceKind {
        self.service_kind
    }

    pub fn with_health(mut self, status: HealthStatus) -> Self {
        self.health_status = Some(status);
        self
    }

    pub fn with_account(mut self, account_id: impl Into<String>) -> Self {
        self.provider_account_id = Some(account_id.into());
        self
    }

    pub fn with_tenant(mut self, tenant: Option<String>) -> Self {
        self.tenant_id = tenant;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoutePlan {
    pub revision: RoutingRevision,
    pub candidates: Vec<RouteCandidate>,
    pub requested_model: String,
    pub resolved_model: String,
    pub provider_id: String,
    pub fusion: Option<FusionPlan>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FusionPlan {
    pub panel: Vec<String>,
    pub judge: String,
}

#[derive(Debug, Clone, Default)]
pub struct RouteSnapshot {
    pub revision: RoutingRevision,
    pub candidates: Vec<RouteCandidate>,
    pub aliases: HashMap<String, HashMap<String, String>>,
    pub cli_aliases: HashMap<String, HashMap<String, String>>,
    pub combos: HashMap<String, HashMap<String, ComboDefinition>>,
    pub created_at: i64,
    pub provider_routing: Option<HashMap<String, HashMap<String, ProviderRoutingSetting>>>,
    pub pool_routing: Option<HashMap<String, PoolRoutingSetting>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilityReason {
    Healthy,
    Cooldown,
    CooldownHard,
    CreditFloorReached,
    ModelCooldown,
    QuotaExhausted,
    Locked,
    Disabled,
}

impl EligibilityReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Cooldown => "cooldown",
            Self::CooldownHard => "cooldown_hard",
            Self::CreditFloorReached => "credit_floor_reached",
            Self::ModelCooldown => "model_cooldown",
            Self::QuotaExhausted => "quota_exhausted",
            Self::Locked => "locked",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EligibilityDecision {
    pub eligible: bool,
    pub reason: EligibilityReason,
}

/// Shared eligibility evaluator used by live routing and the simulator.
#[derive(Debug, Default, Clone, Copy)]
pub struct EligibilityEvaluator;

impl EligibilityEvaluator {
    pub fn evaluate(&self, candidate: &RouteCandidate) -> EligibilityDecision {
        if candidate.account_locked {
            return EligibilityDecision {
                eligible: false,
                reason: EligibilityReason::Locked,
            };
        }
        if candidate.health_status == Some(HealthStatus::Disabled) {
            return EligibilityDecision {
                eligible: false,
                reason: EligibilityReason::Disabled,
            };
        }
        if candidate.credit_limit_enabled != Some(false) {
            if let Some(limit) = candidate.credit_limit {
                if let Some(credit) = candidate.last_remaining_credit {
                    if credit.is_finite() && credit <= limit {
                        return EligibilityDecision {
                            eligible: false,
                            reason: EligibilityReason::CreditFloorReached,
                        };
                    }
                }
                if candidate.last_remaining_credit.is_none() {
                    if let Some(percent) = candidate.last_remaining_percent {
                        if percent.is_finite() && percent <= limit {
                            return EligibilityDecision {
                                eligible: false,
                                reason: EligibilityReason::CreditFloorReached,
                            };
                        }
                    }
                }
            }
        }
        match candidate.health_status {
            Some(HealthStatus::ModelCooldown) => EligibilityDecision {
                eligible: false,
                reason: EligibilityReason::ModelCooldown,
            },
            Some(HealthStatus::CreditFloorReached) => EligibilityDecision {
                eligible: false,
                reason: EligibilityReason::CreditFloorReached,
            },
            Some(HealthStatus::Cooldown) if candidate.cooldown_kind == Some(CooldownKind::Hard) => {
                EligibilityDecision {
                    eligible: false,
                    reason: EligibilityReason::CooldownHard,
                }
            }
            Some(HealthStatus::Cooldown) => EligibilityDecision {
                eligible: true,
                reason: EligibilityReason::Cooldown,
            },
            _ => EligibilityDecision {
                eligible: true,
                reason: EligibilityReason::Healthy,
            },
        }
    }

    pub fn filter(&self, candidates: &[RouteCandidate]) -> Vec<RouteCandidate> {
        candidates
            .iter()
            .filter(|candidate| self.evaluate(candidate).eligible)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionDecision {
    pub admitted: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reservation {
    pub candidate: RouteCandidate,
    pub lease_id: String,
    pub expires_at: i64,
    pub acquired_at: i64,
}

#[async_trait]
pub trait AdmissionController: Send + Sync {
    async fn admit(&self, candidate: &RouteCandidate) -> AdmissionDecision;
    async fn release(&self, reservation: &Reservation);
    async fn snapshot_account_inflight(&self) -> HashMap<String, i64> {
        HashMap::new()
    }
}

fn admission_key(candidate: &RouteCandidate) -> String {
    let base = format!("{}:{}", candidate.provider_id, candidate.model_id);
    match &candidate.provider_account_id {
        Some(account) => format!("{base}:{account}"),
        None => base,
    }
}

enum AdmissionDirective {
    Unlimited,
    Reject,
    Bounded(i64),
}

fn admission_directive(candidate: &RouteCandidate) -> AdmissionDirective {
    match candidate.max_inflight {
        None => AdmissionDirective::Unlimited,
        Some(limit) if limit <= 0 => AdmissionDirective::Reject,
        Some(limit) => AdmissionDirective::Bounded(limit),
    }
}

fn capacity_rejected() -> AdmissionDecision {
    AdmissionDecision {
        admitted: false,
        reason: Some("capacity_exhausted".into()),
    }
}

/// In-memory admission with an account-scoped concurrency ceiling.
#[derive(Debug, Default)]
pub struct InMemoryAdmissionController {
    inflight: Mutex<HashMap<String, i64>>,
}

impl InMemoryAdmissionController {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AdmissionController for InMemoryAdmissionController {
    async fn admit(&self, candidate: &RouteCandidate) -> AdmissionDecision {
        let key = admission_key(candidate);
        let directive = admission_directive(candidate);
        if matches!(directive, AdmissionDirective::Reject) {
            return capacity_rejected();
        }
        let mut inflight = self
            .inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = *inflight.get(&key).unwrap_or(&0);
        if let AdmissionDirective::Bounded(limit) = directive {
            if current >= limit {
                return capacity_rejected();
            }
        }
        inflight.insert(key, current + 1);
        AdmissionDecision {
            admitted: true,
            reason: None,
        }
    }

    async fn release(&self, reservation: &Reservation) {
        let key = admission_key(&reservation.candidate);
        let mut inflight = self
            .inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = *inflight.get(&key).unwrap_or(&1);
        if current <= 1 {
            inflight.remove(&key);
        } else {
            inflight.insert(key, current - 1);
        }
    }

    async fn snapshot_account_inflight(&self) -> HashMap<String, i64> {
        self.inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// In-memory reservation leases with lazy TTL cleanup.
#[derive(Debug, Default)]
pub struct ReservationManager {
    leases: Mutex<HashMap<String, Reservation>>,
    last_sweep_at: Mutex<i64>,
}

impl ReservationManager {
    const SWEEP_INTERVAL_MS: i64 = 30_000;

    pub fn new() -> Self {
        Self::default()
    }

    fn sweep_expired(&self, now: i64) {
        let mut last = self
            .last_sweep_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now - *last < Self::SWEEP_INTERVAL_MS {
            return;
        }
        *last = now;
        let mut leases = self
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        leases.retain(|_, reservation| reservation.expires_at >= now);
    }

    pub fn acquire(&self, candidate: RouteCandidate, ttl_ms: i64) -> Reservation {
        let now = now_ms();
        self.sweep_expired(now);
        let lease_id = format!(
            "{}:{}:{}:{}",
            candidate.provider_id,
            candidate.model_id,
            now,
            now_ms() % 1_000_000
        );
        let reservation = Reservation {
            candidate,
            lease_id: lease_id.clone(),
            acquired_at: now,
            expires_at: now + ttl_ms,
        };
        self.leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(lease_id, reservation.clone());
        reservation
    }

    pub fn release(&self, lease_id: &str) {
        self.leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(lease_id);
    }

    pub fn get(&self, lease_id: &str) -> Option<Reservation> {
        let mut leases = self
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let reservation = leases.get(lease_id)?.clone();
        if reservation.expires_at < now_ms() {
            leases.remove(lease_id);
            return None;
        }
        Some(reservation)
    }

    pub fn size(&self) -> usize {
        self.leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

/// Rotation cursor for one provider/model run.
#[derive(Debug, Default, Clone)]
pub struct RoundRobinState {
    index: usize,
    served_by_current: i64,
}

impl RoundRobinState {
    /// `advance = false` is a read-only peek that must not move the cursor.
    pub fn next_index(&mut self, count: usize, rotate_count: i64, advance: bool) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let safe_count = rotate_count.clamp(1, 1000);
        let index = self.index % count;
        if !advance {
            return Some(index);
        }
        self.served_by_current += 1;
        if self.served_by_current >= safe_count {
            self.index = (self.index + 1) % 1_000_000;
            self.served_by_current = 0;
        }
        Some(index)
    }
}

// ─── Errors ─────────────────────────────────────────────────────────────────

fn error(
    code: GatewayErrorCode,
    status: u16,
    message: String,
    details: Map<String, serde_json::Value>,
) -> GatewayError {
    GatewayError::new(code, status, message, details)
}

pub fn ambiguous_model_error(bare: &str, owners: &[String]) -> GatewayError {
    let mut details = Map::new();
    details.insert("model".into(), serde_json::json!(bare));
    details.insert("owners".into(), serde_json::json!(owners));
    error(
        GatewayErrorCode::AmbiguousModel,
        400,
        format!(
            "Model '{bare}' is ambiguous across providers: {}",
            owners.join(", ")
        ),
        details,
    )
}

pub fn model_not_found_error(requested: &str, resolved: &[String]) -> GatewayError {
    let targets: Vec<&String> = resolved
        .iter()
        .filter(|name| name.as_str() != requested)
        .collect();
    let hint = targets
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut details = Map::new();
    details.insert("model".into(), serde_json::json!(requested));
    if !targets.is_empty() {
        details.insert("resolved_models".into(), serde_json::json!(targets));
    }
    error(
        GatewayErrorCode::ModelNotFound,
        404,
        format!(
            "Model '{requested}'{} not found",
            if targets.is_empty() {
                String::new()
            } else {
                format!(" (resolved to {hint})")
            }
        ),
        details,
    )
}

pub fn accounts_unavailable_error(requested: &str, reasons: &[&str]) -> GatewayError {
    let mut distinct: Vec<String> = reasons.iter().map(|reason| (*reason).to_owned()).collect();
    distinct.sort();
    distinct.dedup();
    let mut details = Map::new();
    details.insert("model".into(), serde_json::json!(requested));
    details.insert("reasons".into(), serde_json::json!(distinct));
    details.insert("candidate_count".into(), serde_json::json!(reasons.len()));
    error(
        GatewayErrorCode::AccountsUnavailable,
        503,
        format!(
            "Model '{requested}' has no available account ({} candidate(s) unusable: {})",
            reasons.len(),
            distinct.join(", ")
        ),
        details,
    )
}

pub fn accounts_rate_limited_error(requested: &str, routed: &str) -> GatewayError {
    let note = if routed == requested {
        String::new()
    } else {
        format!(" routed to '{routed}'")
    };
    let mut details = Map::new();
    details.insert("model".into(), serde_json::json!(requested));
    details.insert("routed_model".into(), serde_json::json!(routed));
    details.insert("reason".into(), serde_json::json!("all_accounts_cooling"));
    error(
        GatewayErrorCode::AccountsRateLimited,
        429,
        format!(
            "Model '{requested}'{note} has no healthy account: every account is rate limited or cooling down"
        ),
        details,
    )
}

pub fn capacity_exhausted_error() -> GatewayError {
    error(
        GatewayErrorCode::CapacityExhausted,
        429,
        "No capacity available".into(),
        Map::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(account: &str, health: Option<HealthStatus>) -> RouteCandidate {
        let mut candidate = RouteCandidate::new(
            "openai",
            "gpt-test",
            WireFamily::Chat,
            ServiceKind::Llm,
            "/v1/chat/completions",
            CapabilityProfile::new(),
        )
        .with_account(account);
        candidate.health_status = health;
        candidate
    }

    #[test]
    fn eligibility_covers_every_health_state() {
        let evaluator = EligibilityEvaluator;
        assert_eq!(
            evaluator.evaluate(&candidate("a", None)).reason,
            EligibilityReason::Healthy
        );
        assert_eq!(
            evaluator
                .evaluate(&candidate("a", Some(HealthStatus::Cooldown)))
                .reason,
            EligibilityReason::Cooldown
        );
        let mut hard = candidate("a", Some(HealthStatus::Cooldown));
        hard.cooldown_kind = Some(CooldownKind::Hard);
        assert_eq!(
            evaluator.evaluate(&hard).reason,
            EligibilityReason::CooldownHard
        );
        assert_eq!(
            evaluator
                .evaluate(&candidate("a", Some(HealthStatus::ModelCooldown)))
                .reason,
            EligibilityReason::ModelCooldown
        );
        assert!(
            !evaluator
                .evaluate(&candidate("a", Some(HealthStatus::Disabled)))
                .eligible
        );
    }

    #[test]
    fn credit_floor_compares_in_the_reported_unit() {
        let evaluator = EligibilityEvaluator;
        let mut credit = candidate("a", None);
        credit.credit_limit_enabled = Some(true);
        credit.credit_limit = Some(5.0);
        credit.last_remaining_credit = Some(5.0);
        assert_eq!(
            evaluator.evaluate(&credit).reason,
            EligibilityReason::CreditFloorReached
        );

        let mut percent = candidate("b", None);
        percent.credit_limit = Some(5.0);
        percent.last_remaining_percent = Some(4.0);
        assert_eq!(
            evaluator.evaluate(&percent).reason,
            EligibilityReason::CreditFloorReached
        );

        let mut disabled = credit.clone();
        disabled.credit_limit_enabled = Some(false);
        assert!(evaluator.evaluate(&disabled).eligible);
    }

    #[tokio::test]
    async fn admission_counts_per_account_and_enforces_the_ceiling() {
        let controller = InMemoryAdmissionController::new();
        let mut first = candidate("a", None);
        first.max_inflight = Some(1);
        assert!(controller.admit(&first).await.admitted);
        assert!(!controller.admit(&first).await.admitted);
        let reservation = Reservation {
            candidate: first.clone(),
            lease_id: "l".into(),
            expires_at: now_ms() + 1_000,
            acquired_at: now_ms(),
        };
        controller.release(&reservation).await;
        assert!(controller.admit(&first).await.admitted);
        // A different account has its own bucket.
        let second = candidate("b", None);
        assert!(controller.admit(&second).await.admitted);
    }

    #[test]
    fn round_robin_advances_after_rotate_count() {
        let mut state = RoundRobinState::default();
        assert_eq!(state.next_index(2, 2, true), Some(0));
        assert_eq!(state.next_index(2, 2, true), Some(0));
        assert_eq!(state.next_index(2, 2, true), Some(1));
        // A peek never advances.
        assert_eq!(state.next_index(2, 2, false), Some(1));
        assert_eq!(state.next_index(2, 2, false), Some(1));
    }
}
