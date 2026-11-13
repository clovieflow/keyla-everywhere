//! Route snapshot, eligibility, ordering, and reservation.

pub mod caps;
pub mod engine;
pub mod model;

pub use caps::{
    MAX_CACHE_BREAKPOINTS, RequiredCapability, RouteCapabilities, candidate_supports_request,
    derive_required_capabilities, is_web_search_tool, is_web_search_tool_name, project_for_route,
    request_uses_web_search, route_capabilities_for, service_kind_for_endpoint,
};
pub use engine::{
    PlanInput, RouteSimulationCandidate, RouteSimulationOutcome, RouteSimulationResult,
    RoutingEngine, SIMULATOR_ENDPOINTS, resolve_alias, resolve_alias_target,
};
pub use model::{
    AdmissionController, AdmissionDecision, CapabilityProfile, ComboDefinition, ComboStrategy,
    CooldownKind, DEFAULT_PROVIDER_USER_AGENT, EligibilityDecision, EligibilityEvaluator,
    EligibilityReason, FusionPlan, HealthStatus, InMemoryAdmissionController, PoolRoutingSetting,
    ProviderRoutingSetting, ProviderRoutingStrategy, ROUTING_STRATEGIES, Reservation,
    ReservationManager, RoundRobinState, RouteCandidate, RoutePlan, RouteSnapshot, RoutingRevision,
    SearchRoute, accounts_rate_limited_error, accounts_unavailable_error, ambiguous_model_error,
    capacity_exhausted_error, model_not_found_error,
};
