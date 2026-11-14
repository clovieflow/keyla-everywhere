//! Route planning, rotation, admission, and simulation. Port of
//! `src/transport/routing/router.ts`.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use keyla_core::{GatewayError, GatewayErrorCode, ServiceKind};
use serde_json::{Map, json};

use crate::caps::{RequiredCapability, candidate_supports_request, service_kind_for_endpoint};
use crate::model::{
    AdmissionController, ComboDefinition, ComboStrategy, EligibilityDecision, EligibilityEvaluator,
    EligibilityReason, FusionPlan, ProviderRoutingSetting, ProviderRoutingStrategy, Reservation,
    ReservationManager, RoundRobinState, RouteCandidate, RoutePlan, RouteSnapshot, RoutingRevision,
    SearchRoute, accounts_rate_limited_error, accounts_unavailable_error, ambiguous_model_error,
    capacity_exhausted_error, model_not_found_error,
};

const SEARCH_PROVIDER_ORDER: [&str; 3] = ["exa", "gemini", "codex"];
const MAX_ROUND_ROBIN_ENTRIES: usize = 1000;

/// Endpoint families the route simulator may evaluate.
pub const SIMULATOR_ENDPOINTS: [&str; 6] = [
    "chat.completions",
    "responses",
    "messages",
    "completions",
    "search",
    "systemone",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteSimulationOutcome {
    Dispatchable,
    AccountsUnavailable,
    AccountsRateLimited,
    ServiceKindUnsupported,
}

impl RouteSimulationOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dispatchable => "dispatchable",
            Self::AccountsUnavailable => "accounts_unavailable",
            Self::AccountsRateLimited => "accounts_rate_limited",
            Self::ServiceKindUnsupported => "service_kind_unsupported",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteSimulationCandidate {
    pub candidate: RouteCandidate,
    pub eligible: bool,
    pub reason: EligibilityReason,
    pub endpoint_supported: bool,
    pub provider_routing: Option<ProviderRoutingSetting>,
}

#[derive(Debug, Clone)]
pub struct RouteSimulationResult {
    pub requested_model: String,
    pub resolved_model: String,
    pub resolution_chain: Vec<String>,
    pub revision: RoutingRevision,
    pub endpoint_service_kind: ServiceKind,
    pub outcome: RouteSimulationOutcome,
    pub candidates: Vec<RouteSimulationCandidate>,
    pub selected: Option<RouteCandidate>,
    pub rotation_active: bool,
    pub strategy: String,
    pub strategy_source: &'static str,
    pub fusion: Option<FusionPlan>,
    pub unmatched_members: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct PlanInput<'a> {
    pub requested_model: &'a str,
    pub tenant_id: Option<&'a str>,
    pub required_capabilities: Option<&'a [RequiredCapability]>,
    pub allow_cli_mappings: bool,
    pub key_id: Option<&'a str>,
    pub web_search: bool,
    pub advance: bool,
}

impl<'a> PlanInput<'a> {
    pub fn new(requested_model: &'a str) -> Self {
        Self {
            requested_model,
            tenant_id: None,
            required_capabilities: None,
            allow_cli_mappings: false,
            key_id: None,
            web_search: false,
            advance: true,
        }
    }
}

fn candidate_identity(candidate: &RouteCandidate) -> String {
    format!(
        "{}:{}:{}",
        candidate.provider_id,
        candidate.model_id,
        candidate.provider_account_id.clone().unwrap_or_default()
    )
}

fn parse_model(model: &str) -> (Option<&str>, &str) {
    match model.find('/') {
        Some(index) => (Some(&model[..index]), &model[index + 1..]),
        None => (None, model),
    }
}

fn candidate_matches(candidate: &RouteCandidate, model: &str) -> bool {
    let (provider_id, bare) = parse_model(model);
    match provider_id {
        None => candidate.model_id == bare,
        Some(provider_id) => candidate.model_id == bare && candidate.provider_id == provider_id,
    }
}

/// Candidates for one requested model id. A provider-qualified id wins. When
/// no provider owns that prefix, fall back to the exact model id so advertised
/// bare ids that contain `/` (for example `Flara/mercury-3`) still route.
fn candidates_for_model(
    snapshot: &RouteSnapshot,
    model_id: &str,
    tenant_id: Option<&str>,
) -> Vec<RouteCandidate> {
    let tenant_matches = |candidate: &&RouteCandidate| {
        candidate.tenant_id.is_none() || candidate.tenant_id.as_deref() == tenant_id
    };
    let mut group: Vec<RouteCandidate> = snapshot
        .candidates
        .iter()
        .filter(|candidate| candidate_matches(candidate, model_id))
        .filter(tenant_matches)
        .cloned()
        .collect();
    if group.is_empty() {
        let (provider_id, _) = parse_model(model_id);
        if provider_id.is_some() {
            group = snapshot
                .candidates
                .iter()
                .filter(|candidate| candidate.model_id == model_id)
                .filter(tenant_matches)
                .cloned()
                .collect();
        }
    }
    group
}

fn normalize_alias_key(requested: &str, aliases: Option<&HashMap<String, String>>) -> String {
    let Some(aliases) = aliases else {
        return requested.to_owned();
    };
    if aliases.contains_key(requested) {
        return requested.to_owned();
    }
    let mut base = requested;
    if let Some(bracket) = requested.find('[') {
        if bracket > 0 {
            base = &requested[..bracket];
            if aliases.contains_key(base) {
                return base.to_owned();
            }
        }
    }
    if let Some(rest) = base.strip_prefix("claude-") {
        if aliases.contains_key(rest) {
            return rest.to_owned();
        }
        if let Some(dash) = rest.find('-') {
            let slot = &rest[..dash];
            if aliases.contains_key(slot) {
                return slot.to_owned();
            }
        }
    }
    base.to_owned()
}

fn alias_map_for(
    snapshot: &RouteSnapshot,
    tenant_id: Option<&str>,
    allow_cli_mappings: bool,
    key_id: Option<&str>,
) -> Option<HashMap<String, String>> {
    let tenant_id = tenant_id?;
    let aliases = snapshot.aliases.get(tenant_id);
    let cli_aliases = if allow_cli_mappings {
        match key_id {
            Some(key_id) => snapshot
                .cli_aliases
                .get(&format!("{tenant_id}:{key_id}"))
                .or_else(|| snapshot.cli_aliases.get(tenant_id)),
            None => snapshot.cli_aliases.get(tenant_id),
        }
    } else {
        None
    };
    if aliases.is_none() && cli_aliases.is_none() {
        return None;
    }
    let mut merged = aliases.cloned().unwrap_or_default();
    if let Some(cli_aliases) = cli_aliases {
        merged.extend(cli_aliases.clone());
    }
    Some(merged)
}

/// Resolves one requested name through aliases, returning the target and the
/// hop chain. Cycles and over-deep chains are errors.
pub fn resolve_alias(
    snapshot: &RouteSnapshot,
    tenant_id: Option<&str>,
    requested: &str,
    allow_cli_mappings: bool,
    key_id: Option<&str>,
) -> Result<(String, Vec<String>), String> {
    let alias_map = alias_map_for(snapshot, tenant_id, allow_cli_mappings, key_id);
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = normalize_alias_key(requested, alias_map.as_ref());
    while let Some(target) = alias_map.as_ref().and_then(|map| map.get(&current)) {
        if seen.contains(&current) {
            let mut path = chain.clone();
            path.push(current.clone());
            return Err(format!("routing alias cycle: {}", path.join(" -> ")));
        }
        if chain.len() >= 16 {
            let mut path = chain.clone();
            path.push(current.clone());
            return Err(format!(
                "routing alias depth exceeded: {}",
                path.join(" -> ")
            ));
        }
        seen.insert(current.clone());
        chain.push(current.clone());
        current = target.clone();
    }
    Ok((current, chain))
}

/// Resolves one requested name to its alias target for pre-routing policy.
pub fn resolve_alias_target(
    snapshot: &RouteSnapshot,
    tenant_id: Option<&str>,
    requested: &str,
    allow_cli_mappings: bool,
    key_id: Option<&str>,
) -> String {
    resolve_alias(snapshot, tenant_id, requested, allow_cli_mappings, key_id)
        .map(|(model, _)| model)
        .unwrap_or_else(|_| requested.to_owned())
}

/// Bounded LRU of rotation cursors, keyed by tenant/provider/model scope.
#[derive(Debug, Default)]
struct LruRoundRobin {
    states: HashMap<String, RoundRobinState>,
    order: VecDeque<String>,
}

impl LruRoundRobin {
    fn get_or_create(&mut self, key: &str) -> &mut RoundRobinState {
        if self.states.contains_key(key) {
            self.order.retain(|existing| existing != key);
            self.order.push_back(key.to_owned());
            return self.states.get_mut(key).expect("state exists");
        }
        if self.states.len() >= MAX_ROUND_ROBIN_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.states.remove(&oldest);
            }
        }
        self.states
            .insert(key.to_owned(), RoundRobinState::default());
        self.order.push_back(key.to_owned());
        self.states.get_mut(key).expect("state inserted")
    }

    fn get(&self, key: &str) -> Option<&RoundRobinState> {
        self.states.get(key)
    }

    fn len(&self) -> usize {
        self.states.len()
    }
}

struct MatchingResolution {
    resolved_model: String,
    chain: Vec<String>,
    matching: Vec<RouteCandidate>,
    unmatched_members: Vec<String>,
    fusion: Option<FusionPlan>,
}

pub struct RoutingEngine {
    admission: Arc<dyn AdmissionController>,
    combo_cursors: Mutex<LruRoundRobin>,
    provider_cursors: Mutex<LruRoundRobin>,
    reservations: ReservationManager,
    eligibility: EligibilityEvaluator,
}

impl RoutingEngine {
    pub fn new(admission: Arc<dyn AdmissionController>) -> Self {
        Self {
            admission,
            combo_cursors: Mutex::new(LruRoundRobin::default()),
            provider_cursors: Mutex::new(LruRoundRobin::default()),
            reservations: ReservationManager::new(),
            eligibility: EligibilityEvaluator,
        }
    }

    pub fn round_robin_entries(&self) -> (usize, usize) {
        (
            self.combo_cursors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            self.provider_cursors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
        )
    }

    pub async fn account_inflight_snapshot(&self) -> HashMap<String, i64> {
        self.admission.snapshot_account_inflight().await
    }

    fn resolve_provider_routing<'a>(
        snapshot: &'a RouteSnapshot,
        provider_id: &str,
        tenant_id: Option<&str>,
    ) -> Option<&'a ProviderRoutingSetting> {
        let routing = snapshot.provider_routing.as_ref()?;
        let tenant_key = tenant_id.unwrap_or("__global__");
        routing
            .get(tenant_key)
            .and_then(|bucket| bucket.get(provider_id))
            .or_else(|| {
                routing
                    .get("__global__")
                    .and_then(|bucket| bucket.get(provider_id))
            })
    }

    fn reorder_run(
        &self,
        run: &[RouteCandidate],
        settings: Option<&ProviderRoutingSetting>,
        tenant_id: Option<&str>,
        advance: bool,
    ) -> Vec<RouteCandidate> {
        let Some(settings) = settings else {
            return run.to_vec();
        };
        if !settings.enabled || settings.strategy == ProviderRoutingStrategy::Fallback {
            return run.to_vec();
        }
        let Some(first) = run.first() else {
            return Vec::new();
        };
        let key = format!(
            "{}::{}",
            tenant_id.unwrap_or("__global__"),
            first.provider_id
        );
        let mut cursors = self
            .provider_cursors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let index = if advance {
            cursors
                .get_or_create(&key)
                .next_index(run.len(), settings.rotate_count, true)
        } else {
            cursors
                .get(&key)
                .cloned()
                .and_then(|mut state| state.next_index(run.len(), settings.rotate_count, false))
        };
        let Some(index) = index else {
            return run.to_vec();
        };
        if index == 0 {
            return run.to_vec();
        }
        let mut reordered = Vec::with_capacity(run.len());
        reordered.extend_from_slice(&run[index..]);
        reordered.extend_from_slice(&run[..index]);
        reordered
    }

    fn apply_provider_routing(
        &self,
        eligible: &[RouteCandidate],
        snapshot: &RouteSnapshot,
        tenant_id: Option<&str>,
        advance: bool,
    ) -> Vec<RouteCandidate> {
        if eligible.len() <= 1 || snapshot.provider_routing.is_none() {
            return eligible.to_vec();
        }
        let mut result = Vec::with_capacity(eligible.len());
        let mut index = 0;
        while index < eligible.len() {
            let current = &eligible[index];
            let run_key = format!("{}::{}", current.provider_id, current.model_id);
            let mut end = index + 1;
            while end < eligible.len()
                && format!("{}::{}", eligible[end].provider_id, eligible[end].model_id) == run_key
            {
                end += 1;
            }
            let run = &eligible[index..end];
            if run.len() > 1 {
                let settings =
                    Self::resolve_provider_routing(snapshot, &current.provider_id, tenant_id);
                result.extend(self.reorder_run(run, settings, tenant_id, advance));
            } else {
                result.extend_from_slice(run);
            }
            index = end;
        }
        result
    }

    fn search_fallback_candidates(
        &self,
        snapshot: &RouteSnapshot,
        tenant_id: Option<&str>,
        advance: bool,
    ) -> Vec<RouteCandidate> {
        let rank = |provider: &str| {
            SEARCH_PROVIDER_ORDER
                .iter()
                .position(|name| *name == provider.to_ascii_lowercase())
                .unwrap_or(SEARCH_PROVIDER_ORDER.len())
        };
        let mut ranked: Vec<RouteCandidate> = snapshot
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.service_kind == ServiceKind::Websearch
                    && (candidate.tenant_id.is_none()
                        || candidate.tenant_id.as_deref() == tenant_id)
            })
            .cloned()
            .collect();
        ranked.sort_by_key(|candidate| rank(&candidate.provider_id));
        let decisions: Vec<(EligibilityDecision, RouteCandidate)> = ranked
            .into_iter()
            .map(|candidate| (self.eligibility.evaluate(&candidate), candidate))
            .filter(|(decision, _)| decision.eligible)
            .collect();
        let mut ordered: Vec<RouteCandidate> = decisions
            .iter()
            .filter(|(decision, _)| decision.reason != EligibilityReason::Cooldown)
            .map(|(_, candidate)| candidate.clone())
            .collect();
        ordered.extend(
            decisions
                .iter()
                .filter(|(decision, _)| decision.reason == EligibilityReason::Cooldown)
                .map(|(_, candidate)| candidate.clone()),
        );
        let ordered = self.apply_provider_routing(&ordered, snapshot, tenant_id, advance);
        ordered
            .into_iter()
            .map(|mut candidate| {
                candidate.search_route = Some(SearchRoute::Fallback);
                candidate
            })
            .collect()
    }

    /// Resolves the requested name to a bare target, expands a combo, and
    /// returns candidates in plan order.
    fn resolve_matching_candidates(
        &self,
        requested_model: &str,
        snapshot: &RouteSnapshot,
        tenant_id: Option<&str>,
        allow_cli_mappings: bool,
        key_id: Option<&str>,
        advance: bool,
    ) -> Result<MatchingResolution, GatewayError> {
        let safe_resolve = |name: &str| {
            resolve_alias(snapshot, tenant_id, name, allow_cli_mappings, key_id)
                .map_err(|_| model_not_found_error(requested_model, &[]))
        };
        let (resolved_model, chain) = safe_resolve(requested_model)?;
        let combo_map = tenant_id.and_then(|tenant| snapshot.combos.get(tenant));
        let combo = combo_map.and_then(|map| map.get(&resolved_model));

        fn expand_member(
            name: &str,
            seen: &BTreeSet<String>,
            combo_map: Option<&HashMap<String, ComboDefinition>>,
            safe_resolve: &dyn Fn(&str) -> Option<String>,
        ) -> Vec<String> {
            if seen.contains(name) || seen.len() >= 16 {
                return Vec::new();
            }
            let mut next = seen.clone();
            next.insert(name.to_owned());
            let Some(alias_model) = safe_resolve(name) else {
                return Vec::new();
            };
            let nested = combo_map.and_then(|map| map.get(&alias_model));
            match nested {
                None => vec![alias_model],
                Some(nested) => nested
                    .members
                    .iter()
                    .flat_map(|member| expand_member(member, &next, combo_map, safe_resolve))
                    .collect(),
            }
        }

        let safe_resolve_name = |name: &str| {
            resolve_alias(snapshot, tenant_id, name, allow_cli_mappings, key_id)
                .ok()
                .map(|(model, _)| model)
        };
        let raw_model_ids: Vec<String> = match combo {
            Some(combo) => {
                let mut seen = BTreeSet::new();
                seen.insert(resolved_model.clone());
                combo
                    .members
                    .iter()
                    .flat_map(|member| expand_member(member, &seen, combo_map, &safe_resolve_name))
                    .collect()
            }
            None => vec![resolved_model.clone()],
        };
        let mut seen_ids = BTreeSet::new();
        let model_ids: Vec<String> = raw_model_ids
            .into_iter()
            .filter(|id| seen_ids.insert(id.clone()))
            .collect();

        let mut matching: Vec<RouteCandidate> = model_ids
            .iter()
            .flat_map(|id| candidates_for_model(snapshot, id, tenant_id))
            .collect();
        let mut seen_candidates = BTreeSet::new();
        matching.retain(|candidate| seen_candidates.insert(candidate_identity(candidate)));

        let mut unmatched_members = Vec::new();
        if let Some(combo) = combo {
            let per_id: Vec<(String, Vec<RouteCandidate>)> = model_ids
                .iter()
                .map(|id| (id.clone(), candidates_for_model(snapshot, id, tenant_id)))
                .collect();
            unmatched_members = per_id
                .iter()
                .filter(|(_, group)| group.is_empty())
                .map(|(id, _)| id.clone())
                .collect();
            let groups: Vec<Vec<RouteCandidate>> = per_id
                .into_iter()
                .map(|(_, group)| group)
                .filter(|group| !group.is_empty())
                .collect();
            if combo.strategy == ComboStrategy::RoundRobin && groups.len() > 1 {
                let heads: Vec<RouteCandidate> = groups
                    .iter()
                    .filter_map(|group| group.first().cloned())
                    .collect();
                let key = format!("{}::{}", tenant_id.unwrap_or("__global__"), resolved_model);
                let mut cursors = self
                    .combo_cursors
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let index = if advance {
                    cursors.get_or_create(&key).next_index(heads.len(), 1, true)
                } else {
                    cursors
                        .get(&key)
                        .cloned()
                        .and_then(|mut state| state.next_index(heads.len(), 1, false))
                }
                .unwrap_or(0);
                matching = groups[index..]
                    .iter()
                    .chain(groups[..index].iter())
                    .flatten()
                    .cloned()
                    .collect();
            } else {
                matching = groups.into_iter().flatten().collect();
            }
        }

        if matching.is_empty() {
            return Err(model_not_found_error(requested_model, &model_ids));
        }
        let owners: BTreeSet<String> = matching
            .iter()
            .map(|candidate| candidate.provider_id.clone())
            .collect();
        if owners.len() > 1 && !resolved_model.contains('/') && combo.is_none() {
            return Err(ambiguous_model_error(
                requested_model,
                &owners.into_iter().collect::<Vec<_>>(),
            ));
        }
        let fusion = match combo {
            Some(combo) if combo.strategy == ComboStrategy::Fusion && model_ids.len() > 1 => {
                Some(FusionPlan {
                    panel: model_ids.clone(),
                    judge: model_ids[0].clone(),
                })
            }
            _ => None,
        };
        Ok(MatchingResolution {
            resolved_model,
            chain,
            matching,
            unmatched_members,
            fusion,
        })
    }

    /// Plans a route: alias/combo resolution, eligibility, ordering, rotation.
    pub fn plan(
        &self,
        snapshot: &RouteSnapshot,
        input: PlanInput<'_>,
    ) -> Result<RoutePlan, GatewayError> {
        let tenant_id = input.tenant_id;
        let resolution = self.resolve_matching_candidates(
            input.requested_model,
            snapshot,
            tenant_id,
            input.allow_cli_mappings,
            input.key_id,
            input.advance,
        )?;
        let resolved_model = resolution.resolved_model;
        let matching = resolution.matching;
        let fusion = resolution.fusion;
        let decisions: Vec<(EligibilityDecision, RouteCandidate)> = matching
            .iter()
            .map(|candidate| (self.eligibility.evaluate(candidate), candidate.clone()))
            .collect();
        let mut eligible: Vec<RouteCandidate> = decisions
            .iter()
            .filter(|(decision, _)| decision.eligible)
            .map(|(_, candidate)| candidate.clone())
            .collect();
        if eligible.is_empty() {
            let hard_cooling = decisions
                .iter()
                .any(|(decision, _)| decision.reason == EligibilityReason::CooldownHard);
            if hard_cooling {
                return Err(accounts_rate_limited_error(
                    input.requested_model,
                    &resolved_model,
                ));
            }
            let reasons: Vec<&str> = decisions
                .iter()
                .map(|(decision, _)| decision.reason.as_str())
                .collect();
            return Err(accounts_unavailable_error(input.requested_model, &reasons));
        }
        let healthy_count = decisions
            .iter()
            .filter(|(decision, _)| {
                decision.eligible && decision.reason != EligibilityReason::Cooldown
            })
            .count();
        if healthy_count == 0 {
            return Err(accounts_rate_limited_error(
                input.requested_model,
                &resolved_model,
            ));
        }
        let cooling: HashSet<String> = decisions
            .iter()
            .filter(|(decision, _)| {
                decision.eligible && decision.reason == EligibilityReason::Cooldown
            })
            .map(|(_, candidate)| candidate_identity(candidate))
            .collect();
        if !cooling.is_empty() && cooling.len() < eligible.len() {
            let (healthy, cooling_candidates): (Vec<_>, Vec<_>) = eligible
                .into_iter()
                .partition(|candidate| !cooling.contains(&candidate_identity(candidate)));
            eligible = healthy;
            eligible.extend(cooling_candidates);
        }
        if let Some(required) = input.required_capabilities {
            if !required.is_empty() {
                eligible.retain(|candidate| candidate_supports_request(candidate, required));
                if eligible.is_empty() {
                    let names: Vec<String> =
                        required.iter().map(RequiredCapability::as_str).collect();
                    let mut details = Map::new();
                    details.insert("capability".into(), json!(names.join(", ")));
                    return Err(GatewayError::new(
                        GatewayErrorCode::CapabilityUnsupported,
                        400,
                        format!("Capability '{}' not supported", names.join(", ")),
                        details,
                    ));
                }
            }
        }
        eligible = self.apply_provider_routing(&eligible, snapshot, tenant_id, input.advance);
        // Re-assert the cooling order: provider rotation is health-blind by
        // design, so it can float a cooling account back to the front.
        if !cooling.is_empty() && cooling.len() < eligible.len() {
            let (healthy, cooling_candidates): (Vec<_>, Vec<_>) = eligible
                .into_iter()
                .partition(|candidate| !cooling.contains(&candidate_identity(candidate)));
            eligible = healthy;
            eligible.extend(cooling_candidates);
        }
        if input.web_search {
            let mut search_candidates: Vec<RouteCandidate> = eligible
                .into_iter()
                .map(|mut candidate| {
                    if candidate.service_kind == ServiceKind::Llm
                        && candidate
                            .capability_profile
                            .get("webSearch")
                            .copied()
                            .unwrap_or(false)
                    {
                        candidate.search_route = Some(SearchRoute::Native);
                    }
                    candidate
                })
                .collect();
            search_candidates.extend(self.search_fallback_candidates(
                snapshot,
                tenant_id,
                input.advance,
            ));
            eligible = search_candidates;
        }
        let chosen = eligible
            .first()
            .cloned()
            .ok_or_else(|| accounts_unavailable_error(input.requested_model, &[]))?;
        Ok(RoutePlan {
            revision: snapshot.revision,
            candidates: eligible,
            requested_model: input.requested_model.to_owned(),
            resolved_model,
            provider_id: chosen.provider_id,
            fusion,
        })
    }

    /// Read-only evaluation of the same pipeline for the console simulator.
    pub fn simulate(
        &self,
        requested_model: &str,
        endpoint: &str,
        snapshot: &RouteSnapshot,
        tenant_id: Option<&str>,
    ) -> Result<RouteSimulationResult, GatewayError> {
        let resolution = self.resolve_matching_candidates(
            requested_model,
            snapshot,
            tenant_id,
            false,
            None,
            false,
        )?;
        let resolved_model = resolution.resolved_model;
        let chain = resolution.chain;
        let matching = resolution.matching;
        let unmatched_members = resolution.unmatched_members;
        let fusion = resolution.fusion;
        let endpoint_service_kind = service_kind_for_endpoint(endpoint);
        let decisions: Vec<(EligibilityDecision, RouteCandidate)> = matching
            .iter()
            .map(|candidate| (self.eligibility.evaluate(candidate), candidate.clone()))
            .collect();
        let cooling: HashSet<String> = decisions
            .iter()
            .filter(|(decision, _)| {
                decision.eligible && decision.reason == EligibilityReason::Cooldown
            })
            .map(|(_, candidate)| candidate_identity(candidate))
            .collect();
        let eligible_canonical: Vec<RouteCandidate> = decisions
            .iter()
            .filter(|(decision, _)| decision.eligible)
            .map(|(_, candidate)| candidate.clone())
            .collect();
        let mut ordered_eligible = eligible_canonical.clone();
        if !cooling.is_empty() && cooling.len() < ordered_eligible.len() {
            let (healthy, cooling_candidates): (Vec<_>, Vec<_>) = ordered_eligible
                .into_iter()
                .partition(|candidate| !cooling.contains(&candidate_identity(candidate)));
            ordered_eligible = healthy;
            ordered_eligible.extend(cooling_candidates);
        }
        let family_serving: Vec<RouteCandidate> = ordered_eligible
            .into_iter()
            .filter(|candidate| candidate.service_kind == endpoint_service_kind)
            .collect();
        let mut ordered = self.apply_provider_routing(&family_serving, snapshot, tenant_id, false);
        if !cooling.is_empty() && cooling.len() < ordered.len() {
            let (healthy, cooling_candidates): (Vec<_>, Vec<_>) = ordered
                .into_iter()
                .partition(|candidate| !cooling.contains(&candidate_identity(candidate)));
            ordered = healthy;
            ordered.extend(cooling_candidates);
        }
        let healthy_count = decisions
            .iter()
            .filter(|(decision, _)| {
                decision.eligible && decision.reason != EligibilityReason::Cooldown
            })
            .count();
        let outcome = if eligible_canonical.is_empty() {
            if decisions
                .iter()
                .any(|(decision, _)| decision.reason == EligibilityReason::CooldownHard)
            {
                RouteSimulationOutcome::AccountsRateLimited
            } else {
                RouteSimulationOutcome::AccountsUnavailable
            }
        } else if healthy_count == 0 {
            RouteSimulationOutcome::AccountsRateLimited
        } else if ordered.is_empty() {
            RouteSimulationOutcome::ServiceKindUnsupported
        } else {
            RouteSimulationOutcome::Dispatchable
        };
        let rotation_active = ordered.len() > 1;
        let selected = if outcome == RouteSimulationOutcome::Dispatchable
            && !rotation_active
            && fusion.is_none()
        {
            ordered.first().cloned()
        } else {
            None
        };
        let strategy = if fusion.is_some() {
            "fusion".to_owned()
        } else {
            ordered
                .first()
                .and_then(|candidate| {
                    Self::resolve_provider_routing(snapshot, &candidate.provider_id, tenant_id)
                })
                .map(|setting| setting.strategy.as_str().to_owned())
                .unwrap_or_else(|| "fallback".into())
        };
        let combo_strategy = tenant_id
            .and_then(|tenant| snapshot.combos.get(tenant))
            .and_then(|map| map.get(&resolved_model))
            .map(|combo| combo.strategy);
        let strategy_source = if fusion.is_some() || combo_strategy.is_some() {
            "combo"
        } else if strategy == "fallback" {
            "default"
        } else {
            "provider"
        };
        let ordered_set: HashSet<String> = ordered.iter().map(candidate_identity).collect();
        let project = |candidate: &RouteCandidate, decision: Option<&EligibilityDecision>| {
            let reason = decision
                .map(|decision| decision.reason)
                .unwrap_or(EligibilityReason::Healthy);
            let endpoint_supported = candidate.service_kind == endpoint_service_kind;
            RouteSimulationCandidate {
                candidate: candidate.clone(),
                eligible: decision.map(|decision| decision.eligible).unwrap_or(false)
                    && endpoint_supported,
                reason,
                endpoint_supported,
                provider_routing: Self::resolve_provider_routing(
                    snapshot,
                    &candidate.provider_id,
                    tenant_id,
                )
                .cloned(),
            }
        };
        let mut projected: Vec<RouteSimulationCandidate> = ordered
            .iter()
            .map(|candidate| {
                let decision = decisions
                    .iter()
                    .find(|(_, existing)| {
                        existing.provider_id == candidate.provider_id
                            && existing.model_id == candidate.model_id
                            && existing.provider_account_id == candidate.provider_account_id
                    })
                    .map(|(decision, _)| decision);
                project(candidate, decision)
            })
            .collect();
        for (decision, candidate) in &decisions {
            let key = candidate_identity(candidate);
            if !ordered_set.contains(&key) {
                projected.push(project(candidate, Some(decision)));
            }
        }
        Ok(RouteSimulationResult {
            requested_model: requested_model.to_owned(),
            resolved_model,
            resolution_chain: chain,
            revision: snapshot.revision,
            endpoint_service_kind,
            outcome,
            candidates: projected,
            selected,
            rotation_active,
            strategy,
            strategy_source,
            fusion,
            unmatched_members,
        })
    }

    /// Reserves the first candidate that admits capacity.
    pub async fn reserve(&self, plan: &RoutePlan) -> Result<Reservation, GatewayError> {
        self.reserve_with_ttl(plan, 30_000).await
    }

    pub async fn reserve_with_ttl(
        &self,
        plan: &RoutePlan,
        ttl_ms: i64,
    ) -> Result<Reservation, GatewayError> {
        for candidate in &plan.candidates {
            if self.admission.admit(candidate).await.admitted {
                return Ok(self.reservations.acquire(candidate.clone(), ttl_ms));
            }
        }
        Err(capacity_exhausted_error())
    }

    pub async fn release(&self, reservation: &Reservation) {
        self.admission.release(reservation).await;
        self.reservations.release(&reservation.lease_id);
    }

    pub fn reservation(&self, lease_id: &str) -> Option<Reservation> {
        self.reservations.get(lease_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CapabilityProfile, HealthStatus, InMemoryAdmissionController, RouteCandidate,
    };
    use keyla_core::WireFamily;

    fn candidate(
        provider: &str,
        model: &str,
        account: &str,
        tenant: Option<&str>,
    ) -> RouteCandidate {
        RouteCandidate::new(
            provider,
            model,
            WireFamily::Chat,
            ServiceKind::Llm,
            "/v1/chat/completions",
            CapabilityProfile::new(),
        )
        .with_account(account)
        .with_tenant(tenant.map(str::to_owned))
    }

    fn snapshot_of(candidates: Vec<RouteCandidate>) -> RouteSnapshot {
        RouteSnapshot {
            revision: 7,
            candidates,
            ..RouteSnapshot::default()
        }
    }

    fn engine() -> RoutingEngine {
        RoutingEngine::new(Arc::new(InMemoryAdmissionController::new()))
    }

    #[test]
    fn alias_chain_resolves_and_detects_cycles() {
        let mut snapshot = snapshot_of(vec![]);
        snapshot.aliases.insert(
            "t".into(),
            [
                ("fast".to_owned(), "gpt-test".to_owned()),
                ("a".to_owned(), "b".to_owned()),
                ("b".to_owned(), "a".to_owned()),
            ]
            .into_iter()
            .collect(),
        );
        let (model, chain) = resolve_alias(&snapshot, Some("t"), "fast", false, None).unwrap();
        assert_eq!(model, "gpt-test");
        assert_eq!(chain, vec!["fast"]);
        assert!(resolve_alias(&snapshot, Some("t"), "a", false, None).is_err());
    }

    #[test]
    fn plan_rejects_ambiguous_bare_models_across_providers() {
        let snapshot = snapshot_of(vec![
            candidate("openai", "gpt-test", "a", None),
            candidate("azure", "gpt-test", "b", None),
        ]);
        let error = engine()
            .plan(&snapshot, PlanInput::new("gpt-test"))
            .unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::AmbiguousModel);
    }

    #[test]
    fn plan_resolves_provider_namespaced_models() {
        let snapshot = snapshot_of(vec![
            candidate("openai", "gpt-test", "a", None),
            candidate("azure", "gpt-test", "b", None),
        ]);
        let plan = engine()
            .plan(&snapshot, PlanInput::new("azure/gpt-test"))
            .unwrap();
        assert_eq!(plan.provider_id, "azure");
        assert_eq!(plan.candidates.len(), 1);
    }

    #[test]
    fn plan_resolves_bare_model_ids_containing_slash() {
        let snapshot = snapshot_of(vec![candidate("valen", "Flara/mercury-3", "a", None)]);
        let plan = engine()
            .plan(&snapshot, PlanInput::new("Flara/mercury-3"))
            .unwrap();
        assert_eq!(plan.resolved_model, "Flara/mercury-3");
        assert_eq!(plan.provider_id, "valen");
    }

    #[test]
    fn plan_prefers_provider_prefix_over_a_full_model_id_collision() {
        let snapshot = snapshot_of(vec![
            candidate("valen", "Flara/mercury-3", "a", None),
            candidate("Flara", "mercury-3", "b", None),
        ]);
        let plan = engine()
            .plan(&snapshot, PlanInput::new("Flara/mercury-3"))
            .unwrap();
        assert_eq!(plan.provider_id, "Flara");
    }

    #[test]
    fn plan_reports_missing_model_with_resolved_aliases() {
        let mut snapshot = snapshot_of(vec![]);
        snapshot.aliases.insert(
            "t".into(),
            [("fast".to_owned(), "gone".to_owned())]
                .into_iter()
                .collect(),
        );
        let mut input = PlanInput::new("fast");
        input.tenant_id = Some("t");
        let error = engine().plan(&snapshot, input).unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::ModelNotFound);
        assert!(error.message.contains("'gone'"));
    }

    #[test]
    fn cooling_accounts_are_ordered_last_and_exclusively_cooling_returns_429() {
        let mut cooling = candidate("openai", "gpt-test", "a", None);
        cooling.health_status = Some(HealthStatus::Cooldown);
        let snapshot = snapshot_of(vec![
            cooling.clone(),
            candidate("openai", "gpt-test", "b", None),
        ]);
        let plan = engine()
            .plan(&snapshot, PlanInput::new("gpt-test"))
            .unwrap();
        assert_eq!(plan.candidates[0].provider_account_id.as_deref(), Some("b"));
        assert_eq!(plan.candidates[1].provider_account_id.as_deref(), Some("a"));

        let only_cooling = snapshot_of(vec![cooling]);
        let error = engine()
            .plan(&only_cooling, PlanInput::new("gpt-test"))
            .unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::AccountsRateLimited);
    }

    #[test]
    fn hard_cooldown_excludes_and_reports_rate_limited() {
        let mut hard = candidate("openai", "gpt-test", "a", None);
        hard.health_status = Some(HealthStatus::Cooldown);
        hard.cooldown_kind = Some(crate::model::CooldownKind::Hard);
        let error = engine()
            .plan(&snapshot_of(vec![hard]), PlanInput::new("gpt-test"))
            .unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::AccountsRateLimited);
    }

    #[test]
    fn combos_expand_and_rotate() {
        let mut snapshot = snapshot_of(vec![
            candidate("openai", "model-a", "a", Some("t")),
            candidate("openai", "model-b", "b", Some("t")),
        ]);
        snapshot.combos.insert(
            "t".into(),
            [(
                "best".to_owned(),
                ComboDefinition {
                    members: vec!["model-a".into(), "model-b".into()],
                    strategy: ComboStrategy::RoundRobin,
                },
            )]
            .into_iter()
            .collect(),
        );
        let engine = engine();
        let mut input = PlanInput::new("best");
        input.tenant_id = Some("t");
        let first = engine.plan(&snapshot, input).unwrap();
        assert_eq!(first.candidates[0].model_id, "model-a");
        let second = engine.plan(&snapshot, input).unwrap();
        assert_eq!(second.candidates[0].model_id, "model-b");
        // A peek never advances the cursor.
        let mut peek = input;
        peek.advance = false;
        let peeked = engine.plan(&snapshot, peek).unwrap();
        assert_eq!(peeked.candidates[0].model_id, "model-a");
        let after = engine.plan(&snapshot, input).unwrap();
        assert_eq!(after.candidates[0].model_id, "model-a");
    }

    #[test]
    fn capability_filter_rejects_unsupported_requirements() {
        let snapshot = snapshot_of(vec![candidate("openai", "gpt-test", "a", None)]);
        let mut input = PlanInput::new("gpt-test");
        let required = [RequiredCapability::Tools];
        input.required_capabilities = Some(&required);
        let error = engine().plan(&snapshot, input).unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::CapabilityUnsupported);
    }

    #[test]
    fn provider_round_robin_rotates_only_within_one_provider_model_run() {
        let mut snapshot = snapshot_of(vec![
            candidate("openai", "gpt-test", "a", Some("t")),
            candidate("openai", "gpt-test", "b", Some("t")),
        ]);
        snapshot.provider_routing = Some(
            [(
                "t".to_owned(),
                [(
                    "openai".to_owned(),
                    ProviderRoutingSetting {
                        strategy: ProviderRoutingStrategy::RoundRobin,
                        rotate_count: 1,
                        max_inflight: None,
                        credit_limit_enabled: None,
                        credit_limit: None,
                        enabled: true,
                        user_agent: None,
                        bypass_proxy: false,
                    },
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
        );
        let engine = engine();
        let mut input = PlanInput::new("gpt-test");
        input.tenant_id = Some("t");
        let first = engine.plan(&snapshot, input).unwrap();
        let second = engine.plan(&snapshot, input).unwrap();
        assert_ne!(
            first.candidates[0].provider_account_id,
            second.candidates[0].provider_account_id
        );
    }

    #[test]
    fn simulate_is_read_only_and_reports_rotation() {
        let snapshot = snapshot_of(vec![
            candidate("openai", "gpt-test", "a", None),
            candidate("openai", "gpt-test", "b", None),
        ]);
        let engine = engine();
        let result = engine
            .simulate("gpt-test", "chat.completions", &snapshot, None)
            .unwrap();
        assert_eq!(result.outcome, RouteSimulationOutcome::Dispatchable);
        assert!(result.rotation_active);
        assert!(result.selected.is_none());
        let (combo, provider) = engine.round_robin_entries();
        assert_eq!((combo, provider), (0, 0));

        let single = snapshot_of(vec![candidate("openai", "gpt-test", "a", None)]);
        let result = engine
            .simulate("gpt-test", "chat.completions", &single, None)
            .unwrap();
        assert!(!result.rotation_active);
        assert!(result.selected.is_some());
    }

    #[tokio::test]
    async fn two_accounts_with_two_slots_each_admit_four_requests() {
        let mut first = candidate("openai", "gpt-test", "a", None);
        first.max_inflight = Some(2);
        let mut second = candidate("openai", "gpt-test", "b", None);
        second.max_inflight = Some(2);
        let snapshot = snapshot_of(vec![first, second]);
        let engine = engine();
        let plan = engine.plan(&snapshot, PlanInput::new("gpt-test")).unwrap();

        let mut reservations = Vec::new();
        for _ in 0..4 {
            reservations.push(engine.reserve(&plan).await.expect("slot available"));
        }
        let mut by_account: HashMap<String, usize> = HashMap::new();
        for reservation in &reservations {
            *by_account
                .entry(
                    reservation
                        .candidate
                        .provider_account_id
                        .clone()
                        .unwrap_or_default(),
                )
                .or_default() += 1;
        }
        assert_eq!(by_account.get("a"), Some(&2));
        assert_eq!(by_account.get("b"), Some(&2));
        assert!(
            engine.reserve(&plan).await.is_err(),
            "the fifth request must not exceed either account ceiling"
        );
        for reservation in reservations {
            engine.release(&reservation).await;
        }
    }

    #[tokio::test]
    async fn reserve_admits_first_available_candidate_then_releases() {
        let mut first = candidate("openai", "gpt-test", "a", None);
        first.max_inflight = Some(0);
        let mut second = candidate("openai", "gpt-test", "b", None);
        second.max_inflight = Some(5);
        let snapshot = snapshot_of(vec![first, second]);
        let engine = engine();
        let plan = engine.plan(&snapshot, PlanInput::new("gpt-test")).unwrap();
        let reservation = engine.reserve(&plan).await.unwrap();
        assert_eq!(
            reservation.candidate.provider_account_id.as_deref(),
            Some("b")
        );
        engine.release(&reservation).await;
        assert!(engine.reservation(&reservation.lease_id).is_none());
    }
}
