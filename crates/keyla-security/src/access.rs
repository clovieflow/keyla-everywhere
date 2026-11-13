//! Authorization scopes and immutable access decisions.
//! Port of `src/security/access-control.ts`.

/// Closed set of authorization scopes.
pub const ACCESS_SCOPES: [&str; 10] = [
    "routing:invoke",
    "routing:cli_mapping",
    "search:invoke",
    "dashboard:read",
    "dashboard:write",
    "providers:read",
    "providers:write",
    "models:read",
    "models:write",
    "platform:admin",
];

/// Every scope a tenant API key may be granted, in display order.
pub const TENANT_KEY_SCOPES: [&str; 9] = [
    "routing:invoke",
    "routing:cli_mapping",
    "search:invoke",
    "dashboard:read",
    "dashboard:write",
    "providers:read",
    "providers:write",
    "models:read",
    "models:write",
];

pub fn is_valid_tenant_key_scope(scope: &str) -> bool {
    TENANT_KEY_SCOPES.contains(&scope)
}

/// Scopes a signed-in console session holds, per principal kind.
pub fn console_session_scopes(is_platform_admin: bool) -> Vec<&'static str> {
    if is_platform_admin {
        return vec![
            "dashboard:read",
            "dashboard:write",
            "providers:read",
            "providers:write",
            "models:read",
            "models:write",
            "platform:admin",
        ];
    }
    vec!["dashboard:read", "providers:read", "models:read"]
}

/// Immutable authorization decision snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub id: String,
    /// `None` for platform-admin cross-tenant operator sessions.
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
    pub admission_identity: String,
}

impl AccessDecision {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|existing| existing == scope)
    }

    pub fn require_scope(&self, scope: &str) -> Result<(), keyla_core::GatewayError> {
        if self.has_scope(scope) {
            return Ok(());
        }
        Err(keyla_core::GatewayError::new(
            keyla_core::GatewayErrorCode::PolicyRejected,
            403,
            format!("missing scope: {scope}"),
            serde_json::Map::new(),
        ))
    }
}

/// Creates an access decision. Tenant keys default to `routing:invoke` only;
/// the stored scope array is the whole truth.
pub fn create_access_decision(
    id: impl Into<String>,
    tenant_id: Option<String>,
    scopes: Vec<String>,
    admission_identity: Option<String>,
) -> AccessDecision {
    let id = id.into();
    let scopes = if scopes.is_empty() && tenant_id.is_some() {
        vec!["routing:invoke".to_owned()]
    } else {
        scopes
    };
    AccessDecision {
        admission_identity: admission_identity.unwrap_or_else(|| id.clone()),
        id,
        tenant_id,
        scopes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_keys_default_to_routing_invoke() {
        let decision = create_access_decision("k", Some("t".into()), Vec::new(), None);
        assert_eq!(decision.scopes, vec!["routing:invoke"]);
        assert_eq!(decision.admission_identity, "k");
    }

    #[test]
    fn stored_scopes_are_not_widened() {
        let decision =
            create_access_decision("k", Some("t".into()), vec!["dashboard:read".into()], None);
        assert_eq!(decision.scopes, vec!["dashboard:read"]);
        assert!(decision.has_scope("dashboard:read"));
        assert!(!decision.has_scope("routing:invoke"));
    }

    #[test]
    fn platform_admin_sessions_get_cross_tenant_scopes() {
        let scopes = console_session_scopes(true);
        assert!(scopes.contains(&"platform:admin"));
        let scopes = console_session_scopes(false);
        assert!(!scopes.contains(&"platform:admin"));
    }
}
