//! The API-key model-access rule: one mode, one list.
//! Port of `src/security/model-access-rule.ts`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelAccessMode {
    Whitelist,
    Blacklist,
}

impl ModelAccessMode {
    pub fn parse(value: Option<&str>) -> Self {
        if value == Some("blacklist") {
            Self::Blacklist
        } else {
            Self::Whitelist
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRejectionReason {
    ModelDenied,
    ModelNotAllowed,
}

impl ModelRejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModelDenied => "model-denied",
            Self::ModelNotAllowed => "model-not-allowed",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModelAccessPolicy {
    pub model_access_mode: Option<ModelAccessMode>,
    pub model_list: Option<Vec<String>>,
}

fn list_includes(list: Option<&Vec<String>>, value: &str) -> bool {
    list.is_some_and(|list| list.iter().any(|entry| entry == value))
}

fn bare_model_id(target_model: &str) -> &str {
    match target_model.rfind('/') {
        Some(index) => &target_model[index + 1..],
        None => target_model,
    }
}

/// Single source of truth for the API-key model access rule. Returns the
/// rejection reason, or `None` when the target model is authorized.
pub fn model_rejection_reason(
    policy: &ModelAccessPolicy,
    target_model: &str,
    target_provider: Option<&str>,
    requested_model: Option<&str>,
) -> Option<ModelRejectionReason> {
    let bare = bare_model_id(target_model);
    let qualified = target_provider.map(|provider| format!("{provider}/{bare}"));
    let mut names = vec![target_model.to_owned(), bare.to_owned()];
    if let Some(qualified) = qualified {
        names.push(qualified);
    }
    if let Some(requested) = requested_model {
        if requested != target_model {
            names.push(requested.to_owned());
        }
    }
    let list = policy.model_list.as_ref();
    if policy.model_access_mode == Some(ModelAccessMode::Blacklist) {
        return names
            .iter()
            .any(|name| list_includes(list, name))
            .then_some(ModelRejectionReason::ModelDenied);
    }
    if list.is_none_or(Vec::is_empty) {
        return None;
    }
    if names.iter().any(|name| list_includes(list, name)) {
        return None;
    }
    Some(ModelRejectionReason::ModelNotAllowed)
}

pub fn is_model_allowed(
    policy: &ModelAccessPolicy,
    target_model: &str,
    target_provider: Option<&str>,
    requested_model: Option<&str>,
) -> bool {
    model_rejection_reason(policy, target_model, target_provider, requested_model).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(mode: ModelAccessMode, list: &[&str]) -> ModelAccessPolicy {
        ModelAccessPolicy {
            model_access_mode: Some(mode),
            model_list: Some(list.iter().map(|entry| (*entry).to_owned()).collect()),
        }
    }

    #[test]
    fn whitelist_empty_allows_everything() {
        let policy = make_policy(ModelAccessMode::Whitelist, &[]);
        assert!(is_model_allowed(&policy, "gpt-test", None, None));
    }

    #[test]
    fn whitelist_matches_bare_qualified_and_requested_names() {
        let policy = make_policy(ModelAccessMode::Whitelist, &["gpt-test"]);
        assert!(is_model_allowed(&policy, "gpt-test", Some("openai"), None));
        assert!(is_model_allowed(
            &policy,
            "openai/gpt-test",
            Some("openai"),
            None
        ));
        assert!(is_model_allowed(
            &policy,
            "other/model",
            Some("other"),
            Some("gpt-test")
        ));
        assert_eq!(
            model_rejection_reason(&policy, "other/model", None, None),
            Some(ModelRejectionReason::ModelNotAllowed)
        );
    }

    #[test]
    fn blacklist_refuses_every_spelling() {
        let policy = make_policy(ModelAccessMode::Blacklist, &["fast", "gpt-test"]);
        assert_eq!(
            model_rejection_reason(&policy, "gpt-test", Some("openai"), None),
            Some(ModelRejectionReason::ModelDenied)
        );
        assert_eq!(
            model_rejection_reason(&policy, "other/model", None, Some("fast")),
            Some(ModelRejectionReason::ModelDenied)
        );
        assert!(is_model_allowed(&policy, "other/model", None, None));
        let empty = make_policy(ModelAccessMode::Blacklist, &[]);
        assert!(is_model_allowed(&empty, "anything", None, None));
    }
}
