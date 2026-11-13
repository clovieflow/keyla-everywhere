//! Tenant-scoped Prompt Injection applied before a request is dispatched.
//!
//! The operator owns the injected text. It is appended to the canonical
//! trusted instruction block (`developer` by default, or `system`) and never
//! to a user message, so the gateway can distinguish policy injected by the
//! installation from content supplied by the caller.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use keyla_core::{CanonicalRequest, ContentPart};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptInjectionConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    prompt: String,
    #[serde(default)]
    target_models: Vec<String>,
    #[serde(default = "default_placement")]
    placement: String,
}

fn default_placement() -> String {
    "developer".to_owned()
}

impl PromptInjectionConfig {
    pub fn is_active(&self) -> bool {
        self.enabled && !self.prompt.trim().is_empty()
    }

    fn matches(&self, requested_model: &str, resolved_model: &str, provider_id: &str) -> bool {
        let qualified = format!("{provider_id}/{resolved_model}");
        self.target_models.is_empty()
            || self.target_models.iter().any(|target| {
                target == "*"
                    || target == requested_model
                    || target == resolved_model
                    || target == &qualified
            })
    }

    /// Applies the configured text to the trusted instruction block. The
    /// prompt is appended (not prepended) so an installation policy cannot
    /// silently erase the caller's own system/developer instructions.
    pub fn apply(&self, request: &mut CanonicalRequest, resolved_model: &str, provider_id: &str) {
        if !self.is_active() || !self.matches(&request.model, resolved_model, provider_id) {
            return;
        }
        let part = ContentPart::Text {
            text: self.prompt.trim().to_owned(),
        };
        if self.placement == "system" {
            request.system.get_or_insert_with(Vec::new).push(part);
        } else {
            request.instructions.get_or_insert_with(Vec::new).push(part);
        }
    }
}

struct Cached {
    at: Instant,
    config: PromptInjectionConfig,
}

/// Small per-process cache. Console writes invalidate naturally after TTL;
/// the request path must not issue a settings query for every model call.
#[derive(Clone)]
pub struct PromptInjectionCache {
    pool: PgPool,
    entries: Arc<Mutex<HashMap<String, Cached>>>,
}

impl PromptInjectionCache {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn config(&self, tenant_id: &str) -> PromptInjectionConfig {
        {
            let entries = self.entries.lock().await;
            if let Some(cached) = entries.get(tenant_id) {
                if cached.at.elapsed() < CACHE_TTL {
                    return cached.config.clone();
                }
            }
        }
        let stored: Option<Value> = sqlx::query_scalar(
            "SELECT preferences -> 'promptInjection'
             FROM console_settings WHERE tenant_id = $1::uuid",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        let config: PromptInjectionConfig = stored
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default();
        let mut entries = self.entries.lock().await;
        entries.insert(
            tenant_id.to_owned(),
            Cached {
                at: Instant::now(),
                config: config.clone(),
            },
        );
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyla_core::{CanonicalRequest, SourceSurface};

    fn request(model: &str) -> CanonicalRequest {
        CanonicalRequest {
            model: model.into(),
            system: None,
            instructions: None,
            messages: Vec::new(),
            tools: None,
            tool_choice: None,
            generation_controls: Default::default(),
            reasoning: None,
            response_format: None,
            cache_hint: None,
            conversation: None,
            metadata: None,
            provider_options: None,
            session_id: None,
            thread_id: None,
            window_id: None,
            turn_id: None,
            parent_turn_id: None,
            conversation_id: None,
            residency: None,
            stream: false,
            source_surface: SourceSurface::Chat,
        }
    }

    #[test]
    fn appends_to_instructions_for_matching_model() {
        let config = PromptInjectionConfig {
            enabled: true,
            prompt: "Be direct.".into(),
            target_models: vec!["gpt-test".into()],
            placement: "developer".into(),
        };
        let mut request = request("alias-test");
        config.apply(&mut request, "gpt-test", "openai");
        assert!(request.system.is_none());
        assert_eq!(
            request.instructions,
            Some(vec![ContentPart::Text {
                text: "Be direct.".into()
            }])
        );
    }

    #[test]
    fn ignores_disabled_or_non_matching_requests() {
        let disabled = PromptInjectionConfig {
            enabled: false,
            prompt: "ignored".into(),
            target_models: Vec::new(),
            placement: "developer".into(),
        };
        let mut request = request("gpt-test");
        disabled.apply(&mut request, "gpt-test", "openai");
        assert!(request.instructions.is_none());

        let configured = PromptInjectionConfig {
            enabled: true,
            prompt: "only this model".into(),
            target_models: vec!["other-model".into()],
            placement: "developer".into(),
        };
        configured.apply(&mut request, "gpt-test", "openai");
        assert!(request.instructions.is_none());
    }

    #[test]
    fn matches_the_qualified_provider_model() {
        let config = PromptInjectionConfig {
            enabled: true,
            prompt: "qualified".into(),
            target_models: vec!["openai/gpt-test".into()],
            placement: "developer".into(),
        };
        let mut request = request("gpt-test");
        config.apply(&mut request, "gpt-test", "openai");
        assert!(request.instructions.is_some());
    }

    #[test]
    fn empty_target_list_means_every_model() {
        let config = PromptInjectionConfig {
            enabled: true,
            prompt: "global".into(),
            target_models: Vec::new(),
            placement: "system".into(),
        };
        let mut request = request("anything");
        config.apply(&mut request, "resolved", "provider");
        assert_eq!(
            request.system,
            Some(vec![ContentPart::Text {
                text: "global".into()
            }])
        );
    }
}
