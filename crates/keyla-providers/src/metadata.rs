//! Built-in provider identity and routing defaults.
//! Port of `src/providers/provider-metadata.ts`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use keyla_core::{ServiceKind, WireFamily};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityProfile {
    /// Endpoint paths per wire family for providers whose base carries a
    /// non-standard prefix.
    pub chat: Option<&'static str>,
    pub responses: Option<&'static str>,
    pub messages: Option<&'static str>,
}

impl CompatibilityProfile {
    pub fn for_family(&self, family: WireFamily) -> Option<&'static str> {
        match family {
            WireFamily::Chat => self.chat,
            WireFamily::Responses => self.responses,
            WireFamily::Messages => self.messages,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderMetadata {
    pub id: &'static str,
    pub display_name: &'static str,
    pub base_url: &'static str,
    pub service_kinds: &'static [ServiceKind],
    pub wire_family_default: WireFamily,
    pub requires_account: bool,
    pub default_bypass_proxy: bool,
    pub bespoke_wire: bool,
    pub has_adapter_user_agent: bool,
    pub ip_scoped_rate_limit: bool,
    pub credential_url: Option<&'static str>,
    pub credential_hint: Option<&'static str>,
    pub compatibility: Option<CompatibilityProfile>,
}

const fn provider(
    id: &'static str,
    display_name: &'static str,
    base_url: &'static str,
) -> ProviderMetadata {
    ProviderMetadata {
        id,
        display_name,
        base_url,
        service_kinds: &[ServiceKind::Llm],
        wire_family_default: WireFamily::Chat,
        requires_account: true,
        default_bypass_proxy: false,
        bespoke_wire: false,
        has_adapter_user_agent: false,
        ip_scoped_rate_limit: false,
        credential_url: None,
        credential_hint: None,
        compatibility: None,
    }
}

/// The canonical built-in provider catalog.
pub static BUNDLED_PROVIDERS: &[ProviderMetadata] = &[
    provider("openai", "OpenAI", "https://api.openai.com"),
    ProviderMetadata {
        wire_family_default: WireFamily::Messages,
        ..provider("anthropic", "Anthropic", "https://api.anthropic.com")
    },
    ProviderMetadata {
        wire_family_default: WireFamily::Messages,
        has_adapter_user_agent: true,
        credential_url: Some("https://claude.ai"),
        credential_hint: Some(
            "Signed in with a Claude subscription account; there is no key to paste.",
        ),
        ..provider("claude", "Claude Code", "https://api.anthropic.com")
    },
    ProviderMetadata {
        service_kinds: &[ServiceKind::Llm, ServiceKind::Websearch],
        wire_family_default: WireFamily::Responses,
        has_adapter_user_agent: true,
        credential_url: Some("https://chatgpt.com"),
        credential_hint: Some("Signed in with a ChatGPT account; there is no key to paste."),
        ..provider("codex", "Codex ChatGPT", "https://chatgpt.com")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://x.ai"),
        credential_hint: Some(
            "Signed in with an xAI account; the CLI uses subscription credits rather than a key.",
        ),
        ..provider("grok", "Grok Build", "https://cli-chat-proxy.grok.com")
    },
    ProviderMetadata {
        wire_family_default: WireFamily::Responses,
        credential_url: Some("https://console.x.ai/account/api-keys"),
        ..provider("xai", "xAI Grok Subscription", "https://api.x.ai/v1")
    },
    ProviderMetadata {
        bespoke_wire: true,
        has_adapter_user_agent: true,
        credential_url: Some("https://devin.ai"),
        credential_hint: Some("Signed in with a Devin account; there is no key to paste."),
        ..provider("devin", "Devin", "https://server.codeium.com")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://antigravity.google"),
        credential_hint: Some(
            "Signed in with a Google account through the Antigravity login flow.",
        ),
        ..provider(
            "antigravity",
            "Antigravity",
            "https://daily-cloudcode-pa.googleapis.com",
        )
    },
    provider("muse", "Muse Code", "https://api.meta.ai"),
    ProviderMetadata {
        wire_family_default: WireFamily::Responses,
        credential_url: Some("https://developer.meta.com/ai/"),
        credential_hint: Some("Create or copy a Model API key from the Meta developer dashboard."),
        ..provider("meta", "Meta Model API", "https://api.meta.ai")
    },
    ProviderMetadata {
        bespoke_wire: true,
        has_adapter_user_agent: true,
        credential_url: Some("https://kiro.dev"),
        credential_hint: Some(
            "Sign in with AWS Builder ID, an Identity Center organization, Google/GitHub, or paste a Kiro API key.",
        ),
        ..provider("kiro", "Kiro", "https://q.us-east-1.amazonaws.com")
    },
    ProviderMetadata {
        credential_url: Some("https://platform.moonshot.ai/console/api-keys"),
        ..provider("kimi", "Kimi Code", "https://api.kimi.com/coding")
    },
    ProviderMetadata {
        requires_account: false,
        ip_scoped_rate_limit: true,
        has_adapter_user_agent: true,
        ..provider("opencodeft", "OpenCode Free", "https://opencode.ai")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://opencode.ai/auth"),
        compatibility: Some(CompatibilityProfile {
            chat: Some("/zen/v1/chat/completions"),
            responses: Some("/zen/v1/responses"),
            messages: None,
        }),
        ..provider("opencodezen", "OpenCode Zen", "https://opencode.ai")
    },
    ProviderMetadata {
        credential_url: Some("https://opencode.ai/auth"),
        compatibility: Some(CompatibilityProfile {
            chat: Some("/zen/go/v1/chat/completions"),
            responses: Some("/zen/go/v1/responses"),
            messages: None,
        }),
        ..provider("opencodego", "OpenCode Go", "https://opencode.ai")
    },
    ProviderMetadata {
        credential_url: Some("https://cloud.cerebras.ai/platform"),
        ..provider("cerebras", "Cerebras", "https://api.cerebras.ai/v1")
    },
    ProviderMetadata {
        credential_url: Some("https://openrouter.ai/settings/keys"),
        ..provider("openrouter", "OpenRouter", "https://openrouter.ai/api/v1")
    },
    ProviderMetadata {
        credential_url: Some("https://console.mistral.ai/api-keys"),
        ..provider("mistral", "Mistral AI", "https://api.mistral.ai/v1")
    },
    ProviderMetadata {
        credential_url: Some("https://fireworks.ai/account/api-keys"),
        ..provider(
            "fireworks",
            "Fireworks AI",
            "https://api.fireworks.ai/inference/v1",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://build.nvidia.com/settings/api-keys"),
        ..provider(
            "nvidia",
            "NVIDIA NIM",
            "https://integrate.api.nvidia.com/v1",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://platform.deepseek.com/api_keys"),
        ..provider("deepseek", "DeepSeek", "https://api.deepseek.com")
    },
    ProviderMetadata {
        credential_url: Some("https://console.gmicloud.ai"),
        ..provider("gmi", "GMI Cloud", "https://api.gmi-serving.com/v1")
    },
    ProviderMetadata {
        credential_url: Some("https://chat.z.ai"),
        credential_hint: Some(
            "Z.AI browser login redirects only to zcode://zai-auth/callback. If no ZCode app opens, copy the callback URL or code into the manual field, or add an API key from https://z.ai/manage-apikey/apikey-list. A chat.z.ai JWT can be pasted into the manual field and is exchanged for a durable API key.",
        ),
        ..provider(
            "zcode",
            "Z.AI Coding Plan",
            "https://api.z.ai/api/coding/paas/v4",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://portal.nousresearch.com"),
        ..provider(
            "hermes",
            "Nous Research",
            "https://inference-api.nousresearch.com/v1",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://b.ai"),
        ..provider("bai", "B.AI", "https://api.b.ai/v1")
    },
    ProviderMetadata {
        default_bypass_proxy: true,
        has_adapter_user_agent: true,
        ..provider("inferhub", "OpRoute", "https://oproute.web.id/v1")
    },
    ProviderMetadata {
        credential_url: Some("https://aihubmix.com/token"),
        ..provider("aihubmix", "AiHubMix", "https://aihubmix.com/v1")
    },
    ProviderMetadata {
        credential_url: Some("https://tokenharbor.ai"),
        ..provider("tokenharbor", "TokenHarbor", "https://tokenharbor.ai/v1")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://agentrouter.org"),
        ..provider("agentrouter", "AgentRouter", "https://agentrouter.org")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://app.cline.bot"),
        ..provider("cline", "Cline", "https://api.cline.bot/api/v1")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://www.codebuddy.ai"),
        credential_hint: Some(
            "Sign in with the same CodeBuddy account you use in the desktop app.",
        ),
        ..provider("cb", "CodeBuddy", "https://www.codebuddy.ai/v2")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://copilot.tencent.com"),
        credential_hint: Some(
            "Sign in with the same CodeBuddy China account you use in the desktop app.",
        ),
        ..provider("cbcn", "CodeBuddy CN", "https://copilot.tencent.com/v2")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://www.workbuddy.ai"),
        credential_hint: Some(
            "Sign in with the same WorkBuddy account you use in the desktop app.",
        ),
        ..provider("workbuddy", "WorkBuddy", "https://www.workbuddy.ai")
    },
    ProviderMetadata {
        credential_url: Some("https://app.kilo.ai/device-auth"),
        ..provider("kilo", "Kilo Code", "https://api.kilo.ai/api/openrouter")
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://commandcode.ai/studio"),
        credential_hint: Some(
            "Use the API key from the Command Code CLI, or create one in the studio.",
        ),
        ..provider(
            "commandcode",
            "Command Code",
            "https://api.commandcode.ai/alpha/generate",
        )
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://qoder.com/account/integrations"),
        credential_hint: Some(
            "Paste a Personal Access Token (pt-...) from the Qoder integrations page, or sign in with your Qoder account.",
        ),
        ..provider(
            "qoder",
            "Qoder",
            "https://api2.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://ollama.com/settings/keys"),
        ..provider("ollamacloud", "Ollama Cloud", "https://ollama.com/v1")
    },
    ProviderMetadata {
        service_kinds: &[ServiceKind::Llm, ServiceKind::Websearch],
        credential_url: Some("https://aistudio.google.com/app/apikey"),
        ..provider(
            "gemini",
            "Google Gemini",
            "https://generativelanguage.googleapis.com/v1beta",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://platform.xiaomimimo.com"),
        ..provider(
            "xiaomipg",
            "Xiaomi MiMo (PAYG)",
            "https://api.xiaomimimo.com/v1",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://platform.xiaomimimo.com"),
        ..provider(
            "xiaomitp",
            "Xiaomi MiMo (Token Plan)",
            "https://token-plan-sgp.xiaomimimo.com/v1",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://platform.xiaomimimo.com"),
        ..provider(
            "mimodesktop",
            "MiMo Desktop",
            "https://api.xiaomimimo.com/v1",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://aistudio.xiaomimimo.com"),
        credential_hint: Some(
            "Paste the browser cookies exported from a signed-in MiMo Studio session.",
        ),
        ..provider(
            "mimostudio",
            "MiMo Studio",
            "https://aistudio.xiaomimimo.com",
        )
    },
    ProviderMetadata {
        has_adapter_user_agent: true,
        credential_url: Some("https://github.com/settings/copilot"),
        ..provider(
            "github",
            "GitHub Copilot",
            "https://api.individual.githubcopilot.com",
        )
    },
    ProviderMetadata {
        credential_url: Some("https://www.perplexity.ai/settings/api"),
        ..provider("perplexity", "Perplexity", "https://api.perplexity.ai")
    },
    ProviderMetadata {
        service_kinds: &[ServiceKind::Websearch],
        credential_url: Some("https://dashboard.exa.ai/api-keys"),
        credential_hint: Some("Create an API key in the Exa dashboard."),
        ..provider("exa", "Exa", "https://api.exa.ai")
    },
];

static PROVIDERS_BY_ID: LazyLock<BTreeMap<&'static str, &'static ProviderMetadata>> =
    LazyLock::new(|| {
        BUNDLED_PROVIDERS
            .iter()
            .map(|provider| (provider.id, provider))
            .collect()
    });

static WEB_SEARCH_CAPABLE: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    [
        "claude",
        "anthropic",
        "codex",
        "gemini",
        "antigravity",
        "devin",
    ]
    .into_iter()
    .collect()
});

pub fn provider_metadata(id: &str) -> Option<&'static ProviderMetadata> {
    PROVIDERS_BY_ID.get(id).copied()
}

pub fn is_bundled_provider(id: &str) -> bool {
    PROVIDERS_BY_ID.contains_key(id)
}

pub fn provider_base_url(id: &str) -> Option<&'static str> {
    provider_metadata(id).map(|provider| provider.base_url.trim_end_matches('/'))
}

pub fn provider_display_name(id: &str) -> &str {
    provider_metadata(id)
        .map(|provider| provider.display_name)
        .unwrap_or(id)
}

pub fn provider_service_kinds(id: &str) -> &'static [ServiceKind] {
    provider_metadata(id)
        .map(|provider| provider.service_kinds)
        .unwrap_or(&[ServiceKind::Llm])
}

pub fn provider_default_wire_family(id: &str) -> WireFamily {
    provider_metadata(id)
        .map(|provider| provider.wire_family_default)
        .unwrap_or(WireFamily::Chat)
}

pub fn provider_requires_account(id: &str) -> bool {
    provider_metadata(id)
        .map(|provider| provider.requires_account)
        .unwrap_or(true)
}

pub fn provider_uses_bespoke_wire(id: &str) -> bool {
    provider_metadata(id)
        .map(|provider| provider.bespoke_wire)
        .unwrap_or(false)
}

pub fn provider_has_adapter_user_agent(id: &str) -> bool {
    provider_metadata(id)
        .map(|provider| provider.has_adapter_user_agent)
        .unwrap_or(false)
}

pub fn provider_rate_limit_is_ip_scoped(id: Option<&str>) -> bool {
    id.and_then(provider_metadata)
        .map(|provider| provider.ip_scoped_rate_limit)
        .unwrap_or(false)
}

pub fn provider_supports_web_search(id: &str) -> bool {
    let normalized = id.to_ascii_lowercase();
    if WEB_SEARCH_CAPABLE.contains(normalized.as_str()) {
        return true;
    }
    let kinds = provider_service_kinds(id);
    kinds.contains(&ServiceKind::Websearch) && kinds.contains(&ServiceKind::Llm)
}

pub fn default_proxy_bypass_provider_ids() -> BTreeSet<&'static str> {
    BUNDLED_PROVIDERS
        .iter()
        .filter(|provider| provider.default_bypass_proxy)
        .map(|provider| provider.id)
        .collect()
}

pub fn bundled_provider_ids() -> Vec<&'static str> {
    BUNDLED_PROVIDERS
        .iter()
        .map(|provider| provider.id)
        .collect()
}

/// Resolves the endpoint path for a provider/wire pair, preferring the
/// provider's compatibility override.
pub fn endpoint_path_for(provider_id: &str, family: WireFamily) -> Option<&'static str> {
    provider_metadata(provider_id)
        .and_then(|provider| provider.compatibility)
        .and_then(|compatibility| compatibility.for_family(family))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_45_unique_providers() {
        let ids = bundled_provider_ids();
        assert_eq!(ids.len(), 45, "bundled provider count");
        let unique: BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "provider ids are unique");
        for id in ["openai", "anthropic", "devin", "exa", "opencodeft"] {
            assert!(is_bundled_provider(id), "missing {id}");
        }
    }

    #[test]
    fn wire_defaults_and_service_kinds_are_normalized() {
        assert_eq!(provider_default_wire_family("codex"), WireFamily::Responses);
        assert_eq!(
            provider_default_wire_family("anthropic"),
            WireFamily::Messages
        );
        assert_eq!(provider_default_wire_family("openai"), WireFamily::Chat);
        assert_eq!(provider_service_kinds("exa"), &[ServiceKind::Websearch]);
        assert!(provider_supports_web_search("gemini"));
        assert!(!provider_supports_web_search("exa"));
    }

    #[test]
    fn identity_flags_match_the_manifest() {
        assert!(provider_requires_account("openai"));
        assert!(!provider_requires_account("opencodeft"));
        assert!(provider_rate_limit_is_ip_scoped(Some("opencodeft")));
        assert!(!provider_rate_limit_is_ip_scoped(Some("openai")));
        assert!(provider_uses_bespoke_wire("devin"));
        assert!(provider_uses_bespoke_wire("kiro"));
        assert!(!provider_uses_bespoke_wire("openai"));
        assert!(provider_has_adapter_user_agent("claude"));
        assert!(!provider_has_adapter_user_agent("openai"));
    }

    #[test]
    fn compatibility_paths_are_used_only_where_declared() {
        assert_eq!(
            endpoint_path_for("opencodezen", WireFamily::Chat),
            Some("/zen/v1/chat/completions")
        );
        assert_eq!(endpoint_path_for("openai", WireFamily::Chat), None);
    }
}
