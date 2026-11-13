//! Provider metadata, registry, and adapters.

pub mod adapter;
pub mod antigravity;
pub mod antigravity_oauth;
pub mod buddy;
pub mod devin;
pub mod gemini;
pub mod kiro;
pub mod kiro_oauth;
pub mod metadata;
pub mod mimodesktop;
pub mod mimostudio;
pub mod qoder;

pub use metadata::{
    BUNDLED_PROVIDERS, CompatibilityProfile, ProviderMetadata, bundled_provider_ids,
    default_proxy_bypass_provider_ids, endpoint_path_for, is_bundled_provider, provider_base_url,
    provider_default_wire_family, provider_display_name, provider_has_adapter_user_agent,
    provider_metadata, provider_rate_limit_is_ip_scoped, provider_requires_account,
    provider_service_kinds, provider_supports_web_search, provider_uses_bespoke_wire,
};
