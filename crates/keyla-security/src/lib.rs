//! Credential crypto, API-key authentication, scopes, and model access.

pub mod access;
pub mod api_key;
pub mod crypto;
pub mod model_abuse;
pub mod model_access;
pub mod redis_admission;

pub use access::{
    ACCESS_SCOPES, AccessDecision, TENANT_KEY_SCOPES, console_session_scopes,
    create_access_decision, is_valid_tenant_key_scope,
};
pub use api_key::{
    ApiKeyAuthorizationSnapshot, ApiKeyRow, AuthError, ResolvedApiKey, get_admission_identity,
    invalidate_api_key_cache, request_token, resolve_api_key_authorization, token_hash,
};
pub use crypto::{
    CryptoError, decrypt_credential, decrypt_credential_to_string, encrypt_credential, hash_secret,
    set_credential_encryption_key_for_testing,
};
pub use model_access::{
    ModelAccessMode, ModelAccessPolicy, ModelRejectionReason, is_model_allowed,
    model_rejection_reason,
};
