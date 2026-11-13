//! Shared model-abuse store (owned by `keyla-security`) plus the client
//! identity extension attached by the admission middleware.

pub use keyla_security::model_abuse::*;

/// Client address resolved at the trusted-proxy boundary and attached by the
/// admission middleware, so every later stage sees one identity.
#[derive(Debug, Clone, Copy)]
pub struct ClientIdentity(pub std::net::IpAddr);
