//! Console access resolution: session cookie or tenant bearer key, projected
//! onto the shared `AccessDecision` contract.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use keyla_core::GatewayError;
use keyla_security::{
    AccessDecision, console_session_scopes, create_access_decision, resolve_api_key_authorization,
};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgPool;

use crate::auth::{SESSION_COOKIE_NAME, find_user_by_id, parse_cookie, validate_session};

/// Resolves a console request's principal. Session cookies win; a scoped
/// tenant bearer key is the fallback (the same pair the original console
/// router accepts).
pub async fn resolve_console_access(
    pool: &PgPool,
    headers: &HeaderMap,
) -> Result<Option<AccessDecision>, sqlx::Error> {
    let cookie_header = headers.get("cookie").and_then(|value| value.to_str().ok());
    if let Some(token) =
        cookie_header.and_then(|header| parse_cookie(Some(header), SESSION_COOKIE_NAME))
    {
        let session = validate_session(pool, &token).await.ok().flatten();
        if let Some(session) = session {
            if let Some(user) = find_user_by_id(pool, &session.user_id).await? {
                if user.is_active {
                    return Ok(Some(create_access_decision(
                        session.id,
                        Some(user.tenant_id),
                        console_session_scopes(user.is_platform_admin)
                            .into_iter()
                            .map(str::to_owned)
                            .collect(),
                        Some(user.id),
                    )));
                }
            }
        }
        return Ok(None);
    }
    let mut map = std::collections::BTreeMap::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            map.insert(name.as_str().to_owned(), value.to_owned());
        }
    }
    let Ok(token) = keyla_security::request_token(&map) else {
        return Ok(None);
    };
    let resolved = resolve_api_key_authorization(pool, &token)
        .await
        .ok()
        .flatten();
    Ok(resolved.map(|key| {
        create_access_decision(
            key.id.clone(),
            Some(key.tenant_id.clone()),
            key.scopes.clone(),
            Some(key.snapshot.admission_identity.clone()),
        )
    }))
}

/// Console-shaped error envelope: `{"error":{origin,code,message,details}}`.
pub fn console_error_body(code: &str, message: &str) -> Value {
    json!({
        "error": {
            "origin": "keyla",
            "code": code,
            "message": message,
            "details": {},
        }
    })
}

/// Console JSON response with no-store caching.
pub fn console_response(status: StatusCode, value: Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(serde_json::to_vec(&value).unwrap_or_default()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Resolves the caller and requires a tenant-scoped grant of `scope`,
/// returning the tenant id or the exact refusal response to send.
#[allow(clippy::result_large_err)]
pub async fn authorize_tenant(
    pool: &PgPool,
    headers: &HeaderMap,
    scope: &str,
) -> Result<String, Response> {
    let Some(access) = resolve_console_access(pool, headers).await.ok().flatten() else {
        return Err(console_response(
            StatusCode::UNAUTHORIZED,
            console_error_body("authentication_failed", "invalid or revoked API key"),
        ));
    };
    if let Err(error) = require_scope(&access, scope) {
        let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST);
        return Err(console_response(status, error.public_body()));
    }
    access.tenant_id.ok_or_else(|| {
        console_response(
            StatusCode::FORBIDDEN,
            console_error_body("tenant_required", "Tenant is required"),
        )
    })
}

pub fn require_scope(decision: &AccessDecision, scope: &str) -> Result<(), GatewayError> {
    if decision.has_scope(scope) {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert("scope".into(), json!(scope));
    Err(GatewayError::new(
        keyla_core::GatewayErrorCode::PolicyRejected,
        403,
        format!("insufficient_scope: missing scope: {scope}"),
        details,
    ))
}
