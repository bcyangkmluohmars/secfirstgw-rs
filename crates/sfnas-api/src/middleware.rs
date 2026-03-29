// SPDX-License-Identifier: AGPL-3.0-or-later
// NOTE: unsafe_code is denied at the crate root (lib.rs)

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::auth::{self, User};

/// Extractor that validates the session and provides the authenticated user.
///
/// Extracts the token from either:
/// - `Authorization: Bearer <token>` header
/// - `sfnas_session` cookie
///
/// Returns 401 if the token is missing or invalid.
pub struct AuthUser {
    pub user: User,
    pub token: String,
}

/// Error type for auth extraction failures.
pub enum AuthError {
    MissingToken,
    InvalidSession,
    InternalError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AuthError::InternalError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
        };

        let body = axum::Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get the DB handle from extensions
        let db = parts
            .extensions
            .get::<sfgw_db::Db>()
            .cloned()
            .ok_or(AuthError::InternalError("db not in extensions".into()))?;

        // Extract token from Authorization header or cookie
        let token = extract_token(parts).ok_or(AuthError::MissingToken)?;

        // Extract client IP from the request (use ConnectInfo or forwarded header)
        let client_ip = extract_client_ip(parts);

        // For now, fingerprint is derived from User-Agent
        let fingerprint = extract_fingerprint(parts);

        // Validate the session
        let user_id = auth::validate_session(&db, &token, &client_ip, &fingerprint)
            .await
            .map_err(|e| AuthError::InternalError(e.to_string()))?
            .ok_or(AuthError::InvalidSession)?;

        // Look up the user
        let user = auth::get_user_by_id(&db, user_id)
            .await
            .map_err(|e| AuthError::InternalError(e.to_string()))?
            .ok_or(AuthError::InvalidSession)?;

        Ok(AuthUser { user, token })
    }
}

/// Extract the session token from the request.
fn extract_token(parts: &Parts) -> Option<String> {
    // Try Authorization: Bearer <token> first
    if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION)
        && let Ok(value) = auth_header.to_str()
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }

    // Try sfnas_session cookie
    if let Some(cookie_header) = parts.headers.get(header::COOKIE)
        && let Ok(cookies) = cookie_header.to_str()
    {
        for cookie in cookies.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix("sfnas_session=") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }

    None
}

/// Extract client IP from the request.
///
/// Always uses the socket peer address (ConnectInfo). Never trusts
/// X-Forwarded-For or other proxy headers — they are attacker-controlled.
fn extract_client_ip(parts: &Parts) -> String {
    if let Some(addr) = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return addr.0.ip().to_string();
    }

    "unknown".to_string()
}

/// Extract a fingerprint from the request (based on User-Agent).
fn extract_fingerprint(parts: &Parts) -> String {
    parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Helper to extract client IP from a socket address (used by endpoint handlers).
///
/// Never trusts X-Forwarded-For or other proxy headers.
pub fn client_ip_from_addr(addr: &std::net::SocketAddr) -> String {
    addr.ip().to_string()
}

/// Helper to extract fingerprint from headers (used by endpoint handlers).
pub fn fingerprint_from_headers(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Middleware that enforces authentication on all routes it wraps.
///
/// Rejects with 401 if no valid session token is present. This is applied
/// as a layer on protected and critical route groups so individual handlers
/// don't need to extract `AuthUser` themselves.
pub async fn require_auth(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let db = match req.extensions().get::<sfgw_db::Db>().cloned() {
        Some(db) => db,
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({ "error": "internal server error" }))).into_response();
        }
    };

    let token = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string())
        .or_else(|| {
            req.headers()
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';')
                        .find_map(|c| c.trim().strip_prefix("sfnas_session="))
                        .map(|v| v.trim().to_string())
                })
        });

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "unauthorized" }))).into_response();
        }
    };

    let client_ip = req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let fingerprint = req.headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    match crate::auth::validate_session(&db, &token, &client_ip, &fingerprint).await {
        Ok(Some(_user_id)) => {
            // Valid session — store token for downstream handlers
            req.extensions_mut().insert(AuthToken(token));
            next.run(req).await
        }
        _ => {
            (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "unauthorized" }))).into_response()
        }
    }
}

/// Token stored in request extensions after auth middleware validates it.
#[derive(Clone)]
pub struct AuthToken(pub String);
