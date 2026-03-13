// SPDX-License-Identifier: AGPL-3.0-or-later

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
/// - `sfgw_session` cookie
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
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "missing authentication token"),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "invalid or expired session"),
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
    if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION) {
        if let Ok(value) = auth_header.to_str() {
            if let Some(token) = value.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }

    // Try sfgw_session cookie
    if let Some(cookie_header) = parts.headers.get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix("sfgw_session=") {
                    let value = value.trim();
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
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
    if let Some(addr) = parts.extensions.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
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
