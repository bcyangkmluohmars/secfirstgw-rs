#![deny(unsafe_code)]

//! API error types.
//!
//! Maps domain errors from `sfnas-storage` and `sfnas-share` into HTTP
//! responses with the standard envelope format. Internal details are never
//! leaked to the client.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

/// All errors the API server can produce.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The request body or parameters failed validation.
    #[error("validation error: {0}")]
    Validation(String),

    /// A storage subsystem operation failed.
    #[error("storage error")]
    Storage(#[from] sfnas_storage::StorageError),

    /// A share subsystem operation failed.
    #[error("share error")]
    Share(#[from] sfnas_share::ShareError),

    /// An internal server error (I/O, unexpected state, etc.).
    #[error("internal error: {0}")]
    Internal(String),

    /// Server startup or runtime failure.
    #[error("server error: {0}")]
    Server(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::Validation(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
            ApiError::Storage(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage operation failed".to_string(),
            ),
            ApiError::Share(e) => match e {
                sfnas_share::ShareError::NotFound(name) => {
                    (StatusCode::NOT_FOUND, format!("share '{name}' not found"))
                }
                sfnas_share::ShareError::AlreadyExists(name) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("share '{name}' already exists"),
                ),
                sfnas_share::ShareError::InvalidShareName(reason) => {
                    (StatusCode::UNPROCESSABLE_ENTITY, reason.clone())
                }
                sfnas_share::ShareError::InvalidUsername(reason) => {
                    (StatusCode::UNPROCESSABLE_ENTITY, reason.clone())
                }
                sfnas_share::ShareError::UserNotFound(name) => {
                    (StatusCode::NOT_FOUND, format!("user '{name}' not found"))
                }
                sfnas_share::ShareError::UserAlreadyExists(name) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("user '{name}' already exists"),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "share operation failed".to_string(),
                ),
            },
            ApiError::Internal(_) | ApiError::Server(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".to_string(),
            ),
        };

        tracing::warn!(
            status = status.as_u16(),
            error = %self,
            "API error response"
        );

        let body = json!({
            "success": false,
            "error": message,
        });

        (status, axum::Json(body)).into_response()
    }
}
