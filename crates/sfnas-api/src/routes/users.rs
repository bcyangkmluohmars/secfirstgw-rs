#![deny(unsafe_code)]

//! NAS user management endpoints.
//!
//! Manages Samba (SMB) users. Users are system users with Samba passwords
//! managed via `smbpasswd`.

use crate::error::ApiError;
use axum::extract::Path;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::process::Command;
use tracing::{info, warn};

/// Request body for creating a user.
#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    /// Username (alphanumeric + hyphens + underscores, 1-32 chars).
    username: String,
    /// Password for the Samba user.
    password: String,
}

/// Request body for changing a user's password.
#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    /// New password.
    password: String,
}

/// Validate a username: alphanumeric + hyphens + underscores, 1-32 chars,
/// no reserved system names.
fn validate_username(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 32 {
        return Err(ApiError::Validation(
            "username must be 1-32 characters".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::Validation(
            "username must contain only alphanumeric characters, hyphens, and underscores"
                .to_string(),
        ));
    }
    // Must start with a letter
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(ApiError::Validation(
            "username must start with a letter".to_string(),
        ));
    }

    // Reject reserved/system usernames
    const RESERVED: &[&str] = &[
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
        "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
        "irc", "gnats", "nobody", "sshd", "samba", "nfs", "admin",
    ];
    if RESERVED.iter().any(|r| name.eq_ignore_ascii_case(r)) {
        return Err(ApiError::Validation(format!(
            "'{name}' is a reserved username"
        )));
    }

    Ok(())
}

/// Validate password: minimum 8 characters, not all whitespace.
fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.len() < 8 {
        return Err(ApiError::Validation(
            "password must be at least 8 characters".to_string(),
        ));
    }
    if password.trim().is_empty() {
        return Err(ApiError::Validation(
            "password must not be all whitespace".to_string(),
        ));
    }
    Ok(())
}

/// `GET /api/v1/users` — list NAS users.
///
/// Reads from the Samba passdb (pdbedit) to get the list of Samba-enabled users.
async fn list_users() -> Result<Json<Value>, ApiError> {
    let output = Command::new("pdbedit")
        .arg("-L")
        .arg("-d")
        .arg("0")
        .output()
        .map_err(|e| ApiError::Internal(format!("failed to run pdbedit: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let users: Vec<Value> = stdout
        .lines()
        .filter_map(|line| {
            // pdbedit -L format: "username:uid:full name"
            let mut parts = line.splitn(3, ':');
            let username = parts.next()?.trim();
            if username.is_empty() {
                return None;
            }
            let uid = parts.next().and_then(|s| s.trim().parse::<u32>().ok());
            let full_name = parts.next().unwrap_or("").trim();
            Some(json!({
                "username": username,
                "uid": uid,
                "full_name": full_name,
            }))
        })
        .collect();

    Ok(Json(json!({
        "success": true,
        "data": users,
    })))
}

/// `POST /api/v1/users` — create a new NAS user.
///
/// Creates a system user (via `adduser`) and sets a Samba password.
async fn create_user(
    Json(body): Json<CreateUserRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_username(&body.username)?;
    validate_password(&body.password)?;

    // Create system user (no login shell, home under /data/homes/)
    let add_output = Command::new("adduser")
        .arg("-D")
        .arg("-h")
        .arg(format!("/data/homes/{}", body.username))
        .arg("-s")
        .arg("/sbin/nologin")
        .arg(&body.username)
        .output()
        .map_err(|e| ApiError::Internal(format!("failed to create system user: {e}")))?;

    if !add_output.status.success() {
        let stderr = String::from_utf8_lossy(&add_output.stderr);
        // Check if user already exists
        if stderr.contains("already exists") || stderr.contains("in use") {
            return Err(ApiError::Validation(format!(
                "user '{}' already exists",
                body.username
            )));
        }
        return Err(ApiError::Internal("failed to create system user".to_string()));
    }

    // Create home directory
    let home = std::path::Path::new("/data/homes").join(&body.username);
    if let Err(e) = std::fs::create_dir_all(&home) {
        warn!(
            username = body.username,
            error = %e,
            "failed to create home directory"
        );
    }

    // Set Samba password
    sfnas_share::SambaConfig::add_user(&body.username, &body.password)?;

    info!(username = body.username, "NAS user created via API");

    Ok(Json(json!({
        "success": true,
        "data": { "username": body.username },
    })))
}

/// `DELETE /api/v1/users/:name` — delete a NAS user.
///
/// Removes the Samba password and the system user.
async fn delete_user(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    validate_username(&name)?;

    // Remove Samba password
    let smb_output = Command::new("smbpasswd")
        .arg("-x")
        .arg(&name)
        .output()
        .map_err(|e| ApiError::Internal(format!("failed to remove samba user: {e}")))?;

    if !smb_output.status.success() {
        warn!(username = name, "smbpasswd -x failed (user may not exist in samba)");
    }

    // Remove system user (keep home directory for data safety)
    let del_output = Command::new("deluser")
        .arg(&name)
        .output()
        .map_err(|e| ApiError::Internal(format!("failed to remove system user: {e}")))?;

    if !del_output.status.success() {
        let stderr = String::from_utf8_lossy(&del_output.stderr);
        if stderr.contains("doesn't exist") || stderr.contains("not found") {
            return Err(ApiError::NotFound(format!("user '{name}' not found")));
        }
        return Err(ApiError::Internal("failed to remove user".to_string()));
    }

    info!(username = name, "NAS user deleted via API");

    Ok(Json(json!({
        "success": true,
        "data": { "deleted": name },
    })))
}

/// `PUT /api/v1/users/:name/password` — change a user's password.
async fn change_password(
    Path(name): Path<String>,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_username(&name)?;
    validate_password(&body.password)?;

    // Update Samba password (add_user with -a also updates existing users)
    sfnas_share::SambaConfig::add_user(&name, &body.password)?;

    info!(username = name, "NAS user password changed via API");

    Ok(Json(json!({
        "success": true,
        "data": { "username": name },
    })))
}

/// Build the users router.
pub fn router() -> Router {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/{name}", delete(delete_user))
        .route("/users/{name}/password", put(change_password))
}
