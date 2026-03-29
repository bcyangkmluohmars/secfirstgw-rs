#![deny(unsafe_code)]

//! SMB share management endpoints.
//!
//! Provides CRUD for Samba file shares. Changes are written to smb.conf
//! and Samba is reloaded automatically.

use crate::error::ApiError;
use axum::extract::Path;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::info;

/// Request body for creating or updating a share.
#[derive(Debug, Deserialize)]
struct ShareRequest {
    /// Share name (alphanumeric + hyphens, 1-64 chars).
    name: String,
    /// Filesystem path for the share.
    path: String,
    /// Optional share template: "standard", "public", "private", "timemachine".
    /// When set, the template provides defaults for guest_ok, read_only,
    /// browseable, vfs_objects, and fruit settings. Explicit fields in the
    /// request still override the template defaults.
    #[serde(default)]
    template: Option<String>,
    /// Optional comment / description.
    #[serde(default)]
    comment: String,
    /// Whether the share is browseable. Defaults to true.
    #[serde(default = "default_true")]
    browseable: bool,
    /// Whether the share is read-only. Defaults to false.
    #[serde(default)]
    read_only: bool,
    /// List of users allowed to access this share.
    #[serde(default)]
    valid_users: Vec<String>,
    /// List of users with write access.
    #[serde(default)]
    write_list: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Validate a share name: alphanumeric + hyphens + underscores, 1-64 chars.
fn validate_share_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::Validation(
            "share name must be 1-64 characters".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::Validation(
            "share name must contain only alphanumeric characters, hyphens, and underscores"
                .to_string(),
        ));
    }
    // Reject reserved names
    if name.eq_ignore_ascii_case("global")
        || name.eq_ignore_ascii_case("homes")
        || name.eq_ignore_ascii_case("printers")
    {
        return Err(ApiError::Validation(format!(
            "'{name}' is a reserved share name"
        )));
    }
    Ok(())
}

/// Validate a share path: must be absolute, under /data/, no traversal.
fn validate_share_path(path: &str) -> Result<PathBuf, ApiError> {
    let p = std::path::Path::new(path);

    if !p.is_absolute() {
        return Err(ApiError::Validation(
            "share path must be absolute".to_string(),
        ));
    }

    // Must be under /data/ to prevent sharing system directories
    if !path.starts_with("/data/") {
        return Err(ApiError::Validation(
            "share path must be under /data/".to_string(),
        ));
    }

    // Reject path traversal components
    for component in p.components() {
        if let std::path::Component::ParentDir = component {
            return Err(ApiError::Validation(
                "path traversal not allowed".to_string(),
            ));
        }
    }

    Ok(p.to_path_buf())
}

/// `GET /api/v1/shares` — list all SMB shares.
async fn list_shares() -> Result<Json<Value>, ApiError> {
    let content = std::fs::read_to_string("/etc/samba/smb.conf")
        .unwrap_or_default();

    let mut shares: Vec<Value> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_path: Option<String> = None;
    let mut current_comment: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Flush previous share
            if let Some(name) = current_name.take()
                && name != "global"
            {
                shares.push(json!({
                    "name": name,
                    "path": current_path.take().unwrap_or_default(),
                    "comment": current_comment.take().unwrap_or_default(),
                }));
            }
            current_path = None;
            current_comment = None;

            let section = &trimmed[1..trimmed.len() - 1];
            current_name = Some(section.to_string());
        } else if let Some((_key, value)) = trimmed.split_once('=') {
            let key = _key.trim();
            let val = value.trim();
            match key {
                "path" => current_path = Some(val.to_string()),
                "comment" => current_comment = Some(val.to_string()),
                _ => {}
            }
        }
    }

    // Flush last share
    if let Some(name) = current_name.take()
        && name != "global"
    {
        shares.push(json!({
            "name": name,
            "path": current_path.unwrap_or_default(),
            "comment": current_comment.unwrap_or_default(),
        }));
    }

    Ok(Json(json!({
        "success": true,
        "data": shares,
    })))
}

/// Build a share from a template name, falling back to `Share::new`.
///
/// Supported templates: "public", "private", "timemachine".
/// Any other value (including "standard" or `None`) uses `Share::new`.
fn share_from_template(
    template: Option<&str>,
    name: &str,
    path: PathBuf,
    valid_users: &[String],
) -> Result<sfnas_share::Share, ApiError> {
    match template {
        Some("public") => Ok(sfnas_share::Share::public(name, path)),
        Some("private") => {
            let user_refs: Vec<&str> = valid_users.iter().map(String::as_str).collect();
            Ok(sfnas_share::Share::private(name, path, &user_refs))
        }
        Some("timemachine") => {
            let user = valid_users.first().map(String::as_str).unwrap_or("nobody");
            Ok(sfnas_share::Share::timemachine(name, path, user))
        }
        Some("standard") | None => Ok(sfnas_share::Share::new(name, path)),
        Some(other) => Err(ApiError::Validation(format!(
            "unknown template '{other}': must be standard, public, private, or timemachine"
        ))),
    }
}

/// `POST /api/v1/shares` — create a new share.
async fn create_share(
    Json(body): Json<ShareRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_share_name(&body.name)?;
    let share_path = validate_share_path(&body.path)?;

    let mut share = share_from_template(
        body.template.as_deref(),
        &body.name,
        share_path.clone(),
        &body.valid_users,
    )?;

    // Override template defaults with any explicitly provided fields
    if !body.comment.is_empty() {
        share.comment = body.comment;
    }
    share.browseable = body.browseable;
    share.read_only = body.read_only;
    if !body.valid_users.is_empty() {
        share.valid_users = body.valid_users;
    }
    if !body.write_list.is_empty() {
        share.write_list = body.write_list;
    }

    // Ensure the share directory exists
    std::fs::create_dir_all(&share_path).map_err(|e| {
        ApiError::Internal(format!("failed to create share directory: {e}"))
    })?;

    let mut config = sfnas_share::SambaConfig::new("WORKGROUP");
    config.add_share(share)?;
    config.apply()?;

    info!(name = body.name, path = %share_path.display(), "share created via API");

    Ok(Json(json!({
        "success": true,
        "data": { "name": body.name, "path": share_path },
    })))
}

/// `PUT /api/v1/shares/:name` — update an existing share.
async fn update_share(
    Path(name): Path<String>,
    Json(body): Json<ShareRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_share_name(&name)?;
    let share_path = validate_share_path(&body.path)?;

    // For now, updating a share means removing the old one and adding the new one.
    // A full implementation would parse smb.conf, update in place, and rewrite.
    let mut share = sfnas_share::Share::new(&name, share_path.clone());
    share.comment = body.comment;
    share.browseable = body.browseable;
    share.read_only = body.read_only;
    share.valid_users = body.valid_users;
    share.write_list = body.write_list;

    let mut config = sfnas_share::SambaConfig::new("WORKGROUP");
    // remove old, add new
    let _ = config.remove_share(&name);
    config.add_share(share)?;
    config.apply()?;

    info!(name, path = %share_path.display(), "share updated via API");

    Ok(Json(json!({
        "success": true,
        "data": { "name": name, "path": share_path },
    })))
}

/// `DELETE /api/v1/shares/:name` — delete a share.
async fn delete_share(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    validate_share_name(&name)?;

    let mut config = sfnas_share::SambaConfig::new("WORKGROUP");
    config.remove_share(&name)?;
    config.apply()?;

    info!(name, "share deleted via API");

    Ok(Json(json!({
        "success": true,
        "data": { "deleted": name },
    })))
}

// ---------------------------------------------------------------------------
// Rsync module management
// ---------------------------------------------------------------------------

/// Request body for creating an rsync module.
#[derive(Debug, Deserialize)]
struct RsyncModuleRequest {
    /// Module name (alphanumeric + hyphens, 1-64 chars).
    name: String,
    /// Filesystem path for the module.
    path: String,
    /// Whether the module is read-only. Defaults to true.
    #[serde(default = "default_true")]
    read_only: bool,
    /// Human-readable description.
    #[serde(default)]
    comment: String,
}

/// Validate a path for rsync modules: must be absolute, under /mnt/, no traversal.
fn validate_rsync_path(path: &str) -> Result<PathBuf, ApiError> {
    let p = std::path::Path::new(path);

    if !p.is_absolute() {
        return Err(ApiError::Validation(
            "rsync module path must be absolute".to_string(),
        ));
    }

    // Must be under /mnt/ to prevent exposing system directories
    if !path.starts_with("/mnt/") {
        return Err(ApiError::Validation(
            "rsync module path must be under /mnt/".to_string(),
        ));
    }

    // Reject path traversal components
    for component in p.components() {
        if let std::path::Component::ParentDir = component {
            return Err(ApiError::Validation(
                "path traversal not allowed".to_string(),
            ));
        }
    }

    Ok(p.to_path_buf())
}

/// `GET /api/v1/rsync/modules` — list rsync modules by parsing rsyncd.conf.
async fn list_rsync_modules() -> Result<Json<Value>, ApiError> {
    let content = std::fs::read_to_string("/etc/rsyncd.conf").unwrap_or_default();

    let mut modules: Vec<Value> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_path: Option<String> = None;
    let mut current_comment: Option<String> = None;
    let mut current_read_only = true;
    let mut current_hosts_allow: Vec<String> = Vec::new();

    // Helper closure to flush a module section into the list.
    let flush = |name: &str,
                 path: &mut Option<String>,
                 comment: &mut Option<String>,
                 read_only: &mut bool,
                 hosts_allow: &mut Vec<String>,
                 modules: &mut Vec<Value>| {
        modules.push(json!({
            "name": name,
            "path": path.take().unwrap_or_default(),
            "comment": comment.take().unwrap_or_default(),
            "read_only": *read_only,
            "allowed_hosts": std::mem::take(hosts_allow),
        }));
        *read_only = true;
    };

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Flush previous section (skip any unnamed global section)
            if let Some(name) = current_name.take() {
                flush(
                    &name,
                    &mut current_path,
                    &mut current_comment,
                    &mut current_read_only,
                    &mut current_hosts_allow,
                    &mut modules,
                );
            }
            current_path = None;
            current_comment = None;
            current_read_only = true;
            current_hosts_allow.clear();

            let section = &trimmed[1..trimmed.len() - 1];
            current_name = Some(section.to_string());
        } else if let Some((key, value)) = trimmed.split_once('=') {
            let k = key.trim();
            let v = value.trim();
            match k {
                "path" => current_path = Some(v.to_string()),
                "comment" => current_comment = Some(v.to_string()),
                "read only" | "read_only" => {
                    current_read_only = matches!(v.to_lowercase().as_str(), "yes" | "true" | "1");
                }
                "hosts allow" | "hosts_allow" => {
                    current_hosts_allow =
                        v.split_whitespace().map(String::from).collect();
                }
                _ => {}
            }
        }
    }

    // Flush last section
    if let Some(name) = current_name.take() {
        flush(
            &name,
            &mut current_path,
            &mut current_comment,
            &mut current_read_only,
            &mut current_hosts_allow,
            &mut modules,
        );
    }

    Ok(Json(json!({
        "success": true,
        "data": modules,
    })))
}

/// `POST /api/v1/rsync/modules` — create a new rsync module.
async fn create_rsync_module(
    Json(body): Json<RsyncModuleRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_share_name(&body.name)?;
    let module_path = validate_rsync_path(&body.path)?;

    let mut module = sfnas_share::RsyncModule::new(&body.name, module_path.clone());
    module.read_only = body.read_only;
    module.comment = body.comment;

    let mut config = sfnas_share::RsyncConfig::new();
    config.add_module(module)?;
    config.apply()?;

    info!(name = body.name, path = %module_path.display(), "rsync module created via API");

    Ok(Json(json!({
        "success": true,
        "data": { "name": body.name, "path": module_path },
    })))
}

/// `DELETE /api/v1/rsync/modules/:name` — delete an rsync module.
async fn delete_rsync_module(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    validate_share_name(&name)?;

    let mut config = sfnas_share::RsyncConfig::new();
    config.remove_module(&name)?;
    config.apply()?;

    info!(name, "rsync module deleted via API");

    Ok(Json(json!({
        "success": true,
        "data": { "deleted": name },
    })))
}

/// Build the shares router (SMB shares + rsync modules).
pub fn router() -> Router {
    Router::new()
        .route("/shares", get(list_shares).post(create_share))
        .route("/shares/{name}", put(update_share).delete(delete_share))
        .route(
            "/rsync/modules",
            get(list_rsync_modules).post(create_rsync_module),
        )
        .route("/rsync/modules/{name}", delete(delete_rsync_module))
}
