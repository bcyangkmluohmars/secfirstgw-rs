#![deny(unsafe_code)]

//! System management endpoints.
//!
//! Provides log viewing, reboot, and network interface information.

use crate::error::ApiError;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::process::Command;
use tracing::{info, warn};

/// Query parameters for log retrieval.
#[derive(Debug, Deserialize)]
struct LogQuery {
    /// Number of lines to return (default: 100, max: 1000).
    #[serde(default = "default_log_lines")]
    lines: u32,
}

fn default_log_lines() -> u32 {
    100
}

/// `GET /api/v1/system/logs` — last N log lines.
///
/// Reads from the system log (syslog / dmesg fallback).
async fn get_logs(
    axum::extract::Query(query): axum::extract::Query<LogQuery>,
) -> Result<Json<Value>, ApiError> {
    let lines = query.lines.clamp(1, 1000);

    // Try syslog first, fall back to dmesg
    let log_content = read_syslog(lines)
        .or_else(|| read_dmesg(lines))
        .unwrap_or_default();

    Ok(Json(json!({
        "success": true,
        "data": {
            "lines": log_content,
            "count": log_content.len(),
        },
    })))
}

/// `POST /api/v1/system/reboot` — reboot the system.
async fn reboot() -> Result<Json<Value>, ApiError> {
    info!("system reboot requested via API");

    // Spawn the reboot command in the background so we can return a response
    let output = Command::new("reboot")
        .output()
        .map_err(|e| ApiError::Internal(format!("failed to execute reboot: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(error = %stderr, "reboot command failed");
        return Err(ApiError::Internal("reboot failed".to_string()));
    }

    Ok(Json(json!({
        "success": true,
        "data": { "message": "system is rebooting" },
    })))
}

/// `GET /api/v1/system/network` — network interface information.
async fn get_network() -> Result<Json<Value>, ApiError> {
    let mut interfaces = Vec::new();

    let net_dir = std::path::Path::new("/sys/class/net");
    let entries = std::fs::read_dir(net_dir)
        .map_err(|e| ApiError::Internal(format!("failed to read /sys/class/net: {e}")))?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();

        // Skip loopback and virtual interfaces
        if name_str == "lo" || name_str.starts_with("veth") || name_str.starts_with("docker") {
            continue;
        }

        let iface_dir = entry.path();

        let operstate =
            read_sysfs_file(&iface_dir.join("operstate")).unwrap_or_else(|| "unknown".to_string());

        let mac = read_sysfs_file(&iface_dir.join("address")).unwrap_or_default();

        let speed = read_sysfs_file(&iface_dir.join("speed")).and_then(|s| s.parse::<u32>().ok());

        let mtu = read_sysfs_file(&iface_dir.join("mtu")).and_then(|s| s.parse::<u32>().ok());

        // Get IP addresses from `ip addr show <iface>`
        let ip_addrs = get_ip_addresses(&name_str);

        interfaces.push(json!({
            "name": name_str,
            "state": operstate,
            "mac": mac,
            "speed_mbps": speed,
            "mtu": mtu,
            "addresses": ip_addrs,
        }));
    }

    Ok(Json(json!({
        "success": true,
        "data": interfaces,
    })))
}

/// Build the system router (protected — read-only).
pub fn router() -> Router {
    Router::new()
        .route("/system/logs", get(get_logs))
        .route("/system/network", get(get_network))
}

/// Critical system operations (destructive — strict rate limit).
pub fn critical_router() -> Router {
    Router::new().route("/system/reboot", post(reboot))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_sysfs_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_syslog(lines: u32) -> Option<Vec<String>> {
    let output = Command::new("tail")
        .arg("-n")
        .arg(lines.to_string())
        .arg("/var/log/messages")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let log_lines: Vec<String> = stdout.lines().map(|l| l.to_string()).collect();
    if log_lines.is_empty() {
        return None;
    }
    Some(log_lines)
}

fn read_dmesg(lines: u32) -> Option<Vec<String>> {
    let output = Command::new("dmesg").arg("--human").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let all_lines: Vec<String> = stdout.lines().map(|l| l.to_string()).collect();
    let start = all_lines.len().saturating_sub(lines as usize);
    Some(all_lines[start..].to_vec())
}

fn get_ip_addresses(iface: &str) -> Vec<String> {
    let output = match Command::new("ip")
        .args(["-o", "addr", "show", "dev", iface])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter_map(|line| {
            // Format: "2: eth0    inet 10.0.0.1/24 ..."
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Find "inet" or "inet6" followed by the address
            for (i, part) in parts.iter().enumerate() {
                if (*part == "inet" || *part == "inet6") && i + 1 < parts.len() {
                    return Some(parts[i + 1].to_string());
                }
            }
            None
        })
        .collect()
}
