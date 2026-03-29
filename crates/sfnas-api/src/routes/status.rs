#![deny(unsafe_code)]

//! System status endpoint.
//!
//! Returns hostname, kernel version, uptime, load averages, memory usage,
//! temperatures, and summary counts of bays, disks, arrays, and shares.

use crate::error::ApiError;
use axum::Extension;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::Path;
use tracing::debug;

/// System status response.
#[derive(Debug, Serialize)]
struct SystemStatus {
    hostname: String,
    kernel: String,
    uptime_seconds: f64,
    load: LoadAverage,
    memory: MemoryInfo,
    temperatures: Vec<ThermalZone>,
    fans: Vec<FanInfo>,
    fan_profile: String,
    bays: Vec<sfnas_storage::Bay>,
    disk_count: usize,
    array_count: usize,
    share_count: usize,
}

/// Load average values.
#[derive(Debug, Serialize)]
struct LoadAverage {
    one: f64,
    five: f64,
    fifteen: f64,
}

/// Memory usage in bytes.
#[derive(Debug, Serialize)]
struct MemoryInfo {
    total_kb: u64,
    available_kb: u64,
    used_kb: u64,
}

/// A single thermal zone reading.
#[derive(Debug, Serialize)]
struct ThermalZone {
    name: String,
    temp_celsius: f64,
}

/// Fan speed + PWM info.
#[derive(Debug, Serialize)]
struct FanInfo {
    id: u8,
    rpm: Option<u32>,
    pwm: Option<u8>,
    pwm_percent: Option<u8>,
}

/// `GET /api/v1/status`
async fn get_status(
    Extension(disk_cache): Extension<sfnas_storage::DiskCache>,
) -> Result<Json<Value>, ApiError> {
    debug!("fetching system status");

    let hostname = read_file_trimmed("/etc/hostname").unwrap_or_else(|| "secfirstnas".to_string());

    let kernel = read_file_trimmed("/proc/version")
        .map(|v| {
            // Extract just the version string (first three fields)
            v.split_whitespace().take(3).collect::<Vec<_>>().join(" ")
        })
        .unwrap_or_else(|| "unknown".to_string());

    let uptime_seconds = read_uptime().unwrap_or(0.0);
    let load = read_loadavg().unwrap_or(LoadAverage {
        one: 0.0,
        five: 0.0,
        fifteen: 0.0,
    });
    let memory = read_meminfo().unwrap_or(MemoryInfo {
        total_kb: 0,
        available_kb: 0,
        used_kb: 0,
    });
    let temperatures = read_thermal_zones(&disk_cache);
    let fans = read_fans();
    let fan_profile = read_fan_profile();

    let bays = sfnas_storage::Bay::read_all();
    let disk_count = disk_cache.get().len();
    let array_count = disk_cache.array_count();

    // Count shares by parsing smb.conf section headers
    let share_count = count_smb_shares();

    let status = SystemStatus {
        hostname,
        kernel,
        uptime_seconds,
        load,
        memory,
        temperatures,
        fans,
        fan_profile,
        bays,
        disk_count,
        array_count,
        share_count,
    };

    Ok(Json(json!({
        "success": true,
        "data": status,
    })))
}

/// Build the status router.
pub fn router() -> Router {
    Router::new().route("/status", get(get_status))
}

// ---------------------------------------------------------------------------
// Helper functions for reading /proc and /sys
// ---------------------------------------------------------------------------

fn read_fans() -> Vec<FanInfo> {
    (1..=4)
        .map(|i| {
            let rpm = std::fs::read_to_string(format!("/sys/class/hwmon/hwmon0/fan{i}_input"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok());
            let pwm = std::fs::read_to_string(format!("/sys/class/hwmon/hwmon0/pwm{i}"))
                .ok()
                .and_then(|s| s.trim().parse::<u8>().ok());
            let pwm_percent = pwm.map(|p| ((p as u16) * 100 / 255) as u8);
            FanInfo {
                id: i,
                rpm,
                pwm,
                pwm_percent,
            }
        })
        .filter(|f| f.rpm.is_some_and(|r| r > 0) || f.pwm.is_some())
        .collect()
}

fn read_fan_profile() -> String {
    std::fs::read_to_string("/data/config/fan_profile")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "balanced".to_string())
}

fn read_file_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_uptime() -> Option<f64> {
    let content = std::fs::read_to_string("/proc/uptime").ok()?;
    content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
}

fn read_loadavg() -> Option<LoadAverage> {
    let content = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut parts = content.split_whitespace();
    let one = parts.next()?.parse::<f64>().ok()?;
    let five = parts.next()?.parse::<f64>().ok()?;
    let fifteen = parts.next()?.parse::<f64>().ok()?;
    Some(LoadAverage { one, five, fifteen })
}

fn read_meminfo() -> Option<MemoryInfo> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = 0u64;
    let mut available_kb = 0u64;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = parse_meminfo_value(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available_kb = parse_meminfo_value(rest);
        }
    }

    let used_kb = total_kb.saturating_sub(available_kb);
    Some(MemoryInfo {
        total_kb,
        available_kb,
        used_kb,
    })
}

fn parse_meminfo_value(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

fn read_thermal_zones(disk_cache: &sfnas_storage::DiskCache) -> Vec<ThermalZone> {
    let mut zones = Vec::new();
    let thermal_dir = Path::new("/sys/class/thermal");

    let entries = match std::fs::read_dir(thermal_dir) {
        Ok(e) => e,
        Err(_) => return zones,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("thermal_zone") {
            continue;
        }

        let type_path = entry.path().join("type");
        let temp_path = entry.path().join("temp");

        let zone_name = std::fs::read_to_string(&type_path)
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| name_str.to_string());

        let temp_millideg: f64 = std::fs::read_to_string(&temp_path)
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .unwrap_or(0.0);

        zones.push(ThermalZone {
            name: zone_name,
            temp_celsius: temp_millideg / 1000.0,
        });
    }

    // Also read HWMON sensors (ADT7475 on UNVR)
    let hwmon_dir = Path::new("/sys/class/hwmon");
    if let Ok(entries) = std::fs::read_dir(hwmon_dir) {
        for entry in entries.flatten() {
            let hwmon_path = entry.path();
            let chip_name = std::fs::read_to_string(hwmon_path.join("name"))
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            for i in 1..=5 {
                let temp_path = hwmon_path.join(format!("temp{i}_input"));
                if let Ok(raw) = std::fs::read_to_string(&temp_path)
                    && let Ok(millideg) = raw.trim().parse::<f64>()
                {
                    let label = std::fs::read_to_string(hwmon_path.join(format!("temp{i}_label")))
                        .ok()
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| format!("{chip_name} temp{i}"));
                    zones.push(ThermalZone {
                        name: label,
                        temp_celsius: millideg / 1000.0,
                    });
                }
            }
        }
    }

    // HDD temps from SMART cache (instant, no smartctl call)
    for disk in disk_cache.get() {
        if let Some(temp) = disk.health.temperature_celsius {
            let name = disk
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "disk".to_string());
            zones.push(ThermalZone {
                name: format!("HDD {name}"),
                temp_celsius: temp as f64,
            });
        }
    }

    zones
}

fn count_smb_shares() -> usize {
    let content = match std::fs::read_to_string("/etc/samba/smb.conf") {
        Ok(c) => c,
        Err(_) => return 0,
    };

    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed != "[global]"
        })
        .count()
}
