#![deny(unsafe_code)]

//! secfirstNAS CLI — full NAS management binary.
//!
//! Subcommands: status, init, health, storage, share, backup, fan, service.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sfnas_storage::{
    Bay, BayState, Disk, FanProfile, RaidArray, RaidLevel, SmartStatus, ThermalManager,
    ThermalStatus,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Known UNVR board IDs from `/proc/ubnthal/board`.
const UNVR_BOARD_IDS: &[(&str, &str)] = &[
    ("ea16", "Ubiquiti UNVR"),
    ("ea18", "Ubiquiti UNVR Pro"),
    ("ea15", "Ubiquiti UDM Pro"),
    ("ea22", "Ubiquiti UDM SE"),
];

const SAMBA_CONF_PATH: &str = "/etc/samba/smb.conf";
const RSYNCD_CONF_PATH: &str = "/etc/rsyncd.conf";

/// Default bind address for the API server (TLS 1.3 on port 443, dual-stack).
const API_BIND_ADDR: &str = "[::]:443";

// ---------------------------------------------------------------------------
// Fan / thermal / hardware constants
// ---------------------------------------------------------------------------

/// Number of fans on the UNVR (matches ThermalManager).
const FAN_COUNT: usize = 3;

/// sysfs base path for the fan/thermal hwmon (ADT7475 on UNVR).
/// Used by `read_hwmon_temp_label` helper; actual sensor reads go through
/// `ThermalManager`.
const HWMON_BASE: &str = "/sys/class/hwmon/hwmon0";

/// Expected RPM range per profile: (min, max).
/// Used by health checks to flag fans running outside normal operating range.
const RPM_RANGE_SILENCE: (u32, u32) = (400, 1500);
const RPM_RANGE_BALANCED: (u32, u32) = (1000, 3000);
const RPM_RANGE_PERFORMANCE: (u32, u32) = (2000, 5000);
const RPM_RANGE_MAX: (u32, u32) = (3000, 6000);

/// SGPO driver sysfs path for status check.
const SGPO_DRIVER_PATH: &str = "/sys/bus/platform/drivers/alpine-sgpo";

/// al_ssm hardware crypto engine check path.
const AL_SSM_PATH: &str = "/sys/bus/platform/drivers/al_crypto";

/// al_dma hardware RAID parity engine check path.
const AL_DMA_PATH: &str = "/sys/bus/platform/drivers/al_dma";

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "secfirstnas")]
#[command(about = "secfirstNAS — security-first NAS firmware")]
#[command(version = VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Increase log verbosity (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Show extended version info (hardware, kernel, uptime)
    #[arg(long)]
    version_info: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show system status overview (bays, disks, arrays, fans, temps, HW engines)
    Status,

    /// First-time setup wizard (non-interactive)
    Init,

    /// Health check (SMART, RAID, filesystem, fans, temps, HW engines)
    Health,

    /// Disk and RAID management
    Storage {
        #[command(subcommand)]
        action: StorageAction,
    },

    /// SMB share management
    Share {
        #[command(subcommand)]
        action: ShareAction,
    },

    /// Rsync backup module management
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },

    /// Fan speed and thermal profile management
    Fan {
        #[command(subcommand)]
        action: FanAction,
    },

    /// Service lifecycle management (API server + NAS services)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Start all NAS services (alias for `service start`)
    Start,

    /// Stop all NAS services (alias for `service stop`)
    Stop,
}

#[derive(Subcommand)]
enum StorageAction {
    /// List all disks and bays
    List,

    /// Show RAID array status
    Arrays,

    /// Create a new RAID array (optionally encrypted with Btrfs)
    Create {
        /// Array name (e.g. "data")
        #[arg(short, long)]
        name: String,

        /// RAID level (0, 1, 5, 10)
        #[arg(short, long)]
        level: String,

        /// Disk devices (e.g. /dev/sdb /dev/sdc)
        #[arg(required = true)]
        disks: Vec<String>,

        /// Enable dm-crypt LUKS encryption on top of RAID
        #[arg(long)]
        encrypt: bool,

        /// Mount point (creates Btrfs filesystem and mounts)
        #[arg(long)]
        mount: Option<String>,
    },
}

#[derive(Subcommand)]
enum ShareAction {
    /// List all SMB shares
    List,

    /// Create a new share
    Create {
        /// Share name
        #[arg(short, long)]
        name: String,

        /// Path on filesystem
        #[arg(short, long)]
        path: String,
    },

    /// Remove a share
    Remove {
        /// Share name
        name: String,
    },

    /// Add a Samba user
    AddUser {
        /// Username
        username: String,

        /// Password
        #[arg(short, long)]
        password: String,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// List rsync modules
    List,

    /// Add a new rsync module
    Add {
        /// Module name
        #[arg(short, long)]
        name: String,

        /// Path to serve via rsync
        #[arg(short, long)]
        path: String,
    },
}

#[derive(Subcommand)]
enum FanAction {
    /// Show fan RPMs, temperatures, and current profile
    Status,

    /// Set silence profile (low RPM, relaxed temp thresholds)
    Silence,

    /// Set balanced profile (moderate RPM and temps)
    Balanced,

    /// Set performance profile (high RPM, aggressive cooling)
    Performance,

    /// Set all fans to 100% duty cycle
    Max,

    /// Set a specific fan to a specific PWM value
    Set {
        /// Fan number (1-3)
        #[arg(value_parser = clap::value_parser!(u8).range(1..=3))]
        fan: u8,

        /// PWM duty cycle (0-255)
        #[arg(value_parser = clap::value_parser!(u8))]
        pwm: u8,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Start API server and all NAS services
    Start {
        /// Bind address for the API server (default: 127.0.0.1:8080)
        #[arg(short, long, default_value = API_BIND_ADDR)]
        bind: String,
    },

    /// Stop all NAS services
    Stop,

    /// Show service status
    Status,
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

/// Print extended version information (hardware, kernel, uptime).
fn print_version_info() {
    let model = detect_hardware_model().unwrap_or_else(|| "Unknown hardware".to_string());
    let kernel = read_kernel_version().unwrap_or_else(|| "unknown".to_string());
    let uptime = read_uptime_secs()
        .map(format_duration)
        .unwrap_or_else(|| "unknown".to_string());

    info!("secfirstNAS v{VERSION}");
    info!("Hardware: {model}");
    info!("Kernel:   {kernel}");
    info!("Uptime:   {uptime}");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Ensure panics in ANY thread (LED service, storage cache, etc.)
    // produce visible output instead of a silent exit 255.
    std::panic::set_hook(Box::new(|info| {
        error!(
            "PANIC in thread {:?}: {info}",
            std::thread::current().name()
        );
    }));

    let cli = Cli::parse();

    if cli.version_info {
        print_version_info();
        return Ok(());
    }

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            // No subcommand given -- show help
            use clap::CommandFactory;
            Cli::command().print_help()?;
            info!("");
            return Ok(());
        }
    };

    let log_level = match cli.verbose {
        0 => "warn",
        1 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .with_target(false)
        .init();

    let result = match command {
        Commands::Status => cmd_status().await,
        Commands::Init => cmd_init().await,
        Commands::Health => cmd_health().await,
        Commands::Storage { action } => cmd_storage(action).await,
        Commands::Share { action } => cmd_share(action).await,
        Commands::Backup { action } => cmd_backup(action).await,
        Commands::Fan { action } => cmd_fan(action).await,
        Commands::Service { action } => cmd_service(action).await,
        Commands::Start => {
            cmd_service(ServiceAction::Start {
                bind: API_BIND_ADDR.to_string(),
            })
            .await
        }
        Commands::Stop => cmd_service(ServiceAction::Stop).await,
    };

    if let Err(ref e) = result {
        // Print a human-readable error chain, not raw Debug output
        error!("{e}");
        for cause in e.chain().skip(1) {
            error!("  caused by: {cause}");
        }
        std::process::exit(1);
    }

    result
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `secfirstnas status` -- pretty overview of the entire system.
async fn cmd_status() -> Result<()> {
    let model = detect_hardware_model().unwrap_or_else(|| "Unknown hardware".to_string());
    let kernel = read_kernel_version().unwrap_or_else(|| "unknown".to_string());
    let uptime = read_uptime_secs()
        .map(format_duration)
        .unwrap_or_else(|| "unknown".to_string());
    let load = read_load_average().unwrap_or_else(|| "unknown".to_string());

    info!("secfirstNAS v{VERSION} -- {model}");
    info!("Kernel: {kernel} | Uptime: {uptime} | Load: {load}");

    // -- Bays -----------------------------------------------------------
    info!("");
    info!("Bays:");

    let bays = Bay::read_all();
    let disks = Disk::list_all().unwrap_or_default();

    // Build a mapping: slot -> Disk (best-effort; sdb=slot1, sdc=slot2, ...)
    let mut slot_disks: Vec<Option<Disk>> = vec![None; bays.len()];
    for (i, disk_path) in disks.iter().enumerate() {
        if i < slot_disks.len() {
            match Disk::from_path(disk_path) {
                Ok(disk) => slot_disks[i] = Some(disk),
                Err(e) => debug!(path = %disk_path.display(), error = %e, "failed to read disk"),
            }
        }
    }

    for (bay, disk_opt) in bays.iter().zip(slot_disks.iter()) {
        let slot_num = bay.slot;
        match bay.state {
            BayState::Present => {
                if let Some(disk) = disk_opt {
                    let temp = disk
                        .health
                        .temperature_celsius
                        .map(|t| format!(", {t}C"))
                        .unwrap_or_default();
                    let health_str = format_smart_status(&disk.health.smart_status);
                    let size = format_bytes(disk.size_bytes);
                    let kind = if disk.rotational { "HDD" } else { "SSD" };
                    info!(
                        "  [{slot_num}] * {kind} Present -- {disk_model} ({size}) [{health_str}{temp}]",
                        disk_model = disk.model.trim(),
                    );
                } else {
                    info!("  [{slot_num}] * HDD Present -- (no details available)");
                }
            }
            BayState::Empty => {
                info!("  [{slot_num}] o Empty");
            }
            BayState::Fault => {
                info!("  [{slot_num}] ! FAULT");
            }
        }
    }

    // -- Fans & Temperatures --------------------------------------------
    info!("");
    info!("Fans & Temperatures:");
    let thermal = ThermalManager::new();
    let thermal_status = thermal.read_status();
    info!("  Profile: {}", thermal_status.active_profile.name());
    for i in 0..FAN_COUNT {
        let rpm = thermal_status.fan_rpm[i]
            .map(|r| format!("{r} RPM"))
            .unwrap_or_else(|| "N/A".to_string());
        let pwm = thermal_status.pwm_values[i]
            .map(|p| format!("PWM {p}"))
            .unwrap_or_else(|| "N/A".to_string());
        info!("  Fan {}: {rpm} ({pwm})", i + 1);
    }
    print_thermal_temps(&thermal_status);

    // -- Arrays ---------------------------------------------------------
    info!("");
    info!("Arrays:");
    let arrays = RaidArray::scan().unwrap_or_default();
    if arrays.is_empty() {
        info!("  (none)");
    } else {
        for line in &arrays {
            info!("  {line}");
        }
    }

    // -- HW Engines -----------------------------------------------------
    info!("");
    info!("Hardware Engines:");
    let sgpo_ok = Path::new(SGPO_DRIVER_PATH).exists();
    info!(
        "  SGPO (bay LEDs):     {}",
        if sgpo_ok { "loaded" } else { "NOT FOUND" }
    );
    let ssm_ok = Path::new(AL_SSM_PATH).exists();
    info!(
        "  al_ssm (HW crypto):  {}",
        if ssm_ok { "loaded" } else { "NOT FOUND" }
    );
    let dma_ok = Path::new(AL_DMA_PATH).exists();
    info!(
        "  al_dma (HW parity):  {}",
        if dma_ok { "loaded" } else { "NOT FOUND" }
    );

    // -- Shares ---------------------------------------------------------
    info!("");
    info!("Shares:");
    let shares = parse_smb_shares();
    if shares.is_empty() {
        info!("  (none)");
    } else {
        for (name, path) in &shares {
            info!("  {name:<16} {path}");
        }
    }

    // -- Network --------------------------------------------------------
    info!("");
    info!("Network:");
    let ifaces = list_network_interfaces();
    if ifaces.is_empty() {
        info!("  (no interfaces detected)");
    } else {
        for line in &ifaces {
            info!("  {line}");
        }
    }

    Ok(())
}

/// `secfirstnas init` -- first-time setup wizard (non-interactive).
async fn cmd_init() -> Result<()> {
    info!("=== secfirstNAS First-Time Setup ===");
    info!("");

    // 1. Detect hardware
    info!("[1/4] Detecting hardware...");
    let model = detect_hardware_model().unwrap_or_else(|| "Unknown hardware".to_string());
    info!("  Model: {model}");

    let kernel = read_kernel_version().unwrap_or_else(|| "unknown".to_string());
    info!("  Kernel: {kernel}");

    // 2. Scan bays
    info!("");
    info!("[2/4] Scanning disk bays...");
    let bays = Bay::read_all();
    let present_count = bays.iter().filter(|b| b.state == BayState::Present).count();
    let total_bays = bays.len();
    info!("  {present_count}/{total_bays} bays populated");

    let disks = Disk::list_all().unwrap_or_default();
    let mut disk_infos: Vec<Disk> = Vec::new();
    for disk_path in &disks {
        match Disk::from_path(disk_path) {
            Ok(d) => {
                let size = format_bytes(d.size_bytes);
                info!("  {} -- {} ({size})", d.path.display(), d.model.trim());
                disk_infos.push(d);
            }
            Err(e) => {
                warn!(path = %disk_path.display(), error = %e, "cannot read disk");
                info!("  {} -- read error: {e}", disk_path.display());
            }
        }
    }

    // 3. Suggest RAID level
    info!("");
    info!("[3/4] RAID recommendation...");
    let disk_count = disk_infos.len();
    let (suggested_level, suggestion) = suggest_raid_level(disk_count);
    info!("  Disks available: {disk_count}");
    info!("  Recommendation:  {suggestion}");

    if let Some(level) = suggested_level
        && !disk_infos.is_empty()
    {
        let ratio = level.capacity_ratio(disk_count);
        let total_raw: u64 = disk_infos.iter().map(|d| d.size_bytes).sum();
        let usable = (total_raw as f64 * ratio) as u64;
        info!(
            "  Usable capacity: ~{} (from {} raw)",
            format_bytes(usable),
            format_bytes(total_raw)
        );
    }

    // 4. Summary
    info!("");
    info!("[4/4] Setup summary");
    info!("  Hardware:   {model}");
    info!("  Disks:      {disk_count} detected");
    if suggested_level.is_some() {
        info!("  RAID:       {suggestion}");
    }
    info!("");
    info!("To create the array, run:");
    if disk_count >= 2 {
        let disk_args: Vec<String> = disk_infos
            .iter()
            .map(|d| d.path.display().to_string())
            .collect();
        let level_str = match suggested_level {
            Some(RaidLevel::Raid0) => "0",
            Some(RaidLevel::Raid1) => "1",
            Some(RaidLevel::Raid5) => "5",
            Some(RaidLevel::Raid10) => "10",
            None => "1",
        };
        info!(
            "  secfirstnas storage create -n data -l {level_str} --encrypt --mount /data/storage {}",
            disk_args.join(" ")
        );
    } else {
        info!("  (not enough disks for RAID -- insert at least 2 disks)");
    }

    Ok(())
}

/// `secfirstnas health` -- comprehensive health check.
async fn cmd_health() -> Result<()> {
    info!("=== secfirstNAS Health Check ===");
    info!("");

    let mut issues: Vec<String> = Vec::new();

    // -- SMART ----------------------------------------------------------
    info!("[SMART] Disk Health");
    let disks = Disk::list_all().unwrap_or_default();
    if disks.is_empty() {
        info!("  No data disks found.");
    }
    for disk_path in &disks {
        match Disk::from_path(disk_path) {
            Ok(disk) => {
                let status_str = format_smart_status(&disk.health.smart_status);
                let temp = disk
                    .health
                    .temperature_celsius
                    .map(|t| format!("{t}C"))
                    .unwrap_or_else(|| "N/A".to_string());
                let hours = disk
                    .health
                    .power_on_hours
                    .map(|h| format!("{h}h"))
                    .unwrap_or_else(|| "N/A".to_string());
                let realloc = disk.health.reallocated_sectors.unwrap_or(0);
                let pending = disk.health.pending_sectors.unwrap_or(0);

                info!("  {} ({}):", disk.path.display(), disk.model.trim());
                info!("    SMART: {status_str}  |  Temp: {temp}  |  Power-on: {hours}");
                info!("    Reallocated sectors: {realloc}  |  Pending sectors: {pending}");

                // Flag problems
                if matches!(disk.health.smart_status, SmartStatus::Failed(_)) {
                    issues.push(format!(
                        "CRITICAL: {} SMART FAILED -- replace immediately",
                        disk.path.display()
                    ));
                }
                if realloc > 0 {
                    issues.push(format!(
                        "WARNING: {} has {realloc} reallocated sectors",
                        disk.path.display()
                    ));
                }
                if pending > 0 {
                    issues.push(format!(
                        "WARNING: {} has {pending} pending sectors",
                        disk.path.display()
                    ));
                }
                if let Some(t) = disk.health.temperature_celsius
                    && t >= 55
                {
                    issues.push(format!(
                        "WARNING: {} temperature is {t}C (threshold: 55C)",
                        disk.path.display()
                    ));
                }
            }
            Err(e) => {
                error!("  {} -- error: {e}", disk_path.display());
                issues.push(format!("ERROR: cannot read {}", disk_path.display()));
            }
        }
    }

    // -- RAID -----------------------------------------------------------
    info!("");
    info!("[RAID] Array Integrity");
    let arrays = RaidArray::scan().unwrap_or_default();
    if arrays.is_empty() {
        info!("  No RAID arrays found.");
    } else {
        // Parse mdstat for more detail
        let mdstat = std::fs::read_to_string("/proc/mdstat").unwrap_or_default();
        if mdstat.is_empty() {
            for line in &arrays {
                info!("  {line}");
            }
        } else {
            for line in mdstat.lines() {
                if !line.is_empty() {
                    info!("  {line}");
                }
            }
        }

        // Check each array device for status
        for line in &arrays {
            // Extract device path from "ARRAY /dev/md/foo ..."
            if let Some(dev) = line.split_whitespace().nth(1) {
                let dev_path = Path::new(dev);
                match RaidArray::status(dev_path) {
                    Ok(sfnas_storage::RaidStatus::Active) => {
                        info!("  {dev}: OK (active/clean)");
                    }
                    Ok(sfnas_storage::RaidStatus::Degraded { missing }) => {
                        let msg = format!("WARNING: {dev} is DEGRADED ({missing} disk(s) missing)");
                        warn!("  {msg}");
                        issues.push(msg);
                    }
                    Ok(sfnas_storage::RaidStatus::Rebuilding { progress }) => {
                        info!("  {dev}: REBUILDING ({progress:.1}%)");
                    }
                    Ok(sfnas_storage::RaidStatus::Checking { progress }) => {
                        info!("  {dev}: CHECKING ({progress:.1}%)");
                    }
                    Ok(sfnas_storage::RaidStatus::Inactive) => {
                        let msg = format!("WARNING: {dev} is INACTIVE");
                        warn!("  {msg}");
                        issues.push(msg);
                    }
                    Err(e) => {
                        debug!(error = %e, "cannot query array status");
                        info!("  {dev}: status unknown ({e})");
                    }
                }
            }
        }
    }

    // -- Filesystem usage -----------------------------------------------
    info!("");
    info!("[FS] Filesystem Usage");
    match run_command("df", &["-h", "--type=btrfs", "--type=ext4", "--type=xfs"]) {
        Ok(output) => {
            for line in output.lines() {
                info!("  {line}");
            }
            // Check for >90% usage
            for line in output.lines().skip(1) {
                if let Some(pct_str) = line.split_whitespace().nth(4)
                    && let Ok(pct) = pct_str.trim_end_matches('%').parse::<u32>()
                    && pct >= 90
                {
                    let mount = line.split_whitespace().last().unwrap_or("unknown");
                    issues.push(format!("WARNING: filesystem {mount} is {pct}% full"));
                }
            }
        }
        Err(_) => info!("  (could not read filesystem usage)"),
    }

    // -- Temperature ----------------------------------------------------
    info!("");
    info!("[TEMP] Temperature Readings");
    let disk_list = Disk::list_all().unwrap_or_default();
    let mut any_temp = false;

    // Use ThermalManager for readings and profile-based thresholds
    let thermal = ThermalManager::new();
    let thermal_status = thermal.read_status();
    let profile = thermal.profile();
    let profile_name = profile.name();
    let hdd_target = profile.hdd_target_c();
    let cpu_target = profile.cpu_target_c();

    for disk_path in &disk_list {
        if let Ok(disk) = Disk::from_path(disk_path)
            && let Some(temp) = disk.health.temperature_celsius
        {
            let status = if temp <= hdd_target {
                "OK"
            } else if temp <= hdd_target + 5 {
                "Warm"
            } else if temp <= hdd_target + 15 {
                "HOT"
            } else {
                "CRITICAL"
            };
            info!(
                "  {} ({}): {temp}C [{status}]",
                disk.path.display(),
                disk.model.trim()
            );
            any_temp = true;

            if temp > hdd_target + 15 {
                issues.push(format!(
                    "CRITICAL: {} temperature is {temp}C (target: {hdd_target}C for {profile_name} profile)",
                    disk.path.display()
                ));
            } else if temp > hdd_target + 5 {
                issues.push(format!(
                    "WARNING: {} temperature is {temp}C (target: {hdd_target}C for {profile_name} profile)",
                    disk.path.display()
                ));
            }
        }
    }
    // Hwmon temperatures from ThermalManager
    for (i, temp_opt) in thermal_status.hwmon_temps_c.iter().enumerate() {
        if let Some(temp) = temp_opt {
            let label = read_hwmon_temp_label(i + 1).unwrap_or_else(|| format!("temp{}", i + 1));
            let status = if *temp <= cpu_target {
                "OK"
            } else if *temp <= cpu_target + 10 {
                "Warm"
            } else {
                "HOT"
            };
            info!("  {label}: {temp}C [{status}]");
            any_temp = true;
            if *temp > cpu_target + 10 {
                issues.push(format!(
                    "CRITICAL: {label} temperature is {temp}C (target: {cpu_target}C for {profile_name} profile)"
                ));
            }
        }
    }
    // CPU temperature from ThermalManager
    if let Some(cpu_temp) = thermal_status.cpu_temp_c {
        info!("  CPU: {cpu_temp}C");
        any_temp = true;
        if cpu_temp > cpu_target + 20 {
            issues.push(format!(
                "CRITICAL: CPU temperature is {cpu_temp}C (target: {cpu_target}C)"
            ));
        } else if cpu_temp > cpu_target + 10 {
            issues.push(format!(
                "WARNING: CPU temperature is {cpu_temp}C (target: {cpu_target}C)"
            ));
        }
    }
    if !any_temp {
        info!("  (no temperature readings available)");
    }

    // -- Fan Health -----------------------------------------------------
    info!("");
    info!("[FAN] Fan Health");
    let (rpm_min, rpm_max) = match profile {
        FanProfile::Silence => RPM_RANGE_SILENCE,
        FanProfile::Balanced => RPM_RANGE_BALANCED,
        FanProfile::Performance => RPM_RANGE_PERFORMANCE,
        FanProfile::Max => RPM_RANGE_MAX,
        _ => RPM_RANGE_BALANCED,
    };
    info!("  Active profile: {profile_name} (expected RPM range: {rpm_min}-{rpm_max})");

    let mut any_fan = false;
    for (i, rpm_opt) in thermal_status.fan_rpm.iter().enumerate() {
        if let Some(rpm) = rpm_opt {
            any_fan = true;
            let fan_num = i + 1;
            let status = if *rpm == 0 {
                "STOPPED"
            } else if *rpm < rpm_min {
                "LOW"
            } else if *rpm > rpm_max {
                "HIGH"
            } else {
                "OK"
            };
            let pwm = thermal_status.pwm_values[i]
                .map(|p| format!(", PWM {p}"))
                .unwrap_or_default();
            info!("  Fan {fan_num}: {rpm} RPM [{status}]{pwm}");

            if *rpm == 0 {
                issues.push(format!("CRITICAL: Fan {fan_num} is STOPPED (0 RPM)"));
            } else if *rpm < rpm_min {
                issues.push(format!(
                    "WARNING: Fan {fan_num} RPM is {rpm} (below expected minimum {rpm_min} for {profile_name} profile)"
                ));
            } else if *rpm > rpm_max {
                issues.push(format!(
                    "WARNING: Fan {fan_num} RPM is {rpm} (above expected maximum {rpm_max} for {profile_name} profile)"
                ));
            }
        }
    }
    if !any_fan {
        info!("  (no fan readings available)");
    }

    // -- HW Engine Health -----------------------------------------------
    info!("");
    info!("[HW] Hardware Engine Health");
    let sgpo_ok = Path::new(SGPO_DRIVER_PATH).exists();
    info!(
        "  SGPO (bay LEDs):     {}",
        if sgpo_ok { "OK" } else { "NOT FOUND" }
    );
    if !sgpo_ok {
        issues.push("WARNING: SGPO driver not loaded -- bay LEDs will not work".to_string());
    }
    let ssm_ok = Path::new(AL_SSM_PATH).exists();
    info!(
        "  al_ssm (HW crypto):  {}",
        if ssm_ok { "OK" } else { "NOT FOUND" }
    );
    if !ssm_ok {
        issues.push(
            "WARNING: al_ssm (HW crypto engine) not loaded -- dm-crypt will use CPU".to_string(),
        );
    }
    let dma_ok = Path::new(AL_DMA_PATH).exists();
    info!(
        "  al_dma (HW parity):  {}",
        if dma_ok { "OK" } else { "NOT FOUND" }
    );
    if !dma_ok {
        issues.push(
            "WARNING: al_dma (HW RAID parity engine) not loaded -- RAID5 will use CPU".to_string(),
        );
    }

    // -- Network --------------------------------------------------------
    info!("");
    info!("[NET] Network Link Status");
    let ifaces = list_network_interfaces();
    if ifaces.is_empty() {
        info!("  (no interfaces detected)");
    } else {
        for line in &ifaces {
            info!("  {line}");
        }
    }

    // -- Summary --------------------------------------------------------
    info!("");
    if issues.is_empty() {
        info!("Health: ALL OK");
    } else {
        warn!("Health: {} issue(s) found:", issues.len());
        for issue in &issues {
            warn!("  - {issue}");
        }
    }

    Ok(())
}

/// `secfirstnas storage ...`
async fn cmd_storage(action: StorageAction) -> Result<()> {
    match action {
        StorageAction::List => {
            let bays = Bay::read_all();
            let disks = Disk::list_all()?;

            info!("Bays:");
            for bay in &bays {
                let slot = bay.slot;
                let state = match bay.state {
                    BayState::Present => "Present",
                    BayState::Empty => "Empty",
                    BayState::Fault => "FAULT",
                };
                info!("  [{slot}] {state}");
            }

            info!("");
            info!("Disks:");
            if disks.is_empty() {
                info!("  No data disks found (eMMC excluded).");
            }
            for disk_path in &disks {
                match Disk::from_path(disk_path) {
                    Ok(disk) => {
                        let size = format_bytes(disk.size_bytes);
                        let health = format_smart_status(&disk.health.smart_status);
                        let temp = disk
                            .health
                            .temperature_celsius
                            .map(|t| format!(", {t}C"))
                            .unwrap_or_default();
                        let kind = if disk.rotational { "HDD" } else { "SSD" };
                        info!(
                            "  {}: {} {kind} ({size}) -- {health}{temp}",
                            disk.path.display(),
                            disk.model.trim(),
                        );
                    }
                    Err(e) => {
                        error!("  {}: error: {e}", disk_path.display());
                    }
                }
            }

            Ok(())
        }

        StorageAction::Arrays => {
            let arrays = RaidArray::scan()?;
            if arrays.is_empty() {
                info!("No RAID arrays found.");
                return Ok(());
            }
            info!("RAID Arrays:");
            for line in &arrays {
                info!("  {line}");
            }

            // Also show /proc/mdstat for detail
            if let Ok(mdstat) = std::fs::read_to_string("/proc/mdstat") {
                info!("");
                info!("/proc/mdstat:");
                for line in mdstat.lines() {
                    info!("  {line}");
                }
            }

            Ok(())
        }

        StorageAction::Create {
            name,
            level,
            disks,
            encrypt,
            mount,
        } => cmd_storage_create(&name, &level, &disks, encrypt, mount.as_deref()).await,
    }
}

/// Full-stack storage creation: RAID -> (optional encrypt) -> Btrfs -> mount.
async fn cmd_storage_create(
    name: &str,
    level: &str,
    disks: &[String],
    encrypt: bool,
    mount_point: Option<&str>,
) -> Result<()> {
    // Validate RAID level
    let raid_level = match level {
        "0" => RaidLevel::Raid0,
        "1" => RaidLevel::Raid1,
        "5" => RaidLevel::Raid5,
        "10" => RaidLevel::Raid10,
        _ => anyhow::bail!("Invalid RAID level: '{level}'. Valid levels: 0, 1, 5, 10"),
    };

    if disks.len() < raid_level.min_disks() {
        anyhow::bail!(
            "RAID{level} requires at least {} disks, but only {} provided",
            raid_level.min_disks(),
            disks.len()
        );
    }

    // Validate disk paths exist
    for d in disks {
        let p = Path::new(d);
        if !p.exists() {
            anyhow::bail!("Disk device {d} does not exist");
        }
    }

    let disk_paths: Vec<PathBuf> = disks.iter().map(PathBuf::from).collect();
    let disk_refs: Vec<&Path> = disk_paths.iter().map(|p| p.as_path()).collect();

    // Step 1: Create RAID array
    info!(
        "[1/{}] Creating RAID{level} array '{name}' with {} disks...",
        if encrypt {
            if mount_point.is_some() { 4 } else { 2 }
        } else if mount_point.is_some() {
            3
        } else {
            1
        },
        disks.len()
    );

    let array =
        RaidArray::create(name, raid_level, &disk_refs).context("Failed to create RAID array")?;
    info!("  Created: {}", array.device.display());
    info!(name, device = %array.device.display(), "RAID array created");

    // The device to format (may become dm-crypt device)
    let mut format_device = array.device.clone();

    // Step 2: Optional LUKS encryption
    if encrypt {
        let step = 2;
        let crypt_name = format!("crypt-{name}");
        info!(
            "[{step}/{}] Setting up LUKS encryption...",
            if mount_point.is_some() { 4 } else { 2 }
        );

        // TODO: sfnas_storage does not yet expose a cryptsetup API.
        // When available, use sfnas_storage::CryptVolume::format() and ::open().
        // For now, shell out to cryptsetup directly.

        // Format LUKS
        let luks_output = Command::new("cryptsetup")
            .args([
                "luksFormat",
                "--type",
                "luks2",
                "--cipher",
                "aes-xts-plain64",
                "--key-size",
                "512",
                "--hash",
                "sha512",
                "--iter-time",
                "5000",
                "--batch-mode",
            ])
            .arg(array.device.as_os_str())
            .stdin(std::process::Stdio::inherit())
            .output()
            .context("Failed to run cryptsetup luksFormat")?;

        if !luks_output.status.success() {
            let stderr = String::from_utf8_lossy(&luks_output.stderr);
            anyhow::bail!("cryptsetup luksFormat failed: {stderr}");
        }
        info!("  LUKS2 formatted on {}", array.device.display());

        // Open LUKS
        let open_output = Command::new("cryptsetup")
            .args(["open", "--type", "luks2"])
            .arg(array.device.as_os_str())
            .arg(&crypt_name)
            .stdin(std::process::Stdio::inherit())
            .output()
            .context("Failed to run cryptsetup open")?;

        if !open_output.status.success() {
            let stderr = String::from_utf8_lossy(&open_output.stderr);
            anyhow::bail!("cryptsetup open failed: {stderr}");
        }

        format_device = PathBuf::from(format!("/dev/mapper/{crypt_name}"));
        info!("  Opened as: {}", format_device.display());
        info!(crypt_name, "LUKS volume opened");
    }

    // Step 3: Optional Btrfs + mount
    if let Some(mp) = mount_point {
        let step = if encrypt { 3 } else { 2 };
        let total = if encrypt { 4 } else { 3 };

        // Create Btrfs
        info!("[{step}/{total}] Creating Btrfs filesystem...");

        // TODO: sfnas_storage does not yet expose a btrfs API.
        // When available, use sfnas_storage::BtrfsVolume::format().
        let mkfs_output = Command::new("mkfs.btrfs")
            .args(["-f", "-L", name])
            .arg(format_device.as_os_str())
            .output()
            .context("Failed to run mkfs.btrfs")?;

        if !mkfs_output.status.success() {
            let stderr = String::from_utf8_lossy(&mkfs_output.stderr);
            anyhow::bail!("mkfs.btrfs failed: {stderr}");
        }
        info!("  Btrfs created on {}", format_device.display());

        // Mount
        let mount_step = step + 1;
        info!("[{mount_step}/{total}] Mounting at {mp}...");
        std::fs::create_dir_all(mp)
            .with_context(|| format!("Failed to create mount point: {mp}"))?;

        let mount_output = Command::new("mount")
            .args([
                "-t",
                "btrfs",
                "-o",
                "compress=zstd:3,noatime,space_cache=v2",
            ])
            .arg(format_device.as_os_str())
            .arg(mp)
            .output()
            .context("Failed to mount filesystem")?;

        if !mount_output.status.success() {
            let stderr = String::from_utf8_lossy(&mount_output.stderr);
            anyhow::bail!("mount failed: {stderr}");
        }
        info!("  Mounted at {mp}");
        info!(mount_point = mp, "filesystem mounted");
    }

    info!("");
    info!("Storage stack created successfully:");
    info!(
        "  RAID:   /dev/md/{name} (RAID{level}, {} disks)",
        disks.len()
    );
    if encrypt {
        info!("  Crypt:  /dev/mapper/crypt-{name} (LUKS2, AES-XTS-512)");
    }
    if let Some(mp) = mount_point {
        info!("  FS:     Btrfs (zstd compression)");
        info!("  Mount:  {mp}");
    }

    Ok(())
}

/// `secfirstnas share ...`
async fn cmd_share(action: ShareAction) -> Result<()> {
    match action {
        ShareAction::List => {
            let shares = parse_smb_shares();
            if shares.is_empty() {
                info!("No SMB shares configured.");
                if !Path::new(SAMBA_CONF_PATH).exists() {
                    info!("  ({SAMBA_CONF_PATH} not found)");
                }
            } else {
                info!("SMB Shares:");
                info!("  {:<20} PATH", "NAME");
                info!("  {:<20} ----", "----");
                for (name, path) in &shares {
                    info!("  {name:<20} {path}");
                }
            }
            Ok(())
        }

        ShareAction::Create { name, path } => {
            info!("Creating share '{name}' at {path}...");

            let share = sfnas_share::Share::new(&name, PathBuf::from(&path));

            // Ensure share path exists
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {path}"))?;

            // Load existing config or create new
            let mut config = sfnas_share::SambaConfig::new("WORKGROUP");

            // Re-add existing shares so we don't clobber them
            let existing = parse_smb_shares();
            for (ename, epath) in &existing {
                if ename != &name {
                    let existing_share = sfnas_share::Share::new(ename, PathBuf::from(epath));
                    let _ = config.add_share(existing_share);
                }
            }

            config
                .add_share(share)
                .with_context(|| format!("Failed to add share '{name}'"))?;
            config
                .apply()
                .context("Failed to apply Samba configuration")?;

            info!("Share '{name}' created at {path}.");
            info!(name, path, "share created");
            Ok(())
        }

        ShareAction::Remove { name } => {
            info!("Removing share '{name}'...");

            let existing = parse_smb_shares();
            if !existing.iter().any(|(n, _)| n == &name) {
                anyhow::bail!("Share '{name}' not found in {SAMBA_CONF_PATH}");
            }

            // Rebuild config without the removed share
            let mut config = sfnas_share::SambaConfig::new("WORKGROUP");
            for (ename, epath) in &existing {
                if ename != &name {
                    let share = sfnas_share::Share::new(ename, PathBuf::from(epath));
                    let _ = config.add_share(share);
                }
            }
            config
                .apply()
                .context("Failed to apply Samba configuration")?;

            info!("Share '{name}' removed.");
            info!(name, "share removed");
            Ok(())
        }

        ShareAction::AddUser { username, password } => {
            info!("Adding Samba user '{username}'...");
            sfnas_share::SambaConfig::add_user(&username, &password)
                .with_context(|| format!("Failed to add Samba user '{username}'"))?;
            info!("Samba user '{username}' added.");
            info!(username, "samba user added");
            Ok(())
        }
    }
}

/// `secfirstnas backup ...`
async fn cmd_backup(action: BackupAction) -> Result<()> {
    match action {
        BackupAction::List => {
            let modules = parse_rsync_modules();
            if modules.is_empty() {
                info!("No rsync modules configured.");
                if !Path::new(RSYNCD_CONF_PATH).exists() {
                    info!("  ({RSYNCD_CONF_PATH} not found)");
                }
            } else {
                info!("Rsync Modules:");
                info!("  {:<20} PATH", "NAME");
                info!("  {:<20} ----", "----");
                for (name, path) in &modules {
                    info!("  {name:<20} {path}");
                }
            }
            Ok(())
        }

        BackupAction::Add { name, path } => {
            info!("Adding rsync module '{name}' -> {path}...");

            // Validate the path exists
            let p = Path::new(&path);
            if !p.exists() {
                std::fs::create_dir_all(p)
                    .with_context(|| format!("Failed to create directory: {path}"))?;
                info!("  Created directory: {path}");
            }

            // Read existing config or create new
            let existing_conf = std::fs::read_to_string(RSYNCD_CONF_PATH).unwrap_or_default();

            // Check for duplicate
            if existing_conf.contains(&format!("[{name}]")) {
                anyhow::bail!("Rsync module '{name}' already exists in {RSYNCD_CONF_PATH}");
            }

            // Append module
            let module_block = format!(
                "\n[{name}]\n\
                 \tpath = {path}\n\
                 \tcomment = secfirstNAS backup module\n\
                 \tread only = no\n\
                 \tlist = yes\n\
                 \tauth users = backup\n\
                 \tsecrets file = /data/config/rsyncd.secrets\n\
                 \thosts allow = 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16\n"
            );

            let new_conf = if existing_conf.is_empty() {
                // Create a new config with global section
                format!(
                    "# secfirstNAS rsyncd configuration\n\
                     # Generated by secfirstnas CLI\n\
                     \n\
                     uid = root\n\
                     gid = root\n\
                     use chroot = yes\n\
                     max connections = 4\n\
                     log file = /var/log/rsyncd.log\n\
                     {module_block}"
                )
            } else {
                format!("{existing_conf}{module_block}")
            };

            // Ensure parent directory exists
            if let Some(parent) = Path::new(RSYNCD_CONF_PATH).parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }

            std::fs::write(RSYNCD_CONF_PATH, &new_conf)
                .with_context(|| format!("Failed to write {RSYNCD_CONF_PATH}"))?;

            info!("Rsync module '{name}' added.");
            info!("");
            info!("To sync from a remote host:");
            info!("  rsync -avz /source/ rsync://backup@<NAS_IP>/{name}/");
            info!("");
            info!("Note: ensure rsyncd secrets file exists at /data/config/rsyncd.secrets");

            info!(name, path, "rsync module added");
            Ok(())
        }
    }
}

/// `secfirstnas fan ...`
async fn cmd_fan(action: FanAction) -> Result<()> {
    let mut thermal = ThermalManager::new();

    match action {
        FanAction::Status => {
            let status = thermal.read_status();
            info!("Fan Status:");
            info!("  Active profile: {}", status.active_profile.name());
            info!("");

            for i in 0..FAN_COUNT {
                let rpm = status.fan_rpm[i]
                    .map(|r| format!("{r} RPM"))
                    .unwrap_or_else(|| "N/A".to_string());
                let pwm = status.pwm_values[i]
                    .map(|p| format!("{p}/255 ({:.0}%)", p as f64 / 255.0 * 100.0))
                    .unwrap_or_else(|| "N/A".to_string());
                info!("  Fan {}: {rpm}  PWM: {pwm}", i + 1);
            }

            info!("");
            info!("Temperatures:");
            print_thermal_temps(&status);

            Ok(())
        }

        FanAction::Silence => {
            let profile = FanProfile::Silence;
            info!(
                "Setting fan profile: {} (min PWM {})...",
                profile.name(),
                profile.min_pwm()
            );
            thermal.set_profile(profile.clone());
            apply_profile_fans(&mut thermal)?;
            info!(
                "Done. HDD target: {}C, CPU target: {}C",
                profile.hdd_target_c(),
                profile.cpu_target_c()
            );
            Ok(())
        }

        FanAction::Balanced => {
            let profile = FanProfile::Balanced;
            info!(
                "Setting fan profile: {} (min PWM {})...",
                profile.name(),
                profile.min_pwm()
            );
            thermal.set_profile(profile.clone());
            apply_profile_fans(&mut thermal)?;
            info!(
                "Done. HDD target: {}C, CPU target: {}C",
                profile.hdd_target_c(),
                profile.cpu_target_c()
            );
            Ok(())
        }

        FanAction::Performance => {
            let profile = FanProfile::Performance;
            info!(
                "Setting fan profile: {} (min PWM {})...",
                profile.name(),
                profile.min_pwm()
            );
            thermal.set_profile(profile.clone());
            apply_profile_fans(&mut thermal)?;
            info!(
                "Done. HDD target: {}C, CPU target: {}C",
                profile.hdd_target_c(),
                profile.cpu_target_c()
            );
            Ok(())
        }

        FanAction::Max => {
            info!("Setting all fans to 100% (PWM 255)...");
            thermal.set_profile(FanProfile::Max);
            apply_profile_fans(&mut thermal)?;
            info!("Done.");
            Ok(())
        }

        FanAction::Set { fan, pwm } => {
            info!("Setting fan {fan} to PWM {pwm}...");
            thermal
                .set_pwm(fan, pwm)
                .map_err(|e| anyhow::anyhow!("failed to set fan PWM: {e}"))?;
            info!(fan, pwm, "fan PWM set directly");
            info!("Done.");
            Ok(())
        }
    }
}

/// `secfirstnas service ...`
async fn cmd_service(action: ServiceAction) -> Result<()> {
    match action {
        ServiceAction::Start { bind } => {
            info!("Starting secfirstNAS services...");

            // Start system services
            let services = ["samba", "sshd", "chronyd", "rsyncd"];
            for svc in &services {
                match Command::new("rc-service").args([svc, "start"]).status() {
                    Ok(status) if status.success() => {
                        info!(service = svc, "started");
                    }
                    Ok(_) => {
                        error!(service = svc, "FAILED to start");
                    }
                    Err(e) => {
                        error!(service = svc, error = %e, "failed to start");
                    }
                }
            }

            // Open (or create) the encrypted database.
            // DB path configured via SFGW_DB_PATH env var (set in init script).
            // Defaults to /var/lib/sfgw/sfgw.db if unset.
            info!("  db: opening...");
            let db = sfgw_db::open_or_create()
                .await
                .map_err(|e| anyhow::anyhow!("database error: {e}"))?;
            info!("  db: ready");

            // Start the API server
            let bind_addr: SocketAddr = bind
                .parse()
                .with_context(|| format!("invalid bind address: {bind}"))?;

            info!("  api: starting on {bind_addr}...");
            info!(%bind_addr, "starting API server");

            sfnas_api::serve(&db, bind_addr, Some(Path::new("/data/www")))
                .await
                .map_err(|e| anyhow::anyhow!("API server error: {e}"))?;

            Ok(())
        }

        ServiceAction::Stop => {
            info!("Stopping secfirstNAS services...");

            let services = ["samba", "rsyncd"];
            for svc in &services {
                match Command::new("rc-service").args([svc, "stop"]).status() {
                    Ok(status) if status.success() => {
                        info!(service = svc, "stopped");
                    }
                    Ok(_) => {
                        error!(service = svc, "FAILED to stop");
                    }
                    Err(e) => {
                        error!(service = svc, error = %e, "failed to stop");
                    }
                }
            }

            info!("Done.");
            Ok(())
        }

        ServiceAction::Status => {
            info!("Service Status:");

            let services = ["samba", "sshd", "chronyd", "rsyncd"];
            for svc in &services {
                let status = match Command::new("rc-service").args([svc, "status"]).output() {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let first_line = stdout.lines().next().unwrap_or("unknown");
                        if output.status.success() {
                            format!("running  {first_line}")
                        } else {
                            format!("stopped  {first_line}")
                        }
                    }
                    Err(e) => format!("error: {e}"),
                };
                info!("  {svc:<12} {status}");
            }

            // Check if the API server port is listening
            let api_listening = check_port_listening(8080);
            info!(
                "  {:<12} {}",
                "api",
                if api_listening {
                    "running (port 8080)"
                } else {
                    "stopped"
                }
            );

            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers — fan / thermal / LED
// ---------------------------------------------------------------------------

/// Apply the current profile to all fans via ThermalManager.
///
/// Runs one control tick which reads sensors and sets PWM values accordingly.
fn apply_profile_fans(thermal: &mut ThermalManager) -> Result<()> {
    let status = thermal
        .tick()
        .map_err(|e| anyhow::anyhow!("failed to apply fan profile: {e}"))?;

    for i in 0..FAN_COUNT {
        let rpm = status.fan_rpm[i]
            .map(|r| format!("{r} RPM"))
            .unwrap_or_else(|| "reading...".to_string());
        let pwm = status.pwm_values[i]
            .map(|p| format!("PWM {p}"))
            .unwrap_or_else(|| "N/A".to_string());
        info!("  Fan {}: {pwm} ({rpm})", i + 1);
    }
    Ok(())
}

/// Print temperature readings from a `ThermalStatus` snapshot.
fn print_thermal_temps(status: &ThermalStatus) {
    for (i, temp_opt) in status.hwmon_temps_c.iter().enumerate() {
        if let Some(temp) = temp_opt {
            let label = read_hwmon_temp_label(i + 1).unwrap_or_else(|| format!("temp{}", i + 1));
            info!("  {label}: {temp}C");
        }
    }
    if let Some(cpu_temp) = status.cpu_temp_c {
        info!("  CPU: {cpu_temp}C");
    }
    for (dev, temp) in &status.hdd_temps_c {
        info!("  {dev}: {temp}C");
    }
}

/// Read a hwmon temperature sensor label. Sensor numbers are 1-indexed.
fn read_hwmon_temp_label(sensor: usize) -> Option<String> {
    let path = format!("{HWMON_BASE}/temp{sensor}_label");
    let content = std::fs::read_to_string(path).ok()?;
    let label = content.trim().to_string();
    if label.is_empty() { None } else { Some(label) }
}

/// Check if a TCP port is currently listening (best-effort via /proc/net/tcp).
fn check_port_listening(port: u16) -> bool {
    let hex_port = format!("{port:04X}");

    // Check both IPv4 and IPv6 TCP socket tables
    for tcp_path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(tcp_path) {
            for line in content.lines().skip(1) {
                // local_address is the second field: "IP:PORT", state is the fourth
                if let Some(local) = line.split_whitespace().nth(1)
                    && let Some(p) = local.split(':').nth(1)
                    && p == hex_port
                    && let Some(state) = line.split_whitespace().nth(3)
                    && state == "0A"
                // 0A = LISTEN
                {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Helpers — system information
// ---------------------------------------------------------------------------

/// Detect hardware model from `/proc/ubnthal/board` or `/sys/class/dmi/id/board_name`.
fn detect_hardware_model() -> Option<String> {
    // Try Ubiquiti board ID first
    if let Ok(content) = std::fs::read_to_string("/proc/ubnthal/board")
        && let Some(board_id) = content.lines().find_map(|l| l.strip_prefix("boardid="))
    {
        let board_id = board_id.trim();
        for &(id, model) in UNVR_BOARD_IDS {
            if id == board_id {
                return Some(model.to_string());
            }
        }
        return Some(format!("Ubiquiti (board {board_id})"));
    }

    // Fallback: DMI board name
    if let Ok(board) = std::fs::read_to_string("/sys/class/dmi/id/board_name") {
        let board = board.trim();
        if !board.is_empty() {
            return Some(board.to_string());
        }
    }

    // Fallback: product name
    if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let product = product.trim();
        if !product.is_empty() {
            return Some(product.to_string());
        }
    }

    None
}

/// Read kernel version from `uname -r`.
fn read_kernel_version() -> Option<String> {
    let output = Command::new("uname").arg("-r").output().ok()?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Read system uptime in seconds from `/proc/uptime`.
fn read_uptime_secs() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/uptime").ok()?;
    content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| f as u64)
}

/// Read 1-minute load average from `/proc/loadavg`.
fn read_load_average() -> Option<String> {
    let content = std::fs::read_to_string("/proc/loadavg").ok()?;
    // Format: "0.12 0.15 0.10 1/234 5678"
    let parts: Vec<&str> = content.split_whitespace().take(3).collect();
    if parts.len() >= 3 {
        Some(format!("{} {} {}", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// Format seconds into a human-readable duration.
fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;

    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

/// Format bytes into human-readable string (e.g. "4.0 TB").
fn format_bytes(bytes: u64) -> String {
    const TB: u64 = 1_099_511_627_776;
    const GB: u64 = 1_073_741_824;
    const MB: u64 = 1_048_576;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Format SMART status for display.
fn format_smart_status(status: &SmartStatus) -> String {
    match status {
        SmartStatus::Passed => "Healthy".to_string(),
        SmartStatus::Failed(reason) => format!("FAILED: {reason}"),
        SmartStatus::Unknown => "Unknown".to_string(),
    }
}

/// Suggest a RAID level based on disk count.
fn suggest_raid_level(disk_count: usize) -> (Option<RaidLevel>, String) {
    match disk_count {
        0 => (
            None,
            "No disks available. Insert at least 2 disks.".to_string(),
        ),
        1 => (
            None,
            "Only 1 disk available. Insert at least 1 more for RAID.".to_string(),
        ),
        2 => (
            Some(RaidLevel::Raid1),
            "RAID1 (mirror) -- full redundancy, 50% usable capacity".to_string(),
        ),
        3 => (
            Some(RaidLevel::Raid5),
            "RAID5 -- 1 disk parity, 66% usable capacity".to_string(),
        ),
        4 => (
            Some(RaidLevel::Raid5),
            "RAID5 -- 1 disk parity, 75% usable capacity (RAID10 also viable)".to_string(),
        ),
        n => (
            Some(RaidLevel::Raid5),
            format!(
                "RAID5 -- 1 disk parity, {n} disks, {}% usable capacity",
                ((n - 1) * 100) / n
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers — parsing
// ---------------------------------------------------------------------------

/// Parse share names and paths from smb.conf.
fn parse_smb_shares() -> Vec<(String, String)> {
    let content = match std::fs::read_to_string(SAMBA_CONF_PATH) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut shares = Vec::new();
    let mut current_section: Option<String> = None;
    let mut current_path: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // Section header: [name]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Save previous section
            if let (Some(name), Some(path)) = (current_section.take(), current_path.take())
                && name != "global"
            {
                shares.push((name, path));
            }
            current_section = Some(trimmed[1..trimmed.len() - 1].to_string());
            current_path = None;
        } else if current_section.is_some() {
            // Parse "path = /some/path"
            if let Some(val) = trimmed.strip_prefix("path") {
                let val = val.trim_start_matches([' ', '=', '\t']);
                current_path = Some(val.trim().to_string());
            }
        }
    }

    // Don't forget the last section
    if let (Some(name), Some(path)) = (current_section, current_path)
        && name != "global"
    {
        shares.push((name, path));
    }

    shares
}

/// Parse rsync modules from rsyncd.conf.
fn parse_rsync_modules() -> Vec<(String, String)> {
    let content = match std::fs::read_to_string(RSYNCD_CONF_PATH) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut modules = Vec::new();
    let mut current_section: Option<String> = None;
    let mut current_path: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if let (Some(name), Some(path)) = (current_section.take(), current_path.take()) {
                modules.push((name, path));
            }
            current_section = Some(trimmed[1..trimmed.len() - 1].to_string());
            current_path = None;
        } else if current_section.is_some()
            && let Some(val) = trimmed.strip_prefix("path")
        {
            let val = val.trim_start_matches([' ', '=', '\t']);
            current_path = Some(val.trim().to_string());
        }
    }

    if let (Some(name), Some(path)) = (current_section, current_path) {
        modules.push((name, path));
    }

    modules
}

/// List network interfaces with IP and link status.
fn list_network_interfaces() -> Vec<String> {
    // Use `ip -brief addr` for a concise view
    let output = match Command::new("ip").args(["-brief", "addr"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let iface = parts[0];
        let state = parts[1];

        // Skip loopback and virtual interfaces
        if iface == "lo" || iface.starts_with("veth") || iface.starts_with("docker") {
            continue;
        }

        let addrs: Vec<&str> = parts[2..].to_vec();
        let addr_str = if addrs.is_empty() {
            "no address".to_string()
        } else {
            addrs.join(", ")
        };

        // Try to get link speed
        let speed = read_link_speed(iface);
        let speed_str = speed.map(|s| format!(" ({s})")).unwrap_or_default();

        lines.push(format!("{iface}: {addr_str}{speed_str}, {state}"));
    }

    lines
}

/// Read link speed from sysfs (e.g. "1000" -> "1Gbps").
fn read_link_speed(iface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{iface}/speed");
    let speed_str = std::fs::read_to_string(path).ok()?;
    let speed: u32 = speed_str.trim().parse().ok()?;

    Some(match speed {
        100_000 => "100Gbps".to_string(),
        40_000 => "40Gbps".to_string(),
        25_000 => "25Gbps".to_string(),
        10_000 => "10Gbps".to_string(),
        5_000 => "5Gbps".to_string(),
        2_500 => "2.5Gbps".to_string(),
        1_000 => "1Gbps".to_string(),
        100 => "100Mbps".to_string(),
        10 => "10Mbps".to_string(),
        s => format!("{s}Mbps"),
    })
}

/// Run a command and return its stdout.
fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run: {cmd}"))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
