// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// systemd notify / watchdog
// ---------------------------------------------------------------------------

/// Send a message to the systemd notify socket (if $NOTIFY_SOCKET is set).
fn sd_notify(msg: &str) {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        // Abstract socket names start with @, convert to \0 for Linux
        let addr = if let Some(stripped) = path.strip_prefix('@') {
            format!("\0{stripped}")
        } else {
            path
        };
        if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
            let _ = sock.send_to(msg.as_bytes(), &addr);
        }
    }
}

/// Spawn a background task that pings the systemd watchdog at half the
/// configured interval.  Does nothing if $WATCHDOG_USEC is not set.
fn spawn_watchdog() {
    let usec: u64 = match std::env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(v) if v > 0 => v,
        _ => return, // no watchdog configured
    };

    // Ping at half the deadline (systemd recommendation)
    let interval = std::time::Duration::from_micros(usec / 2);

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            sd_notify("WATCHDOG=1");
        }
    });
}

#[derive(Parser)]
#[command(name = "sfgw", about = "secfirstgw — Security First Gateway")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start all services
    Start,
    /// Show system status
    Status,
    /// Manage firewall rules
    Fw {
        #[command(subcommand)]
        cmd: FwCommands,
    },
    /// Manage VPN tunnels
    Vpn {
        #[command(subcommand)]
        cmd: VpnCommands,
    },
    /// Manage network configuration
    Net {
        #[command(subcommand)]
        cmd: NetCommands,
    },
    /// Manage device adoption
    Adopt {
        #[command(subcommand)]
        cmd: AdoptCommands,
    },
    /// Manage disk encryption
    Crypto {
        #[command(subcommand)]
        cmd: CryptoCommands,
    },
}

#[derive(Subcommand)]
enum FwCommands {
    /// List current rules
    List,
    /// Reload firewall configuration
    Reload,
}

#[derive(Subcommand)]
enum VpnCommands {
    /// Show active tunnels
    Status,
    /// Start WireGuard with multi-core distribution
    WgUp,
    /// Stop WireGuard
    WgDown,
}

#[derive(Subcommand)]
enum NetCommands {
    /// Show interfaces
    Interfaces,
    /// Show VLANs
    Vlans,
}

#[derive(Subcommand)]
enum AdoptCommands {
    /// Scan for devices
    Scan,
    /// Adopt a device by MAC
    Device { mac: String },
}

#[derive(Subcommand)]
enum CryptoCommands {
    /// Initialize LUKS2 on HDD
    Init {
        /// Skip confirmation prompt (required — this is a destructive operation)
        #[arg(long)]
        confirm: bool,
    },
    /// Unlock HDD
    Unlock,
    /// Show encryption status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with a broadcast layer for live SSE event streaming.
    let (event_tx, broadcast_layer) = sfgw_api::events::init();
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("sfgw=info"))
        .with(tracing_subscriber::fmt::layer())
        .with(broadcast_layer)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Start) => start_services(event_tx).await?,
        Some(Commands::Status) => show_status().await?,
        Some(Commands::Fw { cmd }) => handle_fw(cmd).await?,
        Some(Commands::Vpn { cmd }) => handle_vpn(cmd).await?,
        Some(Commands::Net { cmd }) => handle_net(cmd).await?,
        Some(Commands::Adopt { cmd }) => handle_adopt(cmd).await?,
        Some(Commands::Crypto { cmd }) => handle_crypto(cmd).await?,
        None => start_services(event_tx).await?,
    }

    Ok(())
}

async fn start_services(event_tx: sfgw_api::events::EventTx) -> Result<()> {
    tracing::info!("starting secfirstgw v{}", env!("CARGO_PKG_VERSION"));

    // Phase 1: Hardware init — detect platform (bare metal / VM / Docker)
    tracing::info!("initializing HAL");
    let platform = sfgw_hal::init()?;
    tracing::info!("platform: {platform}");

    // Phase 2: Crypto — unlock HDD if present
    tracing::info!("checking disk encryption");
    sfgw_crypto::auto_unlock(&platform).await?;

    // Phase 3: Database
    tracing::info!("opening database");
    let db = sfgw_db::open_or_create().await?;

    // Phase 4: Logging with forward secrecy
    tracing::info!("initializing encrypted log");
    let _log = sfgw_log::LogManager::init(&db).await?;

    // Phase 5: Network stack
    tracing::info!("configuring network");
    sfgw_net::configure(&db, &platform).await?;

    // Phase 6: Firewall
    tracing::info!("applying firewall rules");
    sfgw_fw::create_default_rules(&db).await?;
    sfgw_fw::apply_rules(&db).await?;

    // Phase 7: DNS/DHCP
    tracing::info!("starting DNS/DHCP");
    let _dnsmasq = sfgw_dns::start(&db).await?;

    // Phase 8: VPN
    tracing::info!("starting VPN services");
    sfgw_vpn::start(&db).await?;

    // Phase 9: NAS (if HDD/volume present)
    tracing::info!("starting NAS services");
    if let Err(e) = sfgw_nas::start(&db, &platform).await {
        tracing::warn!("NAS services unavailable: {e}");
    }

    // Phase 10: Device adoption listener
    tracing::info!("starting adoption service");
    sfgw_adopt::start(&db).await?;

    // Phase 10b: Ubiquiti Inform listener (if enabled in settings)
    let inform_handle = sfgw_inform::new_handle();
    let inform_state_handle = sfgw_inform::new_state_handle();
    if sfgw_inform::is_enabled(&db).await.unwrap_or(false) {
        tracing::info!("starting Ubiquiti Inform listener (port 8080, MGMT only)");
        match sfgw_inform::start(&db, &inform_handle, &inform_state_handle).await {
            Ok(()) => {
                tracing::info!("Ubiquiti Inform listener running");
            }
            Err(e) => {
                tracing::warn!("Ubiquiti Inform listener failed to start: {e}");
            }
        }
    } else {
        tracing::info!("Ubiquiti Inform disabled (enable via settings)");
    }

    // Phase 11: Intrusion Detection
    tracing::info!("starting IDS engine");
    sfgw_ids::start(&db, sfgw_ids::IdsRole::Gateway).await?;

    // Phase 12: System stats sampler (shared between API + display)
    let sys_stats = sfgw_hal::SystemStats::new();
    sfgw_hal::spawn_stats_sampler(&sys_stats, std::time::Duration::from_secs(2));
    tracing::info!("system stats sampler started");

    // Phase 13: Display (auto-detect: native LCM, character LCD, framebuffer, or none)
    tracing::info!("initializing display");
    let display_config = sfgw_display::auto_detect(&platform);
    let _display = match sfgw_display::init(&display_config, &sys_stats) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("display unavailable: {e}");
            None
        }
    };

    // Signal systemd that we're fully ready, then start watchdog pings
    sd_notify("READY=1");
    spawn_watchdog();

    // Phase 14: API server (blocks)
    tracing::info!("starting API server");
    sfgw_api::serve(&db, event_tx, &sys_stats, &inform_handle, &inform_state_handle).await?;

    Ok(())
}

async fn show_status() -> Result<()> {
    println!("secfirstgw v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

async fn handle_fw(cmd: FwCommands) -> Result<()> {
    match cmd {
        FwCommands::List => {
            let db = sfgw_db::open_or_create().await?;
            let rules = sfgw_fw::load_rules(&db).await?;
            for rule in &rules {
                let status = if rule.enabled { "ON " } else { "OFF" };
                let id = rule.id.unwrap_or(0);
                println!(
                    "[{status}] #{id} {chain} p={pri} {detail}",
                    chain = rule.chain,
                    pri = rule.priority,
                    detail = serde_json::to_string(&rule.detail)?
                );
            }
            println!("{} rules total", rules.len());
        }
        FwCommands::Reload => {
            let db = sfgw_db::open_or_create().await?;
            sfgw_fw::apply_rules(&db).await?;
            println!("Firewall rules applied.");
        }
    }
    Ok(())
}

async fn handle_vpn(cmd: VpnCommands) -> Result<()> {
    match cmd {
        VpnCommands::Status => {
            let db = sfgw_db::open_or_create().await?;
            let tunnels = sfgw_vpn::tunnel::list_tunnels(&db).await?;
            for t in &tunnels {
                let status = if t.enabled { "UP" } else { "DOWN" };
                println!("[{status}] {} port={}", t.name, t.listen_port,);
            }
        }
        VpnCommands::WgUp => {
            let db = sfgw_db::open_or_create().await?;
            let tunnels = sfgw_vpn::tunnel::list_tunnels(&db).await?;
            for t in tunnels.iter().filter(|t| t.enabled) {
                sfgw_vpn::tunnel::start_tunnel(&db, t.id).await?;
                println!("Started tunnel: {}", t.name);
            }
        }
        VpnCommands::WgDown => {
            let db = sfgw_db::open_or_create().await?;
            let tunnels = sfgw_vpn::tunnel::list_tunnels(&db).await?;
            for t in &tunnels {
                let _ = sfgw_vpn::tunnel::stop_tunnel(&db, t.id).await;
                println!("Stopped tunnel: {}", t.name);
            }
        }
    }
    Ok(())
}

async fn handle_net(cmd: NetCommands) -> Result<()> {
    match cmd {
        NetCommands::Interfaces => {
            let db = sfgw_db::open_or_create().await?;
            let ifaces = sfgw_net::list_interfaces(&db).await?;
            for iface in &ifaces {
                let status = if iface.is_up { "UP  " } else { "DOWN" };
                let pvid_str = if iface.pvid == 0 {
                    "WAN".to_string()
                } else {
                    format!("pvid={}", iface.pvid)
                };
                println!(
                    "[{status}] {name:<12} {mac:<18} {pvid:<10} mtu={mtu} ips={ips}",
                    name = iface.name,
                    mac = iface.mac,
                    pvid = pvid_str,
                    mtu = iface.mtu,
                    ips = iface.ips.join(", ")
                );
            }
        }
        NetCommands::Vlans => {
            let db = sfgw_db::open_or_create().await?;
            let vlans: Vec<(String, String, i64)> = {
                let conn = db.lock().await;
                let mut stmt = conn.prepare(
                    "SELECT name, role, vlan_id FROM interfaces WHERE vlan_id IS NOT NULL",
                )?;
                stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .filter_map(|r| r.ok())
                    .collect()
            };
            if vlans.is_empty() {
                println!("No VLANs configured.");
            } else {
                for (name, role, vlan_id) in &vlans {
                    println!("VLAN {vlan_id}: {name} ({role})");
                }
            }
        }
    }
    Ok(())
}

async fn handle_adopt(cmd: AdoptCommands) -> Result<()> {
    match cmd {
        AdoptCommands::Scan => {
            let db = sfgw_db::open_or_create().await?;
            let pending = sfgw_adopt::list_pending(&db).await?;
            let all = sfgw_adopt::list_devices(&db).await?;
            println!(
                "{} devices total, {} pending approval",
                all.len(),
                pending.len()
            );
            for d in &all {
                println!(
                    "  {} {} {:?} state={}",
                    d.mac,
                    d.ip.as_deref().unwrap_or("-"),
                    d.model.as_deref().unwrap_or("-"),
                    d.state
                );
            }
        }
        AdoptCommands::Device { mac } => {
            let db = sfgw_db::open_or_create().await?;
            let ca = sfgw_adopt::start(&db).await?;
            let request = sfgw_adopt::AdoptionRequest {
                device_mac: mac.clone(),
                device_model: String::new(),
                device_ip: String::new(),
                device_public_key: String::new(),
                device_kem_public_key: None,
            };
            sfgw_adopt::approve_device(&db, &ca, &request).await?;
            println!("Device {mac} approved.");
        }
    }
    Ok(())
}

async fn handle_crypto(cmd: CryptoCommands) -> Result<()> {
    match cmd {
        CryptoCommands::Init { confirm } => {
            handle_crypto_init(confirm)?;
        }
        CryptoCommands::Unlock => {
            let platform = sfgw_hal::init()?;
            sfgw_crypto::auto_unlock(&platform).await?;
            println!("Crypto unlock complete.");
        }
        CryptoCommands::Status => {
            handle_crypto_status()?;
        }
    }
    Ok(())
}

/// Show actual LUKS encryption status by querying cryptsetup.
fn handle_crypto_status() -> Result<()> {
    use std::path::Path;
    use std::process::Command;

    let platform = sfgw_hal::init()?;
    println!("Platform: {platform}");

    if !platform.has_hdd() {
        println!("HDD: not detected");
        println!("No HDD detected — encryption status not applicable.");
        return Ok(());
    }

    println!("HDD: present");

    let mapper_path = Path::new("/dev/mapper/sfgw-data");
    if !mapper_path.exists() {
        println!("Encryption: HDD present but encrypted volume not open");
        // Check if the underlying device at least has a LUKS header
        let luks_device = Path::new("/dev/sda1");
        if luks_device.exists() {
            let output = Command::new("cryptsetup")
                .args(["isLuks", "/dev/sda1"])
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    println!("LUKS header: detected on /dev/sda1");
                }
                _ => {
                    println!("LUKS header: not found on /dev/sda1");
                }
            }
        } else {
            println!("Device /dev/sda1 not found");
        }
        return Ok(());
    }

    // Volume is open — query cryptsetup for details
    let output = Command::new("cryptsetup")
        .args(["status", "sfgw-data"])
        .output()
        .context("failed to execute cryptsetup status")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Encryption: failed to query status — {stderr}");
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse key fields from cryptsetup status output
    let mut device = None;
    let mut cipher = None;
    let mut keysize = None;
    let mut active = false;

    for line in stdout.lines() {
        let line = line.trim();
        if line.contains("is active") {
            active = true;
        }
        if let Some(val) = line.strip_prefix("device:") {
            device = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("cipher:") {
            cipher = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("keysize:") {
            keysize = Some(val.trim().to_string());
        }
    }

    println!("Volume:  /dev/mapper/sfgw-data");
    println!("State:   {}", if active { "active" } else { "inactive" });
    if let Some(dev) = device {
        println!("Device:  {dev}");
    }
    if let Some(c) = cipher {
        println!("Cipher:  {c}");
    }
    if let Some(k) = keysize {
        println!("Keysize: {k}");
    }

    Ok(())
}

/// Initialize a LUKS2 volume on /dev/sda1.
fn handle_crypto_init(confirm: bool) -> Result<()> {
    use std::path::Path;
    use std::process::Command;

    let platform = sfgw_hal::init()?;
    println!("Platform: {platform}");

    if !platform.has_hdd() {
        anyhow::bail!("no HDD detected on this platform — cannot initialize LUKS");
    }

    let luks_device = Path::new("/dev/sda1");
    if !luks_device.exists() {
        anyhow::bail!("/dev/sda1 not found — is the HDD partitioned?");
    }

    let mapper_path = Path::new("/dev/mapper/sfgw-data");
    if mapper_path.exists() {
        anyhow::bail!(
            "/dev/mapper/sfgw-data already exists — volume is already open. \
             Close it first with: cryptsetup close sfgw-data"
        );
    }

    if !confirm {
        println!("WARNING: This will DESTROY ALL DATA on /dev/sda1.");
        println!();
        println!("To proceed, re-run with --confirm:");
        println!("  sfgw crypto init --confirm");
        println!();
        println!("Or run manually:");
        println!("  cryptsetup luksFormat --type luks2 \\");
        println!("    --cipher aes-xts-plain64 --key-size 512 \\");
        println!("    --pbkdf argon2id /dev/sda1");
        return Ok(());
    }

    println!("Initializing LUKS2 on /dev/sda1...");
    println!("  Type:   LUKS2");
    println!("  Cipher: aes-xts-plain64 (AES-256-XTS)");
    println!("  PBKDF:  argon2id");

    let output = Command::new("cryptsetup")
        .args([
            "luksFormat",
            "--type",
            "luks2",
            "--cipher",
            "aes-xts-plain64",
            "--key-size",
            "512",
            "--pbkdf",
            "argon2id",
            "--batch-mode",
            "/dev/sda1",
        ])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("failed to execute cryptsetup luksFormat")?;

    if output.status.success() {
        println!("LUKS2 volume initialized successfully on /dev/sda1.");
        println!("Next steps:");
        println!("  1. Set up auto-unlock key (hardware-derived or key file)");
        println!("  2. Run: sfgw crypto unlock");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("cryptsetup luksFormat failed: {stderr}");
    }

    Ok(())
}
