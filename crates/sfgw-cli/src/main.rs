// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

mod update;

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
    /// Manage firmware updates
    Update {
        #[command(subcommand)]
        cmd: UpdateCommands,
    },
    /// Hardware switch ASIC diagnostics (RTL8370MB)
    Switch {
        #[command(subcommand)]
        cmd: SwitchCommands,
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

#[derive(Subcommand)]
enum SwitchCommands {
    /// Dump all switch ASIC registers (VLAN, ports, isolation, etc.)
    Dump,
    /// Read a single register by hex address (e.g. 0x1352)
    Read {
        /// Register address in hex (e.g. 0x1300)
        #[arg(value_parser = parse_hex_u16)]
        reg: u16,
    },
    /// Write a single register (use with caution)
    Write {
        /// Register address in hex
        #[arg(value_parser = parse_hex_u16)]
        reg: u16,
        /// Value in hex
        #[arg(value_parser = parse_hex_u16)]
        val: u16,
    },
    /// Show port link status only
    Ports,
    /// Re-apply VLAN config from DB without full restart
    Reapply,
}

fn parse_hex_u16(s: &str) -> Result<u16, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u16::from_str_radix(s, 16).map_err(|e| format!("invalid hex: {e}"))
}

#[derive(Subcommand)]
enum UpdateCommands {
    /// Check for available firmware updates
    Check,
    /// Download and apply a firmware update
    Apply,
    /// Rollback to the previous firmware version
    Rollback,
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
        Some(Commands::Update { cmd }) => handle_update(cmd).await?,
        Some(Commands::Switch { cmd }) => handle_switch(cmd).await?,
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

    // Load saved personality (defaults to Kevin if none saved)
    sfgw_personality::load(&db).await?;

    // Phase 4: Logging with forward secrecy
    tracing::info!("initializing encrypted log");
    let log_mgr = sfgw_log::LogManager::init(&db).await?;
    let log_handle: sfgw_log::LogHandle = std::sync::Arc::new(tokio::sync::Mutex::new(log_mgr));

    // Spawn background task: rotate log encryption key at midnight.
    {
        let lh = log_handle.clone();
        tokio::spawn(async move {
            loop {
                // Calculate time until next midnight UTC.
                let now = chrono::Utc::now();
                let tomorrow = (now.date_naive() + chrono::Duration::days(1))
                    .and_hms_opt(0, 0, 1)
                    .expect("valid midnight"); // INVARIANT: 00:00:01 is always valid
                let until_midnight = tomorrow
                    .and_utc()
                    .signed_duration_since(now)
                    .to_std()
                    .unwrap_or(std::time::Duration::from_secs(3600));

                tokio::time::sleep(until_midnight).await;

                let mut mgr = lh.lock().await;
                if let Err(e) = mgr.rotate_key().await {
                    tracing::error!("failed to rotate log encryption key: {e}");
                }
            }
        });
    }

    // Phase 5: Network stack
    tracing::info!("configuring network");
    sfgw_net::configure(&db, &platform).await?;

    // Phase 6: Firewall
    tracing::info!("applying firewall rules");
    sfgw_fw::create_default_rules(&db).await?;
    sfgw_fw::apply_rules(&db).await?;

    // Phase 6b: QoS / Traffic Shaping
    tracing::info!("applying QoS traffic shaping");
    if let Err(e) = sfgw_fw::qos::apply_qos(&db).await {
        tracing::warn!("QoS setup failed (continuing): {e}");
    }

    // Phase 6c: UPnP/NAT-PMP (if enabled in settings)
    if sfgw_fw::upnp::is_enabled(&db).await.unwrap_or(false) {
        tracing::info!("starting UPnP/NAT-PMP service");
        // Get LAN gateway IP from networks table
        let lan_ip: std::net::Ipv4Addr = {
            let conn = db.lock().await;
            conn.query_row(
                "SELECT gateway FROM networks WHERE zone = 'lan' AND enabled = 1 LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(std::net::Ipv4Addr::new(192, 168, 1, 1))
        };
        match sfgw_fw::upnp::start(&db, lan_ip).await {
            Ok(_handle) => {
                tracing::info!("UPnP/NAT-PMP service running on {lan_ip}");
            }
            Err(e) => {
                tracing::warn!("UPnP/NAT-PMP failed to start: {e}");
            }
        }
    } else {
        tracing::info!("UPnP/NAT-PMP disabled (enable via settings)");
    }

    // Phase 7: DNS/DHCP
    tracing::info!("starting DNS/DHCP");
    let _dnsmasq = sfgw_dns::start(&db).await?;
    sfgw_dns::spawn_watchdog(&_dnsmasq, db.clone());

    // Phase 8: VPN
    tracing::info!("starting VPN services");
    sfgw_vpn::start(&db).await?;

    // Phase 8b: Dynamic DNS
    tracing::info!("starting DDNS client");
    let ddns_handle = sfgw_net::ddns::new_handle();
    if let Err(e) = sfgw_net::ddns::start_background_tasks(&db, &ddns_handle).await {
        tracing::warn!("DDNS background tasks failed to start: {e}");
    }

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

    // Phase 11c: IDS rule expiry cleanup (removes expired auto-block rules every 60s)
    let db_ids_cleanup = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = sfgw_fw::ids_response::cleanup_expired(&db_ids_cleanup).await {
                tracing::warn!("IDS rule cleanup failed: {e}");
            }
        }
    });

    // Phase 11b: Honeypot listener (if enabled in settings)
    if sfgw_personality::honeypot::is_enabled(&db)
        .await
        .unwrap_or(false)
    {
        tracing::info!(
            "starting honeypot listener (port {})",
            sfgw_personality::honeypot::DEFAULT_PORT
        );
        let listen_addr: std::net::SocketAddr =
            format!("[::]:{}", sfgw_personality::honeypot::DEFAULT_PORT)
                .parse()
                .expect("valid honeypot listen address"); // INVARIANT: constant port

        let db_honeypot = db.clone();
        tokio::spawn(async move {
            if let Err(e) = sfgw_personality::honeypot::serve(listen_addr, move |peer| {
                let db_ids = db_honeypot.clone();
                let ip_str = peer.ip().to_string();
                tokio::spawn(async move {
                    if let Err(e) = sfgw_ids::log_event(
                        &db_ids,
                        "Warning",
                        "honeypot",
                        None,
                        Some(&ip_str),
                        None,
                        None,
                        &format!("honeypot connection from {ip_str}:{}", peer.port()),
                    )
                    .await
                    {
                        tracing::error!("failed to log honeypot event to IDS: {e}");
                    }
                });
            })
            .await
            {
                tracing::error!("honeypot listener failed: {e}");
            }
        });
        tracing::info!("honeypot listener running");
    } else {
        tracing::info!("honeypot disabled (enable via settings)");
    }

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

    // Phase 13b: Background firmware update checker
    tracing::info!("starting firmware update checker");
    update::spawn_update_checker(db.clone());

    // Signal systemd that we're fully ready, then start watchdog pings
    sd_notify("READY=1");
    spawn_watchdog();

    // Phase 14: API server (blocks)
    tracing::info!("starting API server");
    sfgw_api::serve(
        &db,
        event_tx,
        &sys_stats,
        &inform_handle,
        &inform_state_handle,
        &log_handle,
    )
    .await?;

    Ok(())
}

async fn show_status() -> Result<()> {
    tracing::info!("secfirstgw v{}", env!("CARGO_PKG_VERSION"));
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
                tracing::info!(
                    status,
                    id,
                    chain = %rule.chain,
                    priority = rule.priority,
                    detail = %serde_json::to_string(&rule.detail)?,
                    "firewall rule"
                );
            }
            tracing::info!(count = rules.len(), "rules total");
        }
        FwCommands::Reload => {
            let db = sfgw_db::open_or_create().await?;
            sfgw_fw::apply_rules(&db).await?;
            tracing::info!("firewall rules applied");
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
                tracing::info!(status, name = %t.name, port = t.listen_port, "VPN tunnel");
            }
        }
        VpnCommands::WgUp => {
            let db = sfgw_db::open_or_create().await?;
            let tunnels = sfgw_vpn::tunnel::list_tunnels(&db).await?;
            for t in tunnels.iter().filter(|t| t.enabled) {
                sfgw_vpn::tunnel::start_tunnel(&db, t.id).await?;
                tracing::info!(name = %t.name, "started tunnel");
            }
        }
        VpnCommands::WgDown => {
            let db = sfgw_db::open_or_create().await?;
            let tunnels = sfgw_vpn::tunnel::list_tunnels(&db).await?;
            for t in &tunnels {
                let _ = sfgw_vpn::tunnel::stop_tunnel(&db, t.id).await;
                tracing::info!(name = %t.name, "stopped tunnel");
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
                tracing::info!(
                    status,
                    name = %iface.name,
                    mac = %iface.mac,
                    pvid = %pvid_str,
                    mtu = iface.mtu,
                    ips = %iface.ips.join(", "),
                    "interface"
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
                tracing::info!("no VLANs configured");
            } else {
                for (name, role, vlan_id) in &vlans {
                    tracing::info!(vlan_id, name = %name, role = %role, "VLAN");
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
            tracing::info!(
                total = all.len(),
                pending = pending.len(),
                "device scan results"
            );
            for d in &all {
                tracing::info!(
                    mac = %d.mac,
                    ip = %d.ip.as_deref().unwrap_or("-"),
                    model = %d.model.as_deref().unwrap_or("-"),
                    state = %d.state,
                    "device"
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
            tracing::info!(mac = %mac, "device approved");
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
            tracing::info!("crypto unlock complete");
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
    tracing::info!(platform = %platform, "crypto status");

    if !platform.has_hdd() {
        tracing::info!("HDD: not detected");
        tracing::info!("no HDD detected — encryption status not applicable");
        return Ok(());
    }

    tracing::info!("HDD: present");

    let mapper_path = Path::new("/dev/mapper/sfgw-data");
    if !mapper_path.exists() {
        tracing::info!("encryption: HDD present but encrypted volume not open");
        // Check if the underlying device at least has a LUKS header
        let luks_device = Path::new("/dev/sda1");
        if luks_device.exists() {
            let output = Command::new("cryptsetup")
                .args(["isLuks", "/dev/sda1"])
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    tracing::info!("LUKS header: detected on /dev/sda1");
                }
                _ => {
                    tracing::info!("LUKS header: not found on /dev/sda1");
                }
            }
        } else {
            tracing::info!("device /dev/sda1 not found");
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
        tracing::error!(stderr = %stderr, "encryption: failed to query status");
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

    tracing::info!(
        volume = "/dev/mapper/sfgw-data",
        state = if active { "active" } else { "inactive" },
        device = device.as_deref().unwrap_or("unknown"),
        cipher = cipher.as_deref().unwrap_or("unknown"),
        keysize = keysize.as_deref().unwrap_or("unknown"),
        "LUKS volume status"
    );

    Ok(())
}

/// Initialize a LUKS2 volume on /dev/sda1.
fn handle_crypto_init(confirm: bool) -> Result<()> {
    use std::path::Path;
    use std::process::Command;

    let platform = sfgw_hal::init()?;
    tracing::info!(platform = %platform, "crypto init");

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
        tracing::warn!("WARNING: This will DESTROY ALL DATA on /dev/sda1");
        tracing::info!("to proceed, re-run with --confirm: sfgw crypto init --confirm");
        tracing::info!(
            "or run manually: cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf argon2id /dev/sda1"
        );
        return Ok(());
    }

    tracing::info!("initializing LUKS2 on /dev/sda1");
    tracing::info!(
        luks_type = "LUKS2",
        cipher = "aes-xts-plain64 (AES-256-XTS)",
        pbkdf = "argon2id",
        "LUKS parameters"
    );

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
        tracing::info!("LUKS2 volume initialized successfully on /dev/sda1");
        tracing::info!(
            "next steps: 1) set up auto-unlock key (hardware-derived or key file), 2) run: sfgw crypto unlock"
        );
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("cryptsetup luksFormat failed: {stderr}");
    }

    Ok(())
}

async fn handle_update(cmd: UpdateCommands) -> Result<()> {
    let db = sfgw_db::open_or_create().await?;

    match cmd {
        UpdateCommands::Check => {
            let result = update::check_for_update(&db).await?;
            tracing::info!(current_version = %result.current_version, "firmware version");
            if let Some(ref info) = result.available {
                tracing::info!(
                    version = %info.version,
                    channel = if info.prerelease { "beta" } else { "stable" },
                    size_bytes = info.size_bytes,
                    sha256 = %if info.sha256.is_empty() { "n/a" } else { &info.sha256 },
                    "update available"
                );
                if !info.release_notes.is_empty() {
                    for line in info.release_notes.lines().take(10) {
                        tracing::info!(note = %line, "release note");
                    }
                }
            } else {
                tracing::info!("no update available");
            }
        }
        UpdateCommands::Apply => {
            let result = update::check_for_update(&db).await?;
            match result.available {
                Some(info) => {
                    tracing::info!(version = %info.version, "downloading firmware");
                    let _temp = update::download_firmware(&info).await?;
                    tracing::info!("download complete, applying update");
                    update::apply_update(&db, &info).await?;
                    tracing::info!("update applied, service restarting");
                    tracing::info!("if the service fails to start, run: sfgw update rollback");
                }
                None => {
                    tracing::info!("no update available");
                }
            }
        }
        UpdateCommands::Rollback => {
            tracing::info!("rolling back to previous firmware version");
            update::rollback(&db).await?;
            tracing::info!("rollback complete, service restarted");
        }
    }

    Ok(())
}

fn open_switch() -> Result<sfgw_net::rtl8370mb::Rtl8370mb> {
    let board = sfgw_hal::detect_board().context("no board detected")?;
    let sw = board.switch.context("no switch ASIC on this board")?;
    sfgw_net::rtl8370mb::Rtl8370mb::new(sw.smi_iface, sw.smi_phy_addr).context("failed to open SMI")
}

async fn handle_switch(cmd: SwitchCommands) -> Result<()> {
    match cmd {
        SwitchCommands::Dump => {
            let drv = open_switch()?;
            let report = drv.dump_state().context("failed to dump switch state")?;
            tracing::info!("{}", report);
        }
        SwitchCommands::Read { reg } => {
            let drv = open_switch()?;
            let val = drv.raw_read(reg).context("SMI read failed")?;
            tracing::info!(
                reg = format_args!("0x{reg:04X}"),
                value = format_args!("0x{val:04X}"),
                decimal = val,
                "register read"
            );
        }
        SwitchCommands::Write { reg, val } => {
            let drv = open_switch()?;
            drv.smi().smi_write(reg, val).context("SMI write failed")?;
            tracing::info!(
                reg = format_args!("0x{reg:04X}"),
                value = format_args!("0x{val:04X}"),
                "register write"
            );
        }
        SwitchCommands::Ports => {
            let drv = open_switch()?;
            for p in 0..=sfgw_net::rtl8370mb::MAX_PORT {
                match drv.port_get_link(p) {
                    Ok(link) => {
                        let speed = if link.up {
                            match link.speed_mbps {
                                10 => "10M",
                                100 => "100M",
                                1000 => "1G",
                                _ => "?",
                            }
                        } else {
                            ""
                        };
                        let duplex = if link.up && link.full_duplex {
                            "/FD"
                        } else if link.up {
                            "/HD"
                        } else {
                            ""
                        };
                        tracing::info!(
                            port = p,
                            status = if link.up { "UP" } else { "DOWN" },
                            speed = format_args!("{speed}{duplex}"),
                            "port link status"
                        );
                    }
                    Err(e) => tracing::error!(port = p, error = %e, "port read error"),
                }
            }
        }
        SwitchCommands::Reapply => {
            let db = sfgw_db::open_or_create().await?;
            sfgw_net::switch::reconfigure_networks(&db).await?;
            tracing::info!("switch VLAN config reapplied from DB");
        }
    }
    Ok(())
}
