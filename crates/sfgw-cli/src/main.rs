// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    Init,
    /// Unlock HDD
    Unlock,
    /// Show encryption status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("sfgw=info")
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Start) => start_services().await?,
        Some(Commands::Status) => show_status().await?,
        Some(Commands::Fw { cmd }) => handle_fw(cmd).await?,
        Some(Commands::Vpn { cmd }) => handle_vpn(cmd).await?,
        Some(Commands::Net { cmd }) => handle_net(cmd).await?,
        Some(Commands::Adopt { cmd }) => handle_adopt(cmd).await?,
        Some(Commands::Crypto { cmd }) => handle_crypto(cmd).await?,
        None => start_services().await?,
    }

    Ok(())
}

async fn start_services() -> Result<()> {
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
    tracing::info!("loading firewall rules");
    sfgw_fw::load_rules(&db).await?;

    // Phase 7: DNS/DHCP
    tracing::info!("starting DNS/DHCP");
    sfgw_dns::start(&db).await?;

    // Phase 8: VPN
    tracing::info!("starting VPN services");
    sfgw_vpn::start(&db).await?;

    // Phase 9: NAS (if HDD/volume present)
    tracing::info!("starting NAS services");
    sfgw_nas::start(&db, &platform).await?;

    // Phase 10: Device adoption listener
    tracing::info!("starting adoption service");
    sfgw_adopt::start(&db).await?;

    // Phase 11: Intrusion Detection
    tracing::info!("starting IDS engine");
    sfgw_ids::start(&db, sfgw_ids::IdsRole::Gateway).await?;

    // Phase 12: LCD display (bare metal only)
    if platform.has_lcd() {
        tracing::info!("initializing display");
        sfgw_lcd::init().await?;
    }

    // Phase 13: API server (blocks)
    tracing::info!("starting API server");
    sfgw_api::serve(&db).await?;

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
                println!(
                    "[{status}] {} port={} peers={}",
                    t.name,
                    t.listen_port,
                    t.peers.len()
                );
            }
        }
        VpnCommands::WgUp => {
            let db = sfgw_db::open_or_create().await?;
            let tunnels = sfgw_vpn::tunnel::list_tunnels(&db).await?;
            for t in tunnels.iter().filter(|t| t.enabled) {
                sfgw_vpn::tunnel::start_tunnel(&db, &t.name).await?;
                println!("Started tunnel: {}", t.name);
            }
        }
        VpnCommands::WgDown => {
            let db = sfgw_db::open_or_create().await?;
            let tunnels = sfgw_vpn::tunnel::list_tunnels(&db).await?;
            for t in &tunnels {
                let _ = sfgw_vpn::tunnel::stop_tunnel(&db, &t.name).await;
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
                println!(
                    "[{status}] {name:<12} {mac:<18} {role:<8} mtu={mtu} ips={ips}",
                    name = iface.name,
                    mac = iface.mac,
                    role = iface.role,
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
        CryptoCommands::Init => {
            let platform = sfgw_hal::init()?;
            println!("Platform: {platform}");
            println!("LUKS2 init not yet supported via CLI. Use system tools.");
        }
        CryptoCommands::Unlock => {
            let platform = sfgw_hal::init()?;
            sfgw_crypto::auto_unlock(&platform).await?;
            println!("Crypto unlock complete.");
        }
        CryptoCommands::Status => {
            let platform = sfgw_hal::init()?;
            println!("Platform: {platform}");
            println!(
                "HDD: {}",
                if platform.has_hdd() {
                    "present"
                } else {
                    "none"
                }
            );
            println!("Encryption: pending implementation");
        }
    }
    Ok(())
}
