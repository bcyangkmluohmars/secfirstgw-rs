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
    sfgw_log::init(&db).await?;

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
        FwCommands::List => { /* TODO */ }
        FwCommands::Reload => { /* TODO */ }
    }
    Ok(())
}

async fn handle_vpn(cmd: VpnCommands) -> Result<()> {
    match cmd {
        VpnCommands::Status => { /* TODO */ }
        VpnCommands::WgUp => { /* TODO */ }
        VpnCommands::WgDown => { /* TODO */ }
    }
    Ok(())
}

async fn handle_net(cmd: NetCommands) -> Result<()> {
    match cmd {
        NetCommands::Interfaces => { /* TODO */ }
        NetCommands::Vlans => { /* TODO */ }
    }
    Ok(())
}

async fn handle_adopt(cmd: AdoptCommands) -> Result<()> {
    match cmd {
        AdoptCommands::Scan => { /* TODO */ }
        AdoptCommands::Device { mac } => { tracing::info!("adopting {mac}"); }
    }
    Ok(())
}

async fn handle_crypto(cmd: CryptoCommands) -> Result<()> {
    match cmd {
        CryptoCommands::Init => { /* TODO */ }
        CryptoCommands::Unlock => { /* TODO */ }
        CryptoCommands::Status => { /* TODO */ }
    }
    Ok(())
}
