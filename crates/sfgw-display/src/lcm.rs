// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native LCM (LCD Module) driver for UDM Pro front-panel display.
//!
//! Communicates directly with the STM32F2 MCU over serial (`/dev/ttyACM0`)
//! using a JSON-over-UART protocol at 115200 baud. Replaces the proprietary
//! `ulcmd` daemon entirely.
//!
//! # Supported boards
//!
//! | Board ID | Model | Serial device |
//! |----------|-------|---------------|
//! | `ea15` | UDM Pro | `/dev/ttyACM0` |
//!
//! Other boards with LCM displays (UDM SE, UNAS, etc.) likely use a similar
//! protocol but have not been verified. They are **not** supported yet.
//!
//! # Protocol
//!
//! Every message is a single JSON line terminated by `\n`.
//! Request/response correlation uses an integer `id` field.
//!
//! ```json
//! TX: {"id":1,"system":{"bootloader":false}}
//! RX: {"id":1,"status":"ok"}
//! ```
//!
//! The MCU also sends unsolicited events:
//! ```json
//! {"screen.changed":"menu.main"}
//! {"log.warning":"..."}
//! ```
//!
//! # Init sequence
//!
//! 1. `system.bootloader: false` — exit bootloader mode
//! 2. `ui.state: "ready"` — transition MCU from boot → ready
//! 3. `system.set.clock` — sync real-time clock
//! 4. `ui.*` — push initial device data

use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{Display, DisplayError, StatusInfo};

/// Default serial device path for UDM Pro LCM.
const SERIAL_DEVICE: &str = "/dev/ttyACM0";

/// Symlink path used by udev for the Ubiquiti LCD UART.
const SERIAL_DEVICE_BY_ID: &str = "/dev/serial/by-id/usb-Ubiquiti_Inc._Ulcd_application-if00";

/// Baud rate for the UDM Pro MCU serial protocol.
const BAUD_RATE: u32 = 115_200;

/// Fan sensor path on UDM Pro (I2C hwmon, fan2 is the active fan).
const FAN_SENSOR_PATH: &str =
    "/sys/devices/platform/soc/fd880000.i2c-pld/i2c-0/i2c-4/4-002e/fan2_input";

/// Monotonically increasing message ID.
static MSG_ID: AtomicU32 = AtomicU32::new(1);

fn next_id() -> u32 {
    MSG_ID.fetch_add(1, Ordering::Relaxed)
}

/// Known MCU screen names.
pub mod screen {
    pub const MENU_MAIN: &str = "menu.main";
    pub const MENU_NETWORK: &str = "menu.network";
    pub const MENU_INFO: &str = "menu.info";
    pub const MENU_SETTINGS: &str = "menu.settings";
    pub const NETWORK_STATUS: &str = "network.status";
    pub const NETWORK_THROUGHPUT: &str = "network.throughput";
    pub const SCREENSAVER: &str = "screensaver";
}

/// Board-specific LCM configuration.
#[derive(Debug, Clone)]
pub struct LcmBoardConfig {
    /// Serial device path.
    pub serial_path: PathBuf,
    /// System ID to send to MCU.
    pub system_id: u32,
    /// Board revision.
    pub board_revision: u8,
    /// Device MAC address.
    pub mac: String,
    /// Fan sensor sysfs path (if known).
    pub fan_sensor: Option<PathBuf>,
}

impl LcmBoardConfig {
    /// Resolve the serial device path (prefer by-id symlink).
    fn resolve_serial_path() -> PathBuf {
        if Path::new(SERIAL_DEVICE_BY_ID).exists() {
            PathBuf::from(SERIAL_DEVICE_BY_ID)
        } else {
            PathBuf::from(SERIAL_DEVICE)
        }
    }

    /// Configuration for UDM Pro (board ID `ea15`). Verified.
    #[must_use]
    pub fn udm_pro(mac: &str) -> Self {
        Self {
            serial_path: Self::resolve_serial_path(),
            system_id: 0xEA15,
            board_revision: 8,
            mac: mac.to_string(),
            fan_sensor: Some(PathBuf::from(FAN_SENSOR_PATH)),
        }
    }

    /// Configuration for UDM SE (board ID `ea22`). Unverified — same protocol assumed.
    #[must_use]
    pub fn udm_se(mac: &str) -> Self {
        Self {
            serial_path: Self::resolve_serial_path(),
            system_id: 0xEA22,
            board_revision: 8,
            mac: mac.to_string(),
            // TODO: verify fan sensor path on UDM SE hardware
            fan_sensor: Some(PathBuf::from(FAN_SENSOR_PATH)),
        }
    }

    /// Configuration for UDM (board ID `ea21`). Unverified — same protocol assumed.
    #[must_use]
    pub fn udm(mac: &str) -> Self {
        Self {
            serial_path: Self::resolve_serial_path(),
            system_id: 0xEA21,
            board_revision: 1,
            mac: mac.to_string(),
            // UDM may not have the same I2C fan sensor
            fan_sensor: None,
        }
    }
}

/// Native LCM display driver.
///
/// Owns the serial file descriptor and provides methods to push data
/// to the MCU. Thread-safe via internal `Mutex`.
#[derive(Debug)]
pub struct LcmDisplay {
    /// Protected serial port (fd + buffered reader).
    port: Arc<Mutex<SerialPort>>,
    /// Board-specific configuration.
    config: LcmBoardConfig,
}

/// Internal serial port wrapper.
#[derive(Debug)]
struct SerialPort {
    /// Raw file descriptor (owned).
    fd: std::os::fd::OwnedFd,
    /// Buffered reader for line-based JSON responses.
    reader: BufReader<std::fs::File>,
}

impl LcmDisplay {
    /// Send a JSON message to the MCU and return the first response.
    fn send(&self, payload: &serde_json::Value) -> Result<serde_json::Value, DisplayError> {
        let mut port = self
            .port
            .lock()
            .map_err(|e| DisplayError::Internal(anyhow::anyhow!("serial lock poisoned: {e}")))?;

        let id = next_id();
        let mut msg = payload.clone();
        msg.as_object_mut()
            .ok_or_else(|| DisplayError::Internal(anyhow::anyhow!("payload must be object")))?
            .insert("id".to_string(), serde_json::json!(id));

        let mut line = serde_json::to_string(&msg)
            .map_err(|e| DisplayError::Internal(anyhow::anyhow!("json serialize: {e}")))?;
        line.push('\n');

        // Write to fd
        {
            use std::os::fd::AsFd;
            nix::unistd::write(port.fd.as_fd(), line.as_bytes())
                .map_err(|e| DisplayError::Internal(anyhow::anyhow!("serial write: {e}")))?;
        }

        // Read responses until we get one with our id or timeout
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut buf = String::new();
        loop {
            if std::time::Instant::now() > deadline {
                return Err(DisplayError::Internal(anyhow::anyhow!(
                    "timeout waiting for MCU response to id={id}"
                )));
            }

            buf.clear();
            match port.reader.read_line(&mut buf) {
                Ok(0) => continue,
                Ok(_) => {
                    let trimmed = buf.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    // Parse response
                    if let Ok(resp) = serde_json::from_str::<serde_json::Value>(trimmed) {
                        // Check if this is our response (has matching id)
                        if resp.get("id").and_then(|v| v.as_u64()) == Some(u64::from(id)) {
                            return Ok(resp);
                        }
                        // Unsolicited event (screen.changed, log.*) — log and continue
                        if let Some(screen) = resp.get("screen.changed") {
                            tracing::debug!(screen = %screen, "lcm: screen changed by touch");
                        } else if resp.get("log.error").is_some()
                            || resp.get("log.warning").is_some()
                        {
                            tracing::trace!(mcu_log = trimmed, "lcm: MCU log");
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(e) => {
                    return Err(DisplayError::Io(e));
                }
            }
        }
    }

    /// Send a UI data update. Does not wait for response if `fire_and_forget` is true.
    fn send_ui(&self, data: serde_json::Value) -> Result<(), DisplayError> {
        let resp = self.send(&serde_json::json!({"ui": data}))?;
        if resp.get("status").and_then(|v| v.as_str()) == Some("ok") {
            Ok(())
        } else {
            Err(DisplayError::Internal(anyhow::anyhow!(
                "MCU rejected UI update: {resp}"
            )))
        }
    }

    /// Send a system command.
    fn send_system(&self, data: serde_json::Value) -> Result<serde_json::Value, DisplayError> {
        self.send(&serde_json::json!({"system": data}))
    }

    /// Run the full MCU init sequence to exit boot mode.
    fn init_sequence(&self) -> Result<(), DisplayError> {
        // Step 1: Exit bootloader mode
        tracing::debug!("lcm: exiting bootloader mode");
        self.send_system(serde_json::json!({"bootloader": false}))?;

        // Step 2: Get firmware version
        let ver_resp = self.send_system(serde_json::json!({"get": "version"}))?;
        let fw_version = ver_resp
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        tracing::info!(fw_version, "lcm: MCU firmware version");

        // Step 3: Set system ID
        self.send_ui(serde_json::json!({"system.id": self.config.system_id}))?;

        // Step 4: Transition to ready state
        tracing::debug!("lcm: setting state=ready");
        self.send_ui(serde_json::json!({"state": "ready"}))?;

        // Step 5: Sync clock
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let uptime = read_uptime_secs();
        self.send_system(serde_json::json!({
            "set.clock": now,
            "set.clock.monotonic": uptime,
        }))?;

        // Step 6: Mark communication active
        self.send_ui(serde_json::json!({
            "communication": true,
            "uptime": uptime,
        }))?;

        // Step 7: Display settings
        self.send_ui(serde_json::json!({
            "backlight.brightness": 80,
            "board.revision": self.config.board_revision,
            "mac": self.config.mac,
            "screen.timeout": 300,
            "update.time": 100,
        }))?;

        tracing::info!("lcm: init sequence complete — display ready");
        Ok(())
    }

    /// Push current system stats to the MCU.
    pub fn update_stats(&self, stats: &sfgw_hal::SystemStats) -> Result<(), DisplayError> {
        let cpu = stats.cpu();
        let mem = stats.mem();
        let uptime = stats.uptime();
        let fan_rpm = self
            .config
            .fan_sensor
            .as_ref()
            .map(|p| read_sysfs_int(p))
            .unwrap_or(0);

        self.send_ui(serde_json::json!({
            "usage.cpu": cpu,
            "usage.mem": mem,
            "fan.rpm": fan_rpm,
            "fan.speed": std::cmp::min(100, fan_rpm / 50),
            "uptime": uptime,
            "communication": true,
        }))?;

        Ok(())
    }

    /// Push network info to the MCU.
    pub fn update_network(
        &self,
        device_name: &str,
        wan_ip: &str,
        lan_ip: &str,
        dns_ip: &str,
        version: &str,
    ) -> Result<(), DisplayError> {
        self.send_ui(serde_json::json!({
            "device.name": device_name,
            "ip.wan": wan_ip,
            "ip.lan": lan_ip,
            "ip.dns": dns_ip,
        }))?;

        self.send_ui(serde_json::json!({
            "version": version,
        }))?;

        Ok(())
    }

    /// Push throughput data to the MCU.
    pub fn update_throughput(&self, rx_mbps: u64, tx_mbps: u64) -> Result<(), DisplayError> {
        self.send_ui(serde_json::json!({
            "throughput.rx": rx_mbps,
            "throughput.tx": tx_mbps,
        }))
    }

    /// Navigate to a specific screen.
    pub fn set_screen(&self, screen_name: &str) -> Result<(), DisplayError> {
        self.send_ui(serde_json::json!({"screen": screen_name}))
    }

    /// Set backlight brightness (0-100).
    pub fn set_brightness(&self, percent: u8) -> Result<(), DisplayError> {
        self.send_ui(serde_json::json!({"backlight.brightness": percent}))
    }

    /// Spawn a background thread that pushes system stats to the MCU
    /// every 3 seconds. Non-critical — errors are logged and retried.
    fn spawn_stats_loop(&self, sys_stats: Arc<sfgw_hal::SystemStats>) {
        let port = Arc::clone(&self.port);
        let config = self.config.clone();

        std::thread::Builder::new()
            .name("lcm-stats".to_string())
            .spawn(move || {
                // Give the display time to settle after init
                std::thread::sleep(Duration::from_secs(3));

                let display = LcmDisplay { port, config };

                loop {
                    if let Err(e) = display.update_stats(&sys_stats) {
                        tracing::debug!("lcm: stats update failed: {e}");
                    }
                    std::thread::sleep(Duration::from_secs(3));
                }
            })
            .ok(); // Non-critical — if thread spawn fails, display just won't update
    }
}

impl Display for LcmDisplay {
    fn show_status(&self, info: &StatusInfo) -> Result<(), DisplayError> {
        self.send_ui(serde_json::json!({
            "device.name": info.hostname,
            "ip.wan": info.ip,
            "usage.cpu": (info.load * 100.0) as u32,
            "uptime": info.uptime_secs,
        }))?;
        Ok(())
    }

    fn clear(&self) -> Result<(), DisplayError> {
        self.set_screen(screen::SCREENSAVER)
    }

    fn set_backlight(&mut self, on: bool) -> Result<(), DisplayError> {
        self.set_brightness(if on { 80 } else { 0 })
    }

    fn name(&self) -> &str {
        "UDM Pro LCM (serial)"
    }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Detect and initialize the LCM display for a specific board.
///
/// Returns `None` if the board is not supported or the serial device
/// is not present.
pub fn init_for_board(
    board_id: &str,
    mac: &str,
    sys_stats: &Arc<sfgw_hal::SystemStats>,
) -> Result<Option<LcmDisplay>, DisplayError> {
    let config = match board_id {
        // UDM Pro — verified, protocol fully reversed
        "ea15" => LcmBoardConfig::udm_pro(mac),
        // UDM SE — same protocol assumed (unverified, separate arm for future changes)
        "ea22" => LcmBoardConfig::udm_se(mac),
        // UDM — same protocol assumed (unverified, separate arm for future changes)
        "ea21" => LcmBoardConfig::udm(mac),
        _ => {
            tracing::debug!(board_id, "lcm: no LCM config for this board");
            return Ok(None);
        }
    };

    if !config.serial_path.exists() {
        return Err(DisplayError::NotFound(format!(
            "LCM serial device not found: {}",
            config.serial_path.display()
        )));
    }

    let display = open_serial(&config)?;

    // Run init sequence to bring MCU out of boot mode
    display.init_sequence()?;

    // Push initial network info and set default screen
    let version = format!("secfirstgw v{}", env!("CARGO_PKG_VERSION"));
    if let Err(e) = display.update_network("secfirstgw", "", "", "", &version) {
        tracing::warn!("lcm: initial network info push failed: {e}");
    }
    if let Err(e) = display.set_screen(screen::SCREENSAVER) {
        tracing::warn!("lcm: failed to set initial screen: {e}");
    }

    // Spawn background thread for periodic stats updates
    display.spawn_stats_loop(Arc::clone(sys_stats));

    Ok(Some(display))
}

/// Open and configure the serial port.
fn open_serial(config: &LcmBoardConfig) -> Result<LcmDisplay, DisplayError> {
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;
    use std::os::fd::{FromRawFd, OwnedFd};

    let fd = nix::fcntl::open(
        &config.serial_path,
        OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| {
        DisplayError::Internal(anyhow::anyhow!(
            "failed to open {}: {e}",
            config.serial_path.display()
        ))
    })?;

    // SAFETY: fd is valid and just opened by nix::fcntl::open.
    // We immediately wrap it in OwnedFd which takes ownership.
    #[allow(unsafe_code)]
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Configure terminal: 115200 8N1, raw mode
    configure_serial(&owned_fd)?;

    // Create a dup'd fd for the reader so read and write are independent
    let reader_fd = nix::unistd::dup(fd)
        .map_err(|e| DisplayError::Internal(anyhow::anyhow!("dup serial fd: {e}")))?;

    // SAFETY: reader_fd is valid, just created by dup.
    #[allow(unsafe_code)]
    let reader_file = unsafe { std::fs::File::from_raw_fd(reader_fd) };
    let reader = BufReader::new(reader_file);

    let port = SerialPort {
        fd: owned_fd,
        reader,
    };

    Ok(LcmDisplay {
        port: Arc::new(Mutex::new(port)),
        config: config.clone(),
    })
}

/// Configure serial port: 115200 baud, 8N1, raw mode, read timeout.
fn configure_serial(fd: &std::os::fd::OwnedFd) -> Result<(), DisplayError> {
    use nix::sys::termios::{self, BaudRate, SetArg};
    use std::os::fd::AsFd;

    let borrowed = fd.as_fd();
    let mut termios = termios::tcgetattr(borrowed)
        .map_err(|e| DisplayError::Internal(anyhow::anyhow!("tcgetattr: {e}")))?;

    // Raw mode — no echo, no signals, no canonical processing
    termios::cfmakeraw(&mut termios);

    // Baud rate
    let baud = match BAUD_RATE {
        115_200 => BaudRate::B115200,
        9600 => BaudRate::B9600,
        _ => BaudRate::B115200,
    };
    termios::cfsetspeed(&mut termios, baud)
        .map_err(|e| DisplayError::Internal(anyhow::anyhow!("cfsetspeed: {e}")))?;

    // VMIN=0, VTIME=10 (1 second timeout for reads)
    termios.control_chars[nix::sys::termios::SpecialCharacterIndices::VMIN as usize] = 0;
    termios.control_chars[nix::sys::termios::SpecialCharacterIndices::VTIME as usize] = 10;

    termios::tcsetattr(borrowed, SetArg::TCSANOW, &termios)
        .map_err(|e| DisplayError::Internal(anyhow::anyhow!("tcsetattr: {e}")))?;

    // Drain any pending data
    termios::tcflush(borrowed, termios::FlushArg::TCIOFLUSH)
        .map_err(|e| DisplayError::Internal(anyhow::anyhow!("tcflush: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// System stats readers (procfs / sysfs)
// ---------------------------------------------------------------------------

/// Read a single integer from a sysfs file.
fn read_sysfs_int(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Read system uptime in seconds from `/proc/uptime`.
fn read_uptime_secs() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|v| v as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_id_increments() {
        let a = next_id();
        let b = next_id();
        assert!(b > a);
    }

    #[test]
    fn read_uptime_returns_nonzero() {
        let uptime = read_uptime_secs();
        // Should be > 0 on any running system
        assert!(uptime > 0, "uptime should be > 0");
    }

    #[test]
    fn udm_pro_config() {
        let config = LcmBoardConfig::udm_pro("74:AC:B9:14:46:39");
        assert_eq!(config.system_id, 0xEA15);
        assert_eq!(config.board_revision, 8);
        assert_eq!(config.mac, "74:AC:B9:14:46:39");
        assert!(config.fan_sensor.is_some());
    }

    #[test]
    fn init_for_unknown_board_returns_none() {
        let stats = sfgw_hal::SystemStats::new();
        let result = init_for_board("ffff", "00:00:00:00:00:00", &stats).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn screen_constants() {
        assert_eq!(screen::MENU_MAIN, "menu.main");
        assert_eq!(screen::NETWORK_STATUS, "network.status");
    }
}
