// SPDX-License-Identifier: AGPL-3.0-or-later

//! UDM Pro LCM display driver via `ulcmd` Unix domain socket.
//!
//! The UDM Pro has a 1.3" IPS LCD (128x128px) controlled by an STM32F2 MCU.
//! The `ulcmd` daemon communicates with the MCU over serial (`/dev/ttyACM0`)
//! and exposes a JSON command interface via a Unix domain socket at
//! `/var/run/ulcmd_uds_server`.
//!
//! This driver controls the display by switching between the MCU's built-in
//! screens. The MCU renders all screens locally — we only tell it which
//! screen to show.
//!
//! # Available screens
//!
//! | Screen name | Content |
//! |---|---|
//! | `network.about` | Device name, IP, firmware version |
//! | `network.status` | Network status overview |
//! | `network.throughput` | Live throughput graph |
//! | `network.clients` | Connected client count |
//! | `protect.about` | UniFi Protect info |
//! | `menu.network` | Network menu |
//!
//! # Protocol
//!
//! Send JSON over the Unix socket:
//! ```json
//! {"command": "screen", "parameter": "network.about"}
//! {"command": "dump"}
//! {"command": "locate"}
//! ```

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{Display, DisplayError, StatusInfo};

/// Default path to the `ulcmd` Unix domain socket.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/ulcmd_uds_server";

/// Screen names for the MCU's built-in display screens.
pub mod screen {
    pub const NETWORK_ABOUT: &str = "network.about";
    pub const NETWORK_STATUS: &str = "network.status";
    pub const NETWORK_THROUGHPUT: &str = "network.throughput";
    pub const NETWORK_CLIENTS: &str = "network.clients";
    pub const MENU_NETWORK: &str = "menu.network";
}

/// Driver for the UDM Pro front-panel LCD via `ulcmd` daemon.
#[derive(Debug)]
pub struct UlcmdDisplay {
    /// Path to the `ulcmd` Unix domain socket.
    socket_path: PathBuf,
}

impl UlcmdDisplay {
    /// Send a JSON command to `ulcmd` and return the response.
    fn send_command(&self, json: &str) -> Result<String, DisplayError> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            DisplayError::Internal(anyhow::anyhow!(
                "failed to connect to ulcmd socket {}: {e}",
                self.socket_path.display()
            ))
        })?;

        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| DisplayError::Internal(anyhow::anyhow!("set timeout: {e}")))?;

        stream.write_all(json.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;

        // ulcmd sends newline-delimited JSON and does NOT close the
        // connection, so `read_to_string` would block until the read
        // timeout fires (EAGAIN).  Read into a fixed buffer instead
        // and return the first response line.
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf)?;

        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    /// Switch the MCU display to a named screen.
    pub fn set_screen(&self, screen_name: &str) -> Result<(), DisplayError> {
        let cmd = format!(r#"{{"command":"screen","parameter":"{screen_name}"}}"#);
        let response = self.send_command(&cmd)?;

        if response.contains("\"error\"") {
            return Err(DisplayError::Internal(anyhow::anyhow!(
                "ulcmd screen command failed: {response}"
            )));
        }

        tracing::debug!(screen = screen_name, "ulcmd: screen changed");
        Ok(())
    }

    /// Trigger the locate function (blinks LEDs).
    pub fn locate(&self) -> Result<(), DisplayError> {
        let response = self.send_command(r#"{"command":"locate"}"#)?;

        if response.contains("\"error\"") {
            return Err(DisplayError::Internal(anyhow::anyhow!(
                "ulcmd locate failed: {response}"
            )));
        }

        tracing::debug!("ulcmd: locate triggered");
        Ok(())
    }

    /// Query the current display state from `ulcmd`.
    pub fn dump(&self) -> Result<String, DisplayError> {
        self.send_command(r#"{"command":"dump"}"#)
    }
}

impl Display for UlcmdDisplay {
    fn show_status(&self, info: &StatusInfo) -> Result<(), DisplayError> {
        // Show the network about screen which displays device info.
        // The actual data (hostname, IP, etc.) is fed by unifi-core via gRPC —
        // we can only select which screen to show.
        self.set_screen(screen::NETWORK_ABOUT)?;

        tracing::debug!(
            hostname = %info.hostname,
            ip = %info.ip,
            uptime_secs = info.uptime_secs,
            load = info.load,
            "ulcmd: status shown (network.about screen)"
        );
        Ok(())
    }

    fn clear(&self) -> Result<(), DisplayError> {
        // No way to blank the MCU display — just go to about screen.
        self.set_screen(screen::NETWORK_ABOUT)?;
        tracing::debug!("ulcmd: display cleared (reset to about)");
        Ok(())
    }

    fn set_backlight(&mut self, on: bool) -> Result<(), DisplayError> {
        // Backlight is controlled via gRPC LcmSettings, not via the command socket.
        // Log the request but we can't action it from here.
        tracing::warn!(
            on,
            "ulcmd: backlight control not available via command socket"
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "UDM Pro LCM (ulcmd)"
    }
}

/// Detect and initialize the UDM Pro LCM display via `ulcmd`.
///
/// Checks that the Unix domain socket exists and that `ulcmd` responds
/// to a `dump` command.
pub fn init(socket_path: &Path) -> Result<UlcmdDisplay, DisplayError> {
    if !socket_path.exists() {
        return Err(DisplayError::NotFound(format!(
            "ulcmd socket not found: {}",
            socket_path.display()
        )));
    }

    let display = UlcmdDisplay {
        socket_path: socket_path.to_path_buf(),
    };

    // Verify the daemon is responding
    let response = display.dump()?;
    if !response.contains("\"status\":\"ok\"") {
        return Err(DisplayError::Internal(anyhow::anyhow!(
            "ulcmd daemon not responding correctly: {response}"
        )));
    }

    tracing::info!(
        socket = %socket_path.display(),
        "UDM Pro LCM display initialized via ulcmd"
    );

    Ok(display)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_constants() {
        assert_eq!(screen::NETWORK_ABOUT, "network.about");
        assert_eq!(screen::NETWORK_STATUS, "network.status");
        assert_eq!(screen::NETWORK_THROUGHPUT, "network.throughput");
    }

    #[test]
    fn default_socket_path() {
        assert_eq!(DEFAULT_SOCKET_PATH, "/var/run/ulcmd_uds_server");
    }

    #[test]
    fn init_fails_without_socket() {
        let result = init(Path::new("/nonexistent/ulcmd_socket"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
    }
}
