// SPDX-License-Identifier: AGPL-3.0-or-later

//! Framebuffer display backend for SPI-attached TFT panels (e.g. ST7789 on UDM Pro).
//!
//! Renders status screens to `/dev/fb0` and reads touch events from
//! `/dev/input/eventX` via the Linux evdev interface.
//!
//! **Status: stub** — hardware testing on UDM Pro required before implementation.

use std::path::{Path, PathBuf};

use crate::{Display, DisplayError, StatusInfo};

/// Driver for a framebuffer-based TFT display with optional touch input.
#[allow(dead_code)] // stub — fields used once rendering is implemented
pub struct FramebufferDisplay {
    /// Path to the framebuffer device (e.g. `/dev/fb0`).
    fb_path: PathBuf,
    /// Path to the touch input device (e.g. `/dev/input/event0`), if present.
    touch_path: Option<PathBuf>,
    /// Display resolution.
    width: u32,
    height: u32,
}

impl Display for FramebufferDisplay {
    fn show_status(&self, info: &StatusInfo) -> Result<(), DisplayError> {
        // TODO: render status screen to framebuffer
        // - System hostname + IP
        // - Uptime bar
        // - Service status icons (green/amber/red dots)
        // - WAN status with current throughput
        // - Load/memory gauges
        tracing::debug!(
            hostname = %info.hostname,
            ip = %info.ip,
            "framebuffer: show_status (stub)"
        );
        Ok(())
    }

    fn clear(&self) -> Result<(), DisplayError> {
        // TODO: zero-fill framebuffer
        tracing::debug!("framebuffer: clear (stub)");
        Ok(())
    }

    fn set_backlight(&mut self, on: bool) -> Result<(), DisplayError> {
        // TODO: write to /sys/class/backlight/*/brightness
        tracing::debug!(on, "framebuffer: set_backlight (stub)");
        Ok(())
    }

    fn name(&self) -> &str {
        "Framebuffer TFT"
    }
}

/// Detect and initialize a framebuffer display.
///
/// Probes `/dev/fb0` for availability and optionally locates the touch
/// input device.
pub fn init(
    fb_path: &Path,
    touch_path: Option<&Path>,
    width: u32,
    height: u32,
) -> Result<FramebufferDisplay, DisplayError> {
    if !fb_path.exists() {
        return Err(DisplayError::NotFound(format!(
            "framebuffer device not found: {}",
            fb_path.display()
        )));
    }

    let fb_str = fb_path.display().to_string();
    let touch_str = touch_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "none".to_string());

    let disp = FramebufferDisplay {
        fb_path: fb_path.to_path_buf(),
        touch_path: touch_path.map(Path::to_path_buf),
        width,
        height,
    };

    tracing::info!(
        fb = %fb_str,
        touch = %touch_str,
        width,
        height,
        "framebuffer display initialized (stub)"
    );

    Ok(disp)
}
