// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Display abstraction for secfirstgw-rs.
//!
//! Supports multiple display backends selected via [`DisplayConfig`]:
//!
//! - **HD44780**: 20x4 character LCD over I2C (PCF8574 backpack)
//! - **Framebuffer**: SPI-attached TFT panel with optional touch input (e.g. UDM Pro)
//! - **None**: no display (VM, Docker, or headless bare metal)
//!
//! The [`init`] function takes a [`DisplayConfig`] and returns a boxed [`Display`]
//! trait object. Use [`auto_detect`] to probe hardware and pick the right backend.

pub mod framebuffer;
pub mod hd44780;

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Errors from display operations.
#[derive(Debug, thiserror::Error)]
pub enum DisplayError {
    /// Display hardware not found at the expected path.
    #[error("display not found: {0}")]
    NotFound(String),

    /// I/O error during display communication.
    #[error("display I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// System status info to render on the display.
pub struct StatusInfo {
    pub hostname: String,
    pub ip: String,
    pub uptime_secs: u64,
    pub load: f64,
}

/// Common interface for all display backends.
pub trait Display {
    /// Render system status information on the display.
    fn show_status(&self, info: &StatusInfo) -> Result<(), DisplayError>;

    /// Clear the display contents.
    fn clear(&self) -> Result<(), DisplayError>;

    /// Turn the backlight on or off.
    fn set_backlight(&mut self, on: bool) -> Result<(), DisplayError>;

    /// Human-readable name of this display backend.
    fn name(&self) -> &str;
}

/// Display backend configuration.
///
/// Stored in the `meta` KV table under key `display_config`, or auto-detected
/// from hardware via [`auto_detect`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DisplayConfig {
    /// No display attached or display disabled.
    None,

    /// HD44780-compatible 20x4 character LCD over I2C.
    Hd44780 {
        /// Path to the I2C device node (e.g. `/dev/i2c-1`).
        #[serde(default = "default_i2c_path")]
        i2c_device: String,
        /// 7-bit I2C address of the PCF8574 backpack (default: `0x27`).
        #[serde(default = "default_i2c_addr")]
        i2c_address: u16,
    },

    /// Framebuffer-based TFT display (e.g. ST7789 on UDM Pro).
    Framebuffer {
        /// Path to the framebuffer device (e.g. `/dev/fb0`).
        #[serde(default = "default_fb_path")]
        fb_device: String,
        /// Path to the touch input device, if present.
        touch_device: Option<String>,
        /// Display width in pixels.
        #[serde(default = "default_fb_width")]
        width: u32,
        /// Display height in pixels.
        #[serde(default = "default_fb_height")]
        height: u32,
    },
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self::None
    }
}

fn default_i2c_path() -> String {
    "/dev/i2c-1".to_string()
}
fn default_i2c_addr() -> u16 {
    0x27
}
fn default_fb_path() -> String {
    "/dev/fb0".to_string()
}
fn default_fb_width() -> u32 {
    240
}
fn default_fb_height() -> u32 {
    240
}

/// Auto-detect the display hardware based on the platform.
///
/// On bare metal:
/// - Checks for `/dev/fb0` first (touchscreen TFT, e.g. UDM Pro LCM)
/// - Falls back to `/dev/i2c-1` (character LCD)
/// - Returns `DisplayConfig::None` if neither is found
///
/// On VM/Docker: always returns `DisplayConfig::None`.
#[must_use]
pub fn auto_detect(platform: &sfgw_hal::Platform) -> DisplayConfig {
    if !platform.has_lcd() {
        return DisplayConfig::None;
    }

    // Prefer framebuffer (touchscreen) over character LCD
    if Path::new("/dev/fb0").exists() {
        tracing::info!("auto-detected framebuffer display at /dev/fb0");
        return DisplayConfig::Framebuffer {
            fb_device: default_fb_path(),
            touch_device: detect_touch_device(),
            width: default_fb_width(),
            height: default_fb_height(),
        };
    }

    // Fall back to I2C character LCD
    if Path::new("/dev/i2c-1").exists() {
        tracing::info!("auto-detected HD44780 LCD on /dev/i2c-1");
        return DisplayConfig::Hd44780 {
            i2c_device: default_i2c_path(),
            i2c_address: default_i2c_addr(),
        };
    }

    tracing::info!("no display hardware detected");
    DisplayConfig::None
}

/// Initialize a display backend from the given configuration.
///
/// Returns `Ok(None)` for `DisplayConfig::None` (no display).
pub fn init(config: &DisplayConfig) -> Result<Option<Box<dyn Display>>, DisplayError> {
    match config {
        DisplayConfig::None => {
            tracing::info!("display: disabled");
            Ok(None)
        }
        DisplayConfig::Hd44780 {
            i2c_device,
            i2c_address,
        } => {
            let lcd = hd44780::init(Path::new(i2c_device), Some(*i2c_address))?;
            Ok(Some(Box::new(lcd)))
        }
        DisplayConfig::Framebuffer {
            fb_device,
            touch_device,
            width,
            height,
        } => {
            let fb = framebuffer::init(
                Path::new(fb_device),
                touch_device.as_ref().map(|p| Path::new(p.as_str())),
                *width,
                *height,
            )?;
            Ok(Some(Box::new(fb)))
        }
    }
}

/// Try to find a touch input device by scanning `/dev/input/`.
fn detect_touch_device() -> Option<String> {
    for i in 0..10 {
        let path = format!("/dev/input/event{i}");
        if Path::new(&path).exists() {
            // TODO: read /sys/class/input/event{i}/device/name to confirm it's a
            // touchscreen rather than a keyboard or other input device.
            // Needs refinement with actual UDM Pro hardware testing.
            tracing::debug!(path, "found input device (touch detection pending)");
        }
    }
    // Don't auto-select until we can verify it's actually a touch device
    Option::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_none_is_default() {
        let config: DisplayConfig = DisplayConfig::default();
        assert_eq!(config, DisplayConfig::None);
    }

    #[test]
    fn config_hd44780_defaults() {
        let json = r#"{"type": "hd44780"}"#;
        let config: DisplayConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(
            config,
            DisplayConfig::Hd44780 {
                i2c_device: "/dev/i2c-1".to_string(),
                i2c_address: 0x27,
            }
        );
    }

    #[test]
    fn config_hd44780_custom() {
        let json = r#"{"type": "hd44780", "i2c_device": "/dev/i2c-0", "i2c_address": 63}"#;
        let config: DisplayConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(
            config,
            DisplayConfig::Hd44780 {
                i2c_device: "/dev/i2c-0".to_string(),
                i2c_address: 63,
            }
        );
    }

    #[test]
    fn config_framebuffer_defaults() {
        let json = r#"{"type": "framebuffer"}"#;
        let config: DisplayConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(
            config,
            DisplayConfig::Framebuffer {
                fb_device: "/dev/fb0".to_string(),
                touch_device: None,
                width: 240,
                height: 240,
            }
        );
    }

    #[test]
    fn config_none_serialization() {
        let config = DisplayConfig::None;
        let json = serde_json::to_string(&config).expect("serialize");
        assert_eq!(json, r#"{"type":"none"}"#);
    }

    #[test]
    fn config_roundtrip() {
        let configs = vec![
            DisplayConfig::None,
            DisplayConfig::Hd44780 {
                i2c_device: "/dev/i2c-1".to_string(),
                i2c_address: 0x27,
            },
            DisplayConfig::Framebuffer {
                fb_device: "/dev/fb0".to_string(),
                touch_device: Some("/dev/input/event2".to_string()),
                width: 320,
                height: 240,
            },
        ];

        for config in configs {
            let json = serde_json::to_string(&config).expect("serialize");
            let parsed: DisplayConfig = serde_json::from_str(&json).expect("parse");
            assert_eq!(config, parsed);
        }
    }

    #[test]
    fn init_none_returns_none() {
        let result = init(&DisplayConfig::None).expect("init None");
        assert!(result.is_none());
    }

    #[test]
    fn auto_detect_vm_returns_none() {
        let config = auto_detect(&sfgw_hal::Platform::Vm);
        assert_eq!(config, DisplayConfig::None);
    }

    #[test]
    fn auto_detect_docker_returns_none() {
        let config = auto_detect(&sfgw_hal::Platform::Docker);
        assert_eq!(config, DisplayConfig::None);
    }
}
