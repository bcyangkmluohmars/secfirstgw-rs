// SPDX-License-Identifier: AGPL-3.0-or-later

//! HD44780-compatible 20x4 character LCD driver over I2C (PCF8574 backpack).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::Context;

use crate::{DisplayError, StatusInfo};

/// Default I2C address for PCF8574 backpack modules.
const DEFAULT_I2C_ADDR: u16 = 0x27;

/// Display dimensions.
const LCD_COLS: usize = 20;
const LCD_ROWS: u8 = 4;

/// I2C_SLAVE ioctl request code (from linux/i2c-dev.h).
const I2C_SLAVE: u64 = 0x0703;

// HD44780 command constants.
const CMD_CLEAR_DISPLAY: u8 = 0x01;
const CMD_RETURN_HOME: u8 = 0x02;
const CMD_ENTRY_MODE_SET: u8 = 0x04;
const CMD_DISPLAY_CONTROL: u8 = 0x08;
const CMD_FUNCTION_SET: u8 = 0x20;

// Entry mode flags.
const ENTRY_LEFT: u8 = 0x02;

// Display control flags.
const DISPLAY_ON: u8 = 0x04;

// Function set flags.
const MODE_2LINE: u8 = 0x08;

// PCF8574 backpack pin mapping.
const BACKLIGHT_BIT: u8 = 0x08;
const ENABLE_BIT: u8 = 0x04;
const RS_BIT: u8 = 0x01; // Register Select: 0 = command, 1 = data

/// DDRAM line start addresses for a 20x4 HD44780 display.
const LINE_ADDRS: [u8; 4] = [0x00, 0x40, 0x14, 0x54];

/// Driver for an HD44780-compatible 20x4 LCD connected via PCF8574 I2C backpack.
pub struct Hd44780Display {
    /// Path to the I2C device node (e.g. `/dev/i2c-1`).
    device_path: PathBuf,
    /// 7-bit I2C slave address of the PCF8574 backpack.
    address: u16,
    /// Whether the backlight is currently enabled.
    backlight: bool,
}

impl Hd44780Display {
    /// Open the I2C device and configure it for communication with the LCD.
    #[allow(unsafe_code)]
    fn open_device(&self) -> Result<File, DisplayError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.device_path)
            .with_context(|| format!("opening I2C device {}", self.device_path.display()))?;

        let fd = file.as_raw_fd();
        // SAFETY: We are calling the Linux I2C_SLAVE ioctl on a valid, open file
        // descriptor obtained from `OpenOptions::open`. The ioctl sets the 7-bit
        // I2C slave address for subsequent read/write operations. The fd remains
        // valid for the lifetime of `file`, and the address is a validated u16
        // that fits in the i2c 7-bit address space.
        let ret = unsafe { libc::ioctl(fd, I2C_SLAVE, i32::from(self.address)) };
        if ret < 0 {
            return Err(DisplayError::Internal(anyhow::anyhow!(
                "ioctl I2C_SLAVE failed for address 0x{:02X}",
                self.address
            )));
        }

        Ok(file)
    }

    /// Return the backlight mask based on current state.
    fn backlight_bits(&self) -> u8 {
        if self.backlight { BACKLIGHT_BIT } else { 0 }
    }

    /// Pulse the enable pin to latch a nibble into the HD44780.
    fn pulse_enable(file: &mut File, nibble: u8) -> Result<(), DisplayError> {
        let with_en = nibble | ENABLE_BIT;
        file.write_all(&[with_en])
            .context("i2c write: enable high")?;
        // The HD44780 needs >= 450ns enable pulse; 1us is safe.
        thread::sleep(Duration::from_micros(1));

        let without_en = nibble & !ENABLE_BIT;
        file.write_all(&[without_en])
            .context("i2c write: enable low")?;
        // Data hold time ~37us for most commands.
        thread::sleep(Duration::from_micros(50));

        Ok(())
    }

    /// Send a 4-bit nibble to the display (high nibble of `data`).
    fn write_nibble(file: &mut File, nibble: u8, backlight: u8) -> Result<(), DisplayError> {
        let data = nibble | backlight;
        file.write_all(&[data]).context("i2c write: nibble")?;
        Self::pulse_enable(file, data)?;
        Ok(())
    }

    /// Send a full byte to the LCD in 4-bit mode.
    ///
    /// `mode` should be 0 for commands or `RS_BIT` for data.
    fn send_byte(file: &mut File, byte: u8, mode: u8, backlight: u8) -> Result<(), DisplayError> {
        let high = (byte & 0xF0) | mode;
        let low = ((byte << 4) & 0xF0) | mode;

        Self::write_nibble(file, high, backlight)?;
        Self::write_nibble(file, low, backlight)?;

        Ok(())
    }

    /// Send a command byte to the LCD.
    fn send_command(&self, file: &mut File, cmd: u8) -> Result<(), DisplayError> {
        Self::send_byte(file, cmd, 0, self.backlight_bits())
    }

    /// Send a data byte (character) to the LCD.
    fn send_data(&self, file: &mut File, data: u8) -> Result<(), DisplayError> {
        Self::send_byte(file, data, RS_BIT, self.backlight_bits())
    }
}

impl crate::Display for Hd44780Display {
    fn show_status(&self, info: &StatusInfo) -> Result<(), DisplayError> {
        let uptime_str = format_uptime(info.uptime_secs);
        let load_str = format_load(info.load);

        self.write_line(0, &info.hostname)?;
        self.write_line(1, &info.ip)?;
        self.write_line(2, &uptime_str)?;
        self.write_line(3, &load_str)?;

        tracing::debug!(
            hostname = %info.hostname,
            ip = %info.ip,
            uptime_secs = info.uptime_secs,
            load = info.load,
            "HD44780: status updated"
        );
        Ok(())
    }

    fn clear(&self) -> Result<(), DisplayError> {
        let mut file = self.open_device()?;
        self.send_command(&mut file, CMD_CLEAR_DISPLAY)?;
        thread::sleep(Duration::from_millis(2));
        tracing::debug!("HD44780: display cleared");
        Ok(())
    }

    fn set_backlight(&mut self, on: bool) -> Result<(), DisplayError> {
        self.backlight = on;
        let mut file = self.open_device()?;
        file.write_all(&[self.backlight_bits()])
            .context("i2c write: backlight update")?;
        tracing::debug!(on, "HD44780: backlight changed");
        Ok(())
    }

    fn name(&self) -> &str {
        "HD44780 20x4 LCD"
    }
}

impl Hd44780Display {
    /// Write text to a specific line (0-3) on the display.
    ///
    /// Text is truncated to 20 characters. Shorter text is padded with spaces.
    #[must_use = "check for I2C write errors"]
    pub fn write_line(&self, line: u8, text: &str) -> Result<(), DisplayError> {
        if line >= LCD_ROWS {
            return Err(DisplayError::Internal(anyhow::anyhow!(
                "invalid line number {line}, must be 0-3"
            )));
        }

        let mut file = self.open_device()?;

        let addr = LINE_ADDRS[line as usize];
        self.send_command(&mut file, 0x80 | addr)?;

        let padded = format!("{:<width$}", text, width = LCD_COLS);
        for byte in padded.bytes().take(LCD_COLS) {
            self.send_data(&mut file, byte)?;
        }

        tracing::trace!(line, text, "HD44780: wrote line");
        Ok(())
    }
}

/// Detect and initialize an HD44780 display over I2C.
///
/// Performs the HD44780 4-bit initialization sequence, clears the display,
/// and turns on the backlight.
pub fn init(device_path: &Path, address: Option<u16>) -> Result<Hd44780Display, DisplayError> {
    let address = address.unwrap_or(DEFAULT_I2C_ADDR);
    let device_path = device_path.to_path_buf();

    if !device_path.exists() {
        return Err(DisplayError::NotFound(format!(
            "I2C device not found: {}",
            device_path.display()
        )));
    }

    let lcd = Hd44780Display {
        device_path,
        address,
        backlight: true,
    };

    let mut file = lcd.open_device()?;

    // HD44780 initialization sequence for 4-bit mode.
    thread::sleep(Duration::from_millis(50));

    let bl = lcd.backlight_bits();
    for _ in 0..3 {
        Hd44780Display::write_nibble(&mut file, 0x30, bl)?;
        thread::sleep(Duration::from_millis(5));
    }

    // Switch to 4-bit mode.
    Hd44780Display::write_nibble(&mut file, 0x20, bl)?;
    thread::sleep(Duration::from_millis(1));

    // Function set: 4-bit, 2 lines, 5x8 dots.
    lcd.send_command(&mut file, CMD_FUNCTION_SET | MODE_2LINE)?;

    // Display on, cursor off, blink off.
    lcd.send_command(&mut file, CMD_DISPLAY_CONTROL | DISPLAY_ON)?;

    // Clear display.
    lcd.send_command(&mut file, CMD_CLEAR_DISPLAY)?;
    thread::sleep(Duration::from_millis(2));

    // Entry mode: increment cursor, no display shift.
    lcd.send_command(&mut file, CMD_ENTRY_MODE_SET | ENTRY_LEFT)?;

    // Return home.
    lcd.send_command(&mut file, CMD_RETURN_HOME)?;
    thread::sleep(Duration::from_millis(2));

    tracing::info!(
        device = %lcd.device_path.display(),
        address = format_args!("0x{:02X}", address),
        "HD44780 display initialized"
    );

    Ok(lcd)
}

/// Format an uptime duration for the 20-char LCD line.
///
/// ```
/// use sfgw_display::hd44780::format_uptime;
///
/// assert_eq!(format_uptime(0), "Up: 0d 00:00:00");
/// assert_eq!(format_uptime(90061), "Up: 1d 01:01:01");
/// assert_eq!(format_uptime(86400), "Up: 1d 00:00:00");
/// ```
pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    format!("Up: {days}d {hours:02}:{mins:02}:{s:02}")
}

/// Format a load average for the 20-char LCD line.
///
/// ```
/// use sfgw_display::hd44780::format_load;
///
/// assert_eq!(format_load(0.42), "Load: 0.42");
/// assert_eq!(format_load(12.345), "Load: 12.35");
/// ```
pub fn format_load(load: f64) -> String {
    format!("Load: {load:.2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_formatting() {
        let uptime = format_uptime(90061);
        assert_eq!(uptime, "Up: 1d 01:01:01");

        let uptime_zero = format_uptime(0);
        assert_eq!(uptime_zero, "Up: 0d 00:00:00");

        let load = format_load(0.42);
        assert_eq!(load, "Load: 0.42");

        let load_high = format_load(12.345);
        assert_eq!(load_high, "Load: 12.35");
    }

    #[test]
    fn line_truncation_to_20_chars() {
        let long_text = "This is a very long string that exceeds twenty characters";
        let padded = format!("{:<width$}", long_text, width = LCD_COLS);
        let output: String = padded.chars().take(LCD_COLS).collect();
        assert_eq!(output.len(), LCD_COLS);
        assert_eq!(output, "This is a very long ");

        let short_text = "Hi";
        let padded = format!("{:<width$}", short_text, width = LCD_COLS);
        let output: String = padded.chars().take(LCD_COLS).collect();
        assert_eq!(output.len(), LCD_COLS);
        assert_eq!(output, "Hi                  ");
    }

    #[test]
    fn clear_command_byte_value() {
        assert_eq!(CMD_CLEAR_DISPLAY, 0x01);
        assert_eq!(CMD_RETURN_HOME, 0x02);
        let cmd = CMD_CLEAR_DISPLAY;
        let high = cmd & 0xF0;
        let low = (cmd << 4) & 0xF0;
        assert_eq!(high, 0x00);
        assert_eq!(low, 0x10);
    }

    #[test]
    fn backlight_bits_reflect_state() {
        let lcd_on = Hd44780Display {
            device_path: std::path::PathBuf::from("/dev/null"),
            address: DEFAULT_I2C_ADDR,
            backlight: true,
        };
        assert_eq!(lcd_on.backlight_bits(), BACKLIGHT_BIT);

        let lcd_off = Hd44780Display {
            device_path: std::path::PathBuf::from("/dev/null"),
            address: DEFAULT_I2C_ADDR,
            backlight: false,
        };
        assert_eq!(lcd_off.backlight_bits(), 0);
    }

    #[test]
    fn line_addresses_are_correct() {
        assert_eq!(LINE_ADDRS[0], 0x00);
        assert_eq!(LINE_ADDRS[1], 0x40);
        assert_eq!(LINE_ADDRS[2], 0x14);
        assert_eq!(LINE_ADDRS[3], 0x54);
    }
}
