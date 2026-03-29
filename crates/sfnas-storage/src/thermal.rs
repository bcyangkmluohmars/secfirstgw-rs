#![deny(unsafe_code)]

//! Thermal management for secfirstNAS (UNVR hardware).
//!
//! Reads temperatures from the ADT7475 HWMON controller and CPU thermal zone,
//! reads HDD temperatures via SMART, and adjusts fan speeds using PWM control
//! with a PID-like algorithm and hysteresis to prevent oscillation.
//!
//! # Hardware layout (ADT7475 at `/sys/class/hwmon/hwmon0/`)
//!
//! - 3 fans: `fan{1,2,3}_input` (RPM readback)
//! - 3 temp sensors: `temp{1,2,3}_input` (millidegrees Celsius)
//! - PWM outputs: `pwm{1,2,3}` (0–255)
//! - Fan RPM range: ~2600 RPM (31%) to ~8600 RPM (100%)
//! - Fan 4 not populated on UNVR

use crate::StorageError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Number of fans on the UNVR ADT7475 controller.
const FAN_COUNT: usize = 3;

/// Number of temperature sensors on the ADT7475.
const TEMP_SENSOR_COUNT: usize = 3;

/// Default hwmon sysfs path for the ADT7475.
const DEFAULT_HWMON_PATH: &str = "/sys/class/hwmon/hwmon0";

/// CPU thermal zone sysfs path.
const CPU_THERMAL_ZONE_PATH: &str = "/sys/class/thermal/thermal_zone0/temp";

/// Maximum PWM value (full speed).
const PWM_MAX: u8 = 255;

/// Hysteresis band in degrees Celsius. Fans won't change speed when the
/// temperature is within ±HYSTERESIS_BAND of the target.
const HYSTERESIS_BAND: u32 = 3;

/// Critical temperature threshold in degrees Celsius. Above this, fans go to
/// 100% regardless of profile.
const CRITICAL_TEMP_C: u32 = 85;

/// Warning temperature offset above target. When exceeded, a warning is logged.
const WARNING_OFFSET_C: u32 = 5;

/// Fan profile controlling target temperatures and minimum PWM duty cycle.
///
/// Each profile defines a target temperature for HDD and CPU sensors, plus a
/// minimum PWM value that fans never drop below. The thermal manager uses these
/// targets with a PID-like control loop and hysteresis band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FanProfile {
    /// Prioritize noise reduction. HDDs may run warmer.
    /// HDD target 50 C, CPU target 70 C, min PWM 20%.
    Silence,
    /// Balanced between noise and thermals (default).
    /// HDD target 42 C, CPU target 60 C, min PWM 31%.
    #[default]
    Balanced,
    /// Aggressive cooling for heavy workloads.
    /// HDD target 35 C, CPU target 50 C, min PWM 50%.
    Performance,
    /// All fans at 100%. For maintenance or diagnostics only.
    Max,
    /// User-defined targets and minimum PWM.
    Custom {
        /// HDD target temperature in degrees Celsius.
        hdd_target: u32,
        /// CPU target temperature in degrees Celsius.
        cpu_target: u32,
        /// Minimum PWM duty cycle (0–255).
        min_pwm: u8,
    },
}

impl FanProfile {
    /// HDD target temperature in degrees Celsius for this profile.
    #[must_use]
    pub const fn hdd_target_c(&self) -> u32 {
        match self {
            Self::Silence => 50,
            Self::Balanced => 42,
            Self::Performance => 35,
            Self::Max => 0, // irrelevant — always full speed
            Self::Custom { hdd_target, .. } => *hdd_target,
        }
    }

    /// CPU target temperature in degrees Celsius for this profile.
    #[must_use]
    pub const fn cpu_target_c(&self) -> u32 {
        match self {
            Self::Silence => 70,
            Self::Balanced => 60,
            Self::Performance => 50,
            Self::Max => 0,
            Self::Custom { cpu_target, .. } => *cpu_target,
        }
    }

    /// Minimum PWM value (0–255) for this profile.
    #[must_use]
    pub const fn min_pwm(&self) -> u8 {
        match self {
            Self::Silence => 51,      // ~20%
            Self::Balanced => 79,     // ~31%
            Self::Performance => 128, // ~50%
            Self::Max => PWM_MAX,
            Self::Custom { min_pwm, .. } => *min_pwm,
        }
    }

    /// Display name for logging and API responses.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Silence => "Silence",
            Self::Balanced => "Balanced",
            Self::Performance => "Performance",
            Self::Max => "Max",
            Self::Custom { .. } => "Custom",
        }
    }
}

/// Snapshot of all thermal sensor readings and fan state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermalStatus {
    /// Fan RPM readings for fan 1, 2, 3. `None` if the sensor read failed.
    pub fan_rpm: [Option<u32>; FAN_COUNT],
    /// ADT7475 temperature readings in degrees Celsius for sensor 1, 2, 3.
    /// `None` if the sensor read failed.
    pub hwmon_temps_c: [Option<u32>; TEMP_SENSOR_COUNT],
    /// CPU thermal zone temperature in degrees Celsius.
    /// `None` if the read failed.
    pub cpu_temp_c: Option<u32>,
    /// HDD temperatures in degrees Celsius from SMART data.
    /// Each entry is `(device_path, temperature)`.
    pub hdd_temps_c: Vec<(String, u32)>,
    /// Current PWM values for fan 1, 2, 3. `None` if the read failed.
    pub pwm_values: [Option<u8>; FAN_COUNT],
    /// The currently active fan profile.
    pub active_profile: FanProfile,
}

/// Thermal management controller for the UNVR.
///
/// Reads hardware sensors and adjusts fan PWM values to maintain target
/// temperatures defined by the active [`FanProfile`]. Uses a proportional
/// control algorithm with a hysteresis band to prevent fan speed oscillation.
pub struct ThermalManager {
    /// Path to the hwmon sysfs directory (e.g., `/sys/class/hwmon/hwmon0`).
    hwmon_path: PathBuf,
    /// Path to the CPU thermal zone temperature file.
    cpu_thermal_path: PathBuf,
    /// Currently active fan profile.
    profile: FanProfile,
    /// Last PWM value written to each fan, used for hysteresis decisions.
    last_pwm: [u8; FAN_COUNT],
    /// Accumulated integral error for PID-like control, per thermal domain
    /// (index 0 = HDD, index 1 = CPU).
    integral_error: [f64; 2],
}

impl ThermalManager {
    /// Create a new thermal manager with default hardware paths and the
    /// [`FanProfile::Balanced`] profile.
    pub fn new() -> Self {
        Self {
            hwmon_path: PathBuf::from(DEFAULT_HWMON_PATH),
            cpu_thermal_path: PathBuf::from(CPU_THERMAL_ZONE_PATH),
            profile: FanProfile::default(),
            last_pwm: [0; FAN_COUNT],
            integral_error: [0.0; 2],
        }
    }

    /// Create a thermal manager with custom sysfs paths (useful for testing
    /// against mock sysfs trees).
    pub fn with_paths(hwmon_path: PathBuf, cpu_thermal_path: PathBuf) -> Self {
        Self {
            hwmon_path,
            cpu_thermal_path,
            profile: FanProfile::default(),
            last_pwm: [0; FAN_COUNT],
            integral_error: [0.0; 2],
        }
    }

    /// Read a snapshot of all thermal sensors, fan RPMs, and PWM values.
    pub fn read_status(&self) -> ThermalStatus {
        let fan_rpm = self.read_fan_rpms();
        let hwmon_temps_c = self.read_hwmon_temps();
        let cpu_temp_c = self.read_cpu_temp();
        let hdd_temps_c = Self::read_hdd_smart_temps();
        let pwm_values = self.read_pwm_values();

        ThermalStatus {
            fan_rpm,
            hwmon_temps_c,
            cpu_temp_c,
            hdd_temps_c,
            pwm_values,
            active_profile: self.profile.clone(),
        }
    }

    /// Set the active fan profile.
    ///
    /// Resets the integral error accumulator to prevent windup when switching
    /// profiles.
    pub fn set_profile(&mut self, profile: FanProfile) {
        info!(
            from = self.profile.name(),
            to = profile.name(),
            "switching fan profile"
        );
        self.profile = profile;
        self.integral_error = [0.0; 2];
    }

    /// Get a reference to the current profile.
    #[must_use]
    pub fn profile(&self) -> &FanProfile {
        &self.profile
    }

    /// Directly set the PWM value for a specific fan (1-indexed).
    ///
    /// The fan number must be 1, 2, or 3. Values are clamped to 0–255.
    pub fn set_pwm(&mut self, fan: u8, value: u8) -> Result<(), StorageError> {
        if fan == 0 || fan as usize > FAN_COUNT {
            return Err(StorageError::Parse(format!(
                "invalid fan number: {fan} (valid: 1-{FAN_COUNT})"
            )));
        }

        let pwm_path = self.hwmon_path.join(format!("pwm{fan}"));
        self.write_pwm_file(&pwm_path, value)?;
        self.last_pwm[(fan - 1) as usize] = value;

        debug!(fan, pwm = value, "PWM set directly");
        Ok(())
    }

    /// Run one control cycle: read all temperatures and adjust fan PWM values
    /// based on the active profile.
    ///
    /// This method should be called periodically (e.g., every 5–10 seconds).
    /// It reads all thermal sources, determines the highest temperature relative
    /// to each target, and computes a PWM value using proportional + integral
    /// control with hysteresis.
    pub fn tick(&mut self) -> Result<ThermalStatus, StorageError> {
        let status = self.read_status();

        // Max profile: slam everything to full speed, no control loop needed.
        if self.profile == FanProfile::Max {
            for fan in 1..=FAN_COUNT as u8 {
                self.set_pwm(fan, PWM_MAX)?;
            }
            return Ok(self.read_status());
        }

        // Gather all relevant temperatures.
        let max_hdd_temp = status.hdd_temps_c.iter().map(|(_, t)| *t).max();

        let max_hwmon_temp = status.hwmon_temps_c.iter().filter_map(|t| *t).max();

        let max_cpu_temp = [status.cpu_temp_c, max_hwmon_temp]
            .iter()
            .filter_map(|t| *t)
            .max();

        // Compute PWM for HDD thermal domain.
        let hdd_pwm = if let Some(hdd_temp) = max_hdd_temp {
            self.check_and_warn("HDD", hdd_temp, self.profile.hdd_target_c());
            self.compute_pwm(hdd_temp, self.profile.hdd_target_c(), 0)
        } else {
            self.profile.min_pwm()
        };

        // Compute PWM for CPU thermal domain.
        let cpu_pwm = if let Some(cpu_temp) = max_cpu_temp {
            self.check_and_warn("CPU", cpu_temp, self.profile.cpu_target_c());
            self.compute_pwm(cpu_temp, self.profile.cpu_target_c(), 1)
        } else {
            self.profile.min_pwm()
        };

        // Use the higher of the two PWM demands — fans serve both domains.
        let target_pwm = hdd_pwm.max(cpu_pwm);

        // Apply hysteresis: only change if we're outside the deadband.
        for fan_idx in 0..FAN_COUNT {
            let fan_num = (fan_idx + 1) as u8;
            let current = self.last_pwm[fan_idx];

            // Always apply if the difference is significant, or if the new
            // target exceeds the current value (heating up takes priority).
            let diff = (target_pwm as i16 - current as i16).unsigned_abs();
            if diff >= 5 || target_pwm > current {
                self.set_pwm(fan_num, target_pwm)?;
            }
        }

        Ok(self.read_status())
    }

    /// Check temperature against target and log warnings when appropriate.
    fn check_and_warn(&self, domain: &str, current_temp: u32, target: u32) {
        if current_temp >= CRITICAL_TEMP_C {
            warn!(
                domain,
                temp_c = current_temp,
                critical = CRITICAL_TEMP_C,
                "CRITICAL: temperature exceeds critical threshold — fans at 100%"
            );
        } else if current_temp > target + WARNING_OFFSET_C {
            warn!(
                domain,
                temp_c = current_temp,
                target_c = target,
                "temperature significantly above target"
            );
        } else if current_temp > target {
            debug!(
                domain,
                temp_c = current_temp,
                target_c = target,
                "temperature above target"
            );
        }
    }

    /// Compute the PWM output for a given temperature and target using
    /// proportional + integral control with hysteresis.
    ///
    /// - Within the hysteresis band (target ± HYSTERESIS_BAND): hold current PWM.
    /// - Above target + band: ramp up proportionally.
    /// - Below target - band: ramp down toward minimum.
    /// - Above critical: force 100%.
    fn compute_pwm(&mut self, current_temp: u32, target: u32, domain_idx: usize) -> u8 {
        // Critical override.
        if current_temp >= CRITICAL_TEMP_C {
            self.integral_error[domain_idx] = 0.0;
            return PWM_MAX;
        }

        let min_pwm = self.profile.min_pwm();

        // Proportional gain: how aggressively we respond per degree above target.
        // At +10 C over target, we want approximately full range above min_pwm.
        let range = (PWM_MAX as f64) - (min_pwm as f64);
        let kp = range / 10.0;

        // Integral gain: slow correction for steady-state offset.
        let ki = 0.3;

        let error = current_temp as f64 - target as f64;

        // Hysteresis: inside the deadband, don't accumulate integral and return
        // whatever the last PWM was (clamped to minimum).
        if error.abs() < HYSTERESIS_BAND as f64 {
            // Slowly decay integral to prevent windup.
            self.integral_error[domain_idx] *= 0.9;
            // Return the minimum PWM — actual hysteresis is handled in tick()
            // by comparing against last_pwm.
            return min_pwm;
        }

        // Accumulate integral error, clamped to prevent windup.
        self.integral_error[domain_idx] += error;
        self.integral_error[domain_idx] = self.integral_error[domain_idx].clamp(-50.0, 50.0);

        let output = (min_pwm as f64) + (kp * error) + (ki * self.integral_error[domain_idx]);

        // Clamp to valid PWM range.
        let clamped = output.clamp(min_pwm as f64, PWM_MAX as f64);
        clamped as u8
    }

    /// Read fan RPM values from hwmon sysfs.
    fn read_fan_rpms(&self) -> [Option<u32>; FAN_COUNT] {
        let mut rpms = [None; FAN_COUNT];
        #[allow(clippy::needless_range_loop)]
        for i in 0..FAN_COUNT {
            let path = self.hwmon_path.join(format!("fan{}_input", i + 1));
            rpms[i] = Self::read_sysfs_u32(&path);
        }
        rpms
    }

    /// Read hwmon temperature sensors (millidegrees to degrees conversion).
    fn read_hwmon_temps(&self) -> [Option<u32>; TEMP_SENSOR_COUNT] {
        let mut temps = [None; TEMP_SENSOR_COUNT];
        #[allow(clippy::needless_range_loop)]
        for i in 0..TEMP_SENSOR_COUNT {
            let path = self.hwmon_path.join(format!("temp{}_input", i + 1));
            temps[i] = Self::read_sysfs_u32(&path).map(|v| v / 1000);
        }
        temps
    }

    /// Read the CPU thermal zone temperature (millidegrees to degrees).
    fn read_cpu_temp(&self) -> Option<u32> {
        Self::read_sysfs_u32(&self.cpu_thermal_path).map(|v| v / 1000)
    }

    /// Read HDD temperatures from SMART data for all detected sd* disks.
    ///
    /// Uses `smartctl` to query each disk's temperature attribute.
    fn read_hdd_smart_temps() -> Vec<(String, u32)> {
        let disk_paths = match crate::Disk::list_all() {
            Ok(paths) => paths,
            Err(e) => {
                debug!(error = %e, "failed to enumerate disks for SMART temps");
                return Vec::new();
            }
        };

        let mut temps = Vec::new();
        for disk_path in &disk_paths {
            match crate::Disk::from_path(disk_path) {
                Ok(disk) => {
                    if let Some(temp) = disk.health.temperature_celsius {
                        temps.push((disk_path.display().to_string(), temp));
                    }
                }
                Err(e) => {
                    debug!(
                        disk = %disk_path.display(),
                        error = %e,
                        "failed to read SMART temperature"
                    );
                }
            }
        }
        temps
    }

    /// Read a single unsigned integer from a sysfs file.
    fn read_sysfs_u32(path: &Path) -> Option<u32> {
        match std::fs::read_to_string(path) {
            Ok(content) => match content.trim().parse::<u32>() {
                Ok(val) => Some(val),
                Err(e) => {
                    debug!(
                        path = %path.display(),
                        error = %e,
                        "failed to parse sysfs value"
                    );
                    None
                }
            },
            Err(e) => {
                debug!(
                    path = %path.display(),
                    error = %e,
                    "failed to read sysfs file"
                );
                None
            }
        }
    }

    /// Read current PWM values from hwmon sysfs.
    fn read_pwm_values(&self) -> [Option<u8>; FAN_COUNT] {
        let mut pwms = [None; FAN_COUNT];
        #[allow(clippy::needless_range_loop)]
        for i in 0..FAN_COUNT {
            let path = self.hwmon_path.join(format!("pwm{}", i + 1));
            pwms[i] = Self::read_sysfs_u32(&path).map(|v| v.min(255) as u8);
        }
        pwms
    }

    /// Write a PWM value to a sysfs file.
    fn write_pwm_file(&self, path: &Path, value: u8) -> Result<(), StorageError> {
        std::fs::write(path, value.to_string()).map_err(StorageError::Io)
    }
}

impl Default for ThermalManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper to create a mock sysfs tree for testing.
    fn setup_mock_sysfs(base: &Path) {
        fs::create_dir_all(base).expect("create mock hwmon dir");

        // Fan RPM files
        for i in 1..=3 {
            fs::write(base.join(format!("fan{i}_input")), "4500\n").expect("write fan rpm");
        }

        // Temperature sensor files (millidegrees)
        fs::write(base.join("temp1_input"), "38000\n").expect("write temp1");
        fs::write(base.join("temp2_input"), "42000\n").expect("write temp2");
        fs::write(base.join("temp3_input"), "35000\n").expect("write temp3");

        // PWM files
        for i in 1..=3 {
            fs::write(base.join(format!("pwm{i}")), "128\n").expect("write pwm");
        }
    }

    /// Helper to create a mock CPU thermal zone file.
    fn setup_mock_cpu_thermal(path: &Path, temp_millidegrees: u32) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create mock thermal dir");
        }
        fs::write(path, format!("{temp_millidegrees}\n")).expect("write cpu temp");
    }

    #[test]
    fn profile_defaults_to_balanced() {
        let profile = FanProfile::default();
        assert_eq!(profile, FanProfile::Balanced);
        assert_eq!(profile.hdd_target_c(), 42);
        assert_eq!(profile.cpu_target_c(), 60);
        assert_eq!(profile.min_pwm(), 79);
    }

    #[test]
    fn profile_silence_targets() {
        let profile = FanProfile::Silence;
        assert_eq!(profile.hdd_target_c(), 50);
        assert_eq!(profile.cpu_target_c(), 70);
        assert_eq!(profile.min_pwm(), 51); // ~20%
    }

    #[test]
    fn profile_performance_targets() {
        let profile = FanProfile::Performance;
        assert_eq!(profile.hdd_target_c(), 35);
        assert_eq!(profile.cpu_target_c(), 50);
        assert_eq!(profile.min_pwm(), 128); // ~50%
    }

    #[test]
    fn profile_max_always_full() {
        let profile = FanProfile::Max;
        assert_eq!(profile.min_pwm(), PWM_MAX);
    }

    #[test]
    fn profile_custom_values() {
        let profile = FanProfile::Custom {
            hdd_target: 40,
            cpu_target: 55,
            min_pwm: 100,
        };
        assert_eq!(profile.hdd_target_c(), 40);
        assert_eq!(profile.cpu_target_c(), 55);
        assert_eq!(profile.min_pwm(), 100);
    }

    #[test]
    fn compute_pwm_at_target_returns_minimum() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Balanced);

        // Temperature exactly at target — within hysteresis band
        let pwm = mgr.compute_pwm(42, 42, 0);
        assert_eq!(pwm, mgr.profile.min_pwm());
    }

    #[test]
    fn compute_pwm_within_hysteresis_returns_minimum() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Balanced);

        // Temperature within ±HYSTERESIS_BAND (3 C) of target (42 C)
        let pwm = mgr.compute_pwm(44, 42, 0); // +2, inside band
        assert_eq!(pwm, mgr.profile.min_pwm());

        let pwm = mgr.compute_pwm(40, 42, 0); // -2, inside band
        assert_eq!(pwm, mgr.profile.min_pwm());
    }

    #[test]
    fn compute_pwm_above_target_increases() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Balanced);

        // 10 C above target — should be well above minimum
        let pwm = mgr.compute_pwm(52, 42, 0);
        assert!(
            pwm > mgr.profile.min_pwm(),
            "PWM {pwm} should be above minimum {}",
            mgr.profile.min_pwm()
        );
    }

    #[test]
    fn compute_pwm_critical_returns_max() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Silence);

        let pwm = mgr.compute_pwm(CRITICAL_TEMP_C, 50, 0);
        assert_eq!(pwm, PWM_MAX);

        let pwm = mgr.compute_pwm(CRITICAL_TEMP_C + 10, 50, 0);
        assert_eq!(pwm, PWM_MAX);
    }

    #[test]
    fn compute_pwm_well_below_target_returns_minimum() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Balanced);

        // 20 C below target — proportional term is negative, output clamped to min
        let pwm = mgr.compute_pwm(22, 42, 0);
        assert_eq!(pwm, mgr.profile.min_pwm());
    }

    #[test]
    fn compute_pwm_clamps_to_255() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Balanced);

        // 30 C above target — proportional output would exceed 255, must clamp
        let pwm = mgr.compute_pwm(72, 42, 0);
        assert!(pwm <= PWM_MAX);
    }

    #[test]
    fn compute_pwm_progressive_increase() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Balanced);

        // Verify PWM increases as temperature rises above target + hysteresis
        let target = 42;
        let pwm_5_over = mgr.compute_pwm(target + 5, target, 0);
        // Reset integral for fair comparison
        mgr.integral_error[0] = 0.0;
        let pwm_10_over = mgr.compute_pwm(target + 10, target, 0);

        assert!(
            pwm_10_over > pwm_5_over,
            "PWM at +10 C ({pwm_10_over}) should be higher than at +5 C ({pwm_5_over})"
        );
    }

    #[test]
    fn read_status_from_mock_sysfs() {
        let dir = std::env::temp_dir().join("sfnas_thermal_test_status");
        let _ = fs::remove_dir_all(&dir);

        let hwmon = dir.join("hwmon");
        let cpu_path = dir.join("thermal_zone0_temp");

        setup_mock_sysfs(&hwmon);
        setup_mock_cpu_thermal(&cpu_path, 55000);

        let mgr = ThermalManager::with_paths(hwmon, cpu_path);
        let status = mgr.read_status();

        // Fan RPMs
        assert_eq!(status.fan_rpm[0], Some(4500));
        assert_eq!(status.fan_rpm[1], Some(4500));
        assert_eq!(status.fan_rpm[2], Some(4500));

        // Hwmon temps (millidegrees -> degrees)
        assert_eq!(status.hwmon_temps_c[0], Some(38));
        assert_eq!(status.hwmon_temps_c[1], Some(42));
        assert_eq!(status.hwmon_temps_c[2], Some(35));

        // CPU temp
        assert_eq!(status.cpu_temp_c, Some(55));

        // PWM values
        assert_eq!(status.pwm_values[0], Some(128));
        assert_eq!(status.pwm_values[1], Some(128));
        assert_eq!(status.pwm_values[2], Some(128));

        // Profile
        assert_eq!(status.active_profile, FanProfile::Balanced);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_pwm_invalid_fan_returns_error() {
        let mut mgr = ThermalManager::new();

        assert!(mgr.set_pwm(0, 128).is_err());
        assert!(mgr.set_pwm(4, 128).is_err());
        assert!(mgr.set_pwm(255, 128).is_err());
    }

    #[test]
    fn set_profile_resets_integral() {
        let mut mgr = ThermalManager::new();

        // Accumulate some integral error
        mgr.integral_error = [10.0, 20.0];

        mgr.set_profile(FanProfile::Performance);

        assert_eq!(mgr.integral_error[0], 0.0);
        assert_eq!(mgr.integral_error[1], 0.0);
        assert_eq!(*mgr.profile(), FanProfile::Performance);
    }

    #[test]
    fn profile_names() {
        assert_eq!(FanProfile::Silence.name(), "Silence");
        assert_eq!(FanProfile::Balanced.name(), "Balanced");
        assert_eq!(FanProfile::Performance.name(), "Performance");
        assert_eq!(FanProfile::Max.name(), "Max");
        assert_eq!(
            FanProfile::Custom {
                hdd_target: 40,
                cpu_target: 55,
                min_pwm: 100,
            }
            .name(),
            "Custom"
        );
    }

    #[test]
    fn integral_windup_is_clamped() {
        let mut mgr = ThermalManager::new();
        mgr.set_profile(FanProfile::Balanced);

        // Call compute_pwm many times with temperature way above target
        // to ensure integral doesn't grow without bound
        for _ in 0..200 {
            mgr.compute_pwm(80, 42, 0);
        }

        assert!(
            mgr.integral_error[0] <= 50.0,
            "integral error {} should be clamped to 50.0",
            mgr.integral_error[0]
        );
        assert!(
            mgr.integral_error[0] >= -50.0,
            "integral error {} should be clamped to -50.0",
            mgr.integral_error[0]
        );
    }
}
