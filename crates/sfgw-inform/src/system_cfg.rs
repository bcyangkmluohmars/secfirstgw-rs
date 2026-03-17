// SPDX-License-Identifier: AGPL-3.0-or-later

//! system.cfg and mgmt_cfg generation for adopted UniFi devices.
//!
//! UniFi devices receive two config blobs via Inform `setparam` responses:
//!
//! - **`mgmt_cfg`** — management parameters (newline-separated key=value string)
//!   Contains: authkey, cfgurl, stun_url, led_enabled, use_aes_gcm, etc.
//!   These go into `/var/etc/persistent/cfg/mgmt` on the device.
//!
//! - **`system_cfg`** — full system configuration (newline-separated key=value string)
//!   Contains: users, SSH, iptables, NTP, syslog, radio, network, etc.
//!   This is the device's running config at `/tmp/system.cfg`.
//!
//! Reference: real UAP system_cfg dump from adopted device.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Configuration parameters for generating system_cfg + mgmt_cfg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCfg {
    /// Gateway MGMT IP (where this inform listener runs).
    pub mgmt_ip: String,
    /// Per-device authkey (32 hex chars).
    pub authkey: String,
    /// Config version hash (16 hex chars). Changes trigger device config reload.
    pub cfgversion: String,
    /// Per-device SSH username.
    pub ssh_username: String,
    /// Per-device SSH password hash (crypt(3) format, e.g. $6$...).
    pub ssh_password_hash: String,
}

/// Generate a 16-hex-char config version hash from the system_cfg content.
///
/// This changes whenever the config changes, telling the device to reload.
/// Real controllers use an opaque hex string; we hash the config content.
pub fn generate_cfgversion(system_cfg: &str) -> String {
    let mut hasher = DefaultHasher::new();
    system_cfg.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Generate the `mgmt_cfg` string for Inform `setparam` responses.
///
/// This is a newline-separated key=value string (NOT JSON) that goes into
/// the `mgmt_cfg` field of the setparam response JSON. The device stores
/// these values in `/var/etc/persistent/cfg/mgmt`.
///
/// Based on real controller traffic (pixiedust capture):
/// ```text
/// cfgversion=bd4b0ca608dd9ca5
/// led_enabled=false
/// stun_url=stun://unifi:3478/
/// mgmt_url=https://unifi:8443/manage/site/default
/// authkey=0ee876dee74ff09c2e88387ecda39512
/// use_aes_gcm=true
/// report_crash=true
/// ```
/// Generate mgmt_cfg matching the real UniFi controller format exactly.
///
/// Reference: ADOPTION_DEFAULT_KEY.json capture from real UDM Pro controller.
/// Field order and format must match exactly — mcad parses these strictly.
pub fn generate_mgmt_cfg(cfg: &SystemCfg, include_authkey: bool) -> String {
    let mut lines = Vec::with_capacity(16);

    // Exact field order from real controller capture
    lines.push("capability=notif,notif-assoc-stat".into());
    lines.push("selfrun_guest_mode=pass".into());
    lines.push(format!("cfgversion={}", cfg.cfgversion));
    lines.push("led_enabled=true".into());
    lines.push(format!("stun_url=stun://{}:3478/", cfg.mgmt_ip));
    lines.push(format!(
        "mgmt_url=https://{}:8443/manage/site/default",
        cfg.mgmt_ip
    ));

    if include_authkey {
        lines.push(format!("authkey={}", cfg.authkey));
    }

    lines.push("use_aes_gcm=true".into());
    lines.push("report_crash=true".into());

    // Trailing newline — matches real controller output
    let mut result = lines.join("\n");
    result.push('\n');
    result
}

/// Generate the `system_cfg` string for Inform `setparam` responses.
///
/// This is the device's full running configuration. Format is newline-separated
/// key=value pairs — NO comments, NO blank lines. The device writes this to
/// `/tmp/system.cfg` and calls `apply-config`. mcad rejects invalid content.
///
/// Format must match real switch system.cfg exactly (alphabetically sorted,
/// all required subsystems present even if disabled).
///
/// Reference: real USW-Flex `/tmp/system.cfg` dump from factory-default device.
pub fn generate_system_cfg(cfg: &SystemCfg) -> String {
    let mut lines = Vec::with_capacity(64);

    // bridge — disabled on switches (no wireless bridge)
    lines.push("bridge.status=disabled".into());

    // dhcpc — DHCP client on management interface
    lines.push("dhcpc.1.devname=eth0".into());
    lines.push("dhcpc.1.status=enabled".into());
    lines.push("dhcpc.status=enabled".into());

    // dhcpd — disabled (we don't run DHCP server on switch)
    lines.push("dhcpd.1.status=disabled".into());
    lines.push("dhcpd.status=disabled".into());

    // ebtables — enabled on switches
    lines.push("ebtables.status=enabled".into());

    // httpd — disabled (no local web UI needed)
    lines.push("httpd.status=disabled".into());

    // iptables — restrict SSH to gateway MGMT IP only
    lines.push(format!(
        "iptables.1.cmd=-A INPUT -s {} -p tcp --dport 22 -j ACCEPT",
        cfg.mgmt_ip
    ));
    lines.push("iptables.1.status=enabled".into());
    lines.push("iptables.2.cmd=-A INPUT -p tcp --dport 22 -j DROP".into());
    lines.push("iptables.2.status=enabled".into());
    lines.push("iptables.status=enabled".into());

    // mgmt — management settings
    lines.push("mgmt.discovery.status=enabled".into());
    lines.push("mgmt.flavor=ace".into());
    lines.push("mgmt.is_default=false".into());

    // netconf — network interface config
    lines.push("netconf.1.autoip.status=disabled".into());
    lines.push("netconf.1.devname=eth0".into());
    lines.push("netconf.1.status=enabled".into());
    lines.push("netconf.1.up=enabled".into());
    lines.push("netconf.status=enabled".into());

    // ntpclient — NTP pointing to gateway + ubnt fallback
    lines.push(format!("ntpclient.1.server={}", cfg.mgmt_ip));
    lines.push("ntpclient.1.status=enabled".into());
    lines.push("ntpclient.2.server=0.ubnt.pool.ntp.org".into());
    lines.push("ntpclient.2.status=enabled".into());
    lines.push("ntpclient.status=enabled".into());

    // radio — disabled on switches
    lines.push("radio.status=disabled".into());

    // route — multicast route (standard on switches)
    lines.push("route.1.devname=eth0".into());
    lines.push("route.1.ip=224.0.0.0".into());
    lines.push("route.1.netmask=3".into());
    lines.push("route.1.status=enabled".into());
    lines.push("route.status=enabled".into());

    // sshd — SSH daemon enabled with password auth
    lines.push("sshd.1.ifname=eth0".into());
    lines.push("sshd.1.status=enabled".into());
    lines.push("sshd.auth.passwd=enabled".into());
    lines.push("sshd.status=enabled".into());

    // stamgr — station manager disabled on switches
    lines.push("stamgr.status=disabled".into());

    // switch — enabled (this IS a switch)
    lines.push("switch.status=enabled".into());

    // syslog
    lines.push("syslog.file=/var/log/messages".into());
    lines.push("syslog.level=8".into());
    lines.push(format!("syslog.remote.ip={}", cfg.mgmt_ip));
    lines.push("syslog.remote.port=514".into());
    lines.push("syslog.remote.status=enabled".into());
    lines.push("syslog.rotate=1".into());
    lines.push("syslog.size=200".into());
    lines.push("syslog.status=enabled".into());

    // unifi key
    lines.push(format!("unifi.key={}", cfg.authkey));

    // users — per-device SSH credentials
    lines.push(format!("users.1.name={}", cfg.ssh_username));
    lines.push(format!("users.1.password={}", cfg.ssh_password_hash));
    lines.push("users.1.status=enabled".into());

    // Disable factory default user if we're using a custom one
    if cfg.ssh_username != "ubnt" {
        lines.push("users.2.name=ubnt".into());
        lines.push("users.2.password=x".into());
        lines.push("users.2.shell=/bin/false".into());
        lines.push("users.2.status=enabled".into());
    }

    lines.push("users.status=enabled".into());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> SystemCfg {
        SystemCfg {
            mgmt_ip: "10.0.0.1".into(),
            authkey: "abcdef0123456789abcdef0123456789".into(),
            cfgversion: "85aa57558291b4d0".into(),
            ssh_username: "sfgw_dev1".into(),
            ssh_password_hash: "$6$rounds=10000$salt$hash".into(),
        }
    }

    #[test]
    fn mgmt_cfg_contains_authkey_and_inform_url() {
        let result = generate_mgmt_cfg(&test_cfg(), true);
        assert!(result.contains("authkey=abcdef0123456789abcdef0123456789"));
        assert!(result.contains("use_aes_gcm=true"));
        assert!(result.contains("cfgversion=85aa57558291b4d0"));
        assert!(result.contains("capability=notif,notif-assoc-stat"));
        assert!(result.contains("stun_url=stun://10.0.0.1:3478/"));
        assert!(result.contains("mgmt_url=https://10.0.0.1:8443/manage/site/default"));
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn mgmt_cfg_without_authkey() {
        let result = generate_mgmt_cfg(&test_cfg(), false);
        assert!(!result.contains("authkey="));
        assert!(result.contains("cfgversion=85aa57558291b4d0"));
        assert!(result.contains("use_aes_gcm=true"));
        assert!(result.contains("mgmt_url=https://10.0.0.1:8443/manage/site/default"));
    }

    #[test]
    fn system_cfg_has_unifi_key() {
        let result = generate_system_cfg(&test_cfg());
        assert!(result.contains("unifi.key=abcdef0123456789abcdef0123456789"));
        assert!(!result.contains("mgmt.authkey"));
        assert!(!result.contains("mgmt.cfgurl"));
    }

    #[test]
    fn system_cfg_has_required_switch_fields() {
        let result = generate_system_cfg(&test_cfg());
        assert!(result.contains("bridge.status=disabled"));
        assert!(result.contains("switch.status=enabled"));
        assert!(result.contains("ebtables.status=enabled"));
        assert!(result.contains("netconf.status=enabled"));
        assert!(result.contains("netconf.1.devname=eth0"));
        assert!(result.contains("route.status=enabled"));
        assert!(result.contains("mgmt.flavor=ace"));
        assert!(result.contains("mgmt.is_default=false"));
        assert!(result.contains("stamgr.status=disabled"));
        assert!(result.contains("radio.status=disabled"));
        assert!(result.contains("httpd.status=disabled"));
    }

    #[test]
    fn system_cfg_has_correct_field_names() {
        let result = generate_system_cfg(&test_cfg());
        assert!(result.contains("users.status=enabled"));
        assert!(result.contains("iptables.status=enabled"));
        assert!(result.contains("ntpclient.status=enabled"));
        assert!(result.contains("syslog.remote.status=enabled"));
        assert!(result.contains("sshd.status=enabled"));
        assert!(result.contains("sshd.auth.passwd=enabled"));
    }

    #[test]
    fn system_cfg_no_comments() {
        let result = generate_system_cfg(&test_cfg());
        assert!(!result.contains('#'));
    }

    #[test]
    fn system_cfg_disables_ubnt_user_when_custom() {
        let result = generate_system_cfg(&test_cfg());
        assert!(result.contains("users.1.name=sfgw_dev1"));
        assert!(result.contains("users.2.name=ubnt"));
        assert!(result.contains("users.2.shell=/bin/false"));
    }

    #[test]
    fn system_cfg_keeps_ubnt_if_username_is_ubnt() {
        let mut cfg = test_cfg();
        cfg.ssh_username = "ubnt".into();
        let result = generate_system_cfg(&cfg);
        assert!(result.contains("users.1.name=ubnt"));
        assert!(!result.contains("users.2.name=ubnt"));
    }
}
