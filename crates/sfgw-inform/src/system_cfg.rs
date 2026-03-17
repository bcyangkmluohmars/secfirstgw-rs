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

/// Device type — determines which system_cfg template to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// Access Point (UAP-AC-Pro, UAP-AC-LR, U6-Pro, etc.)
    Ap,
    /// Switch (USW-Flex, USW-24, etc.)
    Switch,
    /// Unknown device — no system_cfg template available.
    Unknown,
}

impl DeviceType {
    /// Derive device type from UniFi model code (e.g. "U7PG2", "USF5P").
    ///
    /// Returns `Unknown` for unrecognized models — caller must handle this
    /// (e.g. skip system_cfg delivery, alert via IDS).
    pub fn from_model(model: &str) -> Self {
        // AP models: U7xxx (AC generation), U6xxx (WiFi 6), UAPxxx
        if model.starts_with("U7") || model.starts_with("U6") || model.starts_with("UAP") {
            DeviceType::Ap
        // Switch models: USxxx (USW-Flex = USF5P, USW-24 = US24, etc.)
        } else if model.starts_with("US") {
            DeviceType::Switch
        } else {
            DeviceType::Unknown
        }
    }
}

/// A wireless network for system_cfg generation.
#[derive(Debug, Clone)]
pub struct WirelessNetworkCfg {
    pub ssid: String,
    pub security: String,
    pub psk: Option<String>,
    pub hidden: bool,
    pub is_guest: bool,
    pub l2_isolation: bool,
    pub band: String,
    pub vlan_id: Option<u16>,
}

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
    /// Device type — AP or Switch. Determines system_cfg template.
    pub device_type: DeviceType,
    /// Wireless networks to push to APs (ignored for switches).
    #[serde(skip)]
    pub wireless_networks: Vec<WirelessNetworkCfg>,
}

/// Load enabled wireless networks from DB and convert to `WirelessNetworkCfg`.
pub async fn load_wireless_networks(db: &sfgw_db::Db) -> Vec<WirelessNetworkCfg> {
    match sfgw_net::wireless::list_with_psk(db).await {
        Ok(networks) => networks
            .into_iter()
            .map(|n| WirelessNetworkCfg {
                ssid: n.ssid,
                security: match n.security {
                    sfgw_net::wireless::WirelessSecurity::Open => "open".into(),
                    sfgw_net::wireless::WirelessSecurity::Wpa2 => "wpa2".into(),
                    sfgw_net::wireless::WirelessSecurity::Wpa3 => "wpa3".into(),
                },
                psk: n.psk,
                hidden: n.hidden,
                is_guest: n.is_guest,
                l2_isolation: n.l2_isolation,
                band: match n.band {
                    sfgw_net::wireless::WirelessBand::Both => "both".into(),
                    sfgw_net::wireless::WirelessBand::TwoGhz => "2g".into(),
                    sfgw_net::wireless::WirelessBand::FiveGhz => "5g".into(),
                },
                vlan_id: n.vlan_id,
            })
            .collect(),
        Err(e) => {
            tracing::warn!("failed to load wireless networks: {e}");
            Vec::new()
        }
    }
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
/// Dispatches to AP or Switch template based on `cfg.device_type`.
/// Returns `None` for unknown device types — caller should skip system_cfg delivery.
pub fn generate_system_cfg(cfg: &SystemCfg) -> Option<String> {
    match cfg.device_type {
        DeviceType::Ap => Some(generate_ap_system_cfg(cfg)),
        DeviceType::Switch => Some(generate_switch_system_cfg(cfg)),
        DeviceType::Unknown => None,
    }
}

/// Push aaa.N.* + wireless.N.* entries for a single WLAN on a single radio.
///
/// Reference: real UAP-AC-Pro system_cfg dump with WPA2-PSK WLAN.
fn push_aaa_wireless(
    lines: &mut Vec<String>,
    idx: u32,
    net: &WirelessNetworkCfg,
    devname: &str,
    parent: &str,
    is_5ghz: bool,
) {
    let i = idx;
    let hidden = if net.hidden { "true" } else { "false" };
    let guest = if net.is_guest { "true" } else { "false" };
    let l2_iso = if net.l2_isolation {
        "enabled"
    } else {
        "disabled"
    };

    // aaa.N — authentication/encryption config
    let (wpa_ver, key_mgmt, pmf_status, pmf_mode) = match net.security.as_str() {
        "wpa3" => ("2", "SAE", "enabled", "2"),
        _ => ("2", "WPA-PSK", "disabled", "0"), // wpa2 default
    };

    // Bridge device — br0 for untagged, br0.{vlan_id} for VLAN-tagged WLANs
    let br_dev = match net.vlan_id {
        Some(vid) => format!("br0.{vid}"),
        None => "br0".into(),
    };

    lines.push(format!("aaa.{i}.pmf.status={pmf_status}"));
    lines.push(format!("aaa.{i}.pmf.mode={pmf_mode}"));
    lines.push(format!("aaa.{i}.ft.status=disabled"));
    lines.push(format!("aaa.{i}.country_beacon=disabled"));
    lines.push(format!("aaa.{i}.11k.status=disabled"));
    lines.push(format!("aaa.{i}.br.devname={br_dev}"));
    lines.push(format!("aaa.{i}.devname={devname}"));
    lines.push(format!("aaa.{i}.driver=madwifi"));
    lines.push(format!("aaa.{i}.ssid={}", net.ssid));
    lines.push(format!("aaa.{i}.status=enabled"));
    lines.push(format!("aaa.{i}.verbose=2"));
    lines.push(format!("aaa.{i}.wpa={wpa_ver}"));
    lines.push(format!("aaa.{i}.eapol_version=2"));
    lines.push(format!("aaa.{i}.wpa.group_rekey=0"));
    lines.push(format!("aaa.{i}.p2p=disabled"));
    lines.push(format!("aaa.{i}.p2p_cross_connect=disabled"));
    lines.push(format!("aaa.{i}.proxy_arp=disabled"));
    lines.push(format!("aaa.{i}.is_guest={guest}"));
    lines.push(format!("aaa.{i}.tdls_prohibit=disabled"));
    lines.push(format!("aaa.{i}.bss_transition=enabled"));
    lines.push(format!("aaa.{i}.wpa.key.1.mgmt={key_mgmt}"));
    if let Some(ref psk) = net.psk {
        lines.push(format!("aaa.{i}.wpa.psk={psk}"));
    }
    lines.push(format!("aaa.{i}.wpa.1.pairwise=CCMP"));
    lines.push(format!("aaa.{i}.pmf.cipher=AES-128-CMAC"));
    lines.push(format!("aaa.{i}.radius.macacl.status=disabled"));
    lines.push(format!("aaa.{i}.hide_ssid={hidden}"));

    // wireless.N — VAP config
    lines.push(format!("wireless.{i}.mode=master"));
    lines.push(format!("wireless.{i}.devname={devname}"));
    lines.push(format!("wireless.{i}.status=enabled"));
    lines.push(format!("wireless.{i}.authmode=1"));
    lines.push(format!("wireless.{i}.l2_isolation={l2_iso}"));
    lines.push(format!("wireless.{i}.is_guest={guest}"));
    lines.push(format!("wireless.{i}.security=none"));
    lines.push(format!("wireless.{i}.ssid={}", net.ssid));
    lines.push(format!("wireless.{i}.hide_ssid={hidden}"));
    lines.push(format!("wireless.{i}.mac_acl.status=enabled"));
    lines.push(format!("wireless.{i}.mac_acl.policy=deny"));
    lines.push(format!("wireless.{i}.wmm=enabled"));
    lines.push(format!("wireless.{i}.uapsd=disabled"));
    lines.push(format!("wireless.{i}.parent={parent}"));
    lines.push(format!("wireless.{i}.puren=0"));
    lines.push(format!(
        "wireless.{i}.pureg={}",
        if is_5ghz { "1" } else { "0" }
    ));
    lines.push(format!("wireless.{i}.usage=user"));
    lines.push(format!("wireless.{i}.wds=disabled"));
    lines.push(format!("wireless.{i}.mcast.enhance=0"));
    lines.push(format!("wireless.{i}.autowds=disabled"));
    lines.push(format!("wireless.{i}.vport=disabled"));
    lines.push(format!("wireless.{i}.vwire=disabled"));
    lines.push(format!("wireless.{i}.schedule_enabled=disabled"));
    lines.push(format!("wireless.{i}.element_adopt=disabled"));
    lines.push(format!("wireless.{i}.mcastrate=auto"));
    lines.push(format!(
        "wireless.{i}.dtim_period={}",
        if is_5ghz { "3" } else { "1" }
    ));
}

/// AP system_cfg — based on real UAP-AC-Pro dump from adopted device.
///
/// Key differences from switch: bridge enabled (br0), radio/wireless/aaa
/// sections present, switch disabled, sshd/dhcpc on br0 not eth0.
fn generate_ap_system_cfg(cfg: &SystemCfg) -> String {
    let mut lines = Vec::with_capacity(128);

    // unifi
    lines.push(format!("unifi.key={}", cfg.authkey));

    // users
    lines.push("users.status=enabled".into());
    lines.push(format!("users.1.name={}", cfg.ssh_username));
    lines.push(format!("users.1.password={}", cfg.ssh_password_hash));
    lines.push("users.1.status=enabled".into());
    if cfg.ssh_username != "ubnt" {
        lines.push("users.2.name=ubnt".into());
        lines.push("users.2.password=x".into());
        lines.push("users.2.shell=/bin/false".into());
        lines.push("users.2.status=enabled".into());
    }

    // radio — enabled on APs, minimal config (let device use defaults)
    lines.push("radio.status=enabled".into());
    lines.push("radio.countrycode=276".into());

    // radio.1 — 2.4GHz
    lines.push("radio.1.phyname=wifi0".into());
    lines.push("radio.1.mode=master".into());
    lines.push("radio.1.rate.auto=enabled".into());
    lines.push("radio.1.txpower_mode=auto".into());
    lines.push("radio.1.txpower=auto".into());
    lines.push("radio.1.channel=auto".into());
    lines.push("radio.1.ieee_mode=11nght20".into());
    lines.push("radio.1.devname=ath0".into());
    lines.push("radio.1.status=enabled".into());
    lines.push("radio.1.ampdu.status=enabled".into());
    lines.push("radio.1.antenna.gain=3".into());
    lines.push("radio.1.antenna=-1".into());

    // radio.2 — 5GHz
    lines.push("radio.2.phyname=wifi1".into());
    lines.push("radio.2.mode=master".into());
    lines.push("radio.2.rate.auto=enabled".into());
    lines.push("radio.2.txpower_mode=auto".into());
    lines.push("radio.2.txpower=auto".into());
    lines.push("radio.2.channel=auto".into());
    lines.push("radio.2.ieee_mode=11naht40".into());
    lines.push("radio.2.devname=ath1".into());
    lines.push("radio.2.status=enabled".into());
    lines.push("radio.2.ampdu.status=enabled".into());
    lines.push("radio.2.antenna.gain=3".into());
    lines.push("radio.2.antenna=-1".into());

    // aaa + wireless — dynamic from configured WLANs
    // Track which wifi interfaces map to which VLAN for bridge port assignment.
    // ath_to_vlan: (devname, vlan_id_option)
    let mut ath_to_vlan: Vec<(&str, Option<u16>)> = Vec::new();

    lines.push("aaa.status=enabled".into());
    lines.push("wireless.status=enabled".into());

    let mut idx = 1u32;
    for net in &cfg.wireless_networks {
        let on_2g = net.band == "both" || net.band == "2g";
        let on_5g = net.band == "both" || net.band == "5g";

        if on_2g {
            push_aaa_wireless(&mut lines, idx, net, "ath0", "wifi0", false);
            ath_to_vlan.push(("ath0", net.vlan_id));
            idx += 1;
        }
        if on_5g {
            push_aaa_wireless(&mut lines, idx, net, "ath1", "wifi1", true);
            ath_to_vlan.push(("ath1", net.vlan_id));
            idx += 1;
        }
    }

    // mesh
    lines.push("mesh.status=disabled".into());

    // stamgr
    lines.push("stamgr.status=disabled".into());

    // connectivity
    lines.push("connectivity.status=disabled".into());

    // vlan — enable if any WLAN has a VLAN tag
    let has_vlans = cfg.wireless_networks.iter().any(|n| n.vlan_id.is_some());
    let all_vlans = !cfg.wireless_networks.is_empty()
        && cfg.wireless_networks.iter().all(|n| n.vlan_id.is_some());
    if has_vlans {
        lines.push("vlan.status=enabled".into());
        let mut vlan_idx = 1u32;
        let mut seen_vids: Vec<u16> = Vec::new();
        for net in &cfg.wireless_networks {
            if let Some(vid) = net.vlan_id
                && !seen_vids.contains(&vid)
            {
                seen_vids.push(vid);
                // vlan.N.devname is the PARENT device — firmware runs
                // `vconfig add <devname> <id>`. With name type
                // DEV_PLUS_VID_NO_PAD, creates interface "eth0.{vid}".
                lines.push(format!("vlan.{vlan_idx}.devname=eth0"));
                lines.push(format!("vlan.{vlan_idx}.id={vid}"));
                lines.push(format!("vlan.{vlan_idx}.status=enabled"));
                vlan_idx += 1;
            }
        }
    } else {
        lines.push("vlan.status=disabled".into());
    }

    // bridge — AP uses br0 bridging eth0 + wifi interfaces
    // When ALL WLANs are VLAN-tagged, wifi interfaces belong in VLAN bridges
    // (hostapd moves them via aaa.N.br.devname), not in br0.
    lines.push("bridge.status=enabled".into());
    lines.push("bridge.1.devname=br0".into());
    lines.push("bridge.1.fd=1".into());
    lines.push("bridge.1.stp.status=disabled".into());
    lines.push("bridge.1.port.1.devname=eth0".into());
    if !all_vlans {
        // Only include wifi in br0 if there are untagged WLANs (or no WLANs)
        lines.push("bridge.1.port.2.devname=ath0".into());
        lines.push("bridge.1.port.3.devname=ath1".into());
    }

    // VLAN bridges — one br0.{vid} per unique VLAN
    // Includes eth0.{vid} (uplink) + wifi interfaces assigned to this VLAN.
    // Firmware generates bridge.conf which runs `brctl addif` for each port.
    if has_vlans {
        let mut seen_vids: Vec<u16> = Vec::new();
        let mut bridge_idx = 2u32;
        for net in &cfg.wireless_networks {
            if let Some(vid) = net.vlan_id
                && !seen_vids.contains(&vid)
            {
                seen_vids.push(vid);
                lines.push(format!("bridge.{bridge_idx}.devname=br0.{vid}"));
                lines.push(format!("bridge.{bridge_idx}.fd=1"));
                lines.push(format!("bridge.{bridge_idx}.stp.status=disabled"));
                // Port 1: VLAN sub-interface (uplink to switch/router)
                lines.push(format!("bridge.{bridge_idx}.port.1.devname=eth0.{vid}"));
                // Additional ports: wifi interfaces assigned to this VLAN
                let mut port_idx = 2u32;
                for &(ath_dev, ath_vid) in &ath_to_vlan {
                    if ath_vid == Some(vid) {
                        lines.push(format!(
                            "bridge.{bridge_idx}.port.{port_idx}.devname={ath_dev}"
                        ));
                        port_idx += 1;
                    }
                }
                bridge_idx += 1;
            }
        }
    }

    // qos
    lines.push("qos.status=disabled".into());

    // netconf — AP uses br0 as primary
    lines.push("netconf.status=enabled".into());
    lines.push("netconf.1.status=enabled".into());
    lines.push("netconf.1.devname=br0".into());
    lines.push("netconf.1.ip=0.0.0.0".into());
    lines.push("netconf.1.autoip.status=disabled".into());
    lines.push("netconf.1.up=enabled".into());
    lines.push("netconf.2.status=enabled".into());
    lines.push("netconf.2.devname=eth0".into());
    lines.push("netconf.2.ip=0.0.0.0".into());
    lines.push("netconf.2.autoip.status=disabled".into());
    lines.push("netconf.2.promisc=enabled".into());
    lines.push("netconf.2.up=enabled".into());

    // netconf entries for VLAN bridge interfaces — must be UP for traffic to flow
    if has_vlans {
        let mut netconf_idx = 3u32;
        let mut seen_vids: Vec<u16> = Vec::new();
        for net in &cfg.wireless_networks {
            if let Some(vid) = net.vlan_id
                && !seen_vids.contains(&vid)
            {
                seen_vids.push(vid);
                // br0.{vid} — VLAN bridge
                lines.push(format!("netconf.{netconf_idx}.status=enabled"));
                lines.push(format!("netconf.{netconf_idx}.devname=br0.{vid}"));
                lines.push(format!("netconf.{netconf_idx}.ip=0.0.0.0"));
                lines.push(format!("netconf.{netconf_idx}.autoip.status=disabled"));
                lines.push(format!("netconf.{netconf_idx}.up=enabled"));
                netconf_idx += 1;
                // eth0.{vid} — VLAN sub-interface
                lines.push(format!("netconf.{netconf_idx}.status=enabled"));
                lines.push(format!("netconf.{netconf_idx}.devname=eth0.{vid}"));
                lines.push(format!("netconf.{netconf_idx}.ip=0.0.0.0"));
                lines.push(format!("netconf.{netconf_idx}.autoip.status=disabled"));
                lines.push(format!("netconf.{netconf_idx}.promisc=enabled"));
                lines.push(format!("netconf.{netconf_idx}.up=enabled"));
                netconf_idx += 1;
            }
        }
    }

    // macacl
    lines.push("macacl.status=disabled".into());

    // dhcpc — on br0 for AP
    lines.push("dhcpc.status=enabled".into());
    lines.push("dhcpc.1.status=enabled".into());
    lines.push("dhcpc.1.devname=br0".into());

    // route
    lines.push("route.status=enabled".into());

    // resolv
    lines.push("resolv.status=enabled".into());
    lines.push("resolv.nameserver.1.status=disabled".into());
    lines.push("resolv.nameserver.2.status=disabled".into());

    // ebtables
    lines.push("ebtables.status=enabled".into());
    lines.push("ebtables.add_vlan.status=disabled".into());
    lines.push("ebtables.1.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP".into());
    lines.push("ebtables.2.cmd=-t nat -A POSTROUTING --out-interface ath0 -d BGA -j DROP".into());
    lines.push("ebtables.3.cmd=-t nat -A PREROUTING --in-interface ath1 -d BGA -j DROP".into());
    lines.push("ebtables.4.cmd=-t nat -A POSTROUTING --out-interface ath1 -d BGA -j DROP".into());

    // iptables — restrict SSH to gateway MGMT IP only
    lines.push(format!(
        "iptables.1.cmd=-A INPUT -s {} -p tcp --dport 22 -j ACCEPT",
        cfg.mgmt_ip
    ));
    lines.push("iptables.1.status=enabled".into());
    lines.push("iptables.2.cmd=-A INPUT -p tcp --dport 22 -j DROP".into());
    lines.push("iptables.2.status=enabled".into());
    lines.push("iptables.status=enabled".into());
    lines.push("ip6tables.status=disabled".into());

    // redirector
    lines.push("redirector.status=disabled".into());

    // ipset
    lines.push("ipset.status=disabled".into());

    // dnsmasq
    lines.push("dnsmasq.status=disabled".into());

    // sshd — on br0 for AP
    lines.push("sshd.status=enabled".into());
    lines.push("sshd.auth.passwd=enabled".into());
    lines.push("sshd.1.status=enabled".into());
    lines.push("sshd.1.ifname=br0".into());

    // ntpclient
    lines.push("ntpclient.status=enabled".into());
    lines.push(format!("ntpclient.1.server={}", cfg.mgmt_ip));
    lines.push("ntpclient.1.status=enabled".into());
    lines.push("ntpclient.2.server=0.ubnt.pool.ntp.org".into());
    lines.push("ntpclient.2.status=enabled".into());

    // switch — disabled on AP
    lines.push("switch.status=disabled".into());

    // mgmt
    lines.push("mgmt.discovery.status=enabled".into());
    lines.push("mgmt.flavor=ace".into());
    lines.push("mgmt.is_default=false".into());

    lines.join("\n")
}

/// Switch system_cfg — based on real USW-Flex dump.
fn generate_switch_system_cfg(cfg: &SystemCfg) -> String {
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

    fn test_switch_cfg() -> SystemCfg {
        SystemCfg {
            mgmt_ip: "10.0.0.1".into(),
            authkey: "abcdef0123456789abcdef0123456789".into(),
            cfgversion: "85aa57558291b4d0".into(),
            ssh_username: "sfgw_dev1".into(),
            ssh_password_hash: "$6$rounds=10000$salt$hash".into(),
            device_type: DeviceType::Switch,
            wireless_networks: Vec::new(),
        }
    }

    fn test_ap_cfg() -> SystemCfg {
        SystemCfg {
            mgmt_ip: "10.0.0.1".into(),
            authkey: "abcdef0123456789abcdef0123456789".into(),
            cfgversion: "85aa57558291b4d0".into(),
            ssh_username: "sfgw_dev1".into(),
            ssh_password_hash: "$6$rounds=10000$salt$hash".into(),
            device_type: DeviceType::Ap,
            wireless_networks: Vec::new(),
        }
    }

    #[test]
    fn mgmt_cfg_contains_authkey_and_inform_url() {
        let result = generate_mgmt_cfg(&test_switch_cfg(), true);
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
        let result = generate_mgmt_cfg(&test_switch_cfg(), false);
        assert!(!result.contains("authkey="));
        assert!(result.contains("cfgversion=85aa57558291b4d0"));
        assert!(result.contains("use_aes_gcm=true"));
        assert!(result.contains("mgmt_url=https://10.0.0.1:8443/manage/site/default"));
    }

    #[test]
    fn system_cfg_has_unifi_key() {
        let result = generate_system_cfg(&test_switch_cfg()).unwrap();
        assert!(result.contains("unifi.key=abcdef0123456789abcdef0123456789"));
        assert!(!result.contains("mgmt.authkey"));
        assert!(!result.contains("mgmt.cfgurl"));
    }

    #[test]
    fn system_cfg_has_required_switch_fields() {
        let result = generate_system_cfg(&test_switch_cfg()).unwrap();
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
        let result = generate_system_cfg(&test_switch_cfg()).unwrap();
        assert!(result.contains("users.status=enabled"));
        assert!(result.contains("iptables.status=enabled"));
        assert!(result.contains("ntpclient.status=enabled"));
        assert!(result.contains("syslog.remote.status=enabled"));
        assert!(result.contains("sshd.status=enabled"));
        assert!(result.contains("sshd.auth.passwd=enabled"));
    }

    #[test]
    fn system_cfg_no_comments() {
        let result = generate_system_cfg(&test_switch_cfg()).unwrap();
        assert!(!result.contains('#'));
    }

    #[test]
    fn system_cfg_disables_ubnt_user_when_custom() {
        let result = generate_system_cfg(&test_switch_cfg()).unwrap();
        assert!(result.contains("users.1.name=sfgw_dev1"));
        assert!(result.contains("users.2.name=ubnt"));
        assert!(result.contains("users.2.shell=/bin/false"));
    }

    #[test]
    fn system_cfg_keeps_ubnt_if_username_is_ubnt() {
        let mut cfg = test_switch_cfg();
        cfg.ssh_username = "ubnt".into();
        let result = generate_system_cfg(&cfg).unwrap();
        assert!(result.contains("users.1.name=ubnt"));
        assert!(!result.contains("users.2.name=ubnt"));
    }

    #[test]
    fn ap_system_cfg_has_bridge_and_radio() {
        let result = generate_system_cfg(&test_ap_cfg()).unwrap();
        assert!(result.contains("bridge.status=enabled"));
        assert!(result.contains("bridge.1.devname=br0"));
        assert!(result.contains("radio.status=enabled"));
        assert!(result.contains("radio.1.devname=ath0"));
        assert!(result.contains("radio.2.devname=ath1"));
        assert!(result.contains("switch.status=disabled"));
        assert!(result.contains("sshd.1.ifname=br0"));
        assert!(result.contains("dhcpc.1.devname=br0"));
    }

    #[test]
    fn ap_system_cfg_no_switch_fields() {
        let result = generate_system_cfg(&test_ap_cfg()).unwrap();
        assert!(!result.contains("switch.status=enabled"));
        assert!(!result.contains("httpd.status"));
    }

    #[test]
    fn device_type_from_model() {
        assert_eq!(DeviceType::from_model("U7PG2"), DeviceType::Ap);
        assert_eq!(DeviceType::from_model("U6PRO"), DeviceType::Ap);
        assert_eq!(DeviceType::from_model("USF5P"), DeviceType::Switch);
    }

    #[test]
    fn ap_system_cfg_with_wlan() {
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![WirelessNetworkCfg {
            ssid: "MyNetwork".into(),
            security: "wpa2".into(),
            psk: Some("testpass123".into()),
            hidden: false,
            is_guest: false,
            l2_isolation: false,
            band: "both".into(),
            vlan_id: None,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // Should have aaa + wireless entries for both radios (idx 1 = 2.4GHz, idx 2 = 5GHz)
        assert!(result.contains("aaa.1.ssid=MyNetwork"));
        assert!(result.contains("aaa.1.devname=ath0"));
        assert!(result.contains("aaa.1.wpa.psk=testpass123"));
        assert!(result.contains("aaa.1.wpa.key.1.mgmt=WPA-PSK"));
        assert!(result.contains("wireless.1.ssid=MyNetwork"));
        assert!(result.contains("wireless.1.parent=wifi0"));

        assert!(result.contains("aaa.2.ssid=MyNetwork"));
        assert!(result.contains("aaa.2.devname=ath1"));
        assert!(result.contains("aaa.2.wpa.psk=testpass123"));
        assert!(result.contains("wireless.2.ssid=MyNetwork"));
        assert!(result.contains("wireless.2.parent=wifi1"));
    }

    #[test]
    fn ap_system_cfg_wpa3() {
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![WirelessNetworkCfg {
            ssid: "SecureNet".into(),
            security: "wpa3".into(),
            psk: Some("wpa3pass1".into()),
            hidden: true,
            is_guest: false,
            l2_isolation: true,
            band: "5g".into(),
            vlan_id: None,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // 5GHz only — should be idx 1 on ath1
        assert!(result.contains("aaa.1.devname=ath1"));
        assert!(result.contains("aaa.1.wpa.key.1.mgmt=SAE"));
        assert!(result.contains("aaa.1.pmf.status=enabled"));
        assert!(result.contains("aaa.1.pmf.mode=2"));
        assert!(result.contains("aaa.1.hide_ssid=true"));
        assert!(result.contains("wireless.1.l2_isolation=enabled"));

        // Should NOT have ath0 entry
        assert!(!result.contains("aaa.2."));
    }

    #[test]
    fn ap_system_cfg_vlan_tagged_wlan() {
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![WirelessNetworkCfg {
            ssid: "LAN-WiFi".into(),
            security: "wpa2".into(),
            psk: Some("testpass123".into()),
            hidden: false,
            is_guest: false,
            l2_isolation: false,
            band: "both".into(),
            vlan_id: Some(10),
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // Bridge device should be br0.10 for VLAN-tagged WLAN
        assert!(result.contains("aaa.1.br.devname=br0.10"));
        assert!(result.contains("aaa.2.br.devname=br0.10"));

        // VLAN section — devname is the PARENT device (eth0), id is the VLAN ID
        assert!(result.contains("vlan.status=enabled"));
        assert!(result.contains("vlan.1.devname=eth0"));
        assert!(result.contains("vlan.1.id=10"));

        // VLAN bridge with uplink + wifi interfaces
        assert!(result.contains("bridge.2.devname=br0.10"));
        assert!(result.contains("bridge.2.port.1.devname=eth0.10"));
        assert!(result.contains("bridge.2.port.2.devname=ath0"));
        assert!(result.contains("bridge.2.port.3.devname=ath1"));

        // wifi interfaces should NOT be in br0 when all WLANs are VLAN-tagged
        assert!(!result.contains("bridge.1.port.2.devname=ath0"));
        assert!(!result.contains("bridge.1.port.3.devname=ath1"));
    }

    #[test]
    fn ap_system_cfg_no_wlans_still_valid() {
        let result = generate_system_cfg(&test_ap_cfg()).unwrap();
        assert!(result.contains("aaa.status=enabled"));
        assert!(result.contains("wireless.status=enabled"));
        // No aaa.1 or wireless.1 entries
        assert!(!result.contains("aaa.1."));
        assert!(!result.contains("wireless.1."));
    }
}
