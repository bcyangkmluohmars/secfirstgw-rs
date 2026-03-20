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
    /// Radio channel (0 = auto).
    pub channel: u16,
    /// TX power in dBm (0 = auto).
    pub tx_power: u16,
    /// Bandwidth mode for ieee_mode calculation.
    pub bandwidth: sfgw_net::wireless::WirelessBandwidth,
    /// 802.11r fast roaming.
    pub fast_roaming: bool,
    /// Band steering (prefer 5 GHz).
    pub band_steering: bool,
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

/// VAP (Virtual Access Point) assignment for a single wireless network.
///
/// Shows which radio interfaces this network will be assigned to, based on
/// its band setting and its position in the network list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VapAssignment {
    /// Network ID from the database.
    pub network_id: Option<i64>,
    /// SSID for reference.
    pub ssid: String,
    /// VAP device name on 2.4 GHz radio (None if not on this radio).
    pub vap_2g: Option<String>,
    /// VAP device name on 5 GHz radio (None if not on this radio).
    pub vap_5g: Option<String>,
}

/// Compute VAP assignments for a list of wireless networks.
///
/// Returns the assignment for each network, respecting the MAX_VAPS_PER_RADIO limit.
/// Networks beyond the limit on a given radio will have `None` for that radio's VAP.
pub fn compute_vap_assignments(networks: &[WirelessNetworkCfg]) -> Vec<VapAssignment> {
    let mut vap_idx_2g: usize = 0;
    let mut vap_idx_5g: usize = 0;
    let mut result = Vec::with_capacity(networks.len());

    for net in networks {
        let on_2g = net.band == "both" || net.band == "2g";
        let on_5g = net.band == "both" || net.band == "5g";

        let vap_2g = if on_2g && vap_idx_2g < MAX_VAPS_PER_RADIO {
            let dev = vap_devname(false, vap_idx_2g);
            vap_idx_2g += 1;
            Some(dev)
        } else {
            None
        };

        let vap_5g = if on_5g && vap_idx_5g < MAX_VAPS_PER_RADIO {
            let dev = vap_devname(true, vap_idx_5g);
            vap_idx_5g += 1;
            Some(dev)
        } else {
            None
        };

        result.push(VapAssignment {
            network_id: None, // Caller should fill from DB IDs
            ssid: net.ssid.clone(),
            vap_2g,
            vap_5g,
        });
    }

    result
}

/// Count how many VAPs would be used per radio for the given networks.
///
/// Returns `(count_2g, count_5g)`.
pub fn count_vaps_per_radio(networks: &[WirelessNetworkCfg]) -> (usize, usize) {
    let mut count_2g: usize = 0;
    let mut count_5g: usize = 0;

    for net in networks {
        if net.band == "both" || net.band == "2g" {
            count_2g += 1;
        }
        if net.band == "both" || net.band == "5g" {
            count_5g += 1;
        }
    }

    (count_2g, count_5g)
}

/// Validate that the wireless network configuration does not exceed VAP limits.
///
/// Returns `Ok(())` if within limits, or `Err` with a description of the violation.
pub fn validate_vap_limits(networks: &[WirelessNetworkCfg]) -> std::result::Result<(), String> {
    let (count_2g, count_5g) = count_vaps_per_radio(networks);

    if count_2g > MAX_VAPS_PER_RADIO {
        return Err(format!(
            "too many networks on 2.4 GHz radio: {count_2g} (max {MAX_VAPS_PER_RADIO})"
        ));
    }
    if count_5g > MAX_VAPS_PER_RADIO {
        return Err(format!(
            "too many networks on 5 GHz radio: {count_5g} (max {MAX_VAPS_PER_RADIO})"
        ));
    }

    Ok(())
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
                channel: n.channel,
                tx_power: n.tx_power,
                bandwidth: n.bandwidth,
                fast_roaming: n.fast_roaming,
                band_steering: n.band_steering,
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

/// Maximum number of VAPs (Virtual Access Points) per radio.
///
/// UAP-AC-Pro hardware supports up to 4 VAPs per radio (ath0..ath3 on 2.4 GHz,
/// ath10..ath13 on 5 GHz). Exceeding this limit causes the AP firmware to reject
/// the config or behave unpredictably.
pub const MAX_VAPS_PER_RADIO: usize = 4;

/// Compute the VAP device name for a given radio and VAP index within that radio.
///
/// Radio 0 (2.4 GHz): ath0 (primary), ath1, ath2, ath3
/// Radio 1 (5 GHz):   ath10 (primary), ath11, ath12, ath13
///
/// `vap_index` is 0-based within the radio (0 = primary VAP).
fn vap_devname(is_5ghz: bool, vap_index: usize) -> String {
    if is_5ghz {
        format!("ath1{vap_index}")
    } else {
        format!("ath{vap_index}")
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

    // 802.11r fast roaming (FT)
    if net.fast_roaming {
        lines.push(format!("aaa.{i}.ft.status=enabled"));
        lines.push(format!("aaa.{i}.ft_over_ds=1"));
        lines.push(format!("aaa.{i}.ft_key_method=1"));
        // Auto-generate FT MDID from SSID hash (4 hex chars, deterministic per SSID)
        let mdid = {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&net.ssid, &mut hasher);
            format!("{:04x}", std::hash::Hasher::finish(&hasher) as u16)
        };
        lines.push(format!("aaa.{i}.ft_mdid={mdid}"));
    } else {
        lines.push(format!("aaa.{i}.ft.status=disabled"));
    }

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

    // Channel override (0 = auto, already set on radio, skip)
    if net.channel != 0 {
        lines.push(format!("wireless.{i}.channel={}", net.channel));
    }

    // TX power override (0 = auto)
    if net.tx_power != 0 {
        lines.push(format!("wireless.{i}.txpower={}", net.tx_power));
    }

    // HT mode (bandwidth)
    let htmode = net.bandwidth.to_ieee_mode(is_5ghz);
    lines.push(format!("wireless.{i}.htmode={htmode}"));

    // Band steering
    if net.band_steering {
        lines.push(format!("wireless.{i}.band_steering=prefer_5g"));
    }
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

    // Resolve radio-level settings from the first applicable network per band.
    // If multiple networks exist on the same band, the first one's settings win.
    let (ch_2g, txp_2g, bw_2g) = cfg
        .wireless_networks
        .iter()
        .find(|n| n.band == "both" || n.band == "2g")
        .map(|n| (n.channel, n.tx_power, n.bandwidth.clone()))
        .unwrap_or((0, 0, sfgw_net::wireless::WirelessBandwidth::Auto));
    let (ch_5g, txp_5g, bw_5g) = cfg
        .wireless_networks
        .iter()
        .find(|n| n.band == "both" || n.band == "5g")
        .map(|n| (n.channel, n.tx_power, n.bandwidth.clone()))
        .unwrap_or((0, 0, sfgw_net::wireless::WirelessBandwidth::Auto));

    // radio — enabled on APs, minimal config (let device use defaults)
    lines.push("radio.status=enabled".into());
    lines.push("radio.countrycode=276".into());

    // radio.1 — 2.4GHz
    lines.push("radio.1.phyname=wifi0".into());
    lines.push("radio.1.mode=master".into());
    lines.push("radio.1.rate.auto=enabled".into());
    if txp_2g == 0 {
        lines.push("radio.1.txpower_mode=auto".into());
        lines.push("radio.1.txpower=auto".into());
    } else {
        lines.push("radio.1.txpower_mode=custom".into());
        lines.push(format!("radio.1.txpower={txp_2g}"));
    }
    if ch_2g == 0 {
        lines.push("radio.1.channel=auto".into());
    } else {
        lines.push(format!("radio.1.channel={ch_2g}"));
    }
    lines.push(format!("radio.1.ieee_mode={}", bw_2g.to_ieee_mode(false)));
    // radio.1.devname is the primary VAP on 2.4 GHz (always ath0)
    lines.push("radio.1.devname=ath0".into());
    lines.push("radio.1.status=enabled".into());
    lines.push("radio.1.ampdu.status=enabled".into());
    lines.push("radio.1.antenna.gain=3".into());
    lines.push("radio.1.antenna=-1".into());

    // radio.2 — 5GHz
    lines.push("radio.2.phyname=wifi1".into());
    lines.push("radio.2.mode=master".into());
    lines.push("radio.2.rate.auto=enabled".into());
    if txp_5g == 0 {
        lines.push("radio.2.txpower_mode=auto".into());
        lines.push("radio.2.txpower=auto".into());
    } else {
        lines.push("radio.2.txpower_mode=custom".into());
        lines.push(format!("radio.2.txpower={txp_5g}"));
    }
    if ch_5g == 0 {
        lines.push("radio.2.channel=auto".into());
    } else {
        lines.push(format!("radio.2.channel={ch_5g}"));
    }
    lines.push(format!("radio.2.ieee_mode={}", bw_5g.to_ieee_mode(true)));
    // radio.2.devname is the primary VAP on 5 GHz (always ath10)
    lines.push("radio.2.devname=ath10".into());
    lines.push("radio.2.status=enabled".into());
    lines.push("radio.2.ampdu.status=enabled".into());
    lines.push("radio.2.antenna.gain=3".into());
    lines.push("radio.2.antenna=-1".into());

    // aaa + wireless — dynamic from configured WLANs (multi-VAP per radio)
    //
    // Each radio supports up to MAX_VAPS_PER_RADIO VAPs:
    //   Radio 0 (2.4 GHz): ath0 (primary), ath1, ath2, ath3
    //   Radio 1 (5 GHz):   ath10 (primary), ath11, ath12, ath13
    //
    // Networks are grouped by band and assigned VAP indices in order.
    // "both" band networks get a VAP on each radio.
    //
    // Track which wifi interfaces map to which VLAN for bridge port assignment.
    // ath_to_vlan: (devname, vlan_id_option)
    let mut ath_to_vlan: Vec<(String, Option<u16>)> = Vec::new();

    lines.push("aaa.status=enabled".into());
    lines.push("wireless.status=enabled".into());

    // Count VAPs per radio to assign correct devnames
    let mut vap_idx_2g: usize = 0; // next VAP index on 2.4 GHz radio
    let mut vap_idx_5g: usize = 0; // next VAP index on 5 GHz radio
    let mut idx = 1u32; // global aaa/wireless index (1-based)

    for net in &cfg.wireless_networks {
        let on_2g = net.band == "both" || net.band == "2g";
        let on_5g = net.band == "both" || net.band == "5g";

        if on_2g && vap_idx_2g < MAX_VAPS_PER_RADIO {
            let devname = vap_devname(false, vap_idx_2g);
            push_aaa_wireless(&mut lines, idx, net, &devname, "wifi0", false);
            ath_to_vlan.push((devname, net.vlan_id));
            vap_idx_2g += 1;
            idx += 1;
        }
        if on_5g && vap_idx_5g < MAX_VAPS_PER_RADIO {
            let devname = vap_devname(true, vap_idx_5g);
            push_aaa_wireless(&mut lines, idx, net, &devname, "wifi1", true);
            ath_to_vlan.push((devname, net.vlan_id));
            vap_idx_5g += 1;
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
        // Add all untagged VAPs to br0 (or primary VAPs if no WLANs configured)
        let untagged_vaps: Vec<&String> = ath_to_vlan
            .iter()
            .filter(|(_, vid)| vid.is_none())
            .map(|(dev, _)| dev)
            .collect();
        if untagged_vaps.is_empty() && cfg.wireless_networks.is_empty() {
            // No WLANs — include primary VAPs in br0 as defaults
            lines.push("bridge.1.port.2.devname=ath0".into());
            lines.push("bridge.1.port.3.devname=ath10".into());
        } else {
            for (port_idx, dev) in (2u32..).zip(untagged_vaps.iter()) {
                lines.push(format!("bridge.1.port.{port_idx}.devname={dev}"));
            }
        }
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
                for (ath_dev, ath_vid) in &ath_to_vlan {
                    if *ath_vid == Some(vid) {
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

    // ebtables — broadcast/multicast storm protection per VAP
    lines.push("ebtables.status=enabled".into());
    lines.push("ebtables.add_vlan.status=disabled".into());
    {
        let mut eb_idx = 1u32;
        // Generate ebtables rules for all active VAPs
        let active_vaps: Vec<&String> = ath_to_vlan.iter().map(|(dev, _)| dev).collect();
        if active_vaps.is_empty() {
            // No WLANs — still protect primary VAPs
            for iface in &["ath0", "ath10"] {
                lines.push(format!(
                    "ebtables.{eb_idx}.cmd=-t nat -A PREROUTING --in-interface {iface} -d BGA -j DROP"
                ));
                eb_idx += 1;
                lines.push(format!(
                    "ebtables.{eb_idx}.cmd=-t nat -A POSTROUTING --out-interface {iface} -d BGA -j DROP"
                ));
                eb_idx += 1;
            }
        } else {
            for iface in &active_vaps {
                lines.push(format!(
                    "ebtables.{eb_idx}.cmd=-t nat -A PREROUTING --in-interface {iface} -d BGA -j DROP"
                ));
                eb_idx += 1;
                lines.push(format!(
                    "ebtables.{eb_idx}.cmd=-t nat -A POSTROUTING --out-interface {iface} -d BGA -j DROP"
                ));
                eb_idx += 1;
            }
        }
    }

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
        assert!(result.contains("radio.2.devname=ath10"));
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
            channel: 0,
            tx_power: 0,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Auto,
            fast_roaming: false,
            band_steering: false,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // Should have aaa + wireless entries for both radios (idx 1 = 2.4GHz ath0, idx 2 = 5GHz ath10)
        assert!(result.contains("aaa.1.ssid=MyNetwork"));
        assert!(result.contains("aaa.1.devname=ath0"));
        assert!(result.contains("aaa.1.wpa.psk=testpass123"));
        assert!(result.contains("aaa.1.wpa.key.1.mgmt=WPA-PSK"));
        assert!(result.contains("wireless.1.ssid=MyNetwork"));
        assert!(result.contains("wireless.1.parent=wifi0"));

        assert!(result.contains("aaa.2.ssid=MyNetwork"));
        assert!(result.contains("aaa.2.devname=ath10"));
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
            channel: 0,
            tx_power: 0,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Auto,
            fast_roaming: false,
            band_steering: false,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // 5GHz only — should be idx 1 on ath10 (primary 5GHz VAP)
        assert!(result.contains("aaa.1.devname=ath10"));
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
            channel: 0,
            tx_power: 0,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Auto,
            fast_roaming: false,
            band_steering: false,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // Bridge device should be br0.10 for VLAN-tagged WLAN
        assert!(result.contains("aaa.1.br.devname=br0.10"));
        assert!(result.contains("aaa.2.br.devname=br0.10"));

        // VLAN section — devname is the PARENT device (eth0), id is the VLAN ID
        assert!(result.contains("vlan.status=enabled"));
        assert!(result.contains("vlan.1.devname=eth0"));
        assert!(result.contains("vlan.1.id=10"));

        // VLAN bridge with uplink + wifi interfaces (multi-VAP names)
        assert!(result.contains("bridge.2.devname=br0.10"));
        assert!(result.contains("bridge.2.port.1.devname=eth0.10"));
        assert!(result.contains("bridge.2.port.2.devname=ath0"));
        assert!(result.contains("bridge.2.port.3.devname=ath10"));

        // wifi interfaces should NOT be in br0 when all WLANs are VLAN-tagged
        assert!(!result.contains("bridge.1.port.2.devname=ath0"));
        assert!(!result.contains("bridge.1.port.3.devname=ath10"));
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

    #[test]
    fn ap_system_cfg_custom_channel_and_txpower() {
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![WirelessNetworkCfg {
            ssid: "AdvNet".into(),
            security: "wpa2".into(),
            psk: Some("testpass123".into()),
            hidden: false,
            is_guest: false,
            l2_isolation: false,
            band: "both".into(),
            vlan_id: None,
            channel: 6,
            tx_power: 20,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Ht40,
            fast_roaming: false,
            band_steering: false,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // Radio-level channel and TX power
        assert!(result.contains("radio.1.channel=6"));
        assert!(result.contains("radio.1.txpower=20"));
        assert!(result.contains("radio.1.txpower_mode=custom"));
        assert!(result.contains("radio.1.ieee_mode=11nght40"));

        // Same network on 5GHz radio
        assert!(result.contains("radio.2.channel=6")); // same channel applied to both
        assert!(result.contains("radio.2.txpower=20"));
        assert!(result.contains("radio.2.ieee_mode=11naht40"));

        // Per-WLAN entries
        assert!(result.contains("wireless.1.channel=6"));
        assert!(result.contains("wireless.1.txpower=20"));
        assert!(result.contains("wireless.1.htmode=11nght40"));
        assert!(result.contains("wireless.2.channel=6"));
        assert!(result.contains("wireless.2.txpower=20"));
        assert!(result.contains("wireless.2.htmode=11naht40"));
    }

    #[test]
    fn ap_system_cfg_fast_roaming() {
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![WirelessNetworkCfg {
            ssid: "RoamNet".into(),
            security: "wpa2".into(),
            psk: Some("testpass123".into()),
            hidden: false,
            is_guest: false,
            l2_isolation: false,
            band: "5g".into(),
            vlan_id: None,
            channel: 0,
            tx_power: 0,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Auto,
            fast_roaming: true,
            band_steering: false,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        assert!(result.contains("aaa.1.ft.status=enabled"));
        assert!(result.contains("aaa.1.ft_over_ds=1"));
        assert!(result.contains("aaa.1.ft_key_method=1"));
        assert!(result.contains("aaa.1.ft_mdid="));
    }

    #[test]
    fn ap_system_cfg_band_steering() {
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![WirelessNetworkCfg {
            ssid: "SteerNet".into(),
            security: "wpa2".into(),
            psk: Some("testpass123".into()),
            hidden: false,
            is_guest: false,
            l2_isolation: false,
            band: "both".into(),
            vlan_id: None,
            channel: 0,
            tx_power: 0,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Auto,
            fast_roaming: false,
            band_steering: true,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        // Band steering on both radio entries
        assert!(result.contains("wireless.1.band_steering=prefer_5g"));
        assert!(result.contains("wireless.2.band_steering=prefer_5g"));
    }

    #[test]
    fn ap_system_cfg_vht80() {
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![WirelessNetworkCfg {
            ssid: "FastNet".into(),
            security: "wpa2".into(),
            psk: Some("testpass123".into()),
            hidden: false,
            is_guest: false,
            l2_isolation: false,
            band: "5g".into(),
            vlan_id: None,
            channel: 36,
            tx_power: 0,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Vht80,
            fast_roaming: false,
            band_steering: false,
        }];
        let result = generate_system_cfg(&cfg).unwrap();

        assert!(result.contains("radio.2.ieee_mode=11acvht80"));
        assert!(result.contains("radio.2.channel=36"));
        assert!(result.contains("wireless.1.htmode=11acvht80"));
        assert!(result.contains("wireless.1.channel=36"));
    }

    /// Helper to build a test WirelessNetworkCfg.
    fn test_wlan(ssid: &str, band: &str, vlan_id: Option<u16>) -> WirelessNetworkCfg {
        WirelessNetworkCfg {
            ssid: ssid.into(),
            security: "wpa2".into(),
            psk: Some("testpass123".into()),
            hidden: false,
            is_guest: false,
            l2_isolation: false,
            band: band.into(),
            vlan_id,
            channel: 0,
            tx_power: 0,
            bandwidth: sfgw_net::wireless::WirelessBandwidth::Auto,
            fast_roaming: false,
            band_steering: false,
        }
    }

    #[test]
    fn vap_devname_2g() {
        assert_eq!(vap_devname(false, 0), "ath0");
        assert_eq!(vap_devname(false, 1), "ath1");
        assert_eq!(vap_devname(false, 2), "ath2");
        assert_eq!(vap_devname(false, 3), "ath3");
    }

    #[test]
    fn vap_devname_5g() {
        assert_eq!(vap_devname(true, 0), "ath10");
        assert_eq!(vap_devname(true, 1), "ath11");
        assert_eq!(vap_devname(true, 2), "ath12");
        assert_eq!(vap_devname(true, 3), "ath13");
    }

    #[test]
    fn multi_ssid_both_band_vap_assignment() {
        // Two SSIDs, both on "both" bands — should get ath0+ath10 and ath1+ath11
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![
            test_wlan("Home", "both", None),
            test_wlan("Guest", "both", Some(3002)),
        ];
        let result = generate_system_cfg(&cfg).unwrap();

        // First SSID: ath0 (2.4GHz), ath10 (5GHz)
        assert!(result.contains("aaa.1.ssid=Home"));
        assert!(result.contains("aaa.1.devname=ath0"));
        assert!(result.contains("wireless.1.parent=wifi0"));
        assert!(result.contains("aaa.2.ssid=Home"));
        assert!(result.contains("aaa.2.devname=ath10"));
        assert!(result.contains("wireless.2.parent=wifi1"));

        // Second SSID: ath1 (2.4GHz), ath11 (5GHz)
        assert!(result.contains("aaa.3.ssid=Guest"));
        assert!(result.contains("aaa.3.devname=ath1"));
        assert!(result.contains("wireless.3.parent=wifi0"));
        assert!(result.contains("aaa.4.ssid=Guest"));
        assert!(result.contains("aaa.4.devname=ath11"));
        assert!(result.contains("wireless.4.parent=wifi1"));
    }

    #[test]
    fn multi_ssid_mixed_bands() {
        // One on 2g only, one on 5g only, one on both
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![
            test_wlan("IoT", "2g", Some(100)),
            test_wlan("Fast", "5g", None),
            test_wlan("Main", "both", None),
        ];
        let result = generate_system_cfg(&cfg).unwrap();

        // IoT: 2.4GHz only → ath0
        assert!(result.contains("aaa.1.ssid=IoT"));
        assert!(result.contains("aaa.1.devname=ath0"));

        // Fast: 5GHz only → ath10
        assert!(result.contains("aaa.2.ssid=Fast"));
        assert!(result.contains("aaa.2.devname=ath10"));

        // Main: both → ath1 (2nd 2.4GHz VAP), ath11 (2nd 5GHz VAP)
        assert!(result.contains("aaa.3.ssid=Main"));
        assert!(result.contains("aaa.3.devname=ath1"));
        assert!(result.contains("aaa.4.ssid=Main"));
        assert!(result.contains("aaa.4.devname=ath11"));
    }

    #[test]
    fn multi_ssid_bridge_untagged() {
        // Two untagged SSIDs on both bands — all 4 VAPs should be in br0
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![
            test_wlan("Net1", "both", None),
            test_wlan("Net2", "both", None),
        ];
        let result = generate_system_cfg(&cfg).unwrap();

        // br0 should have eth0 + all 4 untagged VAPs
        assert!(result.contains("bridge.1.port.1.devname=eth0"));
        assert!(result.contains("bridge.1.port.2.devname=ath0"));
        assert!(result.contains("bridge.1.port.3.devname=ath10"));
        assert!(result.contains("bridge.1.port.4.devname=ath1"));
        assert!(result.contains("bridge.1.port.5.devname=ath11"));
    }

    #[test]
    fn multi_ssid_bridge_mixed_vlan() {
        // One untagged, one VLAN-tagged — untagged in br0, tagged in br0.{vid}
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![
            test_wlan("Main", "both", None),
            test_wlan("Guest", "both", Some(3002)),
        ];
        let result = generate_system_cfg(&cfg).unwrap();

        // Untagged (Main) VAPs in br0
        assert!(result.contains("bridge.1.port.2.devname=ath0"));
        assert!(result.contains("bridge.1.port.3.devname=ath10"));

        // VLAN bridge for Guest
        assert!(result.contains("bridge.2.devname=br0.3002"));
        assert!(result.contains("bridge.2.port.1.devname=eth0.3002"));
        assert!(result.contains("bridge.2.port.2.devname=ath1"));
        assert!(result.contains("bridge.2.port.3.devname=ath11"));
    }

    #[test]
    fn multi_ssid_ebtables() {
        // Two SSIDs on both bands — ebtables should cover all 4 VAPs
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![
            test_wlan("Net1", "both", None),
            test_wlan("Net2", "both", None),
        ];
        let result = generate_system_cfg(&cfg).unwrap();

        // ebtables rules for ath0, ath10, ath1, ath11
        assert!(
            result
                .contains("ebtables.1.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP")
        );
        assert!(
            result.contains(
                "ebtables.2.cmd=-t nat -A POSTROUTING --out-interface ath0 -d BGA -j DROP"
            )
        );
        assert!(
            result.contains(
                "ebtables.3.cmd=-t nat -A PREROUTING --in-interface ath10 -d BGA -j DROP"
            )
        );
        assert!(
            result.contains(
                "ebtables.4.cmd=-t nat -A POSTROUTING --out-interface ath10 -d BGA -j DROP"
            )
        );
        assert!(
            result
                .contains("ebtables.5.cmd=-t nat -A PREROUTING --in-interface ath1 -d BGA -j DROP")
        );
        assert!(
            result.contains(
                "ebtables.6.cmd=-t nat -A POSTROUTING --out-interface ath1 -d BGA -j DROP"
            )
        );
        assert!(
            result.contains(
                "ebtables.7.cmd=-t nat -A PREROUTING --in-interface ath11 -d BGA -j DROP"
            )
        );
        assert!(
            result.contains(
                "ebtables.8.cmd=-t nat -A POSTROUTING --out-interface ath11 -d BGA -j DROP"
            )
        );
    }

    #[test]
    fn multi_ssid_netconf_vlan_bridges() {
        // Multiple SSIDs with different VLANs
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = vec![
            test_wlan("LAN", "both", Some(10)),
            test_wlan("Guest", "both", Some(3002)),
        ];
        let result = generate_system_cfg(&cfg).unwrap();

        // netconf entries for both VLAN bridges
        assert!(result.contains("netconf.3.devname=br0.10"));
        assert!(result.contains("netconf.4.devname=eth0.10"));
        assert!(result.contains("netconf.5.devname=br0.3002"));
        assert!(result.contains("netconf.6.devname=eth0.3002"));
    }

    #[test]
    fn vap_limit_validation() {
        // 4 networks on "both" = 4 per radio — should be OK
        let nets: Vec<WirelessNetworkCfg> = (0..4)
            .map(|i| test_wlan(&format!("Net{i}"), "both", None))
            .collect();
        assert!(validate_vap_limits(&nets).is_ok());

        // 5 networks on "both" = 5 per radio — should fail
        let nets: Vec<WirelessNetworkCfg> = (0..5)
            .map(|i| test_wlan(&format!("Net{i}"), "both", None))
            .collect();
        assert!(validate_vap_limits(&nets).is_err());

        // 4 on 2g + 4 on 5g = OK (different radios)
        let mut nets: Vec<WirelessNetworkCfg> = (0..4)
            .map(|i| test_wlan(&format!("Net2g{i}"), "2g", None))
            .collect();
        nets.extend((0..4).map(|i| test_wlan(&format!("Net5g{i}"), "5g", None)));
        assert!(validate_vap_limits(&nets).is_ok());

        // 5 on 2g only — should fail
        let nets: Vec<WirelessNetworkCfg> = (0..5)
            .map(|i| test_wlan(&format!("Net{i}"), "2g", None))
            .collect();
        let err = validate_vap_limits(&nets).unwrap_err();
        assert!(
            err.contains("2.4 GHz"),
            "error should mention 2.4 GHz: {err}"
        );
    }

    #[test]
    fn vap_count_per_radio() {
        let nets = vec![
            test_wlan("A", "both", None),
            test_wlan("B", "2g", None),
            test_wlan("C", "5g", None),
        ];
        let (c2g, c5g) = count_vaps_per_radio(&nets);
        assert_eq!(c2g, 2); // A + B
        assert_eq!(c5g, 2); // A + C
    }

    #[test]
    fn compute_vap_assignments_basic() {
        let nets = vec![
            test_wlan("Home", "both", None),
            test_wlan("IoT", "2g", None),
            test_wlan("Fast", "5g", None),
        ];
        let assignments = compute_vap_assignments(&nets);
        assert_eq!(assignments.len(), 3);

        // Home: ath0 + ath10
        assert_eq!(assignments[0].vap_2g.as_deref(), Some("ath0"));
        assert_eq!(assignments[0].vap_5g.as_deref(), Some("ath10"));

        // IoT: ath1 (2.4 only)
        assert_eq!(assignments[1].vap_2g.as_deref(), Some("ath1"));
        assert_eq!(assignments[1].vap_5g, None);

        // Fast: ath11 (5 only)
        assert_eq!(assignments[2].vap_2g, None);
        assert_eq!(assignments[2].vap_5g.as_deref(), Some("ath11"));
    }

    #[test]
    fn four_ssids_both_band_max_vaps() {
        // Maximum: 4 SSIDs on both bands = ath0..ath3 + ath10..ath13
        let mut cfg = test_ap_cfg();
        cfg.wireless_networks = (0..4)
            .map(|i| test_wlan(&format!("Net{i}"), "both", None))
            .collect();
        let result = generate_system_cfg(&cfg).unwrap();

        // Verify all 8 VAPs are created (4 per radio)
        for i in 0..4 {
            let ssid = format!("Net{i}");
            let ath_2g = format!("ath{i}");
            let ath_5g = format!("ath1{i}");
            assert!(
                result.contains(&format!("devname={ath_2g}")),
                "missing 2.4GHz VAP {ath_2g} for {ssid}"
            );
            assert!(
                result.contains(&format!("devname={ath_5g}")),
                "missing 5GHz VAP {ath_5g} for {ssid}"
            );
        }

        // aaa/wireless indices should be 1..8
        assert!(result.contains("aaa.8.ssid=Net3"));
        assert!(!result.contains("aaa.9."));
    }
}
