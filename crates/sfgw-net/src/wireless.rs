// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wireless network (SSID) configuration — CRUD for the `wireless_networks` table.
//!
//! Each wireless network defines an SSID that gets pushed to adopted APs
//! via the Inform protocol's `system_cfg` (as `aaa.*` + `wireless.*` entries).

use crate::Result;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Wireless security mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WirelessSecurity {
    Open,
    Wpa2,
    Wpa3,
}

impl WirelessSecurity {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Wpa2 => "wpa2",
            Self::Wpa3 => "wpa3",
        }
    }

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s {
            "open" => Ok(Self::Open),
            "wpa2" => Ok(Self::Wpa2),
            "wpa3" => Ok(Self::Wpa3),
            other => Err(format!("unknown security type: {other}")),
        }
    }
}

/// Wireless band selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WirelessBand {
    Both,
    #[serde(rename = "2g")]
    TwoGhz,
    #[serde(rename = "5g")]
    FiveGhz,
}

impl WirelessBand {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::TwoGhz => "2g",
            Self::FiveGhz => "5g",
        }
    }

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s {
            "both" => Ok(Self::Both),
            "2g" => Ok(Self::TwoGhz),
            "5g" => Ok(Self::FiveGhz),
            other => Err(format!("unknown band: {other}")),
        }
    }
}

/// Wireless bandwidth / HT mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WirelessBandwidth {
    Auto,
    #[serde(rename = "HT20")]
    Ht20,
    #[serde(rename = "HT40")]
    Ht40,
    #[serde(rename = "VHT80")]
    Vht80,
}

impl std::str::FromStr for WirelessBandwidth {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "HT20" => Ok(Self::Ht20),
            "HT40" => Ok(Self::Ht40),
            "VHT80" => Ok(Self::Vht80),
            other => Err(format!("unknown bandwidth: {other}")),
        }
    }
}

impl WirelessBandwidth {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ht20 => "HT20",
            Self::Ht40 => "HT40",
            Self::Vht80 => "VHT80",
        }
    }

    /// Convert to UniFi ieee_mode string for system_cfg.
    pub fn to_ieee_mode(&self, is_5ghz: bool) -> &'static str {
        match self {
            Self::Auto => {
                if is_5ghz {
                    "11naht40"
                } else {
                    "11nght20"
                }
            }
            Self::Ht20 => {
                if is_5ghz {
                    "11naht20"
                } else {
                    "11nght20"
                }
            }
            Self::Ht40 => {
                if is_5ghz {
                    "11naht40"
                } else {
                    "11nght40"
                }
            }
            Self::Vht80 => {
                if is_5ghz {
                    "11acvht80"
                } else {
                    // VHT80 not valid for 2.4GHz, fall back to HT40
                    "11nght40"
                }
            }
        }
    }
}

/// Valid 2.4 GHz channels.
const CHANNELS_2G: &[u16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Valid 5 GHz channels (UNII-1, UNII-2, UNII-2e, UNII-3).
const CHANNELS_5G: &[u16] = &[
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
];

/// Maximum TX power in dBm.
const MAX_TX_POWER: u16 = 30;

/// Check if a channel number is valid for a given band.
pub fn is_valid_channel(channel: u16, band: &WirelessBand) -> bool {
    if channel == 0 {
        return true; // auto
    }
    match band {
        WirelessBand::Both => CHANNELS_2G.contains(&channel) || CHANNELS_5G.contains(&channel),
        WirelessBand::TwoGhz => CHANNELS_2G.contains(&channel),
        WirelessBand::FiveGhz => CHANNELS_5G.contains(&channel),
    }
}

/// A wireless network (SSID) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessNetwork {
    pub id: Option<i64>,
    pub ssid: String,
    pub security: WirelessSecurity,
    /// PSK — included in create/update requests, never returned in GET responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default = "default_band")]
    pub band: WirelessBand,
    #[serde(default)]
    pub vlan_id: Option<u16>,
    #[serde(default)]
    pub is_guest: bool,
    #[serde(default)]
    pub l2_isolation: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Radio channel (0 = auto).
    #[serde(default)]
    pub channel: u16,
    /// TX power in dBm (0 = auto).
    #[serde(default)]
    pub tx_power: u16,
    /// Bandwidth / HT mode.
    #[serde(default = "default_bandwidth")]
    pub bandwidth: WirelessBandwidth,
    /// 802.11r fast roaming.
    #[serde(default)]
    pub fast_roaming: bool,
    /// Band steering (prefer 5 GHz).
    #[serde(default)]
    pub band_steering: bool,
}

fn default_band() -> WirelessBand {
    WirelessBand::Both
}

fn default_bandwidth() -> WirelessBandwidth {
    WirelessBandwidth::Auto
}

fn default_true() -> bool {
    true
}

/// Validate a wireless network before storing.
pub fn validate(net: &WirelessNetwork) -> std::result::Result<(), String> {
    // SSID: 1-32 bytes
    if net.ssid.is_empty() || net.ssid.len() > 32 {
        return Err("SSID must be 1-32 characters".into());
    }

    // PSK requirements
    match net.security {
        WirelessSecurity::Wpa2 | WirelessSecurity::Wpa3 => {
            if let Some(ref psk) = net.psk
                && (psk.len() < 8 || psk.len() > 63)
            {
                return Err("PSK must be 8-63 characters".into());
            }
            // PSK can be None on update (keep existing)
        }
        WirelessSecurity::Open => {
            if net.psk.is_some() {
                return Err("open networks must not have a PSK".into());
            }
        }
    }

    // VLAN range
    if let Some(vlan) = net.vlan_id
        && (vlan == 0 || vlan > 4094)
    {
        return Err("VLAN ID must be 1-4094".into());
    }

    // Channel validation
    if net.channel != 0 && !is_valid_channel(net.channel, &net.band) {
        return Err(format!(
            "channel {} is not valid for band {:?}",
            net.channel, net.band
        ));
    }

    // TX power: 0 (auto) or 1-30 dBm
    if net.tx_power > MAX_TX_POWER {
        return Err(format!("TX power must be 0 (auto) or 1-{MAX_TX_POWER} dBm"));
    }

    // VHT80 is not valid for 2.4 GHz only band
    if net.bandwidth == WirelessBandwidth::Vht80 && net.band == WirelessBand::TwoGhz {
        return Err("VHT80 is not supported on 2.4 GHz".into());
    }

    // Band steering requires dual-band
    if net.band_steering && net.band != WirelessBand::Both {
        return Err("band steering requires dual-band (both) mode".into());
    }

    Ok(())
}

/// Maximum number of VAPs (Virtual Access Points) per radio.
///
/// UAP-AC-Pro supports up to 4 VAPs per radio. This matches
/// `sfgw_inform::system_cfg::MAX_VAPS_PER_RADIO`.
pub const MAX_VAPS_PER_RADIO: usize = 4;

/// Maximum total wireless networks (4 per radio x 2 radios).
///
/// In practice this is only reachable if all networks are single-band.
/// With "both" band networks, the limit is 4 total.
pub const MAX_TOTAL_NETWORKS: usize = 8;

/// Count how many VAPs would be used per radio for a set of networks.
///
/// Returns `(count_2g, count_5g)`.
pub fn count_vaps_per_radio(networks: &[WirelessNetwork]) -> (usize, usize) {
    let mut count_2g: usize = 0;
    let mut count_5g: usize = 0;

    for net in networks {
        match net.band {
            WirelessBand::Both => {
                count_2g += 1;
                count_5g += 1;
            }
            WirelessBand::TwoGhz => count_2g += 1,
            WirelessBand::FiveGhz => count_5g += 1,
        }
    }

    (count_2g, count_5g)
}

/// Validate that adding a new network (with the given band) would not exceed
/// the per-radio VAP limit, given the existing networks.
///
/// `existing` should be the current list of enabled wireless networks.
/// `new_band` is the band of the network being added.
/// `exclude_id` is an optional network ID to exclude from counting (for updates).
pub fn validate_vap_limit(
    existing: &[WirelessNetwork],
    new_band: &WirelessBand,
    exclude_id: Option<i64>,
) -> std::result::Result<(), String> {
    let mut count_2g: usize = 0;
    let mut count_5g: usize = 0;

    for net in existing {
        // Skip the network being updated
        if let Some(eid) = exclude_id
            && net.id == Some(eid)
        {
            continue;
        }
        match net.band {
            WirelessBand::Both => {
                count_2g += 1;
                count_5g += 1;
            }
            WirelessBand::TwoGhz => count_2g += 1,
            WirelessBand::FiveGhz => count_5g += 1,
        }
    }

    // Add the new network
    match new_band {
        WirelessBand::Both => {
            count_2g += 1;
            count_5g += 1;
        }
        WirelessBand::TwoGhz => count_2g += 1,
        WirelessBand::FiveGhz => count_5g += 1,
    }

    if count_2g > MAX_VAPS_PER_RADIO {
        return Err(format!(
            "too many networks on 2.4 GHz radio: {count_2g} (max {MAX_VAPS_PER_RADIO}). \
             Each network on '2g' or 'both' band uses one VAP slot on the 2.4 GHz radio."
        ));
    }
    if count_5g > MAX_VAPS_PER_RADIO {
        return Err(format!(
            "too many networks on 5 GHz radio: {count_5g} (max {MAX_VAPS_PER_RADIO}). \
             Each network on '5g' or 'both' band uses one VAP slot on the 5 GHz radio."
        ));
    }

    Ok(())
}

/// Parse advanced wireless fields from a DB row starting at the given column offset.
fn parse_advanced_fields(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<(u16, u16, WirelessBandwidth, bool, bool)> {
    let channel = row.get::<_, i64>(offset)? as u16;
    let tx_power = row.get::<_, i64>(offset + 1)? as u16;
    let bandwidth = row
        .get::<_, String>(offset + 2)?
        .parse::<WirelessBandwidth>()
        .unwrap_or(WirelessBandwidth::Auto);
    let fast_roaming = row.get::<_, i64>(offset + 3)? != 0;
    let band_steering = row.get::<_, i64>(offset + 4)? != 0;
    Ok((channel, tx_power, bandwidth, fast_roaming, band_steering))
}

/// List all wireless networks. PSK is **not** included.
pub async fn list(db: &sfgw_db::Db) -> Result<Vec<WirelessNetwork>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT id, ssid, security, hidden, band, vlan_id, is_guest, l2_isolation, enabled,
                channel, tx_power, bandwidth, fast_roaming, band_steering
         FROM wireless_networks ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        let (channel, tx_power, bandwidth, fast_roaming, band_steering) =
            parse_advanced_fields(row, 9)?;
        Ok(WirelessNetwork {
            id: Some(row.get(0)?),
            ssid: row.get(1)?,
            security: WirelessSecurity::from_str(&row.get::<_, String>(2)?)
                .unwrap_or(WirelessSecurity::Wpa2),
            psk: None,
            hidden: row.get::<_, i64>(3)? != 0,
            band: WirelessBand::from_str(&row.get::<_, String>(4)?).unwrap_or(WirelessBand::Both),
            vlan_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u16),
            is_guest: row.get::<_, i64>(6)? != 0,
            l2_isolation: row.get::<_, i64>(7)? != 0,
            enabled: row.get::<_, i64>(8)? != 0,
            channel,
            tx_power,
            bandwidth,
            fast_roaming,
            band_steering,
        })
    })?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Get a single wireless network by ID. PSK is **not** included.
pub async fn get(db: &sfgw_db::Db, id: i64) -> Result<Option<WirelessNetwork>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT id, ssid, security, hidden, band, vlan_id, is_guest, l2_isolation, enabled,
                channel, tx_power, bandwidth, fast_roaming, band_steering
         FROM wireless_networks WHERE id = ?1",
    )?;
    let result = stmt.query_row(rusqlite::params![id], |row| {
        let (channel, tx_power, bandwidth, fast_roaming, band_steering) =
            parse_advanced_fields(row, 9)?;
        Ok(WirelessNetwork {
            id: Some(row.get(0)?),
            ssid: row.get(1)?,
            security: WirelessSecurity::from_str(&row.get::<_, String>(2)?)
                .unwrap_or(WirelessSecurity::Wpa2),
            psk: None,
            hidden: row.get::<_, i64>(3)? != 0,
            band: WirelessBand::from_str(&row.get::<_, String>(4)?).unwrap_or(WirelessBand::Both),
            vlan_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u16),
            is_guest: row.get::<_, i64>(6)? != 0,
            l2_isolation: row.get::<_, i64>(7)? != 0,
            enabled: row.get::<_, i64>(8)? != 0,
            channel,
            tx_power,
            bandwidth,
            fast_roaming,
            band_steering,
        })
    });
    match result {
        Ok(net) => Ok(Some(net)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// List all enabled wireless networks **with PSK** — for system_cfg generation only.
pub async fn list_with_psk(db: &sfgw_db::Db) -> Result<Vec<WirelessNetwork>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT id, ssid, security, psk, hidden, band, vlan_id, is_guest, l2_isolation,
                channel, tx_power, bandwidth, fast_roaming, band_steering
         FROM wireless_networks WHERE enabled = 1 ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        let (channel, tx_power, bandwidth, fast_roaming, band_steering) =
            parse_advanced_fields(row, 9)?;
        Ok(WirelessNetwork {
            id: Some(row.get(0)?),
            ssid: row.get(1)?,
            security: WirelessSecurity::from_str(&row.get::<_, String>(2)?)
                .unwrap_or(WirelessSecurity::Wpa2),
            psk: row.get(3)?,
            hidden: row.get::<_, i64>(4)? != 0,
            band: WirelessBand::from_str(&row.get::<_, String>(5)?).unwrap_or(WirelessBand::Both),
            vlan_id: row.get::<_, Option<i64>>(6)?.map(|v| v as u16),
            is_guest: row.get::<_, i64>(7)? != 0,
            l2_isolation: row.get::<_, i64>(8)? != 0,
            enabled: true,
            channel,
            tx_power,
            bandwidth,
            fast_roaming,
            band_steering,
        })
    })?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Create a new wireless network. Returns the new row ID.
///
/// Validates VAP limits: max 4 networks per radio (2.4 GHz / 5 GHz).
pub async fn create(db: &sfgw_db::Db, net: &WirelessNetwork) -> Result<i64> {
    validate(net).map_err(crate::NetError::Validation)?;

    // WPA2/WPA3 must have a PSK on create
    if matches!(
        net.security,
        WirelessSecurity::Wpa2 | WirelessSecurity::Wpa3
    ) && net.psk.is_none()
    {
        return Err(crate::NetError::Validation(
            "PSK required for WPA2/WPA3 networks".into(),
        ));
    }

    // Check VAP limit before inserting
    let existing = list(db).await?;
    validate_vap_limit(&existing, &net.band, None).map_err(crate::NetError::Validation)?;

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO wireless_networks (ssid, security, psk, hidden, band, vlan_id, is_guest, l2_isolation, enabled,
                                        channel, tx_power, bandwidth, fast_roaming, band_steering)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        rusqlite::params![
            net.ssid,
            net.security.as_str(),
            net.psk,
            net.hidden as i64,
            net.band.as_str(),
            net.vlan_id.map(|v| v as i64),
            net.is_guest as i64,
            net.l2_isolation as i64,
            net.enabled as i64,
            net.channel as i64,
            net.tx_power as i64,
            net.bandwidth.as_str(),
            net.fast_roaming as i64,
            net.band_steering as i64,
        ],
    )?;
    debug!(ssid = %net.ssid, channel = net.channel, tx_power = net.tx_power,
           bandwidth = %net.bandwidth.as_str(), fast_roaming = net.fast_roaming,
           band_steering = net.band_steering, "created wireless network");
    Ok(conn.last_insert_rowid())
}

/// Update an existing wireless network. If `psk` is `None`, the existing PSK is kept.
///
/// Validates VAP limits when band changes.
pub async fn update(db: &sfgw_db::Db, id: i64, net: &WirelessNetwork) -> Result<bool> {
    validate(net).map_err(crate::NetError::Validation)?;

    // Check VAP limit (exclude self from count)
    let existing = list(db).await?;
    validate_vap_limit(&existing, &net.band, Some(id)).map_err(crate::NetError::Validation)?;

    let conn = db.lock().await;
    let rows = if let Some(ref psk) = net.psk {
        conn.execute(
            "UPDATE wireless_networks
             SET ssid = ?1, security = ?2, psk = ?3, hidden = ?4, band = ?5,
                 vlan_id = ?6, is_guest = ?7, l2_isolation = ?8, enabled = ?9,
                 channel = ?10, tx_power = ?11, bandwidth = ?12, fast_roaming = ?13,
                 band_steering = ?14, updated_at = datetime('now')
             WHERE id = ?15",
            rusqlite::params![
                net.ssid,
                net.security.as_str(),
                psk,
                net.hidden as i64,
                net.band.as_str(),
                net.vlan_id.map(|v| v as i64),
                net.is_guest as i64,
                net.l2_isolation as i64,
                net.enabled as i64,
                net.channel as i64,
                net.tx_power as i64,
                net.bandwidth.as_str(),
                net.fast_roaming as i64,
                net.band_steering as i64,
                id,
            ],
        )?
    } else {
        conn.execute(
            "UPDATE wireless_networks
             SET ssid = ?1, security = ?2, hidden = ?3, band = ?4,
                 vlan_id = ?5, is_guest = ?6, l2_isolation = ?7, enabled = ?8,
                 channel = ?9, tx_power = ?10, bandwidth = ?11, fast_roaming = ?12,
                 band_steering = ?13, updated_at = datetime('now')
             WHERE id = ?14",
            rusqlite::params![
                net.ssid,
                net.security.as_str(),
                net.hidden as i64,
                net.band.as_str(),
                net.vlan_id.map(|v| v as i64),
                net.is_guest as i64,
                net.l2_isolation as i64,
                net.enabled as i64,
                net.channel as i64,
                net.tx_power as i64,
                net.bandwidth.as_str(),
                net.fast_roaming as i64,
                net.band_steering as i64,
                id,
            ],
        )?
    };
    debug!(id, ssid = %net.ssid, channel = net.channel, tx_power = net.tx_power,
           bandwidth = %net.bandwidth.as_str(), "updated wireless network");
    Ok(rows > 0)
}

/// Delete a wireless network by ID. Returns true if a row was deleted.
pub async fn delete(db: &sfgw_db::Db, id: i64) -> Result<bool> {
    let conn = db.lock().await;
    let rows = conn.execute(
        "DELETE FROM wireless_networks WHERE id = ?1",
        rusqlite::params![id],
    )?;
    Ok(rows > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> sfgw_db::Db {
        sfgw_db::open_in_memory()
            .await
            .expect("open_in_memory should succeed")
    }

    fn wpa2_network() -> WirelessNetwork {
        WirelessNetwork {
            id: None,
            ssid: "TestNet".into(),
            security: WirelessSecurity::Wpa2,
            psk: Some("supersecret123".into()),
            hidden: false,
            band: WirelessBand::Both,
            vlan_id: None,
            is_guest: false,
            l2_isolation: false,
            enabled: true,
            channel: 0,
            tx_power: 0,
            bandwidth: WirelessBandwidth::Auto,
            fast_roaming: false,
            band_steering: false,
        }
    }

    #[test]
    fn validate_ssid_length() {
        let mut net = wpa2_network();
        net.ssid = String::new();
        assert!(validate(&net).is_err());

        net.ssid = "a".repeat(33);
        assert!(validate(&net).is_err());

        net.ssid = "a".repeat(32);
        assert!(validate(&net).is_ok());
    }

    #[test]
    fn validate_psk_length() {
        let mut net = wpa2_network();
        net.psk = Some("short".into());
        assert!(validate(&net).is_err());

        net.psk = Some("a".repeat(64));
        assert!(validate(&net).is_err());

        net.psk = Some("a".repeat(63));
        assert!(validate(&net).is_ok());
    }

    #[test]
    fn validate_open_no_psk() {
        let mut net = wpa2_network();
        net.security = WirelessSecurity::Open;
        net.psk = Some("should not be here".into());
        assert!(validate(&net).is_err());

        net.psk = None;
        assert!(validate(&net).is_ok());
    }

    #[test]
    fn validate_vlan_range() {
        let mut net = wpa2_network();
        net.vlan_id = Some(0);
        assert!(validate(&net).is_err());

        net.vlan_id = Some(4095);
        assert!(validate(&net).is_err());

        net.vlan_id = Some(100);
        assert!(validate(&net).is_ok());
    }

    #[tokio::test]
    async fn crud_wireless_network() {
        let db = test_db().await;

        // Create
        let id = create(&db, &wpa2_network())
            .await
            .expect("create should succeed");
        assert!(id > 0);

        // List (no PSK)
        let networks = list(&db).await.expect("list should succeed");
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].ssid, "TestNet");
        assert!(
            networks[0].psk.is_none(),
            "PSK must not be in list response"
        );

        // Get (no PSK)
        let net = get(&db, id)
            .await
            .expect("get should succeed")
            .expect("network should exist");
        assert_eq!(net.ssid, "TestNet");
        assert!(net.psk.is_none());

        // List with PSK (internal only)
        let with_psk = list_with_psk(&db)
            .await
            .expect("list_with_psk should succeed");
        assert_eq!(with_psk.len(), 1);
        assert_eq!(with_psk[0].psk.as_deref(), Some("supersecret123"));

        // Update (change SSID, keep PSK)
        let mut updated = wpa2_network();
        updated.ssid = "UpdatedNet".into();
        updated.psk = None; // keep existing
        let ok = update(&db, id, &updated)
            .await
            .expect("update should succeed");
        assert!(ok);

        let net = get(&db, id).await.unwrap().unwrap();
        assert_eq!(net.ssid, "UpdatedNet");

        // PSK should still be there
        let with_psk = list_with_psk(&db).await.unwrap();
        assert_eq!(with_psk[0].psk.as_deref(), Some("supersecret123"));

        // Update with new PSK
        updated.psk = Some("newpassword99".into());
        update(&db, id, &updated).await.unwrap();
        let with_psk = list_with_psk(&db).await.unwrap();
        assert_eq!(with_psk[0].psk.as_deref(), Some("newpassword99"));

        // Delete
        let deleted = delete(&db, id).await.expect("delete should succeed");
        assert!(deleted);

        let networks = list(&db).await.unwrap();
        assert!(networks.is_empty());
    }

    #[tokio::test]
    async fn create_requires_psk_for_wpa2() {
        let db = test_db().await;
        let mut net = wpa2_network();
        net.psk = None;
        let result = create(&db, &net).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn duplicate_ssid_rejected() {
        let db = test_db().await;
        create(&db, &wpa2_network()).await.unwrap();
        let result = create(&db, &wpa2_network()).await;
        assert!(
            result.is_err(),
            "duplicate SSID should be rejected by unique index"
        );
    }

    #[tokio::test]
    async fn list_with_psk_only_enabled() {
        let db = test_db().await;

        let mut net = wpa2_network();
        create(&db, &net).await.unwrap();

        net.ssid = "Disabled".into();
        net.enabled = false;
        create(&db, &net).await.unwrap();

        let with_psk = list_with_psk(&db).await.unwrap();
        assert_eq!(with_psk.len(), 1);
        assert_eq!(with_psk[0].ssid, "TestNet");
    }

    #[test]
    fn validate_channel_2g() {
        let mut net = wpa2_network();
        net.band = WirelessBand::TwoGhz;
        net.channel = 6;
        assert!(validate(&net).is_ok());

        net.channel = 36; // 5GHz channel on 2.4GHz band
        assert!(validate(&net).is_err());
    }

    #[test]
    fn validate_channel_5g() {
        let mut net = wpa2_network();
        net.band = WirelessBand::FiveGhz;
        net.channel = 36;
        assert!(validate(&net).is_ok());

        net.channel = 6; // 2.4GHz channel on 5GHz band
        assert!(validate(&net).is_err());
    }

    #[test]
    fn validate_channel_auto() {
        let mut net = wpa2_network();
        net.channel = 0;
        assert!(validate(&net).is_ok());
    }

    #[test]
    fn validate_tx_power_range() {
        let mut net = wpa2_network();
        net.tx_power = 0;
        assert!(validate(&net).is_ok());

        net.tx_power = 30;
        assert!(validate(&net).is_ok());

        net.tx_power = 31;
        assert!(validate(&net).is_err());
    }

    #[test]
    fn validate_vht80_not_on_2g() {
        let mut net = wpa2_network();
        net.band = WirelessBand::TwoGhz;
        net.bandwidth = WirelessBandwidth::Vht80;
        assert!(validate(&net).is_err());
    }

    #[test]
    fn validate_band_steering_requires_dual_band() {
        let mut net = wpa2_network();
        net.band_steering = true;
        net.band = WirelessBand::Both;
        assert!(validate(&net).is_ok());

        net.band = WirelessBand::FiveGhz;
        assert!(validate(&net).is_err());
    }

    #[tokio::test]
    async fn crud_advanced_fields() {
        let db = test_db().await;

        let mut net = wpa2_network();
        net.channel = 6;
        net.tx_power = 20;
        net.bandwidth = WirelessBandwidth::Ht40;
        net.fast_roaming = true;
        net.band_steering = true;

        let id = create(&db, &net)
            .await
            .expect("create with advanced fields");
        let got = get(&db, id).await.unwrap().unwrap();
        assert_eq!(got.channel, 6);
        assert_eq!(got.tx_power, 20);
        assert_eq!(got.bandwidth, WirelessBandwidth::Ht40);
        assert!(got.fast_roaming);
        assert!(got.band_steering);

        // Update advanced fields
        let mut updated = wpa2_network();
        updated.ssid = "TestNet".into();
        updated.channel = 36;
        updated.tx_power = 15;
        updated.bandwidth = WirelessBandwidth::Vht80;
        updated.fast_roaming = false;
        updated.band_steering = false;
        updated.psk = None;
        update(&db, id, &updated).await.unwrap();

        let got = get(&db, id).await.unwrap().unwrap();
        assert_eq!(got.channel, 36);
        assert_eq!(got.tx_power, 15);
        assert_eq!(got.bandwidth, WirelessBandwidth::Vht80);
        assert!(!got.fast_roaming);
        assert!(!got.band_steering);
    }

    #[test]
    fn validate_vap_limit_both_band() {
        // 4 networks on "both" = 4 per radio — adding a 5th should fail
        let existing: Vec<WirelessNetwork> = (0..4)
            .map(|i| WirelessNetwork {
                id: Some(i + 1),
                ssid: format!("Net{i}"),
                band: WirelessBand::Both,
                ..wpa2_network()
            })
            .collect();

        // Adding another "both" should fail on both radios
        assert!(validate_vap_limit(&existing, &WirelessBand::Both, None).is_err());
        // Adding 2g-only should also fail (2.4GHz radio full)
        assert!(validate_vap_limit(&existing, &WirelessBand::TwoGhz, None).is_err());
        // Adding 5g-only should also fail (5GHz radio full)
        assert!(validate_vap_limit(&existing, &WirelessBand::FiveGhz, None).is_err());
    }

    #[test]
    fn validate_vap_limit_single_band() {
        // 3 networks on "2g" only — adding a 4th on 2g OK, 5th not
        let existing: Vec<WirelessNetwork> = (0..3)
            .map(|i| WirelessNetwork {
                id: Some(i + 1),
                ssid: format!("Net2g{i}"),
                band: WirelessBand::TwoGhz,
                ..wpa2_network()
            })
            .collect();

        assert!(validate_vap_limit(&existing, &WirelessBand::TwoGhz, None).is_ok());
        // 5GHz is empty, so adding 5g-only is fine
        assert!(validate_vap_limit(&existing, &WirelessBand::FiveGhz, None).is_ok());
        // "both" would put 4th on 2.4GHz — still OK
        assert!(validate_vap_limit(&existing, &WirelessBand::Both, None).is_ok());
    }

    #[test]
    fn validate_vap_limit_update_excludes_self() {
        // 4 networks on "both" — updating one (changing band) should be OK
        let existing: Vec<WirelessNetwork> = (0..4)
            .map(|i| WirelessNetwork {
                id: Some(i + 1),
                ssid: format!("Net{i}"),
                band: WirelessBand::Both,
                ..wpa2_network()
            })
            .collect();

        // Updating network ID 2 to stay "both" — should pass (self excluded)
        assert!(validate_vap_limit(&existing, &WirelessBand::Both, Some(2)).is_ok());
    }

    #[test]
    fn count_vaps_mixed_bands() {
        let nets = vec![
            WirelessNetwork {
                band: WirelessBand::Both,
                ..wpa2_network()
            },
            WirelessNetwork {
                ssid: "A".into(),
                band: WirelessBand::TwoGhz,
                ..wpa2_network()
            },
            WirelessNetwork {
                ssid: "B".into(),
                band: WirelessBand::FiveGhz,
                ..wpa2_network()
            },
        ];
        let (c2g, c5g) = count_vaps_per_radio(&nets);
        assert_eq!(c2g, 2); // Both + TwoGhz
        assert_eq!(c5g, 2); // Both + FiveGhz
    }

    #[tokio::test]
    async fn create_rejects_exceeding_vap_limit() {
        let db = test_db().await;

        // Create 4 networks on "both" band
        for i in 0..4 {
            let mut net = wpa2_network();
            net.ssid = format!("Net{i}");
            create(&db, &net).await.expect("create should succeed");
        }

        // 5th should fail
        let mut net = wpa2_network();
        net.ssid = "TooMany".into();
        let result = create(&db, &net).await;
        assert!(
            result.is_err(),
            "5th network on both bands should be rejected"
        );
    }

    #[test]
    fn bandwidth_ieee_mode() {
        assert_eq!(WirelessBandwidth::Auto.to_ieee_mode(false), "11nght20");
        assert_eq!(WirelessBandwidth::Auto.to_ieee_mode(true), "11naht40");
        assert_eq!(WirelessBandwidth::Ht20.to_ieee_mode(false), "11nght20");
        assert_eq!(WirelessBandwidth::Ht20.to_ieee_mode(true), "11naht20");
        assert_eq!(WirelessBandwidth::Ht40.to_ieee_mode(false), "11nght40");
        assert_eq!(WirelessBandwidth::Ht40.to_ieee_mode(true), "11naht40");
        assert_eq!(WirelessBandwidth::Vht80.to_ieee_mode(true), "11acvht80");
        // VHT80 falls back to HT40 on 2.4GHz
        assert_eq!(WirelessBandwidth::Vht80.to_ieee_mode(false), "11nght40");
    }
}
