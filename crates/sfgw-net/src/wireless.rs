// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wireless network (SSID) configuration — CRUD for the `wireless_networks` table.
//!
//! Each wireless network defines an SSID that gets pushed to adopted APs
//! via the Inform protocol's `system_cfg` (as `aaa.*` + `wireless.*` entries).

use crate::Result;
use serde::{Deserialize, Serialize};

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
}

fn default_band() -> WirelessBand {
    WirelessBand::Both
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

    Ok(())
}

/// List all wireless networks. PSK is **not** included.
pub async fn list(db: &sfgw_db::Db) -> Result<Vec<WirelessNetwork>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT id, ssid, security, hidden, band, vlan_id, is_guest, l2_isolation, enabled
         FROM wireless_networks ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
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
        "SELECT id, ssid, security, hidden, band, vlan_id, is_guest, l2_isolation, enabled
         FROM wireless_networks WHERE id = ?1",
    )?;
    let result = stmt.query_row(rusqlite::params![id], |row| {
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
        "SELECT id, ssid, security, psk, hidden, band, vlan_id, is_guest, l2_isolation
         FROM wireless_networks WHERE enabled = 1 ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
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
        })
    })?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Create a new wireless network. Returns the new row ID.
pub async fn create(db: &sfgw_db::Db, net: &WirelessNetwork) -> Result<i64> {
    validate(net).map_err(|e| crate::NetError::Internal(anyhow::anyhow!(e)))?;

    // WPA2/WPA3 must have a PSK on create
    if matches!(
        net.security,
        WirelessSecurity::Wpa2 | WirelessSecurity::Wpa3
    ) && net.psk.is_none()
    {
        return Err(crate::NetError::Internal(anyhow::anyhow!(
            "PSK required for WPA2/WPA3 networks"
        )));
    }

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO wireless_networks (ssid, security, psk, hidden, band, vlan_id, is_guest, l2_isolation, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Update an existing wireless network. If `psk` is `None`, the existing PSK is kept.
pub async fn update(db: &sfgw_db::Db, id: i64, net: &WirelessNetwork) -> Result<bool> {
    validate(net).map_err(|e| crate::NetError::Internal(anyhow::anyhow!(e)))?;

    let conn = db.lock().await;
    let rows = if let Some(ref psk) = net.psk {
        conn.execute(
            "UPDATE wireless_networks
             SET ssid = ?1, security = ?2, psk = ?3, hidden = ?4, band = ?5,
                 vlan_id = ?6, is_guest = ?7, l2_isolation = ?8, enabled = ?9,
                 updated_at = datetime('now')
             WHERE id = ?10",
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
                id,
            ],
        )?
    } else {
        conn.execute(
            "UPDATE wireless_networks
             SET ssid = ?1, security = ?2, hidden = ?3, band = ?4,
                 vlan_id = ?5, is_guest = ?6, l2_isolation = ?7, enabled = ?8,
                 updated_at = datetime('now')
             WHERE id = ?9",
            rusqlite::params![
                net.ssid,
                net.security.as_str(),
                net.hidden as i64,
                net.band.as_str(),
                net.vlan_id.map(|v| v as i64),
                net.is_guest as i64,
                net.l2_isolation as i64,
                net.enabled as i64,
                id,
            ],
        )?
    };
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
}
