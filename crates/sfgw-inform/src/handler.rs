// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP handler for Ubiquiti Inform on port 8080.
//!
//! Accepts POST /inform with binary TNBU-encoded body.
//! Decrypts, validates, processes, and returns encrypted TNBU response.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::codec;
use crate::crypto;
use crate::packet::{self, PacketFlags, TnbuPacket};
use crate::payload::{self, InformPayload, InformResponse};
use crate::rate::RateLimiter;
use crate::state::{UbntDevice, UbntDeviceState, ValidationResult};
use crate::system_cfg;

/// Shared state for the Inform handler.
pub struct InformState {
    pub db: sfgw_db::Db,
    /// In-memory device registry (persisted to DB on state changes).
    pub devices: Mutex<std::collections::HashMap<String, UbntDevice>>,
    /// Rate limiter per source IP.
    pub rate_limiter: RateLimiter,
}

/// Handle an incoming Inform POST request.
///
/// This is the main entry point wired to `POST /inform`.
pub async fn handle_inform(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<InformState>>,
    body: Bytes,
) -> impl IntoResponse {
    let source_ip = addr.ip().to_string();

    // Rate limiting (Stufe 1: before any parsing)
    match state.rate_limiter.check(&source_ip) {
        crate::rate::RateResult::Ok => {}
        crate::rate::RateResult::SoftLimit => {
            warn!(
                source_ip = %source_ip,
                "inform rate limit exceeded (soft) — dropping"
            );
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        crate::rate::RateResult::HardLimit { distinct_macs } => {
            warn!(
                source_ip = %source_ip,
                distinct_macs,
                "inform rate limit exceeded (hard) — IDS event"
            );
            // Log IDS event
            if let Err(e) = sfgw_ids::log_event(
                &state.db,
                "critical",
                "inform_flood",
                None,
                Some(&source_ip),
                None,
                None,
                &format!(
                    "Inform flood from {source_ip}: {distinct_macs} distinct MACs, rate limit exceeded"
                ),
            )
            .await
            {
                warn!(error = %e, "failed to log IDS event for inform flood");
            }
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }

    // Parse TNBU packet
    let pkt = match packet::parse(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!(source_ip = %source_ip, error = %e, body_len = body.len(), first_bytes = ?&body[..body.len().min(48)], "invalid TNBU packet");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let mac_str = pkt.mac_str();
    state.rate_limiter.record_mac(&source_ip, &mac_str);

    // Refresh device from DB BEFORE decryption so resolve_key picks up the authkey.
    // Check Adopting AND Pending — adoption transitions Pending→Adopting→Adopted in DB
    // while in-memory may still be Pending from the last inform cycle.
    {
        let mut devices = state.devices.lock().await;
        if let Some(dev) = devices.get(&mac_str)
            && matches!(
                dev.state,
                UbntDeviceState::Adopting | UbntDeviceState::Pending
            )
            && let Ok(fresh) = reload_device_from_db(&state.db, &mac_str).await
        {
            devices.insert(mac_str.clone(), fresh);
        }
    }

    // Decrypt payload — returns the data AND the key that worked (for response encryption)
    let (json_bytes, decrypt_key) = match decrypt_inform(&pkt, &state, &mac_str).await {
        Ok(result) => result,
        Err(e) => {
            // Dump enough info to reproduce the failure in a test
            let header_hex: String = body[..body.len().min(40)]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            warn!(
                source_ip = %source_ip,
                mac = %mac_str,
                flags = ?pkt.flags,
                payload_len = pkt.payload.len(),
                header_hex = %header_hex,
                error = %e,
                "inform decryption failed"
            );
            // At debug level, dump the full packet for offline analysis
            if tracing::enabled!(tracing::Level::DEBUG) {
                let full_hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
                debug!(mac = %mac_str, packet_hex = %full_hex, "full packet dump for decrypt failure");
            }
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Parse JSON
    let inform: InformPayload = match serde_json::from_slice(&json_bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                source_ip = %source_ip,
                mac = %mac_str,
                error = %e,
                "invalid inform JSON"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    info!(
        source_ip = %source_ip,
        mac = %mac_str,
        model = %inform.model,
        hostname = %inform.hostname,
        version = %inform.version,
        default = inform.default,
        "inform received"
    );

    // Process the inform and generate response
    let response = match process_inform(&state, &source_ip, &mac_str, &pkt, &inform).await {
        Ok(resp) => resp,
        Err(e) if e.to_string() == "__pending_401__" => {
            // Pending device: return 401 so mcad stays in factory-default state
            debug!(mac = %mac_str, "pending device — returning 401 to preserve factory default");
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Err(e) => {
            warn!(
                source_ip = %source_ip,
                mac = %mac_str,
                error = %e,
                "inform processing error"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Encrypt response
    let response_json = match serde_json::to_vec(&response) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "failed to serialize inform response");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Use the SAME key that successfully decrypted the request
    let response_pkt = build_response_packet(&pkt, &response_json, &decrypt_key);

    match response_pkt {
        Ok(bytes) => (
            StatusCode::OK,
            [("Content-Type", "application/x-binary")],
            bytes,
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "failed to build inform response packet");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Decrypt an inform packet (CBC for unadopted, GCM for adopted).
///
/// Tries the device's authkey first (if adopted), then falls back to the default key.
/// This handles the transition period where a device has just received its authkey
/// but the in-memory state hasn't been updated yet, or vice versa.
/// Returns (decrypted_data, key_used) so the response can be encrypted with the same key.
async fn decrypt_inform(
    pkt: &TnbuPacket,
    state: &Arc<InformState>,
    mac: &str,
) -> Result<(Vec<u8>, [u8; 16])> {
    let (primary_key, has_authkey) = resolve_key_with_info(state, mac).await;

    let try_decrypt = |key: &[u8; 16]| -> Result<Vec<u8>> {
        let decrypted = if pkt.flags.is_gcm() {
            crypto::decrypt_gcm(pkt, key).map_err(|e| {
                debug!(
                    mac = %mac,
                    flags = ?pkt.flags,
                    payload_len = pkt.payload.len(),
                    iv_hex = %hex_prefix(&pkt.iv),
                    key_hex = %hex_prefix(key),
                    "GCM decrypt failed: {e}"
                );
                e
            })?
        } else {
            crypto::decrypt_cbc(&pkt.payload, key, &pkt.iv)?
        };
        codec::decompress(&decrypted, pkt.flags).map_err(|e| {
            debug!(
                mac = %mac,
                flags = ?pkt.flags,
                decrypted_len = decrypted.len(),
                decrypted_prefix = %hex_prefix(&decrypted[..decrypted.len().min(32)]),
                "decompression failed after successful decrypt: {e}"
            );
            e
        })
    };

    // Try primary key first
    match try_decrypt(&primary_key) {
        Ok(data) => Ok((data, primary_key)),
        Err(e) => {
            // Try the other key as fallback
            let fallback_key = if has_authkey {
                crypto::default_key()
            } else {
                // No authkey in memory — check DB directly (provisioning may have just completed)
                match resolve_authkey_from_db(state, mac).await {
                    Some(key) => key,
                    None => return Err(e), // No fallback available
                }
            };

            match try_decrypt(&fallback_key) {
                Ok(data) => {
                    debug!(mac = %mac, "decryption succeeded with fallback key");
                    Ok((data, fallback_key))
                }
                Err(_) => Err(e), // Return original error
            }
        }
    }
}

/// Resolve authkey from the database directly (bypasses in-memory cache).
async fn resolve_authkey_from_db(state: &Arc<InformState>, mac: &str) -> Option<[u8; 16]> {
    let dev = reload_device_from_db(&state.db, mac).await.ok()?;
    let authkey_str = dev.authkey.as_ref()?;
    crypto::parse_authkey(authkey_str).ok()
}

/// Get the encryption key + whether an authkey was found in memory.
async fn resolve_key_with_info(state: &Arc<InformState>, mac: &str) -> ([u8; 16], bool) {
    let devices = state.devices.lock().await;
    if let Some(dev) = devices.get(mac)
        && let Some(ref authkey) = dev.authkey
        && let Ok(key) = crypto::parse_authkey(authkey)
    {
        return (key, true);
    }
    (crypto::default_key(), false)
}

/// Process a decrypted Inform and decide what to respond.
async fn process_inform(
    state: &Arc<InformState>,
    source_ip: &str,
    mac: &str,
    pkt: &TnbuPacket,
    inform: &InformPayload,
) -> Result<InformResponse> {
    let now = Utc::now().to_rfc3339();

    // Passive validation (Stufe 1)
    let validation = validate_inform(mac, source_ip, inform);

    let mut devices = state.devices.lock().await;

    // Refresh device from DB if state may have changed (provisioning writes directly to DB)
    if let Some(dev) = devices.get(mac)
        && matches!(
            dev.state,
            UbntDeviceState::Adopting | UbntDeviceState::Pending
        )
        && let Ok(fresh) = reload_device_from_db(&state.db, mac).await
    {
        devices.insert(mac.to_string(), fresh);
    }

    if let Some(dev) = devices.get_mut(mac) {
        // Known device — update last_seen + stats
        dev.last_seen = now.clone();
        dev.source_ip = source_ip.to_string();
        dev.firmware_version = inform.version.clone();

        // Update live stats from inform payload
        dev.stats = Some(crate::state::DeviceStats {
            port_table: inform.port_table.clone(),
            sys_stats: inform.sys_stats.clone(),
            system_stats: inform.system_stats.clone(),
            if_table: inform.if_table.clone(),
            uptime: inform.uptime,
            uptime_str: inform.uptime_str.clone(),
            satisfaction: inform.satisfaction,
            power_source_voltage: inform.power_source_voltage.clone(),
            total_max_power: inform.total_max_power,
            overheating: inform.overheating,
            internet: inform.internet,
            kernel_version: inform.kernel_version.clone(),
            architecture: inform.architecture.clone(),
            serial: inform.serial.clone(),
            total_mac_in_used: inform.total_mac_in_used,
            gateway_ip: inform.gateway_ip.clone(),
            updated_at: now.clone(),
        });

        match dev.state {
            UbntDeviceState::Adopted => {
                if pkt.flags.is_gcm() {
                    // Device is using GCM with authkey — fully adopted
                    if let Some(ref authkey) = dev.authkey {
                        // Generate current system_cfg to compute expected cfgversion
                        let mgmt_ip = resolve_mgmt_ip(&state.db)
                            .await
                            .unwrap_or_else(|_| "10.0.0.1".into());

                        let device_type = system_cfg::DeviceType::from_model(&dev.model);
                        let wireless_networks = if device_type == system_cfg::DeviceType::Ap {
                            let nets = system_cfg::load_wireless_networks(&state.db).await;
                            debug!(
                                mac = %mac,
                                wlan_count = nets.len(),
                                wlans = ?nets.iter().map(|n| format!(
                                    "{}(sec={},psk={},vlan={:?})",
                                    n.ssid, n.security, n.psk.is_some(), n.vlan_id
                                )).collect::<Vec<_>>(),
                                "loaded wireless networks for AP system_cfg"
                            );
                            nets
                        } else {
                            Vec::new()
                        };

                        let sys_cfg_str = match system_cfg::generate_system_cfg(
                            &system_cfg::SystemCfg {
                                mgmt_ip: mgmt_ip.clone(),
                                authkey: authkey.clone(),
                                cfgversion: String::new(),
                                ssh_username: dev.ssh_username.clone().unwrap_or_else(|| {
                                    format!("sfgw_{}", &mac.replace(':', "")[6..])
                                }),
                                ssh_password_hash: dev
                                    .ssh_password_hash
                                    .clone()
                                    .unwrap_or_default(),
                                device_type,
                                wireless_networks,
                            },
                        ) {
                            Some(s) => s,
                            None => {
                                warn!(mac = %mac, model = %dev.model, "unknown device type — no system_cfg template, skipping config delivery");
                                return Ok(InformResponse::noop(30));
                            }
                        };

                        let expected_cfgversion = system_cfg::generate_cfgversion(&sys_cfg_str);

                        // Check if device already has our current config
                        if inform.cfgversion == expected_cfgversion {
                            if !dev.config_applied {
                                info!(mac = %mac, cfgversion = %inform.cfgversion, "device reported matching cfgversion — spawning SSH verification");
                                let dev_clone = dev.clone();
                                let state_clone = state.clone();
                                let mac_owned = mac.to_string();
                                drop(devices);

                                // Spawn async SSH verification
                                tokio::spawn(async move {
                                    // Small delay — let the device finish applying config
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                                    match crate::provision::verify_config_applied(&dev_clone).await
                                    {
                                        Ok(result) if result.is_ok() => {
                                            // Verification passed — mark config as applied
                                            let mut devices = state_clone.devices.lock().await;
                                            if let Some(d) = devices.get_mut(&mac_owned) {
                                                d.config_applied = true;
                                                d.config_delivery_attempts = 0;
                                            }
                                            drop(devices);
                                            persist_device(&state_clone, &mac_owned).await.ok();
                                            info!(mac = %mac_owned, "config verified via SSH — adoption complete");
                                        }
                                        Ok(result) => {
                                            // Verification failed — increment counter, maybe alert
                                            let mut devices = state_clone.devices.lock().await;
                                            let attempts =
                                                if let Some(d) = devices.get_mut(&mac_owned) {
                                                    d.config_applied = false;
                                                    d.config_delivery_attempts += 1;
                                                    d.config_delivery_attempts
                                                } else {
                                                    0
                                                };
                                            drop(devices);
                                            persist_device(&state_clone, &mac_owned).await.ok();

                                            warn!(
                                                mac = %mac_owned,
                                                attempt = attempts,
                                                errors = ?result.errors,
                                                "SSH verification FAILED — will re-deliver system_cfg"
                                            );

                                            if attempts >= 3 {
                                                tracing::error!(
                                                    mac = %mac_owned,
                                                    attempts,
                                                    errors = ?result.errors,
                                                    "config delivery failed 3 times — admin intervention needed"
                                                );
                                                sfgw_ids::log_event(
                                                    &state_clone.db,
                                                    "critical",
                                                    "config_delivery_failed",
                                                    Some(&mac_owned),
                                                    Some(&dev_clone.source_ip),
                                                    None,
                                                    None,
                                                    &format!(
                                                        "Config delivery failed {} times for {}: {}",
                                                        attempts,
                                                        dev_clone.model_display,
                                                        result.errors.join("; ")
                                                    ),
                                                ).await.ok();
                                            }
                                        }
                                        Err(e) => {
                                            // SSH connection failed — maybe iptables locked us out
                                            warn!(mac = %mac_owned, error = %e, "SSH verification failed to connect");
                                            let mut devices = state_clone.devices.lock().await;
                                            if let Some(d) = devices.get_mut(&mac_owned) {
                                                d.config_delivery_attempts += 1;
                                            }
                                            drop(devices);
                                            persist_device(&state_clone, &mac_owned).await.ok();
                                        }
                                    }
                                });
                            } else {
                                debug!(mac = %mac, "adopted device heartbeat");
                            }
                            return Ok(InformResponse::noop(30));
                        }

                        // Device needs (re-)configuration — deliver system_cfg
                        // Check if we've exceeded retry limit
                        if dev.config_delivery_attempts >= 3 {
                            debug!(mac = %mac, attempts = dev.config_delivery_attempts, "config delivery exhausted — noop until admin intervenes");
                            return Ok(InformResponse::noop(60));
                        }

                        let mgmt_cfg_str = system_cfg::generate_mgmt_cfg(
                            &system_cfg::SystemCfg {
                                mgmt_ip,
                                authkey: authkey.clone(),
                                cfgversion: expected_cfgversion.clone(),
                                ssh_username: String::new(),
                                ssh_password_hash: String::new(),
                                device_type: system_cfg::DeviceType::from_model(&dev.model),
                                wireless_networks: Vec::new(),
                            },
                            false,
                        );

                        info!(mac = %mac, device_cfgversion = %inform.cfgversion, expected = %expected_cfgversion, attempt = dev.config_delivery_attempts + 1, "delivering system_cfg");
                        dev.config_applied = false;
                        dev.config_delivery_attempts += 1;
                        Ok(InformResponse::setparam_with_system_cfg(
                            mgmt_cfg_str,
                            sys_cfg_str,
                            10,
                        ))
                    } else {
                        debug!(mac = %mac, "adopted device heartbeat (no authkey?)");
                        Ok(InformResponse::noop(30))
                    }
                } else {
                    // Device using CBC (default key) but marked adopted.
                    // This is the normal adoption path AND the recovery path:
                    // - After SSH provisioning, device still uses default key (CBC)
                    // - We deliver the authkey in mgmt_cfg so mcad switches to GCM
                    // - Also handles recovery if device lost its authkey (reboot, factory reset)
                    if let Some(ref authkey) = dev.authkey {
                        let mgmt_ip = resolve_mgmt_ip(&state.db)
                            .await
                            .unwrap_or_else(|_| "10.0.0.1".into());

                        // Use a zero cfgversion in the initial mgmt_cfg delivery.
                        // This way, when the device switches to GCM and reports this
                        // cfgversion back, the GCM branch won't falsely think the
                        // system_cfg is already applied (it hasn't been sent yet).
                        let mgmt_cfg = system_cfg::generate_mgmt_cfg(
                            &system_cfg::SystemCfg {
                                mgmt_ip,
                                authkey: authkey.clone(),
                                cfgversion: "0000000000000000".into(),
                                ssh_username: String::new(),
                                ssh_password_hash: String::new(),
                                device_type: system_cfg::DeviceType::from_model(&dev.model),
                                wireless_networks: Vec::new(),
                            },
                            true, // include authkey
                        );
                        info!(mac = %mac, "adopted device still on CBC — delivering mgmt_cfg with authkey (no system_cfg yet, waiting for GCM switch)");
                        Ok(InformResponse::setparam(mgmt_cfg, 10))
                    } else {
                        debug!(mac = %mac, "adopted device without authkey — noop");
                        Ok(InformResponse::noop(10))
                    }
                }
            }
            UbntDeviceState::Adopting => {
                // SSH provisioning is running or has completed.
                if let Some(ref authkey) = dev.authkey {
                    // Authkey is set — provisioning succeeded, deliver it.
                    let mgmt_ip = resolve_mgmt_ip(&state.db)
                        .await
                        .unwrap_or_else(|_| "10.0.0.1".into());

                    let mgmt_cfg = system_cfg::generate_mgmt_cfg(
                        &system_cfg::SystemCfg {
                            mgmt_ip,
                            authkey: authkey.clone(),
                            cfgversion: "0000000000000000".into(),
                            ssh_username: String::new(),
                            ssh_password_hash: String::new(),
                            device_type: system_cfg::DeviceType::from_model(&dev.model),
                            wireless_networks: Vec::new(),
                        },
                        true,
                    );
                    info!(mac = %mac, "delivering authkey during adoption");
                    Ok(InformResponse::setparam(mgmt_cfg, 10))
                } else if dev.ssh_provision_failed {
                    // SSH provisioning failed. Handle based on device default state.
                    if !inform.default {
                        // Device still has old controller credentials.
                        // Send "setdefault" to make it factory-reset via protocol.
                        // Limit to 3 attempts to avoid infinite loop.
                        let attempts = dev.config_delivery_attempts;
                        if attempts >= 3 {
                            warn!(mac = %mac, attempts, "setdefault exhausted — moving to Pending for manual retry");
                            dev.state = UbntDeviceState::Pending;
                            dev.ssh_provision_failed = false;
                            dev.config_delivery_attempts = 0;
                            drop(devices);
                            persist_device(state, mac).await.ok();
                            return Ok(InformResponse::noop(30));
                        }
                        dev.config_delivery_attempts += 1;
                        info!(
                            mac = %mac,
                            attempt = attempts + 1,
                            "SSH provisioning failed + device not factory-default — sending setdefault"
                        );
                        Ok(InformResponse::set_default())
                    } else {
                        // Device IS in factory-default — retry SSH provisioning.
                        // Add delay: device just rebooted from setdefault, SSH may not be ready.
                        info!(mac = %mac, "device now reports default=true — retrying SSH provisioning (with delay)");
                        dev.ssh_provision_failed = false;
                        dev.config_delivery_attempts = 0;
                        let dev_clone = dev.clone();
                        let db_clone = state.db.clone();
                        let state_clone = state.clone();
                        let mac_owned = mac.to_string();
                        drop(devices);
                        persist_device(state, mac).await.ok();
                        tokio::spawn(async move {
                            // Wait for device to finish booting after setdefault reset
                            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                            match crate::provision::provision_device(&db_clone, &dev_clone).await {
                                Ok(result) => {
                                    tracing::info!(
                                        mac = %dev_clone.mac,
                                        serial = %result.fingerprint.serialno,
                                        "adoption complete after setdefault — device verified"
                                    );
                                }
                                Err(e) => {
                                    tracing::error!(
                                        mac = %dev_clone.mac,
                                        error = %e,
                                        "SSH provisioning failed after setdefault — reverting to Pending"
                                    );
                                    // Revert to Pending so admin can retry manually
                                    let config_json = {
                                        let conn = db_clone.lock().await;
                                        conn.query_row(
                                            "SELECT config FROM devices WHERE mac = ?1",
                                            rusqlite::params![dev_clone.mac],
                                            |r| r.get::<_, String>(0),
                                        )
                                        .ok()
                                    };
                                    if let Some(json_str) = config_json {
                                        if let Ok(mut d) =
                                            serde_json::from_str::<UbntDevice>(&json_str)
                                        {
                                            d.state = UbntDeviceState::Pending;
                                            d.ssh_provision_failed = false;
                                            if let Ok(json) = serde_json::to_string(&d) {
                                                let conn = db_clone.lock().await;
                                                conn.execute(
                                                    "UPDATE devices SET config = ?1 WHERE mac = ?2",
                                                    rusqlite::params![json, dev_clone.mac],
                                                )
                                                .ok();
                                            }
                                        }
                                    }
                                    // Also update in-memory
                                    let mut devs = state_clone.devices.lock().await;
                                    if let Some(d) = devs.get_mut(&mac_owned) {
                                        d.state = UbntDeviceState::Pending;
                                        d.ssh_provision_failed = false;
                                    }
                                }
                            }
                        });
                        Ok(InformResponse::noop(30))
                    }
                } else {
                    debug!(mac = %mac, "adoption in progress — waiting for SSH provisioning");
                    Ok(InformResponse::noop(10))
                }
            }
            UbntDeviceState::Ignored => {
                // Silently accept, no action
                debug!(mac = %mac, "ignored device inform (silent)");
                Ok(InformResponse::noop(60))
            }
            UbntDeviceState::Pending => {
                // Signal caller to return 401 — device stays in factory-default
                // state (white LED). mcad only transitions to "managed" on HTTP 200.
                // This keeps SSH factory creds (ubnt/ubnt) intact until admin
                // clicks Adopt.
                return Err(anyhow::anyhow!("__pending_401__"));
            }
            UbntDeviceState::Phantom => {
                // Re-validate — if the device now passes (e.g. model code was added),
                // promote it from phantom to pending.
                let recheck = validate_inform(mac, source_ip, inform);
                if recheck.is_valid() {
                    info!(mac = %mac, model = %inform.model, "phantom device now passes validation — promoting to pending");
                    dev.state = UbntDeviceState::Pending;
                    dev.validation = recheck;
                    dev.model_display = payload::model_name(&inform.model)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| inform.model_display.clone());
                    drop(devices);
                    persist_device(state, mac).await.ok();
                    Ok(InformResponse::noop(30))
                } else {
                    debug!(mac = %mac, "phantom device still failing validation");
                    Ok(InformResponse::noop(60))
                }
            }
        }
    } else {
        // Device not in memory — but it might be in the DB (e.g. after service restart,
        // or if GCM decrypt failed on a previous cycle for an adopted device).
        // Check DB BEFORE creating a new Pending record to avoid overwriting adopted config.
        if let Ok(db_dev) = reload_device_from_db(&state.db, mac).await
            && (db_dev.state == UbntDeviceState::Adopted
                || db_dev.state == UbntDeviceState::Adopting)
        {
            info!(
                mac = %mac,
                state = %db_dev.state,
                "found existing {} device in DB — restoring to memory (not overwriting with Pending)",
                db_dev.state
            );
            devices.insert(mac.to_string(), db_dev);
            drop(devices);
            // Return noop — device will re-inform and hit the correct branch
            return Ok(InformResponse::noop(10));
        }

        // New device — passive validation
        if !validation.is_valid() {
            // PHANTOM DEVICE DETECTED
            let reason = validation
                .reason
                .clone()
                .unwrap_or_else(|| "unknown".to_string());

            warn!(
                source_ip = %source_ip,
                mac = %mac,
                model = %inform.model,
                hostname = %inform.hostname,
                reason = %reason,
                "PHANTOM DEVICE INFORM DETECTED — dropped, not added to pending"
            );

            // Log IDS security event
            if let Err(e) = sfgw_ids::log_event(
                &state.db,
                "warning",
                "phantom_inform",
                Some(mac),
                Some(source_ip),
                None,
                None,
                &format!(
                    "Phantom device inform: MAC={mac}, Model={}, IP={source_ip}, Claimed IP={}, Reason: {reason}",
                    inform.model, inform.ip
                ),
            )
            .await
            {
                warn!(error = %e, "failed to log phantom device IDS event");
            }

            // Store the phantom device so it shows in the UI
            let model_display = payload::model_name(&inform.model)
                .map(|s| s.to_string())
                .unwrap_or_else(|| inform.model_display.clone());

            let phantom = UbntDevice {
                mac: mac.to_string(),
                model: inform.model.clone(),
                model_display,
                source_ip: source_ip.to_string(),
                claimed_ip: inform.ip.clone(),
                firmware_version: inform.version.clone(),
                hostname: inform.hostname.clone(),
                state: UbntDeviceState::Phantom,
                authkey: None,
                ssh_username: None,
                ssh_password: None,
                ssh_password_hash: None,
                config_applied: false,
                config_delivery_attempts: 0,
                ssh_provision_failed: false,
                fingerprint: None,
                last_seen: now.clone(),
                first_seen: now,
                validation: validation.clone(),
                port_config: None,
                stats: None,
            };

            devices.insert(mac.to_string(), phantom);
            drop(devices);
            persist_device(state, mac).await.ok();

            // Still respond with noop (don't leak detection to attacker)
            return Ok(InformResponse::noop(30));
        }

        // Valid new device — add as Pending
        let model_display = payload::model_name(&inform.model)
            .map(|s| s.to_string())
            .unwrap_or_else(|| inform.model_display.clone());

        let device = UbntDevice {
            mac: mac.to_string(),
            model: inform.model.clone(),
            model_display,
            source_ip: source_ip.to_string(),
            claimed_ip: inform.ip.clone(),
            firmware_version: inform.version.clone(),
            hostname: inform.hostname.clone(),
            state: UbntDeviceState::Pending,
            authkey: None,
            ssh_username: None,
            ssh_password: None,
            ssh_password_hash: None,
            config_applied: false,
            config_delivery_attempts: 0,
            ssh_provision_failed: false,
            fingerprint: None,
            last_seen: now.clone(),
            first_seen: now,
            validation,
            port_config: None,
            stats: None,
        };

        info!(
            mac = %mac,
            model = %device.model_display,
            source_ip = %source_ip,
            "new device discovered — added to pending list"
        );

        devices.insert(mac.to_string(), device);

        // Persist to DB
        drop(devices);
        persist_device(state, mac).await?;

        Ok(InformResponse::noop(30))
    }
}

/// Passive validation of an Inform payload (Stufe 1 — no SSH).
fn validate_inform(mac: &str, source_ip: &str, inform: &InformPayload) -> ValidationResult {
    // Parse MAC bytes for OUI check
    let mac_bytes: Option<[u8; 6]> = parse_mac_bytes(mac);
    let oui_valid = mac_bytes
        .as_ref()
        .map(payload::is_ubiquiti_oui)
        .unwrap_or(false);

    // IP match check (source IP vs self-declared IP)
    let ip_matches = inform.ip.is_empty() || inform.ip == source_ip;

    // Model recognition
    let model_known = inform.model.is_empty() || payload::model_name(&inform.model).is_some();

    let mut reasons = Vec::new();
    if !oui_valid {
        reasons.push(format!("MAC OUI not Ubiquiti ({mac})"));
    }
    if !ip_matches {
        reasons.push(format!(
            "source IP ({source_ip}) ≠ claimed IP ({})",
            inform.ip
        ));
    }
    if !model_known {
        reasons.push(format!("unknown model code ({})", inform.model));
    }

    let reason = if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    };

    ValidationResult {
        oui_valid,
        ip_matches,
        model_known,
        reason,
    }
}

/// Parse "aa:bb:cc:dd:ee:ff" into [u8; 6].
fn parse_mac_bytes(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

/// Persist a device to the database.
async fn persist_device(state: &Arc<InformState>, mac: &str) -> Result<()> {
    let devices = state.devices.lock().await;
    let dev = devices
        .get(mac)
        .context("device not found in memory")?
        .clone();
    drop(devices);

    let config_json = serde_json::to_string(&dev)?;
    let conn = state.db.lock().await;

    conn.execute(
        "INSERT INTO devices (mac, name, model, ip, adopted, last_seen, config)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(mac) DO UPDATE SET
           model = excluded.model,
           ip = excluded.ip,
           last_seen = excluded.last_seen,
           config = excluded.config",
        rusqlite::params![
            dev.mac,
            dev.hostname,
            dev.model,
            dev.source_ip,
            dev.state == UbntDeviceState::Adopted,
            dev.last_seen,
            config_json,
        ],
    )?;

    Ok(())
}

/// Reload a single device from the database (used to pick up provisioning updates).
async fn reload_device_from_db(db: &sfgw_db::Db, mac: &str) -> Result<UbntDevice> {
    let conn = db.lock().await;
    let config_json: String = conn
        .query_row(
            "SELECT config FROM devices WHERE mac = ?1",
            rusqlite::params![mac],
            |r| r.get(0),
        )
        .context("device not in DB")?;

    serde_json::from_str(&config_json).context("failed to parse device config from DB")
}

/// Format first N bytes as hex for debug logging.
fn hex_prefix(data: &[u8]) -> String {
    data.iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Get the MGMT gateway IP from the database.
async fn resolve_mgmt_ip(db: &sfgw_db::Db) -> Result<String> {
    let conn = db.lock().await;
    conn.query_row(
        "SELECT gateway FROM networks WHERE zone = 'mgmt' AND enabled = 1",
        [],
        |r| r.get::<_, String>(0),
    )
    .map_err(|e| anyhow::anyhow!("no MGMT network for inform URL: {e}"))
}

/// Build an encrypted TNBU response packet.
fn build_response_packet(
    request: &TnbuPacket,
    response_json: &[u8],
    key: &[u8; 16],
) -> Result<Vec<u8>> {
    // Generate random IV for response
    let mut iv = [0u8; 16];
    let rng = ring::rand::SystemRandom::new();
    ring::rand::SecureRandom::fill(&rng, &mut iv)
        .map_err(|_| anyhow::anyhow!("RNG failure for response IV"))?;

    // Response uses same encryption mode as request
    let use_gcm = request.flags.is_gcm();
    let flags = if use_gcm {
        PacketFlags::GCM_ONLY
    } else {
        PacketFlags::CBC
    };

    let encrypted = if use_gcm {
        // GCM encrypted length = plaintext + 16-byte auth tag
        let encrypted_len = response_json.len() + 16;
        // Build packet with correct payload length so header_bytes() generates
        // the right AAD (data_length field must match what the device sees on wire)
        let pkt_for_aad = TnbuPacket {
            version: request.version,
            mac: request.mac,
            flags,
            iv,
            data_version: request.data_version,
            payload: vec![0u8; encrypted_len], // correct length for AAD
            raw_header: None,
        };
        crypto::encrypt_gcm(response_json, key, &pkt_for_aad)?
    } else {
        crypto::encrypt_cbc(response_json, key, &iv)
    };

    let final_pkt = TnbuPacket {
        version: request.version,
        mac: request.mac,
        flags,
        iv,
        data_version: request.data_version,
        payload: encrypted,
        raw_header: None,
    };

    Ok(packet::serialize(&final_pkt))
}
