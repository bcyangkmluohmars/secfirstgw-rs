// SPDX-License-Identifier: AGPL-3.0-or-later

//! SSH-based provisioning for adopted UniFi devices.
//!
//! After the admin clicks "Adopt", we:
//! 1. SSH to the device using factory credentials (ubnt/ubnt)
//! 2. Read `/proc/ubnthal/system.info` for hardware fingerprint
//! 3. Verify the fingerprint matches what we expect from a genuine UniFi device
//! 4. Generate a per-device authkey + SSH credentials
//! 5. Store the fingerprint and authkey in the database
//! 6. The next Inform response will deliver `system_cfg` with the authkey
//!
//! All operations happen in a single SSH session to prevent TOCTOU attacks.
//! If any step fails, the device remains in "Adopting" state and can be retried.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::ChannelMsg;
use russh::client;
use tokio::sync::Semaphore;

use crate::crypto;
use crate::state::{HardwareFingerprint, UbntDevice, UbntDeviceState};

/// Maximum number of concurrent SSH provisioning sessions.
///
/// Limits resource exhaustion if many devices try to adopt simultaneously.
/// 3 is sufficient for typical deployments (rarely more than a few devices
/// adopt at once) while preventing SSH socket/memory exhaustion.
static SSH_PROVISION_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(3));

/// Hardware-derived credential encryption key (derived once, cached).
///
/// Used to encrypt SSH passwords at the application level before storing
/// in the DB. Provides defense-in-depth on top of SQLCipher encryption.
static CREDENTIAL_KEY: LazyLock<sfgw_crypto::credential::CredentialKey> = LazyLock::new(|| {
    sfgw_crypto::credential::derive_credential_key()
        .expect("failed to derive credential encryption key from hardware identity")
});

/// Access the singleton credential encryption key.
fn credential_key() -> &'static sfgw_crypto::credential::CredentialKey {
    &CREDENTIAL_KEY
}

/// Factory default credentials on all UniFi devices.
const FACTORY_USERNAME: &str = "ubnt";
const FACTORY_PASSWORD: &str = "ubnt";

/// SSH connection timeout.
const SSH_TIMEOUT: Duration = Duration::from_secs(10);

/// SSH channel read timeout (per-message).
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(5);

/// Total deadline for a single SSH command execution.
///
/// Prevents a slow device from hanging us indefinitely by sending data
/// just often enough to avoid the per-message timeout.
const COMMAND_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Result of a successful provisioning SSH session.
#[derive(Debug)]
pub struct ProvisionResult {
    /// Hardware fingerprint read from the device.
    pub fingerprint: HardwareFingerprint,
    /// Generated per-device authkey (32 hex chars).
    pub authkey: String,
    /// Generated per-device SSH username.
    pub ssh_username: String,
    /// Generated per-device SSH password (plaintext).
    pub ssh_password: String,
    /// SHA-512 crypt(3) hash of the password (for system_cfg delivery).
    pub ssh_password_hash: String,
}

/// Run the full provisioning flow for a device.
///
/// This is called asynchronously after the admin clicks "Adopt".
/// On success, updates the device state to Adopted with fingerprint + authkey.
/// On failure, logs the error and leaves the device in Adopting state.
///
/// Flow:
/// 1. SSH to device with factory creds (ubnt/ubnt)
/// 2. Read /proc/ubnthal/system.info for hardware fingerprint
/// 3. Validate fingerprint
/// 4. Generate per-device authkey + SSH credentials
/// 5. Store everything in database, state → Adopted
/// 6. Next inform from device (CBC, default key) → handler delivers authkey in mgmt_cfg
/// 7. Device switches to GCM with our authkey → handler delivers system_cfg
pub async fn provision_device(db: &sfgw_db::Db, device: &UbntDevice) -> Result<ProvisionResult> {
    // Acquire a permit from the global semaphore to limit concurrent SSH sessions.
    // This prevents resource exhaustion when many devices adopt simultaneously.
    let _permit = SSH_PROVISION_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| anyhow::anyhow!("SSH provisioning semaphore closed"))?;

    let addr: SocketAddr = format!("{}:22", device.source_ip)
        .parse()
        .with_context(|| format!("invalid device IP for SSH: {}", device.source_ip))?;

    tracing::info!(
        mac = %device.mac,
        ip = %device.source_ip,
        model = %device.model_display,
        "starting SSH provisioning"
    );

    // Step 1: Connect via SSH with factory creds
    let mut session = ssh_connect(addr)
        .await
        .with_context(|| format!("SSH connection failed to {}", device.source_ip))?;

    // Step 2: Read hardware fingerprint
    let fp_output = ssh_exec(&mut session, "cat /proc/ubnthal/system.info")
        .await
        .context("failed to read system.info")?;
    let fingerprint = parse_system_info(&fp_output)?;

    // Step 3: Validate the fingerprint looks like a genuine UniFi device
    validate_fingerprint(&fingerprint)?;

    tracing::info!(
        mac = %device.mac,
        serial = %fingerprint.serialno,
        cpuid = %fingerprint.cpuid,
        "hardware fingerprint verified"
    );

    // Step 4: Generate per-device credentials
    let authkey = crypto::generate_authkey().context("failed to generate authkey")?;

    let ssh_username = generate_ssh_username(&device.mac);
    let ssh_password = generate_ssh_password()?;
    let ssh_password_hash = hash_password_crypt(&ssh_password)?;

    // Step 5: Disconnect SSH — authkey delivery happens via inform response, not SSH
    // Disconnect SSH
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    // Step 6: Store in database — next inform will pick up the authkey via handler
    let result = ProvisionResult {
        fingerprint,
        authkey,
        ssh_username,
        ssh_password,
        ssh_password_hash,
    };

    update_device_adopted(db, &device.mac, &result).await?;

    tracing::info!(mac = %device.mac, "device provisioning complete — adopted, authkey will be delivered via next inform response");

    Ok(result)
}

/// Connect to a device via SSH with factory credentials.
///
/// Returns an authenticated session handle that can be used for multiple commands.
async fn ssh_connect(addr: SocketAddr) -> Result<client::Handle<SshHandler>> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(SSH_TIMEOUT),
        ..Default::default()
    });

    let handler = SshHandler;
    let mut session = tokio::time::timeout(SSH_TIMEOUT, client::connect(config, addr, handler))
        .await
        .map_err(|_| anyhow::anyhow!("SSH connection timed out to {addr}"))?
        .with_context(|| format!("SSH connection failed to {addr}"))?;

    // Authenticate with factory credentials.
    // Try password auth first, then keyboard-interactive as fallback
    // (Dropbear on some UniFi devices only accepts keyboard-interactive).
    let auth_ok = match tokio::time::timeout(
        CHANNEL_TIMEOUT,
        session.authenticate_password(FACTORY_USERNAME, FACTORY_PASSWORD),
    )
    .await
    {
        Ok(Ok(true)) => true,
        other => {
            let reason = match &other {
                Ok(Ok(false)) => "rejected".to_string(),
                Ok(Ok(true)) => unreachable!(),
                Ok(Err(e)) => format!("error: {e}"),
                Err(_) => "timed out".to_string(),
            };
            tracing::info!(addr = %addr, reason = %reason, "password auth failed, trying keyboard-interactive");

            // Fallback: keyboard-interactive (Dropbear may prefer this)
            ssh_authenticate_keyboard_interactive(&mut session, FACTORY_USERNAME, FACTORY_PASSWORD)
                .await
                .context("SSH keyboard-interactive auth failed")?
        }
    };

    if !auth_ok {
        bail!(
            "SSH authentication rejected (factory creds ubnt/ubnt not accepted — device may already be provisioned)"
        );
    }

    Ok(session)
}

/// Execute a command on an SSH session and return stdout as string.
///
/// Uses both a per-message timeout (`CHANNEL_TIMEOUT`) and a total deadline
/// (`COMMAND_TOTAL_TIMEOUT`) to prevent slow-drip data attacks.
async fn ssh_exec(session: &mut client::Handle<SshHandler>, cmd: &str) -> Result<String> {
    let mut channel = session
        .channel_open_session()
        .await
        .context("failed to open SSH channel")?;

    channel
        .exec(true, cmd)
        .await
        .with_context(|| format!("failed to exec: {cmd}"))?;

    // Wrap the entire read loop in a total deadline so a device sending
    // data slowly (just under per-message timeout) can't hang us forever.
    let read_loop = async {
        let mut output = Vec::new();

        loop {
            let msg = tokio::time::timeout(CHANNEL_TIMEOUT, channel.wait()).await;

            match msg {
                Ok(Some(ChannelMsg::Data { data })) => {
                    output.extend_from_slice(&data);
                    if output.len() > 65536 {
                        bail!("command output too large (>64KB)");
                    }
                }
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => {
                    tracing::debug!(
                        stderr = %String::from_utf8_lossy(&data),
                        cmd = %cmd,
                        "SSH stderr"
                    );
                }
                Ok(Some(ChannelMsg::Eof | ChannelMsg::Close)) => break,
                Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                    if exit_status != 0 {
                        bail!("command '{}' exited with status {}", cmd, exit_status);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    if output.is_empty() {
                        bail!("timeout reading output from: {cmd}");
                    }
                    break;
                }
            }
        }

        String::from_utf8(output).with_context(|| format!("non-UTF8 output from: {cmd}"))
    };

    tokio::select! {
        result = read_loop => result,
        _ = tokio::time::sleep(COMMAND_TOTAL_TIMEOUT) => {
            bail!("total command timeout ({:?}) exceeded for: {cmd}", COMMAND_TOTAL_TIMEOUT);
        }
    }
}

/// Maximum length for any fingerprint field value.
///
/// Real UniFi hardware fields are short (4-64 chars). Anything longer
/// is suspicious and may indicate injection or a spoofed device.
const FINGERPRINT_FIELD_MAX_LEN: usize = 256;

/// Parse `/proc/ubnthal/system.info` key=value format.
fn parse_system_info(text: &str) -> Result<HardwareFingerprint> {
    let mut fp = HardwareFingerprint {
        cpuid: String::new(),
        serialno: String::new(),
        device_hashid: String::new(),
        systemid: String::new(),
        boardrevision: String::new(),
        vendorid: String::new(),
        manufid: String::new(),
        mfgweek: String::new(),
    };

    for line in text.lines() {
        let line = line.trim();
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();

            // Validate length for ALL fingerprint fields before storing
            if val.len() > FINGERPRINT_FIELD_MAX_LEN {
                bail!(
                    "fingerprint field '{}' exceeds max length ({} > {})",
                    key,
                    val.len(),
                    FINGERPRINT_FIELD_MAX_LEN
                );
            }

            match key {
                "cpuid" => fp.cpuid = val.into(),
                "serialno" => fp.serialno = val.into(),
                "device.hashid" => fp.device_hashid = val.into(),
                "systemid" => fp.systemid = val.into(),
                "boardrevision" => fp.boardrevision = val.into(),
                "vendorid" => fp.vendorid = val.into(),
                "manufid" => fp.manufid = val.into(),
                "mfgweek" => fp.mfgweek = val.into(),
                _ => {} // Ignore unknown keys
            }
        }
    }

    // Must have at least serial and cpuid
    if fp.serialno.is_empty() || fp.cpuid.is_empty() {
        bail!("system.info missing required fields (serialno, cpuid)");
    }

    Ok(fp)
}

/// Validate the hardware fingerprint looks genuine.
fn validate_fingerprint(fp: &HardwareFingerprint) -> Result<()> {
    // Serial number should be alphanumeric and reasonable length
    if fp.serialno.len() < 4 || fp.serialno.len() > 64 {
        bail!("suspicious serialno length: {}", fp.serialno.len());
    }
    if !fp.serialno.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("serialno contains non-alphanumeric characters");
    }

    // CPU ID should be hex
    if fp.cpuid.is_empty() {
        bail!("empty cpuid");
    }
    if !fp.cpuid.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("cpuid contains non-hex characters");
    }

    Ok(())
}

/// Generate a per-device SSH username from the MAC address.
///
/// Format: `sfgw_AABBCC` (last 3 octets of MAC).
fn generate_ssh_username(mac: &str) -> String {
    let suffix: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .skip(6) // Skip first 3 octets (OUI)
        .take(6)
        .collect::<String>()
        .to_lowercase();
    format!("sfgw_{suffix}")
}

/// Hash a password using SHA-512 crypt(3) format ($6$...).
///
/// **INTEROP CODE**: UniFi devices use standard Linux crypt(3) for password
/// storage. We use SHA-512 which is the strongest crypt(3) variant.
fn hash_password_crypt(password: &str) -> Result<String> {
    let params = sha_crypt::Sha512Params::new(10_000)
        .map_err(|e| anyhow::anyhow!("invalid sha-crypt params: {e:?}"))?;
    sha_crypt::sha512_simple(password, &params)
        .map_err(|e| anyhow::anyhow!("sha-crypt hash failed: {e:?}"))
}

/// Generate a random 24-char alphanumeric SSH password.
fn generate_ssh_password() -> Result<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let password: String = (0..24)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();
    Ok(password)
}

/// Update the device record to Adopted state with fingerprint and authkey.
async fn update_device_adopted(
    db: &sfgw_db::Db,
    mac: &str,
    result: &ProvisionResult,
) -> Result<()> {
    let conn = db.lock().await;

    // Read current device config
    let config_json: String = conn
        .query_row(
            "SELECT config FROM devices WHERE mac = ?1",
            rusqlite::params![mac],
            |r| r.get(0),
        )
        .context("device not found in DB during adoption")?;

    let mut device: UbntDevice =
        serde_json::from_str(&config_json).context("failed to parse device config")?;

    device.state = UbntDeviceState::Adopted;
    device.authkey = Some(result.authkey.clone());
    device.ssh_username = Some(result.ssh_username.clone());
    // Encrypt SSH password at application level (defense-in-depth on top of SQLCipher).
    let encrypted_password = credential_key()
        .encrypt(&result.ssh_password)
        .context("failed to encrypt SSH password")?;
    device.ssh_password = Some(encrypted_password);
    device.ssh_password_hash = Some(result.ssh_password_hash.clone());
    device.config_applied = false;
    device.fingerprint = Some(result.fingerprint.clone());

    let updated_json =
        serde_json::to_string(&device).context("failed to serialize updated device")?;

    conn.execute(
        "UPDATE devices SET config = ?1 WHERE mac = ?2",
        rusqlite::params![updated_json, mac],
    )?;

    Ok(())
}

/// Perform keyboard-interactive authentication.
///
/// Handles the multi-step flow: start → InfoRequest(prompts) → respond(password) → Success/Failure.
async fn ssh_authenticate_keyboard_interactive(
    session: &mut russh::client::Handle<SshHandler>,
    username: &str,
    password: &str,
) -> Result<bool> {
    use russh::client::KeyboardInteractiveAuthResponse;

    let mut response = tokio::time::timeout(
        CHANNEL_TIMEOUT,
        session.authenticate_keyboard_interactive_start(username, None::<String>),
    )
    .await
    .map_err(|_| anyhow::anyhow!("keyboard-interactive start timed out"))?
    .context("keyboard-interactive start failed")?;

    // Handle potentially multiple rounds of prompts
    for _ in 0..5 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // Respond with the password for each prompt
                let responses: Vec<String> = prompts.iter().map(|_| password.to_string()).collect();
                response = tokio::time::timeout(
                    CHANNEL_TIMEOUT,
                    session.authenticate_keyboard_interactive_respond(responses),
                )
                .await
                .map_err(|_| anyhow::anyhow!("keyboard-interactive respond timed out"))?
                .context("keyboard-interactive respond failed")?;
            }
        }
    }

    bail!("keyboard-interactive auth: too many rounds")
}

/// Connect to a device via SSH with custom credentials (post-adoption).
///
/// Same as `ssh_connect` but uses provided username/password instead of factory creds.
async fn ssh_connect_with_creds(
    addr: SocketAddr,
    username: &str,
    password: &str,
) -> Result<client::Handle<SshHandler>> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(SSH_TIMEOUT),
        ..Default::default()
    });

    let handler = SshHandler;
    let mut session = tokio::time::timeout(SSH_TIMEOUT, client::connect(config, addr, handler))
        .await
        .map_err(|_| anyhow::anyhow!("SSH connection timed out to {addr}"))?
        .with_context(|| format!("SSH connection failed to {addr}"))?;

    let auth_ok = match tokio::time::timeout(
        CHANNEL_TIMEOUT,
        session.authenticate_password(username, password),
    )
    .await
    {
        Ok(Ok(true)) => true,
        other => {
            let reason = match &other {
                Ok(Ok(false)) => "rejected".to_string(),
                Ok(Ok(true)) => unreachable!(),
                Ok(Err(e)) => format!("error: {e}"),
                Err(_) => "timed out".to_string(),
            };
            tracing::debug!(addr = %addr, reason = %reason, "password auth failed, trying keyboard-interactive");
            ssh_authenticate_keyboard_interactive(&mut session, username, password)
                .await
                .context("SSH keyboard-interactive auth failed")?
        }
    };

    if !auth_ok {
        bail!("SSH authentication rejected with provisioned credentials");
    }

    Ok(session)
}

/// Verification results from post-adoption SSH check.
#[derive(Debug)]
pub struct VerifyResult {
    /// Whether the authkey on the device matches ours.
    pub authkey_ok: bool,
    /// Whether our SSH user exists and ubnt is disabled.
    pub ssh_user_ok: bool,
    /// Whether iptables restricts SSH to gateway only.
    pub iptables_ok: bool,
    /// Whether the hardware fingerprint (CPUID + serial) still matches.
    /// `false` indicates a possible device swap — critical security event.
    pub fingerprint_ok: bool,
    /// Detailed error descriptions (for debugging).
    pub errors: Vec<String>,
}

impl VerifyResult {
    /// All checks passed.
    pub fn is_ok(&self) -> bool {
        self.authkey_ok && self.ssh_user_ok && self.iptables_ok && self.fingerprint_ok
    }
}

/// SSH to the device and verify system_cfg was correctly applied.
///
/// Called once after "device confirmed config" to verify the device
/// actually applied what we sent. Checks:
/// - `unifi.key` matches our authkey
/// - `users.1.name` is our SSH user
/// - `users.2.shell=/bin/false` (ubnt disabled)
/// - `iptables` has ACCEPT for gateway + DROP for rest
/// - Hardware fingerprint (CPUID + serial) still matches stored values
///   (detects device swap between adoption and verification)
pub async fn verify_config_applied(device: &UbntDevice, db: &sfgw_db::Db) -> Result<VerifyResult> {
    // Acquire a permit — verification also opens an SSH session.
    let _permit = SSH_PROVISION_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| anyhow::anyhow!("SSH provisioning semaphore closed"))?;

    let username = device
        .ssh_username
        .as_deref()
        .context("no SSH username for verification")?;
    // Decrypt SSH password (supports both encrypted and legacy plaintext).
    let encrypted_pw = device
        .ssh_password
        .as_deref()
        .context("no SSH password for verification")?;
    let password = credential_key()
        .decrypt(encrypted_pw)
        .context("failed to decrypt SSH password")?;
    let authkey = device
        .authkey
        .as_deref()
        .context("no authkey for verification")?;

    let addr: SocketAddr = format!("{}:22", device.source_ip)
        .parse()
        .with_context(|| format!("invalid device IP: {}", device.source_ip))?;

    tracing::info!(mac = %device.mac, ip = %device.source_ip, "starting post-adoption SSH verification");

    let mut session = ssh_connect_with_creds(addr, username, &password)
        .await
        .context("SSH verification connect failed")?;

    let system_cfg = ssh_exec(&mut session, "cat /tmp/system.cfg")
        .await
        .context("failed to read system.cfg")?;

    // Re-read hardware fingerprint to detect device swap
    let fp_output = ssh_exec(&mut session, "cat /proc/ubnthal/system.info")
        .await
        .context("failed to re-read system.info during verification")?;

    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    let mut errors = Vec::new();

    // Check hardware fingerprint matches stored values (CPUID + serial)
    // If these changed, the device may have been physically swapped.
    let fingerprint_ok = match (parse_system_info(&fp_output), &device.fingerprint) {
        (Ok(current_fp), Some(stored_fp)) => {
            let cpuid_match = current_fp.cpuid == stored_fp.cpuid;
            let serial_match = current_fp.serialno == stored_fp.serialno;
            if !cpuid_match || !serial_match {
                tracing::error!(
                    mac = %device.mac,
                    stored_cpuid = %stored_fp.cpuid,
                    current_cpuid = %current_fp.cpuid,
                    stored_serial = %stored_fp.serialno,
                    current_serial = %current_fp.serialno,
                    "CRITICAL: hardware fingerprint mismatch — possible device swap"
                );

                // Log IDS critical alert — device identity changed between adoption and verification
                if let Err(ids_err) = sfgw_ids::log_event(
                    db,
                    "critical",
                    "ubnt-inform",
                    Some(&device.mac),
                    Some(&device.source_ip),
                    None,
                    None,
                    &format!(
                        "Hardware fingerprint mismatch during verification for {} — \
                         stored CPUID={}, current CPUID={}, stored serial={}, current serial={}. \
                         Device may have been swapped.",
                        device.model_display,
                        stored_fp.cpuid,
                        current_fp.cpuid,
                        stored_fp.serialno,
                        current_fp.serialno,
                    ),
                )
                .await
                {
                    tracing::warn!(error = %ids_err, "failed to log fingerprint mismatch to IDS");
                }

                errors.push(format!(
                    "hardware fingerprint mismatch (cpuid: {}→{}, serial: {}→{})",
                    stored_fp.cpuid, current_fp.cpuid, stored_fp.serialno, current_fp.serialno,
                ));
                false
            } else {
                true
            }
        }
        (Ok(_), None) => {
            tracing::warn!(mac = %device.mac, "no stored fingerprint to compare — skipping fingerprint re-check");
            true
        }
        (Err(e), _) => {
            errors.push(format!(
                "failed to parse system.info during verification: {e}"
            ));
            false
        }
    };

    // Check authkey
    let authkey_ok = system_cfg
        .lines()
        .any(|l| l.starts_with("unifi.key=") && l[10..] == *authkey);
    if !authkey_ok {
        errors.push(format!("unifi.key mismatch (expected {})", authkey));
    }

    // Check SSH user
    let ssh_user_ok = system_cfg
        .lines()
        .any(|l| l == format!("users.1.name={username}"));
    if !ssh_user_ok {
        errors.push(format!("users.1.name not set to {username}"));
    }

    // Check ubnt disabled
    let ubnt_disabled = system_cfg.lines().any(|l| l == "users.2.shell=/bin/false");
    if !ubnt_disabled && username != "ubnt" {
        errors.push("ubnt user not disabled (users.2.shell=/bin/false missing)".into());
    }

    // Check iptables
    let has_accept = system_cfg
        .lines()
        .any(|l| l.contains("ACCEPT") && l.contains("--dport 22"));
    let has_drop = system_cfg
        .lines()
        .any(|l| l.contains("DROP") && l.contains("--dport 22"));
    let iptables_ok = has_accept && has_drop;
    if !iptables_ok {
        errors.push("iptables SSH rules incomplete (need ACCEPT from gw + DROP)".into());
    }

    let result = VerifyResult {
        authkey_ok,
        ssh_user_ok: ssh_user_ok && (ubnt_disabled || username == "ubnt"),
        iptables_ok,
        fingerprint_ok,
        errors,
    };

    if result.is_ok() {
        tracing::info!(mac = %device.mac, "SSH verification passed — system_cfg confirmed on device");
    } else {
        tracing::warn!(
            mac = %device.mac,
            errors = ?result.errors,
            "SSH verification FAILED — system_cfg not correctly applied"
        );
    }

    Ok(result)
}

/// Minimal SSH client handler — accepts any host key.
///
/// This is acceptable because:
/// 1. We're on the MGMT VLAN (trusted network segment)
/// 2. The device is factory-fresh (no prior key to verify against)
/// 3. We validate the hardware fingerprint from EEPROM instead
struct SshHandler;

#[async_trait::async_trait]
impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept any host key — see struct doc comment for rationale
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_system_info_valid() {
        let text = "\
cpuid=a0b1c2d3
serialno=ABC123456789
device.hashid=deadbeef
systemid=ec20
boardrevision=24
vendorid=0777
manufid=0123
mfgweek=2341
";
        let fp = parse_system_info(text).unwrap();
        assert_eq!(fp.cpuid, "a0b1c2d3");
        assert_eq!(fp.serialno, "ABC123456789");
        assert_eq!(fp.device_hashid, "deadbeef");
        assert_eq!(fp.systemid, "ec20");
        assert_eq!(fp.boardrevision, "24");
        assert_eq!(fp.vendorid, "0777");
        assert_eq!(fp.manufid, "0123");
        assert_eq!(fp.mfgweek, "2341");
    }

    #[test]
    fn parse_system_info_missing_fields() {
        let text = "boardrevision=24\nvendorid=0777\n";
        assert!(parse_system_info(text).is_err());
    }

    #[test]
    fn validate_fingerprint_valid() {
        let fp = HardwareFingerprint {
            cpuid: "a0b1c2d3".into(),
            serialno: "ABC123456789".into(),
            device_hashid: "deadbeef".into(),
            systemid: "ec20".into(),
            boardrevision: "24".into(),
            vendorid: "0777".into(),
            manufid: "0123".into(),
            mfgweek: "2341".into(),
        };
        assert!(validate_fingerprint(&fp).is_ok());
    }

    #[test]
    fn validate_fingerprint_bad_serial() {
        let fp = HardwareFingerprint {
            cpuid: "a0b1c2d3".into(),
            serialno: "AB".into(), // too short
            device_hashid: "".into(),
            systemid: "".into(),
            boardrevision: "".into(),
            vendorid: "".into(),
            manufid: "".into(),
            mfgweek: "".into(),
        };
        assert!(validate_fingerprint(&fp).is_err());
    }

    #[test]
    fn generate_ssh_username_from_mac() {
        assert_eq!(generate_ssh_username("aa:bb:cc:dd:ee:ff"), "sfgw_ddeeff");
        assert_eq!(generate_ssh_username("00:11:22:33:44:55"), "sfgw_334455");
    }

    #[test]
    fn generate_ssh_password_length() {
        let pw = generate_ssh_password().unwrap();
        assert_eq!(pw.len(), 24);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn parse_system_info_rejects_oversized_field() {
        let long_val = "A".repeat(FINGERPRINT_FIELD_MAX_LEN + 1);
        let text = format!("cpuid=a0b1c2d3\nserialro=ABC123\nsystemid={}\n", long_val);
        let err = parse_system_info(&text).unwrap_err();
        assert!(
            err.to_string().contains("exceeds max length"),
            "expected length error, got: {err}"
        );
    }

    #[test]
    fn parse_system_info_accepts_max_length_field() {
        let max_val = "A".repeat(FINGERPRINT_FIELD_MAX_LEN);
        let text = format!(
            "cpuid=a0b1c2d3\nserialno=ABC123456789\nsystemid={}\n",
            max_val
        );
        let fp = parse_system_info(&text).unwrap();
        assert_eq!(fp.systemid.len(), FINGERPRINT_FIELD_MAX_LEN);
    }

    #[test]
    fn verify_result_requires_fingerprint_ok() {
        let result = VerifyResult {
            authkey_ok: true,
            ssh_user_ok: true,
            iptables_ok: true,
            fingerprint_ok: false,
            errors: vec!["fingerprint mismatch".into()],
        };
        assert!(
            !result.is_ok(),
            "VerifyResult should fail when fingerprint_ok is false"
        );
    }
}
