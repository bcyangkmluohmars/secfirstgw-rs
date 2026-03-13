// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Forward-secret encrypted logging.
//!
//! Every day gets a unique AES-256-GCM key derived via HKDF from a master key.
//! Once a day-key is deleted (after export), the corresponding logs become
//! permanently unreadable — achieving forward secrecy for audit logs.

use anyhow::Context;

/// Errors from the log crate.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Crypto error from sfgw-crypto.
    #[error("crypto error: {0}")]
    Crypto(#[from] sfgw_crypto::CryptoError),

    /// Base64 decoding error.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Cryptographic operation failed.
    #[error("crypto operation failed: {0}")]
    CryptoFailed(String),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias for results from this crate.
type Result<T> = std::result::Result<T, LogError>;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{NaiveDate, Utc};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sfgw_crypto::HkdfLen;
use sfgw_crypto::secure_mem::SecureBox;
use zeroize::Zeroize;

/// A decrypted log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: i64,
    pub date: String,
    pub level: String,
    pub module: String,
    pub message: String,
    pub created_at: String,
}

/// Plaintext structure serialized before encryption.
#[derive(Serialize, Deserialize)]
struct LogPayload {
    level: String,
    module: String,
    message: String,
}

/// Encryption key bound to a specific calendar day.
struct DayKey {
    date: NaiveDate,
    key: LessSafeKey,
}

/// Forward-secret log manager.
///
/// Holds a reference to the database and the current day's encryption key.
pub struct LogManager {
    db: sfgw_db::Db,
    current_key: DayKey,
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS encrypted_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    date        TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_logs_date ON encrypted_logs(date);
";

const META_MASTER_KEY: &str = "log_master_key";

fn meta_day_key_name(date: NaiveDate) -> String {
    format!("log_key_{date}")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl LogManager {
    /// Initialise the log subsystem.
    ///
    /// Creates the `encrypted_logs` table if needed, generates a master key on
    /// first run, and derives today's day-key.
    pub async fn init(db: &sfgw_db::Db) -> Result<Self> {
        {
            let conn = db.lock().await;
            conn.execute_batch(SCHEMA_SQL)
                .context("failed to create encrypted_logs table")?;
        }

        // Ensure master key exists (held in SecureBox — encrypted in memory).
        let master_key_box = ensure_master_key(db).await?;

        let today = Utc::now().date_naive();
        let mut master_key_plain = master_key_box.open()
            .context("failed to decrypt master key from SecureBox")?;
        let day_key = ensure_day_key(db, &master_key_plain, today).await?;
        master_key_plain.zeroize();

        tracing::info!("log subsystem initialized (forward-secret encryption active)");

        Ok(Self {
            db: db.clone(),
            current_key: DayKey {
                date: today,
                key: day_key,
            },
        })
    }

    /// Encrypt and store a log entry for today.
    pub async fn write_log(&self, level: &str, module: &str, message: &str) -> Result<()> {
        let today = Utc::now().date_naive();

        // If the date rolled over we cannot write with the stale key; caller
        // should call `rotate_key` first.  We still allow writes so nothing is
        // lost, but warn.
        if today != self.current_key.date {
            tracing::warn!(
                "writing log with stale day-key (today={today}, key={}); call rotate_key",
                self.current_key.date
            );
        }

        let payload = serde_json::to_vec(&LogPayload {
            level: level.to_string(),
            module: module.to_string(),
            message: message.to_string(),
        })?;

        let (nonce_bytes, ciphertext) = encrypt(&self.current_key.key, &payload)?;
        let date_str = self.current_key.date.to_string();
        let nonce_b64 = B64.encode(nonce_bytes);
        let ct_b64 = B64.encode(&ciphertext);

        let conn = self.db.lock().await;
        conn.execute(
            "INSERT INTO encrypted_logs (date, nonce, ciphertext) VALUES (?1, ?2, ?3)",
            rusqlite::params![date_str, nonce_b64, ct_b64],
        )
        .context("failed to insert encrypted log")?;

        Ok(())
    }

    /// Read and decrypt all log entries for a given date.
    ///
    /// Returns an error if the day-key has been deleted (forward secrecy).
    pub async fn read_logs(&self, date: NaiveDate) -> Result<Vec<LogEntry>> {
        let key = self.load_day_key(date).await?;
        self.decrypt_logs_with_key(date, &key).await
    }

    /// Export (decrypt) logs for `date`, then **delete** the day-key so those
    /// logs can never be decrypted again.
    pub async fn export_logs(&self, date: NaiveDate) -> Result<Vec<LogEntry>> {
        let key = self.load_day_key(date).await?;
        let entries = self.decrypt_logs_with_key(date, &key).await?;
        self.delete_day_key(date).await?;
        Ok(entries)
    }

    /// Rotate to a new day-key (call once per day, e.g. from a scheduler).
    ///
    /// Derives and stores a key for today if it doesn't already exist, then
    /// updates the in-memory current key.
    pub async fn rotate_key(&mut self) -> Result<()> {
        let today = Utc::now().date_naive();
        if today == self.current_key.date {
            return Ok(());
        }

        let master_key_box = load_master_key(&self.db).await?;
        let mut master_key_plain = master_key_box.open()
            .context("failed to decrypt master key from SecureBox")?;
        let day_key = ensure_day_key(&self.db, &master_key_plain, today).await?;
        master_key_plain.zeroize();

        self.current_key = DayKey {
            date: today,
            key: day_key,
        };

        tracing::info!("log key rotated to {today}");
        Ok(())
    }

    /// Delete the day-key for `date`, achieving forward secrecy.
    pub async fn delete_day_key(&self, date: NaiveDate) -> Result<()> {
        let key_name = meta_day_key_name(date);
        let conn = self.db.lock().await;
        conn.execute("DELETE FROM meta WHERE key = ?1", rusqlite::params![key_name])
            .context("failed to delete day key")?;
        tracing::info!("deleted day-key for {date} (forward secrecy)");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Load a day-key from the meta table, returning an error if it was deleted.
    async fn load_day_key(&self, date: NaiveDate) -> Result<LessSafeKey> {
        let key_name = meta_day_key_name(date);
        let conn = self.db.lock().await;
        let raw: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                rusqlite::params![key_name],
                |row| row.get(0),
            )
            .with_context(|| {
                format!("day-key for {date} not found (deleted or never created)")
            })?;
        drop(conn);

        let mut key_bytes = B64.decode(&raw).context("invalid base64 in day key")?;
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| LogError::CryptoFailed("invalid AES key material".to_string()))?;
        key_bytes.zeroize();
        Ok(LessSafeKey::new(unbound))
    }

    /// Decrypt all log rows for a given date using the provided key.
    async fn decrypt_logs_with_key(
        &self,
        date: NaiveDate,
        key: &LessSafeKey,
    ) -> Result<Vec<LogEntry>> {
        let date_str = date.to_string();
        let conn = self.db.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, nonce, ciphertext, created_at FROM encrypted_logs WHERE date = ?1 ORDER BY id",
        )?;

        let rows: Vec<(i64, String, String, String)> = stmt
            .query_map(rusqlite::params![date_str], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(conn);

        let mut entries = Vec::with_capacity(rows.len());
        for (id, nonce_b64, ct_b64, created_at) in rows {
            let nonce_bytes = B64.decode(&nonce_b64)?;
            let ciphertext = B64.decode(&ct_b64)?;
            let plaintext = decrypt(key, &nonce_bytes, &ciphertext)?;
            let payload: LogPayload = serde_json::from_slice(&plaintext)?;
            entries.push(LogEntry {
                id,
                date: date_str.clone(),
                level: payload.level,
                module: payload.module,
                message: payload.message,
                created_at,
            });
        }

        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Key management helpers
// ---------------------------------------------------------------------------

/// Load the master key from the meta table, wrapped in a SecureBox.
async fn load_master_key(db: &sfgw_db::Db) -> Result<SecureBox<Vec<u8>>> {
    let conn = db.lock().await;
    let raw: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![META_MASTER_KEY],
            |row| row.get(0),
        )
        .context("master key not found in meta table")?;
    let key_bytes = B64.decode(&raw)?;
    Ok(SecureBox::new(key_bytes).context("failed to wrap master key in SecureBox")?)
}

/// Ensure a master key exists; generate one if this is the first run.
/// Returns the master key wrapped in a SecureBox (encrypted in memory).
async fn ensure_master_key(db: &sfgw_db::Db) -> Result<SecureBox<Vec<u8>>> {
    let conn = db.lock().await;
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![META_MASTER_KEY],
            |row| row.get(0),
        )
        .ok();

    if let Some(raw) = existing {
        let key_bytes = B64.decode(&raw)?;
        return Ok(SecureBox::new(key_bytes).context("failed to wrap master key in SecureBox")?);
    }

    // Generate a fresh 256-bit master key.
    let rng = SystemRandom::new();
    let mut mk = vec![0u8; 32];
    rng.fill(&mut mk)
        .map_err(|_| LogError::CryptoFailed("RNG failure".to_string()))?;
    let encoded = B64.encode(&mk);

    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![META_MASTER_KEY, encoded],
    )
    .context("failed to store master key")?;

    tracing::info!("generated new log master key");
    Ok(SecureBox::new(mk).context("failed to wrap master key in SecureBox")?)
}

/// Derive a day-key via HKDF-SHA256 and store it in the meta table if absent.
async fn ensure_day_key(
    db: &sfgw_db::Db,
    master_key: &[u8],
    date: NaiveDate,
) -> Result<LessSafeKey> {
    let key_name = meta_day_key_name(date);

    // Check if already stored.
    {
        let conn = db.lock().await;
        let existing: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                rusqlite::params![key_name],
                |row| row.get(0),
            )
            .ok();

        if let Some(raw) = existing {
            let mut key_bytes = B64.decode(&raw).context("invalid base64 in day key")?;
            let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
                .map_err(|_| LogError::CryptoFailed(format!("invalid AES key for {date}")))?;
            key_bytes.zeroize();
            return Ok(LessSafeKey::new(unbound));
        }
    }

    // Derive via HKDF.
    let key_bytes = derive_day_key_bytes(master_key, date)?;

    // Store.
    let encoded = B64.encode(&key_bytes);
    {
        let conn = db.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![key_name, encoded],
        )
        .context("failed to store day key")?;
    }

    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| LogError::CryptoFailed("invalid derived key".to_string()))?;
    Ok(LessSafeKey::new(unbound))
}

/// Pure derivation: HKDF-SHA256(master_key, salt=[], info="sfgw-log-YYYY-MM-DD") → 32 bytes.
fn derive_day_key_bytes(master_key: &[u8], date: NaiveDate) -> Result<[u8; 32]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(master_key);
    let info_str = format!("sfgw-log-{date}");
    let info = [info_str.as_bytes()];
    let okm = prk
        .expand(&info, HkdfLen(32))
        .map_err(|_| LogError::CryptoFailed("HKDF expand failed".to_string()))?;
    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .map_err(|_| LogError::CryptoFailed("HKDF fill failed".to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// AES-256-GCM encrypt / decrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with `key`, returning `(nonce, ciphertext_with_tag)`.
fn encrypt(key: &LessSafeKey, plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>)> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| LogError::CryptoFailed("RNG failure generating nonce".to_string()))?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| LogError::CryptoFailed("AES-GCM seal failed".to_string()))?;

    Ok((nonce_bytes, in_out))
}

/// Decrypt `ciphertext_with_tag` using `key` and `nonce_bytes`.
fn decrypt(key: &LessSafeKey, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce_bytes.len() != 12 {
        return Err(LogError::CryptoFailed(format!("invalid nonce length: expected 12, got {}", nonce_bytes.len())));
    }

    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| LogError::CryptoFailed("AES-GCM decryption failed (wrong key or tampered data)".to_string()))?;

    Ok(plaintext.to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Create an in-memory DB with the required schema.
    async fn test_db() -> sfgw_db::Db {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .unwrap();
        conn.execute_batch(SCHEMA_SQL).unwrap();
        Arc::new(Mutex::new(conn))
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let master = [0xABu8; 32];
        let date = NaiveDate::from_ymd_opt(2025, 6, 15).unwrap();
        let k1 = derive_day_key_bytes(&master, date).unwrap();
        let k2 = derive_day_key_bytes(&master, date).unwrap();
        assert_eq!(k1, k2, "same master + same date must yield same key");
    }

    #[test]
    fn different_dates_yield_different_keys() {
        let master = [0xCDu8; 32];
        let d1 = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let d2 = NaiveDate::from_ymd_opt(2025, 1, 2).unwrap();
        let k1 = derive_day_key_bytes(&master, d1).unwrap();
        let k2 = derive_day_key_bytes(&master, d2).unwrap();
        assert_ne!(k1, k2, "different dates must yield different keys");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master = [0x42u8; 32];
        let date = NaiveDate::from_ymd_opt(2025, 3, 10).unwrap();
        let key_bytes = derive_day_key_bytes(&master, date).unwrap();
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        let key = LessSafeKey::new(unbound);

        let plaintext = b"hello forward secrecy";
        let (nonce, ct) = encrypt(&key, plaintext).unwrap();

        // Rebuild key to prove we can decrypt with the same material.
        let unbound2 = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        let key2 = LessSafeKey::new(unbound2);
        let decrypted = decrypt(&key2, &nonce, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key_bytes_a = derive_day_key_bytes(&[0x01u8; 32], NaiveDate::from_ymd_opt(2025, 1, 1).unwrap()).unwrap();
        let key_bytes_b = derive_day_key_bytes(&[0x02u8; 32], NaiveDate::from_ymd_opt(2025, 1, 1).unwrap()).unwrap();

        let key_a = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes_a).unwrap());
        let key_b = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes_b).unwrap());

        let (nonce, ct) = encrypt(&key_a, b"secret").unwrap();
        assert!(decrypt(&key_b, &nonce, &ct).is_err(), "wrong key must fail");
    }

    #[tokio::test]
    async fn write_read_roundtrip() {
        let db = test_db().await;
        let mgr = LogManager::init(&db).await.unwrap();

        mgr.write_log("INFO", "test_mod", "hello world").await.unwrap();
        mgr.write_log("ERROR", "test_mod", "something broke").await.unwrap();

        let today = Utc::now().date_naive();
        let entries = mgr.read_logs(today).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "hello world");
        assert_eq!(entries[1].level, "ERROR");
    }

    #[tokio::test]
    async fn forward_secrecy_delete_key_prevents_read() {
        let db = test_db().await;
        let mgr = LogManager::init(&db).await.unwrap();

        mgr.write_log("INFO", "fs_test", "will be unreadable").await.unwrap();

        let today = Utc::now().date_naive();

        // Can read before deletion.
        assert!(mgr.read_logs(today).await.is_ok());

        // Delete the day key.
        mgr.delete_day_key(today).await.unwrap();

        // Now reading must fail.
        assert!(
            mgr.read_logs(today).await.is_err(),
            "reading logs after key deletion must fail (forward secrecy)"
        );
    }

    #[tokio::test]
    async fn export_deletes_key() {
        let db = test_db().await;
        let mgr = LogManager::init(&db).await.unwrap();

        mgr.write_log("INFO", "export_test", "exported entry").await.unwrap();

        let today = Utc::now().date_naive();
        let exported = mgr.export_logs(today).await.unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].message, "exported entry");

        // After export, key is gone — reading must fail.
        assert!(
            mgr.read_logs(today).await.is_err(),
            "key should have been deleted after export"
        );
    }
}
