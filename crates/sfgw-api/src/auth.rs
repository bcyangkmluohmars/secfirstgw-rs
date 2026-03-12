// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result, bail};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::SaltString,
};
use chrono::{DateTime, Duration, Utc};
use ring::rand::SecureRandom;
use serde::Serialize;
use uuid::Uuid;

/// A user record from the database.
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub created_at: String,
}

/// A session record from the database.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub token: String,
    pub user_id: i64,
    pub client_ip: String,
    pub fingerprint: String,
    pub tls_session: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Hash a password using Argon2id.
pub fn hash_password(password: &str) -> Result<String> {
    let rng = ring::rand::SystemRandom::new();
    let mut salt_bytes = [0u8; 16];
    rng.fill(&mut salt_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate random salt"))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("failed to encode salt: {e}"))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("invalid password hash: {e}"))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Create a new session for the given user, returning the session token.
///
/// The session expires in 24 hours.
pub async fn create_session(
    db: &sfgw_db::Db,
    user_id: i64,
    client_ip: &str,
    fingerprint: &str,
    tls_session: &str,
) -> Result<(String, DateTime<Utc>)> {
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + Duration::hours(24);
    let created_str = now.to_rfc3339();
    let expires_str = expires_at.to_rfc3339();

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO sessions (token, user_id, tls_session, client_ip, fingerprint, envelope_key, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            token,
            user_id,
            tls_session,
            client_ip,
            fingerprint,
            "",  // envelope_key — not used for basic auth sessions
            created_str,
            expires_str,
        ],
    )
    .context("failed to insert session")?;

    Ok((token, expires_at))
}

/// Validate a session token. Returns the user ID if the session is valid.
///
/// A session is valid if:
/// - The token exists in the database
/// - It has not expired
/// - The client IP matches
/// - The fingerprint matches
pub async fn validate_session(
    db: &sfgw_db::Db,
    token: &str,
    client_ip: &str,
    fingerprint: &str,
) -> Result<Option<i64>> {
    let conn = db.lock().await;

    let result = conn.query_row(
        "SELECT user_id, client_ip, fingerprint, expires_at FROM sessions WHERE token = ?1",
        rusqlite::params![token],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    );

    match result {
        Ok((user_id, stored_ip, stored_fp, expires_str)) => {
            // Check expiry
            let expires_at = DateTime::parse_from_rfc3339(&expires_str)
                .context("invalid expires_at in session")?;
            if Utc::now() > expires_at {
                // Session expired — clean it up
                let _ = conn.execute(
                    "DELETE FROM sessions WHERE token = ?1",
                    rusqlite::params![token],
                );
                return Ok(None);
            }

            // Check IP match
            if stored_ip != client_ip {
                return Ok(None);
            }

            // Check fingerprint match
            if stored_fp != fingerprint {
                return Ok(None);
            }

            Ok(Some(user_id))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => bail!("database error validating session: {e}"),
    }
}

/// Look up a user by ID.
pub async fn get_user_by_id(db: &sfgw_db::Db, user_id: i64) -> Result<Option<User>> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT id, username, role, created_at FROM users WHERE id = ?1",
        rusqlite::params![user_id],
        |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                created_at: row.get(3)?,
            })
        },
    );

    match result {
        Ok(user) => Ok(Some(user)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => bail!("database error looking up user: {e}"),
    }
}

/// Look up a user by username.
pub async fn get_user_by_username(db: &sfgw_db::Db, username: &str) -> Result<Option<(User, String)>> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT id, username, role, created_at, password_hash FROM users WHERE username = ?1",
        rusqlite::params![username],
        |row| {
            Ok((
                User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    role: row.get(2)?,
                    created_at: row.get(3)?,
                },
                row.get::<_, String>(4)?,
            ))
        },
    );

    match result {
        Ok(pair) => Ok(Some(pair)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => bail!("database error looking up user: {e}"),
    }
}

/// Count total users in the database.
pub async fn user_count(db: &sfgw_db::Db) -> Result<i64> {
    let conn = db.lock().await;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .context("failed to count users")?;
    Ok(count)
}

/// Create a new user. Returns the user ID.
pub async fn create_user(
    db: &sfgw_db::Db,
    username: &str,
    password_hash: &str,
    role: &str,
) -> Result<i64> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, password_hash, role],
    )
    .context("failed to create user")?;
    Ok(conn.last_insert_rowid())
}

/// Delete a session by token.
pub async fn delete_session(db: &sfgw_db::Db, token: &str) -> Result<()> {
    let conn = db.lock().await;
    conn.execute(
        "DELETE FROM sessions WHERE token = ?1",
        rusqlite::params![token],
    )
    .context("failed to delete session")?;
    Ok(())
}
