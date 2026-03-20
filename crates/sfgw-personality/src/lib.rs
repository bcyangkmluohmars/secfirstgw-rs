// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Personality layer — SecFirstGW has attitude.
//!
//! Switchable personalities for error messages, honeypot responses, and
//! everything else that gives the gateway its character.
//!
//! Open source means everyone can add their own style. Just add a variant
//! to [`Personality`], fill in the message arrays in [`messages`], and
//! submit a PR.

pub mod honeypot;
pub mod messages;

use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::Context;

/// The active personality index. Defaults to `Kevin` (0).
static ACTIVE: AtomicU8 = AtomicU8::new(0);

/// Available personalities.
///
/// Want to add your own? Three steps:
/// 1. Add a variant here
/// 2. Fill in the message arrays in [`messages`]
/// 3. Submit a PR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Personality {
    /// The OG — German/English street slang, zero filter.
    Kevin = 0,
    /// Corporate compliance mode. Stock im Arsch.
    Corporate = 1,
    /// Pirate mode. Arrr.
    Pirate = 2,
    /// Zen master. Calm, cryptic, slightly condescending.
    Zen = 3,
    /// BOFH — Bastard Operator From Hell. Classic sysadmin energy.
    Bofh = 4,
    /// Unreal Tournament announcer. HEADSHOT!
    UnrealTournament = 5,
    /// Gaming Legends — iconic quotes from gaming history.
    GamingLegends = 6,
}

impl Personality {
    /// All available personalities, for iteration/display.
    pub const ALL: &[Personality] = &[
        Personality::Kevin,
        Personality::Corporate,
        Personality::Pirate,
        Personality::Zen,
        Personality::Bofh,
        Personality::UnrealTournament,
        Personality::GamingLegends,
    ];

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Personality::Kevin => "kevin",
            Personality::Corporate => "corporate",
            Personality::Pirate => "pirate",
            Personality::Zen => "zen",
            Personality::Bofh => "bofh",
            Personality::UnrealTournament => "unreal-tournament",
            Personality::GamingLegends => "gaming-legends",
        }
    }

    /// Short description.
    pub fn description(self) -> &'static str {
        match self {
            Personality::Kevin => "German/English street slang, zero filter",
            Personality::Corporate => "stock im arsch",
            Personality::Pirate => "arrr, matey",
            Personality::Zen => "calm, cryptic, slightly condescending",
            Personality::Bofh => "Bastard Operator From Hell",
            Personality::UnrealTournament => "HEADSHOT! DOUBLE KILL! GODLIKE!",
            Personality::GamingLegends => "iconic quotes from gaming history",
        }
    }

    /// Parse from string name (case-insensitive).
    pub fn from_name(name: &str) -> Option<Personality> {
        match name.to_ascii_lowercase().as_str() {
            "kevin" => Some(Personality::Kevin),
            "corporate" => Some(Personality::Corporate),
            "pirate" => Some(Personality::Pirate),
            "zen" => Some(Personality::Zen),
            "bofh" => Some(Personality::Bofh),
            "unreal-tournament" | "unreal" | "ut" => Some(Personality::UnrealTournament),
            "gaming-legends" | "gaming" | "legends" => Some(Personality::GamingLegends),
            _ => None,
        }
    }

    fn from_u8(v: u8) -> Personality {
        match v {
            0 => Personality::Kevin,
            1 => Personality::Corporate,
            2 => Personality::Pirate,
            3 => Personality::Zen,
            4 => Personality::Bofh,
            5 => Personality::UnrealTournament,
            6 => Personality::GamingLegends,
            _ => Personality::Kevin,
        }
    }
}

/// Get the currently active personality.
pub fn active() -> Personality {
    Personality::from_u8(ACTIVE.load(Ordering::Relaxed))
}

/// Switch to a different personality. Takes effect immediately.
///
/// This only updates the in-memory state. Use [`save`] to persist across
/// restarts, or [`set_and_save`] for both in one call.
pub fn set(personality: Personality) {
    ACTIVE.store(personality as u8, Ordering::Relaxed);
    tracing::info!(personality = personality.name(), "personality switched");
}

// ---------------------------------------------------------------------------
// Persistence (via meta table in sfgw-db)
// ---------------------------------------------------------------------------

/// Meta key for the active personality setting.
const META_KEY_PERSONALITY: &str = "personality";

/// Load the saved personality from the database and activate it.
///
/// If no personality is saved (fresh install), leaves the default (`Kevin`)
/// in place and returns `Personality::Kevin`.
pub async fn load(db: &sfgw_db::Db) -> anyhow::Result<Personality> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        [META_KEY_PERSONALITY],
        |r| r.get::<_, String>(0),
    );
    match result {
        Ok(val) => {
            let p = Personality::from_name(&val).unwrap_or(Personality::Kevin);
            ACTIVE.store(p as u8, Ordering::Relaxed);
            tracing::info!(personality = p.name(), "personality loaded from database");
            Ok(p)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            tracing::debug!("no saved personality, defaulting to kevin");
            Ok(Personality::Kevin)
        }
        Err(e) => Err(e).context("failed to read personality setting"),
    }
}

/// Persist the given personality to the database.
pub async fn save(db: &sfgw_db::Db, personality: Personality) -> anyhow::Result<()> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![META_KEY_PERSONALITY, personality.name()],
    )
    .context("failed to write personality setting")?;
    Ok(())
}

/// Switch personality and persist the choice. Convenience wrapper around
/// [`set`] + [`save`].
pub async fn set_and_save(db: &sfgw_db::Db, personality: Personality) -> anyhow::Result<()> {
    set(personality);
    save(db, personality).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_default_when_no_row() {
        let db = sfgw_db::open_in_memory().await.unwrap();
        let p = load(&db).await.unwrap();
        assert_eq!(p, Personality::Kevin, "default personality should be kevin");
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip() {
        let db = sfgw_db::open_in_memory().await.unwrap();

        save(&db, Personality::Pirate).await.unwrap();

        // Reset in-memory to Kevin so we can verify load actually changes it
        ACTIVE.store(Personality::Kevin as u8, Ordering::Relaxed);

        let p = load(&db).await.unwrap();
        assert_eq!(p, Personality::Pirate);
        assert_eq!(
            active(),
            Personality::Pirate,
            "load should activate the personality"
        );
    }

    #[tokio::test]
    async fn test_set_and_save() {
        let db = sfgw_db::open_in_memory().await.unwrap();

        set_and_save(&db, Personality::Bofh).await.unwrap();
        assert_eq!(active(), Personality::Bofh, "in-memory should be updated");

        // Verify it's in the DB
        let conn = db.lock().await;
        let val: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_KEY_PERSONALITY],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(val, "bofh");
    }

    #[tokio::test]
    async fn test_load_unknown_value_defaults_to_kevin() {
        let db = sfgw_db::open_in_memory().await.unwrap();

        // Manually insert a garbage value
        {
            let conn = db.lock().await;
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![META_KEY_PERSONALITY, "nonexistent-personality"],
            )
            .unwrap();
        }

        let p = load(&db).await.unwrap();
        assert_eq!(
            p,
            Personality::Kevin,
            "unknown personality should default to kevin"
        );
    }

    #[tokio::test]
    async fn test_save_overwrites_previous() {
        let db = sfgw_db::open_in_memory().await.unwrap();

        save(&db, Personality::Zen).await.unwrap();
        save(&db, Personality::Corporate).await.unwrap();

        ACTIVE.store(Personality::Kevin as u8, Ordering::Relaxed);
        let p = load(&db).await.unwrap();
        assert_eq!(
            p,
            Personality::Corporate,
            "second save should overwrite first"
        );
    }
}
