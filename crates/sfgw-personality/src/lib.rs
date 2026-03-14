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
pub fn set(personality: Personality) {
    ACTIVE.store(personality as u8, Ordering::Relaxed);
    tracing::info!(personality = personality.name(), "personality switched");
}
