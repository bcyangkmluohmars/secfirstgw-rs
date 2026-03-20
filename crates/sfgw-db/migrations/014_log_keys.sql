-- Migration 014: Forward-secret log key tracking
-- Tracks daily key state for the ratcheting log encryption system.
-- The actual keys live in the meta table; this tracks metadata
-- (exported status, destroyed status) per day.

CREATE TABLE IF NOT EXISTS log_keys (
    date        TEXT PRIMARY KEY,
    exported    INTEGER NOT NULL DEFAULT 0,
    destroyed   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
