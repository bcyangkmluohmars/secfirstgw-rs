-- Migration 002: Firmware manifests
-- Added in schema v2 for firmware management

CREATE TABLE IF NOT EXISTS firmware_manifests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    model      TEXT NOT NULL,
    version    TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    url        TEXT NOT NULL,
    signature  TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_firmware_manifests_model_version
    ON firmware_manifests(model, version);
