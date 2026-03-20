-- Migration 012: Firmware update settings
-- Self-update configuration for the sfgw binary

CREATE TABLE IF NOT EXISTS firmware_settings (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    update_channel       TEXT NOT NULL DEFAULT 'stable',
    auto_check           INTEGER NOT NULL DEFAULT 1,
    check_interval_hours INTEGER NOT NULL DEFAULT 24,
    last_check           TEXT,
    update_url           TEXT NOT NULL DEFAULT 'https://api.github.com/repos/bcyangkmluohmars/secfirstgw-rs/releases'
);

INSERT OR IGNORE INTO firmware_settings (id) VALUES (1);
