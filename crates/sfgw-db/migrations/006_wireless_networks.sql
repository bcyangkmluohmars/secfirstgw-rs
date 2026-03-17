-- Wireless network (SSID) configuration.
-- Each row defines a WiFi network that can be pushed to APs via system_cfg.

CREATE TABLE IF NOT EXISTS wireless_networks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid          TEXT NOT NULL,
    security      TEXT NOT NULL DEFAULT 'wpa2',    -- 'open', 'wpa2', 'wpa3'
    psk           TEXT,                             -- WPA2/WPA3 pre-shared key
    hidden        INTEGER NOT NULL DEFAULT 0,
    band          TEXT NOT NULL DEFAULT 'both',     -- 'both', '2g', '5g'
    vlan_id       INTEGER,                          -- optional VLAN tag for this SSID
    is_guest      INTEGER NOT NULL DEFAULT 0,
    l2_isolation  INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_wireless_ssid ON wireless_networks(ssid);
