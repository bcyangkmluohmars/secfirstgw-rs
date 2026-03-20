-- Migration 008: WAN health check configuration, flap detection, sticky sessions, zone pinning
-- Extends per-interface WAN health monitoring beyond ICMP ping

CREATE TABLE IF NOT EXISTS wan_health_config (
    id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL UNIQUE,
    -- Health check type: 'icmp', 'http', 'dns'
    health_check_type TEXT NOT NULL DEFAULT 'icmp',
    -- JSON config for the health check type (url, expected_status, domain, server)
    health_check_config TEXT NOT NULL DEFAULT '{}',
    -- Flap detection: max state changes within window before suppressing failover
    flap_threshold INTEGER NOT NULL DEFAULT 5,
    -- Flap detection window in seconds
    flap_window_secs INTEGER NOT NULL DEFAULT 60,
    -- Sticky sessions: preserve existing connections on failover
    sticky_sessions INTEGER NOT NULL DEFAULT 0,
    -- Zone pinning: force specific zone traffic through this WAN (nullable, e.g. 'DMZ', 'LAN')
    zone_pin TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (interface) REFERENCES wan_configs(interface) ON DELETE CASCADE
);

-- Flap event log for diagnostics
CREATE TABLE IF NOT EXISTS wan_flap_log (
    id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL,
    -- 'up' or 'down'
    new_state TEXT NOT NULL,
    -- Whether failover was suppressed due to flap threshold
    suppressed INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_wan_flap_log_interface ON wan_flap_log(interface, timestamp);
