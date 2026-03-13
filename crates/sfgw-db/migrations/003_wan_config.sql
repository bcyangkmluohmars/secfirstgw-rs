-- Migration 003: WAN port configuration
-- Per-interface WAN connection type (DHCP, Static, PPPoE, DS-Lite, VLAN)

CREATE TABLE IF NOT EXISTS wan_configs (
    id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL UNIQUE,
    config TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    weight INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
