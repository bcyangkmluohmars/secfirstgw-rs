-- Migration 004: Network zone definitions
-- Stores default and user-configured network zones (LAN, MGMT, Guest, DMZ)
-- with subnet, gateway, and DHCP settings.

CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    zone TEXT NOT NULL,
    vlan_id INTEGER,
    subnet TEXT NOT NULL,
    gateway TEXT NOT NULL,
    dhcp_start TEXT,
    dhcp_end TEXT,
    dhcp_enabled INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
