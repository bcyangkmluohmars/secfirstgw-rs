-- Migration 008: Custom zone definitions
-- Stores user-defined network zones (IoT, VPN, Custom) with configurable
-- inbound/outbound/forward policies and allowed services.

CREATE TABLE IF NOT EXISTS custom_zones (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    vlan_id INTEGER NOT NULL,
    policy_inbound TEXT NOT NULL DEFAULT 'drop',
    policy_outbound TEXT NOT NULL DEFAULT 'drop',
    policy_forward TEXT NOT NULL DEFAULT 'drop',
    allowed_services TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Enforce unique VLAN IDs across custom zones.
CREATE UNIQUE INDEX IF NOT EXISTS idx_custom_zones_vlan_id ON custom_zones(vlan_id);

-- Enforce zone name format: lowercase alphanumeric + hyphens, 1-32 chars.
-- SQLite CHECK constraints validated at insert/update time.
-- name validation: only lowercase letters, digits, hyphens; must start with a letter.
-- vlan_id validation: 2-4094 (VLAN 1 is void/reserved, 0 is WAN).
-- policy validation: must be 'drop' or 'accept'.
