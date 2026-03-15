-- Migration 005: VLAN Trunk Model
-- Transitions the interfaces table from the role-based model (v0.0.3) to the
-- PVID + tagged VLAN trunk model (v0.1.0).
--
-- Role → PVID mapping rationale:
--   lan   → pvid=10  (LAN is VLAN 10, not untagged VLAN 1 — avoids industry "untagged mess")
--   mgmt  → pvid=3000 (dedicated management VLAN, high number to avoid collision)
--   guest → pvid=3001 (guest isolation zone)
--   dmz   → pvid=3002 (DMZ isolation zone)
--   wan   → pvid=0   (WAN is a completely separate world from internal VLANs;
--                      pvid=0 signals "not an internal VLAN port")
--   other → pvid=10  (safe default: unknown roles fall back to LAN)
--
-- The role and vlan_id columns are removed. SQLite pre-3.35 does not support
-- DROP COLUMN, so we use the rename-create-copy-drop pattern.

-- Step 1: Rebuild interfaces table without role/vlan_id, adding pvid/tagged_vlans

ALTER TABLE interfaces RENAME TO interfaces_old;

CREATE TABLE interfaces (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    mac          TEXT NOT NULL DEFAULT '',
    ips          TEXT NOT NULL DEFAULT '[]',
    mtu          INTEGER NOT NULL DEFAULT 1500,
    is_up        INTEGER NOT NULL DEFAULT 0,
    pvid         INTEGER NOT NULL DEFAULT 10,
    tagged_vlans TEXT NOT NULL DEFAULT '[]',
    enabled      INTEGER NOT NULL DEFAULT 1,
    config       TEXT NOT NULL DEFAULT '{}'
);

INSERT INTO interfaces (id, name, mac, ips, mtu, is_up, pvid, tagged_vlans, enabled, config)
SELECT id, name, mac, ips, mtu, is_up,
    CASE
        WHEN role = 'lan'   THEN 10
        WHEN role = 'mgmt'  THEN 3000
        WHEN role = 'guest' THEN 3001
        WHEN role = 'dmz'   THEN 3002
        WHEN role = 'wan'   THEN 0
        ELSE 10
    END,
    '[]',
    enabled, config
FROM interfaces_old;

DROP TABLE interfaces_old;

-- Step 2: Insert VLAN 1 void entry
-- VLAN 1 is the "factory default untagged" VLAN on most switches.
-- We create it as disabled with no subnet — any traffic on VLAN 1 will be
-- DROPped by firewall rules. This prevents accidental forwarding of untagged
-- frames from misconfigured devices.
INSERT OR IGNORE INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled)
VALUES ('Void', 'void', 1, '0.0.0.0/32', '0.0.0.0', 0, 0);

-- Step 3: Update LAN network to VLAN 10
-- LAN was previously untagged (NULL) or VLAN 1. Move it to VLAN 10.
-- Only updates if currently NULL or 1 — does not override user changes.
UPDATE networks SET vlan_id = 10 WHERE zone = 'lan' AND (vlan_id IS NULL OR vlan_id = 1);
