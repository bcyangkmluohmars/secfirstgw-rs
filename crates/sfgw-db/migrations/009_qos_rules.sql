-- Migration 008: QoS / Traffic Shaping rules
-- HTB-based traffic control via tc + iptables MARK

CREATE TABLE IF NOT EXISTS qos_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    interface       TEXT NOT NULL,
    direction       TEXT NOT NULL DEFAULT 'egress',  -- 'egress' or 'ingress'
    bandwidth_kbps  INTEGER NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 4,       -- 1 (highest) to 7 (lowest)
    match_protocol  TEXT,                              -- 'tcp', 'udp', 'icmp', or NULL for any
    match_port_min  INTEGER,                           -- start of port range (NULL = any)
    match_port_max  INTEGER,                           -- end of port range (NULL = match_port_min)
    match_ip        TEXT,                              -- IP or CIDR to match (NULL = any)
    match_dscp      INTEGER,                           -- DSCP value 0-63 (NULL = any)
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_qos_rules_interface ON qos_rules(interface);
