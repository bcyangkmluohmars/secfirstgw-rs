-- Migration 012: UPnP/NAT-PMP port mappings
-- Stores dynamically-created port mappings requested by LAN clients.
-- UPnP is disabled by default for security (see settings table).

CREATE TABLE IF NOT EXISTS upnp_mappings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol        TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
    external_port   INTEGER NOT NULL CHECK(external_port BETWEEN 1 AND 65535),
    internal_ip     TEXT NOT NULL,
    internal_port   INTEGER NOT NULL CHECK(internal_port BETWEEN 1 AND 65535),
    description     TEXT NOT NULL DEFAULT '',
    client_ip       TEXT NOT NULL,
    ttl_seconds     INTEGER NOT NULL CHECK(ttl_seconds > 0),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_upnp_proto_extport
    ON upnp_mappings(protocol, external_port);

CREATE INDEX IF NOT EXISTS idx_upnp_client_ip
    ON upnp_mappings(client_ip);

CREATE INDEX IF NOT EXISTS idx_upnp_expires
    ON upnp_mappings(expires_at);
