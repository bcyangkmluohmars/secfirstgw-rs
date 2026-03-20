-- Migration 014: Site-to-site VPN mesh
-- WireGuard-based site-to-site mesh with auto-failover

CREATE TABLE IF NOT EXISTS site_meshes (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT NOT NULL UNIQUE,
    topology              TEXT NOT NULL DEFAULT 'full-mesh',
    listen_port           INTEGER NOT NULL DEFAULT 51820,
    keepalive_interval    INTEGER NOT NULL DEFAULT 25,
    failover_timeout_secs INTEGER NOT NULL DEFAULT 90,
    enabled               INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS site_mesh_peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mesh_id         INTEGER NOT NULL REFERENCES site_meshes(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    endpoint        TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    private_key_enc TEXT,
    preshared_key   TEXT,
    local_subnets   TEXT NOT NULL DEFAULT '[]',
    remote_subnets  TEXT NOT NULL DEFAULT '[]',
    priority        INTEGER NOT NULL DEFAULT 0,
    is_local        INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_site_mesh_peers_mesh_pubkey
    ON site_mesh_peers(mesh_id, public_key);

CREATE INDEX IF NOT EXISTS idx_site_mesh_peers_mesh_id
    ON site_mesh_peers(mesh_id);
