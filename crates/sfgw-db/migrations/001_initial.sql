-- Migration 001: Initial schema
-- Core tables for secfirstgw-rs

CREATE TABLE IF NOT EXISTS interfaces (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL UNIQUE,
    mac       TEXT NOT NULL DEFAULT '',
    ips       TEXT NOT NULL DEFAULT '[]',
    mtu       INTEGER NOT NULL DEFAULT 1500,
    is_up     INTEGER NOT NULL DEFAULT 0,
    role      TEXT NOT NULL DEFAULT 'lan',
    vlan_id   INTEGER,
    enabled   INTEGER NOT NULL DEFAULT 1,
    config    TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    chain     TEXT NOT NULL,
    priority  INTEGER NOT NULL DEFAULT 0,
    rule      TEXT NOT NULL,
    enabled   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mac        TEXT NOT NULL UNIQUE,
    name       TEXT,
    model      TEXT,
    ip         TEXT,
    adopted    INTEGER NOT NULL DEFAULT 0,
    last_seen  TEXT,
    config     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS vpn_tunnels (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL UNIQUE,
    type      TEXT NOT NULL,
    enabled   INTEGER NOT NULL DEFAULT 0,
    config    TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS vpn_peers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tunnel_id           INTEGER NOT NULL REFERENCES vpn_tunnels(id) ON DELETE CASCADE,
    name                TEXT,
    public_key          TEXT NOT NULL,
    private_key_enc     TEXT NOT NULL,
    preshared_key       TEXT,
    address             TEXT NOT NULL,
    address_v6          TEXT,
    allowed_ips         TEXT NOT NULL DEFAULT '[]',
    endpoint            TEXT,
    persistent_keepalive INTEGER,
    routing_mode        TEXT NOT NULL DEFAULT 'split',
    dns                 TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_peers_tunnel_pubkey
    ON vpn_peers(tunnel_id, public_key);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token         TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    tls_session   TEXT NOT NULL,
    client_ip     TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    envelope_key  TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ids_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    detector    TEXT NOT NULL,
    source_mac  TEXT,
    source_ip   TEXT,
    interface   TEXT NOT NULL,
    vlan        INTEGER,
    description TEXT NOT NULL
);

