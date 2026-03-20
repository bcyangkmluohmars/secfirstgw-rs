-- Migration 007: Dynamic DNS (DDNS) client configuration
--
-- Stores per-hostname DDNS update configurations.
-- Supports DynDNS2 protocol (DynDNS, No-IP, etc.), DuckDNS, and Cloudflare.

CREATE TABLE IF NOT EXISTS ddns_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'dyndns2',
    server TEXT,
    username TEXT,
    password TEXT,
    wan_interface TEXT NOT NULL DEFAULT 'eth8',
    update_interval_secs INTEGER NOT NULL DEFAULT 300,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_ip TEXT,
    last_update TEXT,
    last_status TEXT
);
