-- WiFi advanced features: channel control, TX power, bandwidth, fast roaming, band steering.

ALTER TABLE wireless_networks ADD COLUMN channel INTEGER NOT NULL DEFAULT 0;       -- 0 = auto
ALTER TABLE wireless_networks ADD COLUMN tx_power INTEGER NOT NULL DEFAULT 0;      -- dBm, 0 = auto
ALTER TABLE wireless_networks ADD COLUMN bandwidth TEXT NOT NULL DEFAULT 'auto';   -- 'HT20', 'HT40', 'VHT80', 'auto'
ALTER TABLE wireless_networks ADD COLUMN fast_roaming INTEGER NOT NULL DEFAULT 0;  -- 802.11r
ALTER TABLE wireless_networks ADD COLUMN band_steering INTEGER NOT NULL DEFAULT 0; -- prefer 5GHz
