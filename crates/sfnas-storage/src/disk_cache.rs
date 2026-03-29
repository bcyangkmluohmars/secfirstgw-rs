#![deny(unsafe_code)]

//! Background storage data cache.
//!
//! Queries smartctl and mdadm in a background thread every 60 seconds.
//! API handlers read from the cache (< 1 ms) instead of spawning
//! expensive subprocesses on every request.

use crate::{Disk, RaidArray, RaidDetail};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// How often to refresh cached data in the background.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Cached snapshot of all storage data.
#[derive(Clone)]
struct StorageSnapshot {
    disks: Vec<Disk>,
    arrays: Vec<RaidDetail>,
}

/// Thread-safe storage data cache.
///
/// Caches SMART disk data and RAID array info so the API never blocks
/// on `smartctl` or `mdadm` during request handling.
#[derive(Clone)]
pub struct DiskCache {
    inner: Arc<Mutex<Option<StorageSnapshot>>>,
}

impl DiskCache {
    /// Create a new cache and populate it with an initial synchronous scan.
    pub fn new() -> Self {
        let cache = Self {
            inner: Arc::new(Mutex::new(None)),
        };
        cache.refresh();
        cache
    }

    /// Start the background refresh thread. Call once at startup.
    pub fn start_background_refresh(&self) {
        let cache = self.clone();
        match std::thread::Builder::new()
            .name("storage-cache".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(REFRESH_INTERVAL);
                    cache.refresh();
                }
            }) {
            Ok(_) => {
                info!("storage cache background refresh started (interval: {REFRESH_INTERVAL:?})")
            }
            Err(e) => {
                warn!(error = %e, "failed to spawn storage cache thread — running without background refresh")
            }
        }
    }

    /// Get the cached disks. Returns empty vec if no data yet.
    pub fn get(&self) -> Vec<Disk> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| s.disks.clone())
            .unwrap_or_default()
    }

    /// Get cached RAID array details (parsed mdadm --detail output).
    pub fn get_arrays(&self) -> Vec<RaidDetail> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| s.arrays.clone())
            .unwrap_or_default()
    }

    /// Get cached array count.
    pub fn array_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| s.arrays.len())
            .unwrap_or(0)
    }

    /// Force a refresh (called by background thread and at init).
    fn refresh(&self) {
        let start = Instant::now();

        // --- Disks + SMART ---
        debug!("storage cache: enumerating disks...");
        let disk_paths = match Disk::list_all() {
            Ok(p) => {
                debug!(count = p.len(), "storage cache: found SATA disks");
                p
            }
            Err(e) => {
                warn!(error = %e, "storage cache: failed to list disks");
                Vec::new()
            }
        };

        let mut disks = Vec::with_capacity(disk_paths.len());
        for path in &disk_paths {
            debug!(disk = %path.display(), "storage cache: querying SMART data...");
            match Disk::from_path(path) {
                Ok(disk) => {
                    debug!(disk = %path.display(), model = %disk.model, "storage cache: disk OK");
                    disks.push(disk);
                }
                Err(e) => {
                    debug!(disk = %path.display(), error = %e, "storage cache: skipping disk");
                }
            }
        }

        // --- RAID arrays (scan + detail for each) ---
        debug!("storage cache: scanning RAID arrays...");
        let mut arrays = Vec::new();
        if let Ok(scan_lines) = RaidArray::scan() {
            for line in &scan_lines {
                // Extract device path from "ARRAY /dev/md/0 metadata=..."
                if let Some(dev) = line.split_whitespace().nth(1) {
                    let device = PathBuf::from(dev);
                    match RaidArray::detail(&device) {
                        Ok(detail) => arrays.push(detail),
                        Err(e) => {
                            debug!(device = %dev, error = %e, "storage cache: skipping array");
                        }
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        info!(
            disks = disks.len(),
            arrays = arrays.len(),
            elapsed_ms = elapsed.as_millis(),
            "storage cache refreshed"
        );

        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(StorageSnapshot { disks, arrays });
    }
}

impl Default for DiskCache {
    fn default() -> Self {
        Self::new()
    }
}
