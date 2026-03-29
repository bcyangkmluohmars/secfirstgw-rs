#![deny(unsafe_code)]

//! Storage management endpoints.
//!
//! Provides CRUD for RAID arrays, disk enumeration with SMART data,
//! and physical bay state queries.

use crate::error::ApiError;
use axum::extract::Path;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::{error, info};

/// Validate an array name: alphanumeric + hyphens only, 1-32 characters.
fn validate_array_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 32 {
        return Err(ApiError::Validation(
            "array name must be 1-32 characters".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::Validation(
            "array name must contain only alphanumeric characters and hyphens".to_string(),
        ));
    }
    Ok(())
}

/// Validate a disk device path: must be absolute, start with /dev/, and contain no traversal.
fn validate_disk_path(disk: &str) -> Result<(), ApiError> {
    let p = std::path::Path::new(disk);
    if !p.is_absolute() || !disk.starts_with("/dev/") {
        return Err(ApiError::Validation("invalid disk path: must be an absolute /dev/ path".to_string()));
    }
    if disk.contains("..") {
        return Err(ApiError::Validation(
            "invalid disk path: path traversal not allowed".to_string(),
        ));
    }
    Ok(())
}

/// Resolve an array name to its `/dev/md/X` device path.
///
/// Tries `/dev/md/{name}` first. If that doesn't exist, scans `/dev/md/`
/// for a symlink whose mdadm Name field contains the given name (handles
/// the case where mdadm names arrays as `hostname:0` but the symlink is `0`).
fn resolve_array_device(name: &str) -> Result<PathBuf, ApiError> {
    // Direct match: /dev/md/{name}
    let direct = PathBuf::from(format!("/dev/md/{name}"));
    if direct.exists() {
        return Ok(direct);
    }

    // Scan /dev/md/ for arrays whose mdadm Name contains our name
    if let Ok(entries) = std::fs::read_dir("/dev/md") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(detail_output) = std::process::Command::new("mdadm")
                .arg("--detail")
                .arg(&path)
                .output()
            {
                let stdout = String::from_utf8_lossy(&detail_output.stdout);
                for line in stdout.lines() {
                    if line.contains("Name") && line.contains(name) {
                        return Ok(path);
                    }
                }
            }
        }
    }

    Err(ApiError::NotFound(format!("array '{name}' not found")))
}

/// Request body for creating a RAID array.
#[derive(Debug, Deserialize)]
struct CreateArrayRequest {
    /// Array name (e.g. "data", "backup").
    name: String,
    /// RAID level: "0", "1", "5", or "10".
    level: String,
    /// Disk device paths (e.g. ["/dev/sdb", "/dev/sdc"]).
    disks: Vec<String>,
}

/// Request body for adding or removing a disk from an array.
#[derive(Debug, Deserialize)]
struct DiskActionRequest {
    /// Disk device path (e.g. "/dev/sdb1").
    disk: String,
}

/// Request body for one-shot storage initialization (setup wizard).
///
/// Creates RAID array + optional LUKS encryption + Btrfs filesystem in
/// a single atomic operation.
#[derive(Debug, Deserialize)]
struct InitializeStorageRequest {
    /// Array name (e.g. "data", "backup").
    name: String,
    /// RAID level: "0", "1", "5", or "10".
    level: String,
    /// Disk device paths (e.g. ["/dev/sdb", "/dev/sdc", "/dev/sdd"]).
    disks: Vec<String>,
    /// Whether to encrypt the array with LUKS2.
    #[serde(default)]
    encrypt: bool,
}

/// `POST /api/v1/storage/initialize` — full storage stack setup.
///
/// Wipes disks → partitions → RAID → optional LUKS → Btrfs → mount.
/// Called by the setup wizard to bring storage online in one operation.
async fn initialize_storage(
    Json(body): Json<InitializeStorageRequest>,
) -> Result<Json<Value>, ApiError> {
    // ── Validate array name ──────────────────────────────────────────
    if body.name.is_empty() || body.name.len() > 32 {
        return Err(ApiError::Validation(
            "array name must be 1-32 characters".to_string(),
        ));
    }
    if !body
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::Validation(
            "array name must contain only alphanumeric characters and hyphens".to_string(),
        ));
    }

    // ── Validate RAID level ──────────────────────────────────────────
    let raid_level = match body.level.as_str() {
        "0" => sfnas_storage::RaidLevel::Raid0,
        "1" => sfnas_storage::RaidLevel::Raid1,
        "5" => sfnas_storage::RaidLevel::Raid5,
        "10" => sfnas_storage::RaidLevel::Raid10,
        _ => {
            return Err(ApiError::Validation(
                "invalid RAID level: use 0, 1, 5, or 10".to_string(),
            ))
        }
    };

    // ── Validate disk paths ──────────────────────────────────────────
    if body.disks.is_empty() {
        return Err(ApiError::Validation(
            "at least one disk required".to_string(),
        ));
    }

    if body.disks.len() < raid_level.min_disks() {
        return Err(ApiError::Validation(format!(
            "RAID {} requires at least {} disks, got {}",
            body.level,
            raid_level.min_disks(),
            body.disks.len(),
        )));
    }

    for disk in &body.disks {
        let p = std::path::Path::new(disk);
        if !p.is_absolute() || !disk.starts_with("/dev/") {
            return Err(ApiError::Validation(format!(
                "invalid disk path: {disk} (must be an absolute /dev/ path)"
            )));
        }
        // Reject paths with traversal components
        if disk.contains("..") {
            return Err(ApiError::Validation(format!(
                "invalid disk path: {disk} (path traversal not allowed)"
            )));
        }
    }

    info!(
        name = body.name,
        level = body.level,
        disks = body.disks.len(),
        encrypt = body.encrypt,
        "starting storage initialization"
    );

    // ── Step 1: Wipe + partition each disk ───────────────────────────
    let mut partition_paths: Vec<PathBuf> = Vec::with_capacity(body.disks.len());

    for disk_str in &body.disks {
        let disk_path = std::path::Path::new(disk_str);

        sfnas_storage::Disk::wipe(disk_path).map_err(|e| {
            error!(disk = disk_str, error = %e, "disk wipe failed during initialization");
            e
        })?;

        let part = sfnas_storage::Disk::partition(disk_path).map_err(|e| {
            error!(disk = disk_str, error = %e, "disk partition failed during initialization");
            e
        })?;

        info!(disk = disk_str, partition = %part.display(), "disk prepared");
        partition_paths.push(part);
    }

    // ── Step 2: Create RAID array ────────────────────────────────────
    let part_refs: Vec<&std::path::Path> = partition_paths.iter().map(|p| p.as_path()).collect();
    let array = sfnas_storage::RaidArray::create(&body.name, raid_level, &part_refs).map_err(|e| {
        error!(name = body.name, error = %e, "RAID creation failed during initialization");
        e
    })?;

    info!(
        name = array.name,
        device = %array.device.display(),
        level = ?array.level,
        "RAID array created"
    );

    // ── Step 3: Optional LUKS encryption ─────────────────────────────
    let fs_device: PathBuf;
    let mount_prefix: &str;

    if body.encrypt {
        let keyfile_dir = std::path::Path::new("/data/config");
        let keyfile_path = keyfile_dir.join(".luks-keyfile");

        // Ensure the config directory exists
        std::fs::create_dir_all(keyfile_dir).map_err(|e| {
            error!(error = %e, "failed to create keyfile directory");
            ApiError::Internal(format!("failed to create keyfile directory: {e}"))
        })?;

        // Generate a 512-byte random keyfile
        let mut keyfile_data = vec![0u8; 512];
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut keyfile_data))
            .map_err(|e| {
                error!(error = %e, "failed to generate LUKS keyfile");
                ApiError::Internal(format!("failed to generate LUKS keyfile: {e}"))
            })?;

        // Write keyfile with restrictive permissions (owner-only read)
        std::fs::write(&keyfile_path, &keyfile_data).map_err(|e| {
            error!(error = %e, "failed to write LUKS keyfile");
            ApiError::Internal(format!("failed to write LUKS keyfile: {e}"))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o400);
            std::fs::set_permissions(&keyfile_path, perms).map_err(|e| {
                error!(error = %e, "failed to set keyfile permissions");
                ApiError::Internal(format!("failed to set keyfile permissions: {e}"))
            })?;
        }

        info!("LUKS keyfile generated");

        // Format with LUKS2
        sfnas_storage::CryptVolume::format(&array.device, &keyfile_data).map_err(|e| {
            error!(error = %e, "LUKS format failed during initialization");
            ApiError::Storage(e)
        })?;

        // Open the LUKS volume
        let crypt_name = format!("crypt-{}", body.name);
        let _crypt = sfnas_storage::CryptVolume::open(&array.device, &crypt_name, &keyfile_data)
            .map_err(|e| {
                error!(error = %e, "LUKS open failed during initialization");
                ApiError::Storage(e)
            })?;

        fs_device = sfnas_storage::CryptVolume::mapper_path(&crypt_name);
        mount_prefix = "crypt";

        info!(
            crypt_name = crypt_name,
            device = %fs_device.display(),
            "LUKS volume created and opened"
        );
    } else {
        fs_device = array.device.clone();
        mount_prefix = "md";
    }

    // ── Step 4: Create Btrfs filesystem ──────────────────────────────
    let btrfs = sfnas_storage::BtrfsVolume::format(&fs_device, &body.name).map_err(|e| {
        error!(error = %e, "Btrfs format failed during initialization");
        ApiError::Storage(e)
    })?;

    info!(
        device = %fs_device.display(),
        uuid = btrfs.uuid,
        "Btrfs filesystem created"
    );

    // ── Step 5: Mount ────────────────────────────────────────────────
    let mount_point = PathBuf::from(format!("/mnt/{mount_prefix}-{}", body.name));
    sfnas_storage::BtrfsVolume::mount(&fs_device, &mount_point).map_err(|e| {
        error!(
            mount_point = %mount_point.display(),
            error = %e,
            "Btrfs mount failed during initialization"
        );
        ApiError::Storage(e)
    })?;

    info!(
        mount_point = %mount_point.display(),
        "storage initialization complete"
    );

    Ok(Json(json!({
        "success": true,
        "data": {
            "name": body.name,
            "raid_device": array.device,
            "raid_level": array.level,
            "encrypted": body.encrypt,
            "filesystem_device": fs_device,
            "filesystem_uuid": btrfs.uuid,
            "mount_point": mount_point,
        },
    })))
}

/// `GET /api/v1/storage/disks` — list all disks with SMART health (from cache).
async fn list_disks(Extension(disk_cache): Extension<sfnas_storage::DiskCache>) -> Result<Json<Value>, ApiError> {
    let disks = disk_cache.get();

    Ok(Json(json!({
        "success": true,
        "data": disks,
    })))
}

/// `GET /api/v1/storage/arrays` — list all RAID arrays (from cache).
async fn list_arrays(Extension(disk_cache): Extension<sfnas_storage::DiskCache>) -> Result<Json<Value>, ApiError> {
    let arrays = disk_cache.get_arrays();

    Ok(Json(json!({
        "success": true,
        "data": arrays,
    })))
}

/// `POST /api/v1/storage/arrays` — create a new RAID array.
async fn create_array(
    Json(body): Json<CreateArrayRequest>,
) -> Result<Json<Value>, ApiError> {
    // Validate array name: alphanumeric + hyphens only, 1-32 chars
    if body.name.is_empty() || body.name.len() > 32 {
        return Err(ApiError::Validation(
            "array name must be 1-32 characters".to_string(),
        ));
    }
    if !body
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::Validation(
            "array name must contain only alphanumeric characters and hyphens".to_string(),
        ));
    }

    let raid_level = match body.level.as_str() {
        "0" => sfnas_storage::RaidLevel::Raid0,
        "1" => sfnas_storage::RaidLevel::Raid1,
        "5" => sfnas_storage::RaidLevel::Raid5,
        "10" => sfnas_storage::RaidLevel::Raid10,
        _ => {
            return Err(ApiError::Validation(
                "invalid RAID level: use 0, 1, 5, or 10".to_string(),
            ))
        }
    };

    if body.disks.is_empty() {
        return Err(ApiError::Validation("at least one disk required".to_string()));
    }

    // Validate disk paths: must be absolute and start with /dev/
    for disk in &body.disks {
        let p = std::path::Path::new(disk);
        if !p.is_absolute() || !disk.starts_with("/dev/") {
            return Err(ApiError::Validation(format!(
                "invalid disk path: {disk} (must be an absolute /dev/ path)"
            )));
        }
    }

    let disk_paths: Vec<PathBuf> = body.disks.iter().map(PathBuf::from).collect();
    let disk_refs: Vec<&std::path::Path> = disk_paths.iter().map(|p| p.as_path()).collect();

    let array = sfnas_storage::RaidArray::create(&body.name, raid_level, &disk_refs)?;

    info!(
        name = array.name,
        device = %array.device.display(),
        level = ?array.level,
        "RAID array created via API"
    );

    Ok(Json(json!({
        "success": true,
        "data": {
            "name": array.name,
            "device": array.device,
            "level": array.level,
        },
    })))
}

/// `DELETE /api/v1/storage/arrays/:name` — stop (deactivate) an array.
async fn delete_array(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    // Validate the name
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::Validation(
            "invalid array name".to_string(),
        ));
    }

    let device = resolve_array_device(&name)?;

    sfnas_storage::RaidArray::stop(&device)?;

    info!(name, "RAID array stopped via API");

    Ok(Json(json!({
        "success": true,
        "data": { "stopped": name },
    })))
}

/// `GET /api/v1/storage/arrays/:name/status` — detailed array status with rebuild/check progress.
async fn array_status(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    validate_array_name(&name)?;

    let device = PathBuf::from(format!("/dev/md/{name}"));
    if !device.exists() {
        return Err(ApiError::NotFound(format!("array '{name}' not found")));
    }

    let detail = sfnas_storage::RaidArray::detail(&device).map_err(|e| {
        error!(name = %name, error = %e, "failed to get array detail");
        e
    })?;

    // Merge mdstat data for rebuild/check progress
    let mdstat_entries = sfnas_storage::RaidArray::parse_mdstat().unwrap_or_default();

    // The /dev/md/{name} symlink points to /dev/md12x; resolve it to match mdstat device name.
    let resolved_device = std::fs::read_link(&device)
        .ok()
        .and_then(|target| target.file_name().map(|n| n.to_string_lossy().to_string()));

    let md_device_name = resolved_device.or_else(|| {
        device.file_name().map(|n| n.to_string_lossy().to_string())
    });

    let mdstat_entry = md_device_name
        .as_ref()
        .and_then(|dev_name| mdstat_entries.iter().find(|e| e.device == *dev_name));

    // Determine display status string and optional progress values
    let (status_str, rebuild_progress, check_progress) = if let Some(entry) = mdstat_entry {
        match entry.recovery_action.as_deref() {
            Some("recovery") | Some("reshape") | Some("resync") => (
                "Rebuilding".to_string(),
                entry.recovery_progress,
                None,
            ),
            Some("check") => ("Checking".to_string(), None, entry.recovery_progress),
            _ => (status_label(&detail.status).to_string(), None, None),
        }
    } else {
        (status_label(&detail.status).to_string(), None, None)
    };

    let active_disk_strs: Vec<String> = detail
        .active_disks
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    let spare_disk_strs: Vec<String> = detail
        .spare_disks
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let mut response = json!({
        "success": true,
        "data": {
            "device": detail.device,
            "name": detail.name,
            "level": detail.level.map(|l| format!("{l:?}")).unwrap_or_default(),
            "size_bytes": detail.size_bytes,
            "raid_devices": detail.raid_devices,
            "state": detail.state,
            "uuid": detail.uuid,
            "active_disks": active_disk_strs,
            "spare_disks": spare_disk_strs,
            "status": status_str,
        },
    });

    if let Some(progress) = rebuild_progress {
        response["data"]["rebuild_progress"] = json!(progress);
    }
    if let Some(progress) = check_progress {
        response["data"]["check_progress"] = json!(progress);
    }
    if let Some(entry) = mdstat_entry {
        if let Some(speed) = entry.speed_kbps {
            response["data"]["speed_kbps"] = json!(speed);
        }
        if let Some(finish) = entry.finish_minutes {
            response["data"]["finish_minutes"] = json!(finish);
        }
    }

    Ok(Json(response))
}

/// Map a [`sfnas_storage::RaidStatus`] to a user-facing label.
fn status_label(status: &sfnas_storage::RaidStatus) -> &'static str {
    match status {
        sfnas_storage::RaidStatus::Active => "Active",
        sfnas_storage::RaidStatus::Degraded { .. } => "Degraded",
        sfnas_storage::RaidStatus::Rebuilding { .. } => "Rebuilding",
        sfnas_storage::RaidStatus::Checking { .. } => "Checking",
        sfnas_storage::RaidStatus::Inactive => "Inactive",
    }
}

/// `POST /api/v1/storage/arrays/:name/add-disk` — add a disk to an existing array.
async fn add_disk_to_array(
    Path(name): Path<String>,
    Json(body): Json<DiskActionRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_array_name(&name)?;
    validate_disk_path(&body.disk)?;

    let device = PathBuf::from(format!("/dev/md/{name}"));
    if !device.exists() {
        return Err(ApiError::NotFound(format!("array '{name}' not found")));
    }

    let disk_path = PathBuf::from(&body.disk);

    sfnas_storage::RaidArray::add_disk(&device, &disk_path).map_err(|e| {
        error!(name = %name, disk = %body.disk, error = %e, "failed to add disk to array");
        e
    })?;

    info!(name = %name, disk = %body.disk, "disk added to RAID array via API");

    Ok(Json(json!({
        "success": true,
        "data": { "added": body.disk, "array": name },
    })))
}

/// `POST /api/v1/storage/arrays/:name/remove-disk` — remove a disk from an existing array.
async fn remove_disk_from_array(
    Path(name): Path<String>,
    Json(body): Json<DiskActionRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_array_name(&name)?;
    validate_disk_path(&body.disk)?;

    let device = PathBuf::from(format!("/dev/md/{name}"));
    if !device.exists() {
        return Err(ApiError::NotFound(format!("array '{name}' not found")));
    }

    let disk_path = PathBuf::from(&body.disk);

    sfnas_storage::RaidArray::remove_disk(&device, &disk_path).map_err(|e| {
        error!(name = %name, disk = %body.disk, error = %e, "failed to remove disk from array");
        e
    })?;

    info!(name = %name, disk = %body.disk, "disk removed from RAID array via API");

    Ok(Json(json!({
        "success": true,
        "data": { "removed": body.disk, "array": name },
    })))
}

/// `POST /api/v1/storage/arrays/:name/scrub` — start a RAID scrub (consistency check).
async fn start_array_scrub(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    validate_array_name(&name)?;

    let device = PathBuf::from(format!("/dev/md/{name}"));
    if !device.exists() {
        return Err(ApiError::NotFound(format!("array '{name}' not found")));
    }

    // The scrub sysfs interface needs the md block device name (e.g. md127),
    // not the /dev/md/{name} symlink. Resolve the symlink to get the real device.
    let resolved = std::fs::read_link(&device).map_err(|e| {
        error!(name = %name, error = %e, "failed to resolve array device symlink");
        ApiError::Internal("failed to resolve array device".to_string())
    })?;

    sfnas_storage::RaidArray::scrub(&resolved).map_err(|e| {
        error!(name = %name, error = %e, "failed to start array scrub");
        e
    })?;

    info!(name = %name, "RAID array scrub started via API");

    Ok(Json(json!({
        "success": true,
        "data": { "scrub_started": name },
    })))
}

/// `GET /api/v1/storage/bays` — bay states with disk mapping.
async fn list_bays(
    Extension(disk_cache): Extension<sfnas_storage::DiskCache>,
) -> Result<Json<Value>, ApiError> {
    let bays = sfnas_storage::Bay::read_all();
    let disks = disk_cache.get();

    // Enrich each bay with its mapped disk info (model, serial, size, health)
    let enriched: Vec<Value> = bays
        .iter()
        .map(|bay| {
            let mut entry = json!({
                "slot": bay.slot,
                "state": bay.state,
                "led_mode": bay.led_mode,
            });

            // Try to map this bay to a /dev/sdX and find the matching cached disk
            if let Ok(dev_path) = bay.map_to_disk()
                && let Some(disk) = disks.iter().find(|d| d.path == dev_path) {
                    entry["disk_model"] = json!(disk.model.trim());
                    entry["disk_serial"] = json!(disk.serial.trim());
                    entry["size_bytes"] = json!(disk.size_bytes);
                    entry["rotational"] = json!(disk.rotational);
                    entry["temperature_celsius"] = json!(disk.health.temperature_celsius);
                    entry["smart_status"] = json!(match &disk.health.smart_status {
                        sfnas_storage::SmartStatus::Passed => "healthy",
                        sfnas_storage::SmartStatus::Failed(_) => "failing",
                        sfnas_storage::SmartStatus::Unknown => "unknown",
                    });
                    entry["device"] = json!(dev_path);
                }

            entry
        })
        .collect();

    Ok(Json(json!({
        "success": true,
        "data": enriched,
    })))
}

// ---------------------------------------------------------------------------
// Btrfs management helpers
// ---------------------------------------------------------------------------

/// Scan `/proc/mounts` for the first Btrfs mount at `/mnt/crypt-*` or `/mnt/md-*`.
fn find_btrfs_mount() -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: <device> <mount_point> <fs_type> <options> ...
        if parts.len() < 3 {
            continue;
        }
        let mount_point = parts[1];
        let fs_type = parts[2];
        if fs_type == "btrfs"
            && (mount_point.starts_with("/mnt/crypt-") || mount_point.starts_with("/mnt/md-"))
        {
            return Some(PathBuf::from(mount_point));
        }
    }
    None
}

/// Validate a Btrfs subvolume or snapshot name.
///
/// Allowed: alphanumeric, hyphens, underscores, 1-64 characters.
/// Rejected: path separators, traversal sequences, dots-only names.
fn validate_btrfs_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::Validation(
            "name must be 1-64 characters".to_string(),
        ));
    }
    if name == "." || name == ".." {
        return Err(ApiError::Validation(
            "name must not be '.' or '..'".to_string(),
        ));
    }
    if name.contains('/') || name.contains("..") {
        return Err(ApiError::Validation(
            "name must not contain '/' or '..'".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::Validation(
            "name must contain only alphanumeric characters, hyphens, and underscores".to_string(),
        ));
    }
    Ok(())
}

/// Require a Btrfs mount point or return a descriptive 422 error.
fn require_btrfs_mount() -> Result<PathBuf, ApiError> {
    find_btrfs_mount().ok_or_else(|| {
        ApiError::Validation("no Btrfs filesystem is currently mounted".to_string())
    })
}

// ---------------------------------------------------------------------------
// Btrfs request bodies
// ---------------------------------------------------------------------------

/// Request body for creating a Btrfs subvolume.
#[derive(Debug, Deserialize)]
struct CreateSubvolumeRequest {
    /// Subvolume name (e.g. "documents").
    name: String,
}

/// Request body for creating a Btrfs snapshot.
#[derive(Debug, Deserialize)]
struct CreateSnapshotRequest {
    /// Source subvolume name to snapshot.
    subvolume: String,
    /// Optional snapshot name; if omitted a timestamp-based name is generated.
    name: Option<String>,
}

// ---------------------------------------------------------------------------
// Btrfs endpoint handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/storage/btrfs/subvolumes` — list Btrfs subvolumes.
async fn list_subvolumes() -> Result<Json<Value>, ApiError> {
    let mount = require_btrfs_mount()?;
    let subvols = sfnas_storage::BtrfsVolume::list_subvolumes(&mount)?;

    // Map SubvolumeInfo into the JSON shape the frontend expects.
    let data: Vec<Value> = subvols
        .iter()
        .map(|sv| {
            json!({
                "id": sv.id,
                "name": sv.path,
                "path": mount.join(&sv.path),
                "generation": sv.generation,
                "top_level": sv.top_level,
            })
        })
        .collect();

    Ok(Json(json!({
        "success": true,
        "data": data,
    })))
}

/// `POST /api/v1/storage/btrfs/subvolumes` — create a Btrfs subvolume.
async fn create_subvolume(
    Json(body): Json<CreateSubvolumeRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_btrfs_name(&body.name)?;
    let mount = require_btrfs_mount()?;

    let path = sfnas_storage::BtrfsVolume::create_subvolume(&mount, &body.name)?;

    info!(name = body.name, path = %path.display(), "Btrfs subvolume created via API");

    Ok(Json(json!({
        "success": true,
        "data": {
            "name": body.name,
            "path": path,
        },
    })))
}

/// `DELETE /api/v1/storage/btrfs/subvolumes/{name}` — delete a Btrfs subvolume.
async fn delete_subvolume(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    validate_btrfs_name(&name)?;
    let mount = require_btrfs_mount()?;
    let subvol_path = mount.join(&name);

    sfnas_storage::BtrfsVolume::delete_subvolume(&subvol_path)?;

    info!(name, "Btrfs subvolume deleted via API");

    Ok(Json(json!({
        "success": true,
        "data": { "deleted": name },
    })))
}

/// `POST /api/v1/storage/btrfs/snapshots` — create a read-only snapshot.
async fn create_snapshot(
    Json(body): Json<CreateSnapshotRequest>,
) -> Result<Json<Value>, ApiError> {
    validate_btrfs_name(&body.subvolume)?;

    // Generate a timestamp name if none provided.
    let snap_name = match &body.name {
        Some(n) => {
            validate_btrfs_name(n)?;
            n.clone()
        }
        None => {
            let now = chrono::Utc::now().format("%Y%m%d-%H%M%S");
            format!("{}-snap-{now}", body.subvolume)
        }
    };

    let mount = require_btrfs_mount()?;
    let source = mount.join(&body.subvolume);

    let snap_path = sfnas_storage::BtrfsVolume::snapshot(&source, &snap_name)?;

    info!(
        subvolume = body.subvolume,
        snapshot = %snap_path.display(),
        "Btrfs snapshot created via API"
    );

    Ok(Json(json!({
        "success": true,
        "data": {
            "name": snap_name,
            "source_subvolume": body.subvolume,
            "path": snap_path,
        },
    })))
}

/// `DELETE /api/v1/storage/btrfs/snapshots/{name}` — delete a snapshot.
async fn delete_snapshot(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    validate_btrfs_name(&name)?;
    let mount = require_btrfs_mount()?;
    let snap_path = mount.join(&name);

    sfnas_storage::BtrfsVolume::delete_subvolume(&snap_path)?;

    info!(name, "Btrfs snapshot deleted via API");

    Ok(Json(json!({
        "success": true,
        "data": { "deleted": name },
    })))
}

/// `GET /api/v1/storage/btrfs/scrub` — scrub status.
async fn btrfs_scrub_status() -> Result<Json<Value>, ApiError> {
    let mount = require_btrfs_mount()?;
    let status = sfnas_storage::BtrfsVolume::scrub_status(&mount)?;

    let data = match &status {
        sfnas_storage::ScrubStatus::Running { progress } => json!({
            "running": true,
            "progress": progress,
        }),
        sfnas_storage::ScrubStatus::Finished {
            bytes_scrubbed,
            errors,
        } => json!({
            "running": false,
            "bytes_scrubbed": bytes_scrubbed,
            "errors_found": errors,
        }),
        sfnas_storage::ScrubStatus::Idle => json!({
            "running": false,
        }),
    };

    Ok(Json(json!({
        "success": true,
        "data": data,
    })))
}

/// `POST /api/v1/storage/btrfs/scrub` — start a scrub.
async fn btrfs_scrub_start() -> Result<Json<Value>, ApiError> {
    let mount = require_btrfs_mount()?;

    sfnas_storage::BtrfsVolume::scrub(&mount)?;

    info!(mount_point = %mount.display(), "Btrfs scrub started via API");

    Ok(Json(json!({
        "success": true,
        "data": { "started": true },
    })))
}

/// `GET /api/v1/storage/btrfs/usage` — filesystem usage.
async fn btrfs_usage() -> Result<Json<Value>, ApiError> {
    let mount = require_btrfs_mount()?;
    let usage = sfnas_storage::BtrfsVolume::usage(&mount)?;

    Ok(Json(json!({
        "success": true,
        "data": {
            "total_bytes": usage.total_bytes,
            "used_bytes": usage.used_bytes,
            "free_estimated": usage.free_estimated,
        },
    })))
}

/// Build the storage router (protected — read-only + safe operations).
pub fn router() -> Router {
    Router::new()
        .route("/storage/disks", get(list_disks))
        .route("/storage/arrays", get(list_arrays))
        .route("/storage/arrays/{name}/status", get(array_status))
        .route("/storage/bays", get(list_bays))
        .route("/storage/btrfs/subvolumes", get(list_subvolumes))
        .route("/storage/btrfs/scrub", get(btrfs_scrub_status))
        .route("/storage/btrfs/usage", get(btrfs_usage))
}

/// Critical storage operations (destructive — strict rate limit).
pub fn critical_router() -> Router {
    Router::new()
        .route("/storage/arrays", post(create_array))
        .route("/storage/arrays/{name}", delete(delete_array))
        .route(
            "/storage/arrays/{name}/add-disk",
            post(add_disk_to_array),
        )
        .route(
            "/storage/arrays/{name}/remove-disk",
            post(remove_disk_from_array),
        )
        .route(
            "/storage/arrays/{name}/scrub",
            post(start_array_scrub),
        )
        .route("/storage/initialize", post(initialize_storage))
        .route("/storage/btrfs/subvolumes", post(create_subvolume))
        .route(
            "/storage/btrfs/subvolumes/{name}",
            delete(delete_subvolume),
        )
        .route("/storage/btrfs/snapshots", post(create_snapshot))
        .route(
            "/storage/btrfs/snapshots/{name}",
            delete(delete_snapshot),
        )
        .route("/storage/btrfs/scrub", post(btrfs_scrub_start))
}
