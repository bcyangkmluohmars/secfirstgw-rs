// SPDX-License-Identifier: AGPL-3.0-or-later

// ---- API Envelope ----

/** All API responses are wrapped in { success, data }. */
export interface ApiEnvelope<T> {
  success: boolean
  data: T
}

// ---- System Status ----

export interface SystemStatus {
  hostname: string
  /** Frontend-normalized uptime in seconds. API may send `uptime_seconds`. */
  uptime_secs: number
  kernel_version: string
  hardware_model?: string
  cpu_usage_percent?: number
  load_average?: [number, number, number]
  memory: MemoryInfo
  network?: NetworkStatus
  temperatures?: TemperatureReading[]
  storage_usage?: StorageUsage
  /** Summary counts returned by the API. */
  disk_count?: number
  array_count?: number
  share_count?: number
  /** Raw bay data included in the status response. */
  bays?: BayInfo[]
  /** Raw load object from the API (one/five/fifteen). */
  load?: { one: number; five: number; fifteen: number }
}

export interface MemoryInfo {
  total_mb: number
  used_mb: number
  cached_mb?: number
  /** Raw KB values from the API. */
  total_kb?: number
  used_kb?: number
  available_kb?: number
}

export interface NetworkStatus {
  interfaces: NetworkInterface[]
}

export interface NetworkInterface {
  name: string
  mac?: string
  ipv4?: string
  ipv6?: string
  link_speed_mbps?: number
  state?: 'up' | 'down' | string
  tx_bytes?: number
  rx_bytes?: number
  tx_packets?: number
  rx_packets?: number
  /** API returns speed_mbps instead of link_speed_mbps. */
  speed_mbps?: number
  mtu?: number
  addresses?: string[]
}

export interface TemperatureReading {
  label?: string
  /** API may return `name` instead of `label`. */
  name?: string
  celsius?: number
  /** API may return `temp_celsius` instead of `celsius`. */
  temp_celsius?: number
  warning_threshold?: number
  critical_threshold?: number
}

export interface StorageUsage {
  total_bytes: number
  used_bytes: number
  available_bytes: number
}

// ---- Disks ----

export type DiskHealth = 'healthy' | 'warning' | 'failing' | 'unknown'

/** The API may return health as an object with SMART details. */
export interface DiskHealthDetail {
  smart_status?: string
  temperature_celsius?: number
  power_on_hours?: number
  [key: string]: unknown
}

export interface Disk {
  device: string
  model?: string
  serial?: string
  firmware?: string
  capacity_bytes?: number
  temperature_celsius?: number
  health?: DiskHealth | string
  smart_status?: string
  power_on_hours?: number
  bay?: number | null
  rotation_rate_rpm?: number | null
  interface_type?: string
  /** API may return `size_bytes` instead of `capacity_bytes`. */
  size_bytes?: number
  /** Whether this disk is rotational (HDD) vs SSD. */
  rotational?: boolean
}

// ---- Bays ----

export type BayState = 'healthy' | 'fault' | 'empty' | 'rebuilding' | 'Present' | 'Normal' | string

export interface BayInfo {
  /** Bay slot number. API may return `slot` instead of `bay`. */
  bay: number
  state: BayState
  disk_serial?: string | null
  disk_model?: string | null
  activity_led?: boolean
  /** API may return `slot` instead of `bay`. */
  slot?: number
  /** API may return `led_mode` instead of `activity_led`. */
  led_mode?: string
  /** Disk size in bytes (from enriched bay endpoint). */
  size_bytes?: number
  /** SMART status: "healthy", "failing", "unknown". */
  smart_status?: string
  /** Disk temperature in Celsius. */
  temperature_celsius?: number | null
  /** Whether the disk is rotational (HDD) or solid-state (SSD). */
  rotational?: boolean
  /** Device path, e.g. "/dev/sda". */
  device?: string
}

// ---- RAID Arrays ----

export type RaidLevel = 'raid0' | 'raid1' | 'raid5' | 'raid6' | 'raid10' | 'single' | 'dup'

export type ArrayState = 'healthy' | 'degraded' | 'rebuilding' | 'failed' | 'inactive'

export interface RaidArray {
  name: string
  uuid?: string
  level: RaidLevel | string
  state: ArrayState | string
  total_bytes?: number
  used_bytes?: number
  devices?: ArrayDevice[]
  rebuild_percent?: number | null
  filesystem?: string
  mount_point?: string
  device?: string
}

export interface ArrayDevice {
  device: string
  state?: 'active' | 'spare' | 'faulty' | 'rebuilding' | string
  bay?: number | null
}

export interface CreateArrayRequest {
  name: string
  level: RaidLevel
  devices: string[]
  filesystem: string
}

/** Request body for the one-shot storage initialization (setup wizard). */
export interface InitializeStorageRequest {
  /** Array name (e.g. "data", "backup"). */
  name: string
  /** RAID level: "0", "1", "5", or "10". */
  level: string
  /** Disk device paths (e.g. ["/dev/sdb", "/dev/sdc"]). */
  disks: string[]
  /** Whether to encrypt the array with LUKS2. */
  encrypt: boolean
}

/** Response from a successful storage initialization. */
export interface InitializeStorageResponse {
  name: string
  raid_device: string
  raid_level: string
  encrypted: boolean
  filesystem_device: string
  filesystem_uuid: string
  mount_point: string
}

/** Detailed array status returned by the status endpoint. */
export interface ArrayDetail {
  device: string
  name: string
  level: string
  size_bytes: number
  raid_devices: number
  state: string
  uuid: string
  active_disks: string[]
  spare_disks: string[]
  status: string
  rebuild_progress?: number
  check_progress?: number
  speed_kbps?: number
  finish_minutes?: number
}

// ---- Btrfs ----

export interface BtrfsSubvolume {
  id: number
  name: string
  path: string
  parent_id?: number
  created?: string
  size_bytes?: number | null
}

export interface BtrfsScrub {
  running: boolean
  last_run?: string | null
  duration_secs?: number | null
  bytes_scrubbed?: number | null
  errors_found?: number
}

export interface BtrfsSnapshot {
  name: string
  path: string
  created?: string
  source_subvolume?: string
}

export interface BtrfsUsage {
  total_bytes: number
  used_bytes: number
  free_estimated: number
}

// ---- Shares ----

export type ShareProtocol = 'smb' | 'nfs' | 'rsync'

export interface Share {
  name: string
  path?: string
  protocol?: ShareProtocol | string
  enabled?: boolean
  read_only?: boolean
  allowed_users?: string[]
  guest_access?: boolean
  description?: string
  comment?: string
}

export type ShareTemplate = 'standard' | 'public' | 'private' | 'timemachine'

export interface CreateShareRequest {
  name: string
  path: string
  protocol: ShareProtocol
  read_only: boolean
  allowed_users: string[]
  guest_access: boolean
  description: string
  /** Optional share template: standard, public, private, timemachine. */
  template?: ShareTemplate
}

// ---- Users ----

export interface NasUser {
  username: string
  uid?: number
  groups?: string[]
  shares?: string[]
  enabled?: boolean
  created?: string
}

export interface CreateUserRequest {
  username: string
  password: string
  groups: string[]
}

export interface ChangePasswordRequest {
  username: string
  new_password: string
}

// ---- Rsync Modules ----

export interface RsyncModule {
  name: string
  path?: string
  read_only?: boolean
  comment?: string
  allowed_hosts?: string[]
}

export interface CreateRsyncModuleRequest {
  name: string
  path: string
  read_only: boolean
  comment: string
}

// ---- Active Directory / LDAP ----

export interface AdConfig {
  enabled: boolean
  server: string
  domain: string
  base_dn: string
  bind_user: string
  has_bind_password: boolean
  user_filter: string
  group_filter: string
  sync_interval: number
  last_sync: string
}

export interface AdConfigRequest {
  server: string
  domain: string
  base_dn: string
  bind_user: string
  bind_password?: string
  user_filter?: string
  group_filter?: string
  sync_interval?: number
}

export interface AdTestResult {
  connected: boolean
  message?: string
  error?: string
}

export interface AdStatus {
  enabled: boolean
  joined: boolean
  domain: string
  last_sync: string
  user_count: number
  group_count: number
}

export interface AdSyncResult {
  users: string[]
  groups: string[]
  user_count: number
  group_count: number
  synced_at: string
}

export interface AdJoinResult {
  message: string
  domain: string
  workgroup: string
}

// ---- OIDC / OAuth2 ----

export interface OAuthConfig {
  enabled: boolean
  provider_name: string
  issuer_url: string
  client_id: string
  redirect_uri: string
  scopes: string
  auto_provision: boolean
  has_client_secret: boolean
}

export interface OAuthConfigRequest {
  provider_name?: string
  issuer_url?: string
  client_id?: string
  client_secret?: string
  redirect_uri?: string
  scopes?: string
  auto_provision?: boolean
  enabled?: boolean
}

export interface OAuthDiscoveryResult {
  success: boolean
  error?: string
  discovered?: {
    issuer: string
    authorization_endpoint: string
    token_endpoint: string
    jwks_uri: string
    userinfo_endpoint?: string
  }
}

export interface OAuthProvider {
  id: string
  name: string
  issuer_template: string
  scopes: string
  note: string
}

export interface OAuthStatus {
  enabled: boolean
  provider_name: string
}

// ---- System ----

export interface LogEntry {
  timestamp?: string
  level?: 'error' | 'warn' | 'info' | 'debug' | string
  service?: string
  message: string
}

export interface SshKey {
  fingerprint: string
  type?: string
  comment?: string
  added?: string
}
