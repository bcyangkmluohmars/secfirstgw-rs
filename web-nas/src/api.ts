// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  getEnvelopeKey,
  encryptPayload,
  decryptPayload,
  hasE2EE,
} from './crypto';

import type {
  SystemStatus,
  NetworkInterface,
  Disk,
  BayInfo,
  RaidArray,
  ArrayDetail,
  CreateArrayRequest,
  InitializeStorageRequest,
  InitializeStorageResponse,
  Share,
  CreateShareRequest,
  NasUser,
  CreateUserRequest,
  ChangePasswordRequest,
  LogEntry,
  SshKey,
  BtrfsSubvolume,
  BtrfsScrub,
  BtrfsSnapshot,
  RsyncModule,
  CreateRsyncModuleRequest,
  AdConfig,
  AdConfigRequest,
  AdTestResult,
  AdStatus,
  AdSyncResult,
  AdJoinResult,
  OAuthConfig,
  OAuthConfigRequest,
  OAuthDiscoveryResult,
  OAuthProvider,
  OAuthStatus,
} from './types'

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

// ---- E2EE re-negotiate callback (set by App.tsx to break circular import) ----

let _renegotiateFn: (() => Promise<boolean>) | null = null;

export function setRenegotiateFn(fn: () => Promise<boolean>): void {
  _renegotiateFn = fn;
}

// Guard against concurrent re-negotiate storms
let renegotiating: Promise<boolean> | null = null;

// ---- API error class ----

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(`HTTP ${status}: ${message}`);
    this.name = 'ApiError';
    this.status = status;
  }
}

// ---- Token management ----

const TOKEN_KEY = 'nas_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem(TOKEN_KEY);
}

// ---- Auth types ----

export interface SessionResponse {
  negotiate_id: string;
  server_public_key: string;
  kem_ciphertext?: string;
  authenticated: boolean;
  user?: { id: number; username: string; role: string };
  envelope?: { iv: string; data: string };
}

export interface LoginResponse {
  token: string;
  expires_at: string;
  envelope?: { iv: string; data: string };
}

// ---- E2EE request wrapper ----

interface ApiOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  skipE2EE?: boolean;
}

async function request<T>(path: string, opts: ApiOptions = {}, _retry = false): Promise<T> {
  const { method = 'GET', body, headers = {}, skipE2EE = false } = opts;

  const token = localStorage.getItem(TOKEN_KEY);
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let actualBody: string | undefined;
  const useE2EE = !skipE2EE && hasE2EE() && token;

  if (useE2EE) {
    headers['X-SFGW-E2EE'] = 'true';
  }

  if (body) {
    if (useE2EE) {
      const key = getEnvelopeKey()!;
      const plaintext = new TextEncoder().encode(JSON.stringify(body));
      const encrypted = await encryptPayload(key, plaintext);
      actualBody = JSON.stringify(encrypted);
    } else {
      actualBody = JSON.stringify(body);
    }
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: actualBody,
  });

  if (res.status === 401) {
    // E2EE key lost (server restart) but DB session still valid -- re-negotiate once
    if (!_retry && token && !skipE2EE && _renegotiateFn) {
      if (!renegotiating) {
        renegotiating = _renegotiateFn().finally(() => { renegotiating = null; });
      }
      const ok = await renegotiating;
      if (ok) {
        return request(path, opts, true);
      }
    }
    localStorage.removeItem(TOKEN_KEY);
    throw new ApiError(401, 'unauthorized');
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new ApiError(res.status, text || res.statusText);
  }

  if (res.status === 204) return undefined as T;

  const isE2EEResponse = res.headers.get('x-sfgw-e2ee') === 'true';
  if (isE2EEResponse && hasE2EE()) {
    const envelope = await res.json();
    const key = getEnvelopeKey()!;
    const decrypted = await decryptPayload(key, envelope.iv, envelope.data);
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  const contentType = res.headers.get('Content-Type') ?? '';
  if (contentType.includes('application/json')) {
    return (await res.json()) as T;
  }

  return undefined as T;
}

// ---------------------------------------------------------------------------
// Envelope unwrapping -- the API wraps responses in { success, data }.
// ---------------------------------------------------------------------------

interface Envelope<T> {
  success?: boolean
  data?: T
}

/** Unwrap a `{ data: T }` envelope, or return the raw value if no envelope. */
function unwrap<T>(raw: unknown): T {
  if (raw != null && typeof raw === 'object' && 'data' in raw) {
    return (raw as Envelope<T>).data as T
  }
  return raw as T
}

/** Ensure a value is an array. Handles null, undefined, and non-array values. */
function ensureArray<T>(val: unknown): T[] {
  if (Array.isArray(val)) return val as T[]
  return []
}

// ---------------------------------------------------------------------------
// Normalizers -- map API field names to what the frontend expects.
// ---------------------------------------------------------------------------

function normalizeStatus(raw: Record<string, unknown>): SystemStatus {
  const data = raw ?? {}

  // Memory: API sends _kb, frontend wants _mb
  const mem = (data.memory ?? {}) as Record<string, unknown>
  const totalKb = (mem.total_kb as number) ?? 0
  const usedKb = (mem.used_kb as number) ?? 0
  const availableKb = (mem.available_kb as number) ?? 0
  const totalMb = mem.total_mb != null ? (mem.total_mb as number) : Math.round(totalKb / 1024)
  const usedMb = mem.used_mb != null ? (mem.used_mb as number) : Math.round(usedKb / 1024)
  const cachedMb = (mem.cached_mb as number) ?? 0

  // Load: API sends {one, five, fifteen}, frontend wants [number, number, number]
  const loadObj = data.load as Record<string, number> | undefined
  const loadArray = (data.load_average as [number, number, number]) ?? (
    loadObj
      ? [loadObj.one ?? 0, loadObj.five ?? 0, loadObj.fifteen ?? 0] as [number, number, number]
      : [0, 0, 0] as [number, number, number]
  )

  // Uptime: API sends `uptime_seconds`, frontend wants `uptime_secs`
  const uptimeSecs = (data.uptime_secs as number) ?? (data.uptime_seconds as number) ?? 0

  // Kernel: API sends `kernel`, frontend wants `kernel_version`
  const kernelVersion = (data.kernel_version as string) ?? (data.kernel as string) ?? ''

  // Temperatures: normalize name/label and temp_celsius/celsius
  const rawTemps = ensureArray<Record<string, unknown>>(data.temperatures)
  const temperatures = rawTemps.map((t) => ({
    label: (t.label as string) ?? (t.name as string) ?? 'Unknown',
    name: (t.name as string) ?? (t.label as string) ?? 'Unknown',
    celsius: (t.celsius as number) ?? (t.temp_celsius as number) ?? 0,
    temp_celsius: (t.temp_celsius as number) ?? (t.celsius as number) ?? 0,
    warning_threshold: (t.warning_threshold as number) ?? 85,
    critical_threshold: (t.critical_threshold as number) ?? 100,
  }))

  return {
    hostname: (data.hostname as string) ?? 'unknown',
    uptime_secs: uptimeSecs,
    kernel_version: kernelVersion,
    hardware_model: (data.hardware_model as string) ?? undefined,
    cpu_usage_percent: (data.cpu_usage_percent as number) ?? undefined,
    load_average: loadArray,
    load: loadObj ? { one: loadObj.one ?? 0, five: loadObj.five ?? 0, fifteen: loadObj.fifteen ?? 0 } : undefined,
    memory: {
      total_mb: totalMb,
      used_mb: usedMb,
      cached_mb: cachedMb,
      total_kb: totalKb || undefined,
      used_kb: usedKb || undefined,
      available_kb: availableKb || undefined,
    },
    network: data.network as SystemStatus['network'] ?? undefined,
    temperatures,
    storage_usage: data.storage_usage as SystemStatus['storage_usage'] ?? undefined,
    disk_count: (data.disk_count as number) ?? undefined,
    array_count: (data.array_count as number) ?? undefined,
    share_count: (data.share_count as number) ?? undefined,
    bays: data.bays != null ? ensureArray<BayInfo>(data.bays) : undefined,
    fans: data.fans != null ? ensureArray<Record<string, unknown>>(data.fans) : undefined,
    fan_profile: (data.fan_profile as string) ?? undefined,
  } as SystemStatus
}

function normalizeBay(raw: Record<string, unknown>): BayInfo {
  return {
    bay: (raw.bay as number) ?? (raw.slot as number) ?? 0,
    state: (raw.state as string) ?? 'empty',
    disk_serial: (raw.disk_serial as string) ?? null,
    disk_model: (raw.disk_model as string) ?? null,
    activity_led: (raw.activity_led as boolean | undefined) ?? (raw.led_mode === 'Activity'),
    slot: (raw.slot as number) ?? undefined,
    led_mode: (raw.led_mode as string) ?? undefined,
    size_bytes: (raw.size_bytes as number) ?? undefined,
    smart_status: (raw.smart_status as string) ?? undefined,
    temperature_celsius: (raw.temperature_celsius as number | null) ?? undefined,
    rotational: (raw.rotational as boolean) ?? undefined,
    device: (raw.device as string) ?? undefined,
  }
}

function normalizeDisk(raw: Record<string, unknown>): Disk {
  // health may be a string ("healthy") or an object ({ smart_status, temperature_celsius, ... })
  const rawHealth = raw.health
  let healthStr: string = 'unknown'
  let healthTemp: number | undefined
  let healthPowerOn: number | undefined

  if (rawHealth != null && typeof rawHealth === 'object') {
    const ho = rawHealth as Record<string, unknown>
    // Map SMART status strings to our health enum
    const smart = (ho.smart_status as string) ?? ''
    if (smart.toLowerCase() === 'passed' || smart.toLowerCase() === 'ok') {
      healthStr = 'healthy'
    } else if (smart.toLowerCase() === 'failed') {
      healthStr = 'failing'
    } else if (smart) {
      healthStr = smart.toLowerCase()
    }
    healthTemp = (ho.temperature_celsius as number) ?? undefined
    healthPowerOn = (ho.power_on_hours as number) ?? undefined
  } else if (typeof rawHealth === 'string') {
    healthStr = rawHealth
  }

  const tempCelsius = (raw.temperature_celsius as number)
    ?? (raw.temp_celsius as number)
    ?? healthTemp
    ?? 0
  const powerOnHours = (raw.power_on_hours as number)
    ?? healthPowerOn
    ?? 0

  // Determine rotation: API may send `rotational` boolean
  const rotational = raw.rotational as boolean | undefined
  let rotationRate = (raw.rotation_rate_rpm as number) ?? null
  if (rotationRate === null && rotational === false) {
    rotationRate = 0 // SSD
  }

  return {
    device: (raw.device as string) ?? (raw.path as string) ?? 'unknown',
    model: (raw.model as string) ?? 'Unknown',
    serial: (raw.serial as string) ?? 'Unknown',
    firmware: (raw.firmware as string) ?? undefined,
    capacity_bytes: (raw.capacity_bytes as number) ?? (raw.size_bytes as number) ?? 0,
    temperature_celsius: tempCelsius,
    health: healthStr as Disk['health'],
    smart_status: (raw.smart_status as string) ?? (typeof rawHealth === 'object' && rawHealth != null ? ((rawHealth as Record<string, unknown>).smart_status as string) : undefined) ?? undefined,
    power_on_hours: powerOnHours,
    bay: (raw.bay as number) ?? null,
    rotation_rate_rpm: rotationRate,
    interface_type: (raw.interface_type as string) ?? 'Unknown',
    rotational: rotational,
  }
}

function normalizeShare(raw: Record<string, unknown>): Share {
  return {
    name: (raw.name as string) ?? 'unknown',
    path: (raw.path as string) ?? '',
    protocol: (raw.protocol as string) ?? 'smb',
    enabled: (raw.enabled as boolean) ?? true,
    read_only: (raw.read_only as boolean) ?? false,
    allowed_users: ensureArray<string>(raw.allowed_users ?? raw.valid_users),
    guest_access: (raw.guest_access as boolean) ?? false,
    description: (raw.description as string) ?? (raw.comment as string) ?? '',
    comment: (raw.comment as string) ?? (raw.description as string) ?? '',
  }
}

function normalizeLogEntry(raw: unknown): LogEntry {
  // Logs API returns { lines: string[], count: number } or LogEntry[]
  if (typeof raw === 'string') {
    return { message: raw }
  }
  const obj = (raw ?? {}) as Record<string, unknown>
  return {
    timestamp: (obj.timestamp as string) ?? undefined,
    level: (obj.level as string) ?? undefined,
    service: (obj.service as string) ?? undefined,
    message: (obj.message as string) ?? String(raw),
  }
}

function normalizeNetworkInterface(raw: Record<string, unknown>): NetworkInterface {
  const addresses = ensureArray<string>(raw.addresses)
  // Extract IPv4 and IPv6 from addresses array
  const ipv4 = (raw.ipv4 as string) ?? addresses.find((a) => !a.includes(':')) ?? undefined
  const ipv6 = (raw.ipv6 as string) ?? addresses.find((a) => a.includes(':')) ?? undefined

  return {
    name: (raw.name as string) ?? 'unknown',
    mac: (raw.mac as string) ?? undefined,
    ipv4: ipv4,
    ipv6: ipv6,
    link_speed_mbps: (raw.link_speed_mbps as number) ?? (raw.speed_mbps as number) ?? undefined,
    speed_mbps: (raw.speed_mbps as number) ?? undefined,
    state: (raw.state as string) ?? undefined,
    tx_bytes: (raw.tx_bytes as number) ?? undefined,
    rx_bytes: (raw.rx_bytes as number) ?? undefined,
    tx_packets: (raw.tx_packets as number) ?? undefined,
    rx_packets: (raw.rx_packets as number) ?? undefined,
    mtu: (raw.mtu as number) ?? undefined,
    addresses: addresses,
  }
}

function normalizeArray(raw: Record<string, unknown>): RaidArray {
  // Map active_disks + spare_disks (string[]) to devices (ArrayDevice[])
  const activeDisks = ensureArray<string>(raw.active_disks).map((d) => ({
    device: typeof d === 'string' ? d : (d as Record<string, unknown>).device as string,
    state: 'active' as const,
  }))
  const spareDisks = ensureArray<string>(raw.spare_disks).map((d) => ({
    device: typeof d === 'string' ? d : (d as Record<string, unknown>).device as string,
    state: 'spare' as const,
  }))
  const devices = [...activeDisks, ...spareDisks]

  // level comes as "Raid5" from backend, normalize to "raid5"
  const rawLevel = (raw.level as string) ?? 'unknown'
  const level = rawLevel.toLowerCase().replace(/\s/g, '')

  return {
    name: (raw.name as string) ?? 'unknown',
    uuid: (raw.uuid as string) ?? undefined,
    level,
    state: (raw.status as string) ?? (raw.state as string) ?? 'unknown',
    total_bytes: (raw.size_bytes as number) ?? (raw.total_bytes as number) ?? 0,
    used_bytes: (raw.used_bytes as number) ?? 0,
    devices: devices.length > 0 ? devices : ensureArray(raw.devices),
    rebuild_percent: (raw.rebuild_percent as number) ?? null,
    filesystem: (raw.filesystem as string) ?? '',
    mount_point: (raw.mount_point as string) ?? '',
    device: (raw.device as string) ?? undefined,
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export const api = {
  // ---- Auth (skipE2EE -- handled manually at negotiate level) ----
  session: (body: { client_public_key: string; kem_public_key?: string; token?: string }) =>
    request<SessionResponse>('/api/v1/auth/session', { method: 'POST', body, skipE2EE: true }),

  login: (body: Record<string, string>) =>
    request<LoginResponse>('/api/v1/auth/login', { method: 'POST', body, skipE2EE: true }),

  setupStatus: () =>
    request<{ needed: boolean }>('/api/v1/auth/setup', { skipE2EE: true }),

  setup: (creds: { username: string; password: string }) =>
    request<{ user_id: number }>('/api/v1/auth/setup', { method: 'POST', body: creds, skipE2EE: true }),

  /** Hardware discovery for setup wizard (public, only works before first user is created). */
  setupDiscovery: () =>
    request<{ bays: BayInfo[]; disks: Disk[] }>('/api/v1/auth/setup/discovery', { skipE2EE: true }),

  logout: () => request<void>('/api/v1/auth/logout', { method: 'POST' }),

  // ---- Status (E2EE protected) ----
  getStatus: async (): Promise<SystemStatus> => {
    const raw = await request<unknown>('/api/v1/status')
    const data = unwrap<Record<string, unknown>>(raw)
    const status = normalizeStatus(data ?? {})

    // If status has no network data, fetch it separately
    if (!status.network || (status.network.interfaces ?? []).length === 0) {
      try {
        const netInterfaces = await api.getNetworkInterfaces()
        if (netInterfaces.length > 0) {
          status.network = { interfaces: netInterfaces }
        }
      } catch {
        // Network endpoint may not be available -- leave network empty
      }
    }

    return status
  },

  // ---- Network ----
  getNetworkInterfaces: async (): Promise<NetworkInterface[]> => {
    const raw = await request<unknown>('/api/v1/system/network')
    const data = unwrap<unknown>(raw)
    const arr = ensureArray<Record<string, unknown>>(data)
    return arr.map(normalizeNetworkInterface)
  },

  // ---- Storage ----
  getDisks: async (): Promise<Disk[]> => {
    const raw = await request<unknown>('/api/v1/storage/disks')
    const data = unwrap<unknown>(raw)
    const arr = ensureArray<Record<string, unknown>>(data)
    return arr.map(normalizeDisk)
  },

  getBays: async (): Promise<BayInfo[]> => {
    const raw = await request<unknown>('/api/v1/storage/bays')
    const data = unwrap<unknown>(raw)
    const arr = ensureArray<Record<string, unknown>>(data)
    return arr.map(normalizeBay)
  },

  getArrays: async (): Promise<RaidArray[]> => {
    const raw = await request<unknown>('/api/v1/storage/arrays')
    const data = unwrap<unknown>(raw)
    const arr = ensureArray<Record<string, unknown>>(data)
    return arr.map(normalizeArray)
  },

  createArray: (data: CreateArrayRequest) =>
    request<RaidArray>('/api/v1/storage/arrays', { method: 'POST', body: data }),

  initializeStorage: async (data: InitializeStorageRequest): Promise<InitializeStorageResponse> => {
    const raw = await request<unknown>('/api/v1/storage/initialize', { method: 'POST', body: data })
    return unwrap<InitializeStorageResponse>(raw)
  },

  getArrayStatus: async (name: string): Promise<ArrayDetail> => {
    const raw = await request<unknown>(`/api/v1/storage/arrays/${encodeURIComponent(name)}/status`)
    return unwrap<ArrayDetail>(raw)
  },

  addDiskToArray: (name: string, disk: string) =>
    request<{ added: string; array: string }>(
      `/api/v1/storage/arrays/${encodeURIComponent(name)}/add-disk`,
      { method: 'POST', body: { disk } },
    ),

  removeDiskFromArray: (name: string, disk: string) =>
    request<{ removed: string; array: string }>(
      `/api/v1/storage/arrays/${encodeURIComponent(name)}/remove-disk`,
      { method: 'POST', body: { disk } },
    ),

  startArrayScrub: (name: string) =>
    request<{ scrub_started: string }>(
      `/api/v1/storage/arrays/${encodeURIComponent(name)}/scrub`,
      { method: 'POST' },
    ),

  // ---- Btrfs ----
  getSubvolumes: async (): Promise<BtrfsSubvolume[]> => {
    const raw = await request<unknown>('/api/v1/storage/btrfs/subvolumes')
    const data = unwrap<unknown>(raw)
    return ensureArray<BtrfsSubvolume>(data)
  },

  createSubvolume: (name: string) =>
    request<{ name: string; path: string }>('/api/v1/storage/btrfs/subvolumes', {
      method: 'POST',
      body: { name },
    }),

  deleteSubvolume: (name: string) =>
    request<void>(`/api/v1/storage/btrfs/subvolumes/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),

  createSnapshot: (subvolume: string, name?: string) =>
    request<{ name: string; source_subvolume: string; path: string }>(
      '/api/v1/storage/btrfs/snapshots',
      {
        method: 'POST',
        body: name ? { subvolume, name } : { subvolume },
      },
    ),

  deleteSnapshot: (name: string) =>
    request<void>(`/api/v1/storage/btrfs/snapshots/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),

  getSnapshots: async (): Promise<BtrfsSnapshot[]> => {
    // Snapshots are listed as subvolumes; filter client-side by naming convention
    // or return all subvolumes and let the UI separate them.
    const raw = await request<unknown>('/api/v1/storage/btrfs/subvolumes')
    const data = unwrap<unknown>(raw)
    const all = ensureArray<Record<string, unknown>>(data)
    return all
      .filter((sv) => {
        const name = (sv.name as string) ?? ''
        return name.includes('-snap-') || name.includes('.snap.')
      })
      .map((sv) => ({
        name: (sv.name as string) ?? '',
        path: (sv.path as string) ?? '',
        created: (sv.created as string) ?? undefined,
        source_subvolume: (sv.source_subvolume as string) ?? undefined,
      }))
  },

  getScrubStatus: async (): Promise<BtrfsScrub> => {
    const raw = await request<unknown>('/api/v1/storage/btrfs/scrub')
    const data = unwrap<Record<string, unknown>>(raw)
    return {
      running: (data?.running as boolean) ?? false,
      last_run: (data?.last_run as string) ?? null,
      duration_secs: (data?.duration_secs as number) ?? null,
      bytes_scrubbed: (data?.bytes_scrubbed as number) ?? null,
      errors_found: (data?.errors_found as number) ?? 0,
    }
  },

  startScrub: () =>
    request<void>('/api/v1/storage/btrfs/scrub', { method: 'POST' }),

  getBtrfsUsage: async (): Promise<{ total_bytes: number; used_bytes: number; free_estimated: number }> => {
    const raw = await request<unknown>('/api/v1/storage/btrfs/usage')
    const data = unwrap<Record<string, unknown>>(raw)
    return {
      total_bytes: (data?.total_bytes as number) ?? 0,
      used_bytes: (data?.used_bytes as number) ?? 0,
      free_estimated: (data?.free_estimated as number) ?? 0,
    }
  },

  // ---- Shares ----
  getShares: async (): Promise<Share[]> => {
    const raw = await request<unknown>('/api/v1/shares')
    const data = unwrap<unknown>(raw)
    const arr = ensureArray<Record<string, unknown>>(data)
    return arr.map(normalizeShare)
  },

  createShare: (data: CreateShareRequest) =>
    request<Share>('/api/v1/shares', { method: 'POST', body: data }),

  deleteShare: (name: string) =>
    request<void>(`/api/v1/shares/${encodeURIComponent(name)}`, { method: 'DELETE' }),

  // ---- Rsync ----
  getRsyncModules: async (): Promise<RsyncModule[]> => {
    const raw = await request<unknown>('/api/v1/rsync/modules')
    const data = unwrap<unknown>(raw)
    return ensureArray<RsyncModule>(data)
  },

  createRsyncModule: (data: CreateRsyncModuleRequest) =>
    request<RsyncModule>('/api/v1/rsync/modules', { method: 'POST', body: data }),

  deleteRsyncModule: (name: string) =>
    request<void>(`/api/v1/rsync/modules/${encodeURIComponent(name)}`, { method: 'DELETE' }),

  // ---- Users ----
  getUsers: async (): Promise<NasUser[]> => {
    const raw = await request<unknown>('/api/v1/users')
    const data = unwrap<unknown>(raw)
    return ensureArray<NasUser>(data)
  },

  createUser: (data: CreateUserRequest) =>
    request<NasUser>('/api/v1/users', { method: 'POST', body: data }),

  deleteUser: (username: string) =>
    request<void>(`/api/v1/users/${encodeURIComponent(username)}`, { method: 'DELETE' }),

  changePassword: (data: ChangePasswordRequest) =>
    request<void>('/api/v1/users/password', { method: 'PUT', body: data }),

  // ---- System ----
  getLogs: async (lines?: number): Promise<LogEntry[]> => {
    const raw = await request<unknown>(`/api/v1/system/logs${lines ? `?lines=${lines}` : ''}`)
    const data = unwrap<unknown>(raw)

    // API returns { lines: string[], count: number } or LogEntry[]
    if (data != null && typeof data === 'object' && 'lines' in data) {
      const logLines = ensureArray<unknown>((data as Record<string, unknown>).lines)
      return logLines.map(normalizeLogEntry)
    }
    return ensureArray<unknown>(data).map(normalizeLogEntry)
  },

  getSshKeys: async (): Promise<SshKey[]> => {
    const raw = await request<unknown>('/api/v1/system/ssh-keys')
    const data = unwrap<unknown>(raw)
    return ensureArray<SshKey>(data)
  },

  addSshKey: (key: string) =>
    request<SshKey>('/api/v1/system/ssh-keys', { method: 'POST', body: { key } }),

  deleteSshKey: (fingerprint: string) =>
    request<void>(`/api/v1/system/ssh-keys/${encodeURIComponent(fingerprint)}`, { method: 'DELETE' }),

  getNetwork: async (): Promise<NetworkInterface[]> => {
    return api.getNetworkInterfaces()
  },

  reboot: () =>
    request<void>('/api/v1/system/reboot', { method: 'POST' }),

  shutdown: () =>
    request<void>('/api/v1/system/shutdown', { method: 'POST' }),

  uploadFirmware: async (file: File): Promise<void> => {
    const token = localStorage.getItem(TOKEN_KEY)
    const formData = new FormData()
    formData.append('firmware', file)

    const headers: Record<string, string> = {}
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    const res = await fetch(`${BASE_URL}/api/v1/system/firmware`, {
      method: 'POST',
      headers,
      body: formData,
    })

    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new ApiError(res.status, text || res.statusText)
    }
  },

  // ---- Active Directory / LDAP ----
  getAdConfig: async (): Promise<AdConfig> => {
    const raw = await request<unknown>('/api/v1/auth/ad/config')
    return unwrap<AdConfig>(raw)
  },

  saveAdConfig: (data: AdConfigRequest) =>
    request<{ message: string }>('/api/v1/auth/ad/config', { method: 'PUT', body: data }),

  testAdConnection: async (): Promise<AdTestResult> => {
    const raw = await request<unknown>('/api/v1/auth/ad/test', { method: 'POST' })
    return unwrap<AdTestResult>(raw)
  },

  joinAdDomain: async (): Promise<AdJoinResult> => {
    const raw = await request<unknown>('/api/v1/auth/ad/join', { method: 'POST' })
    return unwrap<AdJoinResult>(raw)
  },

  leaveAdDomain: async (): Promise<{ message: string }> => {
    const raw = await request<unknown>('/api/v1/auth/ad/leave', { method: 'POST' })
    return unwrap<{ message: string }>(raw)
  },

  syncAdUsers: async (): Promise<AdSyncResult> => {
    const raw = await request<unknown>('/api/v1/auth/ad/sync', { method: 'POST' })
    return unwrap<AdSyncResult>(raw)
  },

  getAdStatus: async (): Promise<AdStatus> => {
    const raw = await request<unknown>('/api/v1/auth/ad/status')
    return unwrap<AdStatus>(raw)
  },

  // ---- OIDC / OAuth2 ----

  /** Get OIDC configuration (protected, requires auth). */
  getOauthConfig: async (): Promise<OAuthConfig> => {
    const raw = await request<unknown>('/api/v1/auth/oauth/config')
    return unwrap<OAuthConfig>(raw)
  },

  /** Save OIDC configuration (protected, requires auth). */
  saveOauthConfig: (data: OAuthConfigRequest) =>
    request<{ success: boolean }>('/api/v1/auth/oauth/config', { method: 'PUT', body: data }),

  /** Test OIDC discovery (protected, requires auth). */
  testOauthDiscovery: async (): Promise<OAuthDiscoveryResult> => {
    const raw = await request<unknown>('/api/v1/auth/oauth/test', { method: 'POST' })
    return unwrap<OAuthDiscoveryResult>(raw)
  },

  /** Get available OAuth provider presets (public, no auth). */
  getOauthProviders: async (): Promise<OAuthProvider[]> => {
    const raw = await request<unknown>('/api/v1/auth/oauth/providers', { skipE2EE: true })
    const data = unwrap<Record<string, unknown>>(raw)
    return ensureArray<OAuthProvider>(data?.providers ?? data)
  },

  /** Check if OIDC is enabled (public, for login page). */
  getOauthStatus: async (): Promise<OAuthStatus> => {
    const raw = await request<unknown>('/api/v1/auth/oauth/status', { skipE2EE: true })
    return (raw ?? { enabled: false, provider_name: '' }) as OAuthStatus
  },
}

export { BASE_URL };
