// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  getEnvelopeKey,
  encryptPayload,
  decryptPayload,
  hasE2EE,
} from './crypto';

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

interface ApiOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  skipE2EE?: boolean;
}

// E2EE re-negotiate callback — set by crypto.ts to break circular import
let _renegotiateFn: (() => Promise<boolean>) | null = null;

export function setRenegotiateFn(fn: () => Promise<boolean>): void {
  _renegotiateFn = fn;
}

// Guard against concurrent re-negotiate storms
let renegotiating: Promise<boolean> | null = null;

async function request<T>(path: string, opts: ApiOptions = {}, _retry = false): Promise<T> {
  const { method = 'GET', body, headers = {}, skipE2EE = false } = opts;

  const token = localStorage.getItem('token');
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
    // E2EE key lost (server restart) but DB session still valid — re-negotiate once
    if (!_retry && token && !skipE2EE && _renegotiateFn) {
      if (!renegotiating) {
        renegotiating = _renegotiateFn().finally(() => { renegotiating = null; });
      }
      const ok = await renegotiating;
      if (ok) {
        return request(path, opts, true);
      }
    }
    localStorage.removeItem('token');
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

  return res.json();
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(`HTTP ${status}: ${message}`);
    this.name = 'ApiError';
    this.status = status;
  }
}

// ---- Auth helpers ----

export function getToken(): string | null {
  return localStorage.getItem('token');
}

export function setToken(token: string): void {
  localStorage.setItem('token', token);
}

export function clearToken(): void {
  localStorage.removeItem('token');
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem('token');
}

// ---- Types ----

export interface NetIoStats {
  total_rx_bytes: number;
  total_tx_bytes: number;
  interfaces: { name: string; rx_bytes: number; tx_bytes: number }[];
}

export interface QueueStats {
  queue: number;
  rx_packets: number;
  rx_bytes: number;
  tx_packets: number;
  tx_bytes: number;
}

export interface NicQueueStats {
  name: string;
  driver: string;
  queues: QueueStats[];
}

export interface SystemStatus {
  status: string;
  uptime_secs: number;
  cpu_count: number;
  cpu_percent: number;
  load_average: [number, number, number];
  memory: { total_mb: number; used_mb: number; free_mb: number };
  network: NetIoStats;
  nic_queues?: NicQueueStats[];
  services: Record<string, string>;
}

export interface NetworkInterface {
  name: string;
  mac: string;
  ips: string[];
  mtu: number;
  is_up: boolean;
  role: string;  // computed from pvid — not returned by API
  vlan_id: number | null;
  pvid: number;
  tagged_vlans: number[];
  enabled: boolean;
  speed: string | null;
  driver: string | null;
  port_type: string | null;
}

// Well-known PVID → zone name mapping (matches DB networks table)
const PVID_ZONE_MAP: Record<number, string> = {
  0: 'wan', 1: 'void', 10: 'lan', 3000: 'mgmt', 3001: 'dmz', 3002: 'guest',
};

export function pvidToZone(pvid: number): string {
  return PVID_ZONE_MAP[pvid] ?? 'unknown';
}

function enrichInterface(iface: Omit<NetworkInterface, 'role'>): NetworkInterface {
  return { ...iface, role: pvidToZone(iface.pvid) };
}

export interface PortConfig {
  name: string;
  mac: string;
  ips: string[];
  mtu: number;
  is_up: boolean;
  pvid: number;
  tagged_vlans: number[];
  enabled: boolean;
  speed: string | null;
  driver: string | null;
  port_type: string | null;
}

export interface ZoneInfo {
  id: number;
  name: string;
  zone: string;
  vlan_id: number | null;
  subnet: string | null;
  gateway: string | null;
  dhcp_enabled: boolean;
  enabled: boolean;
  interfaces?: string[];  // only on zone_get, not zone_list
}

export interface Device {
  mac: string;
  name: string | null;
  model: string | null;
  ip: string | null;
  adopted: boolean;
  last_seen: string | null;
}

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

// Firewall types
export interface FirewallRule {
  id: number;
  chain: string;
  priority: number;
  detail: {
    action: string;
    protocol?: string;
    source?: string;
    destination?: string;
    port?: number;
    comment?: string;
    vlan?: number;
    rate_limit?: string;
  };
  enabled: boolean;
}

// VPN types
export interface VpnPeer {
  id: number;
  tunnel_id: number;
  name: string | null;
  public_key: string;
  preshared_key?: string;
  address: string;
  address_v6?: string;
  allowed_ips: string[];
  endpoint?: string;
  persistent_keepalive?: number;
  routing_mode: string;
  dns?: string;
  enabled: boolean;
  created_at: string;
}

export interface VpnTunnel {
  id: number;
  name: string;
  tunnel_type: string;
  enabled: boolean;
  listen_port: number;
  public_key: string;
  address: string;
  address_v6?: string;
  dns: string | null;
  mtu: number;
  zone: string;
  bind_interface?: string;
  peers: VpnPeer[];
}

export interface WgPeer {
  public_key: string;
  preshared_key?: string;
  allowed_ips: string[];
  endpoint?: string;
  persistent_keepalive?: number;
}

export interface TunnelStatus {
  name: string;
  is_up: boolean;
  rx_bytes: number;
  tx_bytes: number;
  peers: { public_key: string; endpoint: string | null; last_handshake_secs: number; rx_bytes: number; tx_bytes: number }[];
}

// DNS types
export interface DnsConfig {
  upstream_dns: string[];
  domain: string;
  dnssec: boolean;
  rebind_protection: boolean;
  cache_size: number;
  bind_interfaces: string[];
}

export interface DhcpRange {
  interface: string;
  start_ip: string;
  end_ip: string;
  netmask: string;
  gateway: string;
  lease_time: string;
  vlan_id: number | null;
}

export interface DhcpStaticLease {
  mac: string;
  ip: string;
  hostname: string;
}

export interface DhcpLease {
  expires: number;
  mac: string;
  ip: string;
  hostname: string;
  client_id: string;
}

export interface DnsOverride {
  domain: string;
  ip: string;
}

// IDS types
export interface IdsEvent {
  id: number;
  timestamp: string;
  severity: string;
  detector: string;
  source_mac: string;
  source_ip: string;
  interface: string;
  vlan: number | null;
  description: string;
}

// Device types
export interface DeviceSummary {
  id: number;
  mac: string;
  name: string | null;
  model: string | null;
  ip: string | null;
  adopted: boolean;
  last_seen: string | null;
  state: string;
}

// Ubiquiti Inform types
export interface UbntValidation {
  oui_valid: boolean
  ip_matches: boolean
  model_known: boolean
  reason: string | null
}

export interface UbntFingerprint {
  cpuid: string
  serialno: string
  device_hashid: string
  systemid: string
  boardrevision: string
  vendorid: string
  manufid: string
  mfgweek: string
}

export type UbntDeviceState = 'pending' | 'ignored' | 'adopting' | 'adopted' | 'phantom'

export interface SwitchPortStats {
  port_idx: number
  up: boolean
  enable: boolean
  speed: number
  full_duplex: boolean
  media: string
  is_uplink: boolean
  rx_bytes: number
  rx_packets: number
  rx_errors: number
  rx_dropped: number
  tx_bytes: number
  tx_packets: number
  tx_errors: number
  tx_dropped: number
  port_poe: boolean
  poe_enable?: boolean
  poe_good?: boolean
  poe_mode?: string
  poe_class?: string
  poe_current?: string
  poe_voltage?: string
  poe_power?: string
  stp_state: string
  mac_table: { mac: string; age: number; vlan: number }[]
  satisfaction: number
}

export interface DeviceStats {
  port_table: SwitchPortStats[]
  sys_stats?: { loadavg_1: string; loadavg_5: string; loadavg_15: string; mem_total: number; mem_used: number }
  system_stats?: { cpu: string; mem: string; uptime: string }
  if_table: { name: string; ip: string; mac: string; netmask: string; up: boolean; speed: number; num_port: number }[]
  uptime: number
  uptime_str: string
  satisfaction: number
  power_source_voltage?: string
  total_max_power?: number
  overheating: boolean
  internet: boolean
  kernel_version: string
  architecture: string
  serial: string
  total_mac_in_used: number
  gateway_ip: string
  updated_at: string
}

export interface SwitchPortConfig {
  port_idx: number
  name: string
  enabled: boolean
  pvid: number
  poe_mode: string
  egress_mode: string
  tagged_vlans: number[]
  isolation: boolean
  egress_rate_limit_kbps: number
}

export interface SwitchConfig {
  ports: SwitchPortConfig[]
}

export interface UbntDevice {
  mac: string
  model: string
  model_display: string
  source_ip: string
  claimed_ip: string
  firmware_version: string
  hostname: string
  state: UbntDeviceState
  authkey: string | null
  ssh_username: string | null
  ssh_password_hash: string | null
  config_applied: boolean
  fingerprint: UbntFingerprint | null
  last_seen: string
  first_seen: string
  validation: UbntValidation
  port_config?: SwitchConfig | null
  stats?: DeviceStats
}

// WAN types
export interface WanPortConfig {
  interface: string
  connection: WanConnectionType
  enabled: boolean
  priority: number
  weight: number
  health_check: string
  health_interval_secs: number
  mtu: number | null
  dns_override: string[] | null
  mac_override: string | null
}

export type WanConnectionType =
  | { type: 'dhcp' }
  | { type: 'static'; address: string; gateway: string; address_v6?: string; gateway_v6?: string }
  | { type: 'pppoe'; username: string; password: string; mtu?: number; service_name?: string; vlan_id?: number }
  | { type: 'dslite'; aftr?: string }
  | { type: 'vlan'; vlan_id: number; inner: WanConnectionType }

export interface WanStatus {
  interface: string
  connection_type: string
  link_up: boolean
  ipv4: string | null
  ipv6: string | null
  gateway_v4: string | null
  gateway_v6: string | null
  dns_servers: string[]
  uptime_secs: number
  rx_bytes: number
  tx_bytes: number
}

// WAN failover/health types
export interface WanFailoverConfig {
  mode: 'failover' | 'loadbalance'
  groups: { name: string; mode: string; interfaces: { interface: string; weight: number; gateway: string; priority: number; check_target: string; enabled: boolean }[] }[]
}

export interface WanHealthEntry {
  interface: string
  healthy: boolean
  enabled: boolean
  latency_ms: number | null
}

// User management types
export interface UserInfo {
  id: number;
  username: string;
  role: string;
  created_at: string;
}

// ---- API endpoints ----

export const api = {
  // Protected (auto-E2EE when envelope key set)
  getStatus: () => request<SystemStatus>('/api/v1/status'),
  getSystem: () => request<Record<string, unknown>>('/api/v1/system'),
  getInterfaces: async () => {
    const res = await request<{ interfaces: Omit<NetworkInterface, 'role'>[] }>('/api/v1/interfaces');
    return { interfaces: (res.interfaces ?? []).map(enrichInterface) };
  },
  updateInterface: (name: string, body: { role?: string; vlan_id?: number | null; mtu?: number; enabled?: boolean }) =>
    request<{ ok: boolean }>(`/api/v1/interfaces/${encodeURIComponent(name)}`, { method: 'PUT', body }),
  toggleInterface: (name: string, enabled: boolean) =>
    request<{ ok: boolean }>(`/api/v1/interfaces/${encodeURIComponent(name)}/toggle`, { method: 'POST', body: { enabled } }),
  createVlan: (body: { parent: string; vlan_id: number; role?: string }) =>
    request<{ name: string; vlan_id: number; role: string }>('/api/v1/interfaces/vlan', { method: 'POST', body }),
  deleteInterface: (name: string) =>
    request<{ ok: boolean }>(`/api/v1/interfaces/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  getMe: () => request<{ user: { id: number; username: string; role: string } }>('/api/v1/auth/me'),
  logout: () => request<void>('/api/v1/auth/logout', { method: 'POST' }),

  // Public (no E2EE middleware — handled manually)
  session: (body: { client_public_key: string; kem_public_key?: string; token?: string }) =>
    request<SessionResponse>('/api/v1/auth/session', { method: 'POST', body, skipE2EE: true }),
  login: (body: Record<string, string>) =>
    request<LoginResponse>('/api/v1/auth/login', { method: 'POST', body, skipE2EE: true }),
  setupStatus: () =>
    request<{ needed: boolean }>('/api/v1/auth/setup', { skipE2EE: true }),
  setup: (creds: { username: string; password: string }) =>
    request<{ user_id: number }>('/api/v1/auth/setup', { method: 'POST', body: creds, skipE2EE: true }),

  // Users
  getUsers: () => request<{ users: UserInfo[] }>('/api/v1/users'),
  createUser: (body: { username: string; password: string; role?: string }) =>
    request<{ id: number; username: string; role: string }>('/api/v1/users', { method: 'POST', body }),
  updateUser: (id: number, body: { username?: string; role?: string }) =>
    request<{ ok: boolean }>(`/api/v1/users/${id}`, { method: 'PUT', body }),
  deleteUser: (id: number) =>
    request<{ ok: boolean }>(`/api/v1/users/${id}`, { method: 'DELETE' }),
  changePassword: (id: number, password: string) =>
    request<{ ok: boolean }>(`/api/v1/users/${id}/password`, { method: 'POST', body: { password } }),

  // Firewall
  getFirewallRules: () => request<{ rules: FirewallRule[] }>('/api/v1/firewall/rules'),
  createFirewallRule: (rule: Omit<FirewallRule, 'id'>) => request<{ id: number }>('/api/v1/firewall/rules', { method: 'POST', body: rule }),
  updateFirewallRule: (id: number, rule: FirewallRule) => request<void>(`/api/v1/firewall/rules/${id}`, { method: 'PUT', body: rule }),
  deleteFirewallRule: (id: number) => request<void>(`/api/v1/firewall/rules/${id}`, { method: 'DELETE' }),
  toggleFirewallRule: (id: number, enabled: boolean) => request<void>(`/api/v1/firewall/rules/${id}/toggle`, { method: 'POST', body: { enabled } }),
  applyFirewall: () => request<void>('/api/v1/firewall/apply', { method: 'POST' }),

  // VPN
  getVpnTunnels: () => request<{ tunnels: VpnTunnel[] }>('/api/v1/vpn/tunnels'),
  createVpnTunnel: (body: { name: string; listen_port: number; address: string; dns?: string; mtu?: number }) => request<{ tunnel: VpnTunnel }>('/api/v1/vpn/tunnels', { method: 'POST', body }),
  deleteVpnTunnel: (id: number) => request<void>(`/api/v1/vpn/tunnels/${id}`, { method: 'DELETE' }),
  startVpnTunnel: (id: number) => request<void>(`/api/v1/vpn/tunnels/${id}/start`, { method: 'POST' }),
  stopVpnTunnel: (id: number) => request<void>(`/api/v1/vpn/tunnels/${id}/stop`, { method: 'POST' }),
  getVpnTunnelStatus: async (id: number) => (await request<{ status: TunnelStatus }>(`/api/v1/vpn/tunnels/${id}/status`)).status,
  addVpnPeer: (tunnelId: number, peer: WgPeer) => request<void>(`/api/v1/vpn/tunnels/${tunnelId}/peers`, { method: 'POST', body: peer }),
  removeVpnPeer: (tunnelId: number, peerId: number) => request<void>(`/api/v1/vpn/tunnels/${tunnelId}/peers/${peerId}`, { method: 'DELETE' }),

  // DNS
  getDnsConfig: () => request<{ config: DnsConfig }>('/api/v1/dns/config'),
  saveDnsConfig: (config: DnsConfig) => request<void>('/api/v1/dns/config', { method: 'PUT', body: config }),
  getDhcpRanges: () => request<{ ranges: DhcpRange[] }>('/api/v1/dns/dhcp/ranges'),
  saveDhcpRanges: (ranges: DhcpRange[]) => request<void>('/api/v1/dns/dhcp/ranges', { method: 'PUT', body: ranges }),
  getDhcpLeases: () => request<{ leases: DhcpLease[] }>('/api/v1/dns/dhcp/leases'),
  getDhcpStaticLeases: () => request<{ leases: DhcpStaticLease[] }>('/api/v1/dns/dhcp/static'),
  saveDhcpStaticLeases: (leases: DhcpStaticLease[]) => request<void>('/api/v1/dns/dhcp/static', { method: 'PUT', body: leases }),
  getDnsOverrides: () => request<{ overrides: DnsOverride[] }>('/api/v1/dns/overrides'),
  saveDnsOverrides: (overrides: DnsOverride[]) => request<void>('/api/v1/dns/overrides', { method: 'PUT', body: overrides }),

  // IDS
  getIdsEvents: (limit?: number, severity?: string) => {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (severity) params.set('severity', severity);
    const qs = params.toString();
    return request<{ events: IdsEvent[] }>(`/api/v1/ids/events${qs ? '?' + qs : ''}`);
  },
  getIdsStats: () => request<Record<string, unknown>>('/api/v1/ids/events/stats'),

  // Devices
  getDevices: () => request<{ devices: DeviceSummary[] }>('/api/v1/devices'),
  getPendingDevices: () => request<{ devices: DeviceSummary[] }>('/api/v1/devices/pending'),
  approveDevice: (mac: string, body: { device_mac: string; device_model: string; device_ip: string; device_public_key: string; device_kem_public_key?: string }) => request<unknown>(`/api/v1/devices/${encodeURIComponent(mac)}/approve`, { method: 'POST', body }),
  rejectDevice: (mac: string) => request<void>(`/api/v1/devices/${encodeURIComponent(mac)}/reject`, { method: 'POST' }),
  getDeviceConfig: (mac: string) => request<unknown>(`/api/v1/devices/${encodeURIComponent(mac)}/config`),
  pushDeviceConfig: (mac: string, config: unknown) => request<{ sequence: number }>(`/api/v1/devices/${encodeURIComponent(mac)}/config`, { method: 'PUT', body: config }),

  // Personality
  getPersonality: () => request<{ active: string; personalities: { name: string; description: string; active: boolean }[] }>('/api/v1/personality'),
  setPersonality: (name: string) => request<{ ok: boolean; active: string }>('/api/v1/personality', { method: 'PUT', body: { name } }),

  // Ports (PVID/tagged VLAN config)
  getPort: (name: string) =>
    request<PortConfig>(`/api/v1/ports/${encodeURIComponent(name)}`),
  updatePort: (name: string, body: { pvid?: number; tagged_vlans?: number[] }) =>
    request<{ ok: boolean }>(`/api/v1/ports/${encodeURIComponent(name)}`, { method: 'PUT', body }),

  // Zones
  getZones: () =>
    request<{ zones: ZoneInfo[] }>('/api/v1/zones'),
  getZone: (zone: string) =>
    request<ZoneInfo>(`/api/v1/zones/${encodeURIComponent(zone)}`),

  // WAN
  getWanConfigs: () => request<{ configs: WanPortConfig[] }>('/api/v1/wan'),
  getWanConfig: (iface: string) => request<{ config: WanPortConfig }>(`/api/v1/wan/${encodeURIComponent(iface)}`),
  setWanConfig: (iface: string, config: WanPortConfig) => request<void>(`/api/v1/wan/${encodeURIComponent(iface)}`, { method: 'PUT', body: config }),
  deleteWanConfig: (iface: string) => request<void>(`/api/v1/wan/${encodeURIComponent(iface)}`, { method: 'DELETE' }),
  getWanStatus: (iface: string) => request<{ wan_status: WanStatus }>(`/api/v1/wan/${encodeURIComponent(iface)}/status`),
  reconnectWan: (iface: string) => request<void>(`/api/v1/wan/${encodeURIComponent(iface)}/reconnect`, { method: 'POST' }),
  getWanFailover: () => request<WanFailoverConfig>('/api/v1/wan/failover'),
  setWanFailover: (mode: 'failover' | 'loadbalance') => request<void>('/api/v1/wan/failover', { method: 'PUT', body: { mode } }),
  getWanHealth: () => request<{ health: WanHealthEntry[] }>('/api/v1/wan/health'),

  // Ubiquiti Inform
  getInformSettings: () => request<{ ubiquiti_inform_enabled: boolean }>('/api/v1/inform/settings'),
  setInformSettings: (enabled: boolean) => request<{ ubiquiti_inform_enabled: boolean }>('/api/v1/inform/settings', { method: 'PUT', body: { enabled } }),
  getInformDevices: () => request<{ devices: UbntDevice[] }>('/api/v1/inform/devices'),
  adoptInformDevice: (mac: string) => request<{ status: string; mac: string }>(`/api/v1/inform/devices/${encodeURIComponent(mac)}/adopt`, { method: 'POST' }),
  ignoreInformDevice: (mac: string) => request<{ status: string; mac: string }>(`/api/v1/inform/devices/${encodeURIComponent(mac)}/ignore`, { method: 'POST' }),
  removeInformDevice: (mac: string) => request<{ status: string; mac: string }>(`/api/v1/inform/devices/${encodeURIComponent(mac)}`, { method: 'DELETE' }),
  getInformDevicePorts: (mac: string) => request<{ ports: SwitchConfig | null }>(`/api/v1/inform/devices/${encodeURIComponent(mac)}/ports`),
  setInformDevicePorts: (mac: string, config: SwitchConfig) => request<{ status: string; mac: string }>(`/api/v1/inform/devices/${encodeURIComponent(mac)}/ports`, { method: 'PUT', body: config }),

  // Wireless networks
  getWirelessNetworks: () => request<{ networks: WirelessNetwork[] }>('/api/v1/wireless'),
  getWirelessNetwork: (id: number) => request<{ network: WirelessNetwork }>(`/api/v1/wireless/${id}`),
  createWirelessNetwork: (net: WirelessNetworkCreate) => request<{ status: string; id: number }>('/api/v1/wireless', { method: 'POST', body: net }),
  updateWirelessNetwork: (id: number, net: WirelessNetworkCreate) => request<{ status: string }>(`/api/v1/wireless/${id}`, { method: 'PUT', body: net }),
  deleteWirelessNetwork: (id: number) => request<{ status: string }>(`/api/v1/wireless/${id}`, { method: 'DELETE' }),
};

export interface WirelessNetwork {
  id: number;
  ssid: string;
  security: 'open' | 'wpa2' | 'wpa3';
  hidden: boolean;
  band: 'both' | '2g' | '5g';
  vlan_id: number | null;
  is_guest: boolean;
  l2_isolation: boolean;
  enabled: boolean;
}

export interface WirelessNetworkCreate {
  ssid: string;
  security: 'open' | 'wpa2' | 'wpa3';
  psk?: string;
  hidden?: boolean;
  band?: 'both' | '2g' | '5g';
  vlan_id?: number | null;
  is_guest?: boolean;
  l2_isolation?: boolean;
  enabled?: boolean;
}

export { BASE_URL };
