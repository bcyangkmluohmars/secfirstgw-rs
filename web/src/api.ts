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

export interface AllowedService {
  protocol: string;
  port: number;
  description?: string;
}

export interface CustomZone {
  id: number;
  name: string;
  vlan_id: number;
  policy_inbound: 'drop' | 'accept';
  policy_outbound: 'drop' | 'accept';
  policy_forward: 'drop' | 'accept';
  allowed_services: AllowedService[];
  description: string;
}

export interface CustomZoneRequest {
  name: string;
  vlan_id: number;
  policy_inbound: 'drop' | 'accept';
  policy_outbound: 'drop' | 'accept';
  policy_forward: 'drop' | 'accept';
  allowed_services: AllowedService[];
  description: string;
}

export interface CustomZonePolicyUpdate {
  policy_inbound: 'drop' | 'accept';
  policy_outbound: 'drop' | 'accept';
  policy_forward: 'drop' | 'accept';
  allowed_services: AllowedService[];
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

// QoS types
export interface QosRule {
  id: number;
  name: string;
  interface: string;
  direction: 'egress' | 'ingress';
  bandwidth_kbps: number;
  priority: number;
  match_protocol?: string | null;
  match_port_min?: number | null;
  match_port_max?: number | null;
  match_ip?: string | null;
  match_dscp?: number | null;
  enabled: boolean;
}

export interface QosClassStats {
  interface: string;
  class_id: string;
  class_name: string;
  sent_bytes: number;
  sent_packets: number;
  dropped_packets: number;
  rate_bps: number;
}

export interface QosInterfaceStats {
  interface: string;
  classes: QosClassStats[];
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

// IPSec types
export type IpsecAuthMethod = 'certificate' | 'psk' | 'eap-mschapv2'
export type IpsecMode = 'roadwarrior' | 'site-to-site'

export interface IpsecTunnel {
  id: number
  name: string
  tunnel_type: 'ipsec'
  enabled: boolean
  listen_port: number
  public_key: string
  address: string
  address_v6?: string
  dns: string | null
  mtu: number
  zone: string
  bind_interface?: string
  peers: VpnPeer[]
  // IPSec-specific fields parsed from the tunnel config
  ipsec_config?: IpsecDbConfig
}

export interface IpsecDbConfig {
  mode: string
  auth_method: string
  local_id: string
  listen_port?: number
  local_addrs?: string
  pool_v4?: string
  pool_v6?: string
  local_ts: string[]
  remote_ts: string[]
  dns?: string
  zone: string
}

export interface CreateIpsecTunnelRequest {
  tunnel_type: 'ipsec'
  name: string
  mode: IpsecMode
  auth_method: IpsecAuthMethod
  local_id?: string
  listen_port?: number
  local_addrs?: string
  pool_v4?: string
  pool_v6?: string
  local_ts?: string[]
  remote_ts?: string[]
  dns?: string
  zone?: string
}

export interface IpsecChildSaStatus {
  name: string
  state: string
  local_ts: string
  remote_ts: string
}

export interface IpsecStatus {
  name: string
  is_up: boolean
  ike_state: string
  child_sas: IpsecChildSaStatus[]
}

// Site mesh types
export type MeshTopology = 'full-mesh' | 'hub-and-spoke'
export type SiteConnectionState = 'connected' | 'degraded' | 'down' | 'pending'

export interface SitePeer {
  id: number
  mesh_id: number
  name: string
  endpoint: string
  public_key: string
  local_subnets: string[]
  remote_subnets: string[]
  priority: number
  is_local: boolean
  enabled: boolean
  created_at: string
}

export interface SiteMesh {
  id: number
  name: string
  topology: MeshTopology
  listen_port: number
  keepalive_interval: number
  failover_timeout_secs: number
  enabled: boolean
  sites: SitePeer[]
  created_at: string
  updated_at: string
}

export interface SiteStatus {
  site_id: number
  site_name: string
  endpoint: string
  state: SiteConnectionState
  last_handshake_secs: number
  latency_ms: number | null
  rx_bytes: number
  tx_bytes: number
}

export interface MeshStatus {
  mesh_id: number
  mesh_name: string
  is_active: boolean
  interface_name: string
  sites: SiteStatus[]
}

export interface CreateMeshRequest {
  name: string
  topology?: MeshTopology
  listen_port?: number
  keepalive_interval?: number
  failover_timeout_secs?: number
  sites?: CreateSiteRequest[]
}

export interface CreateSiteRequest {
  name: string
  endpoint: string
  public_key?: string
  preshared_key?: string
  local_subnets?: string[]
  remote_subnets?: string[]
  priority?: number
  is_local?: boolean
}

export interface UpdateMeshRequest {
  name?: string
  topology?: MeshTopology
  listen_port?: number
  keepalive_interval?: number
  failover_timeout_secs?: number
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

export interface IdsTopSource {
  ip: string;
  count: number;
}

export interface IdsEventStats {
  total: number;
  critical_24h: number;
  by_severity: Record<string, number>;
  by_detector: Record<string, number>;
  top_sources: IdsTopSource[];
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
  check_type?: string
}

// Health check configuration types
export type HealthCheckType =
  | { type: 'icmp' }
  | { type: 'http'; url: string; expected_status?: number }
  | { type: 'dns'; domain: string; server: string }

export interface WanHealthConfig {
  interface: string
  health_check_type: HealthCheckType
  flap_threshold: number
  flap_window_secs: number
  sticky_sessions: boolean
  zone_pin: string | null
}

export interface FlapEvent {
  id: number
  interface: string
  new_state: string
  suppressed: boolean
  timestamp: string
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

  // QoS
  getQosRules: () => request<{ rules: QosRule[] }>('/api/v1/qos/rules'),
  createQosRule: (rule: Omit<QosRule, 'id'>) => request<{ id: number }>('/api/v1/qos/rules', { method: 'POST', body: rule }),
  updateQosRule: (id: number, rule: QosRule) => request<void>(`/api/v1/qos/rules/${id}`, { method: 'PUT', body: rule }),
  deleteQosRule: (id: number) => request<void>(`/api/v1/qos/rules/${id}`, { method: 'DELETE' }),
  applyQos: () => request<{ status: string }>('/api/v1/qos/apply', { method: 'POST' }),
  getQosStats: () => request<{ stats: QosInterfaceStats[] }>('/api/v1/qos/stats'),

  // VPN
  getVpnTunnels: () => request<{ tunnels: VpnTunnel[] }>('/api/v1/vpn/tunnels'),
  createVpnTunnel: (body: { name: string; listen_port: number; address: string; dns?: string; mtu?: number }) => request<{ tunnel: VpnTunnel }>('/api/v1/vpn/tunnels', { method: 'POST', body }),
  deleteVpnTunnel: (id: number) => request<void>(`/api/v1/vpn/tunnels/${id}`, { method: 'DELETE' }),
  startVpnTunnel: (id: number) => request<void>(`/api/v1/vpn/tunnels/${id}/start`, { method: 'POST' }),
  stopVpnTunnel: (id: number) => request<void>(`/api/v1/vpn/tunnels/${id}/stop`, { method: 'POST' }),
  getVpnTunnelStatus: async (id: number) => (await request<{ status: TunnelStatus }>(`/api/v1/vpn/tunnels/${id}/status`)).status,
  addVpnPeer: (tunnelId: number, peer: WgPeer) => request<void>(`/api/v1/vpn/tunnels/${tunnelId}/peers`, { method: 'POST', body: peer }),
  removeVpnPeer: (tunnelId: number, peerId: number) => request<void>(`/api/v1/vpn/tunnels/${tunnelId}/peers/${peerId}`, { method: 'DELETE' }),
  getVpnPeerConfig: (tunnelId: number, peerId: number, endpoint: string) =>
    request<{ config: string }>(`/api/v1/vpn/tunnels/${tunnelId}/peers/${peerId}/config?endpoint=${encodeURIComponent(endpoint)}`),

  // IPSec VPN (uses unified tunnel endpoints with tunnel_type: "ipsec")
  getIpsecTunnels: async () => {
    const res = await request<{ tunnels: VpnTunnel[] }>('/api/v1/vpn/tunnels')
    return { tunnels: (res.tunnels ?? []).filter(t => t.tunnel_type === 'ipsec') }
  },
  createIpsecTunnel: (body: CreateIpsecTunnelRequest) =>
    request<{ tunnel: VpnTunnel }>('/api/v1/vpn/tunnels', { method: 'POST', body }),
  getIpsecTunnel: (id: number) =>
    request<{ tunnel: VpnTunnel }>(`/api/v1/vpn/tunnels/${id}`),
  updateIpsecTunnel: (id: number, body: CreateIpsecTunnelRequest) =>
    request<{ tunnel: VpnTunnel }>(`/api/v1/vpn/tunnels/${id}`, { method: 'PUT', body }),
  deleteIpsecTunnel: (id: number) =>
    request<void>(`/api/v1/vpn/tunnels/${id}`, { method: 'DELETE' }),
  startIpsecTunnel: (id: number) =>
    request<void>(`/api/v1/vpn/tunnels/${id}/start`, { method: 'POST' }),
  stopIpsecTunnel: (id: number) =>
    request<void>(`/api/v1/vpn/tunnels/${id}/stop`, { method: 'POST' }),
  getIpsecTunnelStatus: (id: number) =>
    request<{ status: IpsecStatus }>(`/api/v1/vpn/tunnels/${id}/status`),

  // Site-to-site VPN meshes
  getSiteMeshes: () => request<{ meshes: SiteMesh[] }>('/api/v1/vpn/sites'),
  createSiteMesh: (body: CreateMeshRequest) =>
    request<{ mesh: SiteMesh }>('/api/v1/vpn/sites', { method: 'POST', body }),
  getSiteMesh: (id: number) =>
    request<{ mesh: SiteMesh }>(`/api/v1/vpn/sites/${id}`),
  updateSiteMesh: (id: number, body: UpdateMeshRequest) =>
    request<{ mesh: SiteMesh }>(`/api/v1/vpn/sites/${id}`, { method: 'PUT', body }),
  deleteSiteMesh: (id: number) =>
    request<void>(`/api/v1/vpn/sites/${id}`, { method: 'DELETE' }),
  startSiteMesh: (id: number) =>
    request<void>(`/api/v1/vpn/sites/${id}/start`, { method: 'POST' }),
  stopSiteMesh: (id: number) =>
    request<void>(`/api/v1/vpn/sites/${id}/stop`, { method: 'POST' }),
  getSiteMeshStatus: (id: number) =>
    request<{ status: MeshStatus }>(`/api/v1/vpn/sites/${id}/status`),
  addSiteMeshPeer: (meshId: number, site: CreateSiteRequest) =>
    request<{ site: SitePeer }>(`/api/v1/vpn/sites/${meshId}/peers`, { method: 'POST', body: site }),
  removeSiteMeshPeer: (meshId: number, peerId: number) =>
    request<void>(`/api/v1/vpn/sites/${meshId}/peers/${peerId}`, { method: 'DELETE' }),

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
  getIdsEvents: (opts?: { limit?: number; severity?: string; detector?: string; since?: string }) => {
    const params = new URLSearchParams();
    if (opts?.limit) params.set('limit', String(opts.limit));
    if (opts?.severity) params.set('severity', opts.severity);
    if (opts?.detector) params.set('detector', opts.detector);
    if (opts?.since) params.set('since', opts.since);
    const qs = params.toString();
    return request<{ events: IdsEvent[] }>(`/api/v1/ids/events${qs ? '?' + qs : ''}`);
  },
  getIdsStats: () => request<IdsEventStats>('/api/v1/ids/events/stats'),

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

  // Custom Zones (IoT, VPN, user-defined)
  getCustomZones: () =>
    request<{ zones: CustomZone[] }>('/api/v1/zones/custom'),
  createCustomZone: (zone: CustomZoneRequest) =>
    request<{ id: number; name: string }>('/api/v1/zones/custom', { method: 'POST', body: zone }),
  updateCustomZone: (id: number, zone: CustomZoneRequest) =>
    request<{ ok: boolean }>(`/api/v1/zones/custom/${id}`, { method: 'PUT', body: zone }),
  deleteCustomZone: (id: number) =>
    request<{ ok: boolean }>(`/api/v1/zones/custom/${id}`, { method: 'DELETE' }),
  updateCustomZonePolicy: (id: number, policy: CustomZonePolicyUpdate) =>
    request<{ ok: boolean }>(`/api/v1/zones/custom/${id}/policy`, { method: 'PUT', body: policy }),

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
  getWanHealthConfig: (iface: string) =>
    request<{ health_config: WanHealthConfig }>(`/api/v1/wan/${encodeURIComponent(iface)}/health-config`),
  setWanHealthConfig: (iface: string, config: WanHealthConfig) =>
    request<{ status: string; health_config: WanHealthConfig }>(`/api/v1/wan/${encodeURIComponent(iface)}/health-config`, { method: 'PUT', body: config }),
  getWanFlapLog: (iface?: string, limit?: number) => {
    const params = new URLSearchParams()
    if (iface) params.set('interface', iface)
    if (limit) params.set('limit', String(limit))
    const qs = params.toString()
    return request<{ flap_log: FlapEvent[] }>(`/api/v1/wan/flap-log${qs ? `?${qs}` : ''}`)
  },

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

  // Backup / Restore
  //
  // downloadBackup bypasses the normal request() wrapper because the response
  // is a file download (Content-Disposition: attachment), not a JSON API
  // response. We still send the auth token and handle E2EE headers manually.
  downloadBackup: async (): Promise<void> => {
    const token = localStorage.getItem('token');
    const hdrs: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) hdrs['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${BASE_URL}/api/v1/settings/backup`, { headers: hdrs });
    if (!res.ok) throw new ApiError(res.status, await res.text().catch(() => res.statusText));
    const blob = await res.blob();
    const disposition = res.headers.get('Content-Disposition') ?? '';
    const match = /filename="?([^"]+)"?/.exec(disposition);
    const filename = match?.[1] ?? 'sfgw-backup.json';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
  restoreBackup: (backup: unknown) =>
    request<{ status: string; stats: Record<string, number> }>('/api/v1/settings/restore', { method: 'POST', body: backup }),

  // DDNS
  getDdnsConfigs: () => request<{ configs: DdnsConfig[] }>('/api/v1/ddns'),
  createDdnsConfig: (config: DdnsConfigCreate) =>
    request<{ id: number; status: string }>('/api/v1/ddns', { method: 'POST', body: config }),
  updateDdnsConfig: (id: number, config: DdnsConfigCreate) =>
    request<{ status: string }>(`/api/v1/ddns/${id}`, { method: 'PUT', body: config }),
  deleteDdnsConfig: (id: number) =>
    request<{ status: string }>(`/api/v1/ddns/${id}`, { method: 'DELETE' }),
  forceDdnsUpdate: (id: number) =>
    request<{ result: DdnsUpdateResult }>(`/api/v1/ddns/${id}/update`, { method: 'POST' }),

  // UPnP / NAT-PMP
  getUpnpSettings: () => request<{ upnp: UpnpSettings }>('/api/v1/upnp/settings'),
  setUpnpSettings: (settings: Partial<UpnpSettings>) =>
    request<{ upnp: UpnpSettings; note: string }>('/api/v1/upnp/settings', { method: 'PUT', body: settings }),
  getUpnpMappings: () => request<{ mappings: UpnpMapping[] }>('/api/v1/upnp/mappings'),
  deleteUpnpMapping: (id: number) =>
    request<{ status: string; id: number }>(`/api/v1/upnp/mappings/${id}`, { method: 'DELETE' }),

  // Firmware Update
  checkForUpdate: () =>
    request<UpdateCheckResult>('/api/v1/system/update/check'),
  applyUpdate: () =>
    request<{ status: string; message: string }>('/api/v1/system/update/apply', { method: 'POST' }),
  rollbackUpdate: () =>
    request<{ status: string; message: string }>('/api/v1/system/update/rollback', { method: 'POST' }),
  getUpdateSettings: () =>
    request<{ settings: UpdateSettings }>('/api/v1/system/update/settings'),
  setUpdateSettings: (settings: Partial<UpdateSettings>) =>
    request<{ settings: UpdateSettings }>('/api/v1/system/update/settings', { method: 'PUT', body: settings }),

  // Forward-secret encrypted logs
  getLogDays: () =>
    request<{ days: LogDaySummary[] }>('/api/v1/logs/days'),
  getLogStatus: () =>
    request<{ status: LogKeyStatus }>('/api/v1/logs/status'),
  exportLogDay: async (date: string): Promise<LogExportResult> => {
    const token = localStorage.getItem('token');
    const hdrs: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) hdrs['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${BASE_URL}/api/v1/logs/${encodeURIComponent(date)}/export`, { headers: hdrs });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new ApiError(res.status, text);
    }
    return res.json();
  },
  destroyLogDay: (date: string) =>
    request<{ status: string; date: string; message: string }>(`/api/v1/logs/${encodeURIComponent(date)}/destroy`, { method: 'POST' }),
};

export type WirelessBandwidthMode = 'auto' | 'HT20' | 'HT40' | 'VHT80';

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
  channel: number;
  tx_power: number;
  bandwidth: WirelessBandwidthMode;
  fast_roaming: boolean;
  band_steering: boolean;
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
  channel?: number;
  tx_power?: number;
  bandwidth?: WirelessBandwidthMode;
  fast_roaming?: boolean;
  band_steering?: boolean;
}

// DDNS types
export type DdnsProvider = 'dyndns2' | 'duckdns' | 'cloudflare';

export interface DdnsConfig {
  id: number;
  hostname: string;
  provider: string;
  server: string | null;
  username: string | null;
  password: string | null;
  wan_interface: string;
  update_interval_secs: number;
  enabled: boolean;
  last_ip: string | null;
  last_update: string | null;
  last_status: string | null;
}

export interface DdnsConfigCreate {
  hostname: string;
  provider: string;
  server?: string | null;
  username?: string | null;
  password?: string | null;
  wan_interface: string;
  update_interval_secs: number;
  enabled: boolean;
}

export interface DdnsUpdateResult {
  success: boolean;
  status: string;
  ip: string;
}

// UPnP types
export interface UpnpSettings {
  enabled: boolean;
  port_min: number;
  port_max: number;
  max_per_ip: number;
}

export interface UpnpMapping {
  id: number;
  protocol: string;
  external_port: number;
  internal_ip: string;
  internal_port: number;
  description: string;
  client_ip: string;
  ttl_seconds: number;
  created_at: string;
  expires_at: string;
}

// Firmware Update types
export interface FirmwareInfo {
  version: string;
  sha256: string;
  download_url: string;
  release_notes: string;
  size_bytes: number;
  prerelease: boolean;
  published_at: string;
}

export interface UpdateCheckResult {
  current_version: string;
  update_available: boolean;
  checked_at: string;
  available: FirmwareInfo | null;
}

export interface UpdateSettings {
  update_channel: string;
  auto_check: boolean;
  check_interval_hours: number;
  last_check: string | null;
  update_url: string;
}

// Forward-secret encrypted log types
export interface LogDaySummary {
  date: string;
  entry_count: number;
  exported: boolean;
  key_available: boolean;
}

export interface LogKeyStatus {
  current_date: string;
  ratchet_position: number;
  total_days_stored: number;
  total_entries: number;
  destroyed_days: number;
}

export interface LogExportEntry {
  id: number;
  date: string;
  level: string;
  module: string;
  message: string;
  created_at: string;
}

export interface LogExportResult {
  date: string;
  entries: LogExportEntry[];
  count: number;
  exported: boolean;
}

export { BASE_URL };
