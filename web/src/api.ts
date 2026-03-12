const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

interface ApiOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

async function request<T>(path: string, opts: ApiOptions = {}): Promise<T> {
  const { method = 'GET', body, headers = {} } = opts;

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new ApiError(res.status, text || res.statusText);
  }

  if (res.status === 204) return undefined as T;
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

// ---- Endpoints ----

export interface SystemStatus {
  hostname: string;
  platform: string;
  version: string;
  uptime_seconds: number;
  cpu_usage: number;
  memory_used: number;
  memory_total: number;
}

export interface FirewallRule {
  id: string;
  name: string;
  action: 'allow' | 'deny' | 'reject';
  protocol: string;
  source: string;
  destination: string;
  port: string;
  enabled: boolean;
}

export interface NetworkInterface {
  name: string;
  ip: string;
  mac: string;
  speed: string;
  status: 'up' | 'down';
  rx_bytes: number;
  tx_bytes: number;
}

export interface Vlan {
  id: number;
  name: string;
  interface: string;
  subnet: string;
}

export interface VpnTunnel {
  id: string;
  name: string;
  type: 'wireguard' | 'openvpn';
  status: 'active' | 'inactive';
  endpoint: string;
  rx_bytes: number;
  tx_bytes: number;
  connected_since?: string;
}

export interface Device {
  id: string;
  name: string;
  mac: string;
  ip: string;
  model: string;
  status: 'online' | 'offline' | 'pending';
  firmware: string;
  last_seen: string;
  adopted: boolean;
}

export interface IdsEvent {
  id: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source_ip: string;
  destination_ip: string;
  signature: string;
  action: 'alert' | 'drop' | 'pass';
  protocol: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
}

export const api = {
  getStatus: () => request<SystemStatus>('/api/v1/status'),
  getFirewallRules: () => request<FirewallRule[]>('/api/v1/firewall/rules'),
  getNetworkInterfaces: () => request<NetworkInterface[]>('/api/v1/network/interfaces'),
  getVlans: () => request<Vlan[]>('/api/v1/network/vlans'),
  getVpnTunnels: () => request<VpnTunnel[]>('/api/v1/vpn/tunnels'),
  getDevices: () => request<Device[]>('/api/v1/devices'),
  getIdsEvents: () => request<IdsEvent[]>('/api/v1/ids/events'),
  login: (creds: LoginRequest) => request<LoginResponse>('/api/v1/auth/login', { method: 'POST', body: creds }),
};
