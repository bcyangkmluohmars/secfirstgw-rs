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

async function request<T>(path: string, opts: ApiOptions = {}): Promise<T> {
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
    localStorage.removeItem('token');
    if (window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
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

export interface SystemStatus {
  status: string;
  uptime_secs: number;
  load_average: [number, number, number];
  memory: { total_mb: number; used_mb: number; free_mb: number };
  services: Record<string, string>;
}

export interface NetworkInterface {
  name: string;
  role: string;
  vlan_id: number | null;
  enabled: boolean;
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
  authenticated: boolean;
  user?: { id: number; username: string; role: string };
  envelope?: { iv: string; data: string };
}

export interface LoginResponse {
  token: string;
  expires_at: string;
  envelope?: { iv: string; data: string };
}

// ---- API endpoints ----

export const api = {
  // Protected (auto-E2EE when envelope key set)
  getStatus: () => request<SystemStatus>('/api/v1/status'),
  getSystem: () => request<Record<string, unknown>>('/api/v1/system'),
  getInterfaces: () => request<{ interfaces: NetworkInterface[] }>('/api/v1/interfaces'),
  getDevices: () => request<{ devices: Device[] }>('/api/v1/devices'),
  getMe: () => request<{ user: { id: number; username: string; role: string } }>('/api/v1/auth/me'),
  logout: () => request<void>('/api/v1/auth/logout', { method: 'POST' }),

  // Public (no E2EE middleware — handled manually)
  session: (body: { client_public_key: string; token?: string }) =>
    request<SessionResponse>('/api/v1/auth/session', { method: 'POST', body, skipE2EE: true }),
  login: (body: Record<string, string>) =>
    request<LoginResponse>('/api/v1/auth/login', { method: 'POST', body, skipE2EE: true }),
  setup: (creds: { username: string; password: string }) =>
    request<{ user_id: number }>('/api/v1/auth/setup', { method: 'POST', body: creds, skipE2EE: true }),
};

export { BASE_URL };
