// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * E2EE layer for all API communication.
 *
 * Single unified flow via /auth/session:
 * 1. Generate X25519 + ML-KEM-1024 keypairs, send public keys to /auth/session
 * 2. Server responds with its X25519 public key, KEM ciphertext, negotiate_id, auth status
 * 3. Client derives hybrid shared secret: HKDF-SHA256(x25519_ss || ml_kem_ss) → AES-256-GCM key
 * 4. If authenticated, server also returns envelope key encrypted with negotiate key
 * 5. Client decrypts envelope key, uses it for all subsequent API E2EE
 *
 * On login: negotiate via /auth/session (no token), then encrypt creds for /auth/login
 * On reload: negotiate via /auth/session (with token) → immediate resume with envelope key
 *
 * Hybrid key exchange: X25519 (classical) + ML-KEM-1024 (FIPS 203, post-quantum).
 * If the ML-KEM library fails to load, falls back to X25519-only gracefully.
 */

import { api, getToken, type SessionResponse } from './api';
import type { MlKemInterface } from 'mlkem';

const HKDF_INFO = new TextEncoder().encode('sfgw-e2ee-v1');

// ML-KEM-1024 support — loaded lazily, falls back to X25519-only if unavailable
let mlKemInstance: MlKemInterface | null = null;
let mlKemLoadAttempted = false;

async function getMlKem(): Promise<MlKemInterface | null> {
  if (mlKemLoadAttempted) return mlKemInstance;
  mlKemLoadAttempted = true;
  try {
    const { createMlKem1024 } = await import('mlkem');
    mlKemInstance = await createMlKem1024();
  } catch {
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.warn('ML-KEM-1024 not available, falling back to X25519-only');
    }
  }
  return mlKemInstance;
}

// --- In-memory E2EE state (never persisted — lost on reload, re-negotiated) ---
let envelopeKey: CryptoKey | null = null;

export function getEnvelopeKey(): CryptoKey | null {
  return envelopeKey;
}

export function setEnvelopeKey(key: CryptoKey | null): void {
  envelopeKey = key;
}

export function hasE2EE(): boolean {
  return envelopeKey !== null;
}

// --- Base64 helpers ---

export function toBase64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function fromBase64(b64: string): Uint8Array {
  const raw = atob(b64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

// --- Core crypto operations ---

export interface NegotiateResult {
  negotiateId: string;
  negotiateKey: CryptoKey;
  sessionResponse: SessionResponse;
}

/**
 * Perform hybrid X25519 + ML-KEM-1024 key exchange via /auth/session.
 * Falls back to X25519-only if ML-KEM is unavailable.
 * Optionally includes a token for session resume.
 */
async function negotiateSession(token?: string | null): Promise<NegotiateResult> {
  // 1. Generate X25519 keypair
  const x25519KeyPair = await crypto.subtle.generateKey(
    { name: 'X25519' } as EcKeyGenParams,
    false,
    ['deriveBits'],
  );
  const clientPubRaw = await crypto.subtle.exportKey('raw', x25519KeyPair.publicKey);

  // 2. Generate ML-KEM-1024 keypair (if available)
  const mlkem = await getMlKem();
  let kemEncapsKey: Uint8Array | null = null;
  let kemDecapsKey: Uint8Array | null = null;
  if (mlkem) {
    [kemEncapsKey, kemDecapsKey] = mlkem.generateKeyPair();
  }

  // 3. Send both keys to server
  const sessionRes = await api.session({
    client_public_key: toBase64(clientPubRaw),
    ...(kemEncapsKey ? { kem_public_key: toBase64(kemEncapsKey.buffer as ArrayBuffer) } : {}),
    ...(token ? { token } : {}),
  });

  // 4. X25519 ECDH shared secret
  const serverPubBytes = fromBase64(sessionRes.server_public_key);
  const serverPub = await crypto.subtle.importKey(
    'raw',
    serverPubBytes.buffer as ArrayBuffer,
    { name: 'X25519' } as EcKeyImportParams,
    false,
    [],
  );
  const x25519SharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: serverPub } as EcdhKeyDeriveParams,
    x25519KeyPair.privateKey,
    256,
  );

  // 5. Combine shared secrets: x25519_ss || ml_kem_ss (hybrid) or x25519_ss only (fallback)
  let combinedIkm: Uint8Array;
  if (sessionRes.kem_ciphertext && mlkem && kemDecapsKey) {
    const kemCt = fromBase64(sessionRes.kem_ciphertext);
    const kemSharedSecret = mlkem.decap(kemCt, kemDecapsKey);
    combinedIkm = new Uint8Array(32 + kemSharedSecret.length);
    combinedIkm.set(new Uint8Array(x25519SharedBits), 0);
    combinedIkm.set(kemSharedSecret, 32);
    // Zeroize the KEM decapsulation key
    kemDecapsKey.fill(0);
  } else {
    combinedIkm = new Uint8Array(x25519SharedBits);
  }

  // 6. HKDF-SHA256 to derive AES-256-GCM negotiate key
  const hkdfKey = await crypto.subtle.importKey('raw', combinedIkm.buffer as ArrayBuffer, 'HKDF', false, ['deriveKey']);
  const negotiateKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

  // Zeroize combined IKM
  combinedIkm.fill(0);

  return {
    negotiateId: sessionRes.negotiate_id,
    negotiateKey,
    sessionResponse: sessionRes,
  };
}

/**
 * Initialize session on page load / reload.
 */
export async function initSession(): Promise<{
  authenticated: boolean;
  user?: { id: number; username: string; role: string };
  negotiateId?: string;
  negotiateKey?: CryptoKey;
}> {
  const token = getToken();

  try {
    const { negotiateId, negotiateKey, sessionResponse } = await negotiateSession(token);

    if (sessionResponse.authenticated && sessionResponse.envelope) {
      const envKey = await decryptEnvelopeKey(negotiateKey, sessionResponse.envelope);
      setEnvelopeKey(envKey);
      return { authenticated: true, user: sessionResponse.user };
    }

    return { authenticated: false, negotiateId, negotiateKey };
  } catch {
    setEnvelopeKey(null);
    return { authenticated: false };
  }
}

/**
 * Negotiate E2EE for login flow (no token).
 */
export async function negotiateForLogin(): Promise<{
  negotiateId: string;
  negotiateKey: CryptoKey;
}> {
  const { negotiateId, negotiateKey } = await negotiateSession(null);
  return { negotiateId, negotiateKey };
}

// --- Encrypt / Decrypt ---

export async function encryptPayload(
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<{ iv: string; data: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    plaintext.buffer as ArrayBuffer,
  );
  return { iv: toBase64(iv.buffer as ArrayBuffer), data: toBase64(encrypted) };
}

export async function decryptPayload(
  key: CryptoKey,
  iv: string,
  data: string,
): Promise<Uint8Array> {
  const ivBytes = fromBase64(iv);
  const ctBytes = fromBase64(data);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes.buffer as ArrayBuffer },
    key,
    ctBytes.buffer as ArrayBuffer,
  );
  return new Uint8Array(decrypted);
}

async function decryptEnvelopeKey(
  negotiateKey: CryptoKey,
  envelope: { iv: string; data: string },
): Promise<CryptoKey> {
  const rawKey = await decryptPayload(negotiateKey, envelope.iv, envelope.data);
  return crypto.subtle.importKey(
    'raw',
    rawKey.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Check if browser supports X25519 + AES-GCM.
 */
export async function isE2EESupported(): Promise<boolean> {
  try {
    if (!crypto?.subtle) return false;
    await crypto.subtle.generateKey(
      { name: 'X25519' } as EcKeyGenParams,
      false,
      ['deriveBits'],
    );
    return true;
  } catch {
    return false;
  }
}
