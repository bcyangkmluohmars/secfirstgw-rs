// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * E2EE layer for all API communication.
 *
 * Single unified flow via /auth/session:
 * 1. Generate X25519 keypair, send public key (+ optional token) to /auth/session
 * 2. Server responds with its public key, negotiate_id, auth status
 * 3. Client derives shared secret → HKDF → AES-256-GCM key
 * 4. If authenticated, server also returns envelope key encrypted with negotiate key
 * 5. Client decrypts envelope key, uses it for all subsequent API E2EE
 *
 * On login: negotiate via /auth/session (no token), then encrypt creds for /auth/login
 * On reload: negotiate via /auth/session (with token) → immediate resume with envelope key
 *
 * HYBRID KEY EXCHANGE LIMITATION:
 * The server supports hybrid X25519 + ML-KEM-1024 key exchange (FIPS 203).
 * However, the Web Crypto API does NOT yet support ML-KEM / Kyber.
 * Until a WASM ML-KEM library is integrated into the frontend, the client
 * sends only the X25519 public key (kem_public_key is omitted).  The server
 * gracefully falls back to X25519-only when kem_public_key is absent.
 *
 * TODO: Integrate a WASM ML-KEM-1024 library (e.g. pqcrypto-wasm or
 * crystals-kyber-wasm) to enable full hybrid key exchange from the browser.
 * When done:
 *   - Generate ML-KEM-1024 keypair alongside X25519
 *   - Send kem_public_key in the session request
 *   - Decapsulate the returned kem_ciphertext to get shared_secret_2
 *   - Combine: HKDF-SHA256(x25519_ss || ml_kem_ss, info="sfgw-e2ee-v1")
 */

import { api, getToken, type SessionResponse } from './api';

const HKDF_INFO = new TextEncoder().encode('sfgw-e2ee-v1');

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
 * Perform X25519 ECDH key exchange via /auth/session.
 * Optionally includes a token for session resume.
 */
async function negotiateSession(token?: string | null): Promise<NegotiateResult> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'X25519' } as EcKeyGenParams,
    false,
    ['deriveBits'],
  );

  const clientPubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const clientPubB64 = toBase64(clientPubRaw);

  const sessionRes = await api.session({
    client_public_key: clientPubB64,
    ...(token ? { token } : {}),
  });

  const serverPubBytes = fromBase64(sessionRes.server_public_key);
  const serverPub = await crypto.subtle.importKey(
    'raw',
    serverPubBytes.buffer as ArrayBuffer,
    { name: 'X25519' } as EcKeyImportParams,
    false,
    [],
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: serverPub } as EcdhKeyDeriveParams,
    keyPair.privateKey,
    256,
  );

  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const negotiateKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

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
