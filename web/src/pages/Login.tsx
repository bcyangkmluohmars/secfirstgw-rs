// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, setToken } from '../api'
import {
  negotiateForLogin,
  encryptPayload,
  decryptPayload,
  setEnvelopeKey,
  isE2EESupported,
} from '../crypto'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      const e2eeOk = await isE2EESupported()

      if (e2eeOk) {
        const { negotiateId, negotiateKey } = await negotiateForLogin()

        const credsBytes = new TextEncoder().encode(JSON.stringify({ username, password }))
        const encrypted = await encryptPayload(negotiateKey, credsBytes)

        const res = await api.login({
          negotiate_id: negotiateId,
          ciphertext: encrypted.data,
          iv: encrypted.iv,
        })

        setToken(res.token)

        if (res.envelope) {
          const rawKey = await decryptPayload(negotiateKey, res.envelope.iv, res.envelope.data)
          const envKey = await globalThis.crypto.subtle.importKey(
            'raw',
            rawKey.buffer as ArrayBuffer,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
          )
          setEnvelopeKey(envKey)
        }
      } else {
        const res = await api.login({ username, password })
        setToken(res.token)
        setEnvelopeKey(null)
      }

      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-navy-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm animate-fade-in">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-emerald-400" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
            </svg>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-gray-100">SecFirstGW</h1>
          <p className="text-sm text-navy-400 mt-1">Security Gateway</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-navy-900 border border-navy-800/50 rounded-xl p-6">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-5">Sign In</p>

          {error && (
            <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 mb-4 animate-fade-in">
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-[11px] font-medium text-navy-400 mb-1.5">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-navy-600"
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-navy-400 mb-1.5">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-navy-600"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 disabled:opacity-50 disabled:cursor-not-allowed text-emerald-400 text-sm font-medium py-2.5 rounded-lg transition-all duration-200"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-3.5 h-3.5 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin" />
                  Establishing secure channel...
                </span>
              ) : (
                'Sign In'
              )}
            </button>
          </div>
        </form>

        <div className="flex items-center justify-center gap-2 mt-5">
          <svg className="w-3 h-3 text-navy-600" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
          </svg>
          <p className="text-[11px] text-navy-600">E2EE protected. Unauthorized access is prohibited.</p>
        </div>
      </div>
    </div>
  )
}
