// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, setToken, BASE_URL } from '../api'
import {
  negotiateForLogin,
  encryptPayload,
  decryptPayload,
  setEnvelopeKey,
  isE2EESupported,
} from '../crypto'
import { useBoot } from '../boot'
import { Input, Button } from '../components/ui'
import type { OAuthStatus } from '../types'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [oauthStatus, setOauthStatus] = useState<OAuthStatus | null>(null)
  const navigate = useNavigate()
  const { setReady } = useBoot()
  const [searchParams] = useSearchParams()

  // Check for OAuth error in URL
  useEffect(() => {
    const oauthError = searchParams.get('error')
    if (oauthError === 'oauth_failed') {
      setError('Single sign-on failed. Please try again or sign in with your credentials.')
    } else if (oauthError === 'oauth_no_user') {
      setError('Your account is not provisioned on this NAS. Contact your administrator.')
    }
  }, [searchParams])

  // Fetch OAuth status on mount
  useEffect(() => {
    let cancelled = false
    api.getOauthStatus()
      .then((status) => {
        if (!cancelled) setOauthStatus(status)
      })
      .catch(() => {
        // OIDC not available -- silently ignore
      })
    return () => { cancelled = true }
  }, [])

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

      setReady()
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  function handleOAuthLogin() {
    // Navigate to the OAuth login endpoint (server handles redirect)
    window.location.href = `${BASE_URL}/api/v1/auth/oauth/login`
  }

  return (
    <div className="min-h-screen bg-navy-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm animate-fade-in">
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
              <line x1="6" y1="6" x2="6.01" y2="6" />
              <line x1="6" y1="18" x2="6.01" y2="18" />
            </svg>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-gray-100">SecFirstNAS</h1>
          <p className="text-sm text-navy-400 mt-1">Network Storage</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-navy-900 border border-navy-800/50 rounded-xl p-6">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-5">Sign In</p>

          {error && (
            <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 mb-4 animate-fade-in">
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}

          <div className="space-y-4">
            <Input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              label="Username"
            />
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              label="Password"
            />
            <Button type="submit" loading={loading} className="w-full py-2.5">
              {loading ? 'Establishing secure channel...' : 'Sign In'}
            </Button>
          </div>
        </form>

        {/* OAuth / SSO button */}
        {oauthStatus?.enabled && (
          <div className="mt-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="flex-1 h-px bg-navy-800/50" />
              <span className="text-[11px] text-navy-500 uppercase tracking-wider">or</span>
              <div className="flex-1 h-px bg-navy-800/50" />
            </div>
            <button
              type="button"
              onClick={handleOAuthLogin}
              className="w-full flex items-center justify-center gap-2.5 px-4 py-2.5 bg-navy-900 border border-navy-800/50 rounded-xl text-sm font-medium text-gray-200 hover:bg-navy-800/50 hover:border-navy-700/50 transition-all duration-200"
            >
              <svg className="w-4 h-4 text-sky-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
                <polyline points="10 17 15 12 10 7" />
                <line x1="15" y1="12" x2="3" y2="12" />
              </svg>
              Sign in with {oauthStatus.provider_name || 'SSO'}
            </button>
          </div>
        )}

        <div className="flex items-center justify-center gap-2 mt-5">
          <svg className="w-3 h-3 text-navy-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <p className="text-[11px] text-navy-600">E2EE protected. Unauthorized access is prohibited.</p>
        </div>
      </div>
    </div>
  )
}
