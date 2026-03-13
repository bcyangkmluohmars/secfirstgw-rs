// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useBoot } from '../boot'
import { Input, Button } from '../components/ui'

export default function Setup() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { setLogin } = useBoot()

  const passwordChecks = {
    length: password.length >= 12,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    digit: /\d/.test(password),
    match: password.length > 0 && password === confirmPassword,
  }

  const allValid = username.length > 0 && Object.values(passwordChecks).every(Boolean)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!allValid) return
    setError(null)
    setLoading(true)

    try {
      await api.setup({ username, password })
      setLogin()
      navigate('/login')
    } catch (err) {
      if (err instanceof Error && err.message.includes('409')) {
        setError('Setup already completed. Redirecting to login...')
        setTimeout(() => { setLogin(); navigate('/login') }, 1500)
      } else {
        setError(err instanceof Error ? err.message : 'Setup failed')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-navy-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm animate-fade-in">
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-emerald-400" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
            </svg>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-gray-100">SecFirstGW</h1>
          <p className="text-sm text-navy-400 mt-1">Initial Setup</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-navy-900 border border-navy-800/50 rounded-xl p-6">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-1">Create Admin Account</p>
          <p className="text-xs text-navy-500 mb-5">This is a one-time setup. No default credentials exist.</p>

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
              autoComplete="new-password"
              required
              label="Password"
            />
            <Input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
              required
              label="Confirm Password"
            />

            {password.length > 0 && (
              <div className="space-y-1.5 animate-fade-in">
                <PolicyCheck ok={passwordChecks.length} label="At least 12 characters" />
                <PolicyCheck ok={passwordChecks.upper} label="One uppercase letter" />
                <PolicyCheck ok={passwordChecks.lower} label="One lowercase letter" />
                <PolicyCheck ok={passwordChecks.digit} label="One digit" />
                {confirmPassword.length > 0 && (
                  <PolicyCheck ok={passwordChecks.match} label="Passwords match" />
                )}
              </div>
            )}

            <Button type="submit" loading={loading} disabled={!allValid} className="w-full py-2.5">
              {loading ? 'Creating admin account...' : 'Create Admin Account'}
            </Button>
          </div>
        </form>

        <div className="flex items-center justify-center gap-2 mt-5">
          <svg className="w-3 h-3 text-navy-600" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
          </svg>
          <p className="text-[11px] text-navy-600">No default credentials. Security first.</p>
        </div>
      </div>
    </div>
  )
}

function PolicyCheck({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={`w-3.5 h-3.5 rounded-full flex items-center justify-center ${ok ? 'bg-emerald-500/20' : 'bg-navy-800'}`}>
        {ok ? (
          <svg className="w-2.5 h-2.5 text-emerald-400" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
          </svg>
        ) : (
          <div className="w-1.5 h-1.5 rounded-full bg-navy-600" />
        )}
      </div>
      <span className={`text-xs ${ok ? 'text-emerald-400' : 'text-navy-500'}`}>{label}</span>
    </div>
  )
}
