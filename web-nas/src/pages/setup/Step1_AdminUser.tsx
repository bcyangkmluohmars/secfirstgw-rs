// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, type FormEvent } from 'react'
import { Check, X, Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../../api'
import { useBoot } from '../../boot'

interface Step1Props {
  onCreated: (username: string) => void
}

interface PasswordCheck {
  label: string
  met: boolean
}

function validatePassword(password: string, confirm: string): PasswordCheck[] {
  return [
    { label: '12+ characters', met: password.length >= 12 },
    { label: 'Uppercase letter', met: /[A-Z]/.test(password) },
    { label: 'Lowercase letter', met: /[a-z]/.test(password) },
    { label: 'Digit', met: /\d/.test(password) },
    { label: 'Passwords match', met: password.length > 0 && password === confirm },
  ]
}

export default function Step1_AdminUser({ onCreated }: Step1Props) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { setLogin } = useBoot()

  const checks = validatePassword(password, confirm)
  const allPassed = checks.every((c) => c.met) && username.trim().length > 0

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!allPassed) return

    setError(null)
    setLoading(true)

    try {
      await api.setup({ username: username.trim(), password })
      onCreated(username.trim())
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError('An admin account already exists. Redirecting to login...')
        setTimeout(() => setLogin(), 2000)
        return
      }
      setError(err instanceof Error ? err.message : 'Failed to create account')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="animate-fade-in max-w-md mx-auto">
      <div className="text-center mb-8">
        <div className="w-12 h-12 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center mx-auto mb-4">
          <ShieldCheck className="w-6 h-6 text-sky-400" />
        </div>
        <h2 className="text-xl font-semibold text-gray-100">Create Admin Account</h2>
        <p className="text-sm text-navy-400 mt-1">This account will have full access</p>
      </div>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 mb-6 animate-fade-in">
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Username */}
        <label className="block">
          <span className="block text-[11px] font-medium text-navy-400 mb-1.5">Username</span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-sky-500/50 transition-colors placeholder-navy-600"
            placeholder="admin"
          />
        </label>

        {/* Password */}
        <label className="block">
          <span className="block text-[11px] font-medium text-navy-400 mb-1.5">Password</span>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              required
              className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 pr-10 text-sm text-gray-200 focus:outline-none focus:border-sky-500/50 transition-colors placeholder-navy-600"
              placeholder="Strong password"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-navy-500 hover:text-gray-300 transition-colors"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </label>

        {/* Confirm Password */}
        <label className="block">
          <span className="block text-[11px] font-medium text-navy-400 mb-1.5">Confirm Password</span>
          <div className="relative">
            <input
              type={showConfirm ? 'text' : 'password'}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
              className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 pr-10 text-sm text-gray-200 focus:outline-none focus:border-sky-500/50 transition-colors placeholder-navy-600"
              placeholder="Repeat password"
            />
            <button
              type="button"
              onClick={() => setShowConfirm(!showConfirm)}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-navy-500 hover:text-gray-300 transition-colors"
            >
              {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </label>

        {/* Password Policy Indicators */}
        <div className="bg-navy-900 border border-navy-800/50 rounded-lg p-4">
          <p className="text-[10px] font-medium text-navy-500 uppercase tracking-wider mb-3">Password Policy</p>
          <div className="space-y-2">
            {checks.map((check) => (
              <div key={check.label} className="flex items-center gap-2">
                {check.met ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <X className="w-3.5 h-3.5 text-navy-600" />
                )}
                <span className={`text-xs ${check.met ? 'text-emerald-400' : 'text-navy-500'}`}>
                  {check.label}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={!allPassed || loading}
          className={`
            w-full py-2.5 rounded-lg text-sm font-medium border transition-all duration-200
            ${allPassed && !loading
              ? 'bg-sky-500/10 hover:bg-sky-500/20 border-sky-500/20 text-sky-400 cursor-pointer'
              : 'bg-navy-800 border-navy-700/50 text-navy-500 cursor-not-allowed opacity-50'
            }
          `}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <div className="w-3.5 h-3.5 border-2 border-current/30 border-t-current rounded-full animate-spin" />
              Creating account...
            </span>
          ) : (
            'Create Admin Account'
          )}
        </button>
      </form>
    </div>
  )
}
