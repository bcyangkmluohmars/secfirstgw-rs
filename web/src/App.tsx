// SPDX-License-Identifier: AGPL-3.0-or-later

import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Firewall from './pages/Firewall'
import Network from './pages/Network'
import Vpn from './pages/Vpn'
import Devices from './pages/Devices'
import Ids from './pages/Ids'
import Settings from './pages/Settings'
import Login from './pages/Login'
import { isAuthenticated, clearToken } from './api'
import { initSession } from './crypto'

/**
 * Auth guard: on mount, calls /auth/session to:
 * 1. Establish E2EE channel (X25519 key exchange)
 * 2. If token exists, validate + resume session with new envelope key
 * 3. Redirect to /login if not authenticated
 */
function AuthGuard({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const [ready, setReady] = useState(false)

  useEffect(() => {
    let cancelled = false

    async function init() {
      if (!isAuthenticated()) {
        navigate('/login', { replace: true })
        return
      }

      try {
        const result = await initSession()

        if (!result.authenticated) {
          clearToken()
          if (!cancelled) navigate('/login', { replace: true })
          return
        }

        if (!cancelled) setReady(true)
      } catch (err) {
        if (import.meta.env.DEV) console.error('Session init failed:', err)
        clearToken()
        if (!cancelled) navigate('/login', { replace: true })
      }
    }

    init()
    return () => { cancelled = true }
  }, [navigate])

  if (!ready) {
    return (
      <div className="min-h-screen bg-navy-950 flex items-center justify-center">
        <div className="text-center animate-fade-in">
          <div className="w-10 h-10 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-5 h-5 text-emerald-400" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
            </svg>
          </div>
          <div className="w-6 h-6 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-navy-400">Establishing secure channel...</p>
        </div>
      </div>
    )
  }

  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <AuthGuard>
            <Layout />
          </AuthGuard>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/firewall" element={<Firewall />} />
        <Route path="/network" element={<Network />} />
        <Route path="/vpn" element={<Vpn />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="/ids" element={<Ids />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
