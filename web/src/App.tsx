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
        console.error('Session init failed:', err)
        clearToken()
        if (!cancelled) navigate('/login', { replace: true })
      }
    }

    init()
    return () => { cancelled = true }
  }, [navigate])

  if (!ready) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-gray-500 font-mono">Establishing secure channel...</p>
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
