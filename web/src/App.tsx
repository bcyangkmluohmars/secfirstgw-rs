// SPDX-License-Identifier: AGPL-3.0-or-later

import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useRef, useState, useCallback } from 'react'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Interfaces from './pages/Interfaces'
import Wan from './pages/Wan'
import Firewall from './pages/Firewall'
import Network from './pages/Network'
import Vpn from './pages/Vpn'
import Devices from './pages/Devices'
import Inform from './pages/Inform'
import Ids from './pages/Ids'
import Wireless from './pages/Wireless'
import Ddns from './pages/Ddns'
import Settings from './pages/Settings'
import Logs from './pages/Logs'
import Login from './pages/Login'
import Setup from './pages/Setup'
import { api, isAuthenticated, clearToken, setRenegotiateFn } from './api'
import { initSession } from './crypto'

// Wire up E2EE re-negotiate callback (breaks circular import between api↔crypto)
setRenegotiateFn(async () => {
  try {
    const result = await initSession()
    return result.authenticated
  } catch {
    return false
  }
})
import { BootContext, type BootStatus } from './boot'
import { ToastProvider } from './hooks/useToast'
import { StatusProvider } from './hooks/useStatus'

function useBootCheck() {
  const [status, setStatus] = useState<BootStatus>('loading')
  const ran = useRef(false)

  useEffect(() => {
    if (ran.current) return
    ran.current = true

    async function check() {
      try {
        const { needed } = await api.setupStatus()
        if (needed) { setStatus('setup'); return }
      } catch { /* fall through */ }

      if (!isAuthenticated()) { setStatus('login'); return }

      try {
        const result = await initSession()
        if (!result.authenticated) { clearToken(); setStatus('login'); return }
        setStatus('ready')
      } catch (err) {
        if (import.meta.env.DEV) console.error('Session init failed:', err)
        clearToken()
        setStatus('login')
      }
    }

    check()
  }, [])

  const setLogin = useCallback(() => setStatus('login'), [])
  const setReady = useCallback(() => setStatus('ready'), [])
  const setLogout = useCallback(() => setStatus('login'), [])

  return { status, setLogin, setReady, setLogout }
}

function defaultPath(status: BootStatus): string {
  switch (status) {
    case 'setup': return '/setup'
    case 'login': return '/login'
    default: return '/'
  }
}

function LoadingScreen() {
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

export default function App() {
  const boot = useBootCheck()

  if (boot.status === 'loading') return <LoadingScreen />

  return (
    <BootContext.Provider value={boot}>
      <ToastProvider>
        <Routes>
          <Route path="/setup" element={<Setup />} />
          <Route path="/login" element={<Login />} />
          {boot.status === 'ready' && (
            <Route element={<StatusProvider><Layout /></StatusProvider>}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/interfaces" element={<Interfaces />} />
              <Route path="/wan" element={<Wan />} />
              <Route path="/network" element={<Network />} />
              <Route path="/wireless" element={<Wireless />} />
              <Route path="/firewall" element={<Firewall />} />
              <Route path="/vpn" element={<Vpn />} />
              <Route path="/ddns" element={<Ddns />} />
              <Route path="/devices" element={<Devices />} />
              <Route path="/inform" element={<Inform />} />
              <Route path="/ids" element={<Ids />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/settings" element={<Settings />} />
            </Route>
          )}
          <Route path="*" element={<Navigate to={defaultPath(boot.status)} replace />} />
        </Routes>
      </ToastProvider>
    </BootContext.Provider>
  )
}
