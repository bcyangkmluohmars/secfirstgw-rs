// SPDX-License-Identifier: AGPL-3.0-or-later

import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useRef, useState, useCallback } from 'react'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Storage from './pages/Storage'
import Shares from './pages/Shares'
import System from './pages/System'
import ActiveDirectory from './pages/settings/ActiveDirectory'
import OAuthSettings from './pages/settings/OAuthSettings'
import Login from './pages/Login'
import Setup from './pages/Setup'
import { api, isAuthenticated, clearToken, setToken, setRenegotiateFn } from './api'
import { initSession } from './crypto'

// Wire up E2EE re-negotiate callback (breaks circular import between api<->crypto)
setRenegotiateFn(async () => {
  try {
    const result = await initSession()
    return result.authenticated
  } catch {
    return false
  }
})

import { BootContext, type BootStatus } from './boot'

/**
 * Check for an OAuth session cookie set by the server callback.
 * If present, store it as the token in localStorage so the normal
 * session init flow picks it up.
 */
function checkOAuthCookie(): boolean {
  const cookies = document.cookie.split(';')
  for (const cookie of cookies) {
    const trimmed = cookie.trim()
    if (trimmed.startsWith('sfnas_session=')) {
      const token = trimmed.slice('sfnas_session='.length).trim()
      if (token) {
        setToken(token)
        return true
      }
    }
  }
  return false
}

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

      // Check for OAuth callback cookie (server sets sfnas_session cookie)
      checkOAuthCookie()

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
        <div className="w-10 h-10 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center mx-auto mb-4">
          <svg className="w-5 h-5 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
            <line x1="6" y1="6" x2="6.01" y2="6" />
            <line x1="6" y1="18" x2="6.01" y2="18" />
          </svg>
        </div>
        <div className="w-6 h-6 border-2 border-sky-400/30 border-t-sky-400 rounded-full animate-spin mx-auto mb-3" />
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
      <Routes>
        <Route path="/setup" element={boot.status === 'setup' ? <Setup /> : <Navigate to="/login" replace />} />
        <Route path="/login" element={boot.status === 'setup' ? <Navigate to="/setup" replace /> : <Login />} />
        {boot.status === 'ready' && (
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/storage" element={<Storage />} />
            <Route path="/shares" element={<Shares />} />
            <Route path="/system" element={<System />} />
            <Route path="/settings/ad" element={<ActiveDirectory />} />
            <Route path="/settings/oauth" element={<OAuthSettings />} />
          </Route>
        )}
        <Route path="*" element={<Navigate to={defaultPath(boot.status)} replace />} />
      </Routes>
    </BootContext.Provider>
  )
}
