// SPDX-License-Identifier: AGPL-3.0-or-later

import { Outlet, NavLink } from 'react-router-dom'
import { useState } from 'react'
import { api, clearToken } from '../api'
import { setEnvelopeKey } from '../crypto'
import { useBoot } from '../boot'
import { useStatus } from '../hooks/useStatus'

const navItems = [
  { to: '/', label: 'Dashboard', icon: 'dashboard' },
  { to: '/interfaces', label: 'Interfaces', icon: 'interfaces' },
  { to: '/wan', label: 'WAN', icon: 'wan' },
  { to: '/network', label: 'Network', icon: 'network' },
  { to: '/wireless', label: 'WiFi', icon: 'wifi' },
  { to: '/firewall', label: 'Firewall', icon: 'firewall' },
  { to: '/vpn', label: 'VPN', icon: 'vpn' },
  { to: '/devices', label: 'Devices', icon: 'devices' },
  { to: '/inform', label: 'UniFi Inform', icon: 'inform' },
  { to: '/ids', label: 'IDS', icon: 'ids' },
  { to: '/logs', label: 'System Log', icon: 'logs' },
  { to: '/settings', label: 'Settings', icon: 'settings' },
]

const iconPaths: Record<string, React.ReactNode> = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
  interfaces: <><rect x="2" y="3" width="20" height="4" rx="1" fill="none" stroke="currentColor" strokeWidth="1.5" /><rect x="2" y="10" width="20" height="4" rx="1" fill="none" stroke="currentColor" strokeWidth="1.5" /><rect x="2" y="17" width="20" height="4" rx="1" fill="none" stroke="currentColor" strokeWidth="1.5" /><circle cx="5" cy="5" r="0.8" fill="currentColor" /><circle cx="5" cy="12" r="0.8" fill="currentColor" /><circle cx="5" cy="19" r="0.8" fill="currentColor" /></>,
  wan: <><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" /><ellipse cx="12" cy="12" rx="4" ry="9" fill="none" stroke="currentColor" strokeWidth="1.5" /><line x1="3" y1="12" x2="21" y2="12" stroke="currentColor" strokeWidth="1.5" /><line x1="3.5" y1="7.5" x2="20.5" y2="7.5" stroke="currentColor" strokeWidth="1" /><line x1="3.5" y1="16.5" x2="20.5" y2="16.5" stroke="currentColor" strokeWidth="1" /></>,
  network: <><circle cx="12" cy="5" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.5" /><circle cx="5" cy="19" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.5" /><circle cx="19" cy="19" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.5" /><line x1="12" y1="7.5" x2="12" y2="12" stroke="currentColor" strokeWidth="1.5" /><line x1="12" y1="12" x2="5" y2="16.5" stroke="currentColor" strokeWidth="1.5" /><line x1="12" y1="12" x2="19" y2="16.5" stroke="currentColor" strokeWidth="1.5" /></>,
  firewall: <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4zm0 2.18L18 7.6v4.4c0 4.24-2.76 8.2-6 9.58-3.24-1.38-6-5.34-6-9.58V7.6l6-3.42z" />,
  vpn: <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 13.17l6.59-6.59L18 8l-8 8z" />,
  devices: <><rect x="4" y="4" width="16" height="12" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" /><line x1="12" y1="16" x2="12" y2="20" stroke="currentColor" strokeWidth="1.5" /><line x1="8" y1="20" x2="16" y2="20" stroke="currentColor" strokeWidth="1.5" /></>,
  inform: <><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2v-4M9 21H5a2 2 0 01-2-2v-4m0-6v6" fill="none" stroke="currentColor" strokeWidth="1.5" /></>,
  ids: <><path d="M12 2L2 7l10 5 10-5-10-5z" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M2 17l10 5 10-5" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M2 12l10 5 10-5" fill="none" stroke="currentColor" strokeWidth="1.5" /></>,
  logs: <><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" fill="none" stroke="currentColor" strokeWidth="1.5" /><polyline points="14,2 14,8 20,8" fill="none" stroke="currentColor" strokeWidth="1.5" /><line x1="8" y1="13" x2="16" y2="13" stroke="currentColor" strokeWidth="1.5" /><line x1="8" y1="17" x2="13" y2="17" stroke="currentColor" strokeWidth="1.5" /></>,
  wifi: <><path d="M5 12.55a11 11 0 0114 0" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M1.42 9a16 16 0 0121.16 0" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M8.53 16.11a6 6 0 016.95 0" fill="none" stroke="currentColor" strokeWidth="1.5" /><circle cx="12" cy="20" r="1" fill="currentColor" /></>,
  settings: <><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" fill="none" stroke="currentColor" strokeWidth="1.5" /></>,
}

export default function Layout() {
  const { setLogout } = useBoot()
  const { status, online } = useStatus()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)

  const handleLogout = async () => {
    try { await api.logout() } catch { /* ignore */ }
    clearToken()
    setEnvelopeKey(null)
    setLogout()
  }

  const ramPercent = status && status.memory.total_mb > 0
    ? Math.round((status.memory.used_mb / status.memory.total_mb) * 100)
    : 0

  return (
    <div className="flex h-screen bg-navy-950 text-gray-100">
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/60 z-30 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      <aside className={`
        fixed inset-y-0 left-0 z-40 w-60 bg-navy-900 border-r border-navy-800/50
        flex flex-col transition-transform duration-200 ease-out
        lg:static lg:translate-x-0
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div className="px-5 py-5 border-b border-navy-800/50">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <svg className="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
              </svg>
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight text-gray-100">SecFirstGW</h1>
              <p className="text-[10px] text-navy-400 font-medium">Security Gateway</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 py-3 px-2 overflow-y-auto">
          <div className="space-y-0.5">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                onClick={() => setSidebarOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 text-[13px] font-medium rounded-lg transition-all duration-150 ${
                    isActive
                      ? 'text-emerald-400 bg-emerald-500/8 border-l-2 border-emerald-400 ml-0 pl-2.5'
                      : 'text-navy-400 hover:text-gray-200 hover:bg-navy-800/50 border-l-2 border-transparent'
                  }`
                }
              >
                <svg className="w-[18px] h-[18px] shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  {iconPaths[item.icon]}
                </svg>
                {item.label}
              </NavLink>
            ))}
          </div>
        </nav>

        <div className="px-4 py-3 border-t border-navy-800/50">
          <div className="flex items-center gap-2">
            <div className={`w-1.5 h-1.5 rounded-full ${online ? 'bg-emerald-400 animate-pulse-dot' : 'bg-red-400'}`} />
            <span className="text-[11px] text-navy-400 font-mono">{online ? 'Connected' : 'Offline'}</span>
          </div>
          <p className="text-[10px] text-navy-600 font-mono mt-1">v0.1.0</p>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 bg-navy-900/80 backdrop-blur-sm border-b border-navy-800/50 flex items-center justify-between px-4 sticky top-0 z-20">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-1.5 -ml-1.5 text-navy-400 hover:text-gray-200 rounded-lg hover:bg-navy-800/50 transition-colors"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            </button>
            <span className="text-sm font-medium text-gray-300">
              {status?.status === 'ok' ? 'secfirstgw' : '---'}
            </span>
          </div>

          <div className="flex items-center gap-5">
            <div className="hidden sm:flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${online ? 'bg-emerald-400 animate-pulse-dot' : 'bg-red-400'}`} />
                <span className="text-xs font-medium text-gray-400">{online ? 'Online' : 'Offline'}</span>
              </div>
              {status && (
                <>
                  <div className="flex items-center gap-1.5 text-xs text-navy-400">
                    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                    </svg>
                    <span className="font-mono tabular-nums">{status.load_average[0].toFixed(2)}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-navy-400">
                    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="2" y="6" width="20" height="12" rx="2" /><line x1="6" y1="10" x2="6" y2="14" />
                    </svg>
                    <span className="font-mono tabular-nums">{ramPercent}%</span>
                  </div>
                </>
              )}
            </div>

            <div className="hidden sm:block w-px h-6 bg-navy-800" />

            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-navy-800/50 transition-colors"
              >
                <div className="w-7 h-7 rounded-full bg-navy-700 flex items-center justify-center">
                  <svg className="w-4 h-4 text-navy-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <circle cx="12" cy="8" r="4" /><path d="M4 21v-1a6 6 0 0112 0v1" />
                  </svg>
                </div>
                <svg className="w-3 h-3 text-navy-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M6 9l6 6 6-6" />
                </svg>
              </button>

              {userMenuOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setUserMenuOpen(false)} />
                  <div className="absolute right-0 top-full mt-1 w-44 bg-navy-800 border border-navy-700/50 rounded-lg shadow-xl z-50 py-1 animate-fade-in">
                    <button
                      onClick={handleLogout}
                      className="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-navy-700/50 hover:text-white transition-colors flex items-center gap-2"
                    >
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" />
                      </svg>
                      Sign Out
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
