import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useEffect, useState, useCallback } from 'react'
import { api, clearToken, type SystemStatus } from '../api'

const navItems = [
  { to: '/', label: 'Dashboard', icon: 'dashboard' },
  { to: '/firewall', label: 'Firewall', icon: 'firewall' },
  { to: '/network', label: 'Network', icon: 'network' },
  { to: '/vpn', label: 'VPN', icon: 'vpn' },
  { to: '/devices', label: 'Devices', icon: 'devices' },
  { to: '/ids', label: 'IDS', icon: 'ids' },
  { to: '/settings', label: 'Settings', icon: 'settings' },
]

function NavIcon({ icon }: { icon: string }) {
  const paths: Record<string, React.ReactNode> = {
    dashboard: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    firewall: (
      <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4zm0 2.18L18 7.6v4.4c0 4.24-2.76 8.2-6 9.58-3.24-1.38-6-5.34-6-9.58V7.6l6-3.42z" />
    ),
    network: (
      <>
        <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <ellipse cx="12" cy="12" rx="4" ry="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <line x1="3" y1="12" x2="21" y2="12" stroke="currentColor" strokeWidth="1.5" />
        <path d="M4.5 7.5h15M4.5 16.5h15" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.5" />
      </>
    ),
    vpn: (
      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 13.17l6.59-6.59L18 8l-8 8z" />
    ),
    devices: (
      <>
        <rect x="4" y="4" width="16" height="12" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <line x1="12" y1="16" x2="12" y2="20" stroke="currentColor" strokeWidth="1.5" />
        <line x1="8" y1="20" x2="16" y2="20" stroke="currentColor" strokeWidth="1.5" />
      </>
    ),
    ids: (
      <>
        <path d="M12 2L2 7l10 5 10-5-10-5z" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <path d="M2 17l10 5 10-5" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <path d="M2 12l10 5 10-5" fill="none" stroke="currentColor" strokeWidth="1.5" />
      </>
    ),
    settings: (
      <>
        <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" fill="none" stroke="currentColor" strokeWidth="1.5" />
      </>
    ),
  }

  return (
    <svg className="w-[18px] h-[18px] shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      {paths[icon]}
    </svg>
  )
}

export default function Layout() {
  const navigate = useNavigate()
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [online, setOnline] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)

  const fetchStatus = useCallback(() => {
    api.getStatus()
      .then((s) => { setStatus(s); setOnline(true) })
      .catch(() => setOnline(false))
  }, [])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 10000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  const handleLogout = async () => {
    try { await api.logout() } catch { /* ignore */ }
    clearToken()
    navigate('/login', { replace: true })
  }

  const ramPercent = status && status.memory.total_mb > 0
    ? Math.round((status.memory.used_mb / status.memory.total_mb) * 100)
    : 0

  return (
    <div className="flex h-screen bg-navy-950 text-gray-100">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-40 w-60 bg-navy-900 border-r border-navy-800/50
        flex flex-col transition-transform duration-200 ease-out
        lg:static lg:translate-x-0
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        {/* Logo */}
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

        {/* Navigation */}
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
                <NavIcon icon={item.icon} />
                {item.label}
              </NavLink>
            ))}
          </div>
        </nav>

        {/* Sidebar footer */}
        <div className="px-4 py-3 border-t border-navy-800/50">
          <div className="flex items-center gap-2">
            <div className={`w-1.5 h-1.5 rounded-full ${online ? 'bg-emerald-400 animate-pulse-dot' : 'bg-red-400'}`} />
            <span className="text-[11px] text-navy-400 font-mono">{online ? 'Connected' : 'Offline'}</span>
          </div>
          <p className="text-[10px] text-navy-600 font-mono mt-1">v0.1.0</p>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-14 bg-navy-900/80 backdrop-blur-sm border-b border-navy-800/50 flex items-center justify-between px-4 sticky top-0 z-20">
          <div className="flex items-center gap-3">
            {/* Hamburger */}
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
            {/* Status indicators */}
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
                      <rect x="2" y="6" width="20" height="12" rx="2" />
                      <line x1="6" y1="10" x2="6" y2="14" />
                    </svg>
                    <span className="font-mono tabular-nums">{ramPercent}%</span>
                  </div>
                </>
              )}
            </div>

            {/* Divider */}
            <div className="hidden sm:block w-px h-6 bg-navy-800" />

            {/* User menu */}
            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-navy-800/50 transition-colors"
              >
                <div className="w-7 h-7 rounded-full bg-navy-700 flex items-center justify-center">
                  <svg className="w-4 h-4 text-navy-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <circle cx="12" cy="8" r="4" />
                    <path d="M4 21v-1a6 6 0 0112 0v1" />
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

        {/* Page content */}
        <main className="flex-1 overflow-auto p-6 animate-fade-in">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
