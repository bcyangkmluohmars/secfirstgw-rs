import { Outlet, NavLink } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { api, type SystemStatus } from '../api'

const navItems = [
  { to: '/', label: 'Dashboard', icon: 'grid' },
  { to: '/firewall', label: 'Firewall', icon: 'shield' },
  { to: '/network', label: 'Network', icon: 'globe' },
  { to: '/vpn', label: 'VPN', icon: 'lock' },
  { to: '/devices', label: 'Devices', icon: 'cpu' },
  { to: '/ids', label: 'IDS', icon: 'alert' },
  { to: '/settings', label: 'Settings', icon: 'gear' },
]

function NavIcon({ icon }: { icon: string }) {
  const icons: Record<string, string> = {
    grid: 'M4 4h6v6H4zm10 0h6v6h-6zM4 14h6v6H4zm10 0h6v6h-6z',
    shield: 'M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z',
    globe: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z',
    lock: 'M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z',
    cpu: 'M15 9H9v6h6V9zm-2 4h-2v-2h2v2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2zm-4 6H7V7h10v10z',
    alert: 'M12 2L1 21h22L12 2zm0 3.99L19.53 19H4.47L12 5.99zM11 16h2v2h-2zm0-6h2v4h-2z',
    gear: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.488.488 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z',
  }
  return (
    <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24" fill="currentColor">
      <path d={icons[icon] || icons.grid} />
    </svg>
  )
}

export default function Layout() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [online, setOnline] = useState(false)

  useEffect(() => {
    api.getStatus()
      .then((s) => { setStatus(s); setOnline(true) })
      .catch(() => setOnline(false))

    const interval = setInterval(() => {
      api.getStatus()
        .then((s) => { setStatus(s); setOnline(true) })
        .catch(() => setOnline(false))
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="flex h-screen bg-gray-950 text-gray-100">
      {/* Sidebar */}
      <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="px-4 py-4 border-b border-gray-800">
          <h1 className="text-lg font-bold font-mono tracking-tight text-emerald-400">
            SecFirstGW
          </h1>
          <p className="text-xs text-gray-500 font-mono mt-0.5">Security Gateway</p>
        </div>
        <nav className="flex-1 py-2 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${
                  isActive
                    ? 'text-emerald-400 bg-gray-800/60 border-r-2 border-emerald-400'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/30'
                }`
              }
            >
              <NavIcon icon={item.icon} />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-gray-800 text-xs text-gray-600 font-mono">
          {status?.version ?? 'v0.0.0'}
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-12 bg-gray-900 border-b border-gray-800 flex items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-400 font-mono">
              {status?.hostname ?? '---'}
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-2 text-xs font-mono">
              <span className={`w-2 h-2 rounded-full ${online ? 'bg-emerald-400' : 'bg-red-500'}`} />
              {online ? 'System Online' : 'Offline'}
            </span>
            {status && (
              <span className="text-xs text-gray-500 font-mono">
                CPU {status.cpu_usage.toFixed(0)}% | RAM {formatBytes(status.memory_used)}/{formatBytes(status.memory_total)}
              </span>
            )}
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}
