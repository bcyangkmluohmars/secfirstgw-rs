// SPDX-License-Identifier: AGPL-3.0-or-later

import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import {
  LayoutDashboard,
  HardDrive,
  FolderOpen,
  Settings,
  Shield,
  KeyRound,
  Server,
  Menu,
  LogOut,
} from 'lucide-react'
import { useBoot } from '../boot'
import { api, clearToken } from '../api'
import { setEnvelopeKey } from '../crypto'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/storage', label: 'Storage', icon: HardDrive },
  { to: '/shares', label: 'Shares', icon: FolderOpen },
  { to: '/system', label: 'System', icon: Settings },
  { to: '/settings/ad', label: 'Active Directory', icon: Shield },
  { to: '/settings/oauth', label: 'Single Sign-On', icon: KeyRound },
]

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const { setLogout } = useBoot()
  const navigate = useNavigate()

  async function handleLogout() {
    try {
      await api.logout()
    } catch {
      // Best-effort server-side logout
    }
    clearToken()
    setEnvelopeKey(null)
    setLogout()
    navigate('/login')
  }

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
            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
              <Server className="w-4 h-4 text-sky-400" />
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight text-gray-100">SecFirstNAS</h1>
              <p className="text-[10px] text-navy-400 font-medium">Network Storage</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 py-3 px-2 overflow-y-auto">
          <div className="space-y-0.5">
            {navItems.map((item) => {
              const Icon = item.icon
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2 text-[13px] font-medium rounded-lg transition-all duration-150 ${
                      isActive
                        ? 'text-sky-400 bg-sky-500/8 border-l-2 border-sky-400 ml-0 pl-2.5'
                        : 'text-navy-400 hover:text-gray-200 hover:bg-navy-800/50 border-l-2 border-transparent'
                    }`
                  }
                >
                  <Icon className="w-[18px] h-[18px] shrink-0" />
                  {item.label}
                </NavLink>
              )
            })}
          </div>
        </nav>

        <div className="px-4 py-3 border-t border-navy-800/50 flex items-center justify-between">
          <p className="text-[10px] text-navy-600 font-mono">v0.1.0</p>
          <button
            onClick={handleLogout}
            className="p-1.5 text-navy-500 hover:text-red-400 rounded-lg hover:bg-navy-800/50 transition-colors"
            title="Sign out"
          >
            <LogOut className="w-3.5 h-3.5" />
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 bg-navy-900/80 backdrop-blur-sm border-b border-navy-800/50 flex items-center justify-between px-4 sticky top-0 z-20">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-1.5 -ml-1.5 text-navy-400 hover:text-gray-200 rounded-lg hover:bg-navy-800/50 transition-colors"
            >
              <Menu className="w-5 h-5" />
            </button>
            <span className="text-sm font-medium text-gray-300">
              SecFirstNAS
            </span>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
