// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useRef, useCallback } from 'react'
import { Card, PageHeader, Spinner, Sparkline, StatCard, Badge } from '../components/ui'
import { useStatus } from '../hooks/useStatus'
import {
  api,
  type NicQueueStats,
  type WanStatus,
  type IdsEventStats,
  type VpnTunnel,
  type TunnelStatus,
  type DhcpLease,
  type FirewallRule,
  type UbntDevice,
} from '../api'

const MAX_HISTORY = 60 // 10 min at 10s interval
const POLL_INTERVAL = 5_000 // 5s auto-refresh for secondary data

// ---- Formatters ----

const fmtRate = (bytesPerSec: number) => {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`
  if (bytesPerSec < 1048576) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`
  if (bytesPerSec < 1073741824) return `${(bytesPerSec / 1048576).toFixed(1)} MB/s`
  return `${(bytesPerSec / 1073741824).toFixed(2)} GB/s`
}

const fmtBytes = (b: number) => {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  if (b < 1099511627776) return `${(b / 1073741824).toFixed(2)} GB`
  return `${(b / 1099511627776).toFixed(2)} TB`
}

const fmtPkts = (n: number) => {
  if (n < 1000) return `${n}`
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`
  return `${(n / 1_000_000).toFixed(1)}M`
}

// ---- Uptime hook ----

function useUptime(initialSecs: number) {
  const [secs, setSecs] = useState(initialSecs)
  const startRef = useRef(0)
  const baseRef = useRef(initialSecs)

  useEffect(() => {
    baseRef.current = initialSecs
    startRef.current = Date.now()
    setSecs(initialSecs)
  }, [initialSecs])

  useEffect(() => {
    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startRef.current) / 1000)
      setSecs(baseRef.current + elapsed)
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60

  return { d, h, m, s }
}

function fmtUptime(d: number, h: number, m: number, s: number) {
  const parts: string[] = []
  if (d > 0) parts.push(`${d}d`)
  parts.push(`${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`)
  return parts.join(' ')
}

// ---- Service helpers ----

const statusLabel = (s: string) => {
  switch (s) {
    case 'running': return 'Running'
    case 'stopped': return 'Stopped'
    case 'disabled': return 'Disabled'
    case 'not_configured': return 'Not configured'
    case 'unavailable': return 'Unavailable'
    case 'degraded': return 'Degraded'
    default: return s
  }
}

const statusColor = (s: string) => {
  switch (s) {
    case 'running': return 'emerald'
    case 'degraded': return 'amber'
    case 'disabled': return 'amber'
    case 'not_configured': return 'navy'
    case 'unavailable': return 'navy'
    default: return 'red'
  }
}

// ---- VPN tunnel status with peer info ----

interface TunnelWithStatus {
  tunnel: VpnTunnel
  status: TunnelStatus | null
}

// ---- Sub-components ----

function ServiceGrid({ services }: { services: Record<string, string> }) {
  const entries = Object.entries(services)
  const running = entries.filter(([, s]) => s === 'running').length
  const configured = entries.filter(([, s]) => s !== 'not_configured' && s !== 'unavailable').length

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">Services</p>
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-mono text-emerald-400 tabular-nums">{running}</span>
          <span className="text-xs text-navy-600">/</span>
          <span className="text-xs font-mono text-navy-400 tabular-nums">{configured}</span>
          <span className="text-[10px] text-navy-500 ml-1">running</span>
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 stagger-children">
        {entries.map(([name, status]) => {
          const color = statusColor(status)
          const isRunning = status === 'running'
          const isInactive = status === 'not_configured' || status === 'unavailable'
          return (
            <div
              key={name}
              className={`
                bg-navy-900 border border-navy-800/50 rounded-lg px-3 py-2.5
                flex items-center gap-2.5 group transition-all duration-200
                ${isInactive ? 'opacity-50' : ''}
                hover:border-${color}-500/20
              `}
            >
              <div className="relative">
                <span className={`block w-2 h-2 rounded-full bg-${color}-400 ${isRunning ? 'animate-pulse-dot' : ''}`} />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-medium text-gray-300 capitalize truncate">{name}</p>
                <p className={`text-[10px] text-${color}-400 font-medium`}>{statusLabel(status)}</p>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function NicQueueViz({ nic }: { nic: NicQueueStats }) {
  const totalRx = nic.queues.reduce((s, q) => s + q.rx_packets, 0) || 1
  const totalTx = nic.queues.reduce((s, q) => s + q.tx_packets, 0) || 1

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xs font-mono font-semibold text-gray-300">{nic.name}</span>
        <span className="text-[10px] text-navy-500 font-mono">{nic.driver}</span>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {/* RX distribution */}
        <div>
          <p className="text-[10px] text-navy-400 uppercase tracking-wider font-medium mb-1">
            <span className="text-emerald-400">&#8595;</span> RX per Core
          </p>
          <div className="space-y-1">
            {nic.queues.map((q) => {
              const pct = (q.rx_packets / totalRx) * 100
              return (
                <div key={q.queue} className="flex items-center gap-2">
                  <span className="text-[10px] text-navy-500 font-mono w-8">C{q.queue}</span>
                  <div className="flex-1 h-3 bg-navy-800/50 rounded-sm overflow-hidden">
                    <div
                      className="h-full bg-emerald-500/70 rounded-sm transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400/70 tabular-nums w-14 text-right">
                    {pct.toFixed(1)}%
                  </span>
                  <span className="text-[10px] font-mono text-navy-500 tabular-nums w-16 text-right">
                    {fmtPkts(q.rx_packets)}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
        {/* TX distribution */}
        <div>
          <p className="text-[10px] text-navy-400 uppercase tracking-wider font-medium mb-1">
            <span className="text-blue-400">&#8593;</span> TX per Core
          </p>
          <div className="space-y-1">
            {nic.queues.map((q) => {
              const pct = (q.tx_packets / totalTx) * 100
              return (
                <div key={q.queue} className="flex items-center gap-2">
                  <span className="text-[10px] text-navy-500 font-mono w-8">C{q.queue}</span>
                  <div className="flex-1 h-3 bg-navy-800/50 rounded-sm overflow-hidden">
                    <div
                      className="h-full bg-blue-500/70 rounded-sm transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-[10px] font-mono text-blue-400/70 tabular-nums w-14 text-right">
                    {pct.toFixed(1)}%
                  </span>
                  <span className="text-[10px] font-mono text-navy-500 tabular-nums w-16 text-right">
                    {fmtPkts(q.tx_packets)}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

function SecurityOverview({ stats }: { stats: IdsEventStats | null }) {
  if (!stats) return null

  const critical = stats.critical_24h
  const total = stats.total
  const warnings = stats.by_severity?.['Warning'] ?? 0
  const info = stats.by_severity?.['Info'] ?? 0

  const severityColor = critical > 0 ? '#f87171' : warnings > 0 ? '#fbbf24' : '#34d399'
  const severityLabel = critical > 0 ? 'Threats Detected' : warnings > 0 ? 'Warnings Active' : 'All Clear'

  return (
    <Card noPadding accent={severityColor}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-lg bg-navy-800/80 border border-navy-700/30 flex items-center justify-center">
            <svg className="w-4 h-4 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
            </svg>
          </div>
          <div className="flex-1">
            <p className="text-sm font-semibold text-gray-200">Security Overview</p>
            <p className="text-[10px] font-medium" style={{ color: severityColor }}>{severityLabel}</p>
          </div>
          <Badge variant={critical > 0 ? 'danger' : warnings > 0 ? 'warning' : 'success'}>
            {critical > 0 ? 'ALERT' : warnings > 0 ? 'WARNING' : 'SECURE'}
          </Badge>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {/* Total Events */}
          <div className="bg-navy-800/30 rounded-lg px-3 py-2.5">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Total Events</p>
            <p className="text-lg font-mono text-gray-200 tabular-nums mt-0.5">{total}</p>
          </div>

          {/* Critical 24h */}
          <div className={`rounded-lg px-3 py-2.5 ${critical > 0 ? 'bg-red-500/10 border border-red-500/20' : 'bg-navy-800/30'}`}>
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Critical 24h</p>
            <p className={`text-lg font-mono tabular-nums mt-0.5 ${critical > 0 ? 'text-red-400' : 'text-gray-200'}`}>{critical}</p>
          </div>

          {/* Warnings */}
          <div className={`rounded-lg px-3 py-2.5 ${warnings > 0 ? 'bg-amber-500/10 border border-amber-500/20' : 'bg-navy-800/30'}`}>
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Warnings</p>
            <p className={`text-lg font-mono tabular-nums mt-0.5 ${warnings > 0 ? 'text-amber-400' : 'text-gray-200'}`}>{warnings}</p>
          </div>

          {/* Info */}
          <div className="bg-navy-800/30 rounded-lg px-3 py-2.5">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Info</p>
            <p className="text-lg font-mono text-gray-200 tabular-nums mt-0.5">{info}</p>
          </div>
        </div>

        {/* Detector breakdown */}
        {Object.keys(stats.by_detector).length > 0 && (
          <div className="mt-3 pt-3 border-t border-navy-800/30">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-2">Detectors</p>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(stats.by_detector)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 8)
                .map(([det, count]) => (
                  <span
                    key={det}
                    className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-navy-800/50 border border-navy-700/30 text-[10px] font-mono text-navy-400"
                  >
                    {det}
                    <span className="tabular-nums bg-navy-700/50 px-1 py-0 rounded text-[9px]">{count}</span>
                  </span>
                ))}
            </div>
          </div>
        )}

        {/* Top sources */}
        {stats.top_sources.length > 0 && (
          <div className="mt-3 pt-3 border-t border-navy-800/30">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-2">Top Source IPs</p>
            <div className="space-y-1">
              {stats.top_sources.slice(0, 3).map((src) => {
                const maxCount = stats.top_sources[0]?.count ?? 1
                const pct = Math.round((src.count / maxCount) * 100)
                return (
                  <div key={src.ip} className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-gray-400 w-28 shrink-0 tabular-nums">{src.ip}</span>
                    <div className="flex-1 h-1.5 bg-navy-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-red-500/40 rounded-full transition-all duration-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-navy-500 font-mono tabular-nums w-8 text-right">{src.count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}

function VpnOverview({ tunnels }: { tunnels: TunnelWithStatus[] }) {
  if (tunnels.length === 0) return null

  const activeTunnels = tunnels.filter((t) => t.status?.is_up)
  const totalPeers = tunnels.reduce((sum, t) => sum + t.tunnel.peers.length, 0)
  const connectedPeers = tunnels.reduce((sum, t) => {
    if (!t.status) return sum
    return sum + t.status.peers.filter((p) => p.last_handshake_secs > 0 && p.last_handshake_secs < 300).length
  }, 0)

  return (
    <Card noPadding accent="#818cf8">
      <div className="px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-lg bg-navy-800/80 border border-navy-700/30 flex items-center justify-center">
            <svg className="w-4 h-4 text-indigo-400" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 13.17l6.59-6.59L18 8l-8 8z" />
            </svg>
          </div>
          <div className="flex-1">
            <p className="text-sm font-semibold text-gray-200">VPN Tunnels</p>
            <p className="text-[10px] text-navy-500">{activeTunnels.length} / {tunnels.length} active</p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3 mb-3">
          <div className="bg-navy-800/30 rounded-lg px-3 py-2">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Tunnels</p>
            <p className="text-lg font-mono text-gray-200 tabular-nums mt-0.5">{tunnels.length}</p>
          </div>
          <div className="bg-navy-800/30 rounded-lg px-3 py-2">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Active</p>
            <p className="text-lg font-mono text-emerald-400 tabular-nums mt-0.5">{activeTunnels.length}</p>
          </div>
          <div className="bg-navy-800/30 rounded-lg px-3 py-2">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Peers</p>
            <p className="text-lg font-mono text-gray-200 tabular-nums mt-0.5">
              <span className="text-emerald-400">{connectedPeers}</span>
              <span className="text-navy-600 text-sm"> / {totalPeers}</span>
            </p>
          </div>
        </div>

        <div className="space-y-2">
          {tunnels.map(({ tunnel, status }) => {
            const isUp = status?.is_up ?? false
            const totalRx = status?.rx_bytes ?? 0
            const totalTx = status?.tx_bytes ?? 0
            return (
              <div
                key={tunnel.id}
                className={`rounded-lg border px-3 py-2 flex items-center justify-between ${
                  isUp
                    ? 'bg-emerald-500/5 border-emerald-500/20'
                    : 'bg-navy-800/30 border-navy-700/30'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`block w-2 h-2 rounded-full ${isUp ? 'bg-emerald-400 animate-pulse-dot' : 'bg-navy-600'}`} />
                  <span className="text-xs font-mono font-semibold text-gray-300">{tunnel.name}</span>
                  <span className="text-[10px] text-navy-500 uppercase">{tunnel.tunnel_type}</span>
                  <Badge variant={isUp ? 'success' : 'neutral'}>{isUp ? 'UP' : 'DOWN'}</Badge>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-mono text-navy-400">:{tunnel.listen_port}</span>
                  {isUp && (
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-emerald-400/70 tabular-nums">
                        &#8595; {fmtBytes(totalRx)}
                      </span>
                      <span className="text-[10px] font-mono text-blue-400/70 tabular-nums">
                        &#8593; {fmtBytes(totalTx)}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </Card>
  )
}

function DevicesOverview({ devices }: { devices: UbntDevice[] }) {
  if (devices.length === 0) return null

  const adopted = devices.filter((d) => d.state === 'adopted')
  const pending = devices.filter((d) => d.state === 'pending')
  const adopting = devices.filter((d) => d.state === 'adopting')
  const ignored = devices.filter((d) => d.state === 'ignored')

  // Check for devices with issues
  const devicesWithHighCpu = adopted.filter((d) => {
    const cpuStr = d.stats?.system_stats?.cpu
    if (!cpuStr) return false
    return Number(cpuStr) > 80
  })
  const devicesWithHighMem = adopted.filter((d) => {
    const memStr = d.stats?.system_stats?.mem
    if (!memStr) return false
    return Number(memStr) > 85
  })
  const devicesOverheating = adopted.filter((d) => d.stats?.overheating)
  const hasIssues = devicesWithHighCpu.length > 0 || devicesWithHighMem.length > 0 || devicesOverheating.length > 0

  return (
    <Card noPadding accent="#38bdf8">
      <div className="px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-lg bg-navy-800/80 border border-navy-700/30 flex items-center justify-center">
            <svg className="w-4 h-4 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="4" y="4" width="16" height="12" rx="2" />
              <line x1="12" y1="16" x2="12" y2="20" />
              <line x1="8" y1="20" x2="16" y2="20" />
            </svg>
          </div>
          <div className="flex-1">
            <p className="text-sm font-semibold text-gray-200">Managed Devices</p>
            <p className="text-[10px] text-navy-500">{devices.length} total</p>
          </div>
          {pending.length > 0 && (
            <Badge variant="warning">{pending.length} PENDING</Badge>
          )}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
          <div className="bg-emerald-500/5 border border-emerald-500/15 rounded-lg px-3 py-2">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Adopted</p>
            <p className="text-lg font-mono text-emerald-400 tabular-nums mt-0.5">{adopted.length}</p>
          </div>
          <div className={`rounded-lg px-3 py-2 ${pending.length > 0 ? 'bg-amber-500/10 border border-amber-500/20' : 'bg-navy-800/30'}`}>
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Pending</p>
            <p className={`text-lg font-mono tabular-nums mt-0.5 ${pending.length > 0 ? 'text-amber-400' : 'text-gray-200'}`}>{pending.length}</p>
          </div>
          <div className={`rounded-lg px-3 py-2 ${adopting.length > 0 ? 'bg-sky-500/10 border border-sky-500/20' : 'bg-navy-800/30'}`}>
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Adopting</p>
            <p className="text-lg font-mono text-gray-200 tabular-nums mt-0.5">{adopting.length}</p>
          </div>
          <div className="bg-navy-800/30 rounded-lg px-3 py-2">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Ignored</p>
            <p className="text-lg font-mono text-navy-400 tabular-nums mt-0.5">{ignored.length}</p>
          </div>
        </div>

        {/* Device health alerts */}
        {hasIssues && (
          <div className="mt-3 pt-3 border-t border-navy-800/30 space-y-1.5">
            <p className="text-[10px] text-amber-400 uppercase tracking-wider font-medium">Health Alerts</p>
            {devicesOverheating.map((d) => (
              <div key={`heat-${d.mac}`} className="flex items-center gap-2 text-[11px] text-red-400">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                <span className="font-mono">{d.hostname || d.mac}</span>
                <span className="text-navy-500">overheating</span>
              </div>
            ))}
            {devicesWithHighCpu.map((d) => (
              <div key={`cpu-${d.mac}`} className="flex items-center gap-2 text-[11px] text-amber-400">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                <span className="font-mono">{d.hostname || d.mac}</span>
                <span className="text-navy-500">CPU {d.stats?.system_stats?.cpu}%</span>
              </div>
            ))}
            {devicesWithHighMem.map((d) => (
              <div key={`mem-${d.mac}`} className="flex items-center gap-2 text-[11px] text-amber-400">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                <span className="font-mono">{d.hostname || d.mac}</span>
                <span className="text-navy-500">Memory {d.stats?.system_stats?.mem}%</span>
              </div>
            ))}
          </div>
        )}

        {/* Quick device list for adopted */}
        {adopted.length > 0 && (
          <div className="mt-3 pt-3 border-t border-navy-800/30">
            <div className="space-y-1.5">
              {adopted.slice(0, 5).map((d) => (
                <div key={d.mac} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    <span className="text-xs font-mono text-gray-300">{d.hostname || d.mac}</span>
                    <span className="text-[10px] text-navy-500">{d.model_display}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-navy-400 tabular-nums">{d.claimed_ip}</span>
                    {d.stats?.system_stats && (
                      <span className="text-[9px] font-mono text-navy-500">
                        CPU {d.stats.system_stats.cpu}% | MEM {d.stats.system_stats.mem}%
                      </span>
                    )}
                  </div>
                </div>
              ))}
              {adopted.length > 5 && (
                <p className="text-[10px] text-navy-500 text-center">+{adopted.length - 5} more</p>
              )}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}

function NetworkClientsCard({ leases, firewallRuleCount }: { leases: DhcpLease[]; firewallRuleCount: number }) {
  const activeLeases = leases.filter((l) => l.expires > Date.now() / 1000 || l.expires === 0)

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {/* DHCP Clients */}
      <Card noPadding>
        <div className="px-5 py-4">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 rounded-lg bg-navy-800/80 border border-navy-700/30 flex items-center justify-center">
              <svg className="w-4 h-4 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="5" r="2.5" />
                <circle cx="5" cy="19" r="2.5" />
                <circle cx="19" cy="19" r="2.5" />
                <line x1="12" y1="7.5" x2="12" y2="12" />
                <line x1="12" y1="12" x2="5" y2="16.5" />
                <line x1="12" y1="12" x2="19" y2="16.5" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-gray-200">DHCP Clients</p>
              <p className="text-[10px] text-navy-500">{activeLeases.length} active leases</p>
            </div>
          </div>

          {activeLeases.length > 0 ? (
            <div className="space-y-1">
              {activeLeases.slice(0, 6).map((lease) => (
                <div key={`${lease.mac}-${lease.ip}`} className="flex items-center justify-between py-1">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    <span className="text-[11px] text-gray-300 truncate max-w-[120px]">{lease.hostname || 'Unknown'}</span>
                  </div>
                  <span className="text-[10px] font-mono text-navy-400 tabular-nums">{lease.ip}</span>
                </div>
              ))}
              {activeLeases.length > 6 && (
                <p className="text-[10px] text-navy-500 text-center pt-1">+{activeLeases.length - 6} more clients</p>
              )}
            </div>
          ) : (
            <p className="text-[11px] text-navy-500 text-center py-2">No active DHCP leases</p>
          )}
        </div>
      </Card>

      {/* Firewall Summary */}
      <Card noPadding>
        <div className="px-5 py-4">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 rounded-lg bg-navy-800/80 border border-navy-700/30 flex items-center justify-center">
              <svg className="w-4 h-4 text-orange-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-gray-200">Firewall</p>
              <p className="text-[10px] text-navy-500">{firewallRuleCount} rules configured</p>
            </div>
          </div>

          <div className="flex items-center justify-center py-3">
            <div className="text-center">
              <p className="text-3xl font-mono text-gray-200 tabular-nums">{firewallRuleCount}</p>
              <p className="text-[10px] text-navy-500 uppercase tracking-wider mt-1">Active Rules</p>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}

// ---- Interface traffic table ----

function InterfaceTrafficTable({ interfaces }: { interfaces: { name: string; rx_bytes: number; tx_bytes: number }[] }) {
  if (interfaces.length <= 1) return null

  // Sort by total traffic descending
  const sorted = [...interfaces].sort((a, b) => (b.rx_bytes + b.tx_bytes) - (a.rx_bytes + a.tx_bytes))
  const maxTotal = Math.max(sorted[0]?.rx_bytes + sorted[0]?.tx_bytes ?? 1, 1)

  return (
    <div className="mt-4 pt-4 border-t border-navy-800/30">
      <p className="text-[10px] text-navy-500 uppercase tracking-wider font-medium mb-2">Interface Traffic</p>
      <div className="space-y-2">
        {sorted.map((iface) => {
          const total = iface.rx_bytes + iface.tx_bytes
          const pct = (total / maxTotal) * 100
          const rxPct = total > 0 ? (iface.rx_bytes / total) * pct : 0
          const txPct = total > 0 ? (iface.tx_bytes / total) * pct : 0
          return (
            <div key={iface.name} className="flex items-center gap-3">
              <span className="text-[11px] font-mono text-gray-300 w-16 shrink-0">{iface.name}</span>
              <div className="flex-1 h-4 bg-navy-800/50 rounded-sm overflow-hidden flex">
                <div
                  className="h-full bg-emerald-500/60 transition-all duration-500"
                  style={{ width: `${rxPct}%` }}
                  title={`RX: ${fmtBytes(iface.rx_bytes)}`}
                />
                <div
                  className="h-full bg-blue-500/60 transition-all duration-500"
                  style={{ width: `${txPct}%` }}
                  title={`TX: ${fmtBytes(iface.tx_bytes)}`}
                />
              </div>
              <div className="flex items-center gap-2 shrink-0 w-44 justify-end">
                <span className="text-[10px] font-mono text-emerald-400/70 tabular-nums">
                  &#8595; {fmtBytes(iface.rx_bytes)}
                </span>
                <span className="text-[10px] font-mono text-blue-400/70 tabular-nums">
                  &#8593; {fmtBytes(iface.tx_bytes)}
                </span>
              </div>
            </div>
          )
        })}
      </div>
      <div className="flex items-center gap-4 mt-2">
        <span className="flex items-center gap-1 text-[9px] text-navy-500">
          <span className="w-2 h-2 rounded-sm bg-emerald-500/60" /> RX
        </span>
        <span className="flex items-center gap-1 text-[9px] text-navy-500">
          <span className="w-2 h-2 rounded-sm bg-blue-500/60" /> TX
        </span>
      </div>
    </div>
  )
}

// ---- Main Dashboard ----

export default function Dashboard() {
  const { status } = useStatus()
  const [loadHistory, setLoadHistory] = useState<number[]>([])
  const [memHistory, setMemHistory] = useState<number[]>([])
  const [cpuHistory, setCpuHistory] = useState<number[]>([])
  const [rxRateHistory, setRxRateHistory] = useState<number[]>([])
  const [txRateHistory, setTxRateHistory] = useState<number[]>([])
  const [currentRxRate, setCurrentRxRate] = useState(0)
  const [currentTxRate, setCurrentTxRate] = useState(0)
  const prevUptime = useRef(0)
  const prevRx = useRef(0)
  const prevTx = useRef(0)
  const prevTime = useRef(0)

  // Secondary data
  const [wanStatuses, setWanStatuses] = useState<WanStatus[]>([])
  const [idsStats, setIdsStats] = useState<IdsEventStats | null>(null)
  const [vpnTunnels, setVpnTunnels] = useState<TunnelWithStatus[]>([])
  const [dhcpLeases, setDhcpLeases] = useState<DhcpLease[]>([])
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>([])
  const [informDevices, setInformDevices] = useState<UbntDevice[]>([])

  // Build sparkline history from shared status updates
  useEffect(() => {
    if (!status) return
    if (status.uptime_secs === prevUptime.current) return
    prevUptime.current = status.uptime_secs

    setLoadHistory((prev) => [...prev.slice(-(MAX_HISTORY - 1)), status.load_average[0]])
    const memPct = status.memory.total_mb > 0 ? (status.memory.used_mb / status.memory.total_mb) * 100 : 0
    setMemHistory((prev) => [...prev.slice(-(MAX_HISTORY - 1)), memPct])
    const cpuPct = status.cpu_percent ?? Math.min((status.load_average[0] / (status.cpu_count || 4)) * 100, 100)
    setCpuHistory((prev) => [...prev.slice(-(MAX_HISTORY - 1)), cpuPct])

    // Compute net I/O rate (bytes/sec delta)
    const now = Date.now()
    const rx = status.network?.total_rx_bytes ?? 0
    const tx = status.network?.total_tx_bytes ?? 0

    if (prevTime.current > 0 && prevRx.current > 0) {
      const elapsed = (now - prevTime.current) / 1000
      if (elapsed > 0) {
        const rxRate = Math.max(0, (rx - prevRx.current) / elapsed)
        const txRate = Math.max(0, (tx - prevTx.current) / elapsed)
        setCurrentRxRate(rxRate)
        setCurrentTxRate(txRate)
        setRxRateHistory((prev) => [...prev.slice(-(MAX_HISTORY - 1)), rxRate])
        setTxRateHistory((prev) => [...prev.slice(-(MAX_HISTORY - 1)), txRate])
      }
    }
    prevRx.current = rx
    prevTx.current = tx
    prevTime.current = now
  }, [status])

  // Fetch secondary data (WAN, IDS, VPN, DHCP, Firewall, Devices) on a 5s interval
  const fetchSecondaryData = useCallback(async () => {
    // Fire all requests concurrently, don't let one failure block others
    const results = await Promise.allSettled([
      // WAN statuses
      (async () => {
        const res = await api.getWanConfigs()
        const cfgs = res?.configs ?? []
        const statuses: WanStatus[] = []
        for (const c of cfgs) {
          try {
            const r = await api.getWanStatus(c.interface)
            statuses.push(r.wan_status)
          } catch { /* skip unavailable WAN */ }
        }
        return statuses
      })(),
      // IDS stats
      api.getIdsStats(),
      // VPN tunnels + status
      (async () => {
        const res = await api.getVpnTunnels()
        const tunnels = res?.tunnels ?? []
        const withStatus: TunnelWithStatus[] = await Promise.all(
          tunnels.map(async (tunnel) => {
            try {
              const s = await api.getVpnTunnelStatus(tunnel.id)
              return { tunnel, status: s }
            } catch {
              return { tunnel, status: null }
            }
          })
        )
        return withStatus
      })(),
      // DHCP leases
      (async () => {
        const res = await api.getDhcpLeases()
        return res?.leases ?? []
      })(),
      // Firewall rules
      (async () => {
        const res = await api.getFirewallRules()
        return res?.rules ?? []
      })(),
      // Inform devices
      (async () => {
        const res = await api.getInformDevices()
        return res?.devices ?? []
      })(),
    ])

    // Unpack results safely
    if (results[0].status === 'fulfilled') setWanStatuses(results[0].value)
    if (results[1].status === 'fulfilled') setIdsStats(results[1].value)
    if (results[2].status === 'fulfilled') setVpnTunnels(results[2].value)
    if (results[3].status === 'fulfilled') setDhcpLeases(results[3].value)
    if (results[4].status === 'fulfilled') setFirewallRules(results[4].value)
    if (results[5].status === 'fulfilled') setInformDevices(results[5].value)
  }, [])

  useEffect(() => {
    fetchSecondaryData()
    const interval = setInterval(fetchSecondaryData, POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchSecondaryData])

  const uptime = useUptime(status?.uptime_secs ?? 0)

  if (!status) return <Spinner label="Loading system status..." />

  const ramPercent = status.memory.total_mb > 0
    ? (status.memory.used_mb / status.memory.total_mb) * 100 : 0
  const cores = status.cpu_count || 4
  const cpuPercent = status.cpu_percent ?? Math.min((status.load_average[0] / cores) * 100, 100)
  const netIfaces = status.network?.interfaces ?? []
  const enabledFirewallRules = firewallRules.filter((r) => r.enabled).length

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle={
          <div className="flex items-center gap-2">
            <div className="relative">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse-dot" />
            </div>
            <span className="text-xs font-medium text-emerald-400">System Online</span>
            <span className="text-[10px] text-navy-600 font-mono">E2EE + TLS 1.3</span>
            <span className="text-[10px] text-navy-700 font-mono">|</span>
            <span className="text-[10px] text-navy-500 font-mono">Refresh 5s</span>
          </div>
        }
      />

      <div className="space-y-6">
        {/* ====== ROW 1: System Overview Stats ====== */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 stagger-children">
          <StatCard
            label="System Status"
            value={
              <div className="flex items-center gap-2">
                <div className="relative">
                  <div className="w-3 h-3 rounded-full bg-emerald-400" />
                  <div className="absolute inset-0 w-3 h-3 rounded-full bg-emerald-400 animate-ping opacity-30" />
                </div>
                <span className="text-emerald-400">Online</span>
              </div>
            }
            subtitle={fmtUptime(uptime.d, uptime.h, uptime.m, uptime.s)}
            icon={<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" /></svg>}
            accentColor="#34d399"
          />

          <StatCard
            label="CPU Usage"
            value={<span className="font-mono">{Math.round(cpuPercent)}%</span>}
            subtitle={`${status.load_average[0].toFixed(2)} / ${status.load_average[1].toFixed(2)} / ${status.load_average[2].toFixed(2)}`}
            icon={<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>}
            accentColor={cpuPercent > 80 ? '#f87171' : cpuPercent > 50 ? '#fbbf24' : '#34d399'}
          >
            <Sparkline data={cpuHistory} width={180} height={32} color={cpuPercent > 80 ? '#f87171' : '#34d399'} strokeWidth={1.5} />
          </StatCard>

          <StatCard
            label="Load Average"
            value={<span className="font-mono">{status.load_average[0].toFixed(2)}</span>}
            subtitle={`${cores} cores`}
            icon={<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="4" y="4" width="16" height="16" rx="2" /><line x1="9" y1="4" x2="9" y2="20" /><line x1="15" y1="4" x2="15" y2="20" /><line x1="4" y1="9" x2="20" y2="9" /><line x1="4" y1="15" x2="20" y2="15" /></svg>}
            accentColor={status.load_average[0] > cores * 2 ? '#f87171' : status.load_average[0] > cores ? '#fbbf24' : '#34d399'}
          >
            <Sparkline data={loadHistory} width={180} height={32} color={status.load_average[0] > cores * 2 ? '#f87171' : '#34d399'} strokeWidth={1.5} />
          </StatCard>

          <StatCard
            label="Memory"
            value={<span className="font-mono">{Math.round(ramPercent)}%</span>}
            subtitle={`${status.memory.used_mb} / ${status.memory.total_mb} MB`}
            icon={<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="6" width="20" height="12" rx="2" /><line x1="6" y1="10" x2="6" y2="14" /><line x1="10" y1="10" x2="10" y2="14" /></svg>}
            accentColor={ramPercent > 85 ? '#f87171' : ramPercent > 70 ? '#fbbf24' : '#34d399'}
          >
            <Sparkline data={memHistory} width={180} height={32} color={ramPercent > 85 ? '#f87171' : '#34d399'} strokeWidth={1.5} />
          </StatCard>
        </div>

        {/* ====== ROW 2: Network Status (WAN) ====== */}
        {wanStatuses.length > 0 && (
          <Card noPadding>
            <div className="px-5 py-4">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-8 h-8 rounded-lg bg-navy-800/80 border border-navy-700/30 flex items-center justify-center">
                  <svg className="w-4 h-4 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <circle cx="12" cy="12" r="9" /><ellipse cx="12" cy="12" rx="4" ry="9" /><line x1="3" y1="12" x2="21" y2="12" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-semibold text-gray-200">WAN Uplinks</p>
                  <p className="text-[10px] text-navy-500">{wanStatuses.filter((w) => w.link_up).length} / {wanStatuses.length} connected</p>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {wanStatuses.map((wan) => {
                  const wanUpSecs = wan.uptime_secs ?? 0
                  const wanDays = Math.floor(wanUpSecs / 86400)
                  const wanHrs = Math.floor((wanUpSecs % 86400) / 3600)
                  const wanMins = Math.floor((wanUpSecs % 3600) / 60)
                  return (
                    <div
                      key={wan.interface}
                      className={`rounded-lg border p-4 transition-all ${
                        wan.link_up
                          ? 'bg-emerald-500/5 border-emerald-500/20'
                          : 'bg-red-500/5 border-red-500/20'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <div className="relative">
                            <span className={`block w-2.5 h-2.5 rounded-full ${wan.link_up ? 'bg-emerald-400' : 'bg-red-400'}`} />
                            {wan.link_up && <span className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping opacity-30" />}
                          </div>
                          <span className="text-sm font-mono font-semibold text-gray-200">{wan.interface}</span>
                          <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${
                            wan.link_up ? 'bg-emerald-500/15 text-emerald-400' : 'bg-red-500/15 text-red-400'
                          }`}>
                            {wan.link_up ? 'CONNECTED' : 'DOWN'}
                          </span>
                        </div>
                        <span className="text-[10px] text-navy-500 font-mono uppercase">{wan.connection_type}</span>
                      </div>
                      <div className="grid grid-cols-3 gap-3">
                        <div>
                          <p className="text-[10px] text-navy-500 uppercase">IPv4</p>
                          <p className="text-xs font-mono text-gray-300 tabular-nums mt-0.5">{wan.ipv4 ?? '---'}</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-navy-500 uppercase">Gateway</p>
                          <p className="text-xs font-mono text-gray-300 tabular-nums mt-0.5">{wan.gateway_v4 ?? '---'}</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-navy-500 uppercase">Uptime</p>
                          <p className="text-xs font-mono text-gray-300 tabular-nums mt-0.5">
                            {wanDays > 0 ? `${wanDays}d ` : ''}{wanHrs}h {wanMins}m
                          </p>
                        </div>
                      </div>
                      {wan.link_up && (
                        <div className="flex items-center gap-4 mt-3 pt-3 border-t border-navy-800/30">
                          <div className="flex items-center gap-1.5">
                            <span className="text-emerald-400 text-xs">&#8595;</span>
                            <span className="text-[11px] font-mono text-emerald-400/80 tabular-nums">{fmtBytes(wan.rx_bytes)}</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <span className="text-blue-400 text-xs">&#8593;</span>
                            <span className="text-[11px] font-mono text-blue-400/80 tabular-nums">{fmtBytes(wan.tx_bytes)}</span>
                          </div>
                          {wan.dns_servers.length > 0 && (
                            <div className="ml-auto">
                              <span className="text-[10px] text-navy-500">DNS: </span>
                              <span className="text-[10px] font-mono text-navy-400">{wan.dns_servers.join(', ')}</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </Card>
        )}

        {/* ====== ROW 3: Security + VPN side by side ====== */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SecurityOverview stats={idsStats} />
          <VpnOverview tunnels={vpnTunnels} />
        </div>

        {/* ====== ROW 4: Managed Devices ====== */}
        <DevicesOverview devices={informDevices} />

        {/* ====== ROW 5: Clients + Firewall ====== */}
        <NetworkClientsCard leases={dhcpLeases} firewallRuleCount={enabledFirewallRules} />

        {/* ====== ROW 6: Network I/O ====== */}
        <Card title="Network I/O">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* RX */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 text-sm">&#8595;</span>
                  <span className="text-[11px] text-navy-400 uppercase tracking-wider font-medium">Download</span>
                </div>
                <span className="text-sm font-mono text-emerald-400 tabular-nums">{fmtRate(currentRxRate)}</span>
              </div>
              <Sparkline
                data={rxRateHistory}
                width={400}
                height={48}
                color="#34d399"
                strokeWidth={1.5}
              />
              <p className="text-[10px] text-navy-500 font-mono mt-1 tabular-nums">
                Total: {fmtBytes(status.network?.total_rx_bytes ?? 0)}
              </p>
            </div>
            {/* TX */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-blue-400 text-sm">&#8593;</span>
                  <span className="text-[11px] text-navy-400 uppercase tracking-wider font-medium">Upload</span>
                </div>
                <span className="text-sm font-mono text-blue-400 tabular-nums">{fmtRate(currentTxRate)}</span>
              </div>
              <Sparkline
                data={txRateHistory}
                width={400}
                height={48}
                color="#60a5fa"
                strokeWidth={1.5}
              />
              <p className="text-[10px] text-navy-500 font-mono mt-1 tabular-nums">
                Total: {fmtBytes(status.network?.total_tx_bytes ?? 0)}
              </p>
            </div>
          </div>

          {/* Per-interface traffic bar chart */}
          <InterfaceTrafficTable interfaces={netIfaces} />
        </Card>

        {/* ====== ROW 7: NIC Queue Distribution ====== */}
        {status.nic_queues && status.nic_queues.length > 0 && (
          <Card title="NIC Queue Distribution">
            <p className="text-[10px] text-navy-500 mb-3">Per-core hardware queue packet distribution across CPU cores</p>
            <div className="space-y-4">
              {status.nic_queues.map((nic: NicQueueStats) => (
                <NicQueueViz key={nic.name} nic={nic} />
              ))}
            </div>
          </Card>
        )}

        {/* ====== ROW 8: Services ====== */}
        <ServiceGrid services={status.services} />
      </div>
    </div>
  )
}
