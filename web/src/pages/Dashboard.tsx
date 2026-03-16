// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useRef } from 'react'
import { Card, PageHeader, Spinner, Sparkline, StatCard } from '../components/ui'
import { useStatus } from '../hooks/useStatus'
import { api, type NicQueueStats, type WanStatus } from '../api'

const MAX_HISTORY = 60 // 10 min at 10s interval

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
            <span className="text-emerald-400">↓</span> RX per Core
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
            <span className="text-blue-400">↑</span> TX per Core
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

const fmtPkts = (n: number) => {
  if (n < 1000) return `${n}`
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`
  return `${(n / 1_000_000).toFixed(1)}M`
}

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

  const [wanStatuses, setWanStatuses] = useState<WanStatus[]>([])

  // Load WAN status on mount and periodically
  useEffect(() => {
    let cancelled = false
    const loadWan = async () => {
      try {
        const res = await api.getWanConfigs()
        const cfgs = res?.configs ?? []
        const statuses: WanStatus[] = []
        for (const c of cfgs) {
          try {
            const r = await api.getWanStatus(c.interface)
            statuses.push(r?.wan_status ?? r as unknown as WanStatus)
          } catch { /* skip */ }
        }
        if (!cancelled) setWanStatuses(statuses)
      } catch { /* ignore */ }
    }
    loadWan()
    const interval = setInterval(loadWan, 30000)
    return () => { cancelled = true; clearInterval(interval) }
  }, [])

  const uptime = useUptime(status?.uptime_secs ?? 0)

  if (!status) return <Spinner label="Loading system status..." />

  const ramPercent = status.memory.total_mb > 0
    ? (status.memory.used_mb / status.memory.total_mb) * 100 : 0
  const cores = status.cpu_count || 4
  const cpuPercent = status.cpu_percent ?? Math.min((status.load_average[0] / cores) * 100, 100)
  const netIfaces = status.network?.interfaces ?? []

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
          </div>
        }
      />

      <div className="space-y-6">
        {/* Top stats row */}
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

        {/* WAN Status */}
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
                            <span className="text-emerald-400 text-xs">↓</span>
                            <span className="text-[11px] font-mono text-emerald-400/80 tabular-nums">{fmtBytes(wan.rx_bytes)}</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <span className="text-blue-400 text-xs">↑</span>
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

        {/* Network I/O */}
        <Card title="Network I/O">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* RX */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 text-sm">↓</span>
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
                  <span className="text-blue-400 text-sm">↑</span>
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

          {/* Per-interface breakdown */}
          {netIfaces.length > 1 && (
            <div className="mt-4 pt-4 border-t border-navy-800/30">
              <p className="text-[10px] text-navy-500 uppercase tracking-wider font-medium mb-2">Per Interface</p>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                {netIfaces.map((iface) => (
                  <div key={iface.name} className="bg-navy-800/30 rounded-lg px-3 py-2">
                    <p className="text-xs font-mono text-gray-300 font-semibold">{iface.name}</p>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-[10px] font-mono text-emerald-400/70 tabular-nums">
                        ↓ {fmtBytes(iface.rx_bytes)}
                      </span>
                      <span className="text-[10px] font-mono text-blue-400/70 tabular-nums">
                        ↑ {fmtBytes(iface.tx_bytes)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>

        {/* Per-Core NIC Queue Distribution */}
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

        {/* Services */}
        <ServiceGrid services={status.services} />
      </div>
    </div>
  )
}
