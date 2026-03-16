// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useRef } from 'react'
import { Card, PageHeader, Spinner, Sparkline, MiniGauge, StatCard } from '../components/ui'
import { useStatus } from '../hooks/useStatus'
import type { NicQueueStats } from '../api'

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

function UptimeDisplay({ initialSecs }: { initialSecs: number }) {
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

  return (
    <StatCard
      label="Uptime"
      value={
        <div className="flex items-baseline gap-0.5 font-mono">
          {d > 0 && <><span>{d}</span><span className="text-sm text-navy-500 mr-1">d</span></>}
          <span>{h.toString().padStart(2, '0')}</span>
          <span className="text-lg text-navy-600 animate-pulse">:</span>
          <span>{m.toString().padStart(2, '0')}</span>
          <span className="text-lg text-navy-600 animate-pulse">:</span>
          <span>{s.toString().padStart(2, '0')}</span>
        </div>
      }
      icon={<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" /></svg>}
    />
  )
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
            icon={<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" /></svg>}
            accentColor="#34d399"
          />

          <UptimeDisplay initialSecs={status.uptime_secs} />

          <StatCard
            label="Load Average"
            value={<span className="font-mono">{status.load_average[0].toFixed(2)}</span>}
            subtitle={`${status.load_average[0].toFixed(2)} / ${status.load_average[1].toFixed(2)} / ${status.load_average[2].toFixed(2)}`}
            icon={<svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>}
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

        {/* Gauges */}
        <Card>
          <div className="flex items-center justify-around py-2">
            <MiniGauge
              value={status.load_average[0]}
              max={cores}
              label="CPU Load"
              unit="avg"
              thresholds={{ warn: 75, error: 100 }}
              subtitle={`${status.load_average[0].toFixed(2)} / ${cores} cores`}
            />
            <div className="w-px h-20 bg-navy-800/50" />
            <MiniGauge
              value={Math.round(ramPercent)}
              max={100}
              label="Memory"
              unit="%"
              subtitle={`${status.memory.free_mb} MB free`}
            />
            <div className="w-px h-20 bg-navy-800/50" />
            <MiniGauge
              value={Math.round(cpuPercent)}
              max={100}
              label="CPU Usage"
              unit="%"
              thresholds={{ warn: 50, error: 80 }}
            />
          </div>
        </Card>

        {/* Services */}
        <ServiceGrid services={status.services} />
      </div>
    </div>
  )
}
