// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useRef } from 'react'
import { Card, PageHeader, Spinner, Sparkline, MiniGauge, StatCard } from '../components/ui'
import { useStatus } from '../hooks/useStatus'

const MAX_HISTORY = 60 // 10 min at 10s interval

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

export default function Dashboard() {
  const { status } = useStatus()
  const [loadHistory, setLoadHistory] = useState<number[]>([])
  const [memHistory, setMemHistory] = useState<number[]>([])
  const prevUptime = useRef(0)

  // Build sparkline history from shared status updates
  useEffect(() => {
    if (!status) return
    // Only append when uptime changes (i.e. new data from server, not re-render)
    if (status.uptime_secs === prevUptime.current) return
    prevUptime.current = status.uptime_secs

    setLoadHistory((prev) => [...prev.slice(-(MAX_HISTORY - 1)), status.load_average[0]])
    const memPct = status.memory.total_mb > 0 ? (status.memory.used_mb / status.memory.total_mb) * 100 : 0
    setMemHistory((prev) => [...prev.slice(-(MAX_HISTORY - 1)), memPct])
  }, [status])

  if (!status) return <Spinner label="Loading system status..." />

  const ramPercent = status.memory.total_mb > 0
    ? (status.memory.used_mb / status.memory.total_mb) * 100 : 0
  const cpuPercent = Math.min((status.load_average[0] / 8) * 100, 100)

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
            accentColor={status.load_average[0] > 4 ? '#f87171' : status.load_average[0] > 2 ? '#fbbf24' : '#34d399'}
          >
            <Sparkline data={loadHistory} width={180} height={32} color={status.load_average[0] > 4 ? '#f87171' : '#34d399'} strokeWidth={1.5} />
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

        {/* Gauges */}
        <Card>
          <div className="flex items-center justify-around py-2">
            <MiniGauge
              value={status.load_average[0]}
              max={8}
              label="CPU Load"
              unit="avg"
              thresholds={{ warn: 25, error: 50 }}
              subtitle={`${status.load_average[0].toFixed(2)} / 8 cores`}
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
