import { useEffect, useState, useRef, useCallback } from 'react'
import { api, type SystemStatus } from '../api'

// --- Circular Gauge ---
interface GaugeProps {
  value: number
  max: number
  label: string
  unit: string
  status: 'ok' | 'warn' | 'error'
  subtitle?: string
}

const GAUGE_RADIUS = 40
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS

const gaugeColors = {
  ok: { stroke: '#34d399', bg: 'rgba(52, 211, 153, 0.08)' },
  warn: { stroke: '#fbbf24', bg: 'rgba(251, 191, 36, 0.08)' },
  error: { stroke: '#f87171', bg: 'rgba(248, 113, 113, 0.08)' },
}

function CircularGauge({ value, max, label, unit, status, subtitle }: GaugeProps) {
  const percent = max > 0 ? Math.min((value / max) * 100, 100) : 0
  const offset = GAUGE_CIRCUMFERENCE - (percent / 100) * GAUGE_CIRCUMFERENCE
  const colors = gaugeColors[status]

  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 flex flex-col items-center animate-fade-in">
      <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-4">{label}</p>
      <div className="relative w-24 h-24">
        <svg className="w-24 h-24 -rotate-90" viewBox="0 0 96 96">
          {/* Background ring */}
          <circle
            cx="48" cy="48" r={GAUGE_RADIUS}
            fill="none"
            stroke="currentColor"
            strokeWidth="6"
            className="text-navy-800"
          />
          {/* Value ring */}
          <circle
            cx="48" cy="48" r={GAUGE_RADIUS}
            fill="none"
            stroke={colors.stroke}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={GAUGE_CIRCUMFERENCE}
            strokeDashoffset={offset}
            style={{
              transition: 'stroke-dashoffset 0.8s ease-out',
              filter: `drop-shadow(0 0 6px ${colors.stroke}40)`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-light text-gray-100 tabular-nums leading-none">
            {typeof value === 'number' ? (value % 1 !== 0 ? value.toFixed(1) : value) : value}
          </span>
          <span className="text-[10px] text-navy-400 mt-0.5">{unit}</span>
        </div>
      </div>
      {subtitle && (
        <p className="text-[11px] text-navy-500 font-mono mt-3 tabular-nums">{subtitle}</p>
      )}
    </div>
  )
}

// --- Network Throughput Chart (mock) ---
function NetworkChart() {
  const [points] = useState(() => {
    const data: number[] = []
    let val = 30
    for (let i = 0; i < 24; i++) {
      val += (Math.random() - 0.4) * 15
      val = Math.max(5, Math.min(95, val))
      data.push(val)
    }
    return data
  })

  const width = 400
  const height = 120
  const padding = { top: 8, right: 8, bottom: 24, left: 8 }
  const chartW = width - padding.left - padding.right
  const chartH = height - padding.top - padding.bottom
  const maxVal = Math.max(...points)
  const stepX = chartW / (points.length - 1)

  const linePath = points.map((v, i) => {
    const x = padding.left + i * stepX
    const y = padding.top + chartH - (v / maxVal) * chartH
    return `${i === 0 ? 'M' : 'L'}${x},${y}`
  }).join(' ')

  const areaPath = linePath +
    ` L${padding.left + (points.length - 1) * stepX},${padding.top + chartH}` +
    ` L${padding.left},${padding.top + chartH} Z`

  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
      <div className="flex items-center justify-between mb-4">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">Network Throughput <span className="text-navy-600 normal-case">(Mock Data)</span></p>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-0.5 rounded-full bg-emerald-400" />
            <span className="text-[10px] text-navy-500">RX</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-0.5 rounded-full bg-sky-400" />
            <span className="text-[10px] text-navy-500">TX</span>
          </div>
        </div>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#34d399" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#34d399" stopOpacity="0" />
          </linearGradient>
        </defs>
        {/* Grid lines */}
        {[0.25, 0.5, 0.75].map((frac) => (
          <line
            key={frac}
            x1={padding.left}
            y1={padding.top + chartH * frac}
            x2={padding.left + chartW}
            y2={padding.top + chartH * frac}
            stroke="#1a2540"
            strokeWidth="0.5"
          />
        ))}
        {/* Area fill */}
        <path d={areaPath} fill="url(#chartGrad)" />
        {/* Line */}
        <path d={linePath} fill="none" stroke="#34d399" strokeWidth="1.5" strokeLinejoin="round" />
        {/* Time labels */}
        {[0, 6, 12, 18, 23].map((i) => (
          <text
            key={i}
            x={padding.left + i * stepX}
            y={height - 4}
            fill="#334d6e"
            fontSize="8"
            textAnchor="middle"
            fontFamily="monospace"
          >
            {`${(i).toString().padStart(2, '0')}:00`}
          </text>
        ))}
      </svg>
    </div>
  )
}

// --- Service Tile ---
interface ServiceTileProps {
  name: string
  status: string
}

function ServiceTile({ name, status }: ServiceTileProps) {
  const isRunning = status === 'running'
  const isDegraded = status === 'degraded'
  const borderColor = isRunning ? 'border-l-emerald-400' : isDegraded ? 'border-l-amber-400' : 'border-l-red-400'
  const dotColor = isRunning ? 'bg-emerald-400' : isDegraded ? 'bg-amber-400' : 'bg-red-400'
  const textColor = isRunning ? 'text-emerald-400' : isDegraded ? 'text-amber-400' : 'text-red-400'

  return (
    <div className={`bg-navy-900 border border-navy-800/50 border-l-2 ${borderColor} rounded-lg px-4 py-3 flex items-center justify-between transition-all duration-200 hover:bg-navy-850`}>
      <span className="text-sm font-medium text-gray-200 capitalize">{name}</span>
      <div className="flex items-center gap-2">
        <span className={`w-1.5 h-1.5 rounded-full ${dotColor} ${isRunning ? 'animate-pulse-dot' : ''}`} />
        <span className={`text-xs font-medium ${textColor}`}>{status}</span>
      </div>
    </div>
  )
}

// --- Uptime Display ---
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
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
      <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Uptime</p>
      <div className="flex items-baseline gap-1 font-mono tabular-nums">
        {d > 0 && (
          <>
            <span className="text-2xl font-light text-gray-100">{d}</span>
            <span className="text-xs text-navy-500 mr-2">d</span>
          </>
        )}
        <span className="text-2xl font-light text-gray-100">{h.toString().padStart(2, '0')}</span>
        <span className="text-lg text-navy-600">:</span>
        <span className="text-2xl font-light text-gray-100">{m.toString().padStart(2, '0')}</span>
        <span className="text-lg text-navy-600">:</span>
        <span className="text-2xl font-light text-gray-100">{s.toString().padStart(2, '0')}</span>
      </div>
    </div>
  )
}

// --- Main Dashboard ---
export default function Dashboard() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  const fetchStatus = useCallback(() => {
    api.getStatus()
      .then(setStatus)
      .catch((e: Error) => setError(e.message))
  }, [])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 10000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  const ramPercent = status && status.memory.total_mb > 0
    ? (status.memory.used_mb / status.memory.total_mb) * 100
    : 0

  const loadStatus = (load: number): 'ok' | 'warn' | 'error' =>
    load > 4 ? 'error' : load > 2 ? 'warn' : 'ok'
  const ramStatus = (pct: number): 'ok' | 'warn' | 'error' =>
    pct > 85 ? 'error' : pct > 70 ? 'warn' : 'ok'

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold text-gray-100">Dashboard</h2>
        {status && (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse-dot" />
            <span className="text-xs font-medium text-emerald-400">System Online</span>
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 mb-6 animate-fade-in">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-red-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" />
            </svg>
            <p className="text-sm text-red-400">Failed to connect to backend</p>
          </div>
          <p className="text-xs text-red-400/60 mt-1 ml-6 font-mono">{error}</p>
        </div>
      )}

      {!status && !error && (
        <div className="flex items-center justify-center py-20">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3" />
            <p className="text-sm text-navy-400">Loading system status...</p>
          </div>
        </div>
      )}

      {status && (
        <div className="space-y-6">
          {/* Top row: System status + Uptime + Active Connections */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* System Status */}
            <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
              <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">System Status</p>
              <div className="flex items-center gap-3">
                <div className="relative">
                  <div className="w-3 h-3 rounded-full bg-emerald-400 animate-pulse-dot" />
                </div>
                <span className="text-lg font-medium text-emerald-400">Online</span>
              </div>
              <p className="text-[11px] text-navy-500 mt-2 font-mono">E2EE Active / TLS 1.3</p>
            </div>

            {/* Uptime */}
            <UptimeDisplay initialSecs={status.uptime_secs} />

            {/* Active Connections */}
            <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
              <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Active Connections</p>
              <span className="text-2xl font-light text-navy-500">&mdash;</span>
              <p className="text-[11px] text-navy-500 mt-2 font-mono">Coming soon</p>
            </div>

            {/* Services Running */}
            <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
              <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Services</p>
              <div className="flex items-baseline gap-1">
                <span className="text-2xl font-light text-emerald-400 tabular-nums">
                  {Object.values(status.services).filter(s => s === 'running').length}
                </span>
                <span className="text-sm text-navy-500">/</span>
                <span className="text-sm text-navy-400 tabular-nums">{Object.keys(status.services).length}</span>
              </div>
              <p className="text-[11px] text-navy-500 mt-2 font-mono">Running</p>
            </div>
          </div>

          {/* Gauges row */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <CircularGauge
              value={status.load_average[0]}
              max={8}
              label="CPU Load"
              unit="avg"
              status={loadStatus(status.load_average[0])}
              subtitle={`${status.load_average[0].toFixed(2)} / ${status.load_average[1].toFixed(2)} / ${status.load_average[2].toFixed(2)}`}
            />
            <CircularGauge
              value={Math.round(ramPercent)}
              max={100}
              label="Memory"
              unit="%"
              status={ramStatus(ramPercent)}
              subtitle={`${status.memory.used_mb} / ${status.memory.total_mb} MB`}
            />
            <CircularGauge
              value={status.load_average[0]}
              max={16}
              label="CPU Utilization"
              unit="%"
              status={loadStatus(status.load_average[0])}
              subtitle={`${Math.round((status.load_average[0] / 16) * 100)}% utilized`}
            />
          </div>

          {/* Network chart */}
          <NetworkChart />

          {/* Services */}
          <div className="animate-fade-in">
            <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Service Status</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {Object.entries(status.services).map(([name, svcStatus]) => (
                <ServiceTile key={name} name={name} status={svcStatus} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
