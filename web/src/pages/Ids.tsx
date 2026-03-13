import { useEffect, useState, useCallback, useRef } from 'react'
import { api, type IdsEvent } from '../api'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']

const severityStyle: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300 border-red-500/20',
  high: 'bg-red-500/8 text-red-400 border-red-500/15',
  medium: 'bg-amber-500/10 text-amber-400 border-amber-500/15',
  low: 'bg-yellow-500/8 text-yellow-400 border-yellow-500/15',
  info: 'bg-sky-500/8 text-sky-400 border-sky-500/15',
}

export default function Ids() {
  const [events, setEvents] = useState<IdsEvent[]>([])
  const [stats, setStats] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [severity, setSeverity] = useState('')
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const load = useCallback(async (sev?: string) => {
    try {
      const [evRes, statsRes] = await Promise.all([
        api.getIdsEvents(100, sev || undefined),
        api.getIdsStats(),
      ])
      setEvents(evRes.events)
      setStats(statsRes)
      setError(null)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(severity)
    timerRef.current = setInterval(() => load(severity), 10000)
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [load, severity])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-navy-400">Loading IDS events...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-100">Intrusion Detection</h2>
        <div className="flex items-center gap-3">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-emerald-500/50"
          >
            <option value="">All Severities</option>
            {SEVERITIES.filter(Boolean).map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse-dot" />
            <span className="text-[11px] text-navy-500">Live</span>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 animate-fade-in">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 animate-fade-in">
          {Object.entries(stats).map(([key, value]) => (
            <div key={key} className="bg-navy-900 border border-navy-800/50 rounded-xl p-4">
              <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">{key.replace(/_/g, ' ')}</p>
              {value !== null && typeof value === 'object' ? (
                <div className="mt-1 space-y-0.5">
                  {Object.entries(value as Record<string, unknown>).map(([k, v]) => (
                    <p key={k} className="text-xs text-gray-300 tabular-nums">
                      <span className="text-navy-400">{k.replace(/_/g, ' ')}:</span> {typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
                    </p>
                  ))}
                </div>
              ) : (
                <p className="text-xl font-light text-gray-100 mt-1 tabular-nums">{String(value)}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Events */}
      {events.length === 0 ? (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-16 text-center animate-fade-in">
          <svg className="w-12 h-12 text-navy-700 mx-auto mb-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M12 2L2 7l10 5 10-5-10-5z" />
            <path d="M2 17l10 5 10-5" />
            <path d="M2 12l10 5 10-5" />
          </svg>
          <p className="text-sm font-medium text-navy-400">No IDS events</p>
          <p className="text-xs text-navy-600 mt-2">All quiet. No threats detected.</p>
        </div>
      ) : (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden animate-fade-in">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {['Timestamp', 'Severity', 'Detector', 'Source MAC', 'Source IP', 'Interface', 'Description'].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                    <td className="px-4 py-3 font-mono text-navy-400 text-xs whitespace-nowrap tabular-nums">
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${severityStyle[ev.severity] || 'bg-navy-800 text-navy-400 border-navy-700/50'}`}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{ev.detector}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{ev.source_mac}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{ev.source_ip}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">
                      {ev.interface}
                      {ev.vlan != null && <span className="text-navy-600 ml-1">.{ev.vlan}</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-300 text-xs">{ev.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
