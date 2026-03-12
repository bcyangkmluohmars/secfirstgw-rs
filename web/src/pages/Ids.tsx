import { useEffect, useState, useCallback, useRef } from 'react'
import { api, type IdsEvent } from '../api'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']

const severityColor: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-red-900/60 text-red-300',
  medium: 'bg-amber-900/60 text-amber-300',
  low: 'bg-yellow-900/60 text-yellow-300',
  info: 'bg-blue-900/60 text-blue-300',
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
      <div className="flex items-center gap-3">
        <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
        <span className="text-sm font-mono text-gray-500">Loading IDS events...</span>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Intrusion Detection</h2>
        <div className="flex items-center gap-3">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200"
          >
            <option value="">All Severities</option>
            {SEVERITIES.filter(Boolean).map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <span className="text-xs font-mono text-gray-600">Auto-refresh: 10s</span>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {/* Stats summary */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          {Object.entries(stats).map(([key, value]) => (
            <div key={key} className="bg-gray-900 border border-gray-800 rounded-lg p-3">
              <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">{key.replace(/_/g, ' ')}</p>
              <p className="text-lg font-mono font-bold text-gray-200 mt-1">{String(value)}</p>
            </div>
          ))}
        </div>
      )}

      {events.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-sm font-mono text-gray-500">No IDS events.</p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {['Timestamp', 'Severity', 'Detector', 'Source MAC', 'Source IP', 'Interface', 'Description'].map((h) => (
                    <th key={h} className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-3 py-2.5 font-mono text-gray-400 text-xs whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded ${severityColor[ev.severity] || 'bg-gray-800 text-gray-400'}`}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300 text-xs">{ev.detector}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300 text-xs">{ev.source_mac}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300 text-xs">{ev.source_ip}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300 text-xs">
                      {ev.interface}
                      {ev.vlan != null && <span className="text-gray-500 ml-1">.{ev.vlan}</span>}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300 text-xs">{ev.description}</td>
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
