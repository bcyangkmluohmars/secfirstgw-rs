// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback, useRef } from 'react'
import { api, type IdsEvent } from '../api'
import { Card, PageHeader, Spinner, Badge, Select, EmptyState } from '../components/ui'
import { useToast } from '../hooks/useToast'

const severityVariant = (s: string) => {
  switch (s) {
    case 'critical': case 'high': return 'danger' as const
    case 'medium': return 'warning' as const
    case 'low': return 'warning' as const
    case 'info': return 'info' as const
    default: return 'neutral' as const
  }
}

export default function Ids() {
  const [events, setEvents] = useState<IdsEvent[]>([])
  const [stats, setStats] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState('')
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const toast = useToast()

  const load = useCallback(async (sev?: string) => {
    try {
      const [evRes, statsRes] = await Promise.all([api.getIdsEvents(100, sev || undefined), api.getIdsStats()])
      setEvents(evRes.events)
      setStats(statsRes)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => {
    load(severity)
    timerRef.current = setInterval(() => load(severity), 10000)
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [load, severity])

  if (loading) return <Spinner label="Loading IDS events..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Intrusion Detection"
        actions={
          <div className="flex items-center gap-3">
            <Select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              options={[
                { value: '', label: 'All Severities' },
                { value: 'critical', label: 'critical' },
                { value: 'high', label: 'high' },
                { value: 'medium', label: 'medium' },
                { value: 'low', label: 'low' },
                { value: 'info', label: 'info' },
              ]}
            />
            <div className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse-dot" />
              <span className="text-[11px] text-navy-500">Live</span>
            </div>
          </div>
        }
      />

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 stagger-children">
          {Object.entries(stats).map(([key, value]) => (
            <Card key={key}>
              <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">{key.replace(/_/g, ' ')}</p>
              {value !== null && typeof value === 'object' ? (
                <div className="mt-1 space-y-0.5">
                  {Object.entries(value as Record<string, unknown>).map(([k, v]) => (
                    <p key={k} className="text-xs text-gray-300 tabular-nums">
                      <span className="text-navy-400">{k.replace(/_/g, ' ')}:</span> {String(v)}
                    </p>
                  ))}
                </div>
              ) : (
                <p className="text-xl font-light text-gray-100 mt-1 tabular-nums">{String(value)}</p>
              )}
            </Card>
          ))}
        </div>
      )}

      {events.length === 0 ? (
        <EmptyState
          icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2L2 7l10 5 10-5-10-5z" /><path d="M2 17l10 5 10-5" /><path d="M2 12l10 5 10-5" /></svg>}
          title="No IDS events"
          description="All quiet. No threats detected."
        />
      ) : (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
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
                    <td className="px-4 py-3 font-mono text-navy-400 text-xs whitespace-nowrap tabular-nums">{new Date(ev.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-3"><Badge variant={severityVariant(ev.severity)}>{ev.severity}</Badge></td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{ev.detector}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{ev.source_mac}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{ev.source_ip}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{ev.interface}{ev.vlan != null && <span className="text-navy-600 ml-1">.{ev.vlan}</span>}</td>
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
