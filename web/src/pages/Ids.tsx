// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { api, type IdsEvent, type IdsEventStats, BASE_URL } from '../api'
import { Card, PageHeader, Spinner, Badge, Select, EmptyState, Button, StatCard } from '../components/ui'
import { useToast } from '../hooks/useToast'

// -- Severity helpers --

type BadgeVariant = 'danger' | 'warning' | 'info' | 'neutral'

const severityVariant = (s: string): BadgeVariant => {
  switch (s.toLowerCase()) {
    case 'critical': return 'danger'
    case 'warning': return 'warning'
    case 'info': return 'info'
    default: return 'neutral'
  }
}

const severityWeight = (s: string): number => {
  switch (s.toLowerCase()) {
    case 'critical': return 3
    case 'warning': return 2
    case 'info': return 1
    default: return 0
  }
}

// -- Time range helpers --

interface TimeRange {
  label: string
  value: string
  hours: number | null
}

const TIME_RANGES: TimeRange[] = [
  { label: 'Last 1h', value: '1h', hours: 1 },
  { label: 'Last 6h', value: '6h', hours: 6 },
  { label: 'Last 24h', value: '24h', hours: 24 },
  { label: 'Last 7d', value: '7d', hours: 168 },
  { label: 'All Time', value: 'all', hours: null },
]

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'Critical', label: 'Critical' },
  { value: 'Warning', label: 'Warning' },
  { value: 'Info', label: 'Info' },
]

const CATEGORY_OPTIONS = [
  { value: '', label: 'All Categories' },
  { value: 'arp', label: 'ARP' },
  { value: 'dhcp', label: 'DHCP' },
  { value: 'dns', label: 'DNS' },
  { value: 'vlan', label: 'VLAN' },
  { value: 'honeypot', label: 'Honeypot' },
  { value: 'inform', label: 'Inform' },
  { value: 'ssh', label: 'SSH' },
]

function sinceFromRange(hours: number | null): string | undefined {
  if (hours === null) return undefined
  const d = new Date(Date.now() - hours * 3600_000)
  return d.toISOString()
}

// -- SSE log event type (matches events.rs LogEvent) --

interface SseLogEvent {
  ts: string
  level: string
  target: string
  message: string
  fields: string[]
}

function parseIdsFromSse(log: SseLogEvent): IdsEvent | null {
  // IDS events come from sfgw_ids targets and contain structured fields
  if (!log.target.startsWith('sfgw_ids')) return null

  // Extract structured fields
  const fieldMap: Record<string, string> = {}
  for (const f of log.fields) {
    const eqIdx = f.indexOf('=')
    if (eqIdx > 0) {
      fieldMap[f.slice(0, eqIdx)] = f.slice(eqIdx + 1)
    }
  }

  // Build an IdsEvent from the SSE log
  return {
    id: -Date.now(), // negative to distinguish from DB IDs
    timestamp: log.ts,
    severity: fieldMap['severity'] ?? (log.level === 'WARN' ? 'Warning' : log.level === 'ERROR' ? 'Critical' : 'Info'),
    detector: fieldMap['detector'] ?? log.target.replace('sfgw_ids::', ''),
    source_mac: fieldMap['source_mac'] ?? '',
    source_ip: fieldMap['source_ip'] ?? '',
    interface: fieldMap['interface'] ?? '',
    vlan: fieldMap['vlan'] ? Number(fieldMap['vlan']) : null,
    description: fieldMap['description'] ?? log.message,
  }
}

// -- Expanded event detail --

function EventDetail({ event }: { event: IdsEvent }) {
  return (
    <tr className="border-b border-navy-800/30 bg-navy-800/10">
      <td colSpan={7} className="px-6 py-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div>
            <span className="text-navy-500 block mb-1">Event ID</span>
            <span className="text-gray-300 font-mono tabular-nums">{event.id > 0 ? event.id : 'Live (unsaved)'}</span>
          </div>
          <div>
            <span className="text-navy-500 block mb-1">Detector</span>
            <span className="text-gray-300 font-mono">{event.detector}</span>
          </div>
          <div>
            <span className="text-navy-500 block mb-1">Source MAC</span>
            <span className="text-gray-300 font-mono">{event.source_mac || '--'}</span>
          </div>
          <div>
            <span className="text-navy-500 block mb-1">Source IP</span>
            <span className="text-gray-300 font-mono tabular-nums">{event.source_ip || '--'}</span>
          </div>
          <div>
            <span className="text-navy-500 block mb-1">Interface</span>
            <span className="text-gray-300 font-mono">{event.interface || '--'}{event.vlan != null && <span className="text-navy-600">.{event.vlan}</span>}</span>
          </div>
          <div>
            <span className="text-navy-500 block mb-1">VLAN</span>
            <span className="text-gray-300 font-mono tabular-nums">{event.vlan ?? '--'}</span>
          </div>
          <div className="col-span-2">
            <span className="text-navy-500 block mb-1">Full Description</span>
            <span className="text-gray-300">{event.description}</span>
          </div>
        </div>
      </td>
    </tr>
  )
}

// -- Main component --

export default function Ids() {
  const [events, setEvents] = useState<IdsEvent[]>([])
  const [stats, setStats] = useState<IdsEventStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState('')
  const [detector, setDetector] = useState('')
  const [timeRange, setTimeRange] = useState('24h')
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const tableEndRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const liveEventsRef = useRef<IdsEvent[]>([])
  const toast = useToast()

  // Scroll to bottom when new events arrive
  useEffect(() => {
    if (autoScroll && tableEndRef.current) {
      tableEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

  // Compute the `since` ISO timestamp from the selected time range
  const selectedRange = TIME_RANGES.find((r) => r.value === timeRange)
  const sinceParam = selectedRange ? sinceFromRange(selectedRange.hours) : undefined

  // Load historical events from API
  const load = useCallback(async () => {
    try {
      const [evRes, statsRes] = await Promise.all([
        api.getIdsEvents({
          limit: 500,
          severity: severity || undefined,
          detector: detector || undefined,
          since: sinceParam,
        }),
        api.getIdsStats(),
      ])
      // Merge with live SSE events (deduplicate by checking if live event is already in DB results)
      const dbIds = new Set(evRes.events.map((e) => e.id))
      const newLiveEvents = liveEventsRef.current.filter((e) => !dbIds.has(e.id))
      setEvents([...evRes.events, ...newLiveEvents])
      setStats(statsRes)
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [severity, detector, sinceParam, toast])

  // Initial load + periodic refresh (every 30s for stats update)
  useEffect(() => {
    load()
    const timer = setInterval(load, 30_000)
    return () => clearInterval(timer)
  }, [load])

  // SSE connection for real-time events
  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return

    // EventSource doesn't support custom headers, so we pass token as query param
    // The SSE endpoint is at /api/v1/events/stream
    const url = `${BASE_URL}/api/v1/events/stream`
    const es = new EventSource(url)
    eventSourceRef.current = es

    es.onopen = () => setSseConnected(true)

    es.onmessage = (msg) => {
      if (!msg.data || msg.data === 'ping') return

      try {
        const logEvent: SseLogEvent = JSON.parse(msg.data)
        const idsEvent = parseIdsFromSse(logEvent)
        if (!idsEvent) return

        // Apply client-side filters
        if (severity && idsEvent.severity.toLowerCase() !== severity.toLowerCase()) return
        if (detector && idsEvent.detector.toLowerCase() !== detector.toLowerCase()) return

        liveEventsRef.current = [...liveEventsRef.current.slice(-200), idsEvent]
        setEvents((prev) => [...prev, idsEvent])
      } catch {
        // Skip non-JSON or malformed events
      }
    }

    es.onerror = () => {
      setSseConnected(false)
    }

    return () => {
      es.close()
      eventSourceRef.current = null
      setSseConnected(false)
    }
  }, [severity, detector])

  // Filter events client-side for time range (SSE events may not have been filtered server-side)
  const filteredEvents = useMemo(() => {
    if (!sinceParam) return events
    const sinceDate = new Date(sinceParam).getTime()
    return events.filter((e) => new Date(e.timestamp).getTime() >= sinceDate)
  }, [events, sinceParam])

  // Sort: newest at bottom for auto-scroll
  const sortedEvents = useMemo(() => {
    return [...filteredEvents].sort((a, b) => {
      const ta = new Date(a.timestamp).getTime()
      const tb = new Date(b.timestamp).getTime()
      return ta - tb
    })
  }, [filteredEvents])

  // Export events as JSON
  const handleExport = useCallback(() => {
    const data = JSON.stringify(sortedEvents, null, 2)
    const blob = new Blob([data], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ids-events-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, [sortedEvents])

  // Format timestamp for display
  const formatTimestamp = (ts: string): string => {
    try {
      const d = new Date(ts)
      return d.toLocaleString(undefined, {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      })
    } catch {
      return ts
    }
  }

  if (loading) return <Spinner label="Loading IDS events..." />

  const criticalCount = stats?.by_severity?.['Critical'] ?? 0
  const warningCount = stats?.by_severity?.['Warning'] ?? 0

  return (
    <div className="space-y-6">
      <PageHeader
        title="Intrusion Detection"
        actions={
          <div className="flex items-center gap-3">
            <Select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              options={SEVERITY_OPTIONS}
            />
            <Select
              value={detector}
              onChange={(e) => setDetector(e.target.value)}
              options={CATEGORY_OPTIONS}
            />
            <Select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              options={TIME_RANGES.map((r) => ({ value: r.value, label: r.label }))}
            />
            <Button variant="secondary" onClick={handleExport} disabled={sortedEvents.length === 0}>
              Export JSON
            </Button>
            <div className="flex items-center gap-1.5">
              <div className={`w-1.5 h-1.5 rounded-full ${sseConnected ? 'bg-emerald-400 animate-pulse-dot' : 'bg-amber-400'}`} />
              <span className="text-[11px] text-navy-500">{sseConnected ? 'Live' : 'Polling'}</span>
            </div>
          </div>
        }
      />

      {/* Stats summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 stagger-children">
        <StatCard
          label="Total Events"
          value={stats?.total ?? 0}
          icon={
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 2L2 7l10 5 10-5-10-5z" /><path d="M2 17l10 5 10-5" /><path d="M2 12l10 5 10-5" />
            </svg>
          }
        />
        <StatCard
          label="Critical (24h)"
          value={stats?.critical_24h ?? 0}
          accentColor={criticalCount > 0 ? '#ef4444' : '#34d399'}
          icon={
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          }
        />
        <StatCard
          label="Warnings"
          value={warningCount}
          accentColor="#f59e0b"
          icon={
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          }
        />
        <StatCard
          label="Top Source IP"
          value={stats?.top_sources?.[0]?.ip ?? '--'}
          subtitle={stats?.top_sources?.[0] ? `${stats.top_sources[0].count} events` : undefined}
          icon={
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
              <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
            </svg>
          }
        />
      </div>

      {/* Detector breakdown */}
      {stats && Object.keys(stats.by_detector).length > 0 && (
        <Card title="Events by Detector">
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.by_detector)
              .sort(([, a], [, b]) => b - a)
              .map(([det, count]) => (
                <button
                  key={det}
                  onClick={() => setDetector(det === detector ? '' : det)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all duration-150 ${
                    det === detector
                      ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                      : 'bg-navy-800/50 border-navy-700/30 text-navy-400 hover:text-gray-300 hover:border-navy-600/50'
                  }`}
                >
                  <span>{det}</span>
                  <span className="text-[10px] tabular-nums bg-navy-700/50 px-1.5 py-0.5 rounded">{count}</span>
                </button>
              ))}
          </div>
        </Card>
      )}

      {/* Top source IPs */}
      {stats && stats.top_sources.length > 1 && (
        <Card title="Top Source IPs">
          <div className="space-y-1.5">
            {stats.top_sources.slice(0, 5).map((src) => {
              const maxCount = stats.top_sources[0]?.count ?? 1
              const pct = Math.round((src.count / maxCount) * 100)
              return (
                <div key={src.ip} className="flex items-center gap-3">
                  <span className="text-xs font-mono text-gray-300 w-32 shrink-0 tabular-nums">{src.ip}</span>
                  <div className="flex-1 h-1.5 bg-navy-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-sky-500/50 rounded-full transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-navy-500 font-mono tabular-nums w-10 text-right">{src.count}</span>
                </div>
              )
            })}
          </div>
        </Card>
      )}

      {/* Auto-scroll toggle */}
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">
          Event Feed ({sortedEvents.length} events)
        </p>
        <button
          onClick={() => setAutoScroll(!autoScroll)}
          className={`flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-1 rounded-lg border transition-all duration-150 ${
            autoScroll
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
              : 'bg-navy-800/50 border-navy-700/30 text-navy-500'
          }`}
        >
          <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 5v14M19 12l-7 7-7-7" />
          </svg>
          Auto-scroll
        </button>
      </div>

      {sortedEvents.length === 0 ? (
        <EmptyState
          icon={
            <svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 2L2 7l10 5 10-5-10-5z" /><path d="M2 17l10 5 10-5" /><path d="M2 12l10 5 10-5" />
            </svg>
          }
          title="No IDS events"
          description={severity || detector || timeRange !== 'all'
            ? 'No events match the current filters. Try broadening your search.'
            : 'All quiet. No threats detected.'}
        />
      ) : (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-navy-900 z-10">
                <tr className="border-b border-navy-800/50">
                  {['Time', 'Severity', 'Category', 'Source IP', 'Interface', 'Description', ''].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sortedEvents.map((ev) => {
                  const isExpanded = expandedId === ev.id
                  const isCritical = ev.severity.toLowerCase() === 'critical'
                  return (
                    <>
                      <tr
                        key={ev.id}
                        onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                        className={`border-b border-navy-800/30 cursor-pointer transition-colors ${
                          isCritical
                            ? 'hover:bg-red-500/5 bg-red-500/[0.02]'
                            : 'hover:bg-navy-800/20'
                        } ${isExpanded ? 'bg-navy-800/20' : ''}`}
                      >
                        <td className="px-4 py-3 font-mono text-navy-400 text-xs whitespace-nowrap tabular-nums">
                          {formatTimestamp(ev.timestamp)}
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant={severityVariant(ev.severity)}>
                            {ev.severity}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 font-mono text-gray-400 text-xs">{ev.detector}</td>
                        <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{ev.source_ip || '--'}</td>
                        <td className="px-4 py-3 font-mono text-gray-400 text-xs">
                          {ev.interface || '--'}
                          {ev.vlan != null && <span className="text-navy-600 ml-1">.{ev.vlan}</span>}
                        </td>
                        <td className="px-4 py-3 text-gray-300 text-xs max-w-xs truncate">{ev.description}</td>
                        <td className="px-4 py-3 text-navy-500">
                          <svg
                            className={`w-3.5 h-3.5 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                          >
                            <path d="M6 9l6 6 6-6" />
                          </svg>
                        </td>
                      </tr>
                      {isExpanded && <EventDetail key={`detail-${ev.id}`} event={ev} />}
                    </>
                  )
                })}
              </tbody>
            </table>
            <div ref={tableEndRef} />
          </div>
        </div>
      )}

      {/* Severity legend */}
      <div className="flex items-center gap-4 text-[10px] text-navy-500">
        <span className="uppercase tracking-wider font-medium">Severity:</span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-red-400" />Critical
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-amber-400" />Warning
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-sky-400" />Info
        </span>
      </div>
    </div>
  )
}
