// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState, useCallback } from 'react'
import { PageHeader, Card, Button, Badge, Toggle } from '../components/ui'
import { api, getToken } from '../api'
import type { LogDaySummary, LogKeyStatus } from '../api'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface LogEvent {
  ts: string
  level: string
  target: string
  message: string
  fields: string[]
}

const MAX_EVENTS = 500

const levelColor: Record<string, string> = {
  ERROR: 'text-red-400',
  WARN: 'text-amber-400',
  INFO: 'text-emerald-400',
  DEBUG: 'text-blue-400',
  TRACE: 'text-navy-500',
}

const levelBadge: Record<string, 'danger' | 'warning' | 'success' | 'info' | 'neutral'> = {
  ERROR: 'danger',
  WARN: 'warning',
  INFO: 'success',
  DEBUG: 'info',
  TRACE: 'neutral',
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

type Tab = 'live' | 'archive'

export default function Logs() {
  const [tab, setTab] = useState<Tab>('live')

  return (
    <>
      <PageHeader
        title="System Log"
        subtitle="Live event stream and encrypted log archive"
      />

      {/* Tab bar */}
      <div className="flex gap-1 mb-4">
        <button
          onClick={() => setTab('live')}
          className={`px-4 py-2 rounded-t text-sm font-medium transition-colors ${
            tab === 'live'
              ? 'bg-navy-800 text-emerald-400 border-b-2 border-emerald-400'
              : 'text-navy-400 hover:text-gray-300'
          }`}
        >
          Live Stream
        </button>
        <button
          onClick={() => setTab('archive')}
          className={`px-4 py-2 rounded-t text-sm font-medium transition-colors ${
            tab === 'archive'
              ? 'bg-navy-800 text-emerald-400 border-b-2 border-emerald-400'
              : 'text-navy-400 hover:text-gray-300'
          }`}
        >
          Encrypted Archive
        </button>
      </div>

      {tab === 'live' ? <LiveLogView /> : <ArchiveView />}
    </>
  )
}

// ---------------------------------------------------------------------------
// Live log stream (existing functionality)
// ---------------------------------------------------------------------------

function LiveLogView() {
  const [events, setEvents] = useState<LogEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [filter, setFilter] = useState('')
  const [levelFilter, setLevelFilter] = useState<Set<string>>(new Set(['ERROR', 'WARN', 'INFO']))
  const bottomRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  const connect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const token = getToken()
    const url = `/api/v1/events/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`
    const es = new EventSource(url)
    eventSourceRef.current = es

    es.onopen = () => setConnected(true)

    es.onmessage = (e) => {
      try {
        const event: LogEvent = JSON.parse(e.data)
        setEvents(prev => {
          const next = [...prev, event]
          return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next
        })
      } catch { /* ignore parse errors */ }
    }

    es.onerror = () => {
      setConnected(false)
      es.close()
      setTimeout(connect, 3000)
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
      eventSourceRef.current?.close()
    }
  }, [connect])

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

  const handleScroll = () => {
    if (!containerRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current
    const atBottom = scrollHeight - scrollTop - clientHeight < 60
    if (atBottom !== autoScroll) setAutoScroll(atBottom)
  }

  const toggleLevel = (level: string) => {
    setLevelFilter(prev => {
      const next = new Set(prev)
      if (next.has(level)) next.delete(level)
      else next.add(level)
      return next
    })
  }

  const clearLogs = () => setEvents([])

  const lowerFilter = filter.toLowerCase()
  const filtered = events.filter(e =>
    levelFilter.has(e.level) &&
    (!filter || e.message.toLowerCase().includes(lowerFilter) ||
     e.target.toLowerCase().includes(lowerFilter) ||
     e.fields.some(f => f.toLowerCase().includes(lowerFilter)))
  )

  const formatTime = (ts: string) => {
    if (!ts) return '---'
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })
    } catch { return ts }
  }

  const formatTarget = (target: string) => {
    return target.replace(/^sfgw_?/, '').replace(/::/g, '/')
  }

  return (
    <Card noPadding>
      {/* Toolbar */}
      <div className="p-3 border-b border-navy-800/50 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse-dot' : 'bg-red-400'}`} />
          <span className="text-[11px] text-navy-400 font-mono">
            {connected ? 'LIVE' : 'RECONNECTING...'}
          </span>
        </div>

        <div className="w-px h-5 bg-navy-800" />

        <div className="flex items-center gap-1.5">
          {['ERROR', 'WARN', 'INFO', 'DEBUG'].map(level => (
            <button
              key={level}
              onClick={() => toggleLevel(level)}
              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border transition-all ${
                levelFilter.has(level)
                  ? `${levelColor[level]} border-current/30 bg-current/5`
                  : 'text-navy-600 border-navy-800 bg-navy-900/50'
              }`}
            >
              {level}
            </button>
          ))}
        </div>

        <div className="w-px h-5 bg-navy-800" />

        <input
          type="text"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter..."
          className="bg-navy-900 border border-navy-800/50 rounded px-2 py-1 text-xs font-mono text-gray-300 placeholder:text-navy-600 w-40 focus:outline-none focus:border-emerald-500/30"
        />

        <div className="flex-1" />

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <Toggle checked={autoScroll} onChange={() => setAutoScroll(!autoScroll)} />
            <span className="text-[10px] text-navy-500">Auto-scroll</span>
          </div>
          <span className="text-[10px] text-navy-600 font-mono tabular-nums">{filtered.length} events</span>
          <Button variant="secondary" size="sm" onClick={clearLogs}>Clear</Button>
        </div>
      </div>

      {/* Log output */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="h-[calc(100vh-330px)] overflow-y-auto font-mono text-[11px] leading-relaxed"
      >
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-navy-600 text-sm">
            {events.length === 0 ? 'Waiting for events...' : 'No events match filter'}
          </div>
        ) : (
          <table className="w-full">
            <tbody>
              {filtered.map((e, i) => (
                <tr
                  key={i}
                  className={`border-b border-navy-900/50 hover:bg-navy-800/20 ${
                    e.level === 'ERROR' ? 'bg-red-500/5' : e.level === 'WARN' ? 'bg-amber-500/5' : ''
                  }`}
                >
                  <td className="px-3 py-1 text-navy-600 whitespace-nowrap align-top w-[85px]">
                    {formatTime(e.ts)}
                  </td>
                  <td className="px-1 py-1 align-top w-[50px]">
                    <Badge variant={levelBadge[e.level] ?? 'neutral'}>
                      {e.level}
                    </Badge>
                  </td>
                  <td className="px-2 py-1 text-blue-400/60 whitespace-nowrap align-top w-[120px] truncate max-w-[120px]" title={e.target}>
                    {formatTarget(e.target)}
                  </td>
                  <td className="px-2 py-1 text-gray-300 align-top">
                    <span>{e.message}</span>
                    {e.fields.length > 0 && (
                      <span className="ml-2 text-navy-500">
                        {e.fields.join(' ')}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div ref={bottomRef} />
      </div>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Encrypted log archive management
// ---------------------------------------------------------------------------

function ArchiveView() {
  const [days, setDays] = useState<LogDaySummary[]>([])
  const [status, setStatus] = useState<LogKeyStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [destroying, setDestroying] = useState<string | null>(null)
  const [confirmDestroy, setConfirmDestroy] = useState<string | null>(null)
  const [exporting, setExporting] = useState<string | null>(null)

  const loadData = useCallback(async () => {
    try {
      const [daysRes, statusRes] = await Promise.all([
        api.getLogDays(),
        api.getLogStatus(),
      ])
      setDays(daysRes.days)
      setStatus(statusRes.status)
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to load log data:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  const handleExport = async (date: string) => {
    setExporting(date)
    try {
      const result = await api.exportLogDay(date)
      // Trigger download
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `sfgw-logs-${date}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      // Reload data to reflect exported state
      await loadData()
    } catch (err) {
      if (import.meta.env.DEV) console.error('Export failed:', err)
    } finally {
      setExporting(null)
    }
  }

  const handleDestroy = async (date: string) => {
    setDestroying(date)
    try {
      await api.destroyLogDay(date)
      setConfirmDestroy(null)
      await loadData()
    } catch (err) {
      if (import.meta.env.DEV) console.error('Destroy failed:', err)
    } finally {
      setDestroying(null)
    }
  }

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center h-40 text-navy-500">
          Loading encrypted log archive...
        </div>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {/* Key status card */}
      {status && (
        <Card>
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Key Ratchet Status</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-navy-500 mb-1">Current Date</div>
              <div className="text-sm font-mono text-emerald-400">{status.current_date}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-navy-500 mb-1">Ratchet Position</div>
              <div className="text-sm font-mono text-gray-300">{status.ratchet_position}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-navy-500 mb-1">Days Stored</div>
              <div className="text-sm font-mono text-gray-300">{status.total_days_stored}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-navy-500 mb-1">Total Entries</div>
              <div className="text-sm font-mono text-gray-300">{status.total_entries}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-navy-500 mb-1">Destroyed Days</div>
              <div className="text-sm font-mono text-red-400">{status.destroyed_days}</div>
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-navy-800/50">
            <p className="text-[11px] text-navy-500">
              The master key ratchets forward daily. Each ratchet step is a one-way HKDF derivation --
              once ratcheted, previous master states are permanently unrecoverable. Day keys are derived
              from the ratcheted master and can be individually destroyed after export.
            </p>
          </div>
        </Card>
      )}

      {/* Log days table */}
      <Card noPadding>
        <div className="p-3 border-b border-navy-800/50">
          <h3 className="text-sm font-semibold text-gray-300">Encrypted Log Days</h3>
          <p className="text-[11px] text-navy-500 mt-1">
            Each day's logs are encrypted with a unique AES-256-GCM key. Export decrypts and downloads
            the logs, then permanently deletes the key. Destroy removes the key without exporting.
          </p>
        </div>

        {days.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-navy-600 text-sm">
            No encrypted log entries yet
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[10px] uppercase tracking-wider text-navy-500 border-b border-navy-800/50">
                <th className="text-left px-4 py-2">Date</th>
                <th className="text-right px-4 py-2">Entries</th>
                <th className="text-center px-4 py-2">Status</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {days.map(day => (
                <tr key={day.date} className="border-b border-navy-900/30 hover:bg-navy-800/20">
                  <td className="px-4 py-3 font-mono text-gray-300">{day.date}</td>
                  <td className="px-4 py-3 text-right font-mono text-navy-400">{day.entry_count}</td>
                  <td className="px-4 py-3 text-center">
                    {!day.key_available ? (
                      <Badge variant="danger">KEY DESTROYED</Badge>
                    ) : day.exported ? (
                      <Badge variant="warning">EXPORTED</Badge>
                    ) : (
                      <Badge variant="success">ENCRYPTED</Badge>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {day.key_available && (
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleExport(day.date)}
                          disabled={exporting === day.date}
                        >
                          {exporting === day.date ? 'Exporting...' : 'Export'}
                        </Button>

                        {confirmDestroy === day.date ? (
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] text-red-400 mr-1">Permanent!</span>
                            <Button
                              variant="danger"
                              size="sm"
                              onClick={() => handleDestroy(day.date)}
                              disabled={destroying === day.date}
                            >
                              {destroying === day.date ? '...' : 'Confirm'}
                            </Button>
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => setConfirmDestroy(null)}
                            >
                              Cancel
                            </Button>
                          </div>
                        ) : (
                          <Button
                            variant="danger"
                            size="sm"
                            onClick={() => setConfirmDestroy(day.date)}
                          >
                            Destroy Key
                          </Button>
                        )}
                      </div>
                    )}
                    {!day.key_available && (
                      <span className="text-[11px] text-navy-600 italic">unrecoverable</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
