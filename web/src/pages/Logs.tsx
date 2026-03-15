// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState, useCallback } from 'react'
import { PageHeader, Card, Button, Badge, Toggle } from '../components/ui'
import { getToken } from '../api'

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

export default function Logs() {
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
      // Reconnect after 3s
      setTimeout(connect, 3000)
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
      eventSourceRef.current?.close()
    }
  }, [connect])

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

  // Detect manual scroll up to pause auto-scroll
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
    // sfgw_net::wan → wan, sfgw_fw → fw
    return target.replace(/^sfgw_?/, '').replace(/::/g, '/')
  }

  return (
    <>
      <PageHeader
        title="System Log"
        subtitle="Live event stream from all services"
      />

      <Card noPadding>
        {/* Toolbar */}
        <div className="p-3 border-b border-navy-800/50 flex flex-wrap items-center gap-3">
          {/* Connection status */}
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse-dot' : 'bg-red-400'}`} />
            <span className="text-[11px] text-navy-400 font-mono">
              {connected ? 'LIVE' : 'RECONNECTING...'}
            </span>
          </div>

          <div className="w-px h-5 bg-navy-800" />

          {/* Level filters */}
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

          {/* Text filter */}
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter..."
            className="bg-navy-900 border border-navy-800/50 rounded px-2 py-1 text-xs font-mono text-gray-300 placeholder:text-navy-600 w-40 focus:outline-none focus:border-emerald-500/30"
          />

          <div className="flex-1" />

          {/* Controls */}
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
          className="h-[calc(100vh-280px)] overflow-y-auto font-mono text-[11px] leading-relaxed"
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
    </>
  )
}
