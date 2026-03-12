import { useEffect, useState } from 'react'
import { api, type IdsEvent } from '../api'
import Table from '../components/Table'

export default function Ids() {
  const [events, setEvents] = useState<IdsEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getIdsEvents()
      .then(setEvents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const severityStyles: Record<string, string> = {
    critical: 'bg-red-900/50 text-red-400',
    high: 'bg-orange-900/50 text-orange-400',
    medium: 'bg-amber-900/50 text-amber-400',
    low: 'bg-blue-900/50 text-blue-400',
  }

  const actionStyles: Record<string, string> = {
    drop: 'text-red-400',
    alert: 'text-amber-400',
    pass: 'text-gray-500',
  }

  const columns = [
    {
      key: 'timestamp',
      header: 'Time',
      render: (r: IdsEvent) => {
        try {
          return new Date(r.timestamp).toLocaleString()
        } catch {
          return r.timestamp
        }
      },
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (r: IdsEvent) => (
        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${severityStyles[r.severity] ?? ''}`}>
          {r.severity}
        </span>
      ),
    },
    { key: 'signature', header: 'Signature' },
    { key: 'protocol', header: 'Proto' },
    { key: 'source_ip', header: 'Source' },
    { key: 'destination_ip', header: 'Destination' },
    {
      key: 'action',
      header: 'Action',
      render: (r: IdsEvent) => (
        <span className={`text-xs font-bold uppercase ${actionStyles[r.action] ?? ''}`}>
          {r.action}
        </span>
      ),
    },
  ]

  const critCount = events.filter((e) => e.severity === 'critical').length
  const highCount = events.filter((e) => e.severity === 'high').length

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Intrusion Detection</h2>
        <div className="flex items-center gap-4 text-xs font-mono">
          {critCount > 0 && <span className="text-red-400">{critCount} critical</span>}
          {highCount > 0 && <span className="text-orange-400">{highCount} high</span>}
          <span className="text-gray-500">{events.length} events</span>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {loading ? (
        <p className="text-sm font-mono text-gray-500">Loading IDS events...</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={columns} data={events} keyField="id" />
        </div>
      )}
    </div>
  )
}
