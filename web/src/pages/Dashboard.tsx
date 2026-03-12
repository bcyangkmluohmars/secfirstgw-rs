import { useEffect, useState } from 'react'
import { api, type SystemStatus } from '../api'
import StatusCard from '../components/StatusCard'

export default function Dashboard() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getStatus()
      .then(setStatus)
      .catch((e: Error) => setError(e.message))
  }, [])

  function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400)
    const h = Math.floor((seconds % 86400) / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    if (d > 0) return `${d}d ${h}h ${m}m`
    if (h > 0) return `${h}h ${m}m`
    return `${m}m`
  }

  return (
    <div>
      <h2 className="text-lg font-bold font-mono mb-6">Dashboard</h2>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-6">
          <p className="text-sm font-mono text-red-400">Failed to connect to backend</p>
          <p className="text-xs font-mono text-red-500 mt-1">{error}</p>
        </div>
      )}

      {!status && !error && (
        <div className="text-sm text-gray-500 font-mono">Loading system status...</div>
      )}

      {status && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatusCard
              title="System Status"
              value="Online"
              status="ok"
            />
            <StatusCard
              title="Uptime"
              value={formatUptime(status.uptime_secs)}
              status="ok"
            />
            <StatusCard
              title="Load Average"
              value={status.load_average[0].toFixed(2)}
              status={status.load_average[0] > 4 ? 'error' : status.load_average[0] > 2 ? 'warn' : 'ok'}
              subtitle={`${status.load_average[0].toFixed(2)} / ${status.load_average[1].toFixed(2)} / ${status.load_average[2].toFixed(2)}`}
            />
            <StatusCard
              title="Memory"
              value={`${status.memory.total_mb > 0 ? ((status.memory.used_mb / status.memory.total_mb) * 100).toFixed(0) : 0}%`}
              status={status.memory.total_mb > 0 && status.memory.used_mb / status.memory.total_mb > 0.85 ? 'error' : status.memory.used_mb / status.memory.total_mb > 0.7 ? 'warn' : 'ok'}
              subtitle={`${status.memory.used_mb} MB / ${status.memory.total_mb} MB`}
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">System Information</h3>
              <dl className="space-y-2 text-sm font-mono">
                <div className="flex justify-between">
                  <dt className="text-gray-500">Uptime</dt>
                  <dd className="text-gray-200">{formatUptime(status.uptime_secs)}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Load</dt>
                  <dd className="text-gray-200">{status.load_average.map(v => v.toFixed(2)).join(' / ')}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Memory</dt>
                  <dd className="text-gray-200">{status.memory.used_mb} / {status.memory.total_mb} MB</dd>
                </div>
              </dl>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">Services</h3>
              <div className="space-y-2">
                {Object.entries(status.services).map(([name, svcStatus]) => (
                  <div key={name} className="flex items-center justify-between text-sm font-mono">
                    <span className="text-gray-300 capitalize">{name}</span>
                    <span className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full ${svcStatus === 'running' ? 'bg-emerald-400' : 'bg-gray-600'}`} />
                      <span className={svcStatus === 'running' ? 'text-emerald-400' : 'text-gray-500'}>
                        {svcStatus}
                      </span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
