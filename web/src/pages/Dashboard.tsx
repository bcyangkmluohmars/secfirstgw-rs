import { useEffect, useState } from 'react'
import { api, type SystemStatus } from '../api'
import StatusCard from '../components/StatusCard'

export default function Dashboard() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getStatus()
      .then(setStatus)
      .catch((e) => setError(e.message))
  }, [])

  function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400)
    const h = Math.floor((seconds % 86400) / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    if (d > 0) return `${d}d ${h}h ${m}m`
    if (h > 0) return `${h}h ${m}m`
    return `${m}m`
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
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
              subtitle={status.platform}
            />
            <StatusCard
              title="Uptime"
              value={formatUptime(status.uptime_seconds)}
              status="ok"
            />
            <StatusCard
              title="CPU Usage"
              value={`${status.cpu_usage.toFixed(1)}%`}
              status={status.cpu_usage > 80 ? 'error' : status.cpu_usage > 50 ? 'warn' : 'ok'}
            />
            <StatusCard
              title="Memory"
              value={`${((status.memory_used / status.memory_total) * 100).toFixed(0)}%`}
              status={status.memory_used / status.memory_total > 0.85 ? 'error' : status.memory_used / status.memory_total > 0.7 ? 'warn' : 'ok'}
              subtitle={`${formatBytes(status.memory_used)} / ${formatBytes(status.memory_total)}`}
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">System Information</h3>
              <dl className="space-y-2 text-sm font-mono">
                <div className="flex justify-between">
                  <dt className="text-gray-500">Hostname</dt>
                  <dd className="text-gray-200">{status.hostname}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Platform</dt>
                  <dd className="text-gray-200">{status.platform}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Version</dt>
                  <dd className="text-gray-200">{status.version}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Uptime</dt>
                  <dd className="text-gray-200">{formatUptime(status.uptime_seconds)}</dd>
                </div>
              </dl>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">Services</h3>
              <div className="space-y-2">
                {[
                  { name: 'Firewall', status: 'active' as const },
                  { name: 'IDS/IPS', status: 'active' as const },
                  { name: 'VPN Gateway', status: 'active' as const },
                  { name: 'DNS Resolver', status: 'active' as const },
                  { name: 'DHCP Server', status: 'active' as const },
                ].map((svc) => (
                  <div key={svc.name} className="flex items-center justify-between text-sm font-mono">
                    <span className="text-gray-300">{svc.name}</span>
                    <span className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full ${svc.status === 'active' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                      <span className={svc.status === 'active' ? 'text-emerald-400' : 'text-red-400'}>
                        {svc.status}
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
