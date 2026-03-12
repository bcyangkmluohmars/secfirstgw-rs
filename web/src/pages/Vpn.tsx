import { useEffect, useState } from 'react'
import { api, type VpnTunnel } from '../api'
import Table from '../components/Table'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

export default function Vpn() {
  const [tunnels, setTunnels] = useState<VpnTunnel[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getVpnTunnels()
      .then(setTunnels)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const columns = [
    {
      key: 'status',
      header: '',
      render: (r: VpnTunnel) => (
        <span className={`w-2 h-2 rounded-full inline-block ${r.status === 'active' ? 'bg-emerald-400' : 'bg-gray-600'}`} />
      ),
    },
    { key: 'name', header: 'Name' },
    {
      key: 'type',
      header: 'Type',
      render: (r: VpnTunnel) => (
        <span className="px-2 py-0.5 rounded text-xs font-bold uppercase bg-gray-800 text-gray-300">
          {r.type}
        </span>
      ),
    },
    { key: 'endpoint', header: 'Endpoint' },
    {
      key: 'rx_bytes',
      header: 'RX',
      render: (r: VpnTunnel) => formatBytes(r.rx_bytes),
    },
    {
      key: 'tx_bytes',
      header: 'TX',
      render: (r: VpnTunnel) => formatBytes(r.tx_bytes),
    },
    {
      key: 'connected_since',
      header: 'Connected Since',
      render: (r: VpnTunnel) => r.connected_since ? new Date(r.connected_since).toLocaleString() : '---',
    },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">VPN Tunnels</h2>
        <span className="text-xs font-mono text-gray-500">
          {tunnels.filter((t) => t.status === 'active').length} active / {tunnels.length} total
        </span>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {loading ? (
        <p className="text-sm font-mono text-gray-500">Loading VPN tunnels...</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={columns} data={tunnels} keyField="id" />
        </div>
      )}
    </div>
  )
}
