import { useEffect, useState } from 'react'
import { api, type NetworkInterface, type Vlan } from '../api'
import Table from '../components/Table'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

export default function Network() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [vlans, setVlans] = useState<Vlan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      api.getNetworkInterfaces().catch(() => [] as NetworkInterface[]),
      api.getVlans().catch(() => [] as Vlan[]),
    ])
      .then(([ifaces, vl]) => { setInterfaces(ifaces); setVlans(vl) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const ifaceColumns = [
    {
      key: 'status',
      header: '',
      render: (r: NetworkInterface) => (
        <span className={`w-2 h-2 rounded-full inline-block ${r.status === 'up' ? 'bg-emerald-400' : 'bg-red-400'}`} />
      ),
    },
    { key: 'name', header: 'Interface' },
    { key: 'ip', header: 'IP Address' },
    { key: 'mac', header: 'MAC' },
    { key: 'speed', header: 'Speed' },
    {
      key: 'rx_bytes',
      header: 'RX',
      render: (r: NetworkInterface) => formatBytes(r.rx_bytes),
    },
    {
      key: 'tx_bytes',
      header: 'TX',
      render: (r: NetworkInterface) => formatBytes(r.tx_bytes),
    },
  ]

  const vlanColumns = [
    { key: 'id', header: 'VLAN ID' },
    { key: 'name', header: 'Name' },
    { key: 'interface', header: 'Interface' },
    { key: 'subnet', header: 'Subnet' },
  ]

  if (loading) return <p className="text-sm font-mono text-gray-500">Loading network data...</p>

  return (
    <div>
      <h2 className="text-lg font-bold font-mono mb-6">Network</h2>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      <div className="mb-8">
        <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">Interfaces</h3>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={ifaceColumns} data={interfaces} keyField="name" />
        </div>
      </div>

      <div>
        <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">VLANs</h3>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={vlanColumns} data={vlans} keyField="id" />
        </div>
      </div>
    </div>
  )
}
