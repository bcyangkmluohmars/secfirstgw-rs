import { useEffect, useState } from 'react'
import { api, type NetworkInterface } from '../api'
import Table from '../components/Table'

export default function Network() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getInterfaces()
      .then((res) => setInterfaces(res.interfaces))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const ifaceColumns = [
    {
      key: 'enabled',
      header: '',
      render: (r: NetworkInterface) => (
        <span className={`w-2 h-2 rounded-full inline-block ${r.enabled ? 'bg-emerald-400' : 'bg-red-400'}`} />
      ),
    },
    { key: 'name', header: 'Interface' },
    { key: 'role', header: 'Role' },
    {
      key: 'vlan_id',
      header: 'VLAN',
      render: (r: NetworkInterface) => r.vlan_id != null ? String(r.vlan_id) : '---',
    },
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

      <div>
        <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">Interfaces</h3>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={ifaceColumns} data={interfaces} keyField="name" />
        </div>
      </div>
    </div>
  )
}
