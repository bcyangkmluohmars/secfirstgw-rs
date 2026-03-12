import { useEffect, useState } from 'react'
import { api, type Device } from '../api'
import Table from '../components/Table'

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getDevices()
      .then((res) => setDevices(res.devices))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const columns = [
    {
      key: 'adopted',
      header: '',
      render: (r: Device) => (
        <span className={`w-2 h-2 rounded-full inline-block ${r.adopted ? 'bg-emerald-400' : 'bg-amber-400'}`} />
      ),
    },
    {
      key: 'name',
      header: 'Name',
      render: (r: Device) => r.name || '(unnamed)',
    },
    {
      key: 'model',
      header: 'Model',
      render: (r: Device) => r.model || '---',
    },
    {
      key: 'ip',
      header: 'IP',
      render: (r: Device) => r.ip || '---',
    },
    { key: 'mac', header: 'MAC' },
    {
      key: 'adopted',
      header: 'Adopted',
      render: (r: Device) => (
        <span className={`text-xs font-bold ${r.adopted ? 'text-emerald-400' : 'text-gray-500'}`}>
          {r.adopted ? 'Yes' : 'No'}
        </span>
      ),
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      render: (r: Device) => r.last_seen ? new Date(r.last_seen).toLocaleString() : '---',
    },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Devices</h2>
        <span className="text-xs font-mono text-gray-500">{devices.length} total</span>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {loading ? (
        <p className="text-sm font-mono text-gray-500">Loading devices...</p>
      ) : devices.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-sm font-mono text-gray-500">No devices discovered.</p>
          <p className="text-xs font-mono text-gray-600 mt-2">Devices will appear here when adopted.</p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={columns} data={devices} keyField="mac" />
        </div>
      )}
    </div>
  )
}
