import { useEffect, useState } from 'react'
import { api, type Device } from '../api'
import Table from '../components/Table'

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getDevices()
      .then(setDevices)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const columns = [
    {
      key: 'status',
      header: '',
      render: (r: Device) => (
        <span className={`w-2 h-2 rounded-full inline-block ${
          r.status === 'online' ? 'bg-emerald-400' :
          r.status === 'pending' ? 'bg-amber-400' : 'bg-red-400'
        }`} />
      ),
    },
    { key: 'name', header: 'Name' },
    { key: 'model', header: 'Model' },
    { key: 'ip', header: 'IP Address' },
    { key: 'mac', header: 'MAC' },
    { key: 'firmware', header: 'Firmware' },
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
      render: (r: Device) => {
        try {
          return new Date(r.last_seen).toLocaleString()
        } catch {
          return r.last_seen
        }
      },
    },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Devices</h2>
        <div className="flex items-center gap-4 text-xs font-mono text-gray-500">
          <span>{devices.filter((d) => d.status === 'online').length} online</span>
          <span>{devices.filter((d) => d.status === 'pending').length} pending</span>
          <span>{devices.length} total</span>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {loading ? (
        <p className="text-sm font-mono text-gray-500">Loading devices...</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={columns} data={devices} keyField="id" />
        </div>
      )}
    </div>
  )
}
