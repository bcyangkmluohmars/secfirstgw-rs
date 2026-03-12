import { useEffect, useState, useCallback } from 'react'
import { api, type DeviceSummary } from '../api'

const stateBadge: Record<string, string> = {
  Discovered: 'bg-blue-900/50 text-blue-300',
  Pending: 'bg-amber-900/50 text-amber-300',
  Approved: 'bg-emerald-900/50 text-emerald-300',
  Adopted: 'bg-emerald-600/50 text-emerald-200',
  Rejected: 'bg-red-900/50 text-red-300',
}

export default function Devices() {
  const [devices, setDevices] = useState<DeviceSummary[]>([])
  const [pending, setPending] = useState<DeviceSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<'all' | 'pending'>('all')

  const load = useCallback(async () => {
    try {
      const [allRes, pendingRes] = await Promise.all([
        api.getDevices(),
        api.getPendingDevices(),
      ])
      setDevices(allRes.devices)
      setPending(pendingRes.devices)
      setError(null)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleApprove = async (mac: string) => {
    try {
      await api.approveDevice(mac)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleReject = async (mac: string) => {
    try {
      await api.rejectDevice(mac)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleViewConfig = async (mac: string) => {
    try {
      const config = await api.getDeviceConfig(mac)
      alert(JSON.stringify(config, null, 2))
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-3">
        <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
        <span className="text-sm font-mono text-gray-500">Loading devices...</span>
      </div>
    )
  }

  const currentList = tab === 'all' ? devices : pending

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Devices</h2>
        <span className="text-xs font-mono text-gray-500">{devices.length} total, {pending.length} pending</span>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 mb-4">
        <button
          onClick={() => setTab('all')}
          className={`px-4 py-2 text-xs font-mono rounded-t ${tab === 'all' ? 'bg-gray-900 text-gray-200 border border-gray-800 border-b-0' : 'bg-gray-800/50 text-gray-500 hover:text-gray-300'}`}
        >
          All Devices ({devices.length})
        </button>
        <button
          onClick={() => setTab('pending')}
          className={`px-4 py-2 text-xs font-mono rounded-t ${tab === 'pending' ? 'bg-gray-900 text-gray-200 border border-gray-800 border-b-0' : 'bg-gray-800/50 text-gray-500 hover:text-gray-300'}`}
        >
          Pending Approval ({pending.length})
        </button>
      </div>

      {currentList.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-sm font-mono text-gray-500">
            {tab === 'all' ? 'No devices discovered.' : 'No pending devices.'}
          </p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">State</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Name</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Model</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">IP</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">MAC</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Last Seen</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {currentList.map((d) => (
                  <tr key={d.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-3 py-2.5">
                      <span className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded ${stateBadge[d.state] || 'bg-gray-800 text-gray-400'}`}>
                        {d.state}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{d.name || '(unnamed)'}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{d.model || '---'}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{d.ip || '---'}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{d.mac}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-400 text-xs">{d.last_seen ? new Date(d.last_seen).toLocaleString() : '---'}</td>
                    <td className="px-3 py-2.5">
                      <div className="flex gap-2">
                        {(d.state === 'Pending' || d.state === 'Discovered') && (
                          <>
                            <button onClick={() => handleApprove(d.mac)} className="px-2 py-1 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white">Approve</button>
                            <button onClick={() => handleReject(d.mac)} className="px-2 py-1 text-xs font-mono rounded bg-red-600 hover:bg-red-500 text-white">Reject</button>
                          </>
                        )}
                        {d.adopted && (
                          <button onClick={() => handleViewConfig(d.mac)} className="px-2 py-1 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white">Config</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
