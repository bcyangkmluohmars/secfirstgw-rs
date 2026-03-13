import { useEffect, useState, useCallback } from 'react'
import { api, type DeviceSummary } from '../api'

const stateBadge: Record<string, string> = {
  Discovered: 'bg-sky-500/10 text-sky-400 border-sky-500/20',
  Pending: 'bg-amber-500/10 text-amber-400 border-amber-500/15',
  Approved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  Adopted: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/25',
  Rejected: 'bg-red-500/10 text-red-400 border-red-500/15',
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

  const handleApprove = async (device: DeviceSummary) => {
    try {
      // The backend requires an AdoptionRequest body with device details.
      // device_public_key and device_kem_public_key are populated by the
      // backend from stored discovery data; we pass what we have here.
      await api.approveDevice(device.mac, {
        device_mac: device.mac,
        device_model: device.model ?? '',
        device_ip: device.ip ?? '',
        device_public_key: '', // Backend fills from stored discovery data
      })
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
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-navy-400">Loading devices...</p>
        </div>
      </div>
    )
  }

  const currentList = tab === 'all' ? devices : pending

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-100">Devices</h2>
        <span className="text-xs font-medium text-navy-400">
          {devices.length} total{pending.length > 0 && <>, <span className="text-amber-400">{pending.length} pending</span></>}
        </span>
      </div>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 animate-fade-in">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 bg-navy-900 rounded-lg p-1 w-fit">
        <button
          onClick={() => setTab('all')}
          className={`px-4 py-2 text-xs font-medium rounded-md transition-all duration-150 ${
            tab === 'all'
              ? 'bg-navy-800 text-gray-200 shadow-sm'
              : 'text-navy-400 hover:text-gray-300'
          }`}
        >
          All Devices ({devices.length})
        </button>
        <button
          onClick={() => setTab('pending')}
          className={`px-4 py-2 text-xs font-medium rounded-md transition-all duration-150 ${
            tab === 'pending'
              ? 'bg-navy-800 text-gray-200 shadow-sm'
              : 'text-navy-400 hover:text-gray-300'
          }`}
        >
          Pending ({pending.length})
        </button>
      </div>

      {currentList.length === 0 ? (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-16 text-center animate-fade-in">
          <svg className="w-12 h-12 text-navy-700 mx-auto mb-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="4" y="4" width="16" height="12" rx="2" />
            <line x1="12" y1="16" x2="12" y2="20" />
            <line x1="8" y1="20" x2="16" y2="20" />
          </svg>
          <p className="text-sm font-medium text-navy-400">
            {tab === 'all' ? 'No devices adopted yet' : 'No pending devices'}
          </p>
          <p className="text-xs text-navy-600 mt-2 max-w-xs mx-auto">
            {tab === 'all'
              ? 'Connect a device to the MGMT network. It will appear here once discovered.'
              : 'Devices awaiting approval will appear here.'}
          </p>
        </div>
      ) : (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden animate-fade-in">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">State</th>
                  <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Name</th>
                  <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Model</th>
                  <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">IP</th>
                  <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">MAC</th>
                  <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Last Seen</th>
                  <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {currentList.map((d) => (
                  <tr key={d.id} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${stateBadge[d.state] || 'bg-navy-800 text-navy-400 border-navy-700/50'}`}>
                        {d.state}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-200 text-sm">{d.name || <span className="text-navy-500 italic">unnamed</span>}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{d.model || '---'}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{d.ip || '---'}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{d.mac}</td>
                    <td className="px-4 py-3 text-navy-500 text-xs">{d.last_seen ? new Date(d.last_seen).toLocaleString() : '---'}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        {(d.state === 'Pending' || d.state === 'Discovered') && (
                          <>
                            <button onClick={() => handleApprove(d)} className="px-2.5 py-1 text-[11px] font-medium rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors">Approve</button>
                            <button onClick={() => handleReject(d.mac)} className="px-2.5 py-1 text-[11px] font-medium rounded-md bg-red-500/10 text-red-400 border border-red-500/15 hover:bg-red-500/20 transition-colors">Reject</button>
                          </>
                        )}
                        {d.adopted && (
                          <button onClick={() => handleViewConfig(d.mac)} className="px-2.5 py-1 text-[11px] font-medium rounded-md bg-navy-800 text-gray-400 border border-navy-700/50 hover:bg-navy-700/50 transition-colors">Config</button>
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
