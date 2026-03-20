// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type DeviceSummary } from '../api'
import { PageHeader, Spinner, Button, Badge, Tabs, EmptyState, Modal } from '../components/ui'
import { useToast } from '../hooks/useToast'

const stateVariant = (d: DeviceSummary) => {
  if (d.adopted) return 'success' as const
  switch (d.state) {
    case 'Discovered': return 'info' as const
    case 'Pending': return 'warning' as const
    case 'Approved': case 'Adopted': return 'success' as const
    case 'Rejected': return 'danger' as const
    default: return 'neutral' as const
  }
}

const stateLabel = (d: DeviceSummary) => {
  if (d.adopted) return 'UniFi Inform'
  return d.state
}

export default function Devices() {
  const [devices, setDevices] = useState<DeviceSummary[]>([])
  const [pending, setPending] = useState<DeviceSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('all')
  const [configModal, setConfigModal] = useState<{ mac: string; data: unknown } | null>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const [allRes, pendingRes] = await Promise.all([api.getDevices(), api.getPendingDevices()])
      setDevices(allRes.devices)
      setPending(pendingRes.devices)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleApprove = async (device: DeviceSummary) => {
    try {
      await api.approveDevice(device.mac, {
        device_mac: device.mac, device_model: device.model ?? '',
        device_ip: device.ip ?? '', device_public_key: '',
      })
      toast.success(`Device ${device.name || device.mac} approved`)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleReject = async (mac: string) => {
    try { await api.rejectDevice(mac); toast.success('Device rejected'); load() }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleViewConfig = async (mac: string) => {
    try {
      const config = await api.getDeviceConfig(mac)
      setConfigModal({ mac, data: config })
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading devices..." />

  const currentList = tab === 'all' ? devices : pending

  return (
    <div className="space-y-6">
      <PageHeader
        title="Devices"
        subtitle={<span className="text-xs text-navy-400">{devices.length} total{pending.length > 0 && <>, <span className="text-amber-400">{pending.length} pending</span></>}</span>}
      />

      <Tabs
        tabs={[
          { key: 'all', label: 'All Devices', count: devices.length },
          { key: 'pending', label: 'Pending', count: pending.length },
        ]}
        active={tab}
        onChange={setTab}
      />

      <Modal open={configModal !== null} onClose={() => setConfigModal(null)} title={`Config: ${configModal?.mac ?? ''}`} size="lg">
        <pre className="bg-navy-800 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-auto max-h-96">
          {configModal ? JSON.stringify(configModal.data, null, 2) : ''}
        </pre>
      </Modal>

      {currentList.length === 0 ? (
        <EmptyState
          icon={<svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="4" y="4" width="16" height="12" rx="2" /><line x1="12" y1="16" x2="12" y2="20" /><line x1="8" y1="20" x2="16" y2="20" /></svg>}
          title={tab === 'all' ? 'No devices adopted yet' : 'No pending devices'}
          description={tab === 'all' ? 'Connect a device to the MGMT network.' : 'Devices awaiting approval will appear here.'}
        />
      ) : (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {['State', 'Name', 'Model', 'IP', 'MAC', 'Last Seen', 'Actions'].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {currentList.map((d) => (
                  <tr key={d.id} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                    <td className="px-4 py-3"><Badge variant={stateVariant(d)}>{stateLabel(d)}</Badge></td>
                    <td className="px-4 py-3 text-gray-200 text-sm">{d.name || <span className="text-navy-500 italic">unnamed</span>}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{d.model || '---'}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{d.ip || '---'}</td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">{d.mac}</td>
                    <td className="px-4 py-3 text-navy-500 text-xs">{d.last_seen ? new Date(d.last_seen).toLocaleString() : '---'}</td>
                    <td className="px-4 py-3">
                      {!d.adopted && (
                        <div className="flex gap-2">
                          {(d.state === 'Pending' || d.state === 'Discovered') && (
                            <>
                              <Button size="sm" onClick={() => handleApprove(d)}>Approve</Button>
                              <Button size="sm" variant="danger" onClick={() => handleReject(d.mac)}>Reject</Button>
                            </>
                          )}
                        </div>
                      )}
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
