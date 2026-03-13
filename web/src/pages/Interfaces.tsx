// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type NetworkInterface } from '../api'
import { PageHeader, Spinner, Badge, Button, Modal, Input, Select, Toggle, Card, EmptyState } from '../components/ui'
import { useToast } from '../hooks/useToast'

const ROLES = ['wan', 'lan', 'dmz', 'mgmt', 'guest'] as const

const roleVariant = (r: string) => {
  switch (r.toLowerCase()) {
    case 'wan': return 'danger' as const
    case 'lan': return 'success' as const
    case 'dmz': return 'warning' as const
    case 'mgmt': return 'info' as const
    case 'guest': return 'neutral' as const
    default: return 'neutral' as const
  }
}

const portTypeIcon = (portType: string | null) => {
  if (!portType) return null
  const lower = portType.toLowerCase()
  if (lower.includes('rj45')) return '🔌'
  if (lower.includes('sfp')) return '💎'
  if (lower.includes('qsfp')) return '⚡'
  if (lower.includes('bridge')) return '🌉'
  if (lower.includes('vlan')) return '🏷️'
  if (lower.includes('virtual') || lower.includes('veth')) return '☁️'
  return '🔗'
}

export default function Interfaces() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [loading, setLoading] = useState(true)
  const [showVlanModal, setShowVlanModal] = useState(false)
  const [editIface, setEditIface] = useState<NetworkInterface | null>(null)
  const [vlanForm, setVlanForm] = useState({ parent: '', vlanId: '', role: 'lan' })
  const [editForm, setEditForm] = useState({ role: '', mtu: '', vlanId: '' as string | null })
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getInterfaces()
      setInterfaces(res.interfaces ?? [])
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const physicalInterfaces = interfaces.filter((i) => i.vlan_id == null)
  const vlanInterfaces = interfaces.filter((i) => i.vlan_id != null)

  const openVlanModal = () => {
    setVlanForm({ parent: physicalInterfaces[0]?.name ?? '', vlanId: '', role: 'lan' })
    setShowVlanModal(true)
  }

  const openEdit = (iface: NetworkInterface) => {
    setEditForm({
      role: iface.role,
      mtu: String(iface.mtu),
      vlanId: iface.vlan_id != null ? String(iface.vlan_id) : null,
    })
    setEditIface(iface)
  }

  const handleCreateVlan = async () => {
    const vid = Number(vlanForm.vlanId)
    if (!vlanForm.parent || !vid || vid < 1 || vid > 4094) {
      toast.error('Parent interface and VLAN ID (1-4094) are required')
      return
    }
    try {
      const res = await api.createVlan({ parent: vlanForm.parent, vlan_id: vid, role: vlanForm.role })
      toast.success(`VLAN ${res.name} created`)
      setShowVlanModal(false)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleUpdate = async () => {
    if (!editIface) return
    try {
      await api.updateInterface(editIface.name, {
        role: editForm.role,
        mtu: Number(editForm.mtu),
        ...(editForm.vlanId !== null ? { vlan_id: editForm.vlanId ? Number(editForm.vlanId) : null } : {}),
      })
      toast.success(`${editIface.name} updated`)
      setEditIface(null)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleToggle = async (iface: NetworkInterface) => {
    try {
      await api.toggleInterface(iface.name, !iface.enabled)
      toast.success(`${iface.name} ${iface.enabled ? 'disabled' : 'enabled'}`)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDeleteVlan = async (name: string) => {
    try {
      await api.deleteInterface(name)
      toast.success(`${name} deleted`)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading interfaces..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Interfaces"
        subtitle="Hardware ports, VLANs, and virtual interfaces"
      />

      {interfaces.length === 0 ? (
        <EmptyState
          icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="6" width="20" height="12" rx="2" /><circle cx="6" cy="12" r="1.5" /><circle cx="10" cy="12" r="1.5" /></svg>}
          title="No interfaces found"
          description="Network interfaces will appear here once detected."
        />
      ) : (
        <>
          {/* Action bar */}
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={openVlanModal}>+ Create VLAN</Button>
          </div>

          {/* Create VLAN Modal */}
          <Modal open={showVlanModal} onClose={() => setShowVlanModal(false)} title="Create VLAN Sub-Interface">
            <div className="space-y-4">
              <p className="text-xs text-navy-400">
                Create a tagged sub-interface on an existing physical port. The VLAN will be assigned to a security zone.
              </p>
              <div className="grid grid-cols-2 gap-3">
                <Select
                  label="Parent Interface"
                  value={vlanForm.parent}
                  onChange={(e) => setVlanForm({ ...vlanForm, parent: e.target.value })}
                  options={physicalInterfaces.map((i) => ({
                    value: i.name,
                    label: `${i.name}${i.port_type ? ` (${i.port_type})` : ''}`
                  }))}
                />
                <Input
                  label="VLAN ID (1-4094)"
                  type="number"
                  mono
                  value={vlanForm.vlanId}
                  onChange={(e) => setVlanForm({ ...vlanForm, vlanId: e.target.value })}
                  placeholder="100"
                />
                <Select
                  label="Zone / Role"
                  value={vlanForm.role}
                  onChange={(e) => setVlanForm({ ...vlanForm, role: e.target.value })}
                  options={ROLES.map((r) => ({ value: r, label: r.toUpperCase() }))}
                />
              </div>
              <div className="bg-navy-800/50 border border-navy-700/30 rounded-lg p-3">
                <p className="text-[10px] text-navy-400">
                  Preview: <span className="font-mono text-gray-300">{vlanForm.parent || '...'}.{vlanForm.vlanId || '?'}</span> → <span className="font-mono text-gray-300 uppercase">{vlanForm.role}</span> zone
                </p>
              </div>
              <div className="flex gap-2">
                <Button onClick={handleCreateVlan}>Create VLAN</Button>
                <Button variant="secondary" onClick={() => setShowVlanModal(false)}>Cancel</Button>
              </div>
            </div>
          </Modal>

          {/* Edit Interface Modal */}
          <Modal open={editIface !== null} onClose={() => setEditIface(null)} title={`Edit: ${editIface?.name ?? ''}`}>
            <div className="space-y-4">
              {editIface && (
                <div className="bg-navy-800/50 border border-navy-700/30 rounded-lg p-3 flex items-center gap-3">
                  {editIface.port_type && (
                    <span className="text-lg">{portTypeIcon(editIface.port_type)}</span>
                  )}
                  <div>
                    <p className="text-xs text-navy-400">
                      {editIface.port_type ?? 'Unknown'}{editIface.speed ? ` · ${editIface.speed}` : ''}{editIface.driver ? ` · ${editIface.driver}` : ''}
                    </p>
                    <p className="font-mono text-xs text-navy-500 mt-0.5">{editIface.mac || 'No MAC'}</p>
                  </div>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <Select
                  label="Zone / Role"
                  value={editForm.role}
                  onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                  options={ROLES.map((r) => ({ value: r, label: r.toUpperCase() }))}
                />
                <Input
                  label="MTU"
                  type="number"
                  mono
                  value={editForm.mtu}
                  onChange={(e) => setEditForm({ ...editForm, mtu: e.target.value })}
                />
              </div>
              <div className="flex gap-2">
                <Button onClick={handleUpdate}>Save Changes</Button>
                <Button variant="secondary" onClick={() => setEditIface(null)}>Cancel</Button>
              </div>
            </div>
          </Modal>

          {/* Physical / Hardware Ports */}
          <Card title="Hardware Ports" noPadding>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-navy-800/50">
                    {['', 'Port', 'Type', 'MAC', 'IPs', 'Speed', 'MTU', 'Zone', 'Status', ''].map((h, idx) => (
                      <th key={`${h}-${idx}`} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="stagger-children">
                  {physicalInterfaces.map((iface) => (
                    <tr key={iface.name} className={`border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors ${!iface.enabled ? 'opacity-40' : ''}`}>
                      <td className="px-4 py-3 w-10">
                        <div className="relative">
                          <span className={`block w-2 h-2 rounded-full ${iface.is_up && iface.enabled ? 'bg-emerald-400' : 'bg-red-400'}`} />
                          {iface.is_up && iface.enabled && <span className="absolute inset-0 w-2 h-2 rounded-full bg-emerald-400 animate-ping opacity-30" />}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-gray-200 text-sm font-semibold">{iface.name}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          {iface.port_type && <span className="text-sm">{portTypeIcon(iface.port_type)}</span>}
                          <span className="text-xs text-gray-400">{iface.port_type ?? '---'}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-navy-500 text-xs">{iface.mac || '---'}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">
                        {(iface.ips ?? []).length > 0
                          ? (iface.ips ?? []).map((ip, i) => <div key={i}>{ip}</div>)
                          : <span className="text-navy-600">---</span>}
                      </td>
                      <td className="px-4 py-3">
                        {iface.speed ? (
                          <span className="px-2 py-0.5 rounded bg-navy-800 border border-navy-700/50 text-[10px] font-mono text-gray-300 tabular-nums">{iface.speed}</span>
                        ) : (
                          <span className="text-navy-600 text-xs">---</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{iface.mtu}</td>
                      <td className="px-4 py-3"><Badge variant={roleVariant(iface.role)}>{iface.role.toUpperCase()}</Badge></td>
                      <td className="px-4 py-3">
                        <Toggle checked={iface.enabled} onChange={() => handleToggle(iface)} />
                      </td>
                      <td className="px-4 py-3">
                        <Button variant="secondary" size="sm" onClick={() => openEdit(iface)}>Edit</Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* VLAN Sub-Interfaces */}
          {vlanInterfaces.length > 0 && (
            <Card title="VLAN Sub-Interfaces" noPadding>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-navy-800/50">
                      {['', 'Interface', 'VLAN ID', 'Parent', 'Zone', 'MTU', 'Status', ''].map((h, idx) => (
                        <th key={`${h}-${idx}`} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="stagger-children">
                    {vlanInterfaces.map((iface) => {
                      const parentName = iface.name.includes('.') ? iface.name.split('.')[0] : '---'
                      return (
                        <tr key={iface.name} className={`border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors ${!iface.enabled ? 'opacity-40' : ''}`}>
                          <td className="px-4 py-3 w-10">
                            <span className={`w-2 h-2 rounded-full inline-block ${iface.is_up && iface.enabled ? 'bg-emerald-400' : 'bg-red-400'}`} />
                          </td>
                          <td className="px-4 py-3 font-mono text-gray-200 text-sm">{iface.name}</td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded bg-navy-800 border border-navy-700/50 text-xs font-mono text-gray-300 tabular-nums">{iface.vlan_id}</span>
                          </td>
                          <td className="px-4 py-3 font-mono text-navy-400 text-xs">{parentName}</td>
                          <td className="px-4 py-3"><Badge variant={roleVariant(iface.role)}>{iface.role.toUpperCase()}</Badge></td>
                          <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{iface.mtu}</td>
                          <td className="px-4 py-3">
                            <Toggle checked={iface.enabled} onChange={() => handleToggle(iface)} />
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex gap-1.5">
                              <Button variant="secondary" size="sm" onClick={() => openEdit(iface)}>Edit</Button>
                              <Button variant="danger" size="sm" onClick={() => handleDeleteVlan(iface.name)}>Delete</Button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-4">
              <p className="text-[10px] text-navy-500 uppercase tracking-wider">Physical Ports</p>
              <p className="text-2xl font-semibold text-gray-200 mt-1 tabular-nums">{physicalInterfaces.length}</p>
            </div>
            <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-4">
              <p className="text-[10px] text-navy-500 uppercase tracking-wider">VLANs</p>
              <p className="text-2xl font-semibold text-gray-200 mt-1 tabular-nums">{vlanInterfaces.length}</p>
            </div>
            <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-4">
              <p className="text-[10px] text-navy-500 uppercase tracking-wider">Active</p>
              <p className="text-2xl font-semibold text-emerald-400 mt-1 tabular-nums">{interfaces.filter((i) => i.is_up && i.enabled).length}</p>
            </div>
            <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-4">
              <p className="text-[10px] text-navy-500 uppercase tracking-wider">Disabled</p>
              <p className="text-2xl font-semibold text-red-400 mt-1 tabular-nums">{interfaces.filter((i) => !i.enabled).length}</p>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
