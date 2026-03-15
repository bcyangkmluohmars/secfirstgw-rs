// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { api, pvidToZone, type NetworkInterface } from '../../api'
import { Badge, Button, EmptyState, Modal, Input, Select, Toggle, Card } from '../../components/ui'
import { useToast } from '../../hooks/useToast'

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

interface InterfacesTabProps {
  interfaces: NetworkInterface[]
  onReload: () => void
}

export default function InterfacesTab({ interfaces, onReload }: InterfacesTabProps) {
  const [showVlanModal, setShowVlanModal] = useState(false)
  const [editIface, setEditIface] = useState<NetworkInterface | null>(null)
  const [vlanForm, setVlanForm] = useState({ parent: '', vlanId: '', role: 'lan' })
  const [editForm, setEditForm] = useState({ role: '', mtu: '', vlanId: '' as string | null })
  const toast = useToast()

  const physicalInterfaces = interfaces.filter((i) => i.vlan_id == null)
  const vlanInterfaces = interfaces.filter((i) => i.vlan_id != null)

  const openVlanModal = () => {
    setVlanForm({ parent: physicalInterfaces[0]?.name ?? '', vlanId: '', role: 'lan' })
    setShowVlanModal(true)
  }

  const openEdit = (iface: NetworkInterface) => {
    setEditForm({
      role: pvidToZone(iface.pvid),
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
      onReload()
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
      onReload()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleToggle = async (iface: NetworkInterface) => {
    try {
      await api.toggleInterface(iface.name, !iface.enabled)
      toast.success(`${iface.name} ${iface.enabled ? 'disabled' : 'enabled'}`)
      onReload()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDeleteVlan = async (name: string) => {
    try {
      await api.deleteInterface(name)
      toast.success(`${name} deleted`)
      onReload()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (interfaces.length === 0) {
    return (
      <EmptyState
        icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="6" width="20" height="12" rx="2" /><circle cx="6" cy="12" r="1.5" /><circle cx="10" cy="12" r="1.5" /></svg>}
        title="No interfaces found"
        description="Network interfaces will appear here once detected."
      />
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">
          Interfaces
          <span className="text-navy-600 ml-2">({interfaces.length})</span>
        </p>
        <Button size="sm" onClick={openVlanModal}>+ Create VLAN</Button>
      </div>

      {/* Create VLAN Modal */}
      <Modal open={showVlanModal} onClose={() => setShowVlanModal(false)} title="Create VLAN Sub-Interface">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Parent Interface"
              value={vlanForm.parent}
              onChange={(e) => setVlanForm({ ...vlanForm, parent: e.target.value })}
              options={physicalInterfaces.map((i) => ({ value: i.name, label: `${i.name} (${pvidToZone(i.pvid)})` }))}
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
              Creates <span className="font-mono text-gray-300">{vlanForm.parent || '...'}.{vlanForm.vlanId || '?'}</span> as a tagged sub-interface assigned to the <span className="font-mono text-gray-300 uppercase">{vlanForm.role}</span> zone.
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
            <Button onClick={handleUpdate}>Save</Button>
            <Button variant="secondary" onClick={() => setEditIface(null)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Physical Interfaces */}
      <Card title="Physical Interfaces" noPadding>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-navy-800/50">
                {['', 'Interface', 'MAC', 'IPs', 'MTU', 'Zone', 'Status', ''].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {physicalInterfaces.map((iface) => (
                <tr key={iface.name} className={`border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors ${!iface.enabled ? 'opacity-40' : ''}`}>
                  <td className="px-4 py-3 w-10">
                    <div className="relative">
                      <span className={`block w-2 h-2 rounded-full ${iface.is_up && iface.enabled ? 'bg-emerald-400' : 'bg-red-400'}`} />
                      {iface.is_up && iface.enabled && <span className="absolute inset-0 w-2 h-2 rounded-full bg-emerald-400 animate-ping opacity-30" />}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-200 text-sm font-semibold">{iface.name}</td>
                  <td className="px-4 py-3 font-mono text-navy-500 text-xs">{iface.mac || '---'}</td>
                  <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">
                    {(iface.ips ?? []).length > 0
                      ? (iface.ips ?? []).map((ip, i) => <div key={i}>{ip}</div>)
                      : <span className="text-navy-600">---</span>}
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{iface.mtu}</td>
                  <td className="px-4 py-3"><Badge variant={roleVariant(pvidToZone(iface.pvid))}>{pvidToZone(iface.pvid).toUpperCase()}</Badge></td>
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

      {/* VLAN Interfaces */}
      {vlanInterfaces.length > 0 && (
        <Card title="VLAN Sub-Interfaces" noPadding>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {['', 'Interface', 'VLAN ID', 'Zone', 'MTU', 'Status', ''].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {vlanInterfaces.map((iface) => (
                  <tr key={iface.name} className={`border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors ${!iface.enabled ? 'opacity-40' : ''}`}>
                    <td className="px-4 py-3 w-10">
                      <span className={`w-2 h-2 rounded-full inline-block ${iface.is_up && iface.enabled ? 'bg-emerald-400' : 'bg-red-400'}`} />
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-200 text-sm">{iface.name}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-navy-800 border border-navy-700/50 text-xs font-mono text-gray-300 tabular-nums">{iface.vlan_id}</span>
                    </td>
                    <td className="px-4 py-3"><Badge variant={roleVariant(pvidToZone(iface.pvid))}>{pvidToZone(iface.pvid).toUpperCase()}</Badge></td>
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
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
