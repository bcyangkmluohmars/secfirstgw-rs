// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import {
  api,
  type ZoneInfo,
  type CustomZone,
  type CustomZoneRequest,
  type AllowedService,
} from '../api'
import {
  Card,
  PageHeader,
  Spinner,
  Button,
  Badge,
  Modal,
  Input,
  Select,
  EmptyState,
} from '../components/ui'
import { useToast } from '../hooks/useToast'

// ── Built-in zone display ──────────────────────────────────────────

const ZONE_COLORS: Record<string, string> = {
  wan: 'bg-red-500/15 text-red-400',
  lan: 'bg-emerald-500/15 text-emerald-400',
  dmz: 'bg-amber-500/15 text-amber-400',
  mgmt: 'bg-blue-500/15 text-blue-400',
  guest: 'bg-purple-500/15 text-purple-400',
  iot: 'bg-orange-500/15 text-orange-400',
  vpn: 'bg-cyan-500/15 text-cyan-400',
}

function zoneColor(zone: string): string {
  return ZONE_COLORS[zone.toLowerCase()] ?? 'bg-navy-700 text-navy-300'
}

function policyBadge(policy: string) {
  const variant = policy === 'accept' ? 'success' as const : 'danger' as const
  return <Badge variant={variant}>{policy.toUpperCase()}</Badge>
}

// ── Presets ─────────────────────────────────────────────────────────

function iotPreset(): CustomZoneRequest {
  return {
    name: 'iot',
    vlan_id: 40,
    policy_inbound: 'drop',
    policy_outbound: 'accept',
    policy_forward: 'drop',
    allowed_services: [
      { protocol: 'udp', port: 53, description: 'DNS' },
      { protocol: 'udp', port: 67, description: 'DHCP' },
    ],
    description: 'IoT devices: internet-only, no inter-VLAN access',
  }
}

function vpnPreset(): CustomZoneRequest {
  return {
    name: 'vpn',
    vlan_id: 50,
    policy_inbound: 'drop',
    policy_outbound: 'accept',
    policy_forward: 'drop',
    allowed_services: [
      { protocol: 'udp', port: 53, description: 'DNS' },
    ],
    description: 'VPN clients: access to LAN, blocked from MGMT/DMZ',
  }
}

function emptyZone(): CustomZoneRequest {
  return {
    name: '',
    vlan_id: 100,
    policy_inbound: 'drop',
    policy_outbound: 'drop',
    policy_forward: 'drop',
    allowed_services: [],
    description: '',
  }
}

// ── Service editor ─────────────────────────────────────────────────

function ServiceEditor({
  services,
  onChange,
}: {
  services: AllowedService[]
  onChange: (s: AllowedService[]) => void
}) {
  const addService = () => {
    onChange([...services, { protocol: 'tcp', port: 0, description: '' }])
  }

  const removeService = (idx: number) => {
    onChange(services.filter((_, i) => i !== idx))
  }

  const updateService = (idx: number, field: keyof AllowedService, value: string | number) => {
    const updated = services.map((s, i) =>
      i === idx ? { ...s, [field]: value } : s,
    )
    onChange(updated)
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs font-medium text-navy-400">Allowed Services (to Gateway)</label>
        <Button size="sm" variant="ghost" onClick={addService}>+ Add</Button>
      </div>
      {services.length === 0 && (
        <p className="text-xs text-navy-500">No services allowed to gateway</p>
      )}
      {services.map((svc, idx) => (
        <div key={idx} className="flex items-center gap-2">
          <Select
            value={svc.protocol}
            onChange={(e) => updateService(idx, 'protocol', e.target.value)}
            className="w-20"
            options={[
              { value: 'tcp', label: 'TCP' },
              { value: 'udp', label: 'UDP' },
            ]}
          />
          <Input
            type="number"
            min={1}
            max={65535}
            value={svc.port || ''}
            onChange={(e) => updateService(idx, 'port', parseInt(e.target.value, 10) || 0)}
            placeholder="Port"
            className="w-24"
          />
          <Input
            value={svc.description ?? ''}
            onChange={(e) => updateService(idx, 'description', e.target.value)}
            placeholder="Description"
            className="flex-1"
          />
          <Button size="sm" variant="danger" onClick={() => removeService(idx)}>
            Remove
          </Button>
        </div>
      ))}
    </div>
  )
}

// ── Zone form modal ────────────────────────────────────────────────

function ZoneFormModal({
  open,
  onClose,
  onSave,
  initial,
  title,
}: {
  open: boolean
  onClose: () => void
  onSave: (zone: CustomZoneRequest) => Promise<void>
  initial: CustomZoneRequest
  title: string
}) {
  const [form, setForm] = useState<CustomZoneRequest>(initial)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setForm(initial)
    setError(null)
  }, [initial, open])

  const handleSave = async () => {
    setError(null)
    setSaving(true)
    try {
      await onSave(form)
      onClose()
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  if (!open) return null

  return (
    <Modal title={title} open={open} onClose={onClose}>
      <div className="space-y-4">
        {error && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/20 px-3 py-2 text-xs text-red-400">
            {error}
          </div>
        )}

        <Input
          label="Zone Name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') })}
          placeholder="e.g., iot, vpn, cameras"
        />

        <Input
          label="VLAN ID"
          type="number"
          min={2}
          max={4094}
          value={form.vlan_id}
          onChange={(e) => setForm({ ...form, vlan_id: parseInt(e.target.value, 10) || 2 })}
        />

        <Input
          label="Description"
          value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
          placeholder="What is this zone for?"
        />

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="text-xs font-medium text-navy-400 block mb-1">Inbound</label>
            <Select
              value={form.policy_inbound}
              onChange={(e) => setForm({ ...form, policy_inbound: e.target.value as 'drop' | 'accept' })}
              options={[
                { value: 'drop', label: 'DROP' },
                { value: 'accept', label: 'ACCEPT' },
              ]}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-navy-400 block mb-1">Outbound</label>
            <Select
              value={form.policy_outbound}
              onChange={(e) => setForm({ ...form, policy_outbound: e.target.value as 'drop' | 'accept' })}
              options={[
                { value: 'drop', label: 'DROP' },
                { value: 'accept', label: 'ACCEPT' },
              ]}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-navy-400 block mb-1">Forward</label>
            <Select
              value={form.policy_forward}
              onChange={(e) => setForm({ ...form, policy_forward: e.target.value as 'drop' | 'accept' })}
              options={[
                { value: 'drop', label: 'DROP' },
                { value: 'accept', label: 'ACCEPT' },
              ]}
            />
          </div>
        </div>

        <ServiceEditor
          services={form.allowed_services}
          onChange={(s) => setForm({ ...form, allowed_services: s })}
        />

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} disabled={saving || !form.name}>
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

// ── Main Zones page ────────────────────────────────────────────────

export default function Zones() {
  const [builtInZones, setBuiltInZones] = useState<ZoneInfo[]>([])
  const [customZones, setCustomZones] = useState<CustomZone[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editZone, setEditZone] = useState<CustomZone | null>(null)
  const [presetForm, setPresetForm] = useState<CustomZoneRequest>(emptyZone())
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const [zonesRes, customRes] = await Promise.all([
        api.getZones(),
        api.getCustomZones(),
      ])
      setBuiltInZones(zonesRes.zones)
      setCustomZones(customRes.zones)
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleCreate = async (zone: CustomZoneRequest) => {
    await api.createCustomZone(zone)
    toast.success(`Zone "${zone.name}" created`)
    await load()
  }

  const handleUpdate = async (zone: CustomZoneRequest) => {
    if (!editZone) return
    await api.updateCustomZone(editZone.id, zone)
    toast.success(`Zone "${zone.name}" updated`)
    setEditZone(null)
    await load()
  }

  const handleDelete = async (zone: CustomZone) => {
    try {
      await api.deleteCustomZone(zone.id)
      toast.success(`Zone "${zone.name}" deleted`)
      await load()
    } catch (e: unknown) {
      toast.error((e as Error).message)
    }
  }

  const openCreate = (preset?: CustomZoneRequest) => {
    setEditZone(null)
    setPresetForm(preset ?? emptyZone())
    setModalOpen(true)
  }

  const openEdit = (zone: CustomZone) => {
    setEditZone(zone)
    setPresetForm({
      name: zone.name,
      vlan_id: zone.vlan_id,
      policy_inbound: zone.policy_inbound,
      policy_outbound: zone.policy_outbound,
      policy_forward: zone.policy_forward,
      allowed_services: zone.allowed_services,
      description: zone.description,
    })
    setModalOpen(true)
  }

  if (loading) return <Spinner label="Loading zones..." />

  return (
    <div>
      <PageHeader
        title="Zones"
        subtitle="Network zone management with security policies"
      />

      {/* Built-in zones */}
      <Card title="Built-in Zones" className="mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-navy-700">
                <th className="px-3 py-2 text-left text-navy-400 font-medium">Zone</th>
                <th className="px-3 py-2 text-left text-navy-400 font-medium">Name</th>
                <th className="px-3 py-2 text-left text-navy-400 font-medium">VLAN</th>
                <th className="px-3 py-2 text-left text-navy-400 font-medium">Subnet</th>
                <th className="px-3 py-2 text-left text-navy-400 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {builtInZones.map((z) => (
                <tr key={z.id} className="border-b border-navy-800/50">
                  <td className="px-3 py-2">
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-mono font-medium ${zoneColor(z.zone)}`}>
                      {z.zone.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-navy-200">{z.name}</td>
                  <td className="px-3 py-2 text-navy-300 font-mono">{z.vlan_id ?? '-'}</td>
                  <td className="px-3 py-2 text-navy-300 font-mono">{z.subnet ?? '-'}</td>
                  <td className="px-3 py-2">
                    <Badge variant={z.enabled ? 'success' : 'warning'}>
                      {z.enabled ? 'Active' : 'Disabled'}
                    </Badge>
                  </td>
                </tr>
              ))}
              {builtInZones.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-navy-500 text-sm">
                    No built-in zones configured yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Custom zones */}
      <Card
        title="Custom Zones"
        actions={
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={() => openCreate(iotPreset())}>
              + IoT
            </Button>
            <Button size="sm" variant="ghost" onClick={() => openCreate(vpnPreset())}>
              + VPN
            </Button>
            <Button size="sm" onClick={() => openCreate()}>
              + Custom
            </Button>
          </div>
        }
      >
        {customZones.length === 0 ? (
          <EmptyState
            title="No custom zones"
            description="Create an IoT, VPN, or custom zone to segment your network further."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-700">
                  <th className="px-3 py-2 text-left text-navy-400 font-medium">Zone</th>
                  <th className="px-3 py-2 text-left text-navy-400 font-medium">VLAN</th>
                  <th className="px-3 py-2 text-left text-navy-400 font-medium">Inbound</th>
                  <th className="px-3 py-2 text-left text-navy-400 font-medium">Outbound</th>
                  <th className="px-3 py-2 text-left text-navy-400 font-medium">Forward</th>
                  <th className="px-3 py-2 text-left text-navy-400 font-medium">Services</th>
                  <th className="px-3 py-2 text-left text-navy-400 font-medium">Description</th>
                  <th className="px-3 py-2 text-right text-navy-400 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {customZones.map((cz) => (
                  <tr key={cz.id} className="border-b border-navy-800/50">
                    <td className="px-3 py-2">
                      <span className={`inline-block px-2 py-0.5 rounded text-xs font-mono font-medium ${zoneColor(cz.name)}`}>
                        {cz.name.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-navy-300 font-mono">{cz.vlan_id}</td>
                    <td className="px-3 py-2">{policyBadge(cz.policy_inbound)}</td>
                    <td className="px-3 py-2">{policyBadge(cz.policy_outbound)}</td>
                    <td className="px-3 py-2">{policyBadge(cz.policy_forward)}</td>
                    <td className="px-3 py-2 text-navy-300 text-xs">
                      {cz.allowed_services.length > 0
                        ? cz.allowed_services.map((s) => s.description || `${s.protocol}/${s.port}`).join(', ')
                        : '-'}
                    </td>
                    <td className="px-3 py-2 text-navy-400 text-xs max-w-[200px] truncate">
                      {cz.description || '-'}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" onClick={() => openEdit(cz)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="danger" onClick={() => handleDelete(cz)}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Create/Edit modal */}
      <ZoneFormModal
        open={modalOpen}
        onClose={() => { setModalOpen(false); setEditZone(null) }}
        onSave={editZone ? handleUpdate : handleCreate}
        initial={presetForm}
        title={editZone ? `Edit Zone: ${editZone.name}` : 'Create Custom Zone'}
      />
    </div>
  )
}
