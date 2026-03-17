// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, pvidToZone, type WirelessNetwork, type WirelessNetworkCreate } from '../api'
import { PageHeader, Card, Button, Badge, Toggle, Modal, Input, Select, EmptyState, Spinner } from '../components/ui'
import { useToast } from '../hooks/useToast'

type Security = 'open' | 'wpa2' | 'wpa3'
type Band = 'both' | '2g' | '5g'

interface WlanFormState {
  ssid: string
  security: Security
  psk: string
  hidden: boolean
  band: Band
  vlan_id: string
  is_guest: boolean
  l2_isolation: boolean
  enabled: boolean
}

const emptyForm: WlanFormState = {
  ssid: '', security: 'wpa2', psk: '', hidden: false,
  band: 'both', vlan_id: '', is_guest: false, l2_isolation: false, enabled: true,
}

const securityLabel: Record<Security, string> = { open: 'Open', wpa2: 'WPA2-PSK', wpa3: 'WPA3-SAE' }
const bandLabel: Record<Band, string> = { both: '2.4 + 5 GHz', '2g': '2.4 GHz', '5g': '5 GHz' }

const VLAN_OPTIONS = [
  { value: '',     label: 'None (untagged)' },
  { value: '10',   label: 'LAN (VLAN 10)' },
  { value: '3000', label: 'MGMT (VLAN 3000)' },
  { value: '3001', label: 'DMZ (VLAN 3001)' },
  { value: '3002', label: 'Guest (VLAN 3002)' },
]

function formToPayload(form: WlanFormState): WirelessNetworkCreate {
  return {
    ssid: form.ssid,
    security: form.security,
    ...(form.security !== 'open' && form.psk ? { psk: form.psk } : {}),
    hidden: form.hidden,
    band: form.band,
    vlan_id: form.vlan_id ? Number(form.vlan_id) : null,
    is_guest: form.is_guest,
    l2_isolation: form.l2_isolation,
    enabled: form.enabled,
  }
}

function netToForm(net: WirelessNetwork): WlanFormState {
  return {
    ssid: net.ssid,
    security: net.security,
    psk: '',
    hidden: net.hidden,
    band: net.band,
    vlan_id: net.vlan_id != null ? String(net.vlan_id) : '',
    is_guest: net.is_guest,
    l2_isolation: net.l2_isolation,
    enabled: net.enabled,
  }
}

export default function Wireless() {
  const [networks, setNetworks] = useState<WirelessNetwork[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [form, setForm] = useState<WlanFormState>({ ...emptyForm })
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getWirelessNetworks()
      setNetworks(res.networks ?? [])
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const openCreate = () => {
    setForm({ ...emptyForm })
    setEditId(null)
    setShowForm(true)
  }

  const openEdit = (net: WirelessNetwork) => {
    setForm(netToForm(net))
    setEditId(net.id)
    setShowForm(true)
  }

  const handleSave = async () => {
    if (!form.ssid.trim()) { toast.error('SSID is required'); return }
    if (form.ssid.length > 32) { toast.error('SSID must be 32 characters or less'); return }
    if (form.security !== 'open' && !editId && (!form.psk || form.psk.length < 8)) {
      toast.error('PSK must be at least 8 characters'); return
    }
    if (form.security !== 'open' && form.psk && form.psk.length > 63) {
      toast.error('PSK must be 63 characters or less'); return
    }
    try {
      if (editId) {
        await api.updateWirelessNetwork(editId, formToPayload(form))
        toast.success('Network updated')
      } else {
        await api.createWirelessNetwork(formToPayload(form))
        toast.success('Network created')
      }
      setShowForm(false)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.deleteWirelessNetwork(id)
      toast.success('Network deleted')
      setDeleteConfirm(null)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading wireless networks..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="WiFi"
        subtitle="Wireless networks broadcast by managed access points"
        actions={<Button onClick={openCreate}>+ Add Network</Button>}
      />

      {/* Create / Edit Modal */}
      <Modal open={showForm} onClose={() => setShowForm(false)} title={editId ? 'Edit Network' : 'New WiFi Network'} size="lg">
        <div className="space-y-5">
          <Input
            label="SSID"
            mono
            value={form.ssid}
            onChange={(e) => setForm({ ...form, ssid: e.target.value })}
            placeholder="MyNetwork"
          />

          <div>
            <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-2">Security</p>
            <div className="grid grid-cols-3 gap-2">
              {(['open', 'wpa2', 'wpa3'] as const).map((sec) => (
                <button
                  key={sec}
                  onClick={() => setForm({ ...form, security: sec, psk: sec === 'open' ? '' : form.psk })}
                  className={`p-3 rounded-lg border text-center transition-all ${
                    form.security === sec
                      ? 'bg-emerald-500/10 border-emerald-500/30'
                      : 'bg-navy-800/30 border-navy-700/30 hover:border-navy-600/50'
                  }`}
                >
                  <p className="text-sm font-medium text-gray-200">{securityLabel[sec]}</p>
                  <p className="text-[10px] text-navy-500 mt-0.5">
                    {sec === 'open' ? 'No encryption' : sec === 'wpa2' ? 'AES-CCMP' : 'SAE + PMF'}
                  </p>
                </button>
              ))}
            </div>
          </div>

          {form.security !== 'open' && (
            <Input
              label={`Pre-Shared Key${editId ? ' (leave empty to keep current)' : ''}`}
              type="password"
              mono
              value={form.psk}
              onChange={(e) => setForm({ ...form, psk: e.target.value })}
              placeholder="Min. 8 characters"
            />
          )}

          <div>
            <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-2">Band</p>
            <div className="grid grid-cols-3 gap-2">
              {(['both', '2g', '5g'] as const).map((b) => (
                <button
                  key={b}
                  onClick={() => setForm({ ...form, band: b })}
                  className={`p-3 rounded-lg border text-center transition-all ${
                    form.band === b
                      ? 'bg-emerald-500/10 border-emerald-500/30'
                      : 'bg-navy-800/30 border-navy-700/30 hover:border-navy-600/50'
                  }`}
                >
                  <p className="text-sm font-medium text-gray-200">{bandLabel[b]}</p>
                </button>
              ))}
            </div>
          </div>

          <Select
            label="VLAN"
            value={form.vlan_id}
            onChange={(e) => {
              const vid = e.target.value
              const isGuest = vid === '3002'
              setForm({
                ...form,
                vlan_id: vid,
                is_guest: isGuest || form.is_guest,
                l2_isolation: isGuest || form.l2_isolation,
              })
            }}
            options={VLAN_OPTIONS}
          />

          <div className="border-t border-navy-800/30 pt-4 space-y-3">
            <Toggle checked={form.hidden} onChange={(v) => setForm({ ...form, hidden: v })} label="Hidden SSID" />
            <Toggle checked={form.is_guest} onChange={(v) => setForm({ ...form, is_guest: v })} label="Guest Network" />
            <Toggle checked={form.l2_isolation} onChange={(v) => setForm({ ...form, l2_isolation: v })} label="Client Isolation (L2)" />
            <Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} label="Enabled" />
          </div>

          <div className="flex gap-2 pt-2">
            <Button onClick={handleSave}>{editId ? 'Update' : 'Create Network'}</Button>
            <Button variant="secondary" onClick={() => setShowForm(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Delete confirmation */}
      {deleteConfirm !== null && (
        <Modal open onClose={() => setDeleteConfirm(null)} title="Delete Network">
          <p className="text-sm text-gray-300 mb-4">
            Are you sure you want to delete this wireless network? Connected clients will be disconnected on next AP config push.
          </p>
          <div className="flex gap-2">
            <Button variant="danger" onClick={() => handleDelete(deleteConfirm)}>Delete</Button>
            <Button variant="secondary" onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          </div>
        </Modal>
      )}

      {/* Network list */}
      {networks.length === 0 ? (
        <EmptyState
          icon={<svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M5 12.55a11 11 0 0114 0" /><path d="M1.42 9a16 16 0 0121.16 0" /><path d="M8.53 16.11a6 6 0 016.95 0" /><circle cx="12" cy="20" r="1" fill="currentColor" /></svg>}
          title="No wireless networks configured"
          description="Add a WiFi network to broadcast via managed access points."
        />
      ) : (
        <div className="space-y-3 stagger-children">
          {networks.map((net) => (
            <Card key={net.id} noPadding>
              <div className="flex items-center justify-between px-5 py-4">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-navy-800/80 flex items-center justify-center">
                    <svg className={`w-5 h-5 ${net.enabled ? 'text-emerald-400' : 'text-navy-500'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M5 12.55a11 11 0 0114 0" /><path d="M1.42 9a16 16 0 0121.16 0" /><path d="M8.53 16.11a6 6 0 016.95 0" /><circle cx="12" cy="20" r="1" fill="currentColor" />
                    </svg>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-gray-200">{net.ssid}</span>
                      {net.hidden && <Badge variant="neutral">Hidden</Badge>}
                      {net.is_guest && <Badge variant="warning">Guest</Badge>}
                      {!net.enabled && <Badge variant="neutral">Disabled</Badge>}
                    </div>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-[11px] text-navy-400 font-mono">{securityLabel[net.security]}</span>
                      <span className="text-[11px] text-navy-500">{bandLabel[net.band]}</span>
                      {net.vlan_id != null && <span className="text-[11px] text-navy-500 font-mono">{pvidToZone(net.vlan_id).toUpperCase()} (VLAN {net.vlan_id})</span>}
                      {net.l2_isolation && <span className="text-[11px] text-navy-500">L2 Isolated</span>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="secondary" size="sm" onClick={() => openEdit(net)}>Edit</Button>
                  <Button variant="danger" size="sm" onClick={() => setDeleteConfirm(net.id)}>Delete</Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
