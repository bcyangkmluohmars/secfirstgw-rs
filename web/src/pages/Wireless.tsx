// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, pvidToZone, type WirelessNetwork, type WirelessNetworkCreate, type WirelessBandwidthMode } from '../api'
import { PageHeader, Card, Button, Badge, Toggle, Modal, Input, Select, EmptyState, Spinner } from '../components/ui'
import { useToast } from '../hooks/useToast'

type Security = 'open' | 'wpa2' | 'wpa3'
type Band = 'both' | '2g' | '5g'

const MAX_VAPS_PER_RADIO = 4

/** Compute VAP device names for a network based on its band and position. */
function getVapDevnames(band: Band, vap2gIdx: number, vap5gIdx: number): { vap2g: string | null; vap5g: string | null } {
  const vap2g = (band === 'both' || band === '2g') && vap2gIdx < MAX_VAPS_PER_RADIO ? `ath${vap2gIdx}` : null
  const vap5g = (band === 'both' || band === '5g') && vap5gIdx < MAX_VAPS_PER_RADIO ? `ath1${vap5gIdx}` : null
  return { vap2g, vap5g }
}

/** Count how many VAPs are used per radio for a list of networks. */
function countVapsPerRadio(networks: { band: Band }[]): { count2g: number; count5g: number } {
  let count2g = 0, count5g = 0
  for (const net of networks) {
    if (net.band === 'both' || net.band === '2g') count2g++
    if (net.band === 'both' || net.band === '5g') count5g++
  }
  return { count2g, count5g }
}

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
  channel: string
  tx_power: string
  bandwidth: WirelessBandwidthMode
  fast_roaming: boolean
  band_steering: boolean
}

const emptyForm: WlanFormState = {
  ssid: '', security: 'wpa2', psk: '', hidden: false,
  band: 'both', vlan_id: '', is_guest: false, l2_isolation: false, enabled: true,
  channel: '0', tx_power: '0', bandwidth: 'auto', fast_roaming: false, band_steering: false,
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

const BANDWIDTH_OPTIONS: { value: WirelessBandwidthMode; label: string }[] = [
  { value: 'auto', label: 'Auto' },
  { value: 'HT20', label: 'HT20 (20 MHz)' },
  { value: 'HT40', label: 'HT40 (40 MHz)' },
  { value: 'VHT80', label: 'VHT80 (80 MHz)' },
]

// Valid channels per band
const CHANNELS_2G = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
const CHANNELS_5G = [0, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]

function getChannelOptions(band: Band): { value: string; label: string }[] {
  const opts: { value: string; label: string }[] = [{ value: '0', label: 'Auto' }]
  if (band === '2g' || band === 'both') {
    for (const ch of CHANNELS_2G) {
      if (ch === 0) continue
      opts.push({ value: String(ch), label: `Ch ${ch} (2.4 GHz)` })
    }
  }
  if (band === '5g' || band === 'both') {
    for (const ch of CHANNELS_5G) {
      if (ch === 0) continue
      opts.push({ value: String(ch), label: `Ch ${ch} (5 GHz)` })
    }
  }
  return opts
}

function getBandwidthOptions(band: Band): { value: WirelessBandwidthMode; label: string }[] {
  if (band === '2g') {
    // No VHT80 on 2.4 GHz
    return BANDWIDTH_OPTIONS.filter(o => o.value !== 'VHT80')
  }
  return BANDWIDTH_OPTIONS
}

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
    channel: Number(form.channel) || 0,
    tx_power: Number(form.tx_power) || 0,
    bandwidth: form.bandwidth,
    fast_roaming: form.fast_roaming,
    band_steering: form.band_steering,
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
    channel: String(net.channel),
    tx_power: String(net.tx_power),
    bandwidth: net.bandwidth,
    fast_roaming: net.fast_roaming,
    band_steering: net.band_steering,
  }
}

const bandwidthLabel: Record<WirelessBandwidthMode, string> = {
  auto: 'Auto', HT20: '20 MHz', HT40: '40 MHz', VHT80: '80 MHz',
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
    const txp = Number(form.tx_power) || 0
    if (txp < 0 || txp > 30) {
      toast.error('TX power must be 0 (auto) or 1-30 dBm'); return
    }
    if (form.bandwidth === 'VHT80' && form.band === '2g') {
      toast.error('VHT80 is not supported on 2.4 GHz'); return
    }
    if (form.band_steering && form.band !== 'both') {
      toast.error('Band steering requires dual-band (both) mode'); return
    }
    // Client-side VAP limit check
    {
      const otherNets = editId
        ? networks.filter(n => n.id !== editId)
        : networks
      const { count2g, count5g } = countVapsPerRadio(otherNets)
      const add2g = form.band === 'both' || form.band === '2g'
      const add5g = form.band === 'both' || form.band === '5g'
      if (add2g && count2g >= MAX_VAPS_PER_RADIO) {
        toast.error(`2.4 GHz radio at capacity (${MAX_VAPS_PER_RADIO} VAPs max)`); return
      }
      if (add5g && count5g >= MAX_VAPS_PER_RADIO) {
        toast.error(`5 GHz radio at capacity (${MAX_VAPS_PER_RADIO} VAPs max)`); return
      }
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
                  onClick={() => {
                    const updates: Partial<WlanFormState> = { band: b }
                    // Reset bandwidth if VHT80 on 2.4GHz
                    if (b === '2g' && form.bandwidth === 'VHT80') updates.bandwidth = 'auto'
                    // Disable band steering if not dual-band
                    if (b !== 'both') updates.band_steering = false
                    // Reset channel if invalid for new band
                    const ch = Number(form.channel) || 0
                    if (ch !== 0) {
                      const valid2g = CHANNELS_2G.includes(ch)
                      const valid5g = CHANNELS_5G.includes(ch)
                      if (b === '2g' && !valid2g) updates.channel = '0'
                      if (b === '5g' && !valid5g) updates.channel = '0'
                    }
                    setForm({ ...form, ...updates })
                  }}
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

          {/* Advanced Radio Settings */}
          <div className="border-t border-navy-800/30 pt-4">
            <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-3">Radio Settings</p>
            <div className="grid grid-cols-2 gap-4">
              <Select
                label="Channel"
                value={form.channel}
                onChange={(e) => setForm({ ...form, channel: e.target.value })}
                options={getChannelOptions(form.band)}
              />
              <div>
                <label className="block">
                  <span className="block text-[11px] font-medium text-navy-400 mb-1.5">TX Power</span>
                  <div className="flex items-center gap-3">
                    <input
                      type="range"
                      min={0}
                      max={30}
                      step={1}
                      value={Number(form.tx_power) || 0}
                      onChange={(e) => setForm({ ...form, tx_power: e.target.value })}
                      className="flex-1 accent-emerald-500 h-2 bg-navy-700 rounded-lg cursor-pointer"
                    />
                    <span className="text-sm text-gray-300 font-mono w-16 text-right">
                      {Number(form.tx_power) === 0 ? 'Auto' : `${form.tx_power} dBm`}
                    </span>
                  </div>
                </label>
              </div>
              <Select
                label="Bandwidth"
                value={form.bandwidth}
                onChange={(e) => setForm({ ...form, bandwidth: e.target.value as WirelessBandwidthMode })}
                options={getBandwidthOptions(form.band).map(o => ({ value: o.value, label: o.label }))}
              />
            </div>
          </div>

          <div className="border-t border-navy-800/30 pt-4 space-y-3">
            <Toggle checked={form.hidden} onChange={(v) => setForm({ ...form, hidden: v })} label="Hidden SSID" />
            <Toggle checked={form.is_guest} onChange={(v) => setForm({ ...form, is_guest: v })} label="Guest Network" />
            <Toggle checked={form.l2_isolation} onChange={(v) => setForm({ ...form, l2_isolation: v })} label="Client Isolation (L2)" />
            <Toggle
              checked={form.fast_roaming}
              onChange={(v) => setForm({ ...form, fast_roaming: v })}
              label="Fast Roaming (802.11r)"
            />
            <Toggle
              checked={form.band_steering}
              onChange={(v) => setForm({ ...form, band_steering: v })}
              label="Band Steering (prefer 5 GHz)"
              disabled={form.band !== 'both'}
            />
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

      {/* VAP capacity indicator */}
      {networks.length > 0 && (() => {
        const { count2g, count5g } = countVapsPerRadio(networks)
        const warn2g = count2g >= MAX_VAPS_PER_RADIO
        const warn5g = count5g >= MAX_VAPS_PER_RADIO
        return (
          <Card noPadding>
            <div className="px-5 py-3 flex items-center gap-6">
              <span className="text-[11px] text-navy-400 uppercase tracking-wider font-medium">VAP Slots</span>
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-navy-500">2.4 GHz:</span>
                <span className={`text-[11px] font-mono ${warn2g ? 'text-amber-400' : 'text-gray-300'}`}>
                  {count2g}/{MAX_VAPS_PER_RADIO}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-navy-500">5 GHz:</span>
                <span className={`text-[11px] font-mono ${warn5g ? 'text-amber-400' : 'text-gray-300'}`}>
                  {count5g}/{MAX_VAPS_PER_RADIO}
                </span>
              </div>
              {(warn2g || warn5g) && (
                <span className="text-[11px] text-amber-400">
                  {warn2g && warn5g ? 'Both radios at capacity' : warn2g ? '2.4 GHz radio at capacity' : '5 GHz radio at capacity'}
                </span>
              )}
            </div>
          </Card>
        )
      })()}

      {/* Network list */}
      {networks.length === 0 ? (
        <EmptyState
          icon={<svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M5 12.55a11 11 0 0114 0" /><path d="M1.42 9a16 16 0 0121.16 0" /><path d="M8.53 16.11a6 6 0 016.95 0" /><circle cx="12" cy="20" r="1" fill="currentColor" /></svg>}
          title="No wireless networks configured"
          description="Add a WiFi network to broadcast via managed access points."
        />
      ) : (
        <div className="space-y-3 stagger-children">
          {(() => {
            // Track VAP indices for display
            let vapIdx2g = 0, vapIdx5g = 0
            return networks.map((net) => {
              const { vap2g, vap5g } = getVapDevnames(net.band, vapIdx2g, vapIdx5g)
              if (net.band === 'both' || net.band === '2g') vapIdx2g++
              if (net.band === 'both' || net.band === '5g') vapIdx5g++
              return (
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
                      {net.fast_roaming && <Badge variant="info">802.11r</Badge>}
                      {net.band_steering && <Badge variant="info">Band Steer</Badge>}
                    </div>
                    <div className="flex items-center gap-3 mt-1 flex-wrap">
                      <span className="text-[11px] text-navy-400 font-mono">{securityLabel[net.security]}</span>
                      <span className="text-[11px] text-navy-500">{bandLabel[net.band]}</span>
                      {/* VAP interface names */}
                      {vap2g && <span className="text-[11px] text-emerald-500/70 font-mono">{vap2g}</span>}
                      {vap5g && <span className="text-[11px] text-blue-400/70 font-mono">{vap5g}</span>}
                      {net.vlan_id != null && <span className="text-[11px] text-navy-500 font-mono">{pvidToZone(net.vlan_id).toUpperCase()} (VLAN {net.vlan_id})</span>}
                      {net.l2_isolation && <span className="text-[11px] text-navy-500">L2 Isolated</span>}
                      <span className="text-[11px] text-navy-500 font-mono">
                        Ch {net.channel === 0 ? 'Auto' : net.channel}
                      </span>
                      <span className="text-[11px] text-navy-500 font-mono">
                        TX {net.tx_power === 0 ? 'Auto' : `${net.tx_power} dBm`}
                      </span>
                      <span className="text-[11px] text-navy-500 font-mono">
                        BW {bandwidthLabel[net.bandwidth]}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="secondary" size="sm" onClick={() => openEdit(net)}>Edit</Button>
                  <Button variant="danger" size="sm" onClick={() => setDeleteConfirm(net.id)}>Delete</Button>
                </div>
              </div>
            </Card>
              )
            })
          })()}
        </div>
      )}
    </div>
  )
}
