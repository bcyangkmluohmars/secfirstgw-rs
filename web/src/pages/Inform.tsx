// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback, useRef } from 'react'
import { api, type UbntDevice, type UbntDeviceState, type SwitchPortConfig, type SwitchConfig, type SwitchPortStats, type DeviceStats } from '../api'
import { PageHeader, Spinner, Button, Badge, Tabs, EmptyState, Toggle, ConfirmDialog } from '../components/ui'
import { useToast } from '../hooks/useToast'

const POLL_INTERVAL = 5_000

const stateVariant = (s: UbntDeviceState) => {
  switch (s) {
    case 'pending': return 'warning' as const
    case 'adopting': return 'info' as const
    case 'adopted': return 'success' as const
    case 'ignored': return 'neutral' as const
    case 'phantom': return 'danger' as const
  }
}

const stateLabel = (s: UbntDeviceState) => {
  switch (s) {
    case 'pending': return 'Pending'
    case 'adopting': return 'Adopting'
    case 'adopted': return 'Adopted'
    case 'ignored': return 'Ignored'
    case 'phantom': return 'Phantom'
  }
}

// VLAN → zone color mapping
const VLAN_COLORS: Record<number, { bg: string; border: string; text: string; label: string }> = {
  1: { bg: 'bg-navy-700/50', border: 'border-navy-600', text: 'text-navy-300', label: 'Default' },
  10: { bg: 'bg-blue-500/10', border: 'border-blue-500/50', text: 'text-blue-400', label: 'LAN' },
  3000: { bg: 'bg-purple-500/10', border: 'border-purple-500/50', text: 'text-purple-400', label: 'MGMT' },
  3001: { bg: 'bg-amber-500/10', border: 'border-amber-500/50', text: 'text-amber-400', label: 'DMZ' },
  3002: { bg: 'bg-teal-500/10', border: 'border-teal-500/50', text: 'text-teal-400', label: 'Guest' },
}

function vlanColor(pvid: number) {
  return VLAN_COLORS[pvid] ?? { bg: 'bg-gray-500/10', border: 'border-gray-500/50', text: 'text-gray-400', label: `VLAN ${pvid}` }
}

type TabKey = 'pending' | 'adopted' | 'ignored' | 'phantom' | 'all'

interface ConfirmAction {
  type: 'adopt' | 'remove'
  mac: string
  model: string
}

export default function Inform() {
  const [enabled, setEnabled] = useState(false)
  const [devices, setDevices] = useState<UbntDevice[]>([])
  const [loading, setLoading] = useState(true)
  const [toggling, setToggling] = useState(false)
  const [tab, setTab] = useState<TabKey>('pending')
  const [expandedMac, setExpandedMac] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<ConfirmAction | null>(null)
  const toast = useToast()
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const load = useCallback(async () => {
    try {
      const [settingsRes, devicesRes] = await Promise.all([
        api.getInformSettings(),
        api.getInformDevices(),
      ])
      setEnabled(settingsRes.ubiquiti_inform_enabled)
      setDevices(devicesRes.devices)
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!enabled || loading) return
    pollRef.current = setInterval(() => {
      api.getInformDevices()
        .then(res => setDevices(res.devices))
        .catch(() => {})
    }, POLL_INTERVAL)
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [enabled, loading])

  const handleToggle = async (val: boolean) => {
    setToggling(true)
    try {
      const res = await api.setInformSettings(val)
      setEnabled(res.ubiquiti_inform_enabled)
      toast.success(`Ubiquiti Inform ${val ? 'enabled' : 'disabled'}`)
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setToggling(false)
    }
  }

  const handleAdopt = async (mac: string) => {
    try {
      await api.adoptInformDevice(mac)
      toast.success(`Adoption initiated for ${mac}`)
      load()
    } catch (e: unknown) {
      toast.error((e as Error).message)
    }
  }

  const handleIgnore = async (mac: string) => {
    try {
      await api.ignoreInformDevice(mac)
      toast.success(`Device ${mac} ignored`)
      load()
    } catch (e: unknown) {
      toast.error((e as Error).message)
    }
  }

  const handleRemove = async (mac: string) => {
    try {
      await api.removeInformDevice(mac)
      toast.success(`Device ${mac} removed`)
      load()
    } catch (e: unknown) {
      toast.error((e as Error).message)
    }
  }

  const handleConfirm = () => {
    if (!confirm) return
    if (confirm.type === 'adopt') handleAdopt(confirm.mac)
    else if (confirm.type === 'remove') handleRemove(confirm.mac)
  }

  if (loading) return <Spinner label="Loading Inform settings..." />

  const byState = (s: UbntDeviceState) => devices.filter(d => d.state === s)
  const pendingDevices = byState('pending')
  const adoptedDevices = byState('adopted')
  const ignoredDevices = byState('ignored')
  const phantomDevices = byState('phantom')
  const adoptingDevices = byState('adopting')

  const tabDevices: Record<TabKey, UbntDevice[]> = {
    pending: [...pendingDevices, ...adoptingDevices],
    adopted: adoptedDevices,
    ignored: ignoredDevices,
    phantom: phantomDevices,
    all: devices,
  }

  const currentList = tabDevices[tab]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Ubiquiti Inform"
        subtitle={
          <span className="text-xs text-navy-400">
            Discover and adopt UniFi devices via TNBU protocol
          </span>
        }
      />

      <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-200">Inform Protocol</h3>
            <p className="text-xs text-navy-400 mt-1">
              {enabled
                ? 'Listening on port 8080 (MGMT interface). DNS overrides active for unifi / unifi.lan.'
                : 'Disabled. Enable to start listening for UniFi device discovery on MGMT network.'}
            </p>
          </div>
          <Toggle checked={enabled} onChange={handleToggle} disabled={toggling} />
        </div>
      </div>

      <ConfirmDialog
        open={confirm?.type === 'adopt'}
        onClose={() => setConfirm(null)}
        onConfirm={handleConfirm}
        title="Adopt Device"
        message={`Adopt ${confirm?.model ?? 'device'} (${confirm?.mac ?? ''})? This will SSH to the device, verify its hardware fingerprint, and provision per-device credentials.`}
        confirmLabel="Adopt"
      />
      <ConfirmDialog
        open={confirm?.type === 'remove'}
        onClose={() => setConfirm(null)}
        onConfirm={handleConfirm}
        title="Remove Device"
        message={`Remove ${confirm?.model ?? 'device'} (${confirm?.mac ?? ''}) from the database? This cannot be undone.`}
        confirmLabel="Remove"
        variant="danger"
      />

      {enabled && (
        <>
          <Tabs
            tabs={[
              { key: 'pending', label: 'Pending', count: pendingDevices.length + adoptingDevices.length },
              { key: 'adopted', label: 'Adopted', count: adoptedDevices.length },
              { key: 'ignored', label: 'Ignored', count: ignoredDevices.length },
              { key: 'phantom', label: 'Phantom', count: phantomDevices.length },
              { key: 'all', label: 'All', count: devices.length },
            ]}
            active={tab}
            onChange={(k) => setTab(k as TabKey)}
          />

          {currentList.length === 0 ? (
            <EmptyState
              icon={
                <svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2v-4M9 21H5a2 2 0 01-2-2v-4m0-6v6" />
                </svg>
              }
              title={tab === 'phantom' ? 'No phantom devices detected' : `No ${tab} devices`}
              description={
                tab === 'pending'
                  ? 'UniFi devices on the MGMT network will appear here when they send Inform packets.'
                  : tab === 'phantom'
                    ? 'Phantom devices are logged when passive validation fails.'
                    : `No devices in "${tab}" state.`
              }
            />
          ) : (
            <div className="space-y-3">
              {currentList.map(d => (
                <DeviceCard
                  key={d.mac}
                  device={d}
                  expanded={expandedMac === d.mac}
                  onToggleExpand={() => setExpandedMac(expandedMac === d.mac ? null : d.mac)}
                  onAdopt={() => setConfirm({ type: 'adopt', mac: d.mac, model: d.model_display || d.model })}
                  onIgnore={() => handleIgnore(d.mac)}
                  onRemove={() => setConfirm({ type: 'remove', mac: d.mac, model: d.model_display || d.model })}
                  onPortConfigSaved={load}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function DeviceCard({ device: d, expanded, onToggleExpand, onAdopt, onIgnore, onRemove, onPortConfigSaved }: {
  device: UbntDevice
  expanded: boolean
  onToggleExpand: () => void
  onAdopt: () => void
  onIgnore: () => void
  onRemove: () => void
  onPortConfigSaved: () => void
}) {
  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
      {/* Header row */}
      <div
        className="flex items-center gap-4 px-5 py-3.5 cursor-pointer hover:bg-navy-800/20 transition-colors"
        onClick={onToggleExpand}
      >
        <svg className={`w-4 h-4 text-navy-400 transition-transform ${expanded ? 'rotate-90' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M9 5l7 7-7 7" />
        </svg>
        <Badge variant={stateVariant(d.state)}>{stateLabel(d.state)}</Badge>
        <span className="text-gray-200 text-sm font-medium">{d.model_display || d.model}</span>
        <span className="font-mono text-gray-400 text-xs">{d.mac}</span>
        <span className="font-mono text-gray-400 text-xs tabular-nums">{d.source_ip}</span>
        {d.hostname && <span className="text-gray-500 text-xs">{d.hostname}</span>}
        <span className="text-navy-500 text-xs ml-auto">{new Date(d.last_seen).toLocaleString()}</span>
        <div className="flex gap-2" onClick={e => e.stopPropagation()}>
          {d.state === 'pending' && (
            <>
              <Button size="sm" onClick={onAdopt}>Adopt</Button>
              <Button size="sm" variant="secondary" onClick={onIgnore}>Ignore</Button>
            </>
          )}
          {d.state === 'ignored' && (
            <Button size="sm" onClick={onAdopt}>Adopt</Button>
          )}
          {d.state === 'adopted' && !d.config_applied && (
            <span className="text-xs text-amber-400 self-center">Config pending</span>
          )}
          {d.state === 'adopted' && d.config_applied && (
            <span className="text-xs text-emerald-400 self-center">Active</span>
          )}
          {d.state === 'adopting' && (
            <>
              <span className="text-xs text-amber-400 animate-pulse self-center">Verifying...</span>
              <Button size="sm" variant="secondary" onClick={onAdopt}>Retry</Button>
            </>
          )}
          <Button size="sm" variant="danger" onClick={onRemove}>Remove</Button>
        </div>
      </div>

      {/* Expanded panel */}
      {expanded && (
        <div className="border-t border-navy-800/50 px-5 py-4 space-y-5">
          {/* Device info grid */}
          <div className="grid grid-cols-3 gap-3 text-sm">
            <Detail label="Model" value={`${d.model_display} (${d.model})`} />
            <Detail label="Firmware" value={d.firmware_version} />
            <Detail label="Hostname" value={d.hostname || '---'} />
            <Detail label="Source IP" value={d.source_ip} />
            <Detail label="Claimed IP" value={d.claimed_ip} />
            <Detail label="First Seen" value={new Date(d.first_seen).toLocaleString()} />
          </div>

          {/* Validation */}
          <div className="flex items-center gap-3">
            <span className="text-xs text-navy-400 uppercase tracking-wider">Validation</span>
            <ValidationBadge label="OUI" ok={d.validation.oui_valid} />
            <ValidationBadge label="IP Match" ok={d.validation.ip_matches} />
            <ValidationBadge label="Model" ok={d.validation.model_known} />
            {d.validation.reason && <span className="text-xs text-red-400 ml-2">{d.validation.reason}</span>}
          </div>

          {/* Hardware fingerprint */}
          {d.fingerprint && (
            <div>
              <h4 className="text-xs text-navy-400 uppercase tracking-wider mb-2">Hardware Fingerprint</h4>
              <div className="grid grid-cols-4 gap-2 text-xs">
                <Detail label="Serial" value={d.fingerprint.serialno} />
                <Detail label="CPU ID" value={d.fingerprint.cpuid} />
                <Detail label="System ID" value={d.fingerprint.systemid} />
                <Detail label="Board Rev" value={d.fingerprint.boardrevision} />
              </div>
            </div>
          )}

          {/* Stats + Visual Switch */}
          {d.stats && <DeviceStatsView stats={d.stats} />}

          {/* Port config (adopted switches only) */}
          {d.state === 'adopted' && d.stats && d.stats.port_table.length > 0 && (
            <SwitchPortEditor device={d} onSaved={onPortConfigSaved} />
          )}
        </div>
      )}
    </div>
  )
}

// Visual switch port representation + editor
function SwitchPortEditor({ device, onSaved }: { device: UbntDevice; onSaved: () => void }) {
  const [editing, setEditing] = useState(false)
  const [selectedPort, setSelectedPort] = useState<number | null>(null)
  const [config, setConfig] = useState<SwitchConfig | null>(null)
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)
  const toast = useToast()

  const stats = device.stats!

  // Initialize config from device or generate defaults
  useEffect(() => {
    if (device.port_config) {
      setConfig(device.port_config)
    } else {
      // Generate default config from port count
      setConfig({
        ports: stats.port_table.map(p => ({
          port_idx: p.port_idx,
          name: '',
          enabled: true,
          pvid: 1,
          poe_mode: p.port_poe ? 'auto' : 'off',
          egress_mode: 'untagged',
          tagged_vlans: [],
          isolation: false,
          egress_rate_limit_kbps: 0,
        }))
      })
    }
  }, [device.port_config, stats.port_table])

  const portConfig = (idx: number): SwitchPortConfig | undefined =>
    config?.ports.find(p => p.port_idx === idx)

  const portStats = (idx: number): SwitchPortStats | undefined =>
    stats.port_table.find(p => p.port_idx === idx)

  const updatePort = (idx: number, patch: Partial<SwitchPortConfig>) => {
    if (!config) return
    setConfig({
      ports: config.ports.map(p => p.port_idx === idx ? { ...p, ...patch } : p)
    })
    setDirty(true)
  }

  const handleSave = async () => {
    if (!config) return
    setSaving(true)
    try {
      await api.setInformDevicePorts(device.mac, config)
      toast.success('Port configuration saved')
      setDirty(false)
      setEditing(false)
      onSaved()
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const sel = selectedPort != null ? portConfig(selectedPort) : null
  const selStats = selectedPort != null ? portStats(selectedPort) : null

  return (
    <div className="border-t border-navy-800/50 pt-4">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-xs text-navy-400 uppercase tracking-wider">Switch Ports</h4>
        <div className="flex gap-2">
          {editing && dirty && (
            <Button size="sm" onClick={handleSave} disabled={saving}>
              {saving ? 'Saving...' : 'Save Config'}
            </Button>
          )}
          <Button size="sm" variant="secondary" onClick={() => { setEditing(!editing); setSelectedPort(null) }}>
            {editing ? 'Cancel' : 'Configure'}
          </Button>
        </div>
      </div>

      {/* Visual switch body */}
      <div className="bg-navy-950 border border-navy-800 rounded-lg p-4">
        {/* Switch chassis */}
        <div className="flex items-center gap-1 justify-center">
          {stats.port_table.map(p => {
            const pc = portConfig(p.port_idx)
            const vc = vlanColor(pc?.pvid ?? 1)
            const isSelected = selectedPort === p.port_idx
            const isDisabled = pc && !pc.enabled

            return (
              <button
                key={p.port_idx}
                onClick={() => setSelectedPort(isSelected ? null : p.port_idx)}
                className={`
                  relative flex flex-col items-center justify-center
                  w-16 h-20 rounded border-2 transition-all
                  ${isSelected ? 'border-cyan-400 shadow-lg shadow-cyan-500/20' : vc.border}
                  ${isDisabled ? 'opacity-40' : ''}
                  ${vc.bg} hover:brightness-125
                `}
              >
                {/* Link LED */}
                <div className={`absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full ${
                  p.up ? 'bg-emerald-400 shadow-sm shadow-emerald-400/50' : 'bg-navy-600'
                }`} />

                {/* Port number */}
                <span className="text-lg font-bold text-gray-200">{p.port_idx}</span>

                {/* Speed indicator */}
                <span className="text-[9px] text-gray-400 tabular-nums">
                  {p.up ? (p.speed >= 1000 ? `${p.speed / 1000}G` : `${p.speed}M`) : 'Down'}
                </span>

                {/* Zone/VLAN tag */}
                <span className={`text-[8px] font-medium ${vc.text}`}>
                  {vc.label}
                </span>

                {/* PoE indicator */}
                {p.port_poe && p.poe_good && (
                  <div className="absolute bottom-1 left-1">
                    <svg className="w-2.5 h-2.5 text-amber-400" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                    </svg>
                  </div>
                )}

                {/* Uplink marker */}
                {p.is_uplink && (
                  <div className="absolute top-1.5 left-1.5">
                    <svg className="w-2.5 h-2.5 text-navy-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path d="M12 19V5M5 12l7-7 7 7" />
                    </svg>
                  </div>
                )}

                {/* Port name */}
                {pc?.name && (
                  <span className="absolute -bottom-4 text-[8px] text-navy-400 truncate max-w-16">{pc.name}</span>
                )}
              </button>
            )
          })}
        </div>

        {/* Model label */}
        <div className="text-center mt-5 text-xs text-navy-500">
          {device.model_display}
          {stats.power_source_voltage && <span className="ml-2 text-navy-600">PoE {stats.power_source_voltage}V</span>}
        </div>
      </div>

      {/* Selected port detail / editor */}
      {selectedPort != null && sel && selStats && (
        <div className="mt-3 bg-navy-950/50 border border-navy-800/50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h5 className="text-sm text-gray-200 font-medium">
              Port {sel.port_idx}
              {sel.name && <span className="text-navy-400 ml-2">({sel.name})</span>}
              {selStats.is_uplink && <span className="text-navy-400 ml-2">(uplink)</span>}
            </h5>
            <div className="flex items-center gap-3">
              <span className={`inline-block w-2 h-2 rounded-full ${selStats.up ? 'bg-emerald-400' : 'bg-navy-600'}`} />
              <span className="text-xs text-gray-300">{selStats.up ? `${selStats.speed >= 1000 ? `${selStats.speed / 1000}G` : `${selStats.speed}M`} ${selStats.full_duplex ? 'Full Duplex' : 'Half Duplex'}` : 'Down'}</span>
            </div>
          </div>

          {/* Traffic stats */}
          <div className="grid grid-cols-4 gap-3 mb-3">
            <StatCard label="RX" value={fmtBytes(selStats.rx_bytes)} sub={`${selStats.rx_packets.toLocaleString()} pkts`} />
            <StatCard label="TX" value={fmtBytes(selStats.tx_bytes)} sub={`${selStats.tx_packets.toLocaleString()} pkts`} />
            <StatCard label="Errors" value={`${selStats.rx_errors + selStats.tx_errors}`} sub={`RX ${selStats.rx_errors} / TX ${selStats.tx_errors}`} />
            <StatCard label="MACs" value={`${selStats.mac_table.length}`} sub={selStats.mac_table.length > 0 ? selStats.mac_table.map(m => m.mac).slice(0, 3).join(', ') : undefined} />
          </div>

          {/* PoE stats */}
          {selStats.port_poe && (
            <div className="grid grid-cols-4 gap-3 mb-3">
              <StatCard label="PoE" value={selStats.poe_good ? 'Active' : (selStats.poe_enable ? 'No Device' : 'Off')} />
              {selStats.poe_power && <StatCard label="Power" value={`${selStats.poe_power}W`} />}
              {selStats.poe_voltage && <StatCard label="Voltage" value={`${selStats.poe_voltage}V`} />}
              {selStats.poe_current && <StatCard label="Current" value={`${selStats.poe_current}mA`} />}
            </div>
          )}

          {/* Port config editor */}
          {editing && (
            <div className="border-t border-navy-800/30 pt-3 mt-3 space-y-3">
              <div className="grid grid-cols-2 gap-4">
                {/* Port name */}
                <div>
                  <label className="text-[10px] text-navy-400 uppercase block mb-1">Name</label>
                  <input
                    type="text"
                    value={sel.name}
                    onChange={e => updatePort(sel.port_idx, { name: e.target.value })}
                    placeholder="e.g. Office AP"
                    className="w-full bg-navy-800 border border-navy-700 rounded px-2.5 py-1.5 text-sm text-gray-200 placeholder-navy-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                {/* PVID / Zone */}
                <div>
                  <label className="text-[10px] text-navy-400 uppercase block mb-1">Zone (PVID)</label>
                  <select
                    value={sel.pvid}
                    onChange={e => updatePort(sel.port_idx, { pvid: Number(e.target.value) })}
                    className="w-full bg-navy-800 border border-navy-700 rounded px-2.5 py-1.5 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                  >
                    <option value={1}>Default (VLAN 1)</option>
                    <option value={10}>LAN (VLAN 10)</option>
                    <option value={3000}>MGMT (VLAN 3000)</option>
                    <option value={3001}>DMZ (VLAN 3001)</option>
                    <option value={3002}>Guest (VLAN 3002)</option>
                  </select>
                </div>

                {/* PoE mode */}
                {selStats.port_poe && (
                  <div>
                    <label className="text-[10px] text-navy-400 uppercase block mb-1">PoE Mode</label>
                    <select
                      value={sel.poe_mode}
                      onChange={e => updatePort(sel.port_idx, { poe_mode: e.target.value })}
                      className="w-full bg-navy-800 border border-navy-700 rounded px-2.5 py-1.5 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none"
                    >
                      <option value="auto">Auto</option>
                      <option value="off">Off</option>
                      <option value="passthrough">Passthrough</option>
                    </select>
                  </div>
                )}

                {/* Port enabled */}
                <div className="flex items-center gap-3">
                  <label className="text-[10px] text-navy-400 uppercase">Enabled</label>
                  <button
                    onClick={() => updatePort(sel.port_idx, { enabled: !sel.enabled })}
                    className={`relative w-10 h-5 rounded-full transition-colors ${sel.enabled ? 'bg-cyan-500' : 'bg-navy-700'}`}
                  >
                    <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${sel.enabled ? 'translate-x-5' : ''}`} />
                  </button>
                </div>

                {/* Port isolation */}
                <div className="flex items-center gap-3">
                  <label className="text-[10px] text-navy-400 uppercase">Isolation</label>
                  <button
                    onClick={() => updatePort(sel.port_idx, { isolation: !sel.isolation })}
                    className={`relative w-10 h-5 rounded-full transition-colors ${sel.isolation ? 'bg-amber-500' : 'bg-navy-700'}`}
                  >
                    <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${sel.isolation ? 'translate-x-5' : ''}`} />
                  </button>
                </div>

                {/* Rate limit */}
                <div>
                  <label className="text-[10px] text-navy-400 uppercase block mb-1">Egress Limit (Kbps)</label>
                  <input
                    type="number"
                    value={sel.egress_rate_limit_kbps}
                    onChange={e => updatePort(sel.port_idx, { egress_rate_limit_kbps: Math.max(0, Number(e.target.value)) })}
                    placeholder="0 = unlimited"
                    className="w-full bg-navy-800 border border-navy-700 rounded px-2.5 py-1.5 text-sm text-gray-200 placeholder-navy-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function DeviceStatsView({ stats }: { stats: DeviceStats }) {
  return (
    <>
      <div className="border-t border-navy-800/50 pt-3">
        <h4 className="text-xs text-navy-400 uppercase tracking-wider mb-2">System</h4>
        <div className="grid grid-cols-4 gap-3">
          <StatCard label="CPU" value={`${stats.system_stats?.cpu ?? '?'}%`} />
          <StatCard label="Memory" value={stats.sys_stats ? fmtPct(stats.sys_stats.mem_used, stats.sys_stats.mem_total) : `${stats.system_stats?.mem ?? '?'}%`}
            sub={stats.sys_stats ? `${fmtBytes(stats.sys_stats.mem_used)} / ${fmtBytes(stats.sys_stats.mem_total)}` : undefined} />
          <StatCard label="Uptime" value={stats.uptime_str} />
          <StatCard label="Load" value={stats.sys_stats ? `${stats.sys_stats.loadavg_1} / ${stats.sys_stats.loadavg_5} / ${stats.sys_stats.loadavg_15}` : '?'} />
        </div>
        <div className="grid grid-cols-4 gap-3 mt-2">
          <StatCard label="Arch" value={stats.architecture} />
          <StatCard label="Kernel" value={stats.kernel_version} />
          <StatCard label="Serial" value={stats.serial} />
          <StatCard label="Satisfaction" value={`${stats.satisfaction}%`} />
        </div>
        <div className="grid grid-cols-4 gap-3 mt-2">
          <StatCard label="Internet" value={stats.internet ? 'Yes' : 'No'} />
          <StatCard label="Gateway" value={stats.gateway_ip} />
          {stats.power_source_voltage && <StatCard label="PoE Input" value={`${stats.power_source_voltage}V`} />}
          {stats.total_max_power != null && <StatCard label="PoE Budget" value={`${stats.total_max_power}W`} />}
          {stats.overheating && <StatCard label="Temp" value="OVERHEATING" />}
        </div>
      </div>
    </>
  )
}

function fmtBytes(b: number): string {
  if (b === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), units.length - 1)
  return `${(b / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function fmtPct(used: number, total: number): string {
  if (total === 0) return '0%'
  return `${((used / total) * 100).toFixed(1)}%`
}

function StatCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-navy-800/30 rounded px-2.5 py-1.5">
      <div className="text-[10px] text-navy-400 uppercase">{label}</div>
      <div className="text-sm text-gray-200 font-mono tabular-nums">{value}</div>
      {sub && <div className="text-[10px] text-navy-500">{sub}</div>}
    </div>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-navy-400 text-xs">{label}</span>
      <p className="text-gray-200 font-mono text-xs mt-0.5 break-all">{value}</p>
    </div>
  )
}

function ValidationBadge({ label, ok }: { label: string; ok: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-1 rounded ${ok ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
      {ok ? (
        <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M5 13l4 4L19 7" /></svg>
      ) : (
        <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M18 6L6 18M6 6l12 12" /></svg>
      )}
      {label}
    </span>
  )
}
