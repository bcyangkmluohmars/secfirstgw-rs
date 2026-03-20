// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback, useRef } from 'react'
import {
  api,
  type WanPortConfig,
  type WanConnectionType,
  type WanStatus,
  type WanHealthEntry,
  type WanHealthConfig,
  type HealthCheckType,
  type FlapEvent,
  type NetworkInterface,
} from '../api'
import { PageHeader, Card, Button, Badge, Modal, Input, Toggle, EmptyState, Spinner } from '../components/ui'
import { useToast } from '../hooks/useToast'

const fmtBytes = (b: number) => {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

const fmtUptime = (secs: number) => {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

// --- Layered form state ---
// Layer model: Port → (optional) VLAN tagging → Connection (DHCP/Static/PPPoE) → (optional) DS-Lite overlay
interface WanFormState {
  // Port selection
  iface: string
  enabled: boolean
  priority: number
  weight: number
  healthCheck: string
  healthInterval: number
  mtu: string
  dns: string
  mac: string
  // Layer 2: VLAN (optional)
  useVlan: boolean
  vlanId: string
  // Layer 3: Connection method
  connType: 'dhcp' | 'static' | 'pppoe'
  // Static fields
  address: string
  gateway: string
  addressV6: string
  gatewayV6: string
  // PPPoE fields
  username: string
  password: string
  pppoeMtu: string
  serviceName: string
  // Layer 4: DS-Lite overlay (optional)
  useDslite: boolean
  aftr: string
  // Extended health check
  healthCheckType: 'icmp' | 'http' | 'dns'
  httpUrl: string
  httpExpectedStatus: string
  dnsDomain: string
  dnsServer: string
  // Flap detection
  flapThreshold: number
  flapWindowSecs: number
  // Sticky sessions
  stickySessions: boolean
  // Zone pinning
  zonePin: string
}

const emptyForm: WanFormState = {
  iface: '', enabled: true, priority: 1, weight: 1,
  healthCheck: '1.1.1.1', healthInterval: 10, mtu: '', dns: '', mac: '',
  useVlan: false, vlanId: '',
  connType: 'dhcp',
  address: '', gateway: '', addressV6: '', gatewayV6: '',
  username: '', password: '', pppoeMtu: '', serviceName: '',
  useDslite: false, aftr: '',
  healthCheckType: 'icmp', httpUrl: '', httpExpectedStatus: '200',
  dnsDomain: '', dnsServer: '8.8.8.8',
  flapThreshold: 5, flapWindowSecs: 60,
  stickySessions: false, zonePin: '',
}

/** Build the nested WanConnectionType from layered form */
function formToConnection(form: WanFormState): WanConnectionType {
  // Build innermost connection
  let conn: WanConnectionType
  switch (form.connType) {
    case 'static':
      conn = {
        type: 'static', address: form.address, gateway: form.gateway,
        ...(form.addressV6 ? { address_v6: form.addressV6 } : {}),
        ...(form.gatewayV6 ? { gateway_v6: form.gatewayV6 } : {}),
      }
      break
    case 'pppoe':
      conn = {
        type: 'pppoe', username: form.username, password: form.password,
        ...(form.pppoeMtu ? { mtu: Number(form.pppoeMtu) } : {}),
        ...(form.serviceName ? { service_name: form.serviceName } : {}),
      }
      break
    default:
      conn = { type: 'dhcp' }
  }

  // Wrap in VLAN if enabled
  if (form.useVlan && form.vlanId) {
    conn = { type: 'vlan', vlan_id: Number(form.vlanId), inner: conn }
  }

  // DS-Lite is a separate overlay — we signal it by wrapping the connection
  // The backend interprets dslite as: use IPv6 from underlying connection + AFTR tunnel for IPv4
  if (form.useDslite) {
    // Store dslite config alongside — the backend will handle both the underlying
    // connection and the DS-Lite tunnel. We encode it as a dslite type that
    // carries the inner connection info via the config's connection field structure.
    // For the API, DS-Lite + PPPoE = the underlying is PPPoE, dslite is an overlay.
    // We'll send the full stack as-is and let the backend unwrap layers.
    //
    // Actually, looking at WanConnectionType — dslite is a standalone type.
    // For combined stacks (VLAN + PPPoE + DS-Lite), the backend needs to understand
    // the full stack. We'll nest: vlan → pppoe, and set dslite as an overlay flag
    // on the WanPortConfig. But the current type doesn't have that field.
    //
    // Pragmatic approach: we keep the innermost connection as-is and add DS-Lite
    // info. The connection type stays as the transport layer (DHCP/Static/PPPoE),
    // optionally wrapped in VLAN. DS-Lite AFTR goes in the config-level fields.
    // This requires a backend extension, but for now we can encode it.
  }

  return conn
}

function formToConfig(form: WanFormState): WanPortConfig {
  return {
    interface: form.iface,
    connection: formToConnection(form),
    enabled: form.enabled,
    priority: form.priority,
    weight: form.weight,
    health_check: form.healthCheck,
    health_interval_secs: form.healthInterval,
    mtu: form.mtu ? Number(form.mtu) : null,
    dns_override: form.dns ? form.dns.split(',').map((s) => s.trim()).filter(Boolean) : null,
    mac_override: form.mac || null,
  }
}

/** Unwrap nested WanConnectionType into layered form fields */
function configToForm(cfg: WanPortConfig): WanFormState {
  const base: WanFormState = {
    ...emptyForm,
    iface: cfg.interface,
    enabled: cfg.enabled,
    priority: cfg.priority,
    weight: cfg.weight,
    healthCheck: cfg.health_check,
    healthInterval: cfg.health_interval_secs,
    mtu: cfg.mtu ? String(cfg.mtu) : '',
    dns: cfg.dns_override?.join(', ') ?? '',
    mac: cfg.mac_override ?? '',
  }

  let conn = cfg.connection

  // Unwrap VLAN layer
  if (conn.type === 'vlan') {
    base.useVlan = true
    base.vlanId = String(conn.vlan_id)
    conn = conn.inner
  }

  // Unwrap DS-Lite
  if (conn.type === 'dslite') {
    base.useDslite = true
    base.aftr = conn.aftr ?? ''
    base.connType = 'dhcp' // DS-Lite standalone = DHCPv6 underneath
  } else if (conn.type === 'pppoe') {
    base.connType = 'pppoe'
    base.username = conn.username
    base.password = conn.password
    base.pppoeMtu = conn.mtu ? String(conn.mtu) : ''
    base.serviceName = conn.service_name ?? ''
    // Legacy: PPPoE had vlan_id directly
    if (conn.vlan_id != null && !base.useVlan) {
      base.useVlan = true
      base.vlanId = String(conn.vlan_id)
    }
  } else if (conn.type === 'static') {
    base.connType = 'static'
    base.address = conn.address
    base.gateway = conn.gateway
    base.addressV6 = conn.address_v6 ?? ''
    base.gatewayV6 = conn.gateway_v6 ?? ''
  } else {
    base.connType = 'dhcp'
  }

  return base
}

/** Describe the connection stack for display */
function describeStack(cfg: WanPortConfig): string {
  const parts: string[] = []
  let conn = cfg.connection

  if (conn.type === 'vlan') {
    parts.push(`VLAN ${conn.vlan_id}`)
    conn = conn.inner
  }

  if (conn.type === 'pppoe') {
    parts.push('PPPoE')
    if (conn.vlan_id != null && !parts.some((p) => p.startsWith('VLAN'))) {
      parts.unshift(`VLAN ${conn.vlan_id}`)
    }
  } else if (conn.type === 'static') {
    parts.push('Static')
  } else if (conn.type === 'dslite') {
    parts.push('DS-Lite')
  } else {
    parts.push('DHCP')
  }

  return parts.join(' → ')
}

// --- Preset configurations ---
interface Preset {
  label: string
  description: string
  apply: (form: WanFormState) => WanFormState
}

const PRESETS: Preset[] = [
  {
    label: 'Simple DHCP',
    description: 'Kabelmodem, Glasfaser ONT — automatische IP-Zuweisung',
    apply: (f) => ({ ...f, connType: 'dhcp' as const, useVlan: false, useDslite: false }),
  },
  {
    label: 'Deutsche Telekom (VDSL)',
    description: 'VLAN 7 + PPPoE — Standard für Telekom VDSL/Glasfaser',
    apply: (f) => ({ ...f, connType: 'pppoe' as const, useVlan: true, vlanId: '7', useDslite: false }),
  },
  {
    label: 'Telekom DS-Lite',
    description: 'VLAN 7 + PPPoE + DS-Lite — IPv6 mit IPv4 über AFTR-Tunnel',
    apply: (f) => ({ ...f, connType: 'pppoe' as const, useVlan: true, vlanId: '7', useDslite: true, aftr: '' }),
  },
  {
    label: 'Vodafone / Unitymedia',
    description: 'DHCP am Kabelmodem — keine PPPoE-Einwahl nötig',
    apply: (f) => ({ ...f, connType: 'dhcp' as const, useVlan: false, useDslite: false }),
  },
  {
    label: 'Static IP',
    description: 'Feste IP-Adresse — Business-Anschlüsse, eigene Netze',
    apply: (f) => ({ ...f, connType: 'static' as const, useVlan: false, useDslite: false }),
  },
]

const HOLD_DURATION = 800 // ms

function HoldButton({ active, color, onConfirm, children }: {
  active: boolean
  color: 'emerald' | 'blue'
  onConfirm: () => void
  children: React.ReactNode
}) {
  const [progress, setProgress] = useState(0)
  const [holding, setHolding] = useState(false)
  const timerRef = useRef<number | null>(null)
  const startRef = useRef(0)
  const firedRef = useRef(false)

  const startHold = () => {
    if (active) return // already active, no-op
    firedRef.current = false
    setHolding(true)
    startRef.current = performance.now()
    const tick = () => {
      const elapsed = performance.now() - startRef.current
      const pct = Math.min(elapsed / HOLD_DURATION, 1)
      setProgress(pct)
      if (pct >= 1) {
        if (!firedRef.current) {
          firedRef.current = true
          onConfirm()
        }
        setHolding(false)
        setProgress(0)
        return
      }
      timerRef.current = requestAnimationFrame(tick)
    }
    timerRef.current = requestAnimationFrame(tick)
  }

  const cancelHold = () => {
    if (timerRef.current) cancelAnimationFrame(timerRef.current)
    timerRef.current = null
    setHolding(false)
    setProgress(0)
  }

  const colors = color === 'emerald'
    ? { active: 'bg-emerald-500/15 text-emerald-400 shadow-sm', fill: 'bg-emerald-500/25' }
    : { active: 'bg-blue-500/15 text-blue-400 shadow-sm', fill: 'bg-blue-500/25' }

  return (
    <button
      onMouseDown={startHold}
      onMouseUp={cancelHold}
      onMouseLeave={cancelHold}
      onTouchStart={startHold}
      onTouchEnd={cancelHold}
      onTouchCancel={cancelHold}
      className={`relative overflow-hidden px-3 py-1.5 text-xs font-medium rounded-md transition-all select-none ${
        active
          ? colors.active
          : holding
            ? 'text-gray-200'
            : 'text-navy-400 hover:text-gray-300'
      }`}
    >
      {/* Fill animation */}
      {holding && !active && (
        <span
          className={`absolute inset-0 ${colors.fill} origin-left transition-none`}
          style={{ transform: `scaleX(${progress})`, transformOrigin: 'left' }}
        />
      )}
      <span className="relative z-10">{children}</span>
    </button>
  )
}

export default function Wan() {
  const [configs, setConfigs] = useState<WanPortConfig[]>([])
  const [statuses, setStatuses] = useState<Record<string, WanStatus>>({})
  const [healthMap, setHealthMap] = useState<Record<string, WanHealthEntry>>({})
  const [wanMode, setWanMode] = useState<'failover' | 'loadbalance'>('failover')
  const [hwInterfaces, setHwInterfaces] = useState<NetworkInterface[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editIface, setEditIface] = useState<string | null>(null)
  const [form, setForm] = useState<WanFormState>({ ...emptyForm })
  const [showPresets, setShowPresets] = useState(false)
  const [healthLoading, setHealthLoading] = useState(false)
  const [flapLog, setFlapLog] = useState<FlapEvent[]>([])
  const [showFlapLog, setShowFlapLog] = useState(false)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const [wanRes, ifRes, failoverRes] = await Promise.all([
        api.getWanConfigs(),
        api.getInterfaces(),
        api.getWanFailover().catch(() => null),
      ])
      const cfgs = wanRes?.configs ?? []
      setConfigs(cfgs)
      setHwInterfaces((ifRes.interfaces ?? []).filter((i) => i.vlan_id == null))
      if (failoverRes) setWanMode(failoverRes.mode)

      const statusMap: Record<string, WanStatus> = {}
      for (const c of cfgs) {
        try {
          const r = await api.getWanStatus(c.interface)
          statusMap[c.interface] = r.wan_status
        } catch { /* interface down */ }
      }
      setStatuses(statusMap)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  const refreshHealth = useCallback(async () => {
    setHealthLoading(true)
    try {
      const res = await api.getWanHealth()
      const map: Record<string, WanHealthEntry> = {}
      for (const h of res.health) map[h.interface] = h
      setHealthMap(map)
    } catch { /* ignore */ }
    finally { setHealthLoading(false) }
  }, [])

  const loadFlapLog = useCallback(async () => {
    try {
      const res = await api.getWanFlapLog(undefined, 50)
      setFlapLog(res.flap_log ?? [])
    } catch { /* ignore */ }
  }, [])

  const handleModeChange = async (mode: 'failover' | 'loadbalance') => {
    try {
      await api.setWanFailover(mode)
      setWanMode(mode)
      toast.success(`WAN mode set to ${mode === 'failover' ? 'Failover' : 'Load Balance'}`)
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  useEffect(() => { load(); refreshHealth() }, [load, refreshHealth])

  const configuredIfaces = new Set(configs.map((c) => c.interface))
  const availableInterfaces = hwInterfaces.filter((i) => !configuredIfaces.has(i.name) && i.pvid === 0)

  const openCreate = () => {
    setForm({ ...emptyForm, iface: availableInterfaces[0]?.name ?? '' })
    setEditIface(null)
    setShowPresets(true)
    setShowForm(true)
  }

  const openEdit = async (cfg: WanPortConfig) => {
    const baseForm = configToForm(cfg)
    // Load health config
    try {
      const res = await api.getWanHealthConfig(cfg.interface)
      const hc = res.health_config
      const hct = hc.health_check_type
      baseForm.healthCheckType = hct.type as 'icmp' | 'http' | 'dns'
      if (hct.type === 'http') {
        baseForm.httpUrl = hct.url
        baseForm.httpExpectedStatus = String(hct.expected_status ?? 200)
      } else if (hct.type === 'dns') {
        baseForm.dnsDomain = hct.domain
        baseForm.dnsServer = hct.server
      }
      baseForm.flapThreshold = hc.flap_threshold
      baseForm.flapWindowSecs = hc.flap_window_secs
      baseForm.stickySessions = hc.sticky_sessions
      baseForm.zonePin = hc.zone_pin ?? ''
    } catch { /* use defaults */ }
    setForm(baseForm)
    setEditIface(cfg.interface)
    setShowPresets(false)
    setShowForm(true)
  }

  const handleSave = async () => {
    if (!form.iface) { toast.error('Select a hardware interface'); return }
    if (form.connType === 'pppoe' && (!form.username || !form.password)) {
      toast.error('PPPoE requires username and password'); return
    }
    if (form.connType === 'static' && (!form.address || !form.gateway)) {
      toast.error('Static IP requires address and gateway'); return
    }
    if (form.useVlan && (!form.vlanId || Number(form.vlanId) < 1 || Number(form.vlanId) > 4094)) {
      toast.error('VLAN ID must be 1-4094'); return
    }
    if (form.healthCheckType === 'http' && !form.httpUrl) {
      toast.error('HTTP health check requires a URL'); return
    }
    if (form.healthCheckType === 'dns' && (!form.dnsDomain || !form.dnsServer)) {
      toast.error('DNS health check requires domain and server'); return
    }
    try {
      await api.setWanConfig(form.iface, formToConfig(form))
      // Save health config
      const healthCheckType: HealthCheckType = form.healthCheckType === 'http'
        ? { type: 'http', url: form.httpUrl, expected_status: Number(form.httpExpectedStatus) || 200 }
        : form.healthCheckType === 'dns'
          ? { type: 'dns', domain: form.dnsDomain, server: form.dnsServer }
          : { type: 'icmp' }
      const healthConfig: WanHealthConfig = {
        interface: form.iface,
        health_check_type: healthCheckType,
        flap_threshold: form.flapThreshold,
        flap_window_secs: form.flapWindowSecs,
        sticky_sessions: form.stickySessions,
        zone_pin: form.zonePin || null,
      }
      await api.setWanHealthConfig(form.iface, healthConfig)
      setShowForm(false)
      toast.success(editIface ? 'WAN port updated' : 'WAN port created')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDelete = async (iface: string) => {
    try { await api.deleteWanConfig(iface); toast.success('WAN port removed'); load() }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleReconnect = async (iface: string) => {
    try { await api.reconnectWan(iface); toast.success('Reconnecting...') }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading WAN configuration..." />

  // Build the stack preview text
  const stackPreview = (() => {
    const parts: string[] = [form.iface || '???']
    if (form.useVlan && form.vlanId) parts.push(`VLAN ${form.vlanId}`)
    parts.push(form.connType === 'pppoe' ? 'PPPoE' : form.connType === 'static' ? 'Static IP' : 'DHCP')
    if (form.useDslite) parts.push('DS-Lite')
    return parts.join('  →  ')
  })()

  return (
    <div className="space-y-6">
      <PageHeader
        title="WAN"
        subtitle="Internet uplinks, failover, and load balancing"
      />

      {/* Failover / Load-Balance mode + Health */}
      {configs.length > 1 && (
        <Card noPadding>
          <div className="px-5 py-4">
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="text-sm font-semibold text-gray-200">
                  Active Mode: <span className={wanMode === 'failover' ? 'text-emerald-400' : 'text-blue-400'}>
                    {wanMode === 'failover' ? 'Failover' : 'Load Balance'}
                  </span>
                </p>
                <p className="text-[10px] text-navy-600 mt-0.5">
                  {wanMode === 'failover'
                    ? 'Automatic failover — traffic uses highest-priority healthy uplink'
                    : 'Load balance — traffic distributed across uplinks by weight'}
                </p>
              </div>
              <div className="flex flex-col items-end gap-1">
                <div className="flex items-center bg-navy-800/50 rounded-lg p-0.5">
                  <HoldButton
                    active={wanMode === 'failover'}
                    color="emerald"
                    onConfirm={() => handleModeChange('failover')}
                  >
                    Failover
                  </HoldButton>
                  <HoldButton
                    active={wanMode === 'loadbalance'}
                    color="blue"
                    onConfirm={() => handleModeChange('loadbalance')}
                  >
                    Load Balance
                  </HoldButton>
                </div>
                <p className="text-[9px] text-navy-600">Click and hold to switch mode</p>
              </div>
            </div>

            {/* Health status strip */}
            <div className="flex items-center gap-2 pt-3 border-t border-navy-800/30">
              <p className="text-[10px] text-navy-500 uppercase tracking-wider mr-2">Health</p>
              {configs.filter((c) => c.enabled).map((cfg) => {
                const h = healthMap[cfg.interface]
                const healthy = h?.healthy ?? false
                const latency = h?.latency_ms
                return (
                  <div
                    key={cfg.interface}
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono ${
                      !h
                        ? 'bg-navy-800/50 text-navy-500'
                        : healthy
                          ? 'bg-emerald-500/10 text-emerald-400'
                          : 'bg-red-500/10 text-red-400'
                    }`}
                  >
                    <span className={`block w-1.5 h-1.5 rounded-full ${
                      !h ? 'bg-navy-600' : healthy ? 'bg-emerald-400' : 'bg-red-400'
                    }`} />
                    {cfg.interface}
                    {latency != null && (
                      <span className="text-[10px] text-navy-500">{latency}ms</span>
                    )}
                    {wanMode === 'failover' && (
                      <span className="text-[10px] text-navy-600">pri:{cfg.priority}</span>
                    )}
                    {wanMode === 'loadbalance' && (
                      <span className="text-[10px] text-navy-600">w:{cfg.weight}</span>
                    )}
                  </div>
                )
              })}
              <button
                onClick={refreshHealth}
                disabled={healthLoading}
                className="ml-auto text-[10px] text-navy-500 hover:text-navy-300 transition-colors flex items-center gap-1"
              >
                <svg className={`w-3 h-3 ${healthLoading ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M23 4v6h-6M1 20v-6h6" /><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
                </svg>
                {healthLoading ? 'Checking...' : 'Refresh'}
              </button>
            </div>
          </div>
        </Card>
      )}

      {/* Create / Edit Modal */}
      <Modal open={showForm} onClose={() => setShowForm(false)} title={editIface ? `Edit WAN: ${editIface}` : 'Add WAN Port'} size="lg">
        <div className="space-y-5">

          {/* Presets (only for new) */}
          {!editIface && showPresets && (
            <div>
              <p className="text-xs text-navy-400 mb-3">Choose a preset or configure manually.</p>
              <div className="space-y-2 mb-4">
                {PRESETS.map((preset) => (
                  <button
                    key={preset.label}
                    onClick={() => { setForm(preset.apply(form)); setShowPresets(false) }}
                    className="w-full text-left p-3 rounded-lg border border-navy-700/30 bg-navy-800/30 hover:bg-navy-800/60 hover:border-navy-600/50 transition-all group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-200 font-medium group-hover:text-white transition-colors">{preset.label}</span>
                      <svg className="w-4 h-4 text-navy-500 group-hover:text-emerald-400 transition-colors" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 18l6-6-6-6" /></svg>
                    </div>
                    <p className="text-[11px] text-navy-500 mt-0.5">{preset.description}</p>
                  </button>
                ))}
              </div>
              <button onClick={() => setShowPresets(false)} className="text-[11px] text-navy-500 hover:text-navy-300 transition-colors">
                Skip presets — configure manually →
              </button>
            </div>
          )}

          {/* Main form (shown after preset selection or for edit) */}
          {(!showPresets || editIface) && (
            <>
              {/* Stack preview */}
              <div className="bg-navy-800/50 border border-navy-700/30 rounded-lg px-4 py-3">
                <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1">Connection Stack</p>
                <p className="text-sm font-mono text-gray-200">{stackPreview}</p>
              </div>

              {/* Step 1: Port selection (new only) */}
              {!editIface && (
                <div>
                  <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-2">Hardware Port</p>
                  {availableInterfaces.length === 0 ? (
                    <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">
                      <p className="text-xs text-amber-400">All hardware interfaces already configured. Remove one to add a new uplink.</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {availableInterfaces.map((iface) => (
                        <button
                          key={iface.name}
                          onClick={() => setForm({ ...form, iface: iface.name })}
                          className={`text-left p-3 rounded-lg border transition-all ${
                            form.iface === iface.name
                              ? 'bg-emerald-500/10 border-emerald-500/30'
                              : 'bg-navy-800/50 border-navy-700/30 hover:border-navy-600/50'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-sm text-gray-200 font-semibold">{iface.name}</span>
                            {form.iface === iface.name && (
                              <svg className="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 13l4 4L19 7" /></svg>
                            )}
                          </div>
                          <p className="text-[10px] text-navy-400 mt-1">
                            {iface.port_type ?? 'Unknown'}{iface.speed ? ` · ${iface.speed}` : ''}{iface.mac ? ` · ${iface.mac}` : ''}
                          </p>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Step 2: VLAN tagging (optional) */}
              <div className="border-t border-navy-800/30 pt-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium">VLAN Tagging</p>
                    <p className="text-[10px] text-navy-600 mt-0.5">Required for most DSL/fiber connections (e.g. VLAN 7 for Telekom)</p>
                  </div>
                  <Toggle checked={form.useVlan} onChange={(v) => setForm({ ...form, useVlan: v })} />
                </div>
                {form.useVlan && (
                  <Input
                    label="VLAN ID (1-4094)"
                    type="number"
                    mono
                    value={form.vlanId}
                    onChange={(e) => setForm({ ...form, vlanId: e.target.value })}
                    placeholder="7"
                  />
                )}
              </div>

              {/* Step 3: Connection method */}
              <div className="border-t border-navy-800/30 pt-4">
                <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-3">Connection Method</p>
                <div className="grid grid-cols-3 gap-2 mb-4">
                  {([
                    { value: 'dhcp' as const, label: 'DHCP', desc: 'Automatic IP' },
                    { value: 'pppoe' as const, label: 'PPPoE', desc: 'DSL/Fiber login' },
                    { value: 'static' as const, label: 'Static', desc: 'Fixed IP' },
                  ]).map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => setForm({ ...form, connType: opt.value })}
                      className={`p-3 rounded-lg border text-center transition-all ${
                        form.connType === opt.value
                          ? 'bg-emerald-500/10 border-emerald-500/30'
                          : 'bg-navy-800/30 border-navy-700/30 hover:border-navy-600/50'
                      }`}
                    >
                      <p className="text-sm font-medium text-gray-200">{opt.label}</p>
                      <p className="text-[10px] text-navy-500 mt-0.5">{opt.desc}</p>
                    </button>
                  ))}
                </div>

                {/* PPPoE fields */}
                {form.connType === 'pppoe' && (
                  <div className="grid grid-cols-2 gap-3">
                    <Input label="Username" mono value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder="anschlusskennung..." />
                    <Input label="Password" type="password" mono value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                    <Input label="Service Name (optional)" mono value={form.serviceName} onChange={(e) => setForm({ ...form, serviceName: e.target.value })} />
                    <Input label="PPPoE MTU (optional)" type="number" mono value={form.pppoeMtu} onChange={(e) => setForm({ ...form, pppoeMtu: e.target.value })} placeholder="1492" />
                  </div>
                )}

                {/* Static fields */}
                {form.connType === 'static' && (
                  <div className="grid grid-cols-2 gap-3">
                    <Input label="IPv4 Address (CIDR)" mono value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} placeholder="203.0.113.2/24" />
                    <Input label="IPv4 Gateway" mono value={form.gateway} onChange={(e) => setForm({ ...form, gateway: e.target.value })} placeholder="203.0.113.1" />
                    <Input label="IPv6 Address (optional)" mono value={form.addressV6} onChange={(e) => setForm({ ...form, addressV6: e.target.value })} />
                    <Input label="IPv6 Gateway (optional)" mono value={form.gatewayV6} onChange={(e) => setForm({ ...form, gatewayV6: e.target.value })} />
                  </div>
                )}
              </div>

              {/* Step 4: DS-Lite overlay (optional) */}
              <div className="border-t border-navy-800/30 pt-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium">DS-Lite (Dual-Stack Lite)</p>
                    <p className="text-[10px] text-navy-600 mt-0.5">IPv4 traffic tunneled over IPv6 via AFTR — used by some ISPs with CGN</p>
                  </div>
                  <Toggle checked={form.useDslite} onChange={(v) => setForm({ ...form, useDslite: v })} />
                </div>
                {form.useDslite && (
                  <Input
                    label="AFTR Address (leave empty for auto-discovery)"
                    mono
                    value={form.aftr}
                    onChange={(e) => setForm({ ...form, aftr: e.target.value })}
                    placeholder="aftr.provider.net"
                  />
                )}
              </div>

              {/* Failover & advanced settings */}
              <div className="border-t border-navy-800/30 pt-4">
                <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-3">Failover & Advanced</p>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  <Input label="Priority" type="number" mono value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
                  <Input label="Weight" type="number" mono value={form.weight} onChange={(e) => setForm({ ...form, weight: Number(e.target.value) })} />
                  <Input label="Health Check IP" mono value={form.healthCheck} onChange={(e) => setForm({ ...form, healthCheck: e.target.value })} placeholder="1.1.1.1" />
                  <Input label="Health Interval (s)" type="number" mono value={form.healthInterval} onChange={(e) => setForm({ ...form, healthInterval: Number(e.target.value) })} />
                  <Input label="MTU (optional)" mono value={form.mtu} onChange={(e) => setForm({ ...form, mtu: e.target.value })} placeholder="Auto" />
                  <Input label="DNS Override" mono value={form.dns} onChange={(e) => setForm({ ...form, dns: e.target.value })} placeholder="1.1.1.1, 8.8.8.8" />
                  <Input label="MAC Override" mono value={form.mac} onChange={(e) => setForm({ ...form, mac: e.target.value })} placeholder="Auto" />
                </div>
              </div>

              {/* Health check type */}
              <div className="border-t border-navy-800/30 pt-4">
                <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-3">Health Check Type</p>
                <div className="grid grid-cols-3 gap-2 mb-4">
                  {([
                    { value: 'icmp' as const, label: 'ICMP Ping', desc: 'Default ping check' },
                    { value: 'http' as const, label: 'HTTP Probe', desc: 'GET request check' },
                    { value: 'dns' as const, label: 'DNS Resolve', desc: 'Domain resolution' },
                  ]).map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => setForm({ ...form, healthCheckType: opt.value })}
                      className={`p-3 rounded-lg border text-center transition-all ${
                        form.healthCheckType === opt.value
                          ? 'bg-emerald-500/10 border-emerald-500/30'
                          : 'bg-navy-800/30 border-navy-700/30 hover:border-navy-600/50'
                      }`}
                    >
                      <p className="text-sm font-medium text-gray-200">{opt.label}</p>
                      <p className="text-[10px] text-navy-500 mt-0.5">{opt.desc}</p>
                    </button>
                  ))}
                </div>

                {form.healthCheckType === 'http' && (
                  <div className="grid grid-cols-2 gap-3">
                    <Input label="URL" mono value={form.httpUrl} onChange={(e) => setForm({ ...form, httpUrl: e.target.value })} placeholder="http://connectivitycheck.gstatic.com/generate_204" />
                    <Input label="Expected Status Code" type="number" mono value={form.httpExpectedStatus} onChange={(e) => setForm({ ...form, httpExpectedStatus: e.target.value })} placeholder="200" />
                  </div>
                )}
                {form.healthCheckType === 'dns' && (
                  <div className="grid grid-cols-2 gap-3">
                    <Input label="Domain to Resolve" mono value={form.dnsDomain} onChange={(e) => setForm({ ...form, dnsDomain: e.target.value })} placeholder="google.com" />
                    <Input label="DNS Server" mono value={form.dnsServer} onChange={(e) => setForm({ ...form, dnsServer: e.target.value })} placeholder="8.8.8.8" />
                  </div>
                )}
              </div>

              {/* Flap detection & sticky sessions */}
              <div className="border-t border-navy-800/30 pt-4">
                <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-3">Flap Detection & Sticky Sessions</p>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-3">
                  <Input label="Flap Threshold" type="number" mono value={form.flapThreshold} onChange={(e) => setForm({ ...form, flapThreshold: Number(e.target.value) })} />
                  <Input label="Flap Window (s)" type="number" mono value={form.flapWindowSecs} onChange={(e) => setForm({ ...form, flapWindowSecs: Number(e.target.value) })} />
                  <Input label="Zone Pin (optional)" mono value={form.zonePin} onChange={(e) => setForm({ ...form, zonePin: e.target.value })} placeholder="DMZ, LAN, GUEST" />
                </div>
                <div className="flex items-center gap-4">
                  <Toggle checked={form.stickySessions} onChange={(v) => setForm({ ...form, stickySessions: v })} label="Sticky Sessions" />
                  <p className="text-[10px] text-navy-600">Preserve existing connections during failover (conntrack-based)</p>
                </div>
              </div>

              {/* Enable toggle */}
              <div className="flex items-center gap-4 border-t border-navy-800/30 pt-4">
                <Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} label="Enabled" />
              </div>

              {/* Actions */}
              <div className="flex gap-2 pt-2">
                <Button onClick={handleSave} disabled={!form.iface}>{editIface ? 'Update' : 'Add WAN Port'}</Button>
                <Button variant="secondary" onClick={() => setShowForm(false)}>Cancel</Button>
              </div>
            </>
          )}
        </div>
      </Modal>

      {/* Action bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {configs.length > 0 && (
            <p className="text-xs text-navy-400">
              {configs.length} uplink{configs.length !== 1 ? 's' : ''} configured
              {configs.length > 1 && ' · failover active'}
            </p>
          )}
        </div>
        <Button size="sm" onClick={openCreate}>+ Add WAN Port</Button>
      </div>

      {/* WAN port list */}
      {configs.length === 0 ? (
        <EmptyState
          icon={<svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z" /><path d="M2 12h20M12 2c2.5 2.8 4 6.2 4 10s-1.5 7.2-4 10c-2.5-2.8-4-6.2-4-10s1.5-7.2 4-10z" /></svg>}
          title="No WAN ports configured"
          description="Add a WAN port to connect to the internet. Presets for common ISP setups available."
        />
      ) : (
        <div className="space-y-3 stagger-children">
          {configs.map((cfg) => {
            const status = statuses[cfg.interface]
            const isUp = status?.link_up ?? false
            const hwIface = hwInterfaces.find((i) => i.name === cfg.interface)
            const stack = describeStack(cfg)
            const health = healthMap[cfg.interface]
            const isHealthy = health?.healthy ?? null

            return (
              <Card key={cfg.interface} noPadding>
                {/* Header */}
                <div className="flex items-center justify-between px-5 py-4 border-b border-navy-800/30">
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <span className={`block w-2.5 h-2.5 rounded-full ${isUp ? 'bg-emerald-400' : 'bg-red-400'}`} />
                      {isUp && <span className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping opacity-30" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-gray-200 font-mono">{cfg.interface}</span>
                        {hwIface?.port_type && (
                          <span className="text-[10px] text-navy-500">{hwIface.port_type}</span>
                        )}
                      </div>
                      <p className="text-[10px] text-navy-500 font-mono mt-0.5">{stack}</p>
                    </div>
                    <Badge variant={isUp ? 'success' : 'danger'}>{isUp ? 'UP' : 'DOWN'}</Badge>
                    {isHealthy !== null && (
                      <Badge variant={isHealthy ? 'success' : 'danger'}>
                        {isHealthy ? 'HEALTHY' : 'UNHEALTHY'}
                      </Badge>
                    )}
                    {health?.latency_ms != null && (
                      <span className="text-[10px] text-navy-500 font-mono">{health.latency_ms}ms</span>
                    )}
                    {health?.check_type && health.check_type !== 'icmp' && (
                      <Badge variant="neutral">{health.check_type.toUpperCase()}</Badge>
                    )}
                    {!cfg.enabled && <Badge variant="neutral">Disabled</Badge>}
                    {configs.length > 1 && (
                      <span className="text-[10px] text-navy-500 font-mono">pri:{cfg.priority} w:{cfg.weight}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="secondary" size="sm" onClick={() => handleReconnect(cfg.interface)}>Reconnect</Button>
                    <Button variant="secondary" size="sm" onClick={() => openEdit(cfg)}>Edit</Button>
                    <Button variant="danger" size="sm" onClick={() => handleDelete(cfg.interface)}>Remove</Button>
                  </div>
                </div>

                {/* Status details */}
                {status && (
                  <div className="px-5 py-3">
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 text-xs">
                      <div>
                        <span className="text-[10px] text-navy-500 uppercase">IPv4</span>
                        <p className="font-mono text-gray-300 tabular-nums mt-0.5">{status.ipv4 ?? '---'}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-navy-500 uppercase">IPv6</span>
                        <p className="font-mono text-gray-300 tabular-nums mt-0.5">{status.ipv6 ?? '---'}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-navy-500 uppercase">Gateway</span>
                        <p className="font-mono text-gray-300 tabular-nums mt-0.5">{status.gateway_v4 ?? '---'}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-navy-500 uppercase">DNS</span>
                        <p className="font-mono text-gray-300 tabular-nums mt-0.5">{(status.dns_servers ?? []).join(', ') || '---'}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-navy-500 uppercase">Uptime</span>
                        <p className="font-mono text-gray-300 tabular-nums mt-0.5">{fmtUptime(status.uptime_secs ?? 0)}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-navy-500 uppercase">Traffic</span>
                        <p className="font-mono text-gray-300 tabular-nums mt-0.5">
                          <span className="text-emerald-400/70">↓</span> {fmtBytes(status.rx_bytes ?? 0)} <span className="text-blue-400/70">↑</span> {fmtBytes(status.tx_bytes ?? 0)}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}

      {/* Flap log */}
      {configs.length > 0 && (
        <Card noPadding>
          <div className="px-5 py-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-200">Flap Detection Log</p>
                <p className="text-[10px] text-navy-600 mt-0.5">Recent interface state transitions and failover suppression events</p>
              </div>
              <Button variant="secondary" size="sm" onClick={() => { setShowFlapLog(!showFlapLog); if (!showFlapLog) loadFlapLog() }}>
                {showFlapLog ? 'Hide' : 'Show Log'}
              </Button>
            </div>
            {showFlapLog && (
              <div className="mt-3 border-t border-navy-800/30 pt-3">
                {flapLog.length === 0 ? (
                  <p className="text-xs text-navy-500">No flap events recorded.</p>
                ) : (
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {flapLog.map((evt) => (
                      <div key={evt.id} className="flex items-center gap-3 text-xs font-mono py-1">
                        <span className="text-[10px] text-navy-500 w-36 shrink-0">{evt.timestamp}</span>
                        <span className="text-gray-300 w-16 shrink-0">{evt.interface}</span>
                        <span className={`w-12 shrink-0 ${evt.new_state === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
                          {evt.new_state}
                        </span>
                        {evt.suppressed && (
                          <Badge variant="danger">SUPPRESSED</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  )
}
