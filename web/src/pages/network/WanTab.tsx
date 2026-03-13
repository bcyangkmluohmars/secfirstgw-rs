// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type WanPortConfig, type WanConnectionType, type WanStatus } from '../../api'
import { Card, Button, Badge, Modal, Input, Select, Toggle, EmptyState, Spinner } from '../../components/ui'
import { useToast } from '../../hooks/useToast'

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

interface WanFormState {
  iface: string
  connType: string
  enabled: boolean
  priority: number
  weight: number
  healthCheck: string
  healthInterval: number
  mtu: string
  dns: string
  mac: string
  // static fields
  address: string
  gateway: string
  addressV6: string
  gatewayV6: string
  // pppoe fields
  username: string
  password: string
  serviceName: string
  vlanId: string
  // dslite
  aftr: string
}

const emptyForm: WanFormState = {
  iface: '', connType: 'dhcp', enabled: true, priority: 1, weight: 1,
  healthCheck: '1.1.1.1', healthInterval: 10, mtu: '', dns: '', mac: '',
  address: '', gateway: '', addressV6: '', gatewayV6: '',
  username: '', password: '', serviceName: '', vlanId: '',
  aftr: '',
}

function formToConfig(form: WanFormState): WanPortConfig {
  let connection: WanConnectionType
  switch (form.connType) {
    case 'static':
      connection = {
        type: 'static',
        address: form.address,
        gateway: form.gateway,
        ...(form.addressV6 ? { address_v6: form.addressV6 } : {}),
        ...(form.gatewayV6 ? { gateway_v6: form.gatewayV6 } : {}),
      }
      break
    case 'pppoe':
      connection = {
        type: 'pppoe',
        username: form.username,
        password: form.password,
        ...(form.serviceName ? { service_name: form.serviceName } : {}),
        ...(form.vlanId ? { vlan_id: Number(form.vlanId) } : {}),
      }
      break
    case 'dslite':
      connection = { type: 'dslite', ...(form.aftr ? { aftr: form.aftr } : {}) }
      break
    default:
      connection = { type: 'dhcp' }
  }

  return {
    interface: form.iface,
    connection,
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

function configToForm(cfg: WanPortConfig): WanFormState {
  const base: WanFormState = {
    ...emptyForm,
    iface: cfg.interface,
    connType: cfg.connection.type,
    enabled: cfg.enabled,
    priority: cfg.priority,
    weight: cfg.weight,
    healthCheck: cfg.health_check,
    healthInterval: cfg.health_interval_secs,
    mtu: cfg.mtu ? String(cfg.mtu) : '',
    dns: cfg.dns_override?.join(', ') ?? '',
    mac: cfg.mac_override ?? '',
  }

  const conn = cfg.connection
  if (conn.type === 'static') {
    base.address = conn.address
    base.gateway = conn.gateway
    base.addressV6 = conn.address_v6 ?? ''
    base.gatewayV6 = conn.gateway_v6 ?? ''
  } else if (conn.type === 'pppoe') {
    base.username = conn.username
    base.password = conn.password
    base.serviceName = conn.service_name ?? ''
    base.vlanId = conn.vlan_id != null ? String(conn.vlan_id) : ''
  } else if (conn.type === 'dslite') {
    base.aftr = conn.aftr ?? ''
  }

  return base
}

export default function WanTab() {
  const [configs, setConfigs] = useState<WanPortConfig[]>([])
  const [statuses, setStatuses] = useState<Record<string, WanStatus>>({})
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editIface, setEditIface] = useState<string | null>(null)
  const [form, setForm] = useState<WanFormState>({ ...emptyForm })
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getWanConfigs()
      const cfgs = res?.configs ?? []
      setConfigs(cfgs)
      const statusMap: Record<string, WanStatus> = {}
      for (const c of cfgs) {
        try {
          const r = await api.getWanStatus(c.interface)
          statusMap[c.interface] = r?.wan_status ?? r as unknown as WanStatus
        } catch { /* interface down or unavailable */ }
      }
      setStatuses(statusMap)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const openCreate = () => {
    setForm({ ...emptyForm })
    setEditIface(null)
    setShowForm(true)
  }

  const openEdit = (cfg: WanPortConfig) => {
    setForm(configToForm(cfg))
    setEditIface(cfg.interface)
    setShowForm(true)
  }

  const handleSave = async () => {
    if (!form.iface) { toast.error('Interface name is required'); return }
    try {
      await api.setWanConfig(form.iface, formToConfig(form))
      setShowForm(false)
      toast.success(editIface ? 'WAN port updated' : 'WAN port created')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDelete = async (iface: string) => {
    try { await api.deleteWanConfig(iface); toast.success('WAN port deleted'); load() }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleReconnect = async (iface: string) => {
    try { await api.reconnectWan(iface); toast.success('Reconnecting...') }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading WAN configuration..." />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">
          WAN Ports
          {configs.length > 0 && <span className="text-navy-600 ml-2">({configs.length})</span>}
        </p>
        <Button size="sm" onClick={openCreate}>+ Add WAN Port</Button>
      </div>

      {/* Create / Edit Modal */}
      <Modal open={showForm} onClose={() => setShowForm(false)} title={editIface ? `Edit WAN: ${editIface}` : 'New WAN Port'} size="lg">
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <Input label="Interface" mono value={form.iface} onChange={(e) => setForm({ ...form, iface: e.target.value })} placeholder="eth0" disabled={!!editIface} />
            <Select
              label="Connection Type"
              value={form.connType}
              onChange={(e) => setForm({ ...form, connType: e.target.value })}
              options={[
                { value: 'dhcp', label: 'DHCP' },
                { value: 'static', label: 'Static' },
                { value: 'pppoe', label: 'PPPoE' },
                { value: 'dslite', label: 'DS-Lite' },
              ]}
            />
            <Input label="Priority" type="number" mono value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} />
            <Input label="Weight" type="number" mono value={form.weight} onChange={(e) => setForm({ ...form, weight: Number(e.target.value) })} />
            <Input label="Health Check IP" mono value={form.healthCheck} onChange={(e) => setForm({ ...form, healthCheck: e.target.value })} placeholder="1.1.1.1" />
            <Input label="Health Interval (s)" type="number" mono value={form.healthInterval} onChange={(e) => setForm({ ...form, healthInterval: Number(e.target.value) })} />
            <Input label="MTU" mono value={form.mtu} onChange={(e) => setForm({ ...form, mtu: e.target.value })} placeholder="Auto" />
            <Input label="DNS Override" mono value={form.dns} onChange={(e) => setForm({ ...form, dns: e.target.value })} placeholder="1.1.1.1, 8.8.8.8" />
            <Input label="MAC Override" mono value={form.mac} onChange={(e) => setForm({ ...form, mac: e.target.value })} placeholder="Auto" />
          </div>

          {/* Static IP fields */}
          {form.connType === 'static' && (
            <div className="grid grid-cols-2 gap-3 border-t border-navy-800/30 pt-4">
              <Input label="IPv4 Address (CIDR)" mono value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} placeholder="203.0.113.2/24" />
              <Input label="IPv4 Gateway" mono value={form.gateway} onChange={(e) => setForm({ ...form, gateway: e.target.value })} placeholder="203.0.113.1" />
              <Input label="IPv6 Address (optional)" mono value={form.addressV6} onChange={(e) => setForm({ ...form, addressV6: e.target.value })} />
              <Input label="IPv6 Gateway (optional)" mono value={form.gatewayV6} onChange={(e) => setForm({ ...form, gatewayV6: e.target.value })} />
            </div>
          )}

          {/* PPPoE fields */}
          {form.connType === 'pppoe' && (
            <div className="grid grid-cols-2 gap-3 border-t border-navy-800/30 pt-4">
              <Input label="Username" mono value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
              <Input label="Password" type="password" mono value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <Input label="Service Name (optional)" mono value={form.serviceName} onChange={(e) => setForm({ ...form, serviceName: e.target.value })} />
              <Input label="VLAN ID (optional)" type="number" mono value={form.vlanId} onChange={(e) => setForm({ ...form, vlanId: e.target.value })} />
            </div>
          )}

          {/* DS-Lite fields */}
          {form.connType === 'dslite' && (
            <div className="grid grid-cols-2 gap-3 border-t border-navy-800/30 pt-4">
              <Input label="AFTR (optional)" mono value={form.aftr} onChange={(e) => setForm({ ...form, aftr: e.target.value })} placeholder="Auto-discover" />
            </div>
          )}

          <div className="flex items-center gap-4 border-t border-navy-800/30 pt-4">
            <Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} label="Enabled" />
          </div>

          <div className="flex gap-2 pt-2">
            <Button onClick={handleSave}>{editIface ? 'Update' : 'Create'}</Button>
            <Button variant="secondary" onClick={() => setShowForm(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* WAN port list */}
      {configs.length === 0 ? (
        <EmptyState
          icon={<svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z" /><path d="M2 12h20M12 2c2.5 2.8 4 6.2 4 10s-1.5 7.2-4 10c-2.5-2.8-4-6.2-4-10s1.5-7.2 4-10z" /></svg>}
          title="No WAN ports configured"
          description="Add a WAN port to connect to the internet."
        />
      ) : (
        <div className="space-y-3 stagger-children">
          {configs.map((cfg) => {
            const status = statuses[cfg.interface]
            const isUp = status?.link_up ?? false

            return (
              <Card key={cfg.interface} noPadding>
                {/* Header */}
                <div className="flex items-center justify-between px-5 py-4 border-b border-navy-800/30">
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <span className={`block w-2.5 h-2.5 rounded-full ${isUp ? 'bg-emerald-400' : 'bg-red-400'}`} />
                      {isUp && <span className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping opacity-30" />}
                    </div>
                    <span className="text-sm font-semibold text-gray-200 font-mono">{cfg.interface}</span>
                    <Badge variant={isUp ? 'success' : 'danger'}>{isUp ? 'UP' : 'DOWN'}</Badge>
                    <Badge>{cfg.connection.type.toUpperCase()}</Badge>
                    {!cfg.enabled && <Badge variant="neutral">Disabled</Badge>}
                    <span className="text-[10px] text-navy-500 font-mono">pri:{cfg.priority} w:{cfg.weight}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="secondary" size="sm" onClick={() => handleReconnect(cfg.interface)}>Reconnect</Button>
                    <Button variant="secondary" size="sm" onClick={() => openEdit(cfg)}>Edit</Button>
                    <Button variant="danger" size="sm" onClick={() => handleDelete(cfg.interface)}>Delete</Button>
                  </div>
                </div>

                {/* Status details */}
                {status && (
                  <div className="px-5 py-3 border-b border-navy-800/20">
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
                          rx {fmtBytes(status.rx_bytes ?? 0)} / tx {fmtBytes(status.tx_bytes ?? 0)}
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
    </div>
  )
}
