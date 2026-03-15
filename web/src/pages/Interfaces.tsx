// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type NetworkInterface, type ZoneInfo } from '../api'
import { PageHeader, Spinner, Badge, Button, Modal, Input, Select, Toggle, Card, EmptyState } from '../components/ui'
import { useToast } from '../hooks/useToast'

const ROLES = ['wan', 'lan', 'dmz', 'mgmt', 'guest'] as const

const ZONE_COLORS: Record<string, { bg: string; border: string; text: string; dot: string; glow: string }> = {
  wan:   { bg: 'bg-red-500/10',     border: 'border-red-500/30',     text: 'text-red-400',     dot: 'bg-red-400',     glow: 'shadow-red-500/20' },
  lan:   { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', dot: 'bg-emerald-400', glow: 'shadow-emerald-500/20' },
  dmz:   { bg: 'bg-amber-500/10',   border: 'border-amber-500/30',   text: 'text-amber-400',   dot: 'bg-amber-400',   glow: 'shadow-amber-500/20' },
  mgmt:  { bg: 'bg-blue-500/10',    border: 'border-blue-500/30',    text: 'text-blue-400',    dot: 'bg-blue-400',    glow: 'shadow-blue-500/20' },
  guest: { bg: 'bg-gray-500/10',    border: 'border-gray-500/30',    text: 'text-gray-400',    dot: 'bg-gray-400',    glow: 'shadow-gray-500/20' },
  void:  { bg: 'bg-navy-950',       border: 'border-navy-800/20',    text: 'text-navy-600',    dot: 'bg-navy-700',    glow: '' },
}

const zoneColor = (zone: string) => ZONE_COLORS[zone.toLowerCase()] ?? ZONE_COLORS.guest

const roleVariant = (r: string) => {
  switch (r.toLowerCase()) {
    case 'wan':   return 'danger'  as const
    case 'lan':   return 'success' as const
    case 'dmz':   return 'warning' as const
    case 'mgmt':  return 'info'    as const
    case 'guest': return 'neutral' as const
    default:      return 'neutral' as const
  }
}

interface BoardPort {
  label: string
  iface: string
  connector: string
  default_zone: string
}

interface BoardInfo {
  board_id: string
  model: string
  short_name: string
  port_count: number
  ports: BoardPort[]
}

const portTypeLabel = (portType: string | null) => {
  if (!portType) return ''
  const l = portType.toLowerCase()
  if (l.includes('sfp+') || l.includes('sfpp')) return 'SFP+'
  if (l.includes('sfp')) return 'SFP'
  if (l.includes('rj45')) return 'RJ45'
  if (l.includes('bridge')) return 'Bridge'
  return portType
}

// Determine if a port name is a physical port (not a bridge or VLAN sub-interface)
const isPhysicalPort = (name: string) =>
  !name.startsWith('br-') && !name.includes('.')

export default function Interfaces() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [zones, setZones] = useState<ZoneInfo[]>([])
  const [board, setBoard] = useState<BoardInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [showVlanModal, setShowVlanModal] = useState(false)
  const [editIface, setEditIface] = useState<NetworkInterface | null>(null)
  const [vlanForm, setVlanForm] = useState({ parent: '', vlanId: '', role: 'lan' })
  const [editForm, setEditForm] = useState({ role: '', mtu: '', vlanId: '' as string | null })
  const toast = useToast()

  // Port config panel state
  const [configPort, setConfigPort] = useState<NetworkInterface | null>(null)
  const [configPvid, setConfigPvid] = useState<number>(10)
  const [configTagged, setConfigTagged] = useState<number[]>([])
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const [ifaceRes, sysRes, zoneRes] = await Promise.all([
        api.getInterfaces(),
        api.getSystem(),
        api.getZones(),
      ])
      setInterfaces(ifaceRes.interfaces ?? [])
      setBoard((sysRes.board as BoardInfo) ?? null)
      setZones(zoneRes.zones ?? [])
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  // Build vlan_id → ZoneInfo lookup for PVID-based zone resolution
  const vlanToZone = new Map<number, ZoneInfo>()
  for (const z of zones) {
    if (z.vlan_id != null) {
      vlanToZone.set(z.vlan_id, z)
    }
  }

  // Resolve zone name from a port's pvid.
  // pvid=0  → WAN (outside internal VLAN space)
  // pvid=1  → void (DROP-all VLAN)
  // pvid=N  → zone whose vlan_id === N, or 'guest' as fallback
  const pvid2Zone = (pvid: number): string => {
    if (pvid === 0) return 'wan'
    if (pvid === 1) return 'void'
    const z = vlanToZone.get(pvid)
    return z ? z.zone.toLowerCase() : 'guest'
  }

  // Group by zone (derived from pvid) — for zone cards section
  const zoneGroups = new Map<string, NetworkInterface[]>()
  const bridgeMembers = new Map<string, string[]>()
  const physicalOnly: NetworkInterface[] = []
  const ifaceByName = new Map<string, NetworkInterface>()

  for (const iface of interfaces) {
    ifaceByName.set(iface.name, iface)

    if (iface.name.startsWith('br-')) {
      // Derive zone from bridge name (br-lan → lan, br-mgmt → mgmt)
      const brZoneName = iface.name.replace('br-', '')
      // Find the VLAN ID for this zone from the zones API
      const brZoneInfo = zones.find(z => z.zone.toLowerCase() === brZoneName)
      const brVlanId = brZoneInfo?.vlan_id
      // Only match physical ethN/switchN ports whose pvid matches this bridge's zone VLAN
      const members = brVlanId != null
        ? interfaces
            .filter(i => /^(eth\d|switch\d)/.test(i.name) && i.pvid === brVlanId && i.name !== iface.name)
            .map(i => i.name)
        : []
      bridgeMembers.set(iface.name, members)
    }

    const zone = pvid2Zone(iface.pvid)
    if (!zoneGroups.has(zone)) zoneGroups.set(zone, [])
    zoneGroups.get(zone)!.push(iface)

    if (iface.vlan_id == null && !iface.name.startsWith('br-')) {
      physicalOnly.push(iface)
    }
  }

  const zoneOrder = ['wan', 'lan', 'mgmt', 'dmz', 'guest']
  const sortedZones = [...zoneGroups.entries()].sort((a, b) => {
    const ai = zoneOrder.indexOf(a[0])
    const bi = zoneOrder.indexOf(b[0])
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
  })

  // Zones visible in the legend (from actual zone data, not just roles)
  const legendZones = zones.filter(z => z.zone !== 'void').map(z => z.zone.toLowerCase())

  const openVlanModal = () => {
    setVlanForm({ parent: physicalOnly[0]?.name ?? '', vlanId: '', role: 'lan' })
    setShowVlanModal(true)
  }

  const openEdit = (iface: NetworkInterface) => {
    setEditForm({
      role: pvid2Zone(iface.pvid),
      mtu: String(iface.mtu),
      vlanId: iface.vlan_id != null ? String(iface.vlan_id) : null,
    })
    setEditIface(iface)
  }

  // Open the port config panel for physical ports
  const openPortConfig = async (iface: NetworkInterface) => {
    // Use data from iface if it has pvid/tagged_vlans; otherwise fetch from API
    if (iface.pvid !== undefined && iface.tagged_vlans !== undefined) {
      setConfigPort(iface)
      setConfigPvid(iface.pvid)
      setConfigTagged(iface.tagged_vlans ?? [])
    } else {
      try {
        const portData = await api.getPort(iface.name)
        setConfigPort(iface)
        setConfigPvid(portData.pvid)
        setConfigTagged(portData.tagged_vlans ?? [])
      } catch (e: unknown) {
        toast.error(`Could not load port config: ${(e as Error).message}`)
        return
      }
    }
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

  const handleSavePortConfig = async () => {
    if (!configPort) return
    setSaving(true)
    try {
      await api.updatePort(configPort.name, { pvid: configPvid, tagged_vlans: configTagged })
      toast.success(`Port ${configPort.name} updated`)
      setConfigPort(null)
      await load()
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
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

  // Handle tagged VLAN toggle in config panel
  const toggleTaggedVlan = (vlanId: number) => {
    setConfigTagged(prev =>
      prev.includes(vlanId) ? prev.filter(v => v !== vlanId) : [...prev, vlanId]
    )
  }

  if (loading) return <Spinner label="Loading interfaces..." />

  // ── Switch panel helpers ────────────────────────────────────────────────

  const getPortIface = (bp: BoardPort): NetworkInterface | undefined =>
    ifaceByName.get(bp.iface)

  const getPortUp = (bp: BoardPort): boolean => {
    const iface = getPortIface(bp)
    return iface ? (iface.is_up && iface.enabled) : false
  }

  const getPortSpeed = (bp: BoardPort): string | null =>
    getPortIface(bp)?.speed ?? null

  // Resolve zone name for a board port using PVID (primary model).
  // Falls back to bp.default_zone if the interface isn't in our map yet.
  const getPortZone = (bp: BoardPort): string => {
    const iface = getPortIface(bp)
    if (!iface) return bp.default_zone
    // pvid is always present since the server returns it; use it as primary signal
    return pvid2Zone(iface.pvid)
  }

  // Render colored dots for tagged VLANs (excluding the PVID's own VLAN)
  const renderTaggedDots = (iface: NetworkInterface) => {
    // WAN ports (pvid=0) have no internal VLAN model — skip dots
    if (iface.pvid === 0) return null
    // Filter out the PVID itself (already shown as primary color)
    const tagged = (iface.tagged_vlans ?? []).filter(v => v !== iface.pvid)
    if (tagged.length === 0) return null

    const maxDots = 3
    const shown = tagged.slice(0, maxDots)
    const extra = tagged.length - maxDots

    return (
      <div className="flex items-center gap-0.5 mt-0.5 justify-center">
        {shown.map(vlanId => {
          const z = vlanToZone.get(vlanId)
          const dotColor = z ? zoneColor(z.zone.toLowerCase()).dot : 'bg-navy-600'
          return (
            <span
              key={vlanId}
              className={`w-1.5 h-1.5 rounded-full ${dotColor}`}
              title={z ? `VLAN ${vlanId} (${z.zone})` : `VLAN ${vlanId}`}
            />
          )
        })}
        {extra > 0 && (
          <span className="text-[7px] text-navy-500 ml-0.5">+{extra}</span>
        )}
      </div>
    )
  }

  // ── Port click handler — routes to config panel or old edit modal ───────
  const handlePortClick = (iface: NetworkInterface) => {
    if (isPhysicalPort(iface.name)) {
      openPortConfig(iface)
    } else {
      openEdit(iface)
    }
  }

  // ── Device-specific switch panel (e.g. UDM Pro) ─────────────────────────
  const renderDeviceSwitch = (boardInfo: BoardInfo) => {
    const isSfp = (p: BoardPort) => p.connector === 'SFP+'
    const isWan = (p: BoardPort) => p.default_zone === 'wan'
    const lanPorts = boardInfo.ports.filter(p => !isSfp(p) && !isWan(p) && p.default_zone !== 'mgmt')
    const mgmtPort = boardInfo.ports.find(p => p.default_zone === 'mgmt')
    const wanPorts = boardInfo.ports.filter(p => isWan(p) && !isSfp(p))
    const sfpPorts = boardInfo.ports.filter(p => isSfp(p))

    const renderPort = (bp: BoardPort, size: 'normal' | 'sfp' = 'normal') => {
      const iface = getPortIface(bp)
      const zone = getPortZone(bp)
      const isVoid = zone === 'void'
      const isWanPort = zone === 'wan'
      const up = getPortUp(bp)
      const speed = getPortSpeed(bp)
      const c = zoneColor(zone)

      return (
        <button
          key={bp.iface}
          onClick={() => iface && handlePortClick(iface)}
          className={`relative group flex flex-col items-center justify-center rounded-lg border transition-all cursor-pointer
            ${size === 'sfp' ? 'w-[52px] h-[56px]' : 'w-[56px] h-[72px]'}
            ${isVoid
              ? 'bg-navy-950 border-navy-800/20 opacity-60'
              : up
                ? `${c.bg} ${c.border} shadow-md ${c.glow}`
                : 'bg-navy-900/50 border-navy-800/30 opacity-50'
            }
            hover:scale-105 hover:brightness-125`}
          title={`${bp.iface} — ${isVoid ? 'VOID (unused)' : zone.toUpperCase()}${speed ? ` (${speed})` : ''}`}
        >
          {/* Link indicator dot */}
          <span className={`absolute top-1 right-1 w-1.5 h-1.5 rounded-full ${
            isVoid ? 'bg-navy-800' : up ? c.dot : 'bg-navy-600'
          }`} />

          {/* Port label */}
          <span className={`text-xs font-mono font-bold ${
            isVoid ? 'text-navy-600' : up ? c.text : 'text-navy-500'
          }`}>
            {bp.label}
          </span>

          {/* Connector type */}
          <span className="text-[9px] text-navy-500 mt-0.5">{bp.connector}</span>

          {/* VOID label for void ports */}
          {isVoid && (
            <span className="text-[8px] text-navy-700 font-mono">VOID</span>
          )}

          {/* Speed */}
          {!isVoid && speed && (
            <span className="text-[8px] text-navy-600">{speed}</span>
          )}

          {/* Tagged VLAN dots (not for WAN or void) */}
          {!isVoid && !isWanPort && iface && renderTaggedDots(iface)}
        </button>
      )
    }

    return (
      <div className="bg-navy-950 border border-navy-800/50 rounded-xl p-5">
        {/* Device header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-navy-800 border border-navy-700/50 flex items-center justify-center">
              <svg className="w-4 h-4 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="2" y="3" width="20" height="18" rx="2" />
                <line x1="2" y1="9" x2="22" y2="9" />
                <circle cx="6" cy="6" r="1" fill="currentColor" />
                <circle cx="10" cy="6" r="1" fill="currentColor" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-gray-200">{boardInfo.short_name}</p>
              <p className="text-[10px] text-navy-500">{boardInfo.model}</p>
            </div>
          </div>
          <span className="text-[10px] text-navy-500 font-mono">Board: {boardInfo.board_id}</span>
        </div>

        {/* Port layout — mimics physical front panel */}
        <div className="flex items-end gap-6">
          {/* LAN ports group */}
          {lanPorts.length > 0 && (
            <div>
              <p className="text-[9px] text-navy-600 uppercase tracking-wider mb-1.5 text-center">LAN</p>
              <div className="flex gap-1.5">
                {lanPorts.map(p => renderPort(p))}
              </div>
            </div>
          )}

          {/* MGMT port */}
          {mgmtPort && (
            <div>
              <p className="text-[9px] text-navy-600 uppercase tracking-wider mb-1.5 text-center">MGMT</p>
              <div className="flex gap-1.5">
                {renderPort(mgmtPort)}
              </div>
            </div>
          )}

          {/* Divider */}
          <div className="w-px h-16 bg-navy-800/50 self-center" />

          {/* WAN ports */}
          {wanPorts.length > 0 && (
            <div>
              <p className="text-[9px] text-navy-600 uppercase tracking-wider mb-1.5 text-center">WAN</p>
              <div className="flex gap-1.5">
                {wanPorts.map(p => renderPort(p))}
              </div>
            </div>
          )}

          {/* SFP+ ports */}
          {sfpPorts.length > 0 && (
            <div>
              <p className="text-[9px] text-navy-600 uppercase tracking-wider mb-1.5 text-center">SFP+</p>
              <div className="flex gap-1.5">
                {sfpPorts.map(p => renderPort(p, 'sfp'))}
              </div>
            </div>
          )}
        </div>

        {/* Zone legend — based on zone data from API */}
        <div className="flex flex-wrap items-center justify-center gap-4 mt-4 pt-3 border-t border-navy-800/30">
          {legendZones
            .filter((z, i, arr) => arr.indexOf(z) === i) // unique
            .sort((a, b) => zoneOrder.indexOf(a) - zoneOrder.indexOf(b))
            .map(z => {
              const c = zoneColor(z)
              return (
                <div key={z} className="flex items-center gap-1.5">
                  <span className={`w-2 h-2 rounded-full ${c.dot}`} />
                  <span className={`text-[10px] font-medium uppercase tracking-wider ${c.text}`}>{z}</span>
                </div>
              )
            })}
          {/* Void indicator */}
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-navy-700" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-navy-600">void</span>
          </div>
        </div>
      </div>
    )
  }

  // ── Generic switch panel (no hardware board detected) ───────────────────
  const renderGenericSwitch = () => (
    <div className="bg-navy-950 border border-navy-800/50 rounded-xl p-4">
      <div className="flex flex-wrap gap-2 justify-center">
        {interfaces
          .filter(i => i.vlan_id == null)
          .sort((a, b) => {
            if (a.name.startsWith('br-') && !b.name.startsWith('br-')) return -1
            if (!a.name.startsWith('br-') && b.name.startsWith('br-')) return 1
            return a.name.localeCompare(b.name, undefined, { numeric: true })
          })
          .map(iface => {
            const zone = pvid2Zone(iface.pvid)
            const isVoid = zone === 'void'
            const isWanPort = zone === 'wan'
            const c = zoneColor(zone)
            const isUp = iface.is_up && iface.enabled
            const isBridge = iface.name.startsWith('br-')
            const members = isBridge ? bridgeMembers.get(iface.name) ?? [] : []
            const label = iface.name.startsWith('br-')
              ? iface.name.replace('br-', '').toUpperCase()
              : iface.name.match(/^eth(\d+)$/)?.[1] != null
                ? String(Number(iface.name.match(/^eth(\d+)$/)![1]) + 1)
                : iface.name

            return (
              <button
                key={iface.name}
                onClick={() => handlePortClick(iface)}
                className={`relative group flex flex-col items-center justify-center rounded-lg border transition-all
                  ${isBridge ? 'min-w-[100px] px-3' : 'w-[56px]'} h-[72px]
                  ${isVoid
                    ? 'bg-navy-950 border-navy-800/20 opacity-60'
                    : isUp
                      ? `${c.bg} ${c.border} shadow-md ${c.glow}`
                      : 'bg-navy-900/50 border-navy-800/30 opacity-50'
                  }
                  hover:scale-105 hover:brightness-125 cursor-pointer`}
              >
                {/* Link indicator dot */}
                <span className={`absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full ${
                  isVoid ? 'bg-navy-800' : isUp ? c.dot : 'bg-navy-600'
                }`} />

                {/* Port label */}
                <span className={`text-xs font-mono font-bold ${
                  isVoid ? 'text-navy-600' : isUp ? c.text : 'text-navy-500'
                }`}>
                  {label}
                </span>

                {/* Port type or VOID label */}
                {isVoid ? (
                  <span className="text-[8px] text-navy-700 font-mono mt-0.5">VOID</span>
                ) : (
                  <span className="text-[9px] text-navy-500 mt-0.5">
                    {portTypeLabel(iface.port_type)}
                  </span>
                )}

                {/* Bridge member count */}
                {isBridge && members.length > 0 && (
                  <span className="text-[8px] text-navy-600 mt-0.5 truncate max-w-[90px]">
                    {members.length} ports
                  </span>
                )}

                {/* Speed */}
                {!isVoid && iface.speed && (
                  <span className="text-[8px] text-navy-600">
                    {iface.speed}
                  </span>
                )}

                {/* Tagged VLAN dots */}
                {!isVoid && !isWanPort && !isBridge && renderTaggedDots(iface)}
              </button>
            )
          })}
      </div>

      {/* Zone legend */}
      <div className="flex flex-wrap items-center justify-center gap-4 mt-4 pt-3 border-t border-navy-800/30">
        {legendZones
          .filter((z, i, arr) => arr.indexOf(z) === i)
          .sort((a, b) => zoneOrder.indexOf(a) - zoneOrder.indexOf(b))
          .map(z => {
            const c = zoneColor(z)
            return (
              <div key={z} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${c.dot}`} />
                <span className={`text-[10px] font-medium uppercase tracking-wider ${c.text}`}>{z}</span>
              </div>
            )
          })}
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-navy-700" />
          <span className="text-[10px] font-medium uppercase tracking-wider text-navy-600">void</span>
        </div>
      </div>
    </div>
  )

  // ── Port config panel helpers ───────────────────────────────────────────

  // Resolve the PVID zone info for the config panel header
  const configZone = configPort ? pvid2Zone(configPvid) : 'guest'
  const configZoneColor = zoneColor(configZone)

  // Build zone options for PVID selector:
  // - WAN: pvid=0, special red styling
  // - void: pvid=1, special dark styling
  // - all other zones: pvid = zone.vlan_id
  interface PvidOption {
    pvid: number
    label: string
    zone: string
    dotClass: string
    textClass: string
    borderClass: string
    bgClass: string
  }

  const pvidOptions: PvidOption[] = [
    {
      pvid: 0,
      label: 'WAN (no internal VLAN)',
      zone: 'wan',
      dotClass: ZONE_COLORS.wan.dot,
      textClass: ZONE_COLORS.wan.text,
      borderClass: ZONE_COLORS.wan.border,
      bgClass: ZONE_COLORS.wan.bg,
    },
    ...zones
      .filter(z => z.zone.toLowerCase() !== 'wan' && z.vlan_id != null)
      .sort((a, b) => {
        // void last, then sort by vlan_id
        if (a.zone.toLowerCase() === 'void') return 1
        if (b.zone.toLowerCase() === 'void') return -1
        return (a.vlan_id ?? 0) - (b.vlan_id ?? 0)
      })
      .map(z => {
        const isVoid = z.zone.toLowerCase() === 'void'
        const c = zoneColor(z.zone.toLowerCase())
        return {
          pvid: z.vlan_id!,
          label: isVoid
            ? `VOID — VLAN ${z.vlan_id} (isolated — all traffic dropped)`
            : `${z.zone.toUpperCase()} (VLAN ${z.vlan_id})`,
          zone: z.zone.toLowerCase(),
          dotClass: c.dot,
          textClass: c.text,
          borderClass: c.border,
          bgClass: c.bg,
        }
      }),
  ]

  // Zones available for tagged VLAN checklist:
  // - exclude void zone
  // - exclude the current PVID zone (it's already the primary)
  // - only zones with a vlan_id
  const taggedOptions = zones.filter(z => {
    if (z.vlan_id == null) return false
    if (z.zone.toLowerCase() === 'void') return false
    if (z.vlan_id === configPvid) return false  // already primary
    if (z.zone.toLowerCase() === 'wan') return false  // WAN has no internal VLAN
    return true
  })

  // WAN ports (pvid=0) and void ports (pvid=1) can't carry tagged VLANs
  const taggedDisabled = configPvid === 0 || configPvid === 1

  return (
    <div className="space-y-6 stagger-children">
      <PageHeader
        title="Interfaces"
        subtitle={board ? `${board.short_name} — ${board.port_count} ports` : 'Hardware ports, VLANs, and virtual interfaces'}
      />

      {interfaces.length === 0 ? (
        <EmptyState
          icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="6" width="20" height="12" rx="2" /><circle cx="6" cy="12" r="1.5" /><circle cx="10" cy="12" r="1.5" /></svg>}
          title="No interfaces found"
          description="Network interfaces will appear here once detected."
        />
      ) : (
        <>
          {/* Visual Switch Panel */}
          <Card noPadding>
            <div className="p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-xs text-navy-400 uppercase tracking-wider font-medium">
                    {board ? 'Device Ports' : 'Port Overview'}
                  </p>
                </div>
                <Button size="sm" onClick={openVlanModal}>+ Create VLAN</Button>
              </div>

              {board ? renderDeviceSwitch(board) : renderGenericSwitch()}
            </div>
          </Card>

          {/* Bridges & Virtual Interfaces (not shown in device view since board only shows physical) */}
          {board && interfaces.filter(i => i.name.startsWith('br-')).length > 0 && (
            <Card noPadding>
              <div className="p-5">
                <p className="text-xs text-navy-400 uppercase tracking-wider font-medium mb-3">Bridges</p>
                <div className="space-y-2">
                  {interfaces.filter(i => i.name.startsWith('br-')).map(br => {
                    const brZone = br.name.replace('br-', '')
                    const c = zoneColor(brZone)
                    const members = bridgeMembers.get(br.name) ?? []
                    return (
                      <div key={br.name} className={`rounded-lg border ${c.border} ${c.bg} p-3`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-xs font-mono font-semibold text-gray-200">{br.name}</span>
                            <Badge variant={roleVariant(brZone)}>{brZone.toUpperCase()}</Badge>
                            {br.ips?.map((ip, i) => (
                              <span key={i} className="text-xs font-mono text-gray-400">{ip}</span>
                            ))}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono text-navy-500">MTU {br.mtu}</span>
                            <Toggle checked={br.enabled} onChange={() => handleToggle(br)} />
                            <Button variant="secondary" size="sm" onClick={() => openEdit(br)}>Edit</Button>
                          </div>
                        </div>
                        {members.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {members.map(m => {
                              const mi = ifaceByName.get(m)
                              const mUp = mi?.is_up && mi?.enabled
                              return (
                                <span
                                  key={m}
                                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono border
                                    ${mUp ? 'bg-navy-800/50 border-navy-700/50 text-gray-300' : 'bg-navy-900/50 border-navy-800/30 text-navy-600'}`}
                                >
                                  <span className={`w-1 h-1 rounded-full ${mUp ? c.dot : 'bg-navy-600'}`} />
                                  {m}
                                  {mi?.speed && <span className="text-navy-500">{mi.speed}</span>}
                                </span>
                              )
                            })}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            </Card>
          )}

          {/* Zone Cards */}
          {sortedZones.map(([zone, ifaces]) => {
            const c = zoneColor(zone)
            const bridges = ifaces.filter(i => i.name.startsWith('br-'))
            const ports = ifaces.filter(i => !i.name.startsWith('br-') && i.vlan_id == null)
            const vlans = ifaces.filter(i => i.vlan_id != null)
            const primaryBridge = bridges[0]
            const primaryIp = primaryBridge?.ips?.[0] ?? ports.find(p => p.ips?.length)?.ips?.[0]

            return (
              <Card key={zone} noPadding>
                <div className="p-5">
                  {/* Zone header */}
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${c.dot}`} />
                      <div>
                        <h3 className={`text-sm font-bold uppercase tracking-wider ${c.text}`}>{zone}</h3>
                        {primaryIp && (
                          <span className="text-xs font-mono text-navy-400">{primaryIp}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-navy-500">
                        {ifaces.filter(i => i.is_up && i.enabled).length}/{ifaces.length} up
                      </span>
                    </div>
                  </div>

                  {/* Bridge info (only in non-board mode) */}
                  {!board && bridges.map(br => {
                    const members = bridgeMembers.get(br.name) ?? []
                    return (
                      <div key={br.name} className={`rounded-lg border ${c.border} ${c.bg} p-3 mb-3`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-xs font-mono font-semibold text-gray-200">{br.name}</span>
                            <Badge variant={roleVariant(zone)}>Bridge</Badge>
                            {br.ips?.map((ip, i) => (
                              <span key={i} className="text-xs font-mono text-gray-400">{ip}</span>
                            ))}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono text-navy-500">MTU {br.mtu}</span>
                            <Toggle checked={br.enabled} onChange={() => handleToggle(br)} />
                            <Button variant="secondary" size="sm" onClick={() => openEdit(br)}>Edit</Button>
                          </div>
                        </div>
                        {members.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {members.map(m => {
                              const mi = ifaceByName.get(m)
                              const mUp = mi?.is_up && mi?.enabled
                              return (
                                <span
                                  key={m}
                                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono border
                                    ${mUp ? 'bg-navy-800/50 border-navy-700/50 text-gray-300' : 'bg-navy-900/50 border-navy-800/30 text-navy-600'}`}
                                >
                                  <span className={`w-1 h-1 rounded-full ${mUp ? c.dot : 'bg-navy-600'}`} />
                                  {m}
                                  {mi?.speed && <span className="text-navy-500">{mi.speed}</span>}
                                </span>
                              )
                            })}
                          </div>
                        )}
                      </div>
                    )
                  })}

                  {/* Non-bridge ports */}
                  {ports.filter(p => !bridges.some(br => (bridgeMembers.get(br.name) ?? []).includes(p.name))).length > 0 && (
                    <div className="space-y-1.5">
                      {ports
                        .filter(p => !bridges.some(br => (bridgeMembers.get(br.name) ?? []).includes(p.name)))
                        .map(iface => (
                          <div key={iface.name} className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-navy-800/20 transition-colors group">
                            <div className="flex items-center gap-3">
                              <span className={`w-2 h-2 rounded-full ${iface.is_up && iface.enabled ? c.dot : 'bg-navy-600'}`} />
                              <span className="text-sm font-mono font-semibold text-gray-200">{iface.name}</span>
                              {iface.port_type && (
                                <span className="text-[10px] text-navy-500">{portTypeLabel(iface.port_type)}</span>
                              )}
                              {iface.speed && (
                                <span className="px-1.5 py-0.5 rounded bg-navy-800 border border-navy-700/50 text-[9px] font-mono text-gray-400">{iface.speed}</span>
                              )}
                              {iface.ips?.map((ip, i) => (
                                <span key={i} className="text-xs font-mono text-gray-400">{ip}</span>
                              ))}
                            </div>
                            <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                              <span className="text-[10px] font-mono text-navy-500">MTU {iface.mtu}</span>
                              <Toggle checked={iface.enabled} onChange={() => handleToggle(iface)} />
                              <Button variant="secondary" size="sm" onClick={() => openEdit(iface)}>Edit</Button>
                            </div>
                          </div>
                        ))}
                    </div>
                  )}

                  {/* VLANs in this zone */}
                  {vlans.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-navy-800/30">
                      <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-2">VLANs</p>
                      <div className="space-y-1.5">
                        {vlans.map(vlan => {
                          const parentName = vlan.name.includes('.') ? vlan.name.split('.')[0] : '---'
                          return (
                            <div key={vlan.name} className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-navy-800/20 transition-colors group">
                              <div className="flex items-center gap-3">
                                <span className={`w-2 h-2 rounded-full ${vlan.is_up && vlan.enabled ? c.dot : 'bg-navy-600'}`} />
                                <span className="text-sm font-mono text-gray-200">{vlan.name}</span>
                                <span className="px-1.5 py-0.5 rounded bg-navy-800 border border-navy-700/50 text-[9px] font-mono text-gray-300">VID {vlan.vlan_id}</span>
                                <span className="text-[10px] text-navy-500">on {parentName}</span>
                              </div>
                              <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                <Toggle checked={vlan.enabled} onChange={() => handleToggle(vlan)} />
                                <Button variant="secondary" size="sm" onClick={() => openEdit(vlan)}>Edit</Button>
                                <Button variant="danger" size="sm" onClick={() => handleDeleteVlan(vlan.name)}>Delete</Button>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </Card>
            )
          })}

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
                  options={physicalOnly.map((i) => ({
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

          {/* Edit Interface Modal (bridges and VLAN sub-interfaces only) */}
          <Modal open={editIface !== null} onClose={() => setEditIface(null)} title={`Edit: ${editIface?.name ?? ''}`}>
            <div className="space-y-4">
              {editIface && (
                <div className={`rounded-lg border p-3 flex items-center gap-3 ${zoneColor(pvid2Zone(editIface.pvid)).border} ${zoneColor(pvid2Zone(editIface.pvid)).bg}`}>
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

          {/* Port Config Panel — for physical ports */}
          <Modal
            open={configPort !== null}
            onClose={() => setConfigPort(null)}
            title={`Configure: ${configPort?.name ?? ''}`}
            size="lg"
          >
            {configPort && (
              <div className="space-y-5">
                {/* Section 1: Port Info (read-only) */}
                <div className={`rounded-lg border p-3 flex items-center gap-4 ${configZoneColor.border} ${configZoneColor.bg}`}>
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${configZoneColor.dot}`} />
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                    <span className="font-mono font-semibold text-gray-200">{configPort.name}</span>
                    {configPort.mac && (
                      <span className="font-mono text-navy-400">{configPort.mac}</span>
                    )}
                    {configPort.port_type && (
                      <span className="text-navy-400">{portTypeLabel(configPort.port_type)}</span>
                    )}
                    {configPort.speed && (
                      <span className="text-navy-400">{configPort.speed}</span>
                    )}
                    <span className={`font-medium ${configPort.is_up && configPort.enabled ? 'text-emerald-400' : 'text-navy-500'}`}>
                      {configPort.is_up && configPort.enabled ? 'Link Up' : 'Link Down'}
                    </span>
                  </div>
                </div>

                {/* Section 2: Primary Zone (PVID) */}
                <div>
                  <p className="text-xs text-navy-400 uppercase tracking-wider font-medium mb-2">Primary Zone (PVID)</p>
                  <div className="space-y-1.5">
                    {pvidOptions.map(opt => {
                      const selected = configPvid === opt.pvid
                      return (
                        <button
                          key={opt.pvid}
                          onClick={() => {
                            setConfigPvid(opt.pvid)
                            // Remove any tagged VLANs that would conflict with new PVID
                            setConfigTagged(prev => prev.filter(v => v !== opt.pvid))
                          }}
                          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border text-left transition-all
                            ${selected
                              ? `${opt.bgClass} ${opt.borderClass} ring-1 ring-inset ${opt.borderClass}`
                              : 'bg-navy-900/30 border-navy-800/40 hover:bg-navy-800/30'
                            }`}
                        >
                          {/* Radio indicator */}
                          <span className={`w-4 h-4 rounded-full border-2 flex items-center justify-center flex-shrink-0 transition-colors
                            ${selected ? `${opt.borderClass} border-current` : 'border-navy-600'}`}>
                            {selected && (
                              <span className={`w-2 h-2 rounded-full ${opt.dotClass}`} />
                            )}
                          </span>
                          {/* Zone color dot */}
                          <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${opt.dotClass}`} />
                          {/* Zone label */}
                          <span className={`text-sm font-medium ${selected ? opt.textClass : 'text-navy-300'}`}>
                            {opt.label}
                          </span>
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Section 3: Tagged VLANs */}
                <div>
                  <p className="text-xs text-navy-400 uppercase tracking-wider font-medium mb-2">
                    Additional Tagged VLANs
                    {taggedDisabled && (
                      <span className="ml-2 text-navy-600 normal-case font-normal">
                        {configPvid === 0 ? '— not available on WAN ports' : '— not available on void ports'}
                      </span>
                    )}
                  </p>
                  {taggedOptions.length === 0 && !taggedDisabled ? (
                    <p className="text-xs text-navy-500 italic">No additional zones available to tag.</p>
                  ) : (
                    <div className={`space-y-1.5 ${taggedDisabled ? 'opacity-40 pointer-events-none' : ''}`}>
                      {taggedOptions.map(z => {
                        const c = zoneColor(z.zone.toLowerCase())
                        const checked = configTagged.includes(z.vlan_id!)
                        return (
                          <button
                            key={z.vlan_id}
                            onClick={() => toggleTaggedVlan(z.vlan_id!)}
                            disabled={taggedDisabled}
                            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border text-left transition-all
                              ${checked
                                ? `${c.bg} ${c.border}`
                                : 'bg-navy-900/30 border-navy-800/40 hover:bg-navy-800/30'
                              }`}
                          >
                            {/* Checkbox indicator */}
                            <span className={`w-4 h-4 rounded border-2 flex items-center justify-center flex-shrink-0 transition-colors
                              ${checked ? `${c.border} border-current bg-current/20` : 'border-navy-600'}`}>
                              {checked && (
                                <svg className={`w-2.5 h-2.5 ${c.text}`} viewBox="0 0 10 10" fill="none">
                                  <path d="M1.5 5L4 7.5L8.5 2.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                              )}
                            </span>
                            {/* Zone color dot */}
                            <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${c.dot}`} />
                            {/* Zone label */}
                            <span className={`text-sm font-medium ${checked ? c.text : 'text-navy-300'}`}>
                              {z.zone.toUpperCase()} (VLAN {z.vlan_id})
                            </span>
                          </button>
                        )
                      })}
                    </div>
                  )}
                </div>

                {/* Section 4: Actions */}
                <div className="flex gap-2 pt-1 border-t border-navy-800/30">
                  <Button
                    onClick={handleSavePortConfig}
                    disabled={saving}
                  >
                    {saving ? 'Saving...' : 'Save'}
                  </Button>
                  <Button variant="secondary" onClick={() => setConfigPort(null)} disabled={saving}>
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </Modal>
        </>
      )}
    </div>
  )
}
