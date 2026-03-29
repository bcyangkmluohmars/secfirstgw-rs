// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useEffect, useState, useCallback } from 'react'
import { api, type SwitchAsicState, type SwitchPortState, type SwitchMcEntry, type SwitchVlan4kEntry } from '../../api'
import { Spinner, Card, Badge, Button } from '../../components/ui'
import { useToast } from '../../hooks/useToast'

const hex = (v: number, digits = 4) => `0x${v.toString(16).toUpperCase().padStart(digits, '0')}`
const bin = (v: number, bits: number) => v.toString(2).padStart(bits, '0')

/** Render a port bitmask as colored port labels (P0-P10). */
function PortMask({ mask, maxPort = 10 }: { mask: number; maxPort?: number }) {
  const ports: React.ReactNode[] = []
  for (let p = 0; p <= maxPort; p++) {
    const isMember = (mask >> p) & 1
    ports.push(
      <span
        key={p}
        className={`inline-block w-5 text-center text-[10px] font-mono rounded ${
          isMember
            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
            : 'bg-navy-900/50 text-navy-600 border border-navy-800/30'
        }`}
        title={`Port ${p}: ${isMember ? 'member' : 'not member'}`}
      >
        {p}
      </span>
    )
  }
  return <div className="flex gap-0.5">{ports}</div>
}

function SpeedLabel({ mbps }: { mbps: number }) {
  if (mbps === 1000) return <span className="text-emerald-400">1G</span>
  if (mbps === 100) return <span className="text-amber-400">100M</span>
  if (mbps === 10) return <span className="text-red-400">10M</span>
  return <span className="text-navy-500">?</span>
}

function PortStatusTable({ ports }: { ports: SwitchPortState[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-navy-400 uppercase tracking-wider text-[10px]">
            <th className="text-left py-2 px-2">Port</th>
            <th className="text-left py-2 px-2">Link</th>
            <th className="text-left py-2 px-2">Speed</th>
            <th className="text-left py-2 px-2">Duplex</th>
            <th className="text-left py-2 px-2">PVID MC#</th>
            <th className="text-left py-2 px-2">Isolation</th>
            <th className="text-left py-2 px-2">Status Raw</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-navy-800/30">
          {ports.map(p => (
            <tr key={p.port} className="hover:bg-navy-800/20 transition-colors">
              <td className="py-1.5 px-2 font-mono font-semibold text-gray-200">
                P{p.port}
                {p.port === 9 && <span className="ml-1 text-navy-500 text-[9px]">(CPU)</span>}
                {p.port === 10 && <span className="ml-1 text-navy-500 text-[9px]">(INT)</span>}
              </td>
              <td className="py-1.5 px-2">
                <span className={`inline-flex items-center gap-1 ${p.link_up ? 'text-emerald-400' : 'text-navy-500'}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${p.link_up ? 'bg-emerald-400' : 'bg-navy-600'}`} />
                  {p.link_up ? 'UP' : 'DOWN'}
                </span>
              </td>
              <td className="py-1.5 px-2 font-mono">
                {p.link_up ? <SpeedLabel mbps={p.speed_mbps} /> : <span className="text-navy-600">—</span>}
              </td>
              <td className="py-1.5 px-2 font-mono text-navy-300">
                {p.link_up ? (p.full_duplex ? 'FD' : 'HD') : <span className="text-navy-600">—</span>}
              </td>
              <td className="py-1.5 px-2 font-mono text-navy-300">{p.pvid_mc_index}</td>
              <td className="py-1.5 px-2">
                <PortMask mask={p.isolation_mask} />
              </td>
              <td className="py-1.5 px-2 font-mono text-navy-500">{hex(p.status_raw)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function McTable({ entries }: { entries: SwitchMcEntry[] }) {
  if (entries.length === 0) {
    return <p className="text-xs text-navy-500 italic">No MC entries programmed.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-navy-400 uppercase tracking-wider text-[10px]">
            <th className="text-left py-2 px-2">MC#</th>
            <th className="text-left py-2 px-2">VID</th>
            <th className="text-left py-2 px-2">FID</th>
            <th className="text-left py-2 px-2">Member Ports</th>
            <th className="text-left py-2 px-2">Mask (hex)</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-navy-800/30">
          {entries.map(e => (
            <tr key={e.index} className="hover:bg-navy-800/20 transition-colors">
              <td className="py-1.5 px-2 font-mono font-semibold text-gray-200">{e.index}</td>
              <td className="py-1.5 px-2 font-mono text-blue-400">{e.vid}</td>
              <td className="py-1.5 px-2 font-mono text-navy-300">{e.fid}</td>
              <td className="py-1.5 px-2"><PortMask mask={e.member_mask} /></td>
              <td className="py-1.5 px-2 font-mono text-navy-500">{hex(e.member_mask, 3)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Vlan4kTable({ entries }: { entries: SwitchVlan4kEntry[] }) {
  if (entries.length === 0) {
    return <p className="text-xs text-navy-500 italic">No 4K VLAN entries.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-navy-400 uppercase tracking-wider text-[10px]">
            <th className="text-left py-2 px-2">VID</th>
            <th className="text-left py-2 px-2">FID</th>
            <th className="text-left py-2 px-2">Member Ports</th>
            <th className="text-left py-2 px-2">Untagged Ports</th>
            <th className="text-left py-2 px-2">MBR (hex)</th>
            <th className="text-left py-2 px-2">UNTAG (hex)</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-navy-800/30">
          {entries.map(e => (
            <tr key={e.vid} className="hover:bg-navy-800/20 transition-colors">
              <td className="py-1.5 px-2 font-mono font-semibold text-blue-400">{e.vid}</td>
              <td className="py-1.5 px-2 font-mono text-navy-300">{e.fid}</td>
              <td className="py-1.5 px-2"><PortMask mask={e.member_mask} /></td>
              <td className="py-1.5 px-2"><PortMask mask={e.untag_mask} /></td>
              <td className="py-1.5 px-2 font-mono text-navy-500">{hex(e.member_mask, 3)}</td>
              <td className="py-1.5 px-2 font-mono text-navy-500">{hex(e.untag_mask, 3)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function GlobalConfigPanel({ global, chipId, chipVersion }: {
  global: SwitchAsicState['global']
  chipId: number
  chipVersion: number
}) {
  const items: [string, string | React.ReactNode][] = [
    ['Chip ID', hex(chipId)],
    ['Chip Version', hex(chipVersion)],
    ['SGCR', hex(global.sgcr_raw)],
    ['VLAN Enabled', global.vlan_enabled ? 'Yes' : 'No'],
    ['4K VLAN Enabled', global.vlan_4k_enabled ? 'Yes' : 'No'],
    ['Ingress Filter', `${hex(global.ingress_filter_raw)} (${bin(global.ingress_filter_raw, 11)})`],
    ['STP State', `${hex(global.stp_state[0])} ${hex(global.stp_state[1])}`],
    ['EXT Mode', hex(global.ext_mode)],
    ['EXT1 Force', hex(global.ext1_force)],
    ['EXT1 RGMXF', hex(global.ext1_rgmxf)],
    ['CPU Port Mask', hex(global.cpu_port_mask)],
    ['CPU Port Ctrl', hex(global.cpu_port_ctrl)],
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
      {items.map(([label, value]) => (
        <div key={label} className="bg-navy-900/50 border border-navy-800/30 rounded-lg px-3 py-2">
          <p className="text-[10px] text-navy-500 uppercase tracking-wider">{label}</p>
          <p className="text-xs font-mono text-gray-300 mt-0.5">{value}</p>
        </div>
      ))}
    </div>
  )
}

export default function SwitchTab() {
  const [state, setState] = useState<SwitchAsicState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.getSwitchState()
      if (!res.available) {
        setError(res.error ?? 'No hardware switch detected')
        setState(null)
      } else if (res.state) {
        setState(res.state)
      }
    } catch (e: unknown) {
      const msg = (e as Error).message
      setError(msg)
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  if (loading) return <Spinner label="Reading switch registers..." />

  if (error || !state) {
    return (
      <Card>
        <div className="text-center py-8">
          <p className="text-sm text-navy-400">{error ?? 'No switch data available'}</p>
        </div>
      </Card>
    )
  }

  const CHIP_NAMES: Record<number, string> = {
    0x6368: 'RTL8370MB',  // CHIP_RTL8370B — Ubiquiti-branded RTL8367C
    0x0652: 'RTL8370B',
    0x6367: 'RTL8367C',
    0x0276: 'RTL8367C',
    0x0597: 'RTL8367C',
  }
  const chipName = CHIP_NAMES[state.chip_id] ?? `Unknown (${hex(state.chip_id)})`

  return (
    <div className="space-y-4 stagger-children">
      {/* Chip info header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-navy-800 border border-navy-700/50 flex items-center justify-center">
            <svg className="w-4 h-4 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="6" y="6" width="12" height="12" rx="1" />
              <line x1="6" y1="10" x2="2" y2="10" /><line x1="6" y1="14" x2="2" y2="14" />
              <line x1="18" y1="10" x2="22" y2="10" /><line x1="18" y1="14" x2="22" y2="14" />
              <line x1="10" y1="6" x2="10" y2="2" /><line x1="14" y1="6" x2="14" y2="2" />
              <line x1="10" y1="18" x2="10" y2="22" /><line x1="14" y1="18" x2="14" y2="22" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-semibold text-gray-200">{chipName}</p>
            <p className="text-[10px] text-navy-500">
              ID: {hex(state.chip_id)} &middot; Rev: {hex(state.chip_version)} &middot; {state.ports.length} ports
            </p>
          </div>
        </div>
        <Button size="sm" variant="secondary" onClick={load}>Refresh</Button>
      </div>

      {/* Global Configuration */}
      <Card noPadding>
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <p className="text-xs text-navy-400 uppercase tracking-wider font-medium">Global Configuration</p>
            <Badge variant={state.global.vlan_enabled ? 'success' : 'warning'}>
              VLAN {state.global.vlan_enabled ? 'ON' : 'OFF'}
            </Badge>
            <Badge variant={state.global.vlan_4k_enabled ? 'success' : 'warning'}>
              4K {state.global.vlan_4k_enabled ? 'ON' : 'OFF'}
            </Badge>
          </div>
          <GlobalConfigPanel global={state.global} chipId={state.chip_id} chipVersion={state.chip_version} />
        </div>
      </Card>

      {/* Port Status */}
      <Card noPadding>
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <p className="text-xs text-navy-400 uppercase tracking-wider font-medium">Port Status</p>
            <Badge variant="info">
              {state.ports.filter(p => p.link_up).length}/{state.ports.length} up
            </Badge>
          </div>
          <PortStatusTable ports={state.ports} />
        </div>
      </Card>

      {/* MC Table */}
      <Card noPadding>
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <p className="text-xs text-navy-400 uppercase tracking-wider font-medium">VLAN MC Table</p>
            <Badge variant="neutral">{state.mc_table.length} entries</Badge>
          </div>
          <p className="text-[10px] text-navy-500 mb-2">
            Member Configuration table — 32 direct-mapped entries. Ports reference VLANs by MC index, not VID.
          </p>
          <McTable entries={state.mc_table} />
        </div>
      </Card>

      {/* 4K VLAN Table */}
      <Card noPadding>
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <p className="text-xs text-navy-400 uppercase tracking-wider font-medium">4K VLAN Table</p>
            <Badge variant="neutral">{state.vlan_4k_table.length} entries</Badge>
          </div>
          <p className="text-[10px] text-navy-500 mb-2">
            Hardware forwarding table — actual VLAN membership and untagged port masks used by the ASIC.
          </p>
          <Vlan4kTable entries={state.vlan_4k_table} />
        </div>
      </Card>
    </div>
  )
}
