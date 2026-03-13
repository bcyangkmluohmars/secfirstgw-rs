// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type FirewallRule } from '../api'
import { Card, PageHeader, Spinner, Button, Badge, Toggle, Modal, Input, Select, EmptyState } from '../components/ui'
import { useToast } from '../hooks/useToast'

const ZONES = ['WAN', 'LAN', 'DMZ', 'MGMT', 'GUEST'] as const
type ZoneAction = 'allow' | 'drop' | 'limit'

const ZONE_MATRIX: Record<string, Record<string, ZoneAction>> = {
  WAN:   { WAN: 'drop', LAN: 'drop',  DMZ: 'limit', MGMT: 'drop',  GUEST: 'drop'  },
  LAN:   { WAN: 'allow', LAN: 'allow', DMZ: 'allow', MGMT: 'drop',  GUEST: 'drop'  },
  DMZ:   { WAN: 'allow', LAN: 'drop',  DMZ: 'allow', MGMT: 'drop',  GUEST: 'drop'  },
  MGMT:  { WAN: 'allow', LAN: 'allow', DMZ: 'allow', MGMT: 'allow', GUEST: 'allow' },
  GUEST: { WAN: 'allow', LAN: 'drop',  DMZ: 'drop',  MGMT: 'drop',  GUEST: 'allow' },
}

const ZONE_TOOLTIPS: Record<string, Record<string, string>> = {
  WAN:   { WAN: 'No WAN-to-WAN', LAN: 'Default deny inbound', DMZ: 'Rate-limited HTTP/HTTPS', MGMT: 'Management isolated', GUEST: 'No inbound' },
  LAN:   { WAN: 'Full outbound', LAN: 'Intra-LAN', DMZ: 'LAN can access DMZ', MGMT: 'Management isolated', GUEST: 'Isolated' },
  DMZ:   { WAN: 'Internet access', LAN: 'DMZ cannot reach LAN', DMZ: 'Intra-DMZ', MGMT: 'Management isolated', GUEST: 'Isolated' },
  MGMT:  { WAN: 'Full outbound', LAN: 'Full management access', DMZ: 'Full management access', MGMT: 'Intra-MGMT', GUEST: 'Management access' },
  GUEST: { WAN: 'Internet-only', LAN: 'Guest isolated', DMZ: 'Guest isolated', MGMT: 'Guest isolated', GUEST: 'Intra-guest' },
}

const cellColors: Record<ZoneAction, string> = {
  allow: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  drop: 'bg-red-500/10 text-red-400 border-red-500/15',
  limit: 'bg-amber-500/10 text-amber-400 border-amber-500/15',
}

const actionVariant = (a: string) => a === 'accept' ? 'success' as const : a === 'drop' ? 'danger' as const : 'warning' as const

function ZoneMatrix() {
  const [tooltip, setTooltip] = useState<{ src: string; dst: string } | null>(null)

  return (
    <Card title="Zone Policy Matrix">
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr>
              <th className="px-2 py-2 text-left text-navy-500 font-medium"><span className="text-[10px]">SRC \ DST</span></th>
              {ZONES.map((z) => <th key={z} className="px-2 py-2 text-center text-navy-400 font-medium font-mono">{z}</th>)}
            </tr>
          </thead>
          <tbody>
            {ZONES.map((src) => (
              <tr key={src}>
                <td className="px-2 py-2 text-navy-400 font-medium font-mono">{src}</td>
                {ZONES.map((dst) => {
                  const action = ZONE_MATRIX[src][dst]
                  const isHovered = tooltip?.src === src && tooltip?.dst === dst
                  return (
                    <td key={dst} className="px-1 py-1 text-center relative">
                      <div
                        className={`px-2 py-1.5 rounded-md border font-mono font-bold text-[10px] cursor-default transition-all duration-150 ${cellColors[action]} ${isHovered ? 'ring-1 ring-white/20 scale-105' : ''}`}
                        onMouseEnter={() => setTooltip({ src, dst })}
                        onMouseLeave={() => setTooltip(null)}
                      >
                        {action.toUpperCase()}
                      </div>
                      {isHovered && (
                        <div className="absolute z-10 bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-navy-700 border border-navy-600/50 rounded-lg shadow-xl whitespace-nowrap animate-fade-in">
                          <p className="text-[11px] text-gray-200 font-medium">{src} &rarr; {dst}</p>
                          <p className="text-[10px] text-navy-400 mt-0.5">{ZONE_TOOLTIPS[src][dst]}</p>
                        </div>
                      )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

export default function Firewall() {
  const [rules, setRules] = useState<FirewallRule[]>([])
  const [loading, setLoading] = useState(true)
  const [applying, setApplying] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [chain, setChain] = useState('input')
  const [priority, setPriority] = useState(100)
  const [detail, setDetail] = useState({ action: 'drop', protocol: '', source: '', destination: '', port: '' as string, comment: '' })
  const toast = useToast()

  const load = useCallback(() => {
    api.getFirewallRules()
      .then((res) => setRules(res.rules))
      .catch((e: Error) => toast.error(e.message))
      .finally(() => setLoading(false))
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleToggle = async (rule: FirewallRule) => {
    try {
      await api.toggleFirewallRule(rule.id, !rule.enabled)
      setRules((prev) => prev.map((r) => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.deleteFirewallRule(id)
      setRules((prev) => prev.filter((r) => r.id !== id))
      toast.success('Rule deleted')
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleApply = async () => {
    setApplying(true)
    try {
      await api.applyFirewall()
      toast.success('Firewall rules applied')
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setApplying(false) }
  }

  const handleCreate = async () => {
    try {
      await api.createFirewallRule({
        chain, priority,
        detail: {
          action: detail.action,
          ...(detail.protocol ? { protocol: detail.protocol } : {}),
          ...(detail.source ? { source: detail.source } : {}),
          ...(detail.destination ? { destination: detail.destination } : {}),
          ...(detail.port ? { port: Number(detail.port) } : {}),
          ...(detail.comment ? { comment: detail.comment } : {}),
        },
        enabled: true,
      })
      setShowForm(false)
      setDetail({ action: 'drop', protocol: '', source: '', destination: '', port: '', comment: '' })
      toast.success('Rule created')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading firewall rules..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Firewall"
        actions={<>
          <Button onClick={() => setShowForm(true)}>+ Add Rule</Button>
          <Button variant="secondary" onClick={handleApply} loading={applying}>Apply Changes</Button>
        </>}
      />

      <ZoneMatrix />

      <Modal open={showForm} onClose={() => setShowForm(false)} title="New Firewall Rule" size="lg">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Select label="Chain" value={chain} onChange={(e) => setChain(e.target.value)} options={[
            { value: 'input', label: 'input' }, { value: 'forward', label: 'forward' }, { value: 'output', label: 'output' },
          ]} />
          <Input label="Priority" type="number" mono value={priority} onChange={(e) => setPriority(Number(e.target.value))} />
          <Select label="Action" value={detail.action} onChange={(e) => setDetail({ ...detail, action: e.target.value })} options={[
            { value: 'accept', label: 'accept' }, { value: 'drop', label: 'drop' }, { value: 'reject', label: 'reject' },
          ]} />
          <Select label="Protocol" value={detail.protocol} onChange={(e) => setDetail({ ...detail, protocol: e.target.value })} options={[
            { value: '', label: 'any' }, { value: 'tcp', label: 'tcp' }, { value: 'udp', label: 'udp' }, { value: 'icmp', label: 'icmp' },
          ]} />
          <Input label="Source" mono value={detail.source} onChange={(e) => setDetail({ ...detail, source: e.target.value })} placeholder="0.0.0.0/0" />
          <Input label="Destination" mono value={detail.destination} onChange={(e) => setDetail({ ...detail, destination: e.target.value })} placeholder="0.0.0.0/0" />
          <Input label="Port" mono value={detail.port} onChange={(e) => setDetail({ ...detail, port: e.target.value })} placeholder="Any" />
          <Input label="Comment" value={detail.comment} onChange={(e) => setDetail({ ...detail, comment: e.target.value })} />
        </div>
        <div className="flex gap-2 mt-5">
          <Button onClick={handleCreate}>Create Rule</Button>
          <Button variant="secondary" onClick={() => setShowForm(false)}>Cancel</Button>
        </div>
      </Modal>

      <div>
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Active Rules</p>
        {rules.length === 0 ? (
          <EmptyState
            icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" /></svg>}
            title="No firewall rules configured"
            description="Default deny policy is in effect"
          />
        ) : (
          <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-navy-800/50">
                    {['Chain', 'Pri', 'Action', 'Proto', 'Source', 'Destination', 'Port', 'Status', ''].map((h) => (
                      <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id} className={`border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors ${!rule.enabled ? 'opacity-40' : ''}`}>
                      <td className="px-4 py-3 font-mono text-gray-300 text-xs">{rule.chain}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{rule.priority}</td>
                      <td className="px-4 py-3"><Badge variant={actionVariant(rule.detail.action)}>{rule.detail.action}</Badge></td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs">{rule.detail.protocol || 'any'}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs">{rule.detail.source || '*'}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs">{rule.detail.destination || '*'}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{rule.detail.port ?? '*'}</td>
                      <td className="px-4 py-3"><Toggle checked={rule.enabled} onChange={() => handleToggle(rule)} /></td>
                      <td className="px-4 py-3"><Button variant="danger" size="sm" onClick={() => handleDelete(rule.id)}>Delete</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
