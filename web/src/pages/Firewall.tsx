import { useEffect, useState, useCallback } from 'react'
import { api, type FirewallRule } from '../api'

const EMPTY_DETAIL = { action: 'drop', protocol: '', source: '', destination: '', port: undefined as number | undefined, comment: '' }

// --- Zone Matrix ---
type ZoneAction = 'allow' | 'drop' | 'limit'

const ZONES = ['WAN', 'LAN', 'DMZ', 'MGMT', 'GUEST'] as const

const ZONE_MATRIX: Record<string, Record<string, ZoneAction>> = {
  WAN:   { WAN: 'drop', LAN: 'drop',  DMZ: 'limit', MGMT: 'drop',  GUEST: 'drop'  },
  LAN:   { WAN: 'allow', LAN: 'allow', DMZ: 'allow', MGMT: 'drop',  GUEST: 'drop'  },
  DMZ:   { WAN: 'allow', LAN: 'drop',  DMZ: 'allow', MGMT: 'drop',  GUEST: 'drop'  },
  MGMT:  { WAN: 'allow', LAN: 'allow', DMZ: 'allow', MGMT: 'allow', GUEST: 'allow' },
  GUEST: { WAN: 'allow', LAN: 'drop',  DMZ: 'drop',  MGMT: 'drop',  GUEST: 'allow' },
}

const ZONE_TOOLTIPS: Record<string, Record<string, string>> = {
  WAN:   { WAN: 'No WAN-to-WAN', LAN: 'Blocked — default deny inbound', DMZ: 'Rate-limited: HTTP/HTTPS only', MGMT: 'Blocked — management isolated', GUEST: 'Blocked — no inbound' },
  LAN:   { WAN: 'Full outbound access', LAN: 'Intra-LAN allowed', DMZ: 'LAN can access DMZ services', MGMT: 'Blocked — management isolated', GUEST: 'Blocked — isolation' },
  DMZ:   { WAN: 'DMZ can reach internet', LAN: 'Blocked — DMZ cannot reach LAN', DMZ: 'Intra-DMZ allowed', MGMT: 'Blocked — management isolated', GUEST: 'Blocked — isolation' },
  MGMT:  { WAN: 'Full outbound access', LAN: 'Full access for management', DMZ: 'Full access for management', MGMT: 'Intra-MGMT allowed', GUEST: 'Management can reach guest' },
  GUEST: { WAN: 'Internet-only access', LAN: 'Blocked — guest isolated', DMZ: 'Blocked — guest isolated', MGMT: 'Blocked — guest isolated', GUEST: 'Intra-guest allowed' },
}

const cellColors: Record<ZoneAction, string> = {
  allow: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  drop: 'bg-red-500/10 text-red-400 border-red-500/15',
  limit: 'bg-amber-500/10 text-amber-400 border-amber-500/15',
}

const cellLabels: Record<ZoneAction, string> = {
  allow: 'ALLOW',
  drop: 'DROP',
  limit: 'LIMIT',
}

function ZoneMatrix() {
  const [tooltip, setTooltip] = useState<{ src: string; dst: string } | null>(null)

  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
      <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-4">Zone Policy Matrix</p>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr>
              <th className="px-2 py-2 text-left text-navy-500 font-medium">
                <span className="text-[10px]">SRC \ DST</span>
              </th>
              {ZONES.map((z) => (
                <th key={z} className="px-2 py-2 text-center text-navy-400 font-medium font-mono">{z}</th>
              ))}
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
                        className={`
                          px-2 py-1.5 rounded-md border font-mono font-bold text-[10px] cursor-default
                          transition-all duration-150
                          ${cellColors[action]}
                          ${isHovered ? 'ring-1 ring-white/20 scale-105' : ''}
                        `}
                        onMouseEnter={() => setTooltip({ src, dst })}
                        onMouseLeave={() => setTooltip(null)}
                      >
                        {cellLabels[action]}
                      </div>
                      {isHovered && (
                        <div className="absolute z-10 bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-navy-700 border border-navy-600/50 rounded-lg shadow-xl whitespace-nowrap animate-fade-in">
                          <p className="text-[11px] text-gray-200 font-medium">{src} → {dst}</p>
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
    </div>
  )
}

// --- Main Firewall Page ---
export default function Firewall() {
  const [rules, setRules] = useState<FirewallRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [applying, setApplying] = useState(false)
  const [showForm, setShowForm] = useState(false)

  const [chain, setChain] = useState('input')
  const [priority, setPriority] = useState(100)
  const [detail, setDetail] = useState({ ...EMPTY_DETAIL })

  const load = useCallback(() => {
    api.getFirewallRules()
      .then((res) => { setRules(res.rules); setError(null) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const handleToggle = async (rule: FirewallRule) => {
    try {
      await api.toggleFirewallRule(rule.id, !rule.enabled)
      setRules((prev) => prev.map((r) => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.deleteFirewallRule(id)
      setRules((prev) => prev.filter((r) => r.id !== id))
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleApply = async () => {
    setApplying(true)
    try {
      await api.applyFirewall()
      setError(null)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setApplying(false)
    }
  }

  const handleCreate = async () => {
    try {
      const body: Omit<FirewallRule, 'id'> = {
        chain,
        priority,
        detail: {
          action: detail.action,
          ...(detail.protocol ? { protocol: detail.protocol } : {}),
          ...(detail.source ? { source: detail.source } : {}),
          ...(detail.destination ? { destination: detail.destination } : {}),
          ...(detail.port ? { port: detail.port } : {}),
          ...(detail.comment ? { comment: detail.comment } : {}),
        },
        enabled: true,
      }
      await api.createFirewallRule(body)
      setShowForm(false)
      setChain('input')
      setPriority(100)
      setDetail({ ...EMPTY_DETAIL })
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-navy-400">Loading firewall rules...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-100">Firewall</h2>
        <div className="flex gap-2">
          <button
            onClick={() => setShowForm(!showForm)}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors"
          >
            + Add Rule
          </button>
          <button
            onClick={handleApply}
            disabled={applying}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-navy-800 text-gray-300 border border-navy-700/50 hover:bg-navy-700/50 transition-colors disabled:opacity-50"
          >
            {applying ? 'Applying...' : 'Apply Changes'}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 animate-fade-in">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Zone Matrix */}
      <ZoneMatrix />

      {/* Add Rule Form */}
      {showForm && (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-4">New Rule</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Chain</span>
              <select value={chain} onChange={(e) => setChain(e.target.value)} className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50">
                <option value="input">input</option>
                <option value="forward">forward</option>
                <option value="output">output</option>
              </select>
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Priority</span>
              <input type="number" value={priority} onChange={(e) => setPriority(Number(e.target.value))} className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50" />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Action</span>
              <select value={detail.action} onChange={(e) => setDetail({ ...detail, action: e.target.value })} className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50">
                <option value="accept">accept</option>
                <option value="drop">drop</option>
                <option value="reject">reject</option>
              </select>
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Protocol</span>
              <select value={detail.protocol} onChange={(e) => setDetail({ ...detail, protocol: e.target.value })} className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50">
                <option value="">any</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
              </select>
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Source</span>
              <input type="text" value={detail.source} onChange={(e) => setDetail({ ...detail, source: e.target.value })} placeholder="0.0.0.0/0" className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 placeholder-navy-600 focus:outline-none focus:border-emerald-500/50" />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Destination</span>
              <input type="text" value={detail.destination} onChange={(e) => setDetail({ ...detail, destination: e.target.value })} placeholder="0.0.0.0/0" className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 placeholder-navy-600 focus:outline-none focus:border-emerald-500/50" />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Port</span>
              <input type="number" value={detail.port ?? ''} onChange={(e) => setDetail({ ...detail, port: e.target.value ? Number(e.target.value) : undefined })} placeholder="Any" className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 placeholder-navy-600 focus:outline-none focus:border-emerald-500/50" />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Comment</span>
              <input type="text" value={detail.comment} onChange={(e) => setDetail({ ...detail, comment: e.target.value })} className="mt-1 block w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50" />
            </label>
          </div>
          <div className="flex gap-2 mt-4">
            <button onClick={handleCreate} className="px-4 py-2 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors">Create</button>
            <button onClick={() => setShowForm(false)} className="px-4 py-2 text-xs font-medium rounded-lg bg-navy-800 text-gray-400 border border-navy-700/50 hover:bg-navy-700/50 transition-colors">Cancel</button>
          </div>
        </div>
      )}

      {/* Rules Table */}
      <div className="animate-fade-in">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Active Rules</p>
        {rules.length === 0 ? (
          <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-12 text-center">
            <svg className="w-10 h-10 text-navy-700 mx-auto mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
            </svg>
            <p className="text-sm text-navy-400">No firewall rules configured</p>
            <p className="text-xs text-navy-600 mt-1">Default deny policy is in effect</p>
          </div>
        ) : (
          <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-navy-800/50">
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Chain</th>
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Pri</th>
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Action</th>
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Proto</th>
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Source</th>
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Destination</th>
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Port</th>
                    <th className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">Status</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id} className={`border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors ${!rule.enabled ? 'opacity-40' : ''}`}>
                      <td className="px-4 py-3 font-mono text-gray-300 text-xs">{rule.chain}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{rule.priority}</td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${
                          rule.detail.action === 'accept' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                          rule.detail.action === 'drop' ? 'bg-red-500/10 text-red-400 border-red-500/15' :
                          'bg-amber-500/10 text-amber-400 border-amber-500/15'
                        }`}>
                          {rule.detail.action.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs">{rule.detail.protocol || 'any'}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs">{rule.detail.source || '*'}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs">{rule.detail.destination || '*'}</td>
                      <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{rule.detail.port ?? '*'}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleToggle(rule)}
                          className={`w-9 h-5 rounded-full relative transition-colors duration-200 ${rule.enabled ? 'bg-emerald-500' : 'bg-navy-700'}`}
                        >
                          <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow-sm transition-transform duration-200 ${rule.enabled ? 'left-4.5' : 'left-0.5'}`} />
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleDelete(rule.id)} className="text-[11px] font-medium text-red-400/60 hover:text-red-400 transition-colors">Delete</button>
                      </td>
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
