import { useEffect, useState, useCallback } from 'react'
import { api, type FirewallRule } from '../api'

const EMPTY_DETAIL = { action: 'drop', protocol: '', source: '', destination: '', port: undefined as number | undefined, comment: '' }

export default function Firewall() {
  const [rules, setRules] = useState<FirewallRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [applying, setApplying] = useState(false)
  const [showForm, setShowForm] = useState(false)

  // New rule form state
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
      <div className="flex items-center gap-3">
        <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
        <span className="text-sm font-mono text-gray-500">Loading firewall rules...</span>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Firewall Rules</h2>
        <div className="flex gap-2">
          <button
            onClick={() => setShowForm(!showForm)}
            className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white"
          >
            + Add Rule
          </button>
          <button
            onClick={handleApply}
            disabled={applying}
            className="px-3 py-1.5 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white disabled:opacity-50"
          >
            {applying ? 'Applying...' : 'Apply'}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {showForm && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">New Rule</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Chain</span>
              <select value={chain} onChange={(e) => setChain(e.target.value)} className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200">
                <option value="input">input</option>
                <option value="forward">forward</option>
                <option value="output">output</option>
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Priority</span>
              <input type="number" value={priority} onChange={(e) => setPriority(Number(e.target.value))} className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Action</span>
              <select value={detail.action} onChange={(e) => setDetail({ ...detail, action: e.target.value })} className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200">
                <option value="accept">accept</option>
                <option value="drop">drop</option>
                <option value="reject">reject</option>
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Protocol</span>
              <select value={detail.protocol} onChange={(e) => setDetail({ ...detail, protocol: e.target.value })} className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200">
                <option value="">any</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Source</span>
              <input type="text" value={detail.source} onChange={(e) => setDetail({ ...detail, source: e.target.value })} placeholder="0.0.0.0/0" className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200 placeholder-gray-600" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Destination</span>
              <input type="text" value={detail.destination} onChange={(e) => setDetail({ ...detail, destination: e.target.value })} placeholder="0.0.0.0/0" className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200 placeholder-gray-600" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Port</span>
              <input type="number" value={detail.port ?? ''} onChange={(e) => setDetail({ ...detail, port: e.target.value ? Number(e.target.value) : undefined })} placeholder="Any" className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200 placeholder-gray-600" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Comment</span>
              <input type="text" value={detail.comment} onChange={(e) => setDetail({ ...detail, comment: e.target.value })} className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200" />
            </label>
          </div>
          <div className="flex gap-2 mt-3">
            <button onClick={handleCreate} className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white">Create</button>
            <button onClick={() => setShowForm(false)} className="px-3 py-1.5 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white">Cancel</button>
          </div>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-sm font-mono text-gray-500">No firewall rules configured.</p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Chain</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Pri</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Action</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Proto</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Source</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Dest</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Port</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">Enabled</th>
                  <th className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className={`border-b border-gray-800/50 hover:bg-gray-800/30 ${!rule.enabled ? 'opacity-50' : ''}`}>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{rule.chain}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{rule.priority}</td>
                    <td className="px-3 py-2.5 font-mono">
                      <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                        rule.detail.action === 'accept' ? 'bg-emerald-900/50 text-emerald-400' :
                        rule.detail.action === 'drop' ? 'bg-red-900/50 text-red-400' :
                        'bg-amber-900/50 text-amber-400'
                      }`}>
                        {rule.detail.action}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{rule.detail.protocol || 'any'}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{rule.detail.source || '*'}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{rule.detail.destination || '*'}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{rule.detail.port ?? '*'}</td>
                    <td className="px-3 py-2.5">
                      <button
                        onClick={() => handleToggle(rule)}
                        className={`w-8 h-4 rounded-full relative transition-colors ${rule.enabled ? 'bg-emerald-600' : 'bg-gray-700'}`}
                      >
                        <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${rule.enabled ? 'left-4' : 'left-0.5'}`} />
                      </button>
                    </td>
                    <td className="px-3 py-2.5">
                      <button onClick={() => handleDelete(rule.id)} className="text-xs font-mono text-red-400 hover:text-red-300">Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
