import { useEffect, useState } from 'react'
import { api, type FirewallRule } from '../api'
import Table from '../components/Table'

export default function Firewall() {
  const [rules, setRules] = useState<FirewallRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getFirewallRules()
      .then(setRules)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const columns = [
    {
      key: 'enabled',
      header: '',
      render: (r: FirewallRule) => (
        <span className={`w-2 h-2 rounded-full inline-block ${r.enabled ? 'bg-emerald-400' : 'bg-gray-600'}`} />
      ),
    },
    { key: 'name', header: 'Name' },
    {
      key: 'action',
      header: 'Action',
      render: (r: FirewallRule) => (
        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
          r.action === 'allow' ? 'bg-emerald-900/50 text-emerald-400' :
          r.action === 'deny' ? 'bg-red-900/50 text-red-400' :
          'bg-amber-900/50 text-amber-400'
        }`}>
          {r.action}
        </span>
      ),
    },
    { key: 'protocol', header: 'Proto' },
    { key: 'source', header: 'Source' },
    { key: 'destination', header: 'Destination' },
    { key: 'port', header: 'Port' },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Firewall Rules</h2>
        <span className="text-xs font-mono text-gray-500">{rules.length} rules</span>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {loading ? (
        <p className="text-sm font-mono text-gray-500">Loading firewall rules...</p>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={columns} data={rules} keyField="id" />
        </div>
      )}
    </div>
  )
}
