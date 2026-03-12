import { useEffect, useState, useCallback } from 'react'
import {
  api,
  type NetworkInterface,
  type DnsConfig,
  type DhcpRange,
  type DhcpStaticLease,
  type DhcpLease,
  type DnsOverride,
} from '../api'
import Table from '../components/Table'

export default function Network() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [dnsConfig, setDnsConfig] = useState<DnsConfig | null>(null)
  const [dhcpRanges, setDhcpRanges] = useState<DhcpRange[]>([])
  const [staticLeases, setStaticLeases] = useState<DhcpStaticLease[]>([])
  const [activeLeases, setActiveLeases] = useState<DhcpLease[]>([])
  const [overrides, setOverrides] = useState<DnsOverride[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [ifRes, dnsRes, rangesRes, staticRes, leasesRes, overridesRes] = await Promise.all([
        api.getInterfaces(),
        api.getDnsConfig(),
        api.getDhcpRanges(),
        api.getDhcpStaticLeases(),
        api.getDhcpLeases(),
        api.getDnsOverrides(),
      ])
      setInterfaces(ifRes.interfaces)
      setDnsConfig(dnsRes.config)
      setDhcpRanges(rangesRes.ranges)
      setStaticLeases(staticRes.leases)
      setActiveLeases(leasesRes.leases)
      setOverrides(overridesRes.overrides)
      setError(null)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const save = async (section: string, fn: () => Promise<void>) => {
    setSaving(section)
    try {
      await fn()
      setError(null)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setSaving(null)
    }
  }

  const ifaceColumns = [
    {
      key: 'enabled',
      header: '',
      render: (r: NetworkInterface) => (
        <span className={`w-2 h-2 rounded-full inline-block ${r.enabled ? 'bg-emerald-400' : 'bg-red-400'}`} />
      ),
    },
    { key: 'name', header: 'Interface' },
    { key: 'role', header: 'Role' },
    {
      key: 'vlan_id',
      header: 'VLAN',
      render: (r: NetworkInterface) => r.vlan_id != null ? String(r.vlan_id) : '---',
    },
  ]

  if (loading) {
    return (
      <div className="flex items-center gap-3">
        <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
        <span className="text-sm font-mono text-gray-500">Loading network data...</span>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <h2 className="text-lg font-bold font-mono">Network</h2>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {/* Interfaces */}
      <section>
        <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">Interfaces</h3>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table columns={ifaceColumns} data={interfaces} keyField="name" />
        </div>
      </section>

      {/* DNS Config */}
      {dnsConfig && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider">DNS Configuration</h3>
            <button
              onClick={() => save('dns', () => api.saveDnsConfig(dnsConfig))}
              disabled={saving === 'dns'}
              className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50"
            >
              {saving === 'dns' ? 'Saving...' : 'Save DNS'}
            </button>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="block">
                <span className="text-xs font-mono text-gray-500">Upstream DNS (comma-separated)</span>
                <input
                  type="text"
                  value={dnsConfig.upstream_dns.join(', ')}
                  onChange={(e) => setDnsConfig({ ...dnsConfig, upstream_dns: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200"
                />
              </label>
              <label className="block">
                <span className="text-xs font-mono text-gray-500">Domain</span>
                <input
                  type="text"
                  value={dnsConfig.domain}
                  onChange={(e) => setDnsConfig({ ...dnsConfig, domain: e.target.value })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200"
                />
              </label>
              <label className="block">
                <span className="text-xs font-mono text-gray-500">Cache Size</span>
                <input
                  type="number"
                  value={dnsConfig.cache_size}
                  onChange={(e) => setDnsConfig({ ...dnsConfig, cache_size: Number(e.target.value) })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200"
                />
              </label>
              <label className="block">
                <span className="text-xs font-mono text-gray-500">Bind Interfaces (comma-separated)</span>
                <input
                  type="text"
                  value={dnsConfig.bind_interfaces.join(', ')}
                  onChange={(e) => setDnsConfig({ ...dnsConfig, bind_interfaces: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
                  className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200"
                />
              </label>
              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={dnsConfig.dnssec}
                    onChange={(e) => setDnsConfig({ ...dnsConfig, dnssec: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-emerald-500 focus:ring-emerald-500"
                  />
                  <span className="text-sm font-mono text-gray-300">DNSSEC</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={dnsConfig.rebind_protection}
                    onChange={(e) => setDnsConfig({ ...dnsConfig, rebind_protection: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-emerald-500 focus:ring-emerald-500"
                  />
                  <span className="text-sm font-mono text-gray-300">Rebind Protection</span>
                </label>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* DHCP Ranges */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider">DHCP Ranges</h3>
          <div className="flex gap-2">
            <button
              onClick={() => setDhcpRanges([...dhcpRanges, { interface: '', start_ip: '', end_ip: '', netmask: '255.255.255.0', gateway: '', lease_time: '24h', vlan_id: null }])}
              className="px-3 py-1.5 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white"
            >
              + Add
            </button>
            <button
              onClick={() => save('ranges', () => api.saveDhcpRanges(dhcpRanges))}
              disabled={saving === 'ranges'}
              className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50"
            >
              {saving === 'ranges' ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {['Interface', 'Start IP', 'End IP', 'Netmask', 'Gateway', 'Lease Time', 'VLAN', ''].map((h) => (
                    <th key={h} className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dhcpRanges.map((r, i) => (
                  <tr key={i} className="border-b border-gray-800/50">
                    {(['interface', 'start_ip', 'end_ip', 'netmask', 'gateway', 'lease_time'] as const).map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={r[field]}
                          onChange={(e) => { const copy = [...dhcpRanges]; copy[i] = { ...copy[i], [field]: e.target.value }; setDhcpRanges(copy) }}
                          className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <input
                        type="text"
                        value={r.vlan_id ?? ''}
                        onChange={(e) => { const copy = [...dhcpRanges]; copy[i] = { ...copy[i], vlan_id: e.target.value ? Number(e.target.value) : null }; setDhcpRanges(copy) }}
                        placeholder="---"
                        className="w-16 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200 placeholder-gray-600"
                      />
                    </td>
                    <td className="px-2 py-1.5">
                      <button onClick={() => setDhcpRanges(dhcpRanges.filter((_, j) => j !== i))} className="text-xs font-mono text-red-400 hover:text-red-300">Remove</button>
                    </td>
                  </tr>
                ))}
                {dhcpRanges.length === 0 && (
                  <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-600 font-mono">No DHCP ranges configured</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Static Leases */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider">Static Leases</h3>
          <div className="flex gap-2">
            <button
              onClick={() => setStaticLeases([...staticLeases, { mac: '', ip: '', hostname: '' }])}
              className="px-3 py-1.5 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white"
            >
              + Add
            </button>
            <button
              onClick={() => save('static', () => api.saveDhcpStaticLeases(staticLeases))}
              disabled={saving === 'static'}
              className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50"
            >
              {saving === 'static' ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {['MAC', 'IP', 'Hostname', ''].map((h) => (
                    <th key={h} className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {staticLeases.map((l, i) => (
                  <tr key={i} className="border-b border-gray-800/50">
                    {(['mac', 'ip', 'hostname'] as const).map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={l[field]}
                          onChange={(e) => { const copy = [...staticLeases]; copy[i] = { ...copy[i], [field]: e.target.value }; setStaticLeases(copy) }}
                          className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <button onClick={() => setStaticLeases(staticLeases.filter((_, j) => j !== i))} className="text-xs font-mono text-red-400 hover:text-red-300">Remove</button>
                    </td>
                  </tr>
                ))}
                {staticLeases.length === 0 && (
                  <tr><td colSpan={4} className="px-3 py-8 text-center text-gray-600 font-mono">No static leases</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Active DHCP Leases (read-only) */}
      <section>
        <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">Active DHCP Leases</h3>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Table
            columns={[
              { key: 'hostname', header: 'Hostname', render: (r: DhcpLease) => r.hostname || '---' },
              { key: 'ip', header: 'IP' },
              { key: 'mac', header: 'MAC' },
              { key: 'client_id', header: 'Client ID', render: (r: DhcpLease) => r.client_id || '---' },
              { key: 'expires', header: 'Expires', render: (r: DhcpLease) => r.expires ? new Date(r.expires * 1000).toLocaleString() : '---' },
            ]}
            data={activeLeases}
            keyField="mac"
          />
        </div>
      </section>

      {/* DNS Overrides */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider">DNS Overrides</h3>
          <div className="flex gap-2">
            <button
              onClick={() => setOverrides([...overrides, { domain: '', ip: '' }])}
              className="px-3 py-1.5 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white"
            >
              + Add
            </button>
            <button
              onClick={() => save('overrides', () => api.saveDnsOverrides(overrides))}
              disabled={saving === 'overrides'}
              className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50"
            >
              {saving === 'overrides' ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {['Domain', 'IP', ''].map((h) => (
                    <th key={h} className="text-left px-3 py-2 text-xs text-gray-500 uppercase tracking-wider font-mono font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {overrides.map((o, i) => (
                  <tr key={i} className="border-b border-gray-800/50">
                    {(['domain', 'ip'] as const).map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={o[field]}
                          onChange={(e) => { const copy = [...overrides]; copy[i] = { ...copy[i], [field]: e.target.value }; setOverrides(copy) }}
                          className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <button onClick={() => setOverrides(overrides.filter((_, j) => j !== i))} className="text-xs font-mono text-red-400 hover:text-red-300">Remove</button>
                    </td>
                  </tr>
                ))}
                {overrides.length === 0 && (
                  <tr><td colSpan={3} className="px-3 py-8 text-center text-gray-600 font-mono">No DNS overrides</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  )
}
