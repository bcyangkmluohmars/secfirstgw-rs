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

// Shared input class
const inputCls = 'w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50 transition-colors'
const labelCls = 'text-[11px] font-medium text-navy-400'
const thCls = 'text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium'

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

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-navy-400">Loading network data...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <h2 className="text-lg font-semibold text-gray-100">Network</h2>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 animate-fade-in">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Interfaces */}
      <section className="animate-fade-in">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Interfaces</p>
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-navy-800/50">
                <th className={`${thCls} w-10`}></th>
                <th className={thCls}>Interface</th>
                <th className={thCls}>Role</th>
                <th className={thCls}>VLAN</th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map((iface) => (
                <tr key={iface.name} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                  <td className="px-4 py-3">
                    <span className={`w-2 h-2 rounded-full inline-block ${iface.enabled ? 'bg-emerald-400' : 'bg-red-400'}`} />
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-200 text-sm">{iface.name}</td>
                  <td className="px-4 py-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-md border bg-navy-800 text-navy-400 border-navy-700/50 uppercase">
                      {iface.role}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{iface.vlan_id != null ? String(iface.vlan_id) : '---'}</td>
                </tr>
              ))}
              {interfaces.length === 0 && (
                <tr><td colSpan={4} className="px-4 py-8 text-center text-navy-500">No interfaces found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* DNS Config */}
      {dnsConfig && (
        <section className="animate-fade-in">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">DNS Configuration</p>
            <button
              onClick={() => save('dns', () => api.saveDnsConfig(dnsConfig))}
              disabled={saving === 'dns'}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
            >
              {saving === 'dns' ? 'Saving...' : 'Save DNS'}
            </button>
          </div>
          <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="block">
                <span className={labelCls}>Upstream DNS (comma-separated)</span>
                <input
                  type="text"
                  value={dnsConfig.upstream_dns.join(', ')}
                  onChange={(e) => setDnsConfig({ ...dnsConfig, upstream_dns: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
                  className={`mt-1 ${inputCls}`}
                />
              </label>
              <label className="block">
                <span className={labelCls}>Domain</span>
                <input type="text" value={dnsConfig.domain} onChange={(e) => setDnsConfig({ ...dnsConfig, domain: e.target.value })} className={`mt-1 ${inputCls}`} />
              </label>
              <label className="block">
                <span className={labelCls}>Cache Size</span>
                <input type="number" value={dnsConfig.cache_size} onChange={(e) => setDnsConfig({ ...dnsConfig, cache_size: Number(e.target.value) })} className={`mt-1 ${inputCls}`} />
              </label>
              <label className="block">
                <span className={labelCls}>Bind Interfaces (comma-separated)</span>
                <input
                  type="text"
                  value={dnsConfig.bind_interfaces.join(', ')}
                  onChange={(e) => setDnsConfig({ ...dnsConfig, bind_interfaces: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
                  className={`mt-1 ${inputCls}`}
                />
              </label>
              <div className="flex items-center gap-6 md:col-span-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={dnsConfig.dnssec}
                    onChange={(e) => setDnsConfig({ ...dnsConfig, dnssec: e.target.checked })}
                    className="w-4 h-4 rounded border-navy-700 bg-navy-800 text-emerald-500 focus:ring-emerald-500/30"
                  />
                  <span className="text-sm text-gray-300">DNSSEC</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={dnsConfig.rebind_protection}
                    onChange={(e) => setDnsConfig({ ...dnsConfig, rebind_protection: e.target.checked })}
                    className="w-4 h-4 rounded border-navy-700 bg-navy-800 text-emerald-500 focus:ring-emerald-500/30"
                  />
                  <span className="text-sm text-gray-300">Rebind Protection</span>
                </label>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* DHCP Ranges */}
      <section className="animate-fade-in">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">DHCP Ranges</p>
          <div className="flex gap-2">
            <button
              onClick={() => setDhcpRanges([...dhcpRanges, { interface: '', start_ip: '', end_ip: '', netmask: '255.255.255.0', gateway: '', lease_time: '24h', vlan_id: null }])}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-navy-800 text-gray-400 border border-navy-700/50 hover:bg-navy-700/50 transition-colors"
            >
              + Add
            </button>
            <button
              onClick={() => save('ranges', () => api.saveDhcpRanges(dhcpRanges))}
              disabled={saving === 'ranges'}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
            >
              {saving === 'ranges' ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {['Interface', 'Start IP', 'End IP', 'Netmask', 'Gateway', 'Lease Time', 'VLAN', ''].map((h) => (
                    <th key={h} className={thCls}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dhcpRanges.map((r, i) => (
                  <tr key={i} className="border-b border-navy-800/30">
                    {(['interface', 'start_ip', 'end_ip', 'netmask', 'gateway', 'lease_time'] as const).map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={r[field]}
                          onChange={(e) => { const copy = [...dhcpRanges]; copy[i] = { ...copy[i], [field]: e.target.value }; setDhcpRanges(copy) }}
                          className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <input
                        type="text"
                        value={r.vlan_id ?? ''}
                        onChange={(e) => { const copy = [...dhcpRanges]; copy[i] = { ...copy[i], vlan_id: e.target.value ? Number(e.target.value) : null }; setDhcpRanges(copy) }}
                        placeholder="---"
                        className="w-16 bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 placeholder-navy-600 focus:outline-none focus:border-emerald-500/50"
                      />
                    </td>
                    <td className="px-2 py-1.5">
                      <button onClick={() => setDhcpRanges(dhcpRanges.filter((_, j) => j !== i))} className="text-[11px] font-medium text-red-400/60 hover:text-red-400 transition-colors">Remove</button>
                    </td>
                  </tr>
                ))}
                {dhcpRanges.length === 0 && (
                  <tr><td colSpan={8} className="px-4 py-8 text-center text-navy-500">No DHCP ranges configured</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Static Leases */}
      <section className="animate-fade-in">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">Static Leases</p>
          <div className="flex gap-2">
            <button
              onClick={() => setStaticLeases([...staticLeases, { mac: '', ip: '', hostname: '' }])}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-navy-800 text-gray-400 border border-navy-700/50 hover:bg-navy-700/50 transition-colors"
            >
              + Add
            </button>
            <button
              onClick={() => save('static', () => api.saveDhcpStaticLeases(staticLeases))}
              disabled={saving === 'static'}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
            >
              {saving === 'static' ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {['MAC', 'IP', 'Hostname', ''].map((h) => (
                    <th key={h} className={thCls}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {staticLeases.map((l, i) => (
                  <tr key={i} className="border-b border-navy-800/30">
                    {(['mac', 'ip', 'hostname'] as const).map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={l[field]}
                          onChange={(e) => { const copy = [...staticLeases]; copy[i] = { ...copy[i], [field]: e.target.value }; setStaticLeases(copy) }}
                          className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <button onClick={() => setStaticLeases(staticLeases.filter((_, j) => j !== i))} className="text-[11px] font-medium text-red-400/60 hover:text-red-400 transition-colors">Remove</button>
                    </td>
                  </tr>
                ))}
                {staticLeases.length === 0 && (
                  <tr><td colSpan={4} className="px-4 py-8 text-center text-navy-500">No static leases</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Active DHCP Leases */}
      <section className="animate-fade-in">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-3">Active DHCP Leases</p>
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-navy-800/50">
                <th className={thCls}>Hostname</th>
                <th className={thCls}>IP</th>
                <th className={thCls}>MAC</th>
                <th className={thCls}>Client ID</th>
                <th className={thCls}>Expires</th>
              </tr>
            </thead>
            <tbody>
              {activeLeases.map((l) => (
                <tr key={l.mac} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                  <td className="px-4 py-3 text-gray-200 text-sm">{l.hostname || '---'}</td>
                  <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{l.ip}</td>
                  <td className="px-4 py-3 font-mono text-gray-400 text-xs">{l.mac}</td>
                  <td className="px-4 py-3 font-mono text-navy-500 text-xs">{l.client_id || '---'}</td>
                  <td className="px-4 py-3 text-navy-500 text-xs">{l.expires ? new Date(l.expires * 1000).toLocaleString() : '---'}</td>
                </tr>
              ))}
              {activeLeases.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-navy-500">No active leases</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* DNS Overrides */}
      <section className="animate-fade-in">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">DNS Overrides</p>
          <div className="flex gap-2">
            <button
              onClick={() => setOverrides([...overrides, { domain: '', ip: '' }])}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-navy-800 text-gray-400 border border-navy-700/50 hover:bg-navy-700/50 transition-colors"
            >
              + Add
            </button>
            <button
              onClick={() => save('overrides', () => api.saveDnsOverrides(overrides))}
              disabled={saving === 'overrides'}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
            >
              {saving === 'overrides' ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {['Domain', 'IP', ''].map((h) => (
                    <th key={h} className={thCls}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {overrides.map((o, i) => (
                  <tr key={i} className="border-b border-navy-800/30">
                    {(['domain', 'ip'] as const).map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={o[field]}
                          onChange={(e) => { const copy = [...overrides]; copy[i] = { ...copy[i], [field]: e.target.value }; setOverrides(copy) }}
                          className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <button onClick={() => setOverrides(overrides.filter((_, j) => j !== i))} className="text-[11px] font-medium text-red-400/60 hover:text-red-400 transition-colors">Remove</button>
                    </td>
                  </tr>
                ))}
                {overrides.length === 0 && (
                  <tr><td colSpan={3} className="px-4 py-8 text-center text-navy-500">No DNS overrides</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  )
}
