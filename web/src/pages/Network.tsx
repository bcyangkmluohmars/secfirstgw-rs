// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import {
  api,
  type DnsConfig,
  type DhcpRange,
  type DhcpStaticLease,
  type DhcpLease,
  type DnsOverride,
} from '../api'
import { PageHeader, Spinner, Tabs } from '../components/ui'
import { useToast } from '../hooks/useToast'
import DnsTab from './network/DnsTab'
import DhcpRangesTab from './network/DhcpRangesTab'
import StaticLeasesTab from './network/StaticLeasesTab'
import ActiveLeasesTab from './network/ActiveLeasesTab'
import DnsOverridesTab from './network/DnsOverridesTab'

export default function Network() {
  const [dnsConfig, setDnsConfig] = useState<DnsConfig | null>(null)
  const [dhcpRanges, setDhcpRanges] = useState<DhcpRange[]>([])
  const [staticLeases, setStaticLeases] = useState<DhcpStaticLease[]>([])
  const [activeLeases, setActiveLeases] = useState<DhcpLease[]>([])
  const [overrides, setOverrides] = useState<DnsOverride[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState<string | null>(null)
  const [tab, setTab] = useState('dns')
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const [dnsRes, rangesRes, staticRes, leasesRes, overridesRes] = await Promise.all([
        api.getDnsConfig(),
        api.getDhcpRanges(),
        api.getDhcpStaticLeases(),
        api.getDhcpLeases(),
        api.getDnsOverrides(),
      ])
      setDnsConfig(dnsRes.config)
      setDhcpRanges(rangesRes.ranges)
      setStaticLeases(staticRes.leases)
      setActiveLeases(leasesRes.leases)
      setOverrides(overridesRes.overrides)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const save = async (section: string, fn: () => Promise<void>) => {
    setSaving(section)
    try { await fn(); toast.success(`${section} saved`) }
    catch (e: unknown) { toast.error((e as Error).message) }
    finally { setSaving(null) }
  }

  if (loading) return <Spinner label="Loading network configuration..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Network"
        subtitle="DNS, DHCP, and name resolution settings"
      />

      <Tabs
        tabs={[
          { key: 'dns', label: 'DNS' },
          { key: 'dhcp', label: 'DHCP Ranges', count: dhcpRanges.length },
          { key: 'static', label: 'Static Leases', count: staticLeases.length },
          { key: 'leases', label: 'Active Leases', count: activeLeases.length },
          { key: 'overrides', label: 'DNS Overrides', count: overrides.length },
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === 'dns' && dnsConfig && (
        <DnsTab
          config={dnsConfig}
          onChange={setDnsConfig}
          onSave={() => save('DNS', () => api.saveDnsConfig(dnsConfig!))}
          saving={saving === 'DNS'}
        />
      )}
      {tab === 'dhcp' && (
        <DhcpRangesTab
          ranges={dhcpRanges}
          onChange={setDhcpRanges}
          onSave={() => save('DHCP ranges', () => api.saveDhcpRanges(dhcpRanges))}
          saving={saving === 'DHCP ranges'}
        />
      )}
      {tab === 'static' && (
        <StaticLeasesTab
          leases={staticLeases}
          onChange={setStaticLeases}
          onSave={() => save('Static leases', () => api.saveDhcpStaticLeases(staticLeases))}
          saving={saving === 'Static leases'}
        />
      )}
      {tab === 'leases' && <ActiveLeasesTab leases={activeLeases} />}
      {tab === 'overrides' && (
        <DnsOverridesTab
          overrides={overrides}
          onChange={setOverrides}
          onSave={() => save('DNS overrides', () => api.saveDnsOverrides(overrides))}
          saving={saving === 'DNS overrides'}
        />
      )}
    </div>
  )
}
