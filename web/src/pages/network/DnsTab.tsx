// SPDX-License-Identifier: AGPL-3.0-or-later

import { type DnsConfig } from '../../api'
import { Card, Input, Toggle, Button } from '../../components/ui'

interface DnsTabProps {
  config: DnsConfig
  onChange: (config: DnsConfig) => void
  onSave: () => void
  saving: boolean
}

export default function DnsTab({ config, onChange, onSave, saving }: DnsTabProps) {
  return (
    <Card
      title="DNS Configuration"
      actions={<Button onClick={onSave} loading={saving}>{saving ? 'Saving...' : 'Save DNS'}</Button>}
    >
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Input
          label="Upstream DNS (comma-separated)"
          mono
          value={config.upstream_dns.join(', ')}
          onChange={(e) => onChange({ ...config, upstream_dns: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
          placeholder="1.1.1.1, 8.8.8.8"
        />
        <Input
          label="Domain"
          mono
          value={config.domain}
          onChange={(e) => onChange({ ...config, domain: e.target.value })}
          placeholder="local"
        />
        <Input
          label="Cache Size"
          type="number"
          mono
          value={config.cache_size}
          onChange={(e) => onChange({ ...config, cache_size: Number(e.target.value) })}
        />
        <Input
          label="Bind Interfaces (comma-separated)"
          mono
          value={config.bind_interfaces.join(', ')}
          onChange={(e) => onChange({ ...config, bind_interfaces: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
          placeholder="br0, br1"
        />
        <div className="flex items-center gap-6 md:col-span-2">
          <Toggle checked={config.dnssec} onChange={(v) => onChange({ ...config, dnssec: v })} label="DNSSEC" />
          <Toggle checked={config.rebind_protection} onChange={(v) => onChange({ ...config, rebind_protection: v })} label="Rebind Protection" />
        </div>
      </div>
    </Card>
  )
}
