// SPDX-License-Identifier: AGPL-3.0-or-later

import { type DnsOverride } from '../../api'
import { Button, EmptyState } from '../../components/ui'

interface DnsOverridesTabProps {
  overrides: DnsOverride[]
  onChange: (overrides: DnsOverride[]) => void
  onSave: () => void
  saving: boolean
}

const FIELDS = ['domain', 'ip'] as const
const HEADERS = ['Domain', 'IP', '']

export default function DnsOverridesTab({ overrides, onChange, onSave, saving }: DnsOverridesTabProps) {
  const update = (i: number, field: string, value: string) => {
    const copy = [...overrides]
    copy[i] = { ...copy[i], [field]: value }
    onChange(copy)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">DNS Overrides</p>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => onChange([...overrides, { domain: '', ip: '' }])}>+ Add</Button>
          <Button size="sm" onClick={onSave} loading={saving}>{saving ? 'Saving...' : 'Save'}</Button>
        </div>
      </div>

      {overrides.length === 0 ? (
        <EmptyState
          icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /><path d="M9 10h.01M15 10h.01M9.5 15.5c.83.67 2.17.67 3 0" /></svg>}
          title="No DNS overrides"
          description="Map custom domains to specific IP addresses."
        />
      ) : (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {HEADERS.map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {overrides.map((o, i) => (
                  <tr key={i} className="border-b border-navy-800/30">
                    {FIELDS.map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={o[field]}
                          onChange={(e) => update(i, field, e.target.value)}
                          className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50"
                          placeholder={field === 'domain' ? 'example.local' : '192.168.1.100'}
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <Button variant="danger" size="sm" onClick={() => onChange(overrides.filter((_, j) => j !== i))}>Remove</Button>
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
