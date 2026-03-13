// SPDX-License-Identifier: AGPL-3.0-or-later

import { type DhcpStaticLease } from '../../api'
import { Button, EmptyState } from '../../components/ui'

interface StaticLeasesTabProps {
  leases: DhcpStaticLease[]
  onChange: (leases: DhcpStaticLease[]) => void
  onSave: () => void
  saving: boolean
}

const FIELDS = ['mac', 'ip', 'hostname'] as const
const HEADERS = ['MAC', 'IP', 'Hostname', '']

export default function StaticLeasesTab({ leases, onChange, onSave, saving }: StaticLeasesTabProps) {
  const update = (i: number, field: string, value: string) => {
    const copy = [...leases]
    copy[i] = { ...copy[i], [field]: value }
    onChange(copy)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">Static Leases</p>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => onChange([...leases, { mac: '', ip: '', hostname: '' }])}>+ Add</Button>
          <Button size="sm" onClick={onSave} loading={saving}>{saving ? 'Saving...' : 'Save'}</Button>
        </div>
      </div>

      {leases.length === 0 ? (
        <EmptyState
          icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 12l2 2 4-4" /><circle cx="12" cy="12" r="10" /></svg>}
          title="No static leases"
          description="Pin a device to a fixed IP address."
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
                {leases.map((l, i) => (
                  <tr key={i} className="border-b border-navy-800/30">
                    {FIELDS.map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={l[field]}
                          onChange={(e) => update(i, field, e.target.value)}
                          className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <Button variant="danger" size="sm" onClick={() => onChange(leases.filter((_, j) => j !== i))}>Remove</Button>
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
