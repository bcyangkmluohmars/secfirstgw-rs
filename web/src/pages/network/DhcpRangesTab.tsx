// SPDX-License-Identifier: AGPL-3.0-or-later

import { type DhcpRange } from '../../api'
import { Button, EmptyState } from '../../components/ui'

interface DhcpRangesTabProps {
  ranges: DhcpRange[]
  onChange: (ranges: DhcpRange[]) => void
  onSave: () => void
  saving: boolean
}

const FIELDS = ['interface', 'start_ip', 'end_ip', 'netmask', 'gateway', 'lease_time'] as const
const HEADERS = ['Interface', 'Start IP', 'End IP', 'Netmask', 'Gateway', 'Lease Time', 'VLAN', '']

const emptyRange: DhcpRange = { interface: '', start_ip: '', end_ip: '', netmask: '255.255.255.0', gateway: '', lease_time: '24h', vlan_id: null }

export default function DhcpRangesTab({ ranges, onChange, onSave, saving }: DhcpRangesTabProps) {
  const update = (i: number, field: string, value: string) => {
    const copy = [...ranges]
    copy[i] = { ...copy[i], [field]: value }
    onChange(copy)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">DHCP Ranges</p>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => onChange([...ranges, { ...emptyRange }])}>+ Add</Button>
          <Button size="sm" onClick={onSave} loading={saving}>{saving ? 'Saving...' : 'Save'}</Button>
        </div>
      </div>

      {ranges.length === 0 ? (
        <EmptyState
          icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2v20M2 12h20" /></svg>}
          title="No DHCP ranges configured"
          description="Add a range to start serving DHCP leases."
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
                {ranges.map((r, i) => (
                  <tr key={i} className="border-b border-navy-800/30">
                    {FIELDS.map((field) => (
                      <td key={field} className="px-2 py-1.5">
                        <input
                          type="text"
                          value={r[field]}
                          onChange={(e) => update(i, field, e.target.value)}
                          className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50"
                        />
                      </td>
                    ))}
                    <td className="px-2 py-1.5">
                      <input
                        type="text"
                        value={r.vlan_id ?? ''}
                        onChange={(e) => {
                          const copy = [...ranges]
                          copy[i] = { ...copy[i], vlan_id: e.target.value ? Number(e.target.value) : null }
                          onChange(copy)
                        }}
                        placeholder="---"
                        className="w-16 bg-navy-800 border border-navy-700/50 rounded-lg px-2 py-1 text-xs font-mono text-gray-200 placeholder-navy-600 focus:outline-none focus:border-emerald-500/50"
                      />
                    </td>
                    <td className="px-2 py-1.5">
                      <Button variant="danger" size="sm" onClick={() => onChange(ranges.filter((_, j) => j !== i))}>Remove</Button>
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
