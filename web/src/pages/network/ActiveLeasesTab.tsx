// SPDX-License-Identifier: AGPL-3.0-or-later

import { type DhcpLease } from '../../api'
import { EmptyState } from '../../components/ui'

export default function ActiveLeasesTab({ leases }: { leases: DhcpLease[] }) {
  if (leases.length === 0) {
    return (
      <EmptyState
        icon={<svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" /></svg>}
        title="No active leases"
        description="DHCP clients will appear here when they connect."
      />
    )
  }

  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-navy-800/50">
              {['Hostname', 'IP', 'MAC', 'Client ID', 'Expires'].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {leases.map((l) => (
              <tr key={l.mac} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                <td className="px-4 py-3 text-gray-200 text-sm">{l.hostname || '---'}</td>
                <td className="px-4 py-3 font-mono text-gray-400 text-xs tabular-nums">{l.ip}</td>
                <td className="px-4 py-3 font-mono text-gray-400 text-xs">{l.mac}</td>
                <td className="px-4 py-3 font-mono text-navy-500 text-xs">{l.client_id || '---'}</td>
                <td className="px-4 py-3 text-navy-500 text-xs">{l.expires ? new Date(l.expires * 1000).toLocaleString() : '---'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
