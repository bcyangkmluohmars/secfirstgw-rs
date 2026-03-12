export default function Firewall() {
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Firewall Rules</h2>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
        <p className="text-sm font-mono text-gray-500">No firewall rules configured.</p>
        <p className="text-xs font-mono text-gray-600 mt-2">nftables integration coming soon.</p>
      </div>
    </div>
  )
}
