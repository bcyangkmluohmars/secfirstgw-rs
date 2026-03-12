export default function Vpn() {
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">VPN Tunnels</h2>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
        <p className="text-sm font-mono text-gray-500">No VPN tunnels configured.</p>
        <p className="text-xs font-mono text-gray-600 mt-2">WireGuard and OpenVPN support coming soon.</p>
      </div>
    </div>
  )
}
