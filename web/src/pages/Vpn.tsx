import { useEffect, useState, useCallback } from 'react'
import { api, type VpnTunnel, type TunnelStatus, type WgPeer } from '../api'

export default function Vpn() {
  const [tunnels, setTunnels] = useState<VpnTunnel[]>([])
  const [statuses, setStatuses] = useState<Record<string, TunnelStatus>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [addPeerFor, setAddPeerFor] = useState<string | null>(null)

  // Create tunnel form
  const [newName, setNewName] = useState('')
  const [newPort, setNewPort] = useState(51820)
  const [newAddr, setNewAddr] = useState('')
  const [newDns, setNewDns] = useState('')
  const [newMtu, setNewMtu] = useState(1420)

  // Add peer form
  const [peerKey, setPeerKey] = useState('')
  const [peerAllowedIps, setPeerAllowedIps] = useState('')
  const [peerEndpoint, setPeerEndpoint] = useState('')
  const [peerKeepalive, setPeerKeepalive] = useState(25)

  const load = useCallback(async () => {
    try {
      const res = await api.getVpnTunnels()
      setTunnels(res.tunnels)
      const statusMap: Record<string, TunnelStatus> = {}
      for (const t of res.tunnels) {
        try {
          statusMap[t.name] = await api.getVpnTunnelStatus(t.name)
        } catch {
          // tunnel may be down
        }
      }
      setStatuses(statusMap)
      setError(null)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleCreate = async () => {
    try {
      await api.createVpnTunnel({
        name: newName,
        listen_port: newPort,
        address: newAddr,
        ...(newDns ? { dns: newDns } : {}),
        mtu: newMtu,
      })
      setShowCreate(false)
      setNewName(''); setNewPort(51820); setNewAddr(''); setNewDns(''); setNewMtu(1420)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleStartStop = async (name: string, isUp: boolean) => {
    try {
      if (isUp) { await api.stopVpnTunnel(name) } else { await api.startVpnTunnel(name) }
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleDeleteTunnel = async (name: string) => {
    try {
      await api.deleteVpnTunnel(name)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleAddPeer = async (tunnelName: string) => {
    try {
      const peer: WgPeer = {
        public_key: peerKey,
        allowed_ips: peerAllowedIps.split(',').map((s) => s.trim()).filter(Boolean),
        ...(peerEndpoint ? { endpoint: peerEndpoint } : {}),
        persistent_keepalive: peerKeepalive || undefined,
      }
      await api.addVpnPeer(tunnelName, peer)
      setAddPeerFor(null)
      setPeerKey(''); setPeerAllowedIps(''); setPeerEndpoint(''); setPeerKeepalive(25)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleRemovePeer = async (tunnelName: string, publicKey: string) => {
    try {
      await api.removeVpnPeer(tunnelName, publicKey)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const fmtBytes = (b: number) => {
    if (b < 1024) return `${b} B`
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / 1048576).toFixed(1)} MB`
  }

  if (loading) {
    return (
      <div className="flex items-center gap-3">
        <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
        <span className="text-sm font-mono text-gray-500">Loading VPN tunnels...</span>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">VPN Tunnels</h2>
        <button onClick={() => setShowCreate(!showCreate)} className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white">
          + Create Tunnel
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg p-4 mb-4">
          <p className="text-sm font-mono text-red-400">{error}</p>
        </div>
      )}

      {showCreate && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-4">
          <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-3">New WireGuard Tunnel</h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Name</span>
              <input type="text" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="wg0" className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200 placeholder-gray-600" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Listen Port</span>
              <input type="number" value={newPort} onChange={(e) => setNewPort(Number(e.target.value))} className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">Address (CIDR)</span>
              <input type="text" value={newAddr} onChange={(e) => setNewAddr(e.target.value)} placeholder="10.0.0.1/24" className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200 placeholder-gray-600" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">DNS</span>
              <input type="text" value={newDns} onChange={(e) => setNewDns(e.target.value)} placeholder="1.1.1.1" className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200 placeholder-gray-600" />
            </label>
            <label className="block">
              <span className="text-xs font-mono text-gray-500">MTU</span>
              <input type="number" value={newMtu} onChange={(e) => setNewMtu(Number(e.target.value))} className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm font-mono text-gray-200" />
            </label>
          </div>
          <div className="flex gap-2 mt-3">
            <button onClick={handleCreate} className="px-3 py-1.5 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white">Cancel</button>
          </div>
        </div>
      )}

      {tunnels.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-sm font-mono text-gray-500">No VPN tunnels configured.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {tunnels.map((tunnel) => {
            const status = statuses[tunnel.name]
            const isUp = status?.is_up ?? false
            return (
              <div key={tunnel.id} className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
                  <div className="flex items-center gap-3">
                    <span className={`w-2.5 h-2.5 rounded-full ${isUp ? 'bg-emerald-400' : 'bg-gray-600'}`} />
                    <span className="font-mono font-bold text-gray-200">{tunnel.name}</span>
                    <span className="text-xs font-mono text-gray-500">{tunnel.tunnel_type}</span>
                    <span className="text-xs font-mono text-gray-500">:{tunnel.listen_port}</span>
                    <span className="text-xs font-mono text-gray-600">{tunnel.address}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {status && (
                      <span className="text-xs font-mono text-gray-500">
                        rx {fmtBytes(status.rx_bytes)} / tx {fmtBytes(status.tx_bytes)}
                      </span>
                    )}
                    <button
                      onClick={() => handleStartStop(tunnel.name, isUp)}
                      className={`px-3 py-1 text-xs font-mono rounded ${isUp ? 'bg-amber-700 hover:bg-amber-600 text-white' : 'bg-emerald-600 hover:bg-emerald-500 text-white'}`}
                    >
                      {isUp ? 'Stop' : 'Start'}
                    </button>
                    <button onClick={() => handleDeleteTunnel(tunnel.name)} className="px-3 py-1 text-xs font-mono rounded bg-red-600 hover:bg-red-500 text-white">Delete</button>
                  </div>
                </div>

                {/* Public key */}
                <div className="px-4 py-2 text-xs font-mono text-gray-500">
                  Public Key: <span className="text-gray-400">{tunnel.public_key}</span>
                </div>

                {/* Peers */}
                {tunnel.peers.length > 0 && (
                  <div className="border-t border-gray-800">
                    <div className="px-4 py-2">
                      <span className="text-xs font-mono text-gray-500 uppercase tracking-wider">Peers</span>
                    </div>
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-800/50">
                          <th className="text-left px-4 py-1.5 text-xs text-gray-500 font-mono font-medium">Public Key</th>
                          <th className="text-left px-4 py-1.5 text-xs text-gray-500 font-mono font-medium">Allowed IPs</th>
                          <th className="text-left px-4 py-1.5 text-xs text-gray-500 font-mono font-medium">Endpoint</th>
                          <th className="text-left px-4 py-1.5 text-xs text-gray-500 font-mono font-medium"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {tunnel.peers.map((peer) => (
                          <tr key={peer.public_key} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                            <td className="px-4 py-2 font-mono text-gray-300 text-xs">{peer.public_key.slice(0, 20)}...</td>
                            <td className="px-4 py-2 font-mono text-gray-300 text-xs">{peer.allowed_ips.join(', ')}</td>
                            <td className="px-4 py-2 font-mono text-gray-300 text-xs">{peer.endpoint || '---'}</td>
                            <td className="px-4 py-2">
                              <button onClick={() => handleRemovePeer(tunnel.name, peer.public_key)} className="text-xs font-mono text-red-400 hover:text-red-300">Remove</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Add peer */}
                <div className="border-t border-gray-800 px-4 py-2">
                  {addPeerFor === tunnel.name ? (
                    <div className="space-y-2">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        <input type="text" value={peerKey} onChange={(e) => setPeerKey(e.target.value)} placeholder="Public Key" className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 placeholder-gray-600" />
                        <input type="text" value={peerAllowedIps} onChange={(e) => setPeerAllowedIps(e.target.value)} placeholder="Allowed IPs (comma-sep)" className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 placeholder-gray-600" />
                        <input type="text" value={peerEndpoint} onChange={(e) => setPeerEndpoint(e.target.value)} placeholder="Endpoint (optional)" className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 placeholder-gray-600" />
                        <input type="number" value={peerKeepalive} onChange={(e) => setPeerKeepalive(Number(e.target.value))} placeholder="Keepalive" className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 placeholder-gray-600" />
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => handleAddPeer(tunnel.name)} className="px-3 py-1 text-xs font-mono rounded bg-emerald-600 hover:bg-emerald-500 text-white">Add Peer</button>
                        <button onClick={() => setAddPeerFor(null)} className="px-3 py-1 text-xs font-mono rounded bg-gray-700 hover:bg-gray-600 text-white">Cancel</button>
                      </div>
                    </div>
                  ) : (
                    <button onClick={() => setAddPeerFor(tunnel.name)} className="text-xs font-mono text-emerald-400 hover:text-emerald-300">+ Add Peer</button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
