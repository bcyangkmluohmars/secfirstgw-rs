import { useEffect, useState, useCallback } from 'react'
import { api, type VpnTunnel, type TunnelStatus, type WgPeer } from '../api'

const inputCls = 'bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 placeholder-navy-600 focus:outline-none focus:border-emerald-500/50 transition-colors'

export default function Vpn() {
  const [tunnels, setTunnels] = useState<VpnTunnel[]>([])
  const [statuses, setStatuses] = useState<Record<number, TunnelStatus>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [addPeerFor, setAddPeerFor] = useState<number | null>(null)

  const [newName, setNewName] = useState('')
  const [newPort, setNewPort] = useState(51820)
  const [newAddr, setNewAddr] = useState('')
  const [newDns, setNewDns] = useState('')
  const [newMtu, setNewMtu] = useState(1420)

  const [peerKey, setPeerKey] = useState('')
  const [peerAllowedIps, setPeerAllowedIps] = useState('')
  const [peerEndpoint, setPeerEndpoint] = useState('')
  const [peerKeepalive, setPeerKeepalive] = useState(25)

  const load = useCallback(async () => {
    try {
      const res = await api.getVpnTunnels()
      setTunnels(res.tunnels)
      const statusMap: Record<number, TunnelStatus> = {}
      for (const t of res.tunnels) {
        try {
          statusMap[t.id] = await api.getVpnTunnelStatus(t.id)
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

  const handleStartStop = async (id: number, isUp: boolean) => {
    try {
      if (isUp) { await api.stopVpnTunnel(id) } else { await api.startVpnTunnel(id) }
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleDeleteTunnel = async (id: number) => {
    try {
      await api.deleteVpnTunnel(id)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleAddPeer = async (tunnelId: number) => {
    try {
      const peer: WgPeer = {
        public_key: peerKey,
        allowed_ips: peerAllowedIps.split(',').map((s) => s.trim()).filter(Boolean),
        ...(peerEndpoint ? { endpoint: peerEndpoint } : {}),
        persistent_keepalive: peerKeepalive || undefined,
      }
      await api.addVpnPeer(tunnelId, peer)
      setAddPeerFor(null)
      setPeerKey(''); setPeerAllowedIps(''); setPeerEndpoint(''); setPeerKeepalive(25)
      load()
    } catch (e: unknown) {
      setError((e as Error).message)
    }
  }

  const handleRemovePeer = async (tunnelId: number, peerId: number) => {
    try {
      await api.removeVpnPeer(tunnelId, peerId)
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
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-navy-400">Loading VPN tunnels...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-100">VPN Tunnels</h2>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors"
        >
          + Create Tunnel
        </button>
      </div>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 animate-fade-in">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {showCreate && (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-4">New WireGuard Tunnel</p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Name</span>
              <input type="text" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="wg0" className={`mt-1 block w-full ${inputCls}`} />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Listen Port</span>
              <input type="number" value={newPort} onChange={(e) => setNewPort(Number(e.target.value))} className={`mt-1 block w-full ${inputCls}`} />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">Address (CIDR)</span>
              <input type="text" value={newAddr} onChange={(e) => setNewAddr(e.target.value)} placeholder="10.0.0.1/24" className={`mt-1 block w-full ${inputCls}`} />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">DNS</span>
              <input type="text" value={newDns} onChange={(e) => setNewDns(e.target.value)} placeholder="1.1.1.1" className={`mt-1 block w-full ${inputCls}`} />
            </label>
            <label className="block">
              <span className="text-[11px] font-medium text-navy-400">MTU</span>
              <input type="number" value={newMtu} onChange={(e) => setNewMtu(Number(e.target.value))} className={`mt-1 block w-full ${inputCls}`} />
            </label>
          </div>
          <div className="flex gap-2 mt-4">
            <button onClick={handleCreate} className="px-4 py-2 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 text-xs font-medium rounded-lg bg-navy-800 text-gray-400 border border-navy-700/50 hover:bg-navy-700/50 transition-colors">Cancel</button>
          </div>
        </div>
      )}

      {tunnels.length === 0 ? (
        <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-16 text-center animate-fade-in">
          <svg className="w-12 h-12 text-navy-700 mx-auto mb-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 13.17l6.59-6.59L18 8l-8 8z" />
          </svg>
          <p className="text-sm font-medium text-navy-400">No VPN tunnels configured</p>
          <p className="text-xs text-navy-600 mt-2">Create a WireGuard tunnel to get started.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {tunnels.map((tunnel) => {
            const status = statuses[tunnel.id]
            const isUp = status?.is_up ?? false
            return (
              <div key={tunnel.id} className="bg-navy-900 border border-navy-800/50 rounded-xl overflow-hidden animate-fade-in">
                <div className="flex items-center justify-between px-5 py-4 border-b border-navy-800/30">
                  <div className="flex items-center gap-3">
                    <span className={`w-2.5 h-2.5 rounded-full ${isUp ? 'bg-emerald-400 animate-pulse-dot' : 'bg-navy-600'}`} />
                    <span className="text-sm font-semibold text-gray-200">{tunnel.name}</span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-md border bg-navy-800 text-navy-400 border-navy-700/50 uppercase">{tunnel.tunnel_type}</span>
                    <span className="text-xs font-mono text-navy-500">:{tunnel.listen_port}</span>
                    <span className="text-xs font-mono text-navy-600">{tunnel.address}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    {status && (
                      <span className="text-xs font-mono text-navy-500 tabular-nums">
                        rx {fmtBytes(status.rx_bytes)} / tx {fmtBytes(status.tx_bytes)}
                      </span>
                    )}
                    <button
                      onClick={() => handleStartStop(tunnel.id, isUp)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
                        isUp
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/15 hover:bg-amber-500/20'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20'
                      }`}
                    >
                      {isUp ? 'Stop' : 'Start'}
                    </button>
                    <button onClick={() => handleDeleteTunnel(tunnel.id)} className="px-3 py-1.5 text-xs font-medium rounded-lg bg-red-500/10 text-red-400 border border-red-500/15 hover:bg-red-500/20 transition-colors">Delete</button>
                  </div>
                </div>

                <div className="px-5 py-2.5 text-xs font-mono text-navy-500">
                  Public Key: <span className="text-gray-400 select-all">{tunnel.public_key}</span>
                </div>

                {tunnel.peers.length > 0 && (
                  <div className="border-t border-navy-800/30">
                    <div className="px-5 py-2.5">
                      <span className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">Peers</span>
                    </div>
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-navy-800/30">
                          <th className="text-left px-5 py-2 text-[10px] text-navy-500 font-medium">Public Key</th>
                          <th className="text-left px-5 py-2 text-[10px] text-navy-500 font-medium">Allowed IPs</th>
                          <th className="text-left px-5 py-2 text-[10px] text-navy-500 font-medium">Endpoint</th>
                          <th className="px-5 py-2"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {tunnel.peers.map((peer) => (
                          <tr key={peer.public_key} className="border-b border-navy-800/20 hover:bg-navy-800/20 transition-colors">
                            <td className="px-5 py-2.5 font-mono text-gray-400 text-xs">{peer.public_key.slice(0, 20)}...</td>
                            <td className="px-5 py-2.5 font-mono text-gray-400 text-xs">{peer.allowed_ips.join(', ')}</td>
                            <td className="px-5 py-2.5 font-mono text-gray-400 text-xs tabular-nums">{peer.endpoint || '---'}</td>
                            <td className="px-5 py-2.5">
                              <button onClick={() => handleRemovePeer(tunnel.id, peer.id)} className="text-[11px] font-medium text-red-400/60 hover:text-red-400 transition-colors">Remove</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                <div className="border-t border-navy-800/30 px-5 py-3">
                  {addPeerFor === tunnel.id ? (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        <input type="text" value={peerKey} onChange={(e) => setPeerKey(e.target.value)} placeholder="Public Key" className={inputCls} />
                        <input type="text" value={peerAllowedIps} onChange={(e) => setPeerAllowedIps(e.target.value)} placeholder="Allowed IPs (comma-sep)" className={inputCls} />
                        <input type="text" value={peerEndpoint} onChange={(e) => setPeerEndpoint(e.target.value)} placeholder="Endpoint (optional)" className={inputCls} />
                        <input type="number" value={peerKeepalive} onChange={(e) => setPeerKeepalive(Number(e.target.value))} placeholder="Keepalive" className={inputCls} />
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => handleAddPeer(tunnel.id)} className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors">Add Peer</button>
                        <button onClick={() => setAddPeerFor(null)} className="px-3 py-1.5 text-xs font-medium rounded-lg bg-navy-800 text-gray-400 border border-navy-700/50 hover:bg-navy-700/50 transition-colors">Cancel</button>
                      </div>
                    </div>
                  ) : (
                    <button onClick={() => setAddPeerFor(tunnel.id)} className="text-xs font-medium text-emerald-400/70 hover:text-emerald-400 transition-colors">+ Add Peer</button>
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
