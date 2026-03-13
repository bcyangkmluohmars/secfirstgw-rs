// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type VpnTunnel, type TunnelStatus, type WgPeer } from '../api'
import { PageHeader, Spinner, Button, Badge, Card, Modal, Input, EmptyState } from '../components/ui'
import { useToast } from '../hooks/useToast'

const fmtBytes = (b: number) => {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

const fmtHandshake = (secs: number) => {
  if (secs <= 0) return 'never'
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  return `${Math.floor(secs / 3600)}h ago`
}

function ClientConfigModal({ tunnel, onClose }: { tunnel: VpnTunnel; onClose: () => void }) {
  const [clientKey, setClientKey] = useState('')
  const [clientIp, setClientIp] = useState('')
  const [copied, setCopied] = useState(false)

  // Derive suggested client IP from tunnel address
  useEffect(() => {
    const match = tunnel.address.match(/^(\d+\.\d+\.\d+\.)(\d+)\//)
    if (match) {
      const peers = tunnel.peers ?? []
      const nextOctet = peers.length + 2
      setClientIp(`${match[1]}${nextOctet}/32`)
    }
  }, [tunnel])

  const config = `[Interface]
PrivateKey = <client-private-key>
Address = ${clientIp}
DNS = ${tunnel.dns || '1.1.1.1'}
MTU = ${tunnel.mtu}

[Peer]
PublicKey = ${tunnel.public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = <server-ip>:${tunnel.listen_port}
PersistentKeepalive = 25`

  const handleCopy = async () => {
    await navigator.clipboard.writeText(config)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Modal open onClose={onClose} title={`Client Config: ${tunnel.name}`} size="lg">
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Input label="Client Public Key" mono value={clientKey} onChange={(e) => setClientKey(e.target.value)} placeholder="Paste client public key" />
          <Input label="Client IP (CIDR)" mono value={clientIp} onChange={(e) => setClientIp(e.target.value)} placeholder="10.0.0.2/32" />
        </div>

        <div className="relative">
          <div className="flex items-center justify-between mb-2">
            <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">Generated Client Config</p>
            <Button size="sm" variant={copied ? 'primary' : 'secondary'} onClick={handleCopy}>
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
          <pre className="bg-navy-800/80 border border-navy-700/30 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-auto max-h-64 leading-relaxed select-all">
            {config}
          </pre>
        </div>

        <div className="bg-amber-500/5 border border-amber-500/15 rounded-lg p-3">
          <p className="text-[11px] text-amber-400 font-medium">Replace placeholders</p>
          <p className="text-[10px] text-amber-400/70 mt-0.5">
            {'<client-private-key>'} = client's private key, {'<server-ip>'} = this gateway's public IP
          </p>
        </div>

        <div className="flex gap-2">
          <Button variant="secondary" onClick={onClose}>Close</Button>
        </div>
      </div>
    </Modal>
  )
}

export default function Vpn() {
  const [tunnels, setTunnels] = useState<VpnTunnel[]>([])
  const [statuses, setStatuses] = useState<Record<number, TunnelStatus>>({})
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [addPeerFor, setAddPeerFor] = useState<number | null>(null)
  const [clientConfigFor, setClientConfigFor] = useState<VpnTunnel | null>(null)
  const [newTunnel, setNewTunnel] = useState({ name: '', port: 51820, addr: '', dns: '', mtu: 1420 })
  const [newPeer, setNewPeer] = useState({ name: '', key: '', allowedIps: '', endpoint: '', keepalive: 25, presharedKey: '' })
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getVpnTunnels()
      const tunnelList = res.tunnels ?? []
      setTunnels(tunnelList)
      const statusMap: Record<number, TunnelStatus> = {}
      for (const t of tunnelList) {
        try { statusMap[t.id] = await api.getVpnTunnelStatus(t.id) } catch { /* tunnel down */ }
      }
      setStatuses(statusMap)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleCreate = async () => {
    if (!newTunnel.name || !newTunnel.addr) {
      toast.error('Name and address are required')
      return
    }
    try {
      await api.createVpnTunnel({
        name: newTunnel.name,
        listen_port: newTunnel.port,
        address: newTunnel.addr,
        ...(newTunnel.dns ? { dns: newTunnel.dns } : {}),
        mtu: newTunnel.mtu,
      })
      setShowCreate(false)
      setNewTunnel({ name: '', port: 51820, addr: '', dns: '', mtu: 1420 })
      toast.success('Tunnel created')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleStartStop = async (id: number, isUp: boolean) => {
    try {
      if (isUp) { await api.stopVpnTunnel(id) } else { await api.startVpnTunnel(id) }
      toast.success(isUp ? 'Tunnel stopped' : 'Tunnel started')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDelete = async (id: number) => {
    try { await api.deleteVpnTunnel(id); toast.success('Tunnel deleted'); load() }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleAddPeer = async (tunnelId: number) => {
    if (!newPeer.key || !newPeer.allowedIps) {
      toast.error('Public key and allowed IPs are required')
      return
    }
    try {
      const peer: WgPeer = {
        public_key: newPeer.key,
        allowed_ips: newPeer.allowedIps.split(',').map((s) => s.trim()).filter(Boolean),
        ...(newPeer.endpoint ? { endpoint: newPeer.endpoint } : {}),
        ...(newPeer.presharedKey ? { preshared_key: newPeer.presharedKey } : {}),
        persistent_keepalive: newPeer.keepalive || undefined,
      }
      await api.addVpnPeer(tunnelId, peer)
      setAddPeerFor(null)
      setNewPeer({ name: '', key: '', allowedIps: '', endpoint: '', keepalive: 25, presharedKey: '' })
      toast.success('Peer added')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleRemovePeer = async (tunnelId: number, peerId: number) => {
    try { await api.removeVpnPeer(tunnelId, peerId); toast.success('Peer removed'); load() }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading VPN tunnels..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="VPN Tunnels"
        actions={<Button onClick={() => setShowCreate(true)}>+ Create Tunnel</Button>}
        subtitle={tunnels.length > 0 ? (
          <span className="text-xs text-navy-400">
            {tunnels.length} tunnel{tunnels.length !== 1 ? 's' : ''}
            {' / '}
            {Object.values(statuses).filter((s) => s?.is_up).length} active
          </span>
        ) : undefined}
      />

      {/* Create Tunnel Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="New WireGuard Tunnel">
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <Input label="Name" value={newTunnel.name} onChange={(e) => setNewTunnel({ ...newTunnel, name: e.target.value })} placeholder="wg0" />
            <Input label="Listen Port" type="number" mono value={newTunnel.port} onChange={(e) => setNewTunnel({ ...newTunnel, port: Number(e.target.value) })} />
            <Input label="Address (CIDR)" mono value={newTunnel.addr} onChange={(e) => setNewTunnel({ ...newTunnel, addr: e.target.value })} placeholder="10.0.0.1/24" />
            <Input label="DNS Server" mono value={newTunnel.dns} onChange={(e) => setNewTunnel({ ...newTunnel, dns: e.target.value })} placeholder="1.1.1.1" />
            <Input label="MTU" type="number" mono value={newTunnel.mtu} onChange={(e) => setNewTunnel({ ...newTunnel, mtu: Number(e.target.value) })} />
          </div>
          <div className="bg-navy-800/50 border border-navy-700/30 rounded-lg p-3">
            <p className="text-[10px] text-navy-400">A keypair will be generated automatically on the server. After creation, use "Client Config" to generate configs for peers.</p>
          </div>
          <div className="flex gap-2">
            <Button onClick={handleCreate}>Create Tunnel</Button>
            <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Add Peer Modal */}
      <Modal open={addPeerFor !== null} onClose={() => setAddPeerFor(null)} title="Add Peer">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <Input label="Peer Name (optional)" value={newPeer.name} onChange={(e) => setNewPeer({ ...newPeer, name: e.target.value })} placeholder="Phone, Laptop..." />
            <Input label="Public Key" mono value={newPeer.key} onChange={(e) => setNewPeer({ ...newPeer, key: e.target.value })} />
            <Input label="Allowed IPs" mono value={newPeer.allowedIps} onChange={(e) => setNewPeer({ ...newPeer, allowedIps: e.target.value })} placeholder="10.0.0.2/32" />
            <Input label="Endpoint (optional)" mono value={newPeer.endpoint} onChange={(e) => setNewPeer({ ...newPeer, endpoint: e.target.value })} placeholder="host:port" />
            <Input label="Preshared Key (optional)" mono value={newPeer.presharedKey} onChange={(e) => setNewPeer({ ...newPeer, presharedKey: e.target.value })} />
            <Input label="Keepalive (s)" type="number" mono value={newPeer.keepalive} onChange={(e) => setNewPeer({ ...newPeer, keepalive: Number(e.target.value) })} />
          </div>
          <div className="flex gap-2">
            <Button onClick={() => addPeerFor !== null && handleAddPeer(addPeerFor)}>Add Peer</Button>
            <Button variant="secondary" onClick={() => setAddPeerFor(null)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Client Config Modal */}
      {clientConfigFor && (
        <ClientConfigModal tunnel={clientConfigFor} onClose={() => setClientConfigFor(null)} />
      )}

      {tunnels.length === 0 ? (
        <EmptyState
          icon={<svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" /><path d="M9 12l2 2 4-4" /></svg>}
          title="No VPN tunnels configured"
          description="Create a WireGuard tunnel to establish encrypted site-to-site or remote access connectivity."
        />
      ) : (
        <div className="space-y-4 stagger-children">
          {tunnels.map((tunnel) => {
            const status = statuses[tunnel.id]
            const isUp = status?.is_up ?? false
            const peers = tunnel.peers ?? []
            const statusPeers = status?.peers ?? []

            return (
              <Card key={tunnel.id} noPadding>
                {/* Header */}
                <div className="flex items-center justify-between px-5 py-4 border-b border-navy-800/30">
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <span className={`block w-2.5 h-2.5 rounded-full ${isUp ? 'bg-emerald-400' : 'bg-navy-600'}`} />
                      {isUp && <span className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping opacity-30" />}
                    </div>
                    <span className="text-sm font-semibold text-gray-200">{tunnel.name}</span>
                    <Badge variant={isUp ? 'success' : 'neutral'}>{isUp ? 'UP' : 'DOWN'}</Badge>
                    <Badge>{tunnel.tunnel_type}</Badge>
                    <span className="text-xs font-mono text-navy-500">:{tunnel.listen_port}</span>
                    <span className="text-xs font-mono text-navy-600">{tunnel.address}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {status && (
                      <span className="text-[10px] font-mono text-navy-500 tabular-nums mr-2">
                        rx {fmtBytes(status.rx_bytes)} / tx {fmtBytes(status.tx_bytes)}
                      </span>
                    )}
                    <Button size="sm" variant="secondary" onClick={() => setClientConfigFor(tunnel)}>Client Config</Button>
                    <Button size="sm" variant={isUp ? 'secondary' : 'primary'} onClick={() => handleStartStop(tunnel.id, isUp)}>{isUp ? 'Stop' : 'Start'}</Button>
                    <Button size="sm" variant="danger" onClick={() => handleDelete(tunnel.id)}>Delete</Button>
                  </div>
                </div>

                {/* Public Key */}
                <div className="px-5 py-2.5 text-xs font-mono text-navy-500 flex items-center gap-2">
                  <svg className="w-3 h-3 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" /></svg>
                  Public Key: <span className="text-gray-400 select-all">{tunnel.public_key}</span>
                </div>

                {/* Peer traffic sparklines (when active) */}
                {isUp && statusPeers.length > 0 && (
                  <div className="border-t border-navy-800/30 px-5 py-3">
                    <div className="grid grid-cols-2 gap-4 text-xs">
                      <div>
                        <span className="text-navy-500">Total RX</span>
                        <p className="font-mono text-gray-300 tabular-nums">{fmtBytes(status!.rx_bytes)}</p>
                      </div>
                      <div>
                        <span className="text-navy-500">Total TX</span>
                        <p className="font-mono text-gray-300 tabular-nums">{fmtBytes(status!.tx_bytes)}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Peers */}
                {peers.length > 0 && (
                  <div className="border-t border-navy-800/30">
                    <div className="px-5 py-2.5 flex items-center justify-between">
                      <span className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">
                        Peers ({peers.length})
                      </span>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-navy-800/30">
                            {['Public Key', 'Allowed IPs', 'Endpoint', 'Handshake', 'Transfer', ''].map((h) => (
                              <th key={h} className="text-left px-5 py-2 text-[10px] text-navy-500 font-medium">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {peers.map((peer) => {
                            const peerStatus = statusPeers.find((sp) => sp.public_key === peer.public_key)
                            return (
                              <tr key={peer.public_key} className="border-b border-navy-800/20 hover:bg-navy-800/20 transition-colors">
                                <td className="px-5 py-2.5 font-mono text-gray-400 text-xs">
                                  <span title={peer.public_key}>{peer.public_key.slice(0, 16)}...</span>
                                </td>
                                <td className="px-5 py-2.5 font-mono text-gray-400 text-xs">{(peer.allowed_ips ?? []).join(', ')}</td>
                                <td className="px-5 py-2.5 font-mono text-gray-400 text-xs tabular-nums">{peer.endpoint || '---'}</td>
                                <td className="px-5 py-2.5 text-xs">
                                  {peerStatus ? (
                                    <span className={peerStatus.last_handshake_secs < 180 ? 'text-emerald-400' : 'text-navy-500'}>
                                      {fmtHandshake(peerStatus.last_handshake_secs)}
                                    </span>
                                  ) : (
                                    <span className="text-navy-600">---</span>
                                  )}
                                </td>
                                <td className="px-5 py-2.5 font-mono text-navy-500 text-[10px] tabular-nums">
                                  {peerStatus
                                    ? `rx ${fmtBytes(peerStatus.rx_bytes)} / tx ${fmtBytes(peerStatus.tx_bytes)}`
                                    : '---'}
                                </td>
                                <td className="px-5 py-2.5">
                                  <Button variant="danger" size="sm" onClick={() => handleRemovePeer(tunnel.id, peer.id)}>Remove</Button>
                                </td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Add Peer button */}
                <div className="border-t border-navy-800/30 px-5 py-3 flex items-center gap-2">
                  <Button variant="ghost" size="sm" onClick={() => setAddPeerFor(tunnel.id)}>+ Add Peer</Button>
                  {peers.length === 0 && (
                    <span className="text-[10px] text-navy-600">No peers yet. Add a peer or generate a client config to get started.</span>
                  )}
                </div>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
