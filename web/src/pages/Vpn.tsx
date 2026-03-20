// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback, useRef } from 'react'
import {
  api,
  type VpnTunnel,
  type VpnPeer,
  type TunnelStatus,
  type WgPeer,
  type IpsecStatus,
  type IpsecMode,
  type IpsecAuthMethod,
  type CreateIpsecTunnelRequest,
  type SiteMesh,
  type SitePeer,
  type MeshStatus,
  type SiteConnectionState,
  type MeshTopology,
  type CreateMeshRequest,
  type CreateSiteRequest,
} from '../api'
import { PageHeader, Spinner, Button, Badge, Card, Modal, Input, Select, Tabs, EmptyState } from '../components/ui'
import { useToast } from '../hooks/useToast'
import QRCode from 'qrcode'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

const IKE_STATE_LABELS: Record<string, { label: string; variant: 'success' | 'warning' | 'danger' | 'neutral' }> = {
  established: { label: 'ESTABLISHED', variant: 'success' },
  connecting: { label: 'CONNECTING', variant: 'warning' },
  rekeying: { label: 'REKEYING', variant: 'warning' },
  none: { label: 'DOWN', variant: 'neutral' },
  unavailable: { label: 'UNAVAILABLE', variant: 'danger' },
}

// ---------------------------------------------------------------------------
// WireGuard modals (unchanged)
// ---------------------------------------------------------------------------

function ClientConfigModal({ tunnel, onClose }: { tunnel: VpnTunnel; onClose: () => void }) {
  const [clientKey, setClientKey] = useState('')
  const [clientIp, setClientIp] = useState('')
  const [copied, setCopied] = useState(false)

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

function PeerConfigModal({
  tunnelId,
  tunnelPort,
  peer,
  onClose,
}: {
  tunnelId: number
  tunnelPort: number
  peer: VpnPeer
  onClose: () => void
}) {
  const [config, setConfig] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [endpoint, setEndpoint] = useState('')
  const [copied, setCopied] = useState(false)
  const [showQr, setShowQr] = useState(false)
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const toast = useToast()

  useEffect(() => {
    const host = window.location.hostname
    setEndpoint(`${host}:${tunnelPort}`)
  }, [tunnelPort])

  const fetchConfig = useCallback(async () => {
    if (!endpoint) {
      setError('Server endpoint is required')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const res = await api.getVpnPeerConfig(tunnelId, peer.id, endpoint)
      setConfig(res.config)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [tunnelId, peer.id, endpoint])

  useEffect(() => {
    if (endpoint) fetchConfig()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!showQr || !config) {
      setQrDataUrl(null)
      return
    }
    QRCode.toDataURL(config, {
      width: 320,
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' },
      errorCorrectionLevel: 'M',
    }).then(setQrDataUrl).catch(() => {
      toast.error('Failed to generate QR code')
    })
  }, [showQr, config, toast])

  const handleDownload = () => {
    if (!config) return
    const blob = new Blob([config], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const safeName = (peer.name ?? `peer-${peer.id}`).replace(/[^a-zA-Z0-9_-]/g, '_')
    a.download = `${safeName}.conf`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleCopy = async () => {
    if (!config) return
    await navigator.clipboard.writeText(config)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const peerLabel = peer.name ?? `Peer ${peer.id}`

  return (
    <Modal open onClose={onClose} title={`Config: ${peerLabel}`} size="lg">
      <div className="space-y-4">
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <Input
              label="Server Endpoint (host:port)"
              mono
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="vpn.example.com:51820"
            />
          </div>
          <Button size="sm" variant="secondary" onClick={fetchConfig} disabled={loading || !endpoint}>
            {loading ? 'Loading...' : 'Refresh'}
          </Button>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
            <p className="text-[11px] text-red-400">{error}</p>
          </div>
        )}

        {loading && !config && <Spinner label="Fetching peer config..." />}

        {config && (
          <>
            {!showQr && (
              <div className="relative">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">WireGuard Config</p>
                  <div className="flex gap-2">
                    <Button size="sm" variant={copied ? 'primary' : 'secondary'} onClick={handleCopy}>
                      {copied ? 'Copied' : 'Copy'}
                    </Button>
                  </div>
                </div>
                <pre className="bg-navy-800/80 border border-navy-700/30 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-auto max-h-64 leading-relaxed select-all">
                  {config}
                </pre>
              </div>
            )}

            {showQr && qrDataUrl && (
              <div className="flex flex-col items-center gap-3">
                <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">
                  Scan with WireGuard mobile app
                </p>
                <div className="bg-white rounded-lg p-3">
                  <img src={qrDataUrl} alt="WireGuard QR Code" width={320} height={320} />
                </div>
                <canvas ref={canvasRef} className="hidden" />
              </div>
            )}

            <div className="flex items-center gap-2">
              <Button size="sm" onClick={handleDownload}>
                Download .conf
              </Button>
              <Button size="sm" variant={showQr ? 'primary' : 'secondary'} onClick={() => setShowQr(!showQr)}>
                {showQr ? 'Show Config' : 'Show QR Code'}
              </Button>
              <Button size="sm" variant="secondary" onClick={onClose}>Close</Button>
            </div>

            <div className="bg-amber-500/5 border border-amber-500/15 rounded-lg p-3">
              <p className="text-[11px] text-amber-400 font-medium">Security Notice</p>
              <p className="text-[10px] text-amber-400/70 mt-0.5">
                This config contains the peer's private key. Transfer it securely and do not share it.
              </p>
            </div>
          </>
        )}
      </div>
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// WireGuard tab
// ---------------------------------------------------------------------------

function WireGuardTab() {
  const [tunnels, setTunnels] = useState<VpnTunnel[]>([])
  const [statuses, setStatuses] = useState<Record<number, TunnelStatus>>({})
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [addPeerFor, setAddPeerFor] = useState<number | null>(null)
  const [clientConfigFor, setClientConfigFor] = useState<VpnTunnel | null>(null)
  const [peerConfigFor, setPeerConfigFor] = useState<{ tunnelId: number; tunnelPort: number; peer: VpnPeer } | null>(null)
  const [newTunnel, setNewTunnel] = useState({ name: '', port: 51820, addr: '', dns: '', mtu: 1420 })
  const [newPeer, setNewPeer] = useState({ name: '', key: '', allowedIps: '', endpoint: '', keepalive: 25, presharedKey: '' })
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getVpnTunnels()
      const wgTunnels = (res.tunnels ?? []).filter(t => t.tunnel_type === 'wireguard')
      setTunnels(wgTunnels)
      const statusMap: Record<number, TunnelStatus> = {}
      for (const t of wgTunnels) {
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

  if (loading) return <Spinner label="Loading WireGuard tunnels..." />

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={() => setShowCreate(true)}>+ Create WireGuard Tunnel</Button>
      </div>

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

      {clientConfigFor && (
        <ClientConfigModal tunnel={clientConfigFor} onClose={() => setClientConfigFor(null)} />
      )}

      {peerConfigFor && (
        <PeerConfigModal
          tunnelId={peerConfigFor.tunnelId}
          tunnelPort={peerConfigFor.tunnelPort}
          peer={peerConfigFor.peer}
          onClose={() => setPeerConfigFor(null)}
        />
      )}

      {tunnels.length === 0 ? (
        <EmptyState
          icon={<svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" /><path d="M9 12l2 2 4-4" /></svg>}
          title="No WireGuard tunnels configured"
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
                <div className="flex items-center justify-between px-5 py-4 border-b border-navy-800/30">
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <span className={`block w-2.5 h-2.5 rounded-full ${isUp ? 'bg-emerald-400' : 'bg-navy-600'}`} />
                      {isUp && <span className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping opacity-30" />}
                    </div>
                    <span className="text-sm font-semibold text-gray-200">{tunnel.name}</span>
                    <Badge variant={isUp ? 'success' : 'neutral'}>{isUp ? 'UP' : 'DOWN'}</Badge>
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

                <div className="px-5 py-2.5 text-xs font-mono text-navy-500 flex items-center gap-2">
                  <svg className="w-3 h-3 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" /></svg>
                  Public Key: <span className="text-gray-400 select-all">{tunnel.public_key}</span>
                </div>

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
                            {['Name', 'Address', 'Routing', 'Handshake', 'Transfer', ''].map((h) => (
                              <th key={h} className="text-left px-5 py-2 text-[10px] text-navy-500 font-medium">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {peers.map((peer) => {
                            const peerStatus = statusPeers.find((sp) => sp.public_key === peer.public_key)
                            return (
                              <tr key={peer.public_key} className="border-b border-navy-800/20 hover:bg-navy-800/20 transition-colors">
                                <td className="px-5 py-2.5 text-xs">
                                  <div className="flex flex-col">
                                    <span className="text-gray-300 font-medium">{peer.name ?? `Peer ${peer.id}`}</span>
                                    <span className="font-mono text-navy-500 text-[10px]" title={peer.public_key}>{peer.public_key.slice(0, 16)}...</span>
                                  </div>
                                </td>
                                <td className="px-5 py-2.5 font-mono text-gray-400 text-xs">
                                  {peer.address}
                                  {peer.address_v6 && <span className="text-navy-500 ml-1">+ v6</span>}
                                </td>
                                <td className="px-5 py-2.5 text-xs">
                                  <Badge variant={peer.routing_mode === 'full' ? 'warning' : 'neutral'}>
                                    {peer.routing_mode}
                                  </Badge>
                                </td>
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
                                  <div className="flex items-center gap-1.5">
                                    <Button
                                      variant="secondary"
                                      size="sm"
                                      onClick={() => setPeerConfigFor({
                                        tunnelId: tunnel.id,
                                        tunnelPort: tunnel.listen_port,
                                        peer,
                                      })}
                                      title="Download config / show QR code"
                                    >
                                      Config
                                    </Button>
                                    <Button variant="danger" size="sm" onClick={() => handleRemovePeer(tunnel.id, peer.id)}>Remove</Button>
                                  </div>
                                </td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

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

// ---------------------------------------------------------------------------
// IPSec tab
// ---------------------------------------------------------------------------

interface IpsecFormState {
  name: string
  mode: IpsecMode
  auth_method: IpsecAuthMethod
  local_id: string
  local_addrs: string
  pool_v4: string
  pool_v6: string
  local_ts: string
  remote_ts: string
  dns: string
}

const EMPTY_IPSEC_FORM: IpsecFormState = {
  name: '',
  mode: 'roadwarrior',
  auth_method: 'certificate',
  local_id: '',
  local_addrs: '',
  pool_v4: '10.10.0.0/24',
  pool_v6: '',
  local_ts: '',
  remote_ts: '',
  dns: '',
}

const MODE_OPTIONS = [
  { value: 'roadwarrior', label: 'Remote Access (Roadwarrior)' },
  { value: 'site-to-site', label: 'Site-to-Site' },
]

const AUTH_OPTIONS = [
  { value: 'certificate', label: 'Certificate (X.509)' },
  { value: 'psk', label: 'Pre-Shared Key' },
  { value: 'eap-mschapv2', label: 'EAP-MSCHAPv2 (Windows/macOS/iOS)' },
]

function IpsecCreateModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState<IpsecFormState>({ ...EMPTY_IPSEC_FORM })
  const [submitting, setSubmitting] = useState(false)
  const toast = useToast()

  const update = (patch: Partial<IpsecFormState>) => setForm(prev => ({ ...prev, ...patch }))

  const handleCreate = async () => {
    if (!form.name) {
      toast.error('Tunnel name is required')
      return
    }
    if (form.mode === 'roadwarrior' && !form.pool_v4 && !form.pool_v6) {
      toast.error('Roadwarrior mode requires at least one IP pool')
      return
    }

    setSubmitting(true)
    try {
      const body: CreateIpsecTunnelRequest = {
        tunnel_type: 'ipsec',
        name: form.name,
        mode: form.mode,
        auth_method: form.auth_method,
        ...(form.local_id ? { local_id: form.local_id } : {}),
        ...(form.local_addrs ? { local_addrs: form.local_addrs } : {}),
        ...(form.pool_v4 ? { pool_v4: form.pool_v4 } : {}),
        ...(form.pool_v6 ? { pool_v6: form.pool_v6 } : {}),
        ...(form.local_ts ? { local_ts: form.local_ts.split(',').map(s => s.trim()).filter(Boolean) } : {}),
        ...(form.remote_ts ? { remote_ts: form.remote_ts.split(',').map(s => s.trim()).filter(Boolean) } : {}),
        ...(form.dns ? { dns: form.dns } : {}),
      }
      await api.createIpsecTunnel(body)
      toast.success('IPSec tunnel created')
      setForm({ ...EMPTY_IPSEC_FORM })
      onClose()
      onCreated()
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="New IPSec/IKEv2 Tunnel" size="lg">
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Input label="Tunnel Name" value={form.name} onChange={e => update({ name: e.target.value })} placeholder="ipsec-rw" />
          <Select label="Mode" options={MODE_OPTIONS} value={form.mode} onChange={e => update({ mode: e.target.value as IpsecMode })} />
          <Select label="Authentication" options={AUTH_OPTIONS} value={form.auth_method} onChange={e => update({ auth_method: e.target.value as IpsecAuthMethod })} />
          <Input label="Local Identity" mono value={form.local_id} onChange={e => update({ local_id: e.target.value })} placeholder="gateway.secfirstgw.local" />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Input label="Local Address (bind)" mono value={form.local_addrs} onChange={e => update({ local_addrs: e.target.value })} placeholder="%any (all interfaces)" />
          <Input label="DNS Server" mono value={form.dns} onChange={e => update({ dns: e.target.value })} placeholder="10.10.0.1" />
        </div>

        {form.mode === 'roadwarrior' && (
          <div className="grid grid-cols-2 gap-3">
            <Input label="IPv4 Client Pool (CIDR)" mono value={form.pool_v4} onChange={e => update({ pool_v4: e.target.value })} placeholder="10.10.0.0/24" />
            <Input label="IPv6 Client Pool (CIDR)" mono value={form.pool_v6} onChange={e => update({ pool_v6: e.target.value })} placeholder="fd10::0/112" />
          </div>
        )}

        {form.mode === 'site-to-site' && (
          <div className="grid grid-cols-2 gap-3">
            <Input label="Local Subnets (comma-separated)" mono value={form.local_ts} onChange={e => update({ local_ts: e.target.value })} placeholder="192.168.1.0/24" />
            <Input label="Remote Subnets (comma-separated)" mono value={form.remote_ts} onChange={e => update({ remote_ts: e.target.value })} placeholder="192.168.2.0/24" />
          </div>
        )}

        {/* Security info */}
        <div className="bg-navy-800/50 border border-navy-700/30 rounded-lg p-3 space-y-1.5">
          <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">IKE/ESP Security</p>
          <div className="text-[10px] text-navy-500 space-y-0.5">
            <p>IKE: AES-256-GCM-16 + SHA-384 + X25519, ChaCha20-Poly1305 + SHA-384 + X25519</p>
            <p>ESP: AES-256-GCM-16 + SHA-384, ChaCha20-Poly1305 + SHA-384</p>
            <p>No 3DES, no MD5, no SHA-1, no weak DH groups. IKEv2 only.</p>
          </div>
        </div>

        {form.auth_method === 'psk' && (
          <div className="bg-amber-500/5 border border-amber-500/15 rounded-lg p-3">
            <p className="text-[11px] text-amber-400 font-medium">Pre-Shared Key</p>
            <p className="text-[10px] text-amber-400/70 mt-0.5">
              The PSK must be configured via CLI or config file after tunnel creation.
              Certificate authentication is recommended for production use.
            </p>
          </div>
        )}

        {form.auth_method === 'certificate' && (
          <div className="bg-emerald-500/5 border border-emerald-500/15 rounded-lg p-3">
            <p className="text-[11px] text-emerald-400 font-medium">Certificate Authentication</p>
            <p className="text-[10px] text-emerald-400/70 mt-0.5">
              Uses the gateway's CA certificate for mutual authentication. Server certificate must be installed
              in /etc/swanctl/x509/ before starting the tunnel.
            </p>
          </div>
        )}

        <div className="flex gap-2">
          <Button onClick={handleCreate} disabled={submitting}>
            {submitting ? 'Creating...' : 'Create IPSec Tunnel'}
          </Button>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </Modal>
  )
}

function IpsecStatusModal({ tunnel, onClose }: { tunnel: VpnTunnel; onClose: () => void }) {
  const [status, setStatus] = useState<IpsecStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const toast = useToast()

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await api.getIpsecTunnelStatus(tunnel.id)
        setStatus(res.status)
      } catch (e: unknown) {
        toast.error((e as Error).message)
      } finally {
        setLoading(false)
      }
    }
    fetchStatus()
  }, [tunnel.id, toast])

  const ikeInfo = status ? IKE_STATE_LABELS[status.ike_state] ?? { label: status.ike_state.toUpperCase(), variant: 'neutral' as const } : null

  return (
    <Modal open onClose={onClose} title={`IPSec Status: ${tunnel.name}`} size="lg">
      <div className="space-y-4">
        {loading && <Spinner label="Fetching SA status..." />}

        {status && (
          <>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider mb-1">IKE State</p>
                <Badge variant={ikeInfo!.variant}>{ikeInfo!.label}</Badge>
              </div>
              <div>
                <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider mb-1">Connection</p>
                <p className="text-sm text-gray-300">sfgw-{tunnel.name}</p>
              </div>
            </div>

            {status.child_sas.length > 0 ? (
              <div>
                <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider mb-2">Child SAs (Traffic Flows)</p>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-navy-800/30">
                        {['Name', 'State', 'Local TS', 'Remote TS'].map(h => (
                          <th key={h} className="text-left px-4 py-2 text-[10px] text-navy-500 font-medium">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {status.child_sas.map((sa, i) => (
                        <tr key={i} className="border-b border-navy-800/20">
                          <td className="px-4 py-2 text-xs text-gray-300">{sa.name || tunnel.name}</td>
                          <td className="px-4 py-2 text-xs">
                            <Badge variant={sa.state === 'installed' ? 'success' : 'warning'}>{sa.state.toUpperCase()}</Badge>
                          </td>
                          <td className="px-4 py-2 font-mono text-xs text-navy-400">{sa.local_ts || '---'}</td>
                          <td className="px-4 py-2 font-mono text-xs text-navy-400">{sa.remote_ts || '---'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="text-center py-4 text-xs text-navy-500">
                No active child SAs
              </div>
            )}
          </>
        )}

        <div className="flex gap-2">
          <Button variant="secondary" onClick={onClose}>Close</Button>
        </div>
      </div>
    </Modal>
  )
}

function IpsecTab() {
  const [tunnels, setTunnels] = useState<VpnTunnel[]>([])
  const [ipsecStatuses, setIpsecStatuses] = useState<Record<number, IpsecStatus>>({})
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [statusFor, setStatusFor] = useState<VpnTunnel | null>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getIpsecTunnels()
      const tunnelList = res.tunnels ?? []
      setTunnels(tunnelList)
      const statusMap: Record<number, IpsecStatus> = {}
      for (const t of tunnelList) {
        try {
          const s = await api.getIpsecTunnelStatus(t.id)
          statusMap[t.id] = s.status
        } catch { /* tunnel not running */ }
      }
      setIpsecStatuses(statusMap)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleStartStop = async (id: number, isUp: boolean) => {
    try {
      if (isUp) { await api.stopIpsecTunnel(id) } else { await api.startIpsecTunnel(id) }
      toast.success(isUp ? 'IPSec tunnel stopped' : 'IPSec tunnel started')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.deleteIpsecTunnel(id)
      toast.success('IPSec tunnel deleted')
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading IPSec tunnels..." />

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={() => setShowCreate(true)}>+ Create IPSec Tunnel</Button>
      </div>

      <IpsecCreateModal open={showCreate} onClose={() => setShowCreate(false)} onCreated={load} />

      {statusFor && (
        <IpsecStatusModal tunnel={statusFor} onClose={() => setStatusFor(null)} />
      )}

      {tunnels.length === 0 ? (
        <EmptyState
          icon={
            <svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.43C16.6 22.15 20 17.25 20 12V6l-8-4z" />
              <path d="M8 12h8M12 8v8" />
            </svg>
          }
          title="No IPSec tunnels configured"
          description="Create an IPSec/IKEv2 tunnel for site-to-site VPN or roadwarrior remote access using strongSwan."
        />
      ) : (
        <div className="space-y-4 stagger-children">
          {tunnels.map((tunnel) => {
            const status = ipsecStatuses[tunnel.id]
            const isUp = status?.is_up ?? false
            const ikeInfo = status
              ? IKE_STATE_LABELS[status.ike_state] ?? { label: status.ike_state.toUpperCase(), variant: 'neutral' as const }
              : { label: 'DOWN', variant: 'neutral' as const }

            // Parse mode from address field heuristic (pool means roadwarrior)
            const hasPool = !!tunnel.address && tunnel.address.includes('/')
            const modeLabel = hasPool ? 'Roadwarrior' : 'Site-to-Site'

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
                    <Badge variant={ikeInfo.variant}>{ikeInfo.label}</Badge>
                    <Badge variant="neutral">IPSec</Badge>
                    <Badge variant="neutral">{modeLabel}</Badge>
                    {tunnel.listen_port > 0 && (
                      <span className="text-xs font-mono text-navy-500">:{tunnel.listen_port}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Button size="sm" variant="secondary" onClick={() => setStatusFor(tunnel)}>SA Status</Button>
                    <Button size="sm" variant={isUp ? 'secondary' : 'primary'} onClick={() => handleStartStop(tunnel.id, isUp)}>
                      {isUp ? 'Stop' : 'Start'}
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => handleDelete(tunnel.id)}>Delete</Button>
                  </div>
                </div>

                {/* Details */}
                <div className="px-5 py-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                  {tunnel.address && (
                    <div>
                      <span className="text-navy-500">Pool / Subnet</span>
                      <p className="font-mono text-gray-300">{tunnel.address}</p>
                    </div>
                  )}
                  {tunnel.address_v6 && (
                    <div>
                      <span className="text-navy-500">IPv6 Pool</span>
                      <p className="font-mono text-gray-300">{tunnel.address_v6}</p>
                    </div>
                  )}
                  {tunnel.dns && (
                    <div>
                      <span className="text-navy-500">DNS</span>
                      <p className="font-mono text-gray-300">{tunnel.dns}</p>
                    </div>
                  )}
                  <div>
                    <span className="text-navy-500">Zone</span>
                    <p className="text-gray-300">{tunnel.zone}</p>
                  </div>
                </div>

                {/* Child SAs summary when active */}
                {isUp && status && status.child_sas.length > 0 && (
                  <div className="border-t border-navy-800/30 px-5 py-3">
                    <span className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">
                      Active SAs ({status.child_sas.length})
                    </span>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {status.child_sas.map((sa, i) => (
                        <span key={i} className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-navy-800/50 text-[10px]">
                          <span className={`w-1.5 h-1.5 rounded-full ${sa.state === 'installed' ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                          <span className="text-gray-300">{sa.name || tunnel.name}</span>
                          <span className="text-navy-500">{sa.state}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Site Mesh modals
// ---------------------------------------------------------------------------

function CreateMeshModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('')
  const [topology, setTopology] = useState<MeshTopology>('full-mesh')
  const [listenPort, setListenPort] = useState('51820')
  const [keepalive, setKeepalive] = useState('25')
  const [failoverTimeout, setFailoverTimeout] = useState('90')
  const [saving, setSaving] = useState(false)
  const toast = useToast()

  const handleCreate = async () => {
    if (!name.trim()) { toast.error('Name is required'); return }
    setSaving(true)
    try {
      await api.createSiteMesh({
        name: name.trim(),
        topology,
        listen_port: parseInt(listenPort) || 51820,
        keepalive_interval: parseInt(keepalive) || 25,
        failover_timeout_secs: parseInt(failoverTimeout) || 90,
      })
      toast.success('Site mesh created')
      onCreated()
      onClose()
      setName(''); setTopology('full-mesh'); setListenPort('51820')
      setKeepalive('25'); setFailoverTimeout('90')
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to create mesh')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Create Site Mesh">
      <div className="space-y-4">
        <Input label="Mesh Name" value={name} onChange={setName} placeholder="office-mesh" />
        <Select
          label="Topology"
          value={topology}
          onChange={(v) => setTopology(v as MeshTopology)}
          options={[
            { value: 'full-mesh', label: 'Full Mesh' },
            { value: 'hub-and-spoke', label: 'Hub and Spoke' },
          ]}
        />
        <Input label="Listen Port" value={listenPort} onChange={setListenPort} type="number" />
        <Input label="Keepalive Interval (s)" value={keepalive} onChange={setKeepalive} type="number" />
        <Input label="Failover Timeout (s)" value={failoverTimeout} onChange={setFailoverTimeout} type="number" />
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={handleCreate} disabled={saving}>
            {saving ? 'Creating...' : 'Create'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

function AddSiteModal({ open, onClose, meshId, onAdded }: { open: boolean; onClose: () => void; meshId: number; onAdded: () => void }) {
  const [name, setName] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [isLocal, setIsLocal] = useState(false)
  const [localSubnets, setLocalSubnets] = useState('')
  const [priority, setPriority] = useState('0')
  const [saving, setSaving] = useState(false)
  const toast = useToast()

  const handleAdd = async () => {
    if (!name.trim()) { toast.error('Name is required'); return }
    if (!endpoint.trim()) { toast.error('Endpoint is required'); return }
    if (!isLocal && !publicKey.trim()) { toast.error('Public key required for remote sites'); return }
    setSaving(true)
    try {
      const body: CreateSiteRequest = {
        name: name.trim(),
        endpoint: endpoint.trim(),
        is_local: isLocal,
        priority: parseInt(priority) || 0,
        local_subnets: localSubnets.split(',').map(s => s.trim()).filter(Boolean),
      }
      if (!isLocal && publicKey.trim()) {
        body.public_key = publicKey.trim()
      }
      await api.addSiteMeshPeer(meshId, body)
      toast.success('Site added')
      onAdded()
      onClose()
      setName(''); setEndpoint(''); setPublicKey(''); setIsLocal(false)
      setLocalSubnets(''); setPriority('0')
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to add site')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Add Site">
      <div className="space-y-4">
        <Input label="Site Name" value={name} onChange={setName} placeholder="branch-office" />
        <Input label="Endpoint (ip:port)" value={endpoint} onChange={setEndpoint} placeholder="203.0.113.1:51820" />
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input type="checkbox" checked={isLocal} onChange={(e) => setIsLocal(e.target.checked)}
            className="rounded border-navy-600 bg-navy-800 text-emerald-500 focus:ring-emerald-500/30" />
          This is the local site (keypair auto-generated)
        </label>
        {!isLocal && (
          <Input label="Public Key" value={publicKey} onChange={setPublicKey} placeholder="Base64-encoded WireGuard public key" />
        )}
        <Input label="Local Subnets (comma-separated)" value={localSubnets} onChange={setLocalSubnets} placeholder="10.0.1.0/24, 10.0.2.0/24" />
        <Input label="Priority (0 = primary)" value={priority} onChange={setPriority} type="number" />
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={handleAdd} disabled={saving}>
            {saving ? 'Adding...' : 'Add Site'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// Sites tab
// ---------------------------------------------------------------------------

const SITE_STATE_BADGES: Record<SiteConnectionState, { label: string; variant: 'success' | 'warning' | 'danger' | 'neutral' }> = {
  connected: { label: 'Connected', variant: 'success' },
  degraded: { label: 'Degraded', variant: 'warning' },
  down: { label: 'Down', variant: 'danger' },
  pending: { label: 'Pending', variant: 'neutral' },
}

function SitesTab() {
  const [meshes, setMeshes] = useState<SiteMesh[]>([])
  const [statuses, setStatuses] = useState<Record<number, MeshStatus>>({})
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [addSiteMeshId, setAddSiteMeshId] = useState<number | null>(null)
  const [expandedMesh, setExpandedMesh] = useState<number | null>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getSiteMeshes()
      setMeshes(res.meshes ?? [])
      // Fetch status for enabled meshes
      const newStatuses: Record<number, MeshStatus> = {}
      for (const mesh of (res.meshes ?? [])) {
        if (mesh.enabled) {
          try {
            const sr = await api.getSiteMeshStatus(mesh.id)
            newStatuses[mesh.id] = sr.status
          } catch { /* ignore */ }
        }
      }
      setStatuses(newStatuses)
    } catch { /* ignore */ }
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  // Auto-refresh status every 10s
  useEffect(() => {
    const timer = setInterval(async () => {
      const newStatuses: Record<number, MeshStatus> = {}
      for (const mesh of meshes) {
        if (mesh.enabled) {
          try {
            const sr = await api.getSiteMeshStatus(mesh.id)
            newStatuses[mesh.id] = sr.status
          } catch { /* ignore */ }
        }
      }
      setStatuses(newStatuses)
    }, 10000)
    return () => clearInterval(timer)
  }, [meshes])

  const handleToggle = async (mesh: SiteMesh) => {
    try {
      if (mesh.enabled) {
        await api.stopSiteMesh(mesh.id)
        toast.success(`Mesh "${mesh.name}" stopped`)
      } else {
        await api.startSiteMesh(mesh.id)
        toast.success(`Mesh "${mesh.name}" started`)
      }
      load()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Operation failed')
    }
  }

  const handleDelete = async (mesh: SiteMesh) => {
    if (!confirm(`Delete mesh "${mesh.name}"?`)) return
    try {
      await api.deleteSiteMesh(mesh.id)
      toast.success('Mesh deleted')
      load()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to delete')
    }
  }

  const handleRemoveSite = async (meshId: number, peerId: number) => {
    try {
      await api.removeSiteMeshPeer(meshId, peerId)
      toast.success('Site removed')
      load()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to remove site')
    }
  }

  if (loading) return <Spinner />

  if (meshes.length === 0) {
    return (
      <>
        <EmptyState
          title="No Site Meshes"
          description="Create a site-to-site WireGuard mesh to connect multiple locations with auto-failover."
          action={<Button onClick={() => setShowCreate(true)}>Create Mesh</Button>}
        />
        <CreateMeshModal open={showCreate} onClose={() => setShowCreate(false)} onCreated={load} />
      </>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={() => setShowCreate(true)}>Create Mesh</Button>
      </div>

      {meshes.map((mesh) => {
        const status = statuses[mesh.id]
        const isExpanded = expandedMesh === mesh.id
        const localSite = mesh.sites.find(s => s.is_local)
        const remoteSites = mesh.sites.filter(s => !s.is_local)

        return (
          <Card key={mesh.id} className="p-0 overflow-hidden">
            {/* Header */}
            <div
              className="flex items-center justify-between p-4 cursor-pointer hover:bg-navy-800/30 transition-colors"
              onClick={() => setExpandedMesh(isExpanded ? null : mesh.id)}
            >
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${mesh.enabled ? 'bg-emerald-400' : 'bg-navy-600'}`} />
                <div>
                  <div className="text-sm font-medium text-gray-200">{mesh.name}</div>
                  <div className="text-xs text-navy-400">
                    {mesh.topology} &middot; port {mesh.listen_port} &middot; {mesh.sites.length} site{mesh.sites.length !== 1 ? 's' : ''}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={mesh.enabled ? 'success' : 'neutral'}>
                  {mesh.enabled ? 'Active' : 'Stopped'}
                </Badge>
                <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); handleToggle(mesh) }}>
                  {mesh.enabled ? 'Stop' : 'Start'}
                </Button>
                <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); handleDelete(mesh) }}>
                  Delete
                </Button>
                <svg className={`w-4 h-4 text-navy-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>

            {/* Expanded details */}
            {isExpanded && (
              <div className="border-t border-navy-800/50 p-4 space-y-4">
                {/* Mesh config summary */}
                <div className="grid grid-cols-4 gap-4 text-xs">
                  <div>
                    <span className="text-navy-400">Keepalive</span>
                    <div className="text-gray-300">{mesh.keepalive_interval}s</div>
                  </div>
                  <div>
                    <span className="text-navy-400">Failover Timeout</span>
                    <div className="text-gray-300">{mesh.failover_timeout_secs}s</div>
                  </div>
                  <div>
                    <span className="text-navy-400">Topology</span>
                    <div className="text-gray-300">{mesh.topology}</div>
                  </div>
                  <div>
                    <span className="text-navy-400">Interface</span>
                    <div className="text-gray-300">sm{mesh.id}</div>
                  </div>
                </div>

                {/* Local site */}
                {localSite && (
                  <div className="bg-navy-900/50 rounded-lg p-3">
                    <div className="text-xs text-navy-400 mb-1">Local Site</div>
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm text-gray-200">{localSite.name}</div>
                        <div className="text-xs text-navy-400">
                          {localSite.endpoint} &middot; Subnets: {localSite.local_subnets.join(', ') || 'none'}
                        </div>
                      </div>
                      <div className="text-xs text-navy-500 font-mono truncate max-w-[200px]" title={localSite.public_key}>
                        {localSite.public_key.slice(0, 16)}...
                      </div>
                    </div>
                  </div>
                )}

                {/* Remote sites table */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-navy-400">Remote Sites</span>
                    <Button variant="ghost" size="sm" onClick={() => setAddSiteMeshId(mesh.id)}>
                      Add Site
                    </Button>
                  </div>
                  {remoteSites.length === 0 ? (
                    <div className="text-xs text-navy-500 text-center py-4">No remote sites configured</div>
                  ) : (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-xs text-navy-400 border-b border-navy-800/50">
                          <th className="text-left py-1.5 font-medium">Name</th>
                          <th className="text-left py-1.5 font-medium">Endpoint</th>
                          <th className="text-left py-1.5 font-medium">Subnets</th>
                          <th className="text-left py-1.5 font-medium">Priority</th>
                          <th className="text-left py-1.5 font-medium">Status</th>
                          <th className="text-left py-1.5 font-medium">Transfer</th>
                          <th className="text-right py-1.5 font-medium"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {remoteSites.map((site) => {
                          const siteStatus = status?.sites.find(s => s.site_id === site.id)
                          const stateInfo = siteStatus ? SITE_STATE_BADGES[siteStatus.state] : SITE_STATE_BADGES.pending
                          return (
                            <tr key={site.id} className="border-b border-navy-800/30 last:border-0">
                              <td className="py-2 text-gray-300">{site.name}</td>
                              <td className="py-2 text-navy-300 font-mono text-xs">{site.endpoint}</td>
                              <td className="py-2 text-navy-300 text-xs">{site.local_subnets.join(', ') || '-'}</td>
                              <td className="py-2 text-navy-300">{site.priority === 0 ? 'Primary' : `Backup (${site.priority})`}</td>
                              <td className="py-2">
                                <Badge variant={stateInfo.variant}>{stateInfo.label}</Badge>
                                {siteStatus?.last_handshake_secs ? (
                                  <span className="text-xs text-navy-500 ml-1">
                                    {fmtHandshake(Math.floor(Date.now() / 1000) - siteStatus.last_handshake_secs)}
                                  </span>
                                ) : null}
                              </td>
                              <td className="py-2 text-xs text-navy-400">
                                {siteStatus ? `${fmtBytes(siteStatus.rx_bytes)} / ${fmtBytes(siteStatus.tx_bytes)}` : '-'}
                              </td>
                              <td className="py-2 text-right">
                                <Button variant="ghost" size="sm" onClick={() => handleRemoveSite(mesh.id, site.id)}>
                                  Remove
                                </Button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}
          </Card>
        )
      })}

      <CreateMeshModal open={showCreate} onClose={() => setShowCreate(false)} onCreated={load} />
      {addSiteMeshId !== null && (
        <AddSiteModal
          open={true}
          onClose={() => setAddSiteMeshId(null)}
          meshId={addSiteMeshId}
          onAdded={load}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main VPN page with tabs
// ---------------------------------------------------------------------------

export default function Vpn() {
  const [activeTab, setActiveTab] = useState('wireguard')
  const [wgCount, setWgCount] = useState(0)
  const [ipsecCount, setIpsecCount] = useState(0)
  const [sitesCount, setSitesCount] = useState(0)

  // Fetch counts for tab badges
  useEffect(() => {
    const fetchCounts = async () => {
      try {
        const res = await api.getVpnTunnels()
        const all = res.tunnels ?? []
        setWgCount(all.filter(t => t.tunnel_type === 'wireguard').length)
        setIpsecCount(all.filter(t => t.tunnel_type === 'ipsec').length)
      } catch { /* ignore */ }
      try {
        const res = await api.getSiteMeshes()
        setSitesCount((res.meshes ?? []).length)
      } catch { /* ignore */ }
    }
    fetchCounts()
  }, [activeTab])

  return (
    <div className="space-y-6">
      <PageHeader
        title="VPN"
        subtitle={
          <span className="text-xs text-navy-400">
            {wgCount + ipsecCount} tunnel{wgCount + ipsecCount !== 1 ? 's' : ''}, {sitesCount} mesh{sitesCount !== 1 ? 'es' : ''} configured
          </span>
        }
      />

      <Tabs
        tabs={[
          { key: 'wireguard', label: 'WireGuard', count: wgCount },
          { key: 'ipsec', label: 'IPSec / IKEv2', count: ipsecCount },
          { key: 'sites', label: 'Sites', count: sitesCount },
        ]}
        active={activeTab}
        onChange={setActiveTab}
      />

      {activeTab === 'wireguard' && <WireGuardTab />}
      {activeTab === 'ipsec' && <IpsecTab />}
      {activeTab === 'sites' && <SitesTab />}
    </div>
  )
}
