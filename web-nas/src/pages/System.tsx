// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback, useRef } from 'react'
import {
  Network,
  FileText,
  Upload,
  Power,
  PowerOff,
  Key,
  Plus,
  Trash2,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react'
import {
  PageHeader,
  Tabs,
  Spinner,
  Card,
  Button,
  Badge,
  Modal,
  ConfirmDialog,
  Input,
  EmptyState,
} from '../components/ui'
import { api } from '../api'
import type { SystemStatus, NetworkInterface, LogEntry, SshKey } from '../types'

type TabKey = 'network' | 'logs' | 'firmware' | 'ssh'

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

const logLevelBadge = (level: string | undefined) => {
  switch (level) {
    case 'error': return 'danger' as const
    case 'warn': return 'warning' as const
    case 'info': return 'info' as const
    case 'debug': return 'neutral' as const
    default: return 'neutral' as const
  }
}

export default function System() {
  const [activeTab, setActiveTab] = useState<TabKey>('network')
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [networkInterfaces, setNetworkInterfaces] = useState<NetworkInterface[]>([])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [sshKeys, setSshKeys] = useState<SshKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Log controls
  const [logLines, setLogLines] = useState(100)
  const [logFilter, setLogFilter] = useState('')
  const logContainerRef = useRef<HTMLDivElement>(null)

  // SSH key modal
  const [showAddKey, setShowAddKey] = useState(false)
  const [newKeyData, setNewKeyData] = useState('')
  const [deleteKeyTarget, setDeleteKeyTarget] = useState<string | null>(null)

  // System actions
  const [confirmAction, setConfirmAction] = useState<'reboot' | 'shutdown' | null>(null)
  const [actionLoading, setActionLoading] = useState(false)

  // Firmware
  const [firmwareFile, setFirmwareFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [submitting, setSubmitting] = useState(false)

  const fetchNetworkInterfaces = useCallback(async () => {
    try {
      const ifaces = await api.getNetworkInterfaces()
      setNetworkInterfaces(Array.isArray(ifaces) ? ifaces : [])
    } catch {
      // Network endpoint may not be available
    }
  }, [])

  const fetchStatus = useCallback(async () => {
    try {
      const s = await api.getStatus()
      setStatus(s)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load status')
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchLogs = useCallback(async () => {
    try {
      const l = await api.getLogs(logLines)
      setLogs(Array.isArray(l) ? l : [])
    } catch {
      // Logs may not be available
    }
  }, [logLines])

  const fetchSshKeys = useCallback(async () => {
    try {
      const keys = await api.getSshKeys()
      setSshKeys(Array.isArray(keys) ? keys : [])
    } catch {
      // SSH keys may not be available
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    fetchNetworkInterfaces()
  }, [fetchStatus, fetchNetworkInterfaces])

  useEffect(() => {
    if (activeTab === 'network') {
      fetchNetworkInterfaces()
    }
  }, [activeTab, fetchNetworkInterfaces])

  useEffect(() => {
    if (activeTab === 'logs') {
      fetchLogs()
    }
  }, [activeTab, fetchLogs])

  useEffect(() => {
    if (activeTab === 'ssh') {
      fetchSshKeys()
    }
  }, [activeTab, fetchSshKeys])

  const handleSystemAction = async () => {
    if (!confirmAction) return
    setActionLoading(true)
    try {
      if (confirmAction === 'reboot') {
        await api.reboot()
      } else {
        await api.shutdown()
      }
      setConfirmAction(null)
    } catch {
      // Error
    } finally {
      setActionLoading(false)
    }
  }

  const handleAddSshKey = async () => {
    if (!newKeyData.trim()) return
    setSubmitting(true)
    try {
      await api.addSshKey(newKeyData.trim())
      setShowAddKey(false)
      setNewKeyData('')
      await fetchSshKeys()
    } catch {
      // Error
    } finally {
      setSubmitting(false)
    }
  }

  const handleDeleteSshKey = async () => {
    if (!deleteKeyTarget) return
    setSubmitting(true)
    try {
      await api.deleteSshKey(deleteKeyTarget)
      setDeleteKeyTarget(null)
      await fetchSshKeys()
    } catch {
      // Error
    } finally {
      setSubmitting(false)
    }
  }

  const handleFirmwareUpload = async () => {
    if (!firmwareFile) return
    setUploading(true)
    setUploadProgress('Uploading firmware...')
    try {
      await api.uploadFirmware(firmwareFile)
      setUploadProgress('Upload complete. Device will restart shortly.')
      setFirmwareFile(null)
    } catch {
      setUploadProgress('Upload failed. Please try again.')
    } finally {
      setUploading(false)
    }
  }

  const filteredLogs = logFilter
    ? logs.filter(
        (l) =>
          (l.message ?? '').toLowerCase().includes(logFilter.toLowerCase()) ||
          (l.service ?? '').toLowerCase().includes(logFilter.toLowerCase()) ||
          (l.level ?? '').toLowerCase().includes(logFilter.toLowerCase())
      )
    : logs

  if (loading) return <Spinner label="Loading system info..." />

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <p className="text-sm text-red-400 mb-2">Failed to load system status</p>
          <p className="text-xs text-navy-500">{error}</p>
          <Button variant="secondary" size="sm" className="mt-4" onClick={fetchStatus}>
            Retry
          </Button>
        </div>
      </div>
    )
  }

  const interfaces = networkInterfaces.length > 0 ? networkInterfaces : (status?.network?.interfaces ?? [])

  return (
    <div className="space-y-6">
      <PageHeader
        title="System"
        subtitle={
          <span className="text-xs text-navy-400">
            {status?.hostname ?? 'Unknown'} &middot; {status?.kernel_version ?? ''}
          </span>
        }
        actions={
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={() => setConfirmAction('reboot')}>
              <Power className="w-3.5 h-3.5 mr-1.5 inline" />
              Reboot
            </Button>
            <Button variant="danger" size="sm" onClick={() => setConfirmAction('shutdown')}>
              <PowerOff className="w-3.5 h-3.5 mr-1.5 inline" />
              Shutdown
            </Button>
          </div>
        }
      />

      <Tabs
        tabs={[
          { key: 'network', label: 'Network' },
          { key: 'logs', label: 'Logs' },
          { key: 'firmware', label: 'Firmware' },
          { key: 'ssh', label: 'SSH Keys', count: sshKeys.length },
        ]}
        active={activeTab}
        onChange={(k) => setActiveTab(k as TabKey)}
      />

      {/* Network tab */}
      {activeTab === 'network' && (
        <div className="space-y-4">
          {interfaces.length > 0 ? (
            interfaces.map((iface) => (
              <Card key={iface.name}>
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
                      <Network className="w-5 h-5 text-sky-400" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-gray-100">{iface.name}</h3>
                      {iface.mac && (
                        <p className="text-[11px] text-navy-400 font-mono">{iface.mac}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {iface.state && (
                      <Badge variant={iface.state === 'up' ? 'success' : 'danger'}>
                        {iface.state}
                      </Badge>
                    )}
                    {(iface.link_speed_mbps ?? iface.speed_mbps) != null && (
                      <span className="text-xs text-navy-400">{iface.link_speed_mbps ?? iface.speed_mbps} Mbps</span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="p-3 bg-navy-800/30 rounded-lg">
                    <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1">IPv4</p>
                    <p className="text-sm text-gray-200 font-mono">{iface.ipv4 || 'Not configured'}</p>
                  </div>
                  <div className="p-3 bg-navy-800/30 rounded-lg">
                    <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1">IPv6</p>
                    <p className="text-sm text-gray-200 font-mono">{iface.ipv6 || 'Not configured'}</p>
                  </div>
                </div>

                {(iface.tx_bytes != null || iface.rx_bytes != null) && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
                    <div className="text-center p-2">
                      <p className="text-[10px] text-navy-500 uppercase tracking-wider">TX Bytes</p>
                      <p className="text-sm text-gray-200 font-mono tabular-nums mt-0.5">{fmtBytes(iface.tx_bytes ?? 0)}</p>
                    </div>
                    <div className="text-center p-2">
                      <p className="text-[10px] text-navy-500 uppercase tracking-wider">RX Bytes</p>
                      <p className="text-sm text-gray-200 font-mono tabular-nums mt-0.5">{fmtBytes(iface.rx_bytes ?? 0)}</p>
                    </div>
                    {iface.tx_packets != null && (
                      <div className="text-center p-2">
                        <p className="text-[10px] text-navy-500 uppercase tracking-wider">TX Packets</p>
                        <p className="text-sm text-gray-200 font-mono tabular-nums mt-0.5">{(iface.tx_packets ?? 0).toLocaleString()}</p>
                      </div>
                    )}
                    {iface.rx_packets != null && (
                      <div className="text-center p-2">
                        <p className="text-[10px] text-navy-500 uppercase tracking-wider">RX Packets</p>
                        <p className="text-sm text-gray-200 font-mono tabular-nums mt-0.5">{(iface.rx_packets ?? 0).toLocaleString()}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Show addresses from API if available */}
                {(iface.addresses ?? []).length > 0 && (
                  <div className="mt-4 p-3 bg-navy-800/30 rounded-lg">
                    <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1">Addresses</p>
                    <div className="space-y-1">
                      {(iface.addresses ?? []).map((addr, i) => (
                        <p key={i} className="text-sm text-gray-200 font-mono">{addr}</p>
                      ))}
                    </div>
                  </div>
                )}
              </Card>
            ))
          ) : (
            <EmptyState
              icon={<Network className="w-12 h-12" />}
              title="No network interfaces detected"
              description="Network interface data is not available from the API."
            />
          )}
        </div>
      )}

      {/* Logs tab */}
      {activeTab === 'logs' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Input
              placeholder="Filter logs..."
              value={logFilter}
              onChange={(e) => setLogFilter(e.target.value)}
              className="max-w-xs"
              mono
            />
            <select
              value={logLines}
              onChange={(e) => setLogLines(Number(e.target.value))}
              className="bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50"
            >
              <option value={50}>50 lines</option>
              <option value={100}>100 lines</option>
              <option value={200}>200 lines</option>
              <option value={500}>500 lines</option>
            </select>
            <Button variant="secondary" size="sm" onClick={fetchLogs}>
              <RefreshCw className="w-3.5 h-3.5 mr-1.5 inline" />
              Refresh
            </Button>
          </div>

          <Card noPadding>
            <div
              ref={logContainerRef}
              className="max-h-[60vh] overflow-y-auto font-mono text-xs"
            >
              {filteredLogs.length > 0 ? (
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-navy-800/50 sticky top-0 bg-navy-900">
                      <th className="text-left px-3 py-2 text-[10px] text-navy-400 uppercase tracking-wider w-40">Time</th>
                      <th className="text-left px-3 py-2 text-[10px] text-navy-400 uppercase tracking-wider w-16">Level</th>
                      <th className="text-left px-3 py-2 text-[10px] text-navy-400 uppercase tracking-wider w-28">Service</th>
                      <th className="text-left px-3 py-2 text-[10px] text-navy-400 uppercase tracking-wider">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map((log, i) => (
                      <tr key={i} className="border-b border-navy-800/20 hover:bg-navy-800/20">
                        <td className="px-3 py-1.5 text-navy-500 whitespace-nowrap">
                          {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td className="px-3 py-1.5">
                          <Badge variant={logLevelBadge(log.level)}>{log.level ?? 'info'}</Badge>
                        </td>
                        <td className="px-3 py-1.5 text-navy-400">{log.service ?? ''}</td>
                        <td className="px-3 py-1.5 text-gray-300 break-all">{log.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="p-12 text-center">
                  <FileText className="w-8 h-8 text-navy-700 mx-auto mb-2" />
                  <p className="text-xs text-navy-500">
                    {logFilter ? 'No logs match the filter' : 'No log entries available'}
                  </p>
                </div>
              )}
            </div>
          </Card>
        </div>
      )}

      {/* Firmware tab */}
      {activeTab === 'firmware' && (
        <Card title="Firmware Update">
          <div className="space-y-4">
            <div className="p-4 bg-navy-800/30 rounded-lg border border-navy-800/50">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm text-gray-200 font-medium">Firmware Update</p>
                  <p className="text-xs text-navy-400 mt-1">
                    Uploading a firmware image will restart the device. Ensure you have a valid
                    firmware image before proceeding. Do not power off the device during the update process.
                  </p>
                </div>
              </div>
            </div>

            {status && (
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-navy-800/30 rounded-lg">
                  <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1">Current Version</p>
                  <p className="text-sm text-gray-200 font-mono">{status.kernel_version || 'N/A'}</p>
                </div>
                <div className="p-3 bg-navy-800/30 rounded-lg">
                  <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1">Hardware</p>
                  <p className="text-sm text-gray-200">{status.hardware_model || 'N/A'}</p>
                </div>
              </div>
            )}

            <div className="border-2 border-dashed border-navy-700/50 rounded-xl p-8 text-center">
              <input
                ref={fileInputRef}
                type="file"
                accept=".bin,.img,.fw"
                onChange={(e) => setFirmwareFile(e.target.files?.[0] ?? null)}
                className="hidden"
              />
              <Upload className="w-10 h-10 text-navy-600 mx-auto mb-3" />
              {firmwareFile ? (
                <div>
                  <p className="text-sm text-gray-200">{firmwareFile.name}</p>
                  <p className="text-xs text-navy-400 mt-1">{fmtBytes(firmwareFile.size)}</p>
                </div>
              ) : (
                <div>
                  <p className="text-sm text-navy-400">Select a firmware image</p>
                  <p className="text-xs text-navy-600 mt-1">.bin, .img, .fw files accepted</p>
                </div>
              )}
              <Button
                variant="secondary"
                size="sm"
                className="mt-3"
                onClick={() => fileInputRef.current?.click()}
              >
                Choose File
              </Button>
            </div>

            {uploadProgress && (
              <div className="p-3 bg-navy-800/30 rounded-lg">
                <p className="text-xs text-gray-300">{uploadProgress}</p>
              </div>
            )}

            <div className="flex justify-end">
              <Button
                size="sm"
                onClick={handleFirmwareUpload}
                loading={uploading}
                disabled={!firmwareFile}
              >
                <Upload className="w-3.5 h-3.5 mr-1.5 inline" />
                Upload & Install
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* SSH keys tab */}
      {activeTab === 'ssh' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <Button size="sm" onClick={() => setShowAddKey(true)}>
              <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
              Add SSH Key
            </Button>
          </div>

          {sshKeys.length > 0 ? (
            <div className="space-y-3">
              {sshKeys.map((key) => (
                <Card key={key.fingerprint} className="!p-0">
                  <div className="flex items-center justify-between p-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
                        <Key className="w-5 h-5 text-violet-400" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-medium text-gray-100">{key.comment || 'Unnamed key'}</h3>
                          {key.type && <Badge variant="info">{key.type}</Badge>}
                        </div>
                        <p className="text-[11px] text-navy-400 font-mono mt-0.5">{key.fingerprint}</p>
                        {key.added && (
                          <p className="text-[10px] text-navy-500 mt-0.5">
                            Added: {new Date(key.added).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                    </div>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => setDeleteKeyTarget(key.fingerprint)}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<Key className="w-12 h-12" />}
              title="No SSH keys configured"
              description="Add SSH keys for secure remote access."
              action={
                <Button size="sm" onClick={() => setShowAddKey(true)}>
                  <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                  Add SSH Key
                </Button>
              }
            />
          )}
        </div>
      )}

      {/* Add SSH key modal */}
      <Modal
        open={showAddKey}
        onClose={() => setShowAddKey(false)}
        title="Add SSH Key"
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-[11px] font-medium text-navy-400 mb-1.5">Public Key</label>
            <textarea
              value={newKeyData}
              onChange={(e) => setNewKeyData(e.target.value)}
              placeholder="ssh-ed25519 AAAA... user@host"
              rows={4}
              className="w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:border-emerald-500/50 transition-colors placeholder-navy-600 resize-none"
            />
            <p className="text-[10px] text-navy-500 mt-1">
              Paste your public key (ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256)
            </p>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="secondary" size="sm" onClick={() => setShowAddKey(false)} disabled={submitting}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleAddSshKey} loading={submitting} disabled={!newKeyData.trim()}>
              Add Key
            </Button>
          </div>
        </div>
      </Modal>

      {/* Reboot/Shutdown confirmation */}
      <ConfirmDialog
        open={confirmAction !== null}
        onClose={() => setConfirmAction(null)}
        onConfirm={handleSystemAction}
        title={confirmAction === 'reboot' ? 'Reboot Device' : 'Shutdown Device'}
        message={
          confirmAction === 'reboot'
            ? 'Are you sure you want to reboot the NAS? All active connections will be interrupted.'
            : 'Are you sure you want to shut down the NAS? You will need physical access to power it back on.'
        }
        confirmLabel={confirmAction === 'reboot' ? 'Reboot' : 'Shutdown'}
        variant="danger"
        loading={actionLoading}
      />

      {/* Delete SSH key confirmation */}
      <ConfirmDialog
        open={deleteKeyTarget !== null}
        onClose={() => setDeleteKeyTarget(null)}
        onConfirm={handleDeleteSshKey}
        title="Delete SSH Key"
        message="Are you sure you want to delete this SSH key? This will revoke access for anyone using it."
        confirmLabel="Delete"
        variant="danger"
        loading={submitting}
      />
    </div>
  )
}
