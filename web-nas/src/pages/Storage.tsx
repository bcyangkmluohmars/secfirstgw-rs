// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import {
  HardDrive,
  Database,
  Plus,
  RefreshCw,
  GitBranch,
  Camera,
  Shield,
  Trash2,
} from 'lucide-react'
import {
  PageHeader,
  Tabs,
  Spinner,
  Card,
  Button,
  Modal,
  Select,
  Input,
  Badge,
  DataTable,
  EmptyState,
} from '../components/ui'
import DiskCard from '../components/DiskCard'
import RaidStatus from '../components/RaidStatus'
import BayVisualization from '../components/BayVisualization'
import { api } from '../api'
import type {
  Disk,
  BayInfo,
  RaidArray,
  CreateArrayRequest,
  RaidLevel,
  BtrfsSubvolume,
  BtrfsScrub,
  BtrfsSnapshot,
  BtrfsUsage,
} from '../types'

function fmtBytes(bytes: number): string {
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(0)} MB`
  if (bytes < 1e12) return `${(bytes / 1e9).toFixed(1)} GB`
  return `${(bytes / 1e12).toFixed(2)} TB`
}

type TabKey = 'disks' | 'arrays' | 'btrfs'

export default function Storage() {
  const [activeTab, setActiveTab] = useState<TabKey>('disks')
  const [disks, setDisks] = useState<Disk[]>([])
  const [bays, setBays] = useState<BayInfo[]>([])
  const [arrays, setArrays] = useState<RaidArray[]>([])
  const [subvolumes, setSubvolumes] = useState<BtrfsSubvolume[]>([])
  const [snapshots, setSnapshots] = useState<BtrfsSnapshot[]>([])
  const [scrub, setScrub] = useState<BtrfsScrub | null>(null)
  const [btrfsUsage, setBtrfsUsage] = useState<BtrfsUsage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Create array modal
  const [showCreateArray, setShowCreateArray] = useState(false)
  const [createName, setCreateName] = useState('')
  const [createLevel, setCreateLevel] = useState<RaidLevel>('raid1')
  const [createFs, setCreateFs] = useState('btrfs')
  const [selectedDevices, setSelectedDevices] = useState<string[]>([])
  const [creating, setCreating] = useState(false)

  // Btrfs modals
  const [showCreateSubvolume, setShowCreateSubvolume] = useState(false)
  const [newSubvolumeName, setNewSubvolumeName] = useState('')
  const [creatingSubvolume, setCreatingSubvolume] = useState(false)
  const [confirmDeleteSubvolume, setConfirmDeleteSubvolume] = useState<string | null>(null)
  const [confirmDeleteSnapshot, setConfirmDeleteSnapshot] = useState<string | null>(null)
  const [snapshotTarget, setSnapshotTarget] = useState<string | null>(null)
  const [snapshotName, setSnapshotName] = useState('')
  const [creatingSnapshot, setCreatingSnapshot] = useState(false)

  const fetchData = useCallback(async () => {
    try {
      const [d, b, a] = await Promise.all([
        api.getDisks(),
        api.getBays(),
        api.getArrays(),
      ])
      const fetchedBays = Array.isArray(b) ? b : []
      // Enrich disks with bay slot numbers from enriched bays
      const fetchedDisks = (Array.isArray(d) ? d : []).map((disk) => {
        if (disk.bay != null) return disk
        const matchedBay = fetchedBays.find((bay) => bay.device === disk.device)
        if (matchedBay) {
          return { ...disk, bay: matchedBay.bay ?? matchedBay.slot ?? null }
        }
        return disk
      })
      setDisks(fetchedDisks)
      setBays(fetchedBays)
      setArrays(Array.isArray(a) ? a : [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load storage data')
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchBtrfs = useCallback(async () => {
    try {
      const [sv, sn, sc, usage] = await Promise.all([
        api.getSubvolumes(),
        api.getSnapshots(),
        api.getScrubStatus(),
        api.getBtrfsUsage(),
      ])
      setSubvolumes(Array.isArray(sv) ? sv : [])
      setSnapshots(Array.isArray(sn) ? sn : [])
      setScrub(sc ?? null)
      setBtrfsUsage(usage ?? null)
    } catch {
      // Btrfs endpoints may not be available
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  useEffect(() => {
    if (activeTab === 'btrfs') {
      fetchBtrfs()
    }
  }, [activeTab, fetchBtrfs])

  const handleCreateArray = async () => {
    if (!createName.trim() || selectedDevices.length === 0) return
    setCreating(true)
    try {
      const req: CreateArrayRequest = {
        name: createName.trim(),
        level: createLevel,
        devices: selectedDevices,
        filesystem: createFs,
      }
      await api.createArray(req)
      setShowCreateArray(false)
      setCreateName('')
      setSelectedDevices([])
      await fetchData()
    } catch {
      // Error handling
    } finally {
      setCreating(false)
    }
  }

  const handleStartScrub = async () => {
    try {
      await api.startScrub()
      await fetchBtrfs()
    } catch {
      // Error handling
    }
  }

  const handleCreateSubvolume = async () => {
    const name = newSubvolumeName.trim()
    if (!name) return
    setCreatingSubvolume(true)
    try {
      await api.createSubvolume(name)
      setShowCreateSubvolume(false)
      setNewSubvolumeName('')
      await fetchBtrfs()
    } catch {
      // Error handling
    } finally {
      setCreatingSubvolume(false)
    }
  }

  const handleDeleteSubvolume = async (name: string) => {
    try {
      await api.deleteSubvolume(name)
      setConfirmDeleteSubvolume(null)
      await fetchBtrfs()
    } catch {
      // Error handling
    }
  }

  const handleCreateSnapshot = async () => {
    if (!snapshotTarget) return
    setCreatingSnapshot(true)
    try {
      const name = snapshotName.trim() || undefined
      await api.createSnapshot(snapshotTarget, name)
      setSnapshotTarget(null)
      setSnapshotName('')
      await fetchBtrfs()
    } catch {
      // Error handling
    } finally {
      setCreatingSnapshot(false)
    }
  }

  const handleDeleteSnapshot = async (name: string) => {
    try {
      await api.deleteSnapshot(name)
      setConfirmDeleteSnapshot(null)
      await fetchBtrfs()
    } catch {
      // Error handling
    }
  }

  /** Validate a Btrfs name: alphanumeric + hyphens + underscores, 1-64 chars. */
  const isValidBtrfsName = (name: string): boolean => {
    if (name.length === 0 || name.length > 64) return false
    return /^[a-zA-Z0-9_-]+$/.test(name)
  }

  const toggleDevice = (dev: string) => {
    setSelectedDevices((prev) =>
      prev.includes(dev)
        ? prev.filter((d) => d !== dev)
        : [...prev, dev]
    )
  }

  if (loading) return <Spinner label="Loading storage..." />

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <p className="text-sm text-red-400 mb-2">Failed to load storage data</p>
          <p className="text-xs text-navy-500">{error}</p>
          <Button variant="secondary" size="sm" className="mt-4" onClick={fetchData}>
            Retry
          </Button>
        </div>
      </div>
    )
  }

  // Find disks not in any array
  const arrayDevices = new Set(
    arrays.flatMap((a) => (a.devices ?? []).map((d) => d.device))
  )
  const availableDisks = disks.filter((d) => !arrayDevices.has(d.device))

  return (
    <div className="space-y-6">
      <PageHeader
        title="Storage"
        subtitle={
          <span className="text-xs text-navy-400">
            {disks.length} disk{disks.length !== 1 ? 's' : ''} &middot; {arrays.length} array{arrays.length !== 1 ? 's' : ''}
          </span>
        }
        actions={
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={fetchData}>
              <RefreshCw className="w-3.5 h-3.5 mr-1.5 inline" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setShowCreateArray(true)}>
              <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
              Create Array
            </Button>
          </div>
        }
      />

      <Tabs
        tabs={[
          { key: 'disks', label: 'Disks', count: disks.length },
          { key: 'arrays', label: 'Arrays', count: arrays.length },
          { key: 'btrfs', label: 'Btrfs' },
        ]}
        active={activeTab}
        onChange={(k) => setActiveTab(k as TabKey)}
      />

      {/* Bay visualization (always visible) */}
      <Card title="Bay Mapping">
        <BayVisualization bays={bays} />
      </Card>

      {/* Disks tab */}
      {activeTab === 'disks' && (
        <div className="space-y-4">
          {disks.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {disks.map((disk) => (
                <DiskCard key={disk.serial ?? disk.device} disk={disk} />
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<HardDrive className="w-12 h-12" />}
              title="No disks detected"
              description="Insert drives into the NAS bays to get started."
            />
          )}
        </div>
      )}

      {/* Arrays tab */}
      {activeTab === 'arrays' && (
        <div className="space-y-4">
          {arrays.length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {arrays.map((arr) => (
                <RaidStatus
                  key={arr.uuid ?? arr.name}
                  array={arr}
                  availableDisks={availableDisks}
                  onRefresh={fetchData}
                />
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<Database className="w-12 h-12" />}
              title="No arrays configured"
              description="Create a RAID array to start using your storage."
              action={
                <Button size="sm" onClick={() => setShowCreateArray(true)}>
                  <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                  Create Array
                </Button>
              }
            />
          )}
        </div>
      )}

      {/* Btrfs tab */}
      {activeTab === 'btrfs' && (
        <div className="space-y-6">
          {/* Usage */}
          {btrfsUsage && btrfsUsage.total_bytes > 0 && (
            <Card title="Filesystem Usage">
              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-300">
                    {fmtBytes(btrfsUsage.used_bytes)} used of {fmtBytes(btrfsUsage.total_bytes)}
                  </span>
                  <span className="text-navy-400">
                    {fmtBytes(btrfsUsage.free_estimated)} free
                  </span>
                </div>
                <div className="w-full h-3 bg-navy-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      btrfsUsage.used_bytes / btrfsUsage.total_bytes > 0.9
                        ? 'bg-red-500'
                        : btrfsUsage.used_bytes / btrfsUsage.total_bytes > 0.75
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                    }`}
                    style={{
                      width: `${Math.min(100, (btrfsUsage.used_bytes / btrfsUsage.total_bytes) * 100).toFixed(1)}%`,
                    }}
                  />
                </div>
                <p className="text-xs text-navy-500">
                  {((btrfsUsage.used_bytes / btrfsUsage.total_bytes) * 100).toFixed(1)}% used
                </p>
              </div>
            </Card>
          )}

          {/* Scrub status */}
          <Card
            title="Scrub"
            actions={
              <Button size="sm" variant="secondary" onClick={handleStartScrub} disabled={scrub?.running}>
                <Shield className="w-3.5 h-3.5 mr-1.5 inline" />
                {scrub?.running ? 'Scrubbing...' : 'Start Scrub'}
              </Button>
            }
          >
            {scrub ? (
              <div className="space-y-2">
                <div className="flex items-center gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${scrub.running ? 'bg-amber-400 animate-pulse-dot' : 'bg-emerald-400'}`} />
                    <span className="text-gray-300">{scrub.running ? 'Running' : 'Idle'}</span>
                  </div>
                  {scrub.last_run && (
                    <span className="text-xs text-navy-400">
                      Last run: {new Date(scrub.last_run).toLocaleString()}
                    </span>
                  )}
                  {(scrub.errors_found ?? 0) > 0 && (
                    <Badge variant="danger">{scrub.errors_found} errors</Badge>
                  )}
                  {(scrub.errors_found ?? 0) === 0 && scrub.last_run && (
                    <Badge variant="success">No errors</Badge>
                  )}
                </div>
                {scrub.bytes_scrubbed != null && (
                  <p className="text-xs text-navy-500">
                    Scrubbed: {fmtBytes(scrub.bytes_scrubbed)}
                    {scrub.duration_secs != null && ` in ${Math.floor(scrub.duration_secs / 60)}m ${scrub.duration_secs % 60}s`}
                  </p>
                )}
              </div>
            ) : (
              <p className="text-xs text-navy-500">No scrub data available</p>
            )}
          </Card>

          {/* Subvolumes */}
          <Card
            title="Subvolumes"
            noPadding
            actions={
              <Button size="sm" onClick={() => setShowCreateSubvolume(true)}>
                <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                Create Subvolume
              </Button>
            }
          >
            {subvolumes.length > 0 ? (
              <DataTable
                columns={[
                  {
                    key: 'name',
                    header: 'Name',
                    render: (sv: BtrfsSubvolume) => (
                      <div className="flex items-center gap-2">
                        <GitBranch className="w-3.5 h-3.5 text-navy-500" />
                        <span className="font-mono text-sm text-gray-200">{sv.name}</span>
                      </div>
                    ),
                  },
                  { key: 'path', header: 'Path', className: 'font-mono text-xs text-navy-400' },
                  {
                    key: 'size_bytes',
                    header: 'Size',
                    render: (sv: BtrfsSubvolume) => (
                      <span className="font-mono text-xs text-gray-300">
                        {sv.size_bytes != null ? fmtBytes(sv.size_bytes) : 'N/A'}
                      </span>
                    ),
                  },
                  {
                    key: 'actions',
                    header: '',
                    render: (sv: BtrfsSubvolume) => (
                      <div className="flex items-center gap-1 justify-end">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => {
                            setSnapshotTarget(sv.name)
                            setSnapshotName('')
                          }}
                        >
                          <Camera className="w-3 h-3 mr-1 inline" />
                          Snapshot
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() => setConfirmDeleteSubvolume(sv.name)}
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    ),
                  },
                ]}
                data={subvolumes}
                keyField="id"
                emptyMessage="No subvolumes found"
              />
            ) : (
              <EmptyState
                icon={<GitBranch className="w-12 h-12" />}
                title="No subvolumes"
                description="Create a subvolume to organize your storage."
                action={
                  <Button size="sm" onClick={() => setShowCreateSubvolume(true)}>
                    <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                    Create Subvolume
                  </Button>
                }
              />
            )}
          </Card>

          {/* Snapshots */}
          <Card title="Snapshots" noPadding>
            {snapshots.length > 0 ? (
              <DataTable
                columns={[
                  {
                    key: 'name',
                    header: 'Name',
                    render: (s: BtrfsSnapshot) => (
                      <div className="flex items-center gap-2">
                        <Camera className="w-3.5 h-3.5 text-navy-500" />
                        <span className="font-mono text-sm text-gray-200">{s.name}</span>
                      </div>
                    ),
                  },
                  {
                    key: 'source_subvolume',
                    header: 'Source',
                    className: 'font-mono text-xs text-navy-400',
                  },
                  {
                    key: 'created',
                    header: 'Created',
                    render: (s: BtrfsSnapshot) => (
                      <span className="text-xs text-navy-400">
                        {s.created ? new Date(s.created).toLocaleString() : 'N/A'}
                      </span>
                    ),
                  },
                  {
                    key: 'actions',
                    header: '',
                    render: (s: BtrfsSnapshot) => (
                      <div className="flex justify-end">
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() => setConfirmDeleteSnapshot(s.name)}
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    ),
                  },
                ]}
                data={snapshots}
                keyField="name"
                emptyMessage="No snapshots found"
              />
            ) : (
              <div className="p-8 text-center">
                <p className="text-xs text-navy-500">No Btrfs snapshots found. Take a snapshot from a subvolume above.</p>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* Create subvolume modal */}
      <Modal
        open={showCreateSubvolume}
        onClose={() => {
          setShowCreateSubvolume(false)
          setNewSubvolumeName('')
        }}
        title="Create Subvolume"
        size="sm"
      >
        <div className="space-y-4">
          <Input
            label="Subvolume Name"
            value={newSubvolumeName}
            onChange={(e) => setNewSubvolumeName(e.target.value)}
            placeholder="documents"
            mono
          />
          <p className="text-[11px] text-navy-500">
            Alphanumeric characters, hyphens, and underscores only. Max 64 characters.
          </p>
          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setShowCreateSubvolume(false)
                setNewSubvolumeName('')
              }}
              disabled={creatingSubvolume}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleCreateSubvolume}
              loading={creatingSubvolume}
              disabled={!isValidBtrfsName(newSubvolumeName.trim())}
            >
              Create
            </Button>
          </div>
        </div>
      </Modal>

      {/* Confirm delete subvolume modal */}
      <Modal
        open={confirmDeleteSubvolume !== null}
        onClose={() => setConfirmDeleteSubvolume(null)}
        title="Delete Subvolume"
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-300">
            Are you sure you want to delete subvolume{' '}
            <span className="font-mono text-red-400">{confirmDeleteSubvolume}</span>?
            This action is irreversible and all data within it will be lost.
          </p>
          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setConfirmDeleteSubvolume(null)}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => {
                if (confirmDeleteSubvolume) {
                  handleDeleteSubvolume(confirmDeleteSubvolume)
                }
              }}
            >
              Delete
            </Button>
          </div>
        </div>
      </Modal>

      {/* Create snapshot modal */}
      <Modal
        open={snapshotTarget !== null}
        onClose={() => {
          setSnapshotTarget(null)
          setSnapshotName('')
        }}
        title="Take Snapshot"
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-300">
            Creating a read-only snapshot of{' '}
            <span className="font-mono text-emerald-400">{snapshotTarget}</span>.
          </p>
          <Input
            label="Snapshot Name (optional)"
            value={snapshotName}
            onChange={(e) => setSnapshotName(e.target.value)}
            placeholder="Auto-generated if empty"
            mono
          />
          <p className="text-[11px] text-navy-500">
            Leave empty for a timestamp-based name. Alphanumeric, hyphens, and underscores only.
          </p>
          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setSnapshotTarget(null)
                setSnapshotName('')
              }}
              disabled={creatingSnapshot}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleCreateSnapshot}
              loading={creatingSnapshot}
              disabled={snapshotName.trim() !== '' && !isValidBtrfsName(snapshotName.trim())}
            >
              Take Snapshot
            </Button>
          </div>
        </div>
      </Modal>

      {/* Confirm delete snapshot modal */}
      <Modal
        open={confirmDeleteSnapshot !== null}
        onClose={() => setConfirmDeleteSnapshot(null)}
        title="Delete Snapshot"
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-300">
            Are you sure you want to delete snapshot{' '}
            <span className="font-mono text-red-400">{confirmDeleteSnapshot}</span>?
            This action cannot be undone.
          </p>
          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setConfirmDeleteSnapshot(null)}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => {
                if (confirmDeleteSnapshot) {
                  handleDeleteSnapshot(confirmDeleteSnapshot)
                }
              }}
            >
              Delete
            </Button>
          </div>
        </div>
      </Modal>

      {/* Create array modal */}
      <Modal
        open={showCreateArray}
        onClose={() => setShowCreateArray(false)}
        title="Create RAID Array"
        size="md"
      >
        <div className="space-y-4">
          <Input
            label="Array Name"
            value={createName}
            onChange={(e) => setCreateName(e.target.value)}
            placeholder="data"
            mono
          />

          <Select
            label="RAID Level"
            value={createLevel}
            onChange={(e) => setCreateLevel(e.target.value as RaidLevel)}
            options={[
              { value: 'single', label: 'Single (No redundancy)' },
              { value: 'dup', label: 'DUP (Btrfs metadata duplication)' },
              { value: 'raid0', label: 'RAID 0 (Stripe - Performance)' },
              { value: 'raid1', label: 'RAID 1 (Mirror - Safety)' },
              { value: 'raid5', label: 'RAID 5 (Parity - Balanced)' },
              { value: 'raid6', label: 'RAID 6 (Double parity)' },
              { value: 'raid10', label: 'RAID 10 (Mirror + Stripe)' },
            ]}
          />

          <Select
            label="Filesystem"
            value={createFs}
            onChange={(e) => setCreateFs(e.target.value)}
            options={[
              { value: 'btrfs', label: 'Btrfs (Recommended)' },
              { value: 'ext4', label: 'ext4' },
              { value: 'xfs', label: 'XFS' },
            ]}
          />

          {/* Device selection */}
          <div>
            <p className="text-[11px] font-medium text-navy-400 mb-2">
              Select Devices ({selectedDevices.length} selected)
            </p>
            {availableDisks.length > 0 ? (
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {availableDisks.map((disk) => (
                  <label
                    key={disk.serial ?? disk.device}
                    className="flex items-center gap-3 py-2 px-3 rounded-lg bg-navy-800/30 hover:bg-navy-800/50 cursor-pointer transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={selectedDevices.includes(disk.device)}
                      onChange={() => toggleDevice(disk.device)}
                      className="rounded border-navy-700 bg-navy-800 text-emerald-500 focus:ring-emerald-500/50"
                    />
                    <HardDrive className="w-4 h-4 text-navy-500" />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-gray-200 font-mono">{disk.device}</span>
                        {disk.bay != null && (
                          <span className="text-[10px] text-navy-500">Bay {disk.bay}</span>
                        )}
                      </div>
                      <p className="text-[11px] text-navy-400">
                        {disk.model ?? 'Unknown'} &middot; {fmtBytes(disk.capacity_bytes ?? disk.size_bytes ?? 0)}
                      </p>
                    </div>
                  </label>
                ))}
              </div>
            ) : (
              <p className="text-xs text-navy-500 py-3 text-center">
                No available disks. All disks are in use by existing arrays.
              </p>
            )}
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowCreateArray(false)}
              disabled={creating}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleCreateArray}
              loading={creating}
              disabled={!createName.trim() || selectedDevices.length === 0}
            >
              Create Array
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
