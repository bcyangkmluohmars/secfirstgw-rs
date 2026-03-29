// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect, useCallback } from 'react'
import { Database, HardDrive, Plus, Trash2, Shield } from 'lucide-react'
import type { RaidArray, ArrayDetail, Disk } from '../types'
import StatusBadge from './StatusBadge'
import { Button, Modal, Badge, ConfirmDialog } from './ui'
import { api } from '../api'

interface RaidStatusProps {
  array: RaidArray
  availableDisks?: Disk[]
  onRefresh?: () => void
}

function fmtBytes(bytes: number): string {
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(0)} MB`
  if (bytes < 1e12) return `${(bytes / 1e9).toFixed(1)} GB`
  return `${(bytes / 1e12).toFixed(2)} TB`
}

function raidLabel(level: string | undefined | null): string {
  const l = String(level ?? 'unknown').toLowerCase()
  switch (l) {
    case 'raid0': return 'RAID 0 (Stripe)'
    case 'raid1': return 'RAID 1 (Mirror)'
    case 'raid5': return 'RAID 5'
    case 'raid6': return 'RAID 6'
    case 'raid10': return 'RAID 10'
    case 'single': return 'Single'
    case 'dup': return 'DUP'
    default: return l.toUpperCase()
  }
}

export default function RaidStatus({ array, availableDisks = [], onRefresh }: RaidStatusProps) {
  // Extract the array identifier from the device path (e.g. "/dev/md/0" -> "0")
  // Falls back to array.name if no device path available.
  const arrayId = array.device
    ? array.device.replace(/^\/dev\/md\//, '').replace(/^\/dev\//, '')
    : array.name

  const totalBytes = array.total_bytes ?? 0
  const usedBytes = array.used_bytes ?? 0
  const usedPercent = totalBytes > 0
    ? Math.min((usedBytes / totalBytes) * 100, 100)
    : 0

  const devices = array.devices ?? []

  // Detail state (fetched on mount)
  const [detail, setDetail] = useState<ArrayDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  // Add disk modal
  const [showAddDisk, setShowAddDisk] = useState(false)
  const [selectedDisk, setSelectedDisk] = useState('')
  const [addingDisk, setAddingDisk] = useState(false)

  // Remove disk confirm
  const [removeDisk, setRemoveDisk] = useState<string | null>(null)
  const [removingDisk, setRemovingDisk] = useState(false)

  // Scrub
  const [scrubbing, setScrubbing] = useState(false)

  const fetchDetail = useCallback(async () => {
    setDetailLoading(true)
    try {
      const d = await api.getArrayStatus(arrayId)
      setDetail(d)
    } catch {
      // Detail endpoint may fail on inactive arrays
    } finally {
      setDetailLoading(false)
    }
  }, [arrayId])

  useEffect(() => {
    fetchDetail()
  }, [fetchDetail])

  // Auto-poll every 5s when rebuilding/checking
  useEffect(() => {
    const isActive = detail?.status === 'Rebuilding' || detail?.status === 'Checking'
    if (!isActive) return
    const timer = setInterval(fetchDetail, 5000)
    return () => clearInterval(timer)
  }, [detail?.status, fetchDetail])

  const handleAddDisk = async () => {
    if (!selectedDisk) return
    setAddingDisk(true)
    try {
      await api.addDiskToArray(arrayId, selectedDisk)
      setShowAddDisk(false)
      setSelectedDisk('')
      await fetchDetail()
      onRefresh?.()
    } catch {
      // Error feedback handled by api layer
    } finally {
      setAddingDisk(false)
    }
  }

  const handleRemoveDisk = async () => {
    if (!removeDisk) return
    setRemovingDisk(true)
    try {
      await api.removeDiskFromArray(arrayId, removeDisk)
      setRemoveDisk(null)
      await fetchDetail()
      onRefresh?.()
    } catch {
      // Error feedback handled by api layer
    } finally {
      setRemovingDisk(false)
    }
  }

  const handleScrub = async () => {
    setScrubbing(true)
    try {
      await api.startArrayScrub(arrayId)
      await fetchDetail()
    } catch {
      // Error feedback handled by api layer
    } finally {
      setScrubbing(false)
    }
  }

  // Use detail data for enriched display when available
  const sizeBytes = detail?.size_bytes ?? totalBytes
  const uuid = detail?.uuid ?? array.uuid
  const raidDevices = detail?.raid_devices
  const rebuildProgress = detail?.rebuild_progress ?? (array.rebuild_percent != null ? array.rebuild_percent : null)
  const checkProgress = detail?.check_progress ?? null
  const speedKbps = detail?.speed_kbps ?? null
  const finishMinutes = detail?.finish_minutes ?? null
  const statusStr = String(detail?.status ?? array.state ?? 'unknown')

  // Build enriched device list from detail if available
  const activeDisks: Array<{ device: string; state: string }> = detail
    ? detail.active_disks.map((d) => ({ device: d, state: 'active' }))
    : devices.filter((d) => d.state === 'active').map((d) => ({ device: d.device, state: 'active' }))

  const spareDisks: Array<{ device: string; state: string }> = detail
    ? detail.spare_disks.map((d) => ({ device: d, state: 'spare' }))
    : devices.filter((d) => d.state === 'spare').map((d) => ({ device: d.device, state: 'spare' }))

  const allDisks = [...activeDisks, ...spareDisks]

  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in hover:border-navy-700/50 transition-colors duration-300">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Database className="w-5 h-5 text-sky-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-100">{arrayId}</h3>
            <p className="text-[11px] text-navy-400">
              {raidLabel(array.level ?? 'unknown')}
              {array.filesystem ? ` \u00b7 ${array.filesystem}` : ''}
              {raidDevices != null ? ` \u00b7 ${raidDevices} devices` : ''}
            </p>
          </div>
        </div>
        <StatusBadge status={statusStr.toLowerCase()} />
      </div>

      {/* Size & UUID info */}
      {(sizeBytes > 0 || uuid) && (
        <div className="mb-4 space-y-1">
          {sizeBytes > 0 && (
            <p className="text-[11px] text-navy-400">
              Size: <span className="text-gray-300 font-mono">{fmtBytes(sizeBytes)}</span>
            </p>
          )}
          {uuid && (
            <p className="text-[10px] text-navy-500 font-mono truncate" title={uuid}>
              UUID: {uuid}
            </p>
          )}
        </div>
      )}

      {/* Storage bar */}
      {totalBytes > 0 && (
        <div className="mb-4">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] text-navy-400 uppercase tracking-wider">Storage</span>
            <span className="text-[11px] text-gray-400 font-mono tabular-nums">
              {fmtBytes(usedBytes)} / {fmtBytes(totalBytes)}
            </span>
          </div>
          <div className="w-full h-2 bg-navy-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${usedPercent}%`,
                background: usedPercent >= 90 ? '#f87171' : usedPercent >= 75 ? '#fbbf24' : '#34d399',
              }}
            />
          </div>
          <p className="text-[10px] text-navy-500 mt-1 font-mono tabular-nums">
            {usedPercent.toFixed(1)}% used &middot; {fmtBytes(totalBytes - usedBytes)} free
          </p>
        </div>
      )}

      {/* Rebuild progress */}
      {rebuildProgress != null && (
        <div className="mb-4 p-3 bg-amber-500/5 border border-amber-500/15 rounded-lg">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] text-amber-400 uppercase tracking-wider font-medium">Rebuilding</span>
            <span className="text-[11px] text-amber-400 font-mono tabular-nums">{rebuildProgress.toFixed(1)}%</span>
          </div>
          <div className="w-full h-1.5 bg-navy-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-amber-400 rounded-full transition-all duration-500"
              style={{ width: `${rebuildProgress}%` }}
            />
          </div>
          {(speedKbps != null || finishMinutes != null) && (
            <div className="flex items-center gap-3 mt-1.5 text-[10px] text-amber-400/70 font-mono tabular-nums">
              {speedKbps != null && <span>{(speedKbps / 1024).toFixed(0)} MB/s</span>}
              {finishMinutes != null && <span>ETA: {finishMinutes < 60 ? `${finishMinutes.toFixed(0)}m` : `${Math.floor(finishMinutes / 60)}h ${Math.round(finishMinutes % 60)}m`}</span>}
            </div>
          )}
        </div>
      )}

      {/* Check / scrub progress */}
      {checkProgress != null && (
        <div className="mb-4 p-3 bg-sky-500/5 border border-sky-500/15 rounded-lg">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] text-sky-400 uppercase tracking-wider font-medium">Checking</span>
            <span className="text-[11px] text-sky-400 font-mono tabular-nums">{checkProgress.toFixed(1)}%</span>
          </div>
          <div className="w-full h-1.5 bg-navy-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-sky-400 rounded-full transition-all duration-500"
              style={{ width: `${checkProgress}%` }}
            />
          </div>
          {(speedKbps != null || finishMinutes != null) && (
            <div className="flex items-center gap-3 mt-1.5 text-[10px] text-sky-400/70 font-mono tabular-nums">
              {speedKbps != null && <span>{(speedKbps / 1024).toFixed(0)} MB/s</span>}
              {finishMinutes != null && <span>ETA: {finishMinutes < 60 ? `${finishMinutes.toFixed(0)}m` : `${Math.floor(finishMinutes / 60)}h ${Math.round(finishMinutes % 60)}m`}</span>}
            </div>
          )}
        </div>
      )}

      {/* Member disks */}
      {allDisks.length > 0 && (
        <div className="mb-4">
          <p className="text-[10px] text-navy-400 uppercase tracking-wider mb-2">
            Member Disks ({allDisks.length})
          </p>
          <div className="space-y-1.5">
            {allDisks.map((dev) => (
              <div key={dev.device} className="flex items-center justify-between py-1.5 px-2 rounded-lg bg-navy-800/30">
                <div className="flex items-center gap-2">
                  <HardDrive className="w-3.5 h-3.5 text-navy-500" />
                  <span className="text-xs text-gray-300 font-mono">{dev.device}</span>
                  <Badge variant={dev.state === 'active' ? 'success' : 'warning'}>
                    {dev.state}
                  </Badge>
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => setRemoveDisk(dev.device)}
                  title={`Remove ${dev.device}`}
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No devices yet but loading detail */}
      {allDisks.length === 0 && devices.length > 0 && (
        <div>
          <p className="text-[10px] text-navy-400 uppercase tracking-wider mb-2">Devices</p>
          <div className="space-y-1.5">
            {devices.map((dev) => (
              <div key={dev.device} className="flex items-center justify-between py-1.5 px-2 rounded-lg bg-navy-800/30">
                <div className="flex items-center gap-2">
                  <HardDrive className="w-3.5 h-3.5 text-navy-500" />
                  <span className="text-xs text-gray-300 font-mono">{dev.device}</span>
                  {dev.bay != null && (
                    <span className="text-[10px] text-navy-500">Bay {dev.bay}</span>
                  )}
                </div>
                <StatusBadge status={dev.state ?? 'unknown'} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-2 mt-4 pt-3 border-t border-navy-800/50">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setShowAddDisk(true)}
          disabled={detailLoading}
        >
          <Plus className="w-3 h-3 mr-1 inline" />
          Add Disk
        </Button>
        <Button
          variant="secondary"
          size="sm"
          onClick={handleScrub}
          loading={scrubbing}
          disabled={checkProgress != null || detailLoading}
        >
          <Shield className="w-3 h-3 mr-1 inline" />
          {checkProgress != null ? 'Scrubbing...' : 'Start Scrub'}
        </Button>
      </div>

      {/* Mount point */}
      {array.mount_point && (
        <div className="mt-3 pt-3 border-t border-navy-800/50">
          <p className="text-[10px] text-navy-500">
            Mount: <span className="text-navy-400 font-mono">{array.mount_point}</span>
          </p>
        </div>
      )}

      {/* Add Disk Modal */}
      <Modal
        open={showAddDisk}
        onClose={() => { setShowAddDisk(false); setSelectedDisk('') }}
        title={`Add Disk to ${arrayId}`}
        size="sm"
      >
        <div className="space-y-4">
          {availableDisks.length > 0 ? (
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {availableDisks.map((disk) => (
                <label
                  key={disk.serial ?? disk.device}
                  className={`flex items-center gap-3 py-2 px-3 rounded-lg cursor-pointer transition-colors ${
                    selectedDisk === disk.device
                      ? 'bg-emerald-500/10 border border-emerald-500/20'
                      : 'bg-navy-800/30 hover:bg-navy-800/50 border border-transparent'
                  }`}
                >
                  <input
                    type="radio"
                    name="add-disk"
                    checked={selectedDisk === disk.device}
                    onChange={() => setSelectedDisk(disk.device)}
                    className="rounded-full border-navy-700 bg-navy-800 text-emerald-500 focus:ring-emerald-500/50"
                  />
                  <HardDrive className="w-4 h-4 text-navy-500" />
                  <div className="flex-1">
                    <span className="text-sm text-gray-200 font-mono">{disk.device}</span>
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
          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => { setShowAddDisk(false); setSelectedDisk('') }}
              disabled={addingDisk}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleAddDisk}
              loading={addingDisk}
              disabled={!selectedDisk}
            >
              Add Disk
            </Button>
          </div>
        </div>
      </Modal>

      {/* Remove Disk Confirm */}
      <ConfirmDialog
        open={removeDisk !== null}
        onClose={() => setRemoveDisk(null)}
        onConfirm={handleRemoveDisk}
        title="Remove Disk"
        message={`Are you sure you want to remove ${removeDisk ?? ''} from ${arrayId}? This will mark the disk as failed and remove it from the array.`}
        confirmLabel="Remove Disk"
        variant="danger"
        loading={removingDisk}
      />
    </div>
  )
}
