// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect } from 'react'
import {
  AlertTriangle,
  Check,
  HardDrive,
  Lock,
  Unlock,
  Server,
  Database,
  User,
  Loader,
} from 'lucide-react'
import type { BayInfo, Disk } from '../../types'

type DeviceMode = 'nas' | 'nvr' | 'nas-nvr'
type RaidLevel = 'raid0' | 'raid1' | 'raid5' | 'raid10'

interface WizardState {
  adminCreated: boolean
  deviceMode: DeviceMode
  bayAssignments: Record<number, 'nas' | 'nvr'>
  selectedDisks: string[]
  raidLevel: RaidLevel | null
  encryption: boolean
  discoveredBays: BayInfo[]
  discoveredDisks: Disk[]
}

interface Step6Props {
  state: WizardState
  username: string
  onInitialize: () => Promise<void>
  onBack: () => void
}

function fmtBytes(bytes: number): string {
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(0)} MB`
  if (bytes < 1e12) return `${(bytes / 1e9).toFixed(0)} GB`
  return `${(bytes / 1e12).toFixed(2)} TB`
}

function raidLabel(level: RaidLevel | null): string {
  switch (level) {
    case 'raid0': return 'RAID 0 (Striping)'
    case 'raid1': return 'RAID 1 (Mirror)'
    case 'raid5': return 'RAID 5 (Distributed Parity)'
    case 'raid10': return 'RAID 10 (Striped Mirror)'
    default: return 'Single Disk (No RAID)'
  }
}

function deviceModeLabel(mode: DeviceMode): string {
  switch (mode) {
    case 'nas': return 'NAS Only'
    case 'nvr': return 'NVR Only'
    case 'nas-nvr': return 'NAS + NVR'
  }
}

function computeUsableCapacityFromSizes(sizes: number[], raidLevel: RaidLevel | null): number {
  if (sizes.length === 0) return 0
  const smallest = Math.min(...sizes)
  const count = sizes.length

  switch (raidLevel) {
    case 'raid0': return count * smallest
    case 'raid1': return smallest
    case 'raid5': return (count - 1) * smallest
    case 'raid10': return (count / 2) * smallest
    default: return sizes.reduce((a, b) => a + b, 0)
  }
}

function normalizeBayState(state: string | undefined): string {
  switch (state) {
    case 'healthy':
    case 'Present':
    case 'Normal':
      return 'healthy'
    case 'empty':
    case 'Empty':
      return 'empty'
    default:
      return state ?? 'empty'
  }
}

export default function Step6_Summary({ state, username, onInitialize, onBack }: Step6Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [existingRaid, setExistingRaid] = useState(false)

  // Check for existing RAID on mount
  useEffect(() => {
    import('../../api').then(({ api }) =>
      api.getArrays().then((arrays) => {
        if (arrays.length > 0) setExistingRaid(true)
      }).catch(() => {})
    )
  }, [])

  // Use selectedDisks from RAID config step, matched against enriched bays for size info
  const selectedBays = state.discoveredBays.filter(
    (b) => b.device && state.selectedDisks.includes(b.device)
  )
  const selectedSizes = selectedBays.map((b) => b.size_bytes ?? 0).filter((s) => s > 0)
  const usableCapacity = computeUsableCapacityFromSizes(selectedSizes, state.raidLevel)

  const populatedBays = state.discoveredBays.filter(
    (b) => normalizeBayState(b.state) !== 'empty'
  )

  async function handleInitialize() {
    setError(null)
    setLoading(true)
    try {
      await onInitialize()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Initialization failed')
      setLoading(false)
    }
  }

  return (
    <div className="animate-fade-in max-w-lg mx-auto">
      <div className="text-center mb-8">
        <h2 className="text-xl font-semibold text-gray-100">Summary</h2>
        <p className="text-sm text-navy-400 mt-1">Review your configuration</p>
      </div>

      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 mb-6 animate-fade-in">
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}

      {/* Configuration Summary */}
      <div className="bg-navy-900 border border-navy-800/50 rounded-xl divide-y divide-navy-800/50 mb-6">
        {/* Admin User */}
        <div className="flex items-center gap-4 p-4">
          <div className="w-9 h-9 rounded-lg bg-navy-800 flex items-center justify-center shrink-0">
            <User className="w-4 h-4 text-navy-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Admin User</p>
            <p className="text-sm text-gray-200 font-mono truncate">{username || 'Not set'}</p>
          </div>
          {state.adminCreated && <Check className="w-4 h-4 text-emerald-400 shrink-0" />}
        </div>

        {/* Device Mode */}
        <div className="flex items-center gap-4 p-4">
          <div className="w-9 h-9 rounded-lg bg-navy-800 flex items-center justify-center shrink-0">
            <Server className="w-4 h-4 text-navy-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Device Mode</p>
            <p className="text-sm text-gray-200">{deviceModeLabel(state.deviceMode)}</p>
          </div>
        </div>

        {/* Bay Assignment */}
        <div className="flex items-start gap-4 p-4">
          <div className="w-9 h-9 rounded-lg bg-navy-800 flex items-center justify-center shrink-0 mt-0.5">
            <HardDrive className="w-4 h-4 text-navy-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1">Bay Assignment</p>
            {populatedBays.length === 0 ? (
              <p className="text-sm text-navy-500">No drives detected</p>
            ) : (
              <div className="space-y-1">
                {Array.from({ length: 4 }, (_, i) => {
                  const slotNum = i + 1
                  const bay = state.discoveredBays.find((b) => (b.bay ?? b.slot) === slotNum)
                  const isEmpty = !bay || normalizeBayState(bay.state) === 'empty'
                  if (isEmpty) return null
                  const inRaid = bay?.device ? state.selectedDisks.includes(bay.device) : false
                  return (
                    <div key={slotNum} className="flex items-center gap-2 text-xs">
                      <span className="text-navy-500 font-mono w-10">Bay {slotNum}</span>
                      <span className="text-gray-300 font-mono truncate flex-1">
                        {bay?.disk_model ?? 'Unknown'}
                      </span>
                      {inRaid ? (
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400">
                          RAID
                        </span>
                      ) : (
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-navy-800 text-navy-500">
                          SKIP
                        </span>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* RAID Level */}
        <div className="flex items-center gap-4 p-4">
          <div className="w-9 h-9 rounded-lg bg-navy-800 flex items-center justify-center shrink-0">
            <Database className="w-4 h-4 text-navy-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">RAID Level</p>
            <p className="text-sm text-gray-200">{raidLabel(state.raidLevel)}</p>
            {usableCapacity > 0 && (
              <p className="text-[11px] text-navy-500 font-mono mt-0.5">
                Usable: {fmtBytes(usableCapacity)}
              </p>
            )}
          </div>
        </div>

        {/* Encryption */}
        <div className="flex items-center gap-4 p-4">
          <div className={`
            w-9 h-9 rounded-lg flex items-center justify-center shrink-0
            ${state.encryption ? 'bg-emerald-500/10' : 'bg-red-500/10'}
          `}>
            {state.encryption ? (
              <Lock className="w-4 h-4 text-emerald-400" />
            ) : (
              <Unlock className="w-4 h-4 text-red-400" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] text-navy-500 uppercase tracking-wider">Encryption</p>
            <p className={`text-sm font-medium ${state.encryption ? 'text-emerald-400' : 'text-red-400'}`}>
              {state.encryption ? 'Enabled (AES-256-XTS)' : 'Disabled'}
            </p>
          </div>
        </div>
      </div>

      {/* Existing RAID notice */}
      {existingRaid && (
        <div className="bg-sky-500/5 border border-sky-500/20 rounded-xl p-4 mb-6 flex items-start gap-3">
          <Database className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-sky-300 font-medium mb-1">RAID Already Configured</p>
            <p className="text-xs text-sky-300/70 leading-relaxed">
              A RAID array already exists on this device. Storage initialization will be skipped.
              Click &quot;Continue to Dashboard&quot; to proceed.
            </p>
          </div>
        </div>
      )}

      {/* Destructive Warning */}
      {!existingRaid && populatedBays.length > 0 && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 mb-6 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-red-300 font-medium mb-1">Data Destruction Warning</p>
            <p className="text-xs text-red-300/70 leading-relaxed">
              This will ERASE ALL DATA on the selected drives. This action cannot be undone.
              Make sure you have backed up any important data before proceeding.
            </p>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex gap-3">
        <button
          type="button"
          onClick={onBack}
          disabled={loading}
          className="flex-1 py-2.5 rounded-lg text-sm font-medium border bg-navy-800 hover:bg-navy-700/50 border-navy-700/50 text-gray-300 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Go Back
        </button>
        <button
          type="button"
          onClick={handleInitialize}
          disabled={loading}
          className={`flex-1 py-2.5 rounded-lg text-sm font-medium border transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed ${
            existingRaid
              ? 'bg-sky-500/10 hover:bg-sky-500/20 border-sky-500/20 text-sky-400'
              : 'bg-red-500/10 hover:bg-red-500/20 border-red-500/20 text-red-400'
          }`}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <Loader className="w-3.5 h-3.5 animate-spin" />
              {existingRaid ? 'Loading...' : 'Initializing...'}
            </span>
          ) : existingRaid ? (
            'Continue to Dashboard'
          ) : (
            'Initialize Storage'
          )}
        </button>
      </div>
    </div>
  )
}
