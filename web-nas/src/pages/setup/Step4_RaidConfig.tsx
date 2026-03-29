// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardDrive, Database, AlertTriangle, Shield, Zap } from 'lucide-react'
import type { BayInfo, Disk } from '../../types'

type RaidLevel = 'raid0' | 'raid1' | 'raid5' | 'raid10'

interface Step4Props {
  bays: BayInfo[]
  disks: Disk[]
  bayAssignments: Record<number, 'nas' | 'nvr'>
  selectedDisks: string[]
  onSelectDisks: (disks: string[]) => void
  value: RaidLevel | null
  onChange: (level: RaidLevel) => void
}

interface RaidOption {
  level: RaidLevel
  label: string
  description: string
  minDisks: number
  exactDisks?: number
  icon: typeof Database
  capacityFn: (diskCount: number, smallestDiskBytes: number) => number
  capacityLabel: (diskCount: number) => string
  redundancy: string
  redundancyColor: string
  warning?: string
}

const raidOptions: RaidOption[] = [
  {
    level: 'raid0',
    label: 'RAID 0',
    description: 'Striping',
    minDisks: 2,
    icon: Zap,
    capacityFn: (n, s) => n * s,
    capacityLabel: (n) => `${n} x smallest disk`,
    redundancy: 'No redundancy',
    redundancyColor: 'text-red-400',
    warning: 'Any disk failure destroys ALL data',
  },
  {
    level: 'raid1',
    label: 'RAID 1',
    description: 'Mirror',
    minDisks: 2,
    icon: Shield,
    capacityFn: (_n, s) => s,
    capacityLabel: () => '1 x smallest disk',
    redundancy: 'Full redundancy',
    redundancyColor: 'text-emerald-400',
  },
  {
    level: 'raid5',
    label: 'RAID 5',
    description: 'Distributed Parity',
    minDisks: 3,
    icon: Database,
    capacityFn: (n, s) => (n - 1) * s,
    capacityLabel: (n) => `${n - 1} x smallest disk`,
    redundancy: 'One disk fault tolerance',
    redundancyColor: 'text-sky-400',
  },
  {
    level: 'raid10',
    label: 'RAID 10',
    description: 'Striped Mirror',
    exactDisks: 4,
    minDisks: 4,
    icon: Zap,
    capacityFn: (n, s) => (n / 2) * s,
    capacityLabel: (n) => `${n / 2} x smallest disk`,
    redundancy: 'High performance + redundancy',
    redundancyColor: 'text-emerald-400',
  },
]

function fmtBytes(bytes: number): string {
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(0)} MB`
  if (bytes < 1e12) return `${(bytes / 1e9).toFixed(0)} GB`
  return `${(bytes / 1e12).toFixed(2)} TB`
}

export default function Step4_RaidConfig({
  bays,
  disks: _disks,
  bayAssignments: _bayAssignments,
  selectedDisks,
  onSelectDisks,
  value,
  onChange,
}: Step4Props) {
  // Build selectable disks from enriched bays (only populated bays)
  const populatedBays = bays.filter(
    (b) => b.state === 'Present' || b.state === 'healthy'
  )

  function toggleDisk(device: string) {
    if (selectedDisks.includes(device)) {
      onSelectDisks(selectedDisks.filter((d) => d !== device))
    } else {
      onSelectDisks([...selectedDisks, device])
    }
  }

  function selectAll() {
    const allDevices = populatedBays
      .map((b) => b.device)
      .filter((d): d is string => !!d)
    onSelectDisks(allDevices)
  }

  function selectNone() {
    onSelectDisks([])
  }

  const diskCount = selectedDisks.length
  const selectedBayData = populatedBays.filter(
    (b) => b.device && selectedDisks.includes(b.device)
  )
  const smallestBytes =
    selectedBayData.length > 0
      ? Math.min(
          ...selectedBayData.map((b) => b.size_bytes ?? 0).filter((s) => s > 0)
        )
      : 0

  return (
    <div className="animate-fade-in">
      <div className="text-center mb-6">
        <h2 className="text-xl font-semibold text-gray-100">
          RAID Configuration
        </h2>
        <p className="text-sm text-navy-400 mt-1">
          Select drives and choose a redundancy level
        </p>
      </div>

      {/* Disk Selection */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-300">Select Drives</h3>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={selectAll}
              className="text-[10px] text-sky-400 hover:text-sky-300 transition-colors"
            >
              Select All
            </button>
            <span className="text-navy-600">|</span>
            <button
              type="button"
              onClick={selectNone}
              className="text-[10px] text-navy-400 hover:text-gray-300 transition-colors"
            >
              Deselect All
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {populatedBays.map((bay) => {
            const slot = bay.bay ?? bay.slot ?? 0
            const device = bay.device
            const isSelected = device ? selectedDisks.includes(device) : false

            return (
              <button
                key={slot}
                type="button"
                onClick={() => device && toggleDisk(device)}
                className={`
                  text-left p-3 rounded-lg border transition-all duration-200
                  ${
                    isSelected
                      ? 'bg-sky-500/5 border-sky-500/30 ring-1 ring-sky-500/20'
                      : 'bg-navy-900 border-navy-800/50 hover:border-navy-700/50'
                  }
                `}
              >
                <div className="flex items-center gap-2 mb-2">
                  <div
                    className={`w-4 h-4 rounded border flex items-center justify-center ${
                      isSelected
                        ? 'bg-sky-500 border-sky-500'
                        : 'border-navy-600'
                    }`}
                  >
                    {isSelected && (
                      <svg
                        className="w-3 h-3 text-white"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="3"
                      >
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    )}
                  </div>
                  <HardDrive
                    className={`w-3.5 h-3.5 ${isSelected ? 'text-sky-400' : 'text-navy-500'}`}
                  />
                  <span className="text-xs font-mono text-navy-400">
                    Bay {slot}
                  </span>
                </div>
                <p className="text-[11px] text-gray-300 font-mono truncate">
                  {bay.disk_model ?? 'Unknown'}
                </p>
                <p className="text-[10px] text-navy-500">
                  {bay.size_bytes ? fmtBytes(bay.size_bytes) : 'N/A'}
                  {bay.rotational === false ? ' SSD' : ' HDD'}
                </p>
              </button>
            )
          })}
        </div>

        {diskCount > 0 && (
          <p className="text-xs text-navy-400 mt-2 text-center">
            {diskCount} drive{diskCount !== 1 ? 's' : ''} selected
          </p>
        )}
      </div>

      {/* RAID Level Selection */}
      {diskCount === 0 ? (
        <div className="text-center py-8">
          <Database className="w-8 h-8 text-navy-600 mx-auto mb-3" />
          <p className="text-sm text-navy-400">
            Select at least one drive above to configure RAID.
          </p>
        </div>
      ) : diskCount === 1 ? (
        <div className="max-w-md mx-auto text-center py-6">
          <Database className="w-8 h-8 text-navy-500 mx-auto mb-3" />
          <p className="text-sm text-gray-300 mb-2">Single disk selected</p>
          <p className="text-xs text-navy-400">
            RAID requires at least 2 disks. The selected disk will be used as a
            standalone volume without RAID protection.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-2xl mx-auto">
          {raidOptions.map((opt) => {
            const available =
              diskCount >= opt.minDisks &&
              (opt.exactDisks == null || diskCount === opt.exactDisks)
            const selected = value === opt.level
            const Icon = opt.icon
            const usableCapacity = available
              ? opt.capacityFn(diskCount, smallestBytes)
              : 0

            return (
              <button
                key={opt.level}
                type="button"
                disabled={!available}
                onClick={() => available && onChange(opt.level)}
                className={`
                  relative text-left p-5 rounded-xl border transition-all duration-200
                  ${
                    selected
                      ? 'bg-sky-500/5 border-sky-500/30 ring-1 ring-sky-500/20'
                      : available
                        ? 'bg-navy-900 border-navy-800/50 hover:border-navy-700/50 cursor-pointer'
                        : 'bg-navy-900/50 border-navy-800/30 opacity-40 cursor-not-allowed'
                  }
                `}
              >
                <div className="flex items-start justify-between mb-3">
                  <div
                    className={`w-9 h-9 rounded-lg flex items-center justify-center ${selected ? 'bg-sky-500/10' : 'bg-navy-800'}`}
                  >
                    <Icon
                      className={`w-4 h-4 ${selected ? 'text-sky-400' : 'text-navy-400'}`}
                    />
                  </div>
                  {!available && (
                    <span className="text-[9px] font-medium text-navy-500 bg-navy-800/50 px-2 py-0.5 rounded-full">
                      {opt.minDisks}+ disks needed
                    </span>
                  )}
                </div>

                <h3
                  className={`text-sm font-medium ${selected ? 'text-sky-300' : 'text-gray-200'}`}
                >
                  {opt.label}
                </h3>
                <p className="text-xs text-navy-400 mb-3">{opt.description}</p>

                {available && (
                  <div className="space-y-2">
                    <div>
                      <p className="text-[10px] text-navy-500 uppercase tracking-wider">
                        Usable Capacity
                      </p>
                      <p className="text-xs text-gray-300 font-mono">
                        {fmtBytes(usableCapacity)}
                        <span className="text-navy-500 ml-1">
                          ({opt.capacityLabel(diskCount)})
                        </span>
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] text-navy-500 uppercase tracking-wider">
                        Redundancy
                      </p>
                      <p className={`text-xs font-medium ${opt.redundancyColor}`}>
                        {opt.redundancy}
                      </p>
                    </div>
                  </div>
                )}

                {opt.warning && available && (
                  <div className="flex items-center gap-1.5 mt-3 pt-3 border-t border-navy-800/50">
                    <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />
                    <p className="text-[10px] text-red-400">{opt.warning}</p>
                  </div>
                )}

                {selected && (
                  <div className="absolute top-0 left-0 right-0 h-px rounded-t-xl bg-gradient-to-r from-transparent via-sky-500/40 to-transparent" />
                )}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
