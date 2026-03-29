// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardDrive } from 'lucide-react'
import type { BayInfo, Disk } from '../../types'

type BayRole = 'nas' | 'nvr'

interface Step3Props {
  bays: BayInfo[]
  disks: Disk[]
  assignments: Record<number, BayRole>
  onChange: (assignments: Record<number, BayRole>) => void
}

function fmtCapacity(bytes: number): string {
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(0)} MB`
  if (bytes < 1e12) return `${(bytes / 1e9).toFixed(0)} GB`
  return `${(bytes / 1e12).toFixed(2)} TB`
}

function normalizeBayState(state: string | undefined): 'healthy' | 'fault' | 'empty' | 'rebuilding' {
  switch (state) {
    case 'healthy':
    case 'Present':
    case 'Normal':
      return 'healthy'
    case 'fault':
      return 'fault'
    case 'rebuilding':
      return 'rebuilding'
    case 'empty':
    case 'Empty':
      return 'empty'
    default:
      return state ? 'healthy' : 'empty'
  }
}

export default function Step3_BayAssignment({ bays, disks, assignments, onChange }: Step3Props) {
  const baySlots = Array.from({ length: 4 }, (_, i) => {
    const slotNum = i + 1
    const bay = bays.find((b) => (b.bay ?? b.slot) === slotNum) ?? {
      bay: slotNum,
      state: 'empty' as const,
      disk_serial: null,
      disk_model: null,
    }
    const disk = disks.find((d) => d.bay === slotNum) ??
      (bay.disk_serial ? disks.find((d) => d.serial === bay.disk_serial) : undefined)
    return { bay, disk }
  })

  function setRole(slotNum: number, role: BayRole) {
    onChange({ ...assignments, [slotNum]: role })
  }

  return (
    <div className="animate-fade-in">
      <div className="text-center mb-8">
        <h2 className="text-xl font-semibold text-gray-100">Bay Assignment</h2>
        <p className="text-sm text-navy-400 mt-1">Assign drives to NAS or NVR</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto">
        {baySlots.map(({ bay, disk }) => {
          const slotNum = bay.bay ?? bay.slot ?? 0
          const state = normalizeBayState(bay.state)
          const isEmpty = state === 'empty'
          const currentRole = assignments[slotNum] ?? 'nas'

          return (
            <div
              key={slotNum}
              className={`
                bg-navy-900 border rounded-xl p-4 transition-colors duration-300
                ${isEmpty
                  ? 'border-navy-800/30 opacity-40'
                  : currentRole === 'nas'
                    ? 'border-sky-500/30'
                    : 'border-navy-800/50'
                }
              `}
            >
              <div className="flex items-center gap-2 mb-3">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${isEmpty ? 'bg-navy-800/50' : 'bg-navy-800'}`}>
                  <HardDrive className={`w-4 h-4 ${isEmpty ? 'text-navy-600' : 'text-navy-400'}`} />
                </div>
                <span className="text-xs font-mono text-navy-400">Bay {slotNum}</span>
              </div>

              {isEmpty ? (
                <p className="text-xs text-navy-600">Empty</p>
              ) : (
                <>
                  <div className="space-y-1.5 mb-3">
                    <p className="text-xs text-gray-300 font-mono truncate">
                      {disk?.model ?? bay.disk_model ?? 'Unknown'}
                    </p>
                    <p className="text-[11px] text-navy-500 font-mono">
                      {disk?.capacity_bytes ? fmtCapacity(disk.capacity_bytes) : 'N/A'}
                    </p>
                  </div>

                  {/* Role selector */}
                  <div className="flex gap-1">
                    <button
                      type="button"
                      onClick={() => setRole(slotNum, 'nas')}
                      className={`
                        flex-1 py-1.5 text-[10px] font-medium rounded-md border transition-all duration-200
                        ${currentRole === 'nas'
                          ? 'bg-sky-500/10 border-sky-500/20 text-sky-400'
                          : 'bg-navy-800/50 border-navy-700/30 text-navy-500 hover:text-gray-300'
                        }
                      `}
                    >
                      NAS
                    </button>
                    <button
                      type="button"
                      disabled
                      className="flex-1 py-1.5 text-[10px] font-medium rounded-md border bg-navy-800/30 border-navy-700/20 text-navy-600 cursor-not-allowed"
                      title="NVR coming soon"
                    >
                      NVR
                    </button>
                  </div>
                </>
              )}
            </div>
          )
        })}
      </div>

      <p className="text-center text-[11px] text-navy-500 mt-6">
        NVR bay assignment will be available in a future update.
      </p>
    </div>
  )
}
