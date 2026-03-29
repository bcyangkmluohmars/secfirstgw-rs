// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react'
import { HardDrive, Thermometer, AlertTriangle, Check, Loader } from 'lucide-react'
import { api } from '../../api'
import type { BayInfo, Disk } from '../../types'

interface Step0Props {
  onDiscovered: (bays: BayInfo[], disks: Disk[]) => void
}

function fmtCapacity(bytes: number): string {
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(0)} MB`
  if (bytes < 1e12) return `${(bytes / 1e9).toFixed(0)} GB`
  return `${(bytes / 1e12).toFixed(2)} TB`
}

export default function Step0_Discovery({ onDiscovered }: Step0Props) {
  const [bays, setBays] = useState<BayInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function discover() {
      try {
        const [fetchedBays, fetchedDisks] = await Promise.all([
          api.getBays(),
          api.getDisks(),
        ])
        if (cancelled) return
        setBays(fetchedBays)
        onDiscovered(fetchedBays, fetchedDisks)
      } catch {
        if (!cancelled) {
          setError('Failed to detect hardware. The device may still be initializing.')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    discover()
    return () => { cancelled = true }
  }, [onDiscovered])

  // Build 4-bay grid from enriched bay data
  const baySlots = Array.from({ length: 4 }, (_, i) => {
    const slotNum = i + 1
    const bay = bays.find((b) => (b.bay ?? b.slot) === slotNum)
    return { slotNum, bay }
  })

  return (
    <div className="animate-fade-in">
      <div className="text-center mb-8">
        <h2 className="text-xl font-semibold text-gray-100">Hardware Discovery</h2>
        <p className="text-sm text-navy-400 mt-1">
          {loading ? 'Detecting your drives...' : 'Drive detection complete'}
        </p>
      </div>

      {error && (
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3 mb-6 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <p className="text-xs text-amber-300">{error}</p>
        </div>
      )}

      {loading ? (
        <div className="flex flex-col items-center justify-center py-16">
          <Loader className="w-8 h-8 text-sky-400 animate-spin mb-4" />
          <p className="text-sm text-navy-400">Scanning drive bays...</p>
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {baySlots.map(({ slotNum, bay }) => {
            const state = bay?.state
            const isEmpty = !state || state === 'Empty' || state === 'empty'
            const model = bay?.disk_model
            const sizeBytes = bay?.size_bytes
            const smartStatus = bay?.smart_status
            const tempC = bay?.temperature_celsius
            const rotational = bay?.rotational

            const healthColor = smartStatus === 'healthy' ? 'emerald' :
              smartStatus === 'failing' ? 'red' :
              smartStatus === 'warning' ? 'amber' : 'navy'

            return (
              <div
                key={slotNum}
                className={`
                  bg-navy-900 border rounded-xl p-4 transition-colors duration-300
                  ${isEmpty
                    ? 'border-navy-800/50 opacity-50'
                    : healthColor === 'emerald' ? 'border-emerald-500/30'
                    : healthColor === 'red' ? 'border-red-500/30'
                    : healthColor === 'amber' ? 'border-amber-500/30'
                    : 'border-navy-700/50'
                  }
                `}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${isEmpty ? 'bg-navy-800/50' : 'bg-navy-800'}`}>
                      <HardDrive className={`w-4 h-4 ${isEmpty ? 'text-navy-600' : 'text-navy-400'}`} />
                    </div>
                    <span className="text-xs font-mono text-navy-400">Bay {slotNum}</span>
                  </div>
                  {!isEmpty && smartStatus && (
                    <span className={`w-2 h-2 rounded-full ${
                      smartStatus === 'healthy' ? 'bg-emerald-400' :
                      smartStatus === 'failing' ? 'bg-red-400' :
                      smartStatus === 'warning' ? 'bg-amber-400' : 'bg-navy-500'
                    }`} />
                  )}
                </div>

                {isEmpty ? (
                  <p className="text-xs text-navy-600 mt-2">Empty</p>
                ) : (
                  <div className="space-y-2">
                    <div>
                      <p className="text-[10px] text-navy-500 uppercase tracking-wider">Model</p>
                      <p className="text-xs text-gray-300 font-mono truncate">
                        {model ?? 'Unknown'}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] text-navy-500 uppercase tracking-wider">
                        {rotational === false ? 'SSD' : 'HDD'} Size
                      </p>
                      <p className="text-xs text-gray-300 font-mono">
                        {sizeBytes ? fmtCapacity(sizeBytes) : 'N/A'}
                      </p>
                    </div>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-[10px] text-navy-500 uppercase tracking-wider">SMART</p>
                        <div className="flex items-center gap-1">
                          {smartStatus === 'healthy' ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : smartStatus === 'failing' ? (
                            <AlertTriangle className="w-3 h-3 text-red-400" />
                          ) : null}
                          <span className={`text-xs ${
                            smartStatus === 'healthy' ? 'text-emerald-400'
                            : smartStatus === 'failing' ? 'text-red-400'
                            : 'text-navy-400'
                          }`}>
                            {smartStatus === 'healthy' ? 'Passed' : smartStatus ?? 'N/A'}
                          </span>
                        </div>
                      </div>
                      {tempC != null && tempC > 0 && (
                        <div className="flex items-center gap-1">
                          <Thermometer className={`w-3 h-3 ${
                            tempC >= 55 ? 'text-red-400'
                            : tempC >= 45 ? 'text-amber-400'
                            : 'text-emerald-400'
                          }`} />
                          <span className="text-xs text-navy-400 font-mono tabular-nums">
                            {tempC}&deg;C
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
