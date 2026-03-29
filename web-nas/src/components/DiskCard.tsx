// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardDrive, Thermometer, Clock } from 'lucide-react'
import type { Disk } from '../types'
import StatusBadge from './StatusBadge'

interface DiskCardProps {
  disk: Disk
}

function fmtCapacity(bytes: number): string {
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(0)} MB`
  if (bytes < 1e12) return `${(bytes / 1e9).toFixed(0)} GB`
  return `${(bytes / 1e12).toFixed(2)} TB`
}

function fmtHours(hours: number): string {
  const years = Math.floor(hours / 8760)
  const days = Math.floor((hours % 8760) / 24)
  if (years > 0) return `${years}y ${days}d`
  return `${days}d ${hours % 24}h`
}

export default function DiskCard({ disk }: DiskCardProps) {
  const tempC = disk.temperature_celsius ?? 0
  const tempColor = tempC >= 55 ? 'text-red-400'
    : tempC >= 45 ? 'text-amber-400'
    : 'text-emerald-400'

  const capacityBytes = disk.capacity_bytes ?? disk.size_bytes ?? 0
  const powerOnHours = disk.power_on_hours ?? 0

  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-4 animate-fade-in hover:border-navy-700/50 transition-colors duration-300">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-navy-800 flex items-center justify-center">
            <HardDrive className="w-4 h-4 text-navy-400" />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-200">{disk.device}</p>
            <p className="text-[11px] text-navy-500 font-mono">{disk.model ?? 'Unknown'}</p>
          </div>
        </div>
        <StatusBadge status={disk.health ?? 'unknown'} />
      </div>

      <div className="grid grid-cols-2 gap-3 mt-3">
        <div>
          <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-0.5">Serial</p>
          <p className="text-xs text-gray-300 font-mono">{disk.serial ?? 'N/A'}</p>
        </div>
        <div>
          <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-0.5">Capacity</p>
          <p className="text-xs text-gray-300 font-mono">{fmtCapacity(capacityBytes)}</p>
        </div>
        <div>
          <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-0.5">SMART</p>
          <p className="text-xs text-gray-300">{disk.smart_status ?? 'N/A'}</p>
        </div>
        <div>
          <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-0.5">Bay</p>
          <p className="text-xs text-gray-300">{disk.bay != null ? `Bay ${disk.bay}` : 'N/A'}</p>
        </div>
      </div>

      <div className="flex items-center gap-4 mt-3 pt-3 border-t border-navy-800/50">
        <div className="flex items-center gap-1.5">
          <Thermometer className={`w-3.5 h-3.5 ${tempColor}`} />
          <span className={`text-xs font-mono tabular-nums ${tempColor}`}>{tempC}&deg;C</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-navy-500" />
          <span className="text-xs text-navy-400 font-mono tabular-nums">{fmtHours(powerOnHours)}</span>
        </div>
        {disk.rotation_rate_rpm != null && disk.rotation_rate_rpm > 0 && (
          <span className="text-[10px] text-navy-500 font-mono">{disk.rotation_rate_rpm} RPM</span>
        )}
        {(disk.rotation_rate_rpm === 0 || (disk.rotation_rate_rpm == null && disk.rotational === false)) && (
          <span className="text-[10px] text-navy-500 font-mono">SSD</span>
        )}
        {disk.rotation_rate_rpm == null && disk.rotational === true && (
          <span className="text-[10px] text-navy-500 font-mono">HDD</span>
        )}
      </div>
    </div>
  )
}
