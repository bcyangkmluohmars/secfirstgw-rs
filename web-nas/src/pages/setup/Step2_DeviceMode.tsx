// SPDX-License-Identifier: AGPL-3.0-or-later

import { Server, Video, Layers } from 'lucide-react'

type DeviceMode = 'nas' | 'nvr' | 'nas-nvr'

interface Step2Props {
  value: DeviceMode
  onChange: (mode: DeviceMode) => void
}

interface ModeOption {
  id: DeviceMode
  label: string
  description: string
  icon: typeof Server
  disabled: boolean
  comingSoon: boolean
}

const options: ModeOption[] = [
  {
    id: 'nas',
    label: 'NAS Only',
    description: 'SMB shares, rsync, backups',
    icon: Server,
    disabled: false,
    comingSoon: false,
  },
  {
    id: 'nvr',
    label: 'NVR Only',
    description: 'Camera recording & playback',
    icon: Video,
    disabled: true,
    comingSoon: true,
  },
  {
    id: 'nas-nvr',
    label: 'NAS + NVR',
    description: 'File storage and camera recording',
    icon: Layers,
    disabled: true,
    comingSoon: true,
  },
]

export default function Step2_DeviceMode({ value, onChange }: Step2Props) {
  return (
    <div className="animate-fade-in">
      <div className="text-center mb-8">
        <h2 className="text-xl font-semibold text-gray-100">Device Mode</h2>
        <p className="text-sm text-navy-400 mt-1">How will you use this device?</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-2xl mx-auto">
        {options.map((opt) => {
          const Icon = opt.icon
          const selected = value === opt.id
          const selectable = !opt.disabled

          return (
            <button
              key={opt.id}
              type="button"
              disabled={opt.disabled}
              onClick={() => selectable && onChange(opt.id)}
              className={`
                relative text-left p-5 rounded-xl border transition-all duration-200
                ${selected
                  ? 'bg-sky-500/5 border-sky-500/30 ring-1 ring-sky-500/20'
                  : opt.disabled
                    ? 'bg-navy-900/50 border-navy-800/30 opacity-60 cursor-not-allowed'
                    : 'bg-navy-900 border-navy-800/50 hover:border-navy-700/50 cursor-pointer'
                }
              `}
            >
              {opt.comingSoon && (
                <span className="absolute top-3 right-3 text-[9px] font-semibold uppercase tracking-wider bg-navy-700/50 text-navy-400 px-2 py-0.5 rounded-full">
                  Coming Soon
                </span>
              )}

              <div className={`
                w-10 h-10 rounded-xl flex items-center justify-center mb-4
                ${selected ? 'bg-sky-500/10' : 'bg-navy-800'}
              `}>
                <Icon className={`w-5 h-5 ${selected ? 'text-sky-400' : 'text-navy-400'}`} />
              </div>

              <h3 className={`text-sm font-medium mb-1 ${selected ? 'text-sky-300' : 'text-gray-200'}`}>
                {opt.label}
              </h3>
              <p className="text-xs text-navy-400">{opt.description}</p>

              {selected && (
                <div className="absolute top-0 left-0 right-0 h-px rounded-t-xl bg-gradient-to-r from-transparent via-sky-500/40 to-transparent" />
              )}
            </button>
          )
        })}
      </div>
    </div>
  )
}
