// SPDX-License-Identifier: AGPL-3.0-or-later

import { Lock, Unlock, ShieldCheck, AlertTriangle } from 'lucide-react'

interface Step5Props {
  value: boolean
  onChange: (enabled: boolean) => void
}

export default function Step5_Encryption({ value, onChange }: Step5Props) {
  return (
    <div className="animate-fade-in max-w-lg mx-auto">
      <div className="text-center mb-8">
        <h2 className="text-xl font-semibold text-gray-100">Drive Encryption</h2>
        <p className="text-sm text-navy-400 mt-1">Hardware-accelerated AES encryption</p>
      </div>

      {/* Toggle Card */}
      <div className={`
        rounded-xl border p-6 transition-all duration-300 mb-6
        ${value
          ? 'bg-emerald-500/5 border-emerald-500/20'
          : 'bg-red-500/5 border-red-500/20'
        }
      `}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className={`
              w-11 h-11 rounded-xl flex items-center justify-center
              ${value ? 'bg-emerald-500/10' : 'bg-red-500/10'}
            `}>
              {value ? (
                <Lock className="w-5 h-5 text-emerald-400" />
              ) : (
                <Unlock className="w-5 h-5 text-red-400" />
              )}
            </div>
            <div>
              <p className={`text-sm font-medium ${value ? 'text-emerald-300' : 'text-red-300'}`}>
                Encrypt Storage
              </p>
              <p className="text-xs text-navy-400">
                LUKS/dm-crypt with AES-256-XTS
              </p>
            </div>
          </div>

          {/* Toggle Switch */}
          <button
            type="button"
            role="switch"
            aria-checked={value}
            onClick={() => onChange(!value)}
            className={`
              w-12 h-[26px] rounded-full relative transition-colors duration-200 shrink-0
              ${value ? 'bg-emerald-500' : 'bg-navy-700'}
            `}
          >
            <span
              className={`
                absolute top-[3px] left-[3px] w-5 h-5 rounded-full bg-white shadow-sm transition-transform duration-200
                ${value ? 'translate-x-[22px]' : 'translate-x-0'}
              `}
            />
          </button>
        </div>

        {value ? (
          <div className="flex items-start gap-3 bg-emerald-500/5 border border-emerald-500/10 rounded-lg p-4">
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-emerald-300 font-medium mb-1">Encryption Enabled</p>
              <p className="text-xs text-navy-400 leading-relaxed">
                Your data is protected even if drives are physically stolen. All data at rest is encrypted using
                hardware-accelerated AES. Encryption keys are managed automatically and secured in the device TPM
                when available.
              </p>
            </div>
          </div>
        ) : (
          <div className="flex items-start gap-3 bg-red-500/5 border border-red-500/10 rounded-lg p-4">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-red-300 font-medium mb-1">WARNING: Encryption Disabled</p>
              <p className="text-xs text-red-300/70 leading-relaxed">
                Data will NOT be encrypted at rest. Anyone with physical access to the drives can read your data.
                This includes scenarios where drives are stolen, decommissioned, or the device is accessed by
                unauthorized personnel.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Info Section */}
      <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5">
        <p className="text-[10px] font-medium text-navy-500 uppercase tracking-wider mb-3">Details</p>
        <div className="space-y-3">
          <div className="flex items-start gap-3">
            <div className="w-1.5 h-1.5 rounded-full bg-navy-600 mt-1.5 shrink-0" />
            <p className="text-xs text-navy-400">
              Uses LUKS2 with AES-256-XTS, the industry standard for full-disk encryption
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="w-1.5 h-1.5 rounded-full bg-navy-600 mt-1.5 shrink-0" />
            <p className="text-xs text-navy-400">
              Hardware AES acceleration ensures minimal performance overhead (typically less than 3%)
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="w-1.5 h-1.5 rounded-full bg-navy-600 mt-1.5 shrink-0" />
            <p className="text-xs text-navy-400">
              Encryption is applied at the block device level, below the filesystem and RAID layers
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="w-1.5 h-1.5 rounded-full bg-navy-600 mt-1.5 shrink-0" />
            <p className="text-xs text-navy-400">
              Enabling encryption after initial setup requires reformatting all drives
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
