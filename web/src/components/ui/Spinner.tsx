// SPDX-License-Identifier: AGPL-3.0-or-later

interface SpinnerProps {
  label?: string
  size?: 'sm' | 'md'
}

export default function Spinner({ label, size = 'md' }: SpinnerProps) {
  const dim = size === 'sm' ? 'w-5 h-5' : 'w-8 h-8'
  return (
    <div className="flex items-center justify-center py-20">
      <div className="text-center">
        <div className={`${dim} border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin mx-auto mb-3`} />
        {label && <p className="text-sm text-navy-400">{label}</p>}
      </div>
    </div>
  )
}
