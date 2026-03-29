// SPDX-License-Identifier: AGPL-3.0-or-later

import { type SelectHTMLAttributes } from 'react'

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string
  options: { value: string; label: string }[]
}

export default function Select({ label, options, className = '', ...props }: SelectProps) {
  return (
    <label className="block">
      {label && <span className="block text-[11px] font-medium text-navy-400 mb-1.5">{label}</span>}
      <select
        className={`
          w-full bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-200
          focus:outline-none focus:border-emerald-500/50 transition-colors
          ${className}
        `}
        {...props}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  )
}
