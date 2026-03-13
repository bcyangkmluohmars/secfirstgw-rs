// SPDX-License-Identifier: AGPL-3.0-or-later

import { type InputHTMLAttributes } from 'react'

interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> {
  label?: string
  mono?: boolean
  error?: string
}

export default function Input({ label, mono = false, error, className = '', ...props }: InputProps) {
  return (
    <label className="block">
      {label && <span className="block text-[11px] font-medium text-navy-400 mb-1.5">{label}</span>}
      <input
        className={`
          w-full bg-navy-800 border rounded-lg px-3 py-2 text-sm text-gray-200
          focus:outline-none focus:border-emerald-500/50 transition-colors
          placeholder-navy-600
          ${mono ? 'font-mono' : ''}
          ${error ? 'border-red-500/50' : 'border-navy-700/50'}
          ${className}
        `}
        {...props}
      />
      {error && <p className="text-[11px] text-red-400 mt-1">{error}</p>}
    </label>
  )
}
