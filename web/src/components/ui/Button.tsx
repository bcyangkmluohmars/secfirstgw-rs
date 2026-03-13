// SPDX-License-Identifier: AGPL-3.0-or-later

import { type ButtonHTMLAttributes } from 'react'

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost'
type Size = 'sm' | 'md'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
  loading?: boolean
}

const variants: Record<Variant, string> = {
  primary: 'bg-emerald-500/10 hover:bg-emerald-500/20 border-emerald-500/20 text-emerald-400',
  secondary: 'bg-navy-800 hover:bg-navy-700/50 border-navy-700/50 text-gray-300',
  danger: 'bg-red-500/10 hover:bg-red-500/20 border-red-500/15 text-red-400',
  ghost: 'bg-transparent hover:bg-navy-800/50 border-transparent text-navy-400 hover:text-gray-200',
}

const sizes: Record<Size, string> = {
  sm: 'px-2.5 py-1 text-[11px]',
  md: 'px-3 py-1.5 text-xs',
}

export default function Button({
  variant = 'primary',
  size = 'md',
  loading = false,
  disabled,
  children,
  className = '',
  ...props
}: ButtonProps) {
  return (
    <button
      disabled={disabled || loading}
      className={`
        font-medium rounded-lg border transition-all duration-200
        disabled:opacity-50 disabled:cursor-not-allowed
        ${variants[variant]} ${sizes[size]} ${className}
      `}
      {...props}
    >
      {loading ? (
        <span className="flex items-center justify-center gap-2">
          <div className="w-3.5 h-3.5 border-2 border-current/30 border-t-current rounded-full animate-spin" />
          {children}
        </span>
      ) : children}
    </button>
  )
}
