// SPDX-License-Identifier: AGPL-3.0-or-later

type Variant = 'success' | 'warning' | 'danger' | 'info' | 'neutral'

interface BadgeProps {
  variant?: Variant
  children: React.ReactNode
  className?: string
}

const styles: Record<Variant, string> = {
  success: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  warning: 'bg-amber-500/10 text-amber-400 border-amber-500/15',
  danger: 'bg-red-500/10 text-red-400 border-red-500/15',
  info: 'bg-sky-500/10 text-sky-400 border-sky-500/15',
  neutral: 'bg-navy-800 text-navy-400 border-navy-700/50',
}

export default function Badge({ variant = 'neutral', children, className = '' }: BadgeProps) {
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border uppercase ${styles[variant]} ${className}`}>
      {children}
    </span>
  )
}
