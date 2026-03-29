// SPDX-License-Identifier: AGPL-3.0-or-later

import type { DiskHealth, BayState, ArrayState } from '../types'

type StatusType = DiskHealth | BayState | ArrayState | string

interface StatusBadgeProps {
  status: StatusType
  className?: string
}

function resolveVariant(status: StatusType): { bg: string; text: string; border: string; dot: string } {
  switch (status) {
    case 'healthy':
    case 'active':
    case 'passed':
    case 'Passed':
    case 'ok':
    case 'up':
      return { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20', dot: 'bg-emerald-400' }
    case 'warning':
    case 'degraded':
    case 'rebuilding':
    case 'spare':
      return { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/15', dot: 'bg-amber-400' }
    case 'failing':
    case 'fault':
    case 'faulty':
    case 'failed':
      return { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/15', dot: 'bg-red-400' }
    case 'empty':
    case 'inactive':
    case 'unknown':
    default:
      return { bg: 'bg-navy-800', text: 'text-navy-400', border: 'border-navy-700/50', dot: 'bg-navy-500' }
  }
}

export default function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const v = resolveVariant(status)

  return (
    <span className={`
      inline-flex items-center gap-1.5 text-[10px] font-bold px-2 py-0.5
      rounded-md border uppercase
      ${v.bg} ${v.text} ${v.border} ${className}
    `}>
      <span className={`w-1.5 h-1.5 rounded-full ${v.dot}`} />
      {status}
    </span>
  )
}
