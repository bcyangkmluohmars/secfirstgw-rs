// SPDX-License-Identifier: AGPL-3.0-or-later

interface DonutChartProps {
  used: number
  total: number
  size?: number
  strokeWidth?: number
  label?: string
  usedLabel?: string
  freeLabel?: string
}

export default function DonutChart({
  used,
  total,
  size = 160,
  strokeWidth = 14,
  label,
  usedLabel,
  freeLabel,
}: DonutChartProps) {
  const percent = total > 0 ? Math.min((used / total) * 100, 100) : 0
  const r = (size - strokeWidth) / 2
  const c = 2 * Math.PI * r
  const offset = c - (percent / 100) * c

  const color = percent >= 90 ? '#f87171' : percent >= 75 ? '#fbbf24' : '#34d399'

  return (
    <div className="flex flex-col items-center">
      {label && <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider mb-3">{label}</p>}
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform -rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-navy-800/60"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={`${c}`}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.3s ease',
              filter: `drop-shadow(0 0 6px ${color}40)`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-light tabular-nums" style={{ color }}>
            {percent.toFixed(1)}%
          </span>
          <span className="text-[10px] text-navy-500 mt-0.5">used</span>
        </div>
      </div>
      {(usedLabel || freeLabel) && (
        <div className="flex gap-4 mt-3 text-[11px]">
          {usedLabel && (
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-navy-400">{usedLabel}</span>
            </div>
          )}
          {freeLabel && (
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-navy-700" />
              <span className="text-navy-400">{freeLabel}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
