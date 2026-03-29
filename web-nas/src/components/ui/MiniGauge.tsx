// SPDX-License-Identifier: AGPL-3.0-or-later

interface MiniGaugeProps {
  value: number
  max: number
  label: string
  unit: string
  color?: string
  size?: number
  subtitle?: string
  thresholds?: { warn: number; error: number }
}

export default function MiniGauge({
  value,
  max,
  label,
  unit,
  color,
  size = 100,
  subtitle,
  thresholds = { warn: 70, error: 85 },
}: MiniGaugeProps) {
  const percent = max > 0 ? Math.min((value / max) * 100, 100) : 0
  const resolvedColor = color ?? (percent >= thresholds.error ? '#f87171' : percent >= thresholds.warn ? '#fbbf24' : '#34d399')

  const r = (size - 12) / 2
  const c = 2 * Math.PI * r
  const arcLen = c * 0.75 // 270 degrees
  const offset = arcLen - (percent / 100) * arcLen

  return (
    <div className="flex flex-col items-center">
      <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider mb-2">{label}</p>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform rotate-[135deg]">
          <circle
            cx={size / 2} cy={size / 2} r={r}
            fill="none" stroke="currentColor" strokeWidth="5"
            strokeDasharray={`${arcLen} ${c}`}
            className="text-navy-800/80"
            strokeLinecap="round"
          />
          <circle
            cx={size / 2} cy={size / 2} r={r}
            fill="none" stroke={resolvedColor} strokeWidth="5"
            strokeDasharray={`${arcLen} ${c}`}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.3s ease',
              filter: `drop-shadow(0 0 4px ${resolvedColor}50)`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-light text-gray-100 tabular-nums leading-none" style={{ color: resolvedColor }}>
            {value % 1 !== 0 ? value.toFixed(1) : value}
          </span>
          <span className="text-[9px] text-navy-500 mt-0.5">{unit}</span>
        </div>
      </div>
      {subtitle && <p className="text-[10px] text-navy-500 font-mono mt-1 tabular-nums text-center">{subtitle}</p>}
    </div>
  )
}
