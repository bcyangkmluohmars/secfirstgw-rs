// SPDX-License-Identifier: AGPL-3.0-or-later

import type { BayInfo } from '../types'

interface BayVisualizationProps {
  bays: BayInfo[]
}

/** Map the API bay state to a normalized state for display. */
function normalizeBayState(state: string | undefined): 'healthy' | 'fault' | 'empty' | 'rebuilding' {
  switch (state) {
    case 'healthy':
    case 'Present':
      return 'healthy'
    case 'fault':
      return 'fault'
    case 'rebuilding':
      return 'rebuilding'
    case 'empty':
    case 'Empty':
      return 'empty'
    default:
      // Treat unknown states as healthy if present, empty otherwise
      return state ? 'healthy' : 'empty'
  }
}

function bayColor(state: string): string {
  const normalized = normalizeBayState(state)
  switch (normalized) {
    case 'healthy': return '#34d399'
    case 'rebuilding': return '#fbbf24'
    case 'fault': return '#f87171'
    case 'empty': return '#334d6e'
  }
}

function bayGlow(state: string): string {
  const normalized = normalizeBayState(state)
  switch (normalized) {
    case 'healthy': return 'drop-shadow(0 0 4px #34d39940)'
    case 'rebuilding': return 'drop-shadow(0 0 6px #fbbf2460)'
    case 'fault': return 'drop-shadow(0 0 6px #f8717160)'
    case 'empty': return 'none'
  }
}

export default function BayVisualization({ bays }: BayVisualizationProps) {
  // Ensure we always show 4 bays
  const normalizedBays: BayInfo[] = Array.from({ length: 4 }, (_, i) => {
    const slotNum = i + 1
    const found = (bays ?? []).find((b) => (b.bay ?? b.slot) === slotNum)
    return found ?? { bay: slotNum, state: 'empty' as const, disk_serial: null, disk_model: null, activity_led: false }
  })

  const bayWidth = 56
  const bayHeight = 80
  const gap = 8
  const padding = 16
  const totalWidth = padding * 2 + bayWidth * 4 + gap * 3
  const totalHeight = padding * 2 + bayHeight + 32

  return (
    <div className="flex flex-col items-center">
      <svg
        width={totalWidth}
        height={totalHeight}
        viewBox={`0 0 ${totalWidth} ${totalHeight}`}
        className="max-w-full h-auto"
      >
        {/* Chassis */}
        <rect
          x="2"
          y="2"
          width={totalWidth - 4}
          height={totalHeight - 4}
          rx="8"
          fill="#0b1120"
          stroke="#1a2540"
          strokeWidth="1.5"
        />

        {/* Top label */}
        <text x={totalWidth / 2} y="18" textAnchor="middle" className="text-[9px] fill-navy-500 font-mono uppercase">
          SecFirstNAS
        </text>

        {normalizedBays.map((bay, i) => {
          const x = padding + i * (bayWidth + gap)
          const y = 28
          const state = bay.state ?? 'empty'
          const normalizedState = normalizeBayState(state)
          const color = bayColor(state)
          const glow = bayGlow(state)
          const isActive = bay.activity_led ?? (bay.led_mode === 'Activity')

          return (
            <g key={bay.bay ?? bay.slot ?? i}>
              {/* Bay slot */}
              <rect
                x={x}
                y={y}
                width={bayWidth}
                height={bayHeight}
                rx="4"
                fill="#111a2e"
                stroke="#1a2540"
                strokeWidth="1"
              />

              {/* Drive tray handle */}
              <rect
                x={x + 4}
                y={y + 4}
                width={bayWidth - 8}
                height={6}
                rx="2"
                fill="#1a2540"
              />

              {/* Drive body (if not empty) */}
              {normalizedState !== 'empty' && (
                <rect
                  x={x + 6}
                  y={y + 14}
                  width={bayWidth - 12}
                  height={bayHeight - 22}
                  rx="2"
                  fill="#0e1529"
                  stroke={color}
                  strokeWidth="0.5"
                  opacity="0.8"
                />
              )}

              {/* Status LED */}
              <circle
                cx={x + bayWidth - 10}
                cy={y + bayHeight - 8}
                r="3"
                fill={color}
                style={{ filter: glow }}
              >
                {normalizedState === 'rebuilding' && (
                  <animate attributeName="opacity" values="1;0.3;1" dur="1.5s" repeatCount="indefinite" />
                )}
                {normalizedState === 'healthy' && isActive && (
                  <animate attributeName="opacity" values="1;0.5;1" dur="0.3s" repeatCount="indefinite" />
                )}
              </circle>

              {/* Activity LED */}
              {isActive && normalizedState !== 'empty' && (
                <circle cx={x + 10} cy={y + bayHeight - 8} r="2" fill="#60a5fa">
                  <animate attributeName="opacity" values="0;1;0" dur="0.15s" repeatCount="indefinite" />
                </circle>
              )}

              {/* Bay number */}
              <text
                x={x + bayWidth / 2}
                y={y + bayHeight + 14}
                textAnchor="middle"
                className="text-[10px] fill-navy-400 font-mono"
              >
                Bay {bay.bay ?? bay.slot ?? i + 1}
              </text>
            </g>
          )
        })}
      </svg>

      {/* Legend */}
      <div className="flex gap-4 mt-2 text-[10px]">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="text-navy-400">Healthy</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-amber-400" />
          <span className="text-navy-400">Rebuilding</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-red-400" />
          <span className="text-navy-400">Fault</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-navy-500" />
          <span className="text-navy-400">Empty</span>
        </div>
      </div>
    </div>
  )
}
