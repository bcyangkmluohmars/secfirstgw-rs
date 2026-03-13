// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from 'react'

interface SparklineProps {
  data: number[]
  width?: number
  height?: number
  color?: string
  fillOpacity?: number
  strokeWidth?: number
  className?: string
  showDot?: boolean
  animated?: boolean
}

export default function Sparkline({
  data,
  width = 200,
  height = 48,
  color = '#34d399',
  fillOpacity = 0.15,
  strokeWidth = 1.5,
  className = '',
  showDot = true,
  animated = true,
}: SparklineProps) {
  const { linePath, areaPath, lastPoint } = useMemo(() => {
    if (data.length < 2) return { linePath: '', areaPath: '', maxY: 0, lastPoint: { x: 0, y: 0 } }

    const max = Math.max(...data, 1)
    const pad = 2
    const usableW = width - pad * 2
    const usableH = height - pad * 2
    const step = usableW / (data.length - 1)

    const points = data.map((v, i) => ({
      x: pad + i * step,
      y: pad + usableH - (v / max) * usableH,
    }))

    // Smooth catmull-rom spline
    const catmull = (pts: { x: number; y: number }[], tension = 0.3) => {
      if (pts.length < 2) return ''
      const segments: string[] = [`M${pts[0].x},${pts[0].y}`]
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[Math.max(i - 1, 0)]
        const p1 = pts[i]
        const p2 = pts[i + 1]
        const p3 = pts[Math.min(i + 2, pts.length - 1)]

        const cp1x = p1.x + (p2.x - p0.x) * tension
        const cp1y = p1.y + (p2.y - p0.y) * tension
        const cp2x = p2.x - (p3.x - p1.x) * tension
        const cp2y = p2.y - (p3.y - p1.y) * tension

        segments.push(`C${cp1x},${cp1y} ${cp2x},${cp2y} ${p2.x},${p2.y}`)
      }
      return segments.join(' ')
    }

    const line = catmull(points)
    const last = points[points.length - 1]
    const area = `${line} L${last.x},${height} L${points[0].x},${height} Z`

    return { linePath: line, areaPath: area, lastPoint: last }
  }, [data, width, height])

  if (data.length < 2) {
    return (
      <svg width={width} height={height} className={className}>
        <line x1="0" y1={height / 2} x2={width} y2={height / 2} stroke={color} strokeWidth="0.5" opacity="0.3" />
      </svg>
    )
  }

  return (
    <svg width={width} height={height} className={className} viewBox={`0 0 ${width} ${height}`}>
      <defs>
        <linearGradient id={`fill-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={fillOpacity} />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
        {animated && (
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        )}
      </defs>
      <path
        d={areaPath}
        fill={`url(#fill-${color.replace('#', '')})`}
        className={animated ? 'animate-fade-in' : ''}
      />
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        className={animated ? 'animate-fade-in' : ''}
      />
      {showDot && lastPoint && (
        <g>
          <circle cx={lastPoint.x} cy={lastPoint.y} r="3" fill={color} opacity="0.3">
            <animate attributeName="r" from="3" to="8" dur="2s" repeatCount="indefinite" />
            <animate attributeName="opacity" from="0.3" to="0" dur="2s" repeatCount="indefinite" />
          </circle>
          <circle cx={lastPoint.x} cy={lastPoint.y} r="2.5" fill={color} filter={animated ? 'url(#glow)' : undefined} />
        </g>
      )}
    </svg>
  )
}
