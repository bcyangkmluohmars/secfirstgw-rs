interface StatusCardProps {
  title: string
  value: string | number
  subtitle?: string
  status?: 'ok' | 'warn' | 'error' | 'neutral'
}

const statusColors = {
  ok: 'text-emerald-400',
  warn: 'text-amber-400',
  error: 'text-red-400',
  neutral: 'text-gray-100',
}

export default function StatusCard({ title, value, subtitle, status = 'neutral' }: StatusCardProps) {
  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
      <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-2">{title}</p>
      <p className={`text-xl font-light tabular-nums ${statusColors[status]}`}>{value}</p>
      {subtitle && <p className="text-[11px] text-navy-500 font-mono mt-1.5">{subtitle}</p>}
    </div>
  )
}
