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
  neutral: 'text-gray-300',
}

export default function StatusCard({ title, value, subtitle, status = 'neutral' }: StatusCardProps) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <p className="text-xs text-gray-500 uppercase tracking-wider font-mono mb-1">{title}</p>
      <p className={`text-xl font-mono font-bold ${statusColors[status]}`}>{value}</p>
      {subtitle && <p className="text-xs text-gray-600 font-mono mt-1">{subtitle}</p>}
    </div>
  )
}
