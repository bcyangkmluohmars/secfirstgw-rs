// SPDX-License-Identifier: AGPL-3.0-or-later

interface StatCardProps {
  label: string
  value: React.ReactNode
  subtitle?: string
  icon?: React.ReactNode
  accentColor?: string
  children?: React.ReactNode
}

export default function StatCard({ label, value, subtitle, icon, accentColor = '#34d399', children }: StatCardProps) {
  return (
    <div className="relative bg-navy-900 border border-navy-800/50 rounded-xl p-4 overflow-hidden group animate-fade-in">
      <div
        className="absolute -top-12 -right-12 w-24 h-24 rounded-full opacity-[0.03] group-hover:opacity-[0.06] transition-opacity duration-500"
        style={{ background: `radial-gradient(circle, ${accentColor}, transparent)` }}
      />
      <div className="relative">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            {icon && <div className="text-navy-500">{icon}</div>}
            <p className="text-[10px] font-medium text-navy-400 uppercase tracking-wider">{label}</p>
          </div>
        </div>
        <div className="text-2xl font-light text-gray-100 tabular-nums tracking-tight">{value}</div>
        {subtitle && <p className="text-[10px] text-navy-500 font-mono mt-1.5 tabular-nums">{subtitle}</p>}
        {children && <div className="mt-3">{children}</div>}
      </div>
    </div>
  )
}
