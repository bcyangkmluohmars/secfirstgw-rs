// SPDX-License-Identifier: AGPL-3.0-or-later

interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
}

export default function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="bg-navy-900 border border-navy-800/50 rounded-xl p-16 text-center animate-fade-in">
      {icon && <div className="text-navy-700 mx-auto mb-4 flex items-center justify-center">{icon}</div>}
      <p className="text-sm font-medium text-navy-400">{title}</p>
      {description && <p className="text-xs text-navy-600 mt-2 max-w-xs mx-auto">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
