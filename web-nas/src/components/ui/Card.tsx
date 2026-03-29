// SPDX-License-Identifier: AGPL-3.0-or-later

interface CardProps {
  title?: string
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
  noPadding?: boolean
  accent?: string
}

export default function Card({ title, actions, children, className = '', noPadding, accent }: CardProps) {
  return (
    <div className={`
      relative bg-navy-900 border border-navy-800/50 rounded-xl animate-fade-in
      ${noPadding ? '' : 'p-5'} ${className}
      hover:border-navy-700/50 transition-colors duration-300
    `}>
      {accent && (
        <div
          className="absolute top-0 left-0 right-0 h-px rounded-t-xl"
          style={{ background: `linear-gradient(to right, transparent, ${accent}40, transparent)` }}
        />
      )}
      {(title || actions) && (
        <div className={`flex items-center justify-between ${noPadding ? 'px-5 pt-5' : ''} ${title ? 'mb-4' : ''}`}>
          {title && <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider">{title}</p>}
          {actions && <div className="flex gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </div>
  )
}
