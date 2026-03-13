// SPDX-License-Identifier: AGPL-3.0-or-later

interface Tab {
  key: string
  label: string
  count?: number
}

interface TabsProps {
  tabs: Tab[]
  active: string
  onChange: (key: string) => void
}

export default function Tabs({ tabs, active, onChange }: TabsProps) {
  return (
    <div className="flex gap-0.5 bg-navy-900 border border-navy-800/50 rounded-xl p-1 w-fit">
      {tabs.map((tab) => {
        const isActive = active === tab.key
        return (
          <button
            key={tab.key}
            onClick={() => onChange(tab.key)}
            className={`
              relative px-4 py-2 text-xs font-medium rounded-lg transition-all duration-200
              ${isActive
                ? 'bg-navy-800 text-gray-200 shadow-sm shadow-black/20'
                : 'text-navy-400 hover:text-gray-300 hover:bg-navy-800/40'
              }
            `}
          >
            {isActive && (
              <span className="absolute bottom-0.5 left-1/2 -translate-x-1/2 w-4 h-0.5 rounded-full bg-emerald-400/60" />
            )}
            {tab.label}
            {tab.count != null && (
              <span className={`ml-1.5 text-[10px] tabular-nums ${isActive ? 'text-emerald-400' : 'text-navy-600'}`}>
                {tab.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
