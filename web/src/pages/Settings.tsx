import { useState } from 'react'

interface SettingGroup {
  title: string
  fields: { label: string; value: string; type?: string }[]
}

const settingGroups: SettingGroup[] = [
  {
    title: 'General',
    fields: [
      { label: 'Hostname', value: 'secfirstgw' },
      { label: 'Timezone', value: 'UTC' },
      { label: 'DNS Server 1', value: '1.1.1.1' },
      { label: 'DNS Server 2', value: '8.8.8.8' },
    ],
  },
  {
    title: 'Management',
    fields: [
      { label: 'Web UI Port', value: '443' },
      { label: 'SSH Port', value: '22' },
      { label: 'API Port', value: '8443' },
    ],
  },
  {
    title: 'Logging',
    fields: [
      { label: 'Log Level', value: 'info' },
      { label: 'Syslog Server', value: '' },
      { label: 'Log Retention (days)', value: '30' },
    ],
  },
]

// TODO: Wire to settings API when implemented
export default function Settings() {
  const [groups, setGroups] = useState(settingGroups)

  function handleChange(gi: number, fi: number, val: string) {
    setGroups((prev) => {
      const next = [...prev]
      next[gi] = {
        ...next[gi],
        fields: next[gi].fields.map((f, i) => (i === fi ? { ...f, value: val } : f)),
      }
      return next
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-100">Settings</h2>
        <button
          disabled
          className="px-4 py-2 text-xs font-medium rounded-lg border transition-all duration-200 bg-navy-800 text-navy-500 border-navy-700/50 cursor-not-allowed"
        >
          Not yet implemented
        </button>
      </div>

      {groups.map((group, gi) => (
        <div key={group.title} className="bg-navy-900 border border-navy-800/50 rounded-xl p-5 animate-fade-in">
          <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-5">{group.title}</p>
          <div className="space-y-4">
            {group.fields.map((field, fi) => (
              <div key={field.label} className="flex items-center gap-4">
                <label className="w-48 text-sm text-navy-400 shrink-0">{field.label}</label>
                <input
                  type={field.type ?? 'text'}
                  value={field.value}
                  onChange={(e) => handleChange(gi, fi, e.target.value)}
                  className="flex-1 bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-emerald-500/50 transition-colors"
                />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
