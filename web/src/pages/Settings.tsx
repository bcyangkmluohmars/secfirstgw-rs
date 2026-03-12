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

export default function Settings() {
  const [groups, setGroups] = useState(settingGroups)
  const [saved, setSaved] = useState(false)

  function handleChange(gi: number, fi: number, val: string) {
    setGroups((prev) => {
      const next = [...prev]
      next[gi] = {
        ...next[gi],
        fields: next[gi].fields.map((f, i) => (i === fi ? { ...f, value: val } : f)),
      }
      return next
    })
    setSaved(false)
  }

  function handleSave() {
    // In the future, POST to /api/v1/settings
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold font-mono">Settings</h2>
        <button
          onClick={handleSave}
          className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-mono rounded transition-colors"
        >
          {saved ? 'Saved' : 'Save Changes'}
        </button>
      </div>

      <div className="space-y-6">
        {groups.map((group, gi) => (
          <div key={group.title} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wider mb-4">{group.title}</h3>
            <div className="space-y-3">
              {group.fields.map((field, fi) => (
                <div key={field.label} className="flex items-center gap-4">
                  <label className="w-48 text-sm font-mono text-gray-500 shrink-0">{field.label}</label>
                  <input
                    type={field.type ?? 'text'}
                    value={field.value}
                    onChange={(e) => handleChange(gi, fi, e.target.value)}
                    className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-200 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
