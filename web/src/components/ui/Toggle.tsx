// SPDX-License-Identifier: AGPL-3.0-or-later

interface ToggleProps {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  label?: string
}

export default function Toggle({ checked, onChange, disabled, label }: ToggleProps) {
  return (
    <label className={`flex items-center gap-2 ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        className={`
          w-10 h-[22px] rounded-full relative transition-colors duration-200 shrink-0
          ${checked ? 'bg-emerald-500' : 'bg-navy-700'}
        `}
      >
        <span
          className={`
            absolute top-[3px] left-[3px] w-4 h-4 rounded-full bg-white shadow-sm transition-transform duration-200
            ${checked ? 'translate-x-[18px]' : 'translate-x-0'}
          `}
        />
      </button>
      {label && <span className="text-sm text-gray-300">{label}</span>}
    </label>
  )
}
