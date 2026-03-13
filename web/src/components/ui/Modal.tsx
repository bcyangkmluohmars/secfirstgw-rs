// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect } from 'react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  size?: 'sm' | 'md' | 'lg'
}

const widths = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl' }

export default function Modal({ open, onClose, title, children, size = 'md' }: ModalProps) {
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handler)
      document.body.style.overflow = ''
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-navy-950/80 backdrop-blur-md animate-fade-in"
        onClick={onClose}
        style={{ animationDuration: '0.15s' }}
      />
      <div className={`
        relative w-full ${widths[size]} bg-navy-900 border border-navy-800/50
        rounded-xl shadow-2xl shadow-black/40 animate-scale-in overflow-hidden
      `}>
        {/* Subtle top accent line */}
        <div className="h-px bg-gradient-to-r from-transparent via-emerald-500/30 to-transparent" />
        <div className="flex items-center justify-between px-5 py-4 border-b border-navy-800/50">
          <h3 className="text-sm font-semibold text-gray-100">{title}</h3>
          <button
            onClick={onClose}
            className="p-1.5 text-navy-400 hover:text-gray-200 rounded-lg hover:bg-navy-800/50 transition-all duration-150 hover:rotate-90"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <div className="p-5 max-h-[70vh] overflow-y-auto">{children}</div>
      </div>
    </div>
  )
}
