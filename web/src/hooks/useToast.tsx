// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useCallback, useContext, useState, useRef } from 'react'

type ToastType = 'success' | 'error' | 'info'

interface Toast {
  id: number
  type: ToastType
  message: string
  exiting?: boolean
}

interface ToastContextValue {
  success: (msg: string) => void
  error: (msg: string) => void
  info: (msg: string) => void
}

const ToastContext = createContext<ToastContextValue>({
  success: () => {},
  error: () => {},
  info: () => {},
})

export function useToast() {
  return useContext(ToastContext)
}

const typeStyles: Record<ToastType, string> = {
  success: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
  error: 'border-red-500/30 bg-red-500/10 text-red-400',
  info: 'border-sky-500/30 bg-sky-500/10 text-sky-400',
}

const accentColors: Record<ToastType, string> = {
  success: '#34d399',
  error: '#f87171',
  info: '#38bdf8',
}

const icons: Record<ToastType, React.ReactNode> = {
  success: (
    <svg className="w-4 h-4 shrink-0" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
    </svg>
  ),
  error: (
    <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" />
    </svg>
  ),
  info: (
    <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  ),
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(0)

  const add = useCallback((type: ToastType, message: string) => {
    const id = nextId.current++
    setToasts((prev) => [...prev, { id, type, message }])
    // Start exit animation before removal
    setTimeout(() => setToasts((prev) => prev.map((t) => t.id === id ? { ...t, exiting: true } : t)), 3500)
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4000)
  }, [])

  const value: ToastContextValue = {
    success: useCallback((msg: string) => add('success', msg), [add]),
    error: useCallback((msg: string) => add('error', msg), [add]),
    info: useCallback((msg: string) => add('info', msg), [add]),
  }

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`
              pointer-events-auto flex items-center gap-2.5 px-4 py-3 rounded-lg border
              shadow-lg shadow-black/20 backdrop-blur-md text-xs font-medium
              transition-all duration-300
              ${t.exiting ? 'opacity-0 translate-x-4' : 'animate-slide-in-right'}
              ${typeStyles[t.type]}
            `}
          >
            {/* Left accent bar */}
            <div
              className="absolute left-0 top-1 bottom-1 w-0.5 rounded-full"
              style={{ background: accentColors[t.type] }}
            />
            {icons[t.type]}
            <span className="ml-1">{t.message}</span>
            {/* Progress bar */}
            <div className="absolute bottom-0 left-2 right-2 h-px overflow-hidden rounded-full">
              <div
                className="h-full rounded-full"
                style={{
                  background: accentColors[t.type],
                  opacity: 0.4,
                  animation: 'shrink-bar 3.5s linear forwards',
                }}
              />
            </div>
          </div>
        ))}
      </div>

      <style>{`
        @keyframes shrink-bar {
          from { width: 100%; }
          to { width: 0%; }
        }
      `}</style>
    </ToastContext.Provider>
  )
}
