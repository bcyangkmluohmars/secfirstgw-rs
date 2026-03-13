// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useContext, useEffect, useState, useRef, useCallback, type ReactNode } from 'react'
import { api, ApiError, type SystemStatus } from '../api'

interface StatusContextValue {
  status: SystemStatus | null
  online: boolean
}

const StatusContext = createContext<StatusContextValue>({ status: null, online: false })

const BASE_INTERVAL = 10_000  // 10s normal poll
const BACKOFF_INTERVAL = 60_000 // 60s when rate-limited

export function StatusProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [online, setOnline] = useState(false)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const backoffUntil = useRef(0)

  const fetchStatus = useCallback(async () => {
    // Skip if still in backoff window
    if (Date.now() < backoffUntil.current) return

    try {
      const s = await api.getStatus()
      setStatus(s)
      setOnline(true)
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 429) {
        // Rate limited — back off for 60s, don't spam
        backoffUntil.current = Date.now() + BACKOFF_INTERVAL
      }
      setOnline(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    intervalRef.current = setInterval(fetchStatus, BASE_INTERVAL)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [fetchStatus])

  return (
    <StatusContext.Provider value={{ status, online }}>
      {children}
    </StatusContext.Provider>
  )
}

export function useStatus() {
  return useContext(StatusContext)
}
