// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useContext } from 'react'

export type BootStatus = 'loading' | 'setup' | 'login' | 'ready'

export interface BootState {
  status: BootStatus
  setLogin: () => void
  setReady: () => void
  setLogout: () => void
}

export const BootContext = createContext<BootState>({
  status: 'loading',
  setLogin: () => {},
  setReady: () => {},
  setLogout: () => {},
})

export function useBoot(): BootState {
  return useContext(BootContext)
}
