// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, ChevronRight, LogIn } from 'lucide-react'
import { useBoot } from '../../boot'
import { api, setToken } from '../../api'
import { initSession } from '../../crypto'
import type { BayInfo, Disk } from '../../types'
import Step0_Discovery from './Step0_Discovery'
import Step1_AdminUser from './Step1_AdminUser'
import Step2_DeviceMode from './Step2_DeviceMode'
import Step3_BayAssignment from './Step3_BayAssignment'
import Step4_RaidConfig from './Step4_RaidConfig'
import Step5_Encryption from './Step5_Encryption'
import Step6_Summary from './Step6_Summary'

type DeviceMode = 'nas' | 'nvr' | 'nas-nvr'
type RaidLevel = 'raid0' | 'raid1' | 'raid5' | 'raid10'

interface WizardState {
  adminCreated: boolean
  loggedIn: boolean
  deviceMode: DeviceMode
  bayAssignments: Record<number, 'nas' | 'nvr'>
  selectedDisks: string[] // device paths, e.g. ["/dev/sda", "/dev/sdb"]
  raidLevel: RaidLevel | null
  encryption: boolean
  discoveredBays: BayInfo[]
  discoveredDisks: Disk[]
}

// New order: Admin(0) -> Login(1) -> Discovery(2) -> Mode(3) -> Bays(4) -> RAID(5) -> Encryption(6) -> Summary(7)
const STEP_LABELS = [
  'Admin',
  'Login',
  'Discovery',
  'Mode',
  'Bays',
  'RAID',
  'Encryption',
  'Summary',
]

const TOTAL_STEPS = STEP_LABELS.length

export default function SetupWizard() {
  const { setReady } = useBoot()
  const navigate = useNavigate()
  const [step, setStep] = useState(0)
  const [adminUsername, setAdminUsername] = useState('')
  const [loginError, setLoginError] = useState<string | null>(null)
  const [loggingIn, setLoggingIn] = useState(false)

  const [state, setState] = useState<WizardState>({
    adminCreated: false,
    loggedIn: false,
    deviceMode: 'nas',
    bayAssignments: {},
    selectedDisks: [],
    raidLevel: null,
    encryption: true,
    discoveredBays: [],
    discoveredDisks: [],
  })

  // Step 0: Admin created -> auto-advance to login
  function handleAdminCreated(username: string) {
    setAdminUsername(username)
    setState((prev) => ({ ...prev, adminCreated: true }))
    setStep(1)
  }

  // Step 1: Auto-login with the credentials just created
  // The admin user form stores the password temporarily for auto-login
  async function handleLogin(password: string) {
    setLoggingIn(true)
    setLoginError(null)
    try {
      const res = await api.login({ username: adminUsername, password })
      setToken(res.token)
      await initSession()
      setState((prev) => ({ ...prev, loggedIn: true }))
      setStep(2) // -> Discovery
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoggingIn(false)
    }
  }

  // Step 2: Discovery complete
  const handleDiscovered = useCallback((bays: BayInfo[], disks: Disk[]) => {
    setState((prev) => ({ ...prev, discoveredBays: bays, discoveredDisks: disks }))

    const assignments: Record<number, 'nas' | 'nvr'> = {}
    for (const bay of bays) {
      const slotNum = bay.bay ?? bay.slot ?? 0
      const isEmpty = bay.state === 'empty' || bay.state === 'Empty'
      if (!isEmpty && slotNum > 0) {
        assignments[slotNum] = 'nas'
      }
    }
    setState((prev) => ({ ...prev, bayAssignments: assignments }))

    const diskCount = disks.length
    let defaultRaid: RaidLevel | null = null
    if (diskCount >= 3) defaultRaid = 'raid5'
    else if (diskCount === 2) defaultRaid = 'raid1'
    setState((prev) => ({ ...prev, raidLevel: defaultRaid }))
  }, [])

  // Summary: Initialize storage
  async function handleInitialize(): Promise<void> {
    // Check if RAID already exists
    try {
      const arrays = await api.getArrays()
      if (arrays.length > 0) {
        // RAID already exists — skip initialization, go to dashboard
        setReady()
        navigate('/')
        return
      }
    } catch {
      // Can't check — try to initialize anyway
    }

    // No existing RAID — create one
    if (state.selectedDisks.length < 2 || !state.raidLevel) {
      // Not enough disks or no RAID level — skip to dashboard
      setReady()
      navigate('/')
      return
    }

    const levelMap: Record<string, string> = {
      raid0: '0', raid1: '1', raid5: '5', raid10: '10',
    }

    await api.initializeStorage({
      name: 'data',
      level: levelMap[state.raidLevel] ?? '5',
      disks: state.selectedDisks,
      encrypt: state.encryption,
    })

    setReady()
    navigate('/')
  }

  // Skip to dashboard (available after login)
  function handleSkip() {
    setReady()
    navigate('/')
  }

  // Navigation
  function goBack() {
    if (step > 2) setStep(step - 1)
  }

  function goNext() {
    if (step < TOTAL_STEPS - 1) setStep(step + 1)
  }

  const showBack = step > 2
  const showNext = step >= 2 && step < TOTAL_STEPS - 1
  const showSkip = step >= 2 && state.loggedIn

  return (
    <div className="min-h-screen bg-navy-950 flex flex-col">
      {/* Header */}
      <div className="pt-8 pb-2 px-4 text-center">
        <div className="w-10 h-10 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center mx-auto mb-3">
          <svg className="w-5 h-5 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
            <line x1="6" y1="6" x2="6.01" y2="6" />
            <line x1="6" y1="18" x2="6.01" y2="18" />
          </svg>
        </div>
        <h1 className="text-lg font-semibold tracking-tight text-gray-100">SecFirstNAS Setup</h1>
      </div>

      {/* Step Progress */}
      <div className="px-4 py-4">
        <div className="flex items-center justify-center gap-1 max-w-lg mx-auto">
          {STEP_LABELS.map((label, i) => {
            const isActive = i === step
            const isCompleted = i < step
            return (
              <div key={label} className="flex items-center gap-1">
                {i > 0 && (
                  <div className={`w-3 h-px ${isCompleted ? 'bg-sky-500/40' : 'bg-navy-700'}`} />
                )}
                <div className="flex flex-col items-center gap-1">
                  <div
                    className={`
                      w-2.5 h-2.5 rounded-full transition-all duration-300
                      ${isActive
                        ? 'bg-sky-400 ring-2 ring-sky-400/20'
                        : isCompleted
                          ? 'bg-sky-500/50'
                          : 'bg-navy-700'
                      }
                    `}
                  />
                  <span className={`text-[8px] font-medium tracking-wider ${
                    isActive ? 'text-sky-400' : isCompleted ? 'text-navy-500' : 'text-navy-600'
                  }`}>
                    {label}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Step Content */}
      <div className="flex-1 px-4 py-4 overflow-y-auto">
        <div className="max-w-3xl mx-auto">
          {step === 0 && (
            <Step1_AdminUser onCreated={handleAdminCreated} />
          )}
          {step === 1 && (
            <LoginStep
              username={adminUsername}
              onLogin={handleLogin}
              error={loginError}
              loading={loggingIn}
            />
          )}
          {step === 2 && (
            <Step0_Discovery onDiscovered={handleDiscovered} />
          )}
          {step === 3 && (
            <Step2_DeviceMode
              value={state.deviceMode}
              onChange={(mode) => setState((prev) => ({ ...prev, deviceMode: mode }))}
            />
          )}
          {step === 4 && (
            <Step3_BayAssignment
              bays={state.discoveredBays}
              disks={state.discoveredDisks}
              assignments={state.bayAssignments}
              onChange={(a) => setState((prev) => ({ ...prev, bayAssignments: a }))}
            />
          )}
          {step === 5 && (
            <Step4_RaidConfig
              bays={state.discoveredBays}
              disks={state.discoveredDisks}
              bayAssignments={state.bayAssignments}
              selectedDisks={state.selectedDisks}
              onSelectDisks={(disks) => setState((prev) => ({ ...prev, selectedDisks: disks }))}
              value={state.raidLevel}
              onChange={(level) => setState((prev) => ({ ...prev, raidLevel: level }))}
            />
          )}
          {step === 6 && (
            <Step5_Encryption
              value={state.encryption}
              onChange={(enabled) => setState((prev) => ({ ...prev, encryption: enabled }))}
            />
          )}
          {step === 7 && (
            <Step6_Summary
              state={state}
              username={adminUsername}
              onInitialize={handleInitialize}
              onBack={goBack}
            />
          )}
        </div>
      </div>

      {/* Bottom Navigation */}
      {(showBack || showNext || showSkip) && step !== TOTAL_STEPS - 1 && (
        <div className="border-t border-navy-800/50 px-4 py-4">
          <div className="flex items-center justify-between max-w-3xl mx-auto">
            <div>
              {showBack && (
                <button
                  type="button"
                  onClick={goBack}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border bg-navy-800 hover:bg-navy-700/50 border-navy-700/50 text-gray-300 transition-all duration-200"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  Back
                </button>
              )}
            </div>

            <div className="flex items-center gap-3">
              {showSkip && (
                <button
                  type="button"
                  onClick={handleSkip}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border bg-transparent hover:bg-navy-800/50 border-transparent text-navy-400 hover:text-gray-200 transition-all duration-200"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  Skip to Dashboard
                </button>
              )}
              {showNext && (
                <button
                  type="button"
                  onClick={goNext}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border bg-sky-500/10 hover:bg-sky-500/20 border-sky-500/20 text-sky-400 transition-all duration-200"
                >
                  Next
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Inline login step (auto-login after admin creation)
// ---------------------------------------------------------------------------

interface LoginStepProps {
  username: string
  onLogin: (password: string) => void
  error: string | null
  loading: boolean
}

function LoginStep({ username, onLogin, error, loading }: LoginStepProps) {
  const [password, setPassword] = useState('')

  return (
    <div className="text-center">
      <h2 className="text-xl font-semibold text-gray-100 mb-2">Sign In</h2>
      <p className="text-sm text-navy-400 mb-8">
        Sign in as <span className="text-sky-400 font-medium">{username}</span> to continue setup
      </p>

      <div className="max-w-sm mx-auto space-y-4">
        <div>
          <label className="block text-xs font-medium text-navy-400 mb-1.5 text-left">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && password && onLogin(password)}
            className="w-full px-3 py-2 text-sm bg-navy-800 border border-navy-700/50 rounded-lg text-gray-100 placeholder-navy-500 focus:outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/20"
            placeholder="Enter your password"
            autoFocus
          />
        </div>

        {error && (
          <p className="text-xs text-red-400">{error}</p>
        )}

        <button
          type="button"
          onClick={() => onLogin(password)}
          disabled={!password || loading}
          className="w-full py-2 text-sm font-medium rounded-lg bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/20 text-sky-400 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200"
        >
          {loading ? 'Signing in...' : 'Continue'}
        </button>
      </div>
    </div>
  )
}
