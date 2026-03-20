// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type UpdateCheckResult, type UpdateSettings } from '../api'
import { Card, PageHeader, Spinner, Button, Badge, Select } from '../components/ui'
import { useToast } from '../hooks/useToast'

export default function Update() {
  const [loading, setLoading] = useState(true)
  const [checking, setChecking] = useState(false)
  const [applying, setApplying] = useState(false)
  const [rollingBack, setRollingBack] = useState(false)
  const [checkResult, setCheckResult] = useState<UpdateCheckResult | null>(null)
  const [settings, setSettings] = useState<UpdateSettings | null>(null)
  const [showConfirmApply, setShowConfirmApply] = useState(false)
  const [showConfirmRollback, setShowConfirmRollback] = useState(false)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const settingsRes = await api.getUpdateSettings()
      setSettings(settingsRes.settings)
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleCheck = async () => {
    setChecking(true)
    try {
      const result = await api.checkForUpdate()
      setCheckResult(result)
      if (result.update_available) {
        toast.success(`Update available: v${result.available?.version}`)
      } else {
        toast.success('No update available')
      }
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setChecking(false)
    }
  }

  const handleApply = async () => {
    setShowConfirmApply(false)
    setApplying(true)
    try {
      const res = await api.applyUpdate()
      toast.success(res.message || 'Update initiated')
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setApplying(false)
    }
  }

  const handleRollback = async () => {
    setShowConfirmRollback(false)
    setRollingBack(true)
    try {
      const res = await api.rollbackUpdate()
      toast.success(res.message || 'Rollback complete')
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setRollingBack(false)
    }
  }

  const handleSettingsChange = async (field: string, value: string | boolean | number) => {
    if (!settings) return
    const updated = { ...settings, [field]: value }
    try {
      const res = await api.setUpdateSettings({ [field]: value })
      setSettings(res.settings)
      toast.success('Update settings saved')
    } catch (e: unknown) {
      toast.error((e as Error).message)
      setSettings(updated) // revert optimistic
    }
  }

  if (loading) return <Spinner label="Loading update settings..." />

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const formatDate = (iso: string): string => {
    try {
      return new Date(iso).toLocaleString()
    } catch {
      return iso
    }
  }

  return (
    <div className="space-y-6 stagger-children">
      <PageHeader title="Firmware Update" />

      {/* Current Version */}
      <Card title="Current Firmware">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center gap-4">
            <span className="w-32 text-sm text-navy-400 shrink-0">Version</span>
            <span className="text-sm font-mono text-gray-200">v{checkResult?.current_version ?? '---'}</span>
          </div>
          {settings?.last_check && (
            <div className="flex items-center gap-4">
              <span className="w-32 text-sm text-navy-400 shrink-0">Last Check</span>
              <span className="text-sm font-mono text-navy-300">{formatDate(settings.last_check)}</span>
            </div>
          )}
        </div>
        <div className="flex gap-3 mt-4">
          <Button onClick={handleCheck} disabled={checking}>
            {checking ? 'Checking...' : 'Check for Updates'}
          </Button>
          <Button variant="secondary" onClick={() => setShowConfirmRollback(true)} disabled={rollingBack}>
            {rollingBack ? 'Rolling back...' : 'Rollback'}
          </Button>
        </div>
      </Card>

      {/* Update Available */}
      {checkResult?.update_available && checkResult.available && (
        <Card title="Update Available">
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4 mb-4">
            <div className="flex items-center gap-3 mb-3">
              <span className="text-lg font-mono font-semibold text-emerald-400">
                v{checkResult.available.version}
              </span>
              <Badge variant={checkResult.available.prerelease ? 'warning' : 'success'}>
                {checkResult.available.prerelease ? 'BETA' : 'STABLE'}
              </Badge>
              <span className="text-sm text-navy-400">
                {formatBytes(checkResult.available.size_bytes)}
              </span>
            </div>

            {checkResult.available.published_at && (
              <div className="text-xs text-navy-400 mb-3">
                Published: {formatDate(checkResult.available.published_at)}
              </div>
            )}

            {checkResult.available.release_notes && (
              <div className="mt-3">
                <h4 className="text-xs text-navy-400 uppercase tracking-wider font-medium mb-2">Release Notes</h4>
                <div className="bg-navy-950/50 rounded-lg p-3 text-sm text-navy-300 font-mono whitespace-pre-wrap max-h-64 overflow-y-auto">
                  {checkResult.available.release_notes}
                </div>
              </div>
            )}

            {checkResult.available.sha256 && (
              <div className="mt-3 flex items-center gap-2">
                <span className="text-[10px] text-navy-500 uppercase tracking-wider">SHA-256:</span>
                <span className="text-[10px] font-mono text-navy-400 break-all">{checkResult.available.sha256}</span>
              </div>
            )}
          </div>

          <div className="flex gap-3">
            <Button onClick={() => setShowConfirmApply(true)} disabled={applying}>
              {applying ? 'Applying...' : 'Apply Update'}
            </Button>
          </div>
        </Card>
      )}

      {checkResult && !checkResult.update_available && (
        <Card title="Status">
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-emerald-400" />
            <span className="text-sm text-navy-300">Your firmware is up to date.</span>
          </div>
        </Card>
      )}

      {/* Update Settings */}
      {settings && (
        <Card title="Update Settings">
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Select
                  label="Update Channel"
                  value={settings.update_channel}
                  onChange={(e) => handleSettingsChange('update_channel', e.target.value)}
                  options={[
                    { value: 'stable', label: 'Stable -- Production releases only' },
                    { value: 'beta', label: 'Beta -- Includes pre-release builds' },
                  ]}
                />
              </div>
              <div>
                <Select
                  label="Check Interval"
                  value={String(settings.check_interval_hours)}
                  onChange={(e) => handleSettingsChange('check_interval_hours', parseInt(e.target.value, 10))}
                  options={[
                    { value: '1', label: 'Every hour' },
                    { value: '6', label: 'Every 6 hours' },
                    { value: '12', label: 'Every 12 hours' },
                    { value: '24', label: 'Every 24 hours' },
                    { value: '48', label: 'Every 48 hours' },
                    { value: '168', label: 'Every week' },
                  ]}
                />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => handleSettingsChange('auto_check', !settings.auto_check)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  settings.auto_check ? 'bg-emerald-500' : 'bg-navy-700'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    settings.auto_check ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
              <span className="text-sm text-navy-300">Automatically check for updates</span>
            </div>
            <div>
              <label className="block text-xs text-navy-400 uppercase tracking-wider font-medium mb-1">
                Update URL
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={settings.update_url}
                  onChange={(e) => setSettings({ ...settings, update_url: e.target.value })}
                  onBlur={(e) => handleSettingsChange('update_url', e.target.value)}
                  className="flex-1 bg-navy-900/50 border border-navy-700/50 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:ring-1 focus:ring-emerald-500/50 focus:border-emerald-500/50"
                />
              </div>
              <p className="text-[10px] text-navy-500 mt-1">
                GitHub releases API endpoint. Only change if using a private mirror.
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Confirm Apply Modal */}
      {showConfirmApply && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-navy-900 border border-navy-700/50 rounded-xl p-6 max-w-md mx-4 shadow-2xl">
            <h3 className="text-lg font-semibold text-gray-200 mb-3">Confirm Firmware Update</h3>
            <p className="text-sm text-navy-400 mb-2">
              This will download and apply the firmware update. The service will restart automatically.
            </p>
            <p className="text-sm text-amber-400 mb-4">
              A backup of the current firmware will be created. If the update fails, use the Rollback button.
            </p>
            <div className="flex gap-2">
              <Button onClick={handleApply}>Apply Update</Button>
              <Button variant="secondary" onClick={() => setShowConfirmApply(false)}>Cancel</Button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Rollback Modal */}
      {showConfirmRollback && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-navy-900 border border-navy-700/50 rounded-xl p-6 max-w-md mx-4 shadow-2xl">
            <h3 className="text-lg font-semibold text-gray-200 mb-3">Confirm Rollback</h3>
            <p className="text-sm text-navy-400 mb-2">
              This will revert to the previous firmware version. The service will restart.
            </p>
            <p className="text-sm text-red-400 mb-4">
              Only a backup from the last update is available. If no backup exists, rollback will fail.
            </p>
            <div className="flex gap-2">
              <Button variant="danger" onClick={handleRollback}>Rollback</Button>
              <Button variant="secondary" onClick={() => setShowConfirmRollback(false)}>Cancel</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
