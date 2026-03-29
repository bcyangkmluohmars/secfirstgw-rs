// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import {
  RefreshCw,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronRight,
  Users,
  LogIn,
  LogOut,
  Zap,
} from 'lucide-react'
import {
  PageHeader,
  Spinner,
  Card,
  Button,
  Badge,
  Input,
  Select,
  ConfirmDialog,
} from '../../components/ui'
import { api } from '../../api'
import type { AdStatus, AdSyncResult } from '../../types'

const SYNC_INTERVALS = [
  { value: '15', label: 'Every 15 minutes' },
  { value: '30', label: 'Every 30 minutes' },
  { value: '60', label: 'Every 1 hour' },
  { value: '240', label: 'Every 4 hours' },
  { value: '720', label: 'Every 12 hours' },
  { value: '1440', label: 'Every 24 hours' },
]

type TestState = 'idle' | 'testing' | 'success' | 'error'

interface FormState {
  server: string
  domain: string
  base_dn: string
  bind_user: string
  bind_password: string
  user_filter: string
  group_filter: string
  sync_interval: string
}

const emptyForm: FormState = {
  server: '',
  domain: '',
  base_dn: '',
  bind_user: '',
  bind_password: '',
  user_filter: '(&(objectClass=user)(objectCategory=person))',
  group_filter: '(objectClass=group)',
  sync_interval: '60',
}

export default function ActiveDirectory() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [status, setStatus] = useState<AdStatus | null>(null)
  const [testState, setTestState] = useState<TestState>('idle')
  const [testMessage, setTestMessage] = useState('')
  const [joining, setJoining] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [syncResult, setSyncResult] = useState<AdSyncResult | null>(null)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [showLeaveConfirm, setShowLeaveConfirm] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saveSuccess, setSaveSuccess] = useState(false)

  const loadConfig = useCallback(async () => {
    try {
      const [config, adStatus] = await Promise.all([
        api.getAdConfig(),
        api.getAdStatus(),
      ])
      setForm({
        server: config.server ?? '',
        domain: config.domain ?? '',
        base_dn: config.base_dn ?? '',
        bind_user: config.bind_user ?? '',
        bind_password: '',
        user_filter: config.user_filter || '(&(objectClass=user)(objectCategory=person))',
        group_filter: config.group_filter || '(objectClass=group)',
        sync_interval: String(config.sync_interval ?? 60),
      })
      setStatus(adStatus)
    } catch {
      // Config may not exist yet -- use defaults
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadConfig()
  }, [loadConfig])

  const updateField = (field: keyof FormState, value: string) => {
    setForm((prev) => ({ ...prev, [field]: value }))
    setSaveSuccess(false)
  }

  const handleSave = async () => {
    setError(null)
    setSaving(true)
    setSaveSuccess(false)
    try {
      await api.saveAdConfig({
        server: form.server,
        domain: form.domain,
        base_dn: form.base_dn,
        bind_user: form.bind_user,
        bind_password: form.bind_password || undefined,
        user_filter: form.user_filter || undefined,
        group_filter: form.group_filter || undefined,
        sync_interval: parseInt(form.sync_interval, 10) || undefined,
      })
      setSaveSuccess(true)
      // Re-fetch status
      const adStatus = await api.getAdStatus()
      setStatus(adStatus)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save configuration')
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    setTestState('testing')
    setTestMessage('')
    try {
      const result = await api.testAdConnection()
      if (result.connected) {
        setTestState('success')
        setTestMessage(result.message ?? 'Connection successful')
      } else {
        setTestState('error')
        setTestMessage(result.error ?? 'Connection failed')
      }
    } catch (e) {
      setTestState('error')
      setTestMessage(e instanceof Error ? e.message : 'Test failed')
    }
  }

  const handleJoin = async () => {
    setJoining(true)
    setError(null)
    try {
      const result = await api.joinAdDomain()
      // Refresh status
      const adStatus = await api.getAdStatus()
      setStatus(adStatus)
      setError(null)
      setTestMessage(result.message ?? 'Joined domain successfully')
      setTestState('success')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Domain join failed')
    } finally {
      setJoining(false)
    }
  }

  const handleLeave = async () => {
    setLeaving(true)
    setError(null)
    try {
      await api.leaveAdDomain()
      const adStatus = await api.getAdStatus()
      setStatus(adStatus)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Domain leave failed')
    } finally {
      setLeaving(false)
    }
  }

  const handleSync = async () => {
    setSyncing(true)
    setSyncResult(null)
    try {
      const result = await api.syncAdUsers()
      setSyncResult(result)
      // Refresh status
      const adStatus = await api.getAdStatus()
      setStatus(adStatus)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Sync failed')
    } finally {
      setSyncing(false)
    }
  }

  if (loading) return <Spinner label="Loading AD configuration..." />

  const isJoined = status?.joined ?? false

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        title="Active Directory"
        subtitle={<p className="text-sm text-navy-400">Integrate with an on-premises AD/LDAP server for user and group sync</p>}
      />

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Status Card */}
      <Card title="Domain Status">
        <div className="flex items-center gap-6 flex-wrap">
          <div className="flex items-center gap-2">
            {isJoined ? (
              <CheckCircle className="w-5 h-5 text-emerald-400" />
            ) : (
              <XCircle className="w-5 h-5 text-navy-500" />
            )}
            <span className="text-sm text-gray-300">
              {isJoined ? 'Joined to domain' : 'Not joined'}
            </span>
            {isJoined && status?.domain && (
              <Badge variant="success">{status.domain}</Badge>
            )}
          </div>
          {status?.last_sync && (
            <div className="text-xs text-navy-400">
              Last sync: {new Date(status.last_sync).toLocaleString()}
            </div>
          )}
          {isJoined && (
            <div className="flex items-center gap-4 text-xs text-navy-400">
              <span className="flex items-center gap-1">
                <Users className="w-3.5 h-3.5" />
                {status?.user_count ?? 0} users
              </span>
              <span className="flex items-center gap-1">
                <Users className="w-3.5 h-3.5" />
                {status?.group_count ?? 0} groups
              </span>
            </div>
          )}
        </div>
      </Card>

      {/* Configuration Form */}
      <Card title="AD/LDAP Configuration">
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="AD Server"
              placeholder="dc01.corp.local"
              value={form.server}
              onChange={(e) => updateField('server', e.target.value)}
            />
            <Input
              label="Domain"
              placeholder="corp.local"
              value={form.domain}
              onChange={(e) => updateField('domain', e.target.value)}
            />
          </div>

          <Input
            label="Base DN"
            placeholder="DC=corp,DC=local"
            value={form.base_dn}
            onChange={(e) => updateField('base_dn', e.target.value)}
            mono
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Bind User (DN or UPN)"
              placeholder="CN=svc-nas,OU=Services,DC=corp,DC=local"
              value={form.bind_user}
              onChange={(e) => updateField('bind_user', e.target.value)}
              mono
            />
            <Input
              label="Bind Password"
              type="password"
              placeholder={form.bind_password ? '' : 'Leave empty to keep current'}
              value={form.bind_password}
              onChange={(e) => updateField('bind_password', e.target.value)}
            />
          </div>

          {/* Advanced Settings (collapsible) */}
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-1.5 text-xs text-navy-400 hover:text-gray-300 transition-colors"
          >
            {showAdvanced ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
            Advanced Settings
          </button>

          {showAdvanced && (
            <div className="space-y-4 pl-4 border-l border-navy-800/50">
              <Input
                label="User Filter (LDAP)"
                placeholder="(&(objectClass=user)(objectCategory=person))"
                value={form.user_filter}
                onChange={(e) => updateField('user_filter', e.target.value)}
                mono
              />
              <Input
                label="Group Filter (LDAP)"
                placeholder="(objectClass=group)"
                value={form.group_filter}
                onChange={(e) => updateField('group_filter', e.target.value)}
                mono
              />
              <Select
                label="Sync Interval"
                options={SYNC_INTERVALS}
                value={form.sync_interval}
                onChange={(e) => updateField('sync_interval', e.target.value)}
              />
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center gap-3 pt-2 border-t border-navy-800/50">
            <Button
              variant="primary"
              onClick={handleSave}
              loading={saving}
              disabled={!form.server || !form.domain}
            >
              Save Configuration
            </Button>

            {saveSuccess && (
              <span className="text-xs text-emerald-400 flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" />
                Saved
              </span>
            )}

            <Button
              variant="secondary"
              onClick={handleTest}
              loading={testState === 'testing'}
              disabled={!form.server || !form.bind_user}
            >
              <span className="flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5" />
                Test Connection
              </span>
            </Button>

            {testState === 'success' && (
              <span className="text-xs text-emerald-400 flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" />
                {testMessage}
              </span>
            )}
            {testState === 'error' && (
              <span className="text-xs text-red-400 flex items-center gap-1">
                <XCircle className="w-3.5 h-3.5" />
                {testMessage}
              </span>
            )}
          </div>
        </div>
      </Card>

      {/* Domain Operations */}
      <Card title="Domain Operations">
        <div className="space-y-4">
          {!isJoined ? (
            <div className="flex items-start gap-4">
              <div className="flex-1">
                <p className="text-sm text-gray-300 mb-1">Join AD Domain</p>
                <p className="text-xs text-navy-400">
                  Join the configured Active Directory domain. This will configure Samba
                  for AD authentication and enable winbind for user/group resolution.
                  Ensure the configuration above is saved and the connection test passes first.
                </p>
              </div>
              <Button
                variant="primary"
                onClick={handleJoin}
                loading={joining}
                disabled={!form.server || !form.domain || !form.bind_user}
              >
                <span className="flex items-center gap-1.5">
                  <LogIn className="w-3.5 h-3.5" />
                  Join Domain
                </span>
              </Button>
            </div>
          ) : (
            <>
              <div className="flex items-start gap-4">
                <div className="flex-1">
                  <p className="text-sm text-gray-300 mb-1">Leave AD Domain</p>
                  <p className="text-xs text-navy-400">
                    Leave the Active Directory domain and revert Samba to standalone mode.
                    AD users will no longer be able to access shares.
                  </p>
                </div>
                <Button
                  variant="danger"
                  onClick={() => setShowLeaveConfirm(true)}
                  loading={leaving}
                >
                  <span className="flex items-center gap-1.5">
                    <LogOut className="w-3.5 h-3.5" />
                    Leave Domain
                  </span>
                </Button>
              </div>

              <div className="border-t border-navy-800/50 pt-4">
                <div className="flex items-start gap-4">
                  <div className="flex-1">
                    <p className="text-sm text-gray-300 mb-1">Sync Users &amp; Groups</p>
                    <p className="text-xs text-navy-400">
                      Manually trigger a sync of users and groups from Active Directory.
                      This is also done automatically based on the configured sync interval.
                    </p>
                  </div>
                  <Button
                    variant="secondary"
                    onClick={handleSync}
                    loading={syncing}
                  >
                    <span className="flex items-center gap-1.5">
                      <RefreshCw className="w-3.5 h-3.5" />
                      Sync Now
                    </span>
                  </Button>
                </div>

                {syncResult && (
                  <div className="mt-4 bg-navy-800/50 rounded-lg p-4 space-y-3">
                    <div className="flex items-center gap-4 text-sm">
                      <Badge variant="info">{syncResult.user_count} users</Badge>
                      <Badge variant="info">{syncResult.group_count} groups</Badge>
                      <span className="text-xs text-navy-400">
                        Synced at {new Date(syncResult.synced_at).toLocaleString()}
                      </span>
                    </div>

                    {syncResult.users.length > 0 && (
                      <div>
                        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-1.5">
                          Users
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {syncResult.users.slice(0, 50).map((u) => (
                            <span
                              key={u}
                              className="text-xs bg-navy-700/50 text-gray-300 px-2 py-0.5 rounded"
                            >
                              {u}
                            </span>
                          ))}
                          {syncResult.users.length > 50 && (
                            <span className="text-xs text-navy-500">
                              +{syncResult.users.length - 50} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                    {syncResult.groups.length > 0 && (
                      <div>
                        <p className="text-[11px] font-medium text-navy-400 uppercase tracking-wider mb-1.5">
                          Groups
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {syncResult.groups.slice(0, 50).map((g) => (
                            <span
                              key={g}
                              className="text-xs bg-navy-700/50 text-gray-300 px-2 py-0.5 rounded"
                            >
                              {g}
                            </span>
                          ))}
                          {syncResult.groups.length > 50 && (
                            <span className="text-xs text-navy-500">
                              +{syncResult.groups.length - 50} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </Card>

      {/* Leave Domain Confirmation */}
      <ConfirmDialog
        open={showLeaveConfirm}
        onClose={() => setShowLeaveConfirm(false)}
        onConfirm={handleLeave}
        title="Leave AD Domain"
        message="Are you sure you want to leave the Active Directory domain? AD users will lose access to all SMB shares. This action cannot be undone."
        confirmLabel="Leave Domain"
        variant="danger"
        loading={leaving}
      />
    </div>
  )
}
