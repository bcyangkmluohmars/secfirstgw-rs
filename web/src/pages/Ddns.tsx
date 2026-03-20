// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type DdnsConfig, type DdnsConfigCreate, type DdnsProvider } from '../api'
import { PageHeader, Card, Button, Badge, Toggle, Modal, Input, Select, EmptyState, Spinner } from '../components/ui'
import { useToast } from '../hooks/useToast'

const PROVIDERS: { value: DdnsProvider; label: string; description: string }[] = [
  { value: 'dyndns2', label: 'DynDNS2', description: 'DynDNS, No-IP, and compatible' },
  { value: 'duckdns', label: 'DuckDNS', description: 'Free dynamic DNS' },
  { value: 'cloudflare', label: 'Cloudflare', description: 'Cloudflare DNS API' },
]

const INTERVAL_OPTIONS = [
  { value: '60', label: '1 minute' },
  { value: '300', label: '5 minutes' },
  { value: '600', label: '10 minutes' },
  { value: '900', label: '15 minutes' },
  { value: '1800', label: '30 minutes' },
  { value: '3600', label: '1 hour' },
  { value: '7200', label: '2 hours' },
  { value: '21600', label: '6 hours' },
  { value: '43200', label: '12 hours' },
  { value: '86400', label: '24 hours' },
]

interface DdnsFormState {
  hostname: string
  provider: DdnsProvider
  server: string
  username: string
  password: string
  wan_interface: string
  update_interval_secs: string
  enabled: boolean
}

const emptyForm: DdnsFormState = {
  hostname: '',
  provider: 'dyndns2',
  server: '',
  username: '',
  password: '',
  wan_interface: 'eth8',
  update_interval_secs: '300',
  enabled: true,
}

function configToForm(cfg: DdnsConfig): DdnsFormState {
  return {
    hostname: cfg.hostname,
    provider: (cfg.provider as DdnsProvider) || 'dyndns2',
    server: cfg.server ?? '',
    username: cfg.username ?? '',
    password: '', // never pre-fill credentials
    wan_interface: cfg.wan_interface,
    update_interval_secs: String(cfg.update_interval_secs),
    enabled: cfg.enabled,
  }
}

function formToPayload(form: DdnsFormState, isEdit: boolean): DdnsConfigCreate {
  const payload: DdnsConfigCreate = {
    hostname: form.hostname.trim(),
    provider: form.provider,
    wan_interface: form.wan_interface.trim(),
    update_interval_secs: Number(form.update_interval_secs),
    enabled: form.enabled,
  }
  if (form.server.trim()) payload.server = form.server.trim()
  if (form.username.trim()) payload.username = form.username.trim()
  // Only send password if set (on edit, empty means keep current)
  if (form.password || !isEdit) payload.password = form.password
  return payload
}

function providerLabel(provider: string): string {
  return PROVIDERS.find((p) => p.value === provider)?.label ?? provider
}

function statusBadge(status: string | null): { variant: 'success' | 'error' | 'neutral'; text: string } {
  if (!status) return { variant: 'neutral', text: 'Never updated' }
  if (status.startsWith('ok:')) return { variant: 'success', text: status.replace('ok: ', '') }
  if (status.startsWith('error:')) return { variant: 'error', text: status.replace('error: ', '') }
  return { variant: 'neutral', text: status }
}

function formatTimestamp(ts: string | null): string {
  if (!ts) return 'Never'
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return ts
    return d.toLocaleString()
  } catch {
    return ts
  }
}

function usernameLabel(provider: DdnsProvider): string {
  switch (provider) {
    case 'dyndns2': return 'Username'
    case 'duckdns': return 'Username (optional)'
    case 'cloudflare': return 'Zone ID'
  }
}

function passwordLabel(provider: DdnsProvider): string {
  switch (provider) {
    case 'dyndns2': return 'Password'
    case 'duckdns': return 'Token'
    case 'cloudflare': return 'API Token'
  }
}

function usernameRequired(provider: DdnsProvider): boolean {
  return provider === 'dyndns2' || provider === 'cloudflare'
}

export default function Ddns() {
  const [configs, setConfigs] = useState<DdnsConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [form, setForm] = useState<DdnsFormState>({ ...emptyForm })
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null)
  const [updating, setUpdating] = useState<number | null>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const res = await api.getDdnsConfigs()
      setConfigs(res.configs ?? [])
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const openCreate = () => {
    setForm({ ...emptyForm })
    setEditId(null)
    setShowForm(true)
  }

  const openEdit = (cfg: DdnsConfig) => {
    setForm(configToForm(cfg))
    setEditId(cfg.id)
    setShowForm(true)
  }

  const handleSave = async () => {
    if (!form.hostname.trim()) { toast.error('Hostname is required'); return }
    if (!form.hostname.includes('.')) { toast.error('Hostname must be a fully qualified domain name'); return }
    if (usernameRequired(form.provider) && !form.username.trim()) {
      toast.error(`${usernameLabel(form.provider)} is required for ${providerLabel(form.provider)}`)
      return
    }
    if (!editId && !form.password) {
      toast.error(`${passwordLabel(form.provider)} is required`)
      return
    }
    if (!form.wan_interface.trim()) { toast.error('WAN interface is required'); return }

    try {
      if (editId) {
        await api.updateDdnsConfig(editId, formToPayload(form, true))
        toast.success('DDNS config updated')
      } else {
        await api.createDdnsConfig(formToPayload(form, false))
        toast.success('DDNS config created')
      }
      setShowForm(false)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.deleteDdnsConfig(id)
      toast.success('DDNS config deleted')
      setDeleteConfirm(null)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleForceUpdate = async (id: number) => {
    setUpdating(id)
    try {
      const res = await api.forceDdnsUpdate(id)
      if (res.result.success) {
        toast.success(`Updated to ${res.result.ip}: ${res.result.status}`)
      } else {
        toast.error(`Update failed: ${res.result.status}`)
      }
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setUpdating(null) }
  }

  if (loading) return <Spinner label="Loading DDNS configurations..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dynamic DNS"
        subtitle="Automatically update DNS records when your WAN IP changes"
        actions={<Button onClick={openCreate}>+ Add DDNS Config</Button>}
      />

      {/* Create / Edit Modal */}
      <Modal open={showForm} onClose={() => setShowForm(false)} title={editId ? 'Edit DDNS Config' : 'New DDNS Config'} size="lg">
        <div className="space-y-5">
          <Input
            label="Hostname"
            mono
            value={form.hostname}
            onChange={(e) => setForm({ ...form, hostname: e.target.value })}
            placeholder="myhost.example.com"
          />

          <div>
            <p className="text-[11px] text-navy-400 uppercase tracking-wider font-medium mb-2">Provider</p>
            <div className="grid grid-cols-3 gap-2">
              {PROVIDERS.map((p) => (
                <button
                  key={p.value}
                  onClick={() => setForm({ ...form, provider: p.value, server: '' })}
                  className={`p-3 rounded-lg border text-center transition-all ${
                    form.provider === p.value
                      ? 'bg-emerald-500/10 border-emerald-500/30'
                      : 'bg-navy-800/30 border-navy-700/30 hover:border-navy-600/50'
                  }`}
                >
                  <p className="text-sm font-medium text-gray-200">{p.label}</p>
                  <p className="text-[10px] text-navy-500 mt-0.5">{p.description}</p>
                </button>
              ))}
            </div>
          </div>

          {form.provider === 'dyndns2' && (
            <Input
              label="Server (optional)"
              mono
              value={form.server}
              onChange={(e) => setForm({ ...form, server: e.target.value })}
              placeholder="members.dyndns.org"
            />
          )}

          {(form.provider === 'dyndns2' || form.provider === 'cloudflare') && (
            <Input
              label={usernameLabel(form.provider)}
              mono
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              placeholder={form.provider === 'cloudflare' ? 'Zone ID from Cloudflare dashboard' : 'Username'}
            />
          )}

          <Input
            label={`${passwordLabel(form.provider)}${editId ? ' (leave empty to keep current)' : ''}`}
            type="password"
            mono
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            placeholder={passwordLabel(form.provider)}
          />

          <Input
            label="WAN Interface"
            mono
            value={form.wan_interface}
            onChange={(e) => setForm({ ...form, wan_interface: e.target.value })}
            placeholder="eth8"
          />

          <Select
            label="Check Interval"
            value={form.update_interval_secs}
            onChange={(e) => setForm({ ...form, update_interval_secs: e.target.value })}
            options={INTERVAL_OPTIONS}
          />

          <div className="border-t border-navy-800/30 pt-4">
            <Toggle checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} label="Enabled" />
          </div>

          <div className="flex gap-2 pt-2">
            <Button onClick={handleSave}>{editId ? 'Update' : 'Create Config'}</Button>
            <Button variant="secondary" onClick={() => setShowForm(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Delete confirmation */}
      {deleteConfirm !== null && (
        <Modal open onClose={() => setDeleteConfirm(null)} title="Delete DDNS Config">
          <p className="text-sm text-gray-300 mb-4">
            Are you sure you want to delete this DDNS configuration? DNS records will no longer be updated automatically.
          </p>
          <div className="flex gap-2">
            <Button variant="danger" onClick={() => handleDelete(deleteConfirm)}>Delete</Button>
            <Button variant="secondary" onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          </div>
        </Modal>
      )}

      {/* Config list */}
      {configs.length === 0 ? (
        <EmptyState
          icon={
            <svg className="w-12 h-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="9" /><ellipse cx="12" cy="12" rx="4" ry="9" /><line x1="3" y1="12" x2="21" y2="12" />
            </svg>
          }
          title="No DDNS configurations"
          description="Add a Dynamic DNS configuration to keep DNS records updated with your current WAN IP."
        />
      ) : (
        <div className="space-y-3 stagger-children">
          {configs.map((cfg) => {
            const st = statusBadge(cfg.last_status)
            return (
              <Card key={cfg.id} noPadding>
                <div className="flex items-center justify-between px-5 py-4">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-lg bg-navy-800/80 flex items-center justify-center">
                      <svg className={`w-5 h-5 ${cfg.enabled ? 'text-emerald-400' : 'text-navy-500'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="9" /><ellipse cx="12" cy="12" rx="4" ry="9" /><line x1="3" y1="12" x2="21" y2="12" />
                      </svg>
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-gray-200 font-mono">{cfg.hostname}</span>
                        <Badge variant={cfg.enabled ? 'success' : 'neutral'}>{cfg.enabled ? 'Active' : 'Disabled'}</Badge>
                        <Badge variant="neutral">{providerLabel(cfg.provider)}</Badge>
                        <Badge variant={st.variant}>{st.text}</Badge>
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-[11px] text-navy-400 font-mono">
                          IP: {cfg.last_ip ?? 'Unknown'}
                        </span>
                        <span className="text-[11px] text-navy-500">
                          Updated: {formatTimestamp(cfg.last_update)}
                        </span>
                        <span className="text-[11px] text-navy-500 font-mono">
                          {cfg.wan_interface}
                        </span>
                        <span className="text-[11px] text-navy-500">
                          every {INTERVAL_OPTIONS.find((o) => o.value === String(cfg.update_interval_secs))?.label ?? `${cfg.update_interval_secs}s`}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleForceUpdate(cfg.id)}
                      disabled={updating === cfg.id}
                    >
                      {updating === cfg.id ? 'Updating...' : 'Force Update'}
                    </Button>
                    <Button variant="secondary" size="sm" onClick={() => openEdit(cfg)}>Edit</Button>
                    <Button variant="danger" size="sm" onClick={() => setDeleteConfirm(cfg.id)}>Delete</Button>
                  </div>
                </div>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
