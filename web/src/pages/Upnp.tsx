// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type UpnpSettings, type UpnpMapping } from '../api'
import { Card, PageHeader, Spinner, Button, Input, Badge } from '../components/ui'
import { useToast } from '../hooks/useToast'

export default function Upnp() {
  const [settings, setSettings] = useState<UpnpSettings | null>(null)
  const [mappings, setMappings] = useState<UpnpMapping[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [portMin, setPortMin] = useState('')
  const [portMax, setPortMax] = useState('')
  const [maxPerIp, setMaxPerIp] = useState('')
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const [settingsRes, mappingsRes] = await Promise.all([
        api.getUpnpSettings(),
        api.getUpnpMappings(),
      ])
      setSettings(settingsRes.upnp)
      setPortMin(String(settingsRes.upnp.port_min))
      setPortMax(String(settingsRes.upnp.port_max))
      setMaxPerIp(String(settingsRes.upnp.max_per_ip))
      setMappings(mappingsRes.mappings ?? [])
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleToggle = async () => {
    if (!settings) return
    setSaving(true)
    try {
      const res = await api.setUpnpSettings({ enabled: !settings.enabled })
      setSettings(res.upnp)
      toast.success(`UPnP ${res.upnp.enabled ? 'enabled' : 'disabled'} (restart required)`)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setSaving(false) }
  }

  const handleSaveSettings = async () => {
    setSaving(true)
    try {
      const res = await api.setUpnpSettings({
        port_min: parseInt(portMin, 10),
        port_max: parseInt(portMax, 10),
        max_per_ip: parseInt(maxPerIp, 10),
      })
      setSettings(res.upnp)
      setPortMin(String(res.upnp.port_min))
      setPortMax(String(res.upnp.port_max))
      setMaxPerIp(String(res.upnp.max_per_ip))
      toast.success('UPnP settings saved')
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setSaving(false) }
  }

  const handleDeleteMapping = async (id: number) => {
    try {
      await api.deleteUpnpMapping(id)
      setMappings(prev => prev.filter(m => m.id !== id))
      toast.success('Mapping removed')
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  if (loading) return <Spinner label="Loading UPnP settings..." />

  const formatTtl = (seconds: number): string => {
    if (seconds < 60) return `${seconds}s`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
  }

  const formatExpiry = (expiresAt: string): string => {
    const now = new Date()
    const expires = new Date(expiresAt + 'Z')
    const diff = Math.max(0, Math.floor((expires.getTime() - now.getTime()) / 1000))
    if (diff === 0) return 'expired'
    return formatTtl(diff) + ' remaining'
  }

  return (
    <div className="space-y-6 stagger-children">
      <PageHeader title="UPnP / NAT-PMP" />

      {/* Security Warning */}
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <div>
            <p className="text-sm font-medium text-amber-300">Security Notice</p>
            <p className="text-xs text-amber-400/80 mt-1">
              UPnP allows LAN clients to automatically open ports on the gateway. This is a known security risk
              -- malware can use it to expose internal services. Only enable if required by specific applications
              (gaming, VoIP, etc.). Mappings are restricted to the configured port range and per-IP limits.
            </p>
          </div>
        </div>
      </div>

      {/* Enable/Disable */}
      <Card title="Service Status">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <Badge variant={settings?.enabled ? 'success' : 'warning'}>
                {settings?.enabled ? 'ENABLED' : 'DISABLED'}
              </Badge>
              <span className="text-sm text-navy-400">
                {settings?.enabled
                  ? 'LAN clients can request port mappings'
                  : 'No UPnP/NAT-PMP services running'}
              </span>
            </div>
            {settings?.enabled && (
              <p className="text-xs text-navy-500 mt-2">
                SSDP on UDP 1900, NAT-PMP on UDP 5351, HTTP control on TCP 5000 (LAN only)
              </p>
            )}
          </div>
          <Button
            variant={settings?.enabled ? 'danger' : 'primary'}
            size="sm"
            onClick={handleToggle}
            disabled={saving}
          >
            {settings?.enabled ? 'Disable' : 'Enable'}
          </Button>
        </div>
      </Card>

      {/* Settings */}
      <Card title="Port Mapping Rules">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Input
            label="Allowed Port Range (Min)"
            type="number"
            mono
            value={portMin}
            onChange={(e) => setPortMin(e.target.value)}
          />
          <Input
            label="Allowed Port Range (Max)"
            type="number"
            mono
            value={portMax}
            onChange={(e) => setPortMax(e.target.value)}
          />
          <Input
            label="Max Mappings per IP"
            type="number"
            mono
            value={maxPerIp}
            onChange={(e) => setMaxPerIp(e.target.value)}
          />
        </div>
        <p className="text-xs text-navy-500 mt-3">
          Only external ports within the configured range will be allowed.
          Per-IP limits prevent a single client from exhausting all available ports.
        </p>
        <div className="mt-4">
          <Button size="sm" onClick={handleSaveSettings} disabled={saving}>
            Save Settings
          </Button>
        </div>
      </Card>

      {/* Active Mappings */}
      <Card title="Active Mappings" actions={
        <Button size="sm" variant="secondary" onClick={load}>Refresh</Button>
      }>
        {mappings.length === 0 ? (
          <p className="text-sm text-navy-500">No active port mappings</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-navy-800/50">
                  {['Protocol', 'External Port', 'Internal', 'Client IP', 'Description', 'TTL', 'Expires', ''].map((h) => (
                    <th key={h} className="text-left px-4 py-2 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {mappings.map((m) => (
                  <tr key={m.id} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                    <td className="px-4 py-3">
                      <Badge variant={m.protocol === 'tcp' ? 'info' : 'warning'}>
                        {m.protocol.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-200">{m.external_port}</td>
                    <td className="px-4 py-3 font-mono text-gray-200">
                      {m.internal_ip}:{m.internal_port}
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-300">{m.client_ip}</td>
                    <td className="px-4 py-3 text-navy-300">{m.description || '---'}</td>
                    <td className="px-4 py-3 text-xs text-navy-400">{formatTtl(m.ttl_seconds)}</td>
                    <td className="px-4 py-3 text-xs text-navy-400">{formatExpiry(m.expires_at)}</td>
                    <td className="px-4 py-3">
                      <Button variant="danger" size="sm" onClick={() => handleDeleteMapping(m.id)}>
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
