// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import { api, type QosRule, type QosInterfaceStats } from '../api'
import { Card, PageHeader, Spinner, Button, Badge, Modal, Input, Select, EmptyState } from '../components/ui'
import { useToast } from '../hooks/useToast'

const PRIORITIES = [
  { value: '1', label: '1 - Highest (VoIP/Gaming)' },
  { value: '2', label: '2 - High' },
  { value: '3', label: '3 - Normal+' },
  { value: '4', label: '4 - Normal' },
  { value: '5', label: '5 - Low+' },
  { value: '6', label: '6 - Low (Bulk)' },
  { value: '7', label: '7 - Lowest (Best-effort)' },
]

const PROTOCOLS = [
  { value: '', label: 'Any' },
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'icmp', label: 'ICMP' },
]

const DIRECTIONS = [
  { value: 'egress', label: 'Egress (Upload)' },
  { value: 'ingress', label: 'Ingress (Download)' },
]

function priorityBadge(p: number) {
  if (p <= 2) return <Badge variant="danger">P{p} High</Badge>
  if (p <= 4) return <Badge variant="warning">P{p} Normal</Badge>
  if (p <= 6) return <Badge variant="info">P{p} Low</Badge>
  return <Badge>P{p} Default</Badge>
}

function formatBandwidth(kbps: number): string {
  if (kbps >= 1000000) return `${(kbps / 1000000).toFixed(1)} Gbps`
  if (kbps >= 1000) return `${(kbps / 1000).toFixed(1)} Mbps`
  return `${kbps} Kbps`
}

function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GB`
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

interface RuleFormData {
  name: string
  interface: string
  direction: string
  bandwidth_kbps: string
  priority: string
  match_protocol: string
  match_port_min: string
  match_port_max: string
  match_ip: string
  match_dscp: string
  enabled: boolean
}

const emptyForm: RuleFormData = {
  name: '',
  interface: '',
  direction: 'egress',
  bandwidth_kbps: '10000',
  priority: '4',
  match_protocol: '',
  match_port_min: '',
  match_port_max: '',
  match_ip: '',
  match_dscp: '',
  enabled: true,
}

function ruleToForm(rule: QosRule): RuleFormData {
  return {
    name: rule.name,
    interface: rule.interface,
    direction: rule.direction,
    bandwidth_kbps: String(rule.bandwidth_kbps),
    priority: String(rule.priority),
    match_protocol: rule.match_protocol ?? '',
    match_port_min: rule.match_port_min != null ? String(rule.match_port_min) : '',
    match_port_max: rule.match_port_max != null ? String(rule.match_port_max) : '',
    match_ip: rule.match_ip ?? '',
    match_dscp: rule.match_dscp != null ? String(rule.match_dscp) : '',
    enabled: rule.enabled,
  }
}

function formToRule(form: RuleFormData, id?: number): QosRule {
  return {
    id: id ?? 0,
    name: form.name,
    interface: form.interface,
    direction: form.direction as 'egress' | 'ingress',
    bandwidth_kbps: parseInt(form.bandwidth_kbps, 10) || 0,
    priority: parseInt(form.priority, 10) || 4,
    match_protocol: form.match_protocol || null,
    match_port_min: form.match_port_min ? parseInt(form.match_port_min, 10) : null,
    match_port_max: form.match_port_max ? parseInt(form.match_port_max, 10) : null,
    match_ip: form.match_ip || null,
    match_dscp: form.match_dscp ? parseInt(form.match_dscp, 10) : null,
    enabled: form.enabled,
  }
}

function BandwidthBar({ stats }: { stats: QosInterfaceStats }) {
  const childClasses = stats.classes.filter(c => c.class_id !== '1:1')
  const totalBytes = childClasses.reduce((sum, c) => sum + c.sent_bytes, 0)

  if (totalBytes === 0) {
    return (
      <div className="text-xs text-navy-500 py-2">No traffic recorded yet</div>
    )
  }

  const colors: Record<string, string> = {
    '1:10': 'bg-red-500',
    '1:20': 'bg-blue-500',
    '1:30': 'bg-amber-500',
    '1:40': 'bg-navy-600',
  }

  return (
    <div className="space-y-2">
      <div className="flex h-4 rounded-full overflow-hidden bg-navy-800">
        {childClasses.map(cls => {
          const pct = totalBytes > 0 ? (cls.sent_bytes / totalBytes) * 100 : 0
          if (pct < 0.5) return null
          return (
            <div
              key={cls.class_id}
              className={`${colors[cls.class_id] ?? 'bg-navy-600'} transition-all duration-300`}
              style={{ width: `${pct}%` }}
              title={`${cls.class_name}: ${formatBytes(cls.sent_bytes)} (${pct.toFixed(1)}%)`}
            />
          )
        })}
      </div>
      <div className="flex flex-wrap gap-3 text-[10px]">
        {childClasses.map(cls => (
          <div key={cls.class_id} className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${colors[cls.class_id] ?? 'bg-navy-600'}`} />
            <span className="text-navy-400">{cls.class_name}</span>
            <span className="text-gray-300 font-mono">{formatBytes(cls.sent_bytes)}</span>
            <span className="text-navy-500">({cls.sent_packets} pkts, {cls.dropped_packets} drops)</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Qos() {
  const [rules, setRules] = useState<QosRule[]>([])
  const [stats, setStats] = useState<QosInterfaceStats[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editingRule, setEditingRule] = useState<QosRule | null>(null)
  const [form, setForm] = useState<RuleFormData>(emptyForm)
  const [saving, setSaving] = useState(false)
  const [applying, setApplying] = useState(false)
  const toast = useToast()

  const loadData = useCallback(async () => {
    try {
      const [rulesRes, statsRes] = await Promise.all([
        api.getQosRules(),
        api.getQosStats().catch(() => ({ stats: [] })),
      ])
      setRules(rulesRes.rules)
      setStats(statsRes.stats)
    } catch {
      toast.error('Failed to load QoS rules')
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { loadData() }, [loadData])

  const openCreate = () => {
    setEditingRule(null)
    setForm(emptyForm)
    setShowModal(true)
  }

  const openEdit = (rule: QosRule) => {
    setEditingRule(rule)
    setForm(ruleToForm(rule))
    setShowModal(true)
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      if (editingRule) {
        await api.updateQosRule(editingRule.id, formToRule(form, editingRule.id))
        toast.success('QoS rule updated')
      } else {
        await api.createQosRule(formToRule(form))
        toast.success('QoS rule created')
      }
      setShowModal(false)
      loadData()
    } catch {
      toast.error('Failed to save QoS rule')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.deleteQosRule(id)
      toast.success('QoS rule deleted')
      loadData()
    } catch {
      toast.error('Failed to delete QoS rule')
    }
  }

  const handleApply = async () => {
    setApplying(true)
    try {
      await api.applyQos()
      toast.success('QoS rules applied successfully')
      loadData()
    } catch {
      toast.error('Failed to apply QoS rules')
    } finally {
      setApplying(false)
    }
  }

  const update = (field: keyof RuleFormData, value: string | boolean) =>
    setForm(prev => ({ ...prev, [field]: value }))

  if (loading) return <Spinner />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Traffic Shaping / QoS"
        subtitle="Manage bandwidth allocation and traffic prioritization via HTB"
      />

      {/* Action bar */}
      <div className="flex items-center gap-3">
        <Button onClick={openCreate}>Add Rule</Button>
        <Button
          variant="secondary"
          onClick={handleApply}
          disabled={applying}
        >
          {applying ? 'Applying...' : 'Apply QoS Rules'}
        </Button>
        <span className="text-xs text-navy-500 ml-2">
          {rules.length} rule{rules.length !== 1 ? 's' : ''} configured
        </span>
      </div>

      {/* Stats */}
      {stats.length > 0 && (
        <Card title="Bandwidth Usage">
          <div className="space-y-4">
            {stats.map(ifStats => (
              <div key={ifStats.interface}>
                <div className="text-sm font-mono text-gray-300 mb-1">{ifStats.interface}</div>
                <BandwidthBar stats={ifStats} />
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Rules list */}
      {rules.length === 0 ? (
        <EmptyState
          title="No QoS rules"
          description="Create traffic shaping rules to prioritize network traffic by protocol, port, or IP."
          action={{ label: 'Add Rule', onClick: openCreate }}
        />
      ) : (
        <Card title="QoS Rules">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-navy-400 text-xs border-b border-navy-800/50">
                  <th className="text-left px-3 py-2">Name</th>
                  <th className="text-left px-3 py-2">Interface</th>
                  <th className="text-left px-3 py-2">Direction</th>
                  <th className="text-left px-3 py-2">Bandwidth</th>
                  <th className="text-left px-3 py-2">Priority</th>
                  <th className="text-left px-3 py-2">Match</th>
                  <th className="text-center px-3 py-2">Status</th>
                  <th className="text-right px-3 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map(rule => (
                  <tr key={rule.id} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                    <td className="px-3 py-2.5 font-medium text-gray-200">{rule.name}</td>
                    <td className="px-3 py-2.5 font-mono text-navy-300">{rule.interface}</td>
                    <td className="px-3 py-2.5">
                      <Badge variant={rule.direction === 'egress' ? 'info' : 'warning'}>
                        {rule.direction === 'egress' ? 'Upload' : 'Download'}
                      </Badge>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-emerald-400">{formatBandwidth(rule.bandwidth_kbps)}</td>
                    <td className="px-3 py-2.5">{priorityBadge(rule.priority)}</td>
                    <td className="px-3 py-2.5 text-xs text-navy-400">
                      {[
                        rule.match_protocol && rule.match_protocol.toUpperCase(),
                        rule.match_port_min && (rule.match_port_max && rule.match_port_max !== rule.match_port_min
                          ? `ports ${rule.match_port_min}-${rule.match_port_max}`
                          : `port ${rule.match_port_min}`),
                        rule.match_ip && rule.match_ip,
                        rule.match_dscp != null && `DSCP ${rule.match_dscp}`,
                      ].filter(Boolean).join(', ') || 'All traffic'}
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      <Badge variant={rule.enabled ? 'success' : 'danger'}>
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openEdit(rule)}
                          className="text-xs text-navy-400 hover:text-white transition-colors"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(rule.id)}
                          className="text-xs text-red-400 hover:text-red-300 transition-colors"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Add/Edit Modal */}
      {showModal && (
        <Modal
          title={editingRule ? 'Edit QoS Rule' : 'Add QoS Rule'}
          onClose={() => setShowModal(false)}
        >
          <div className="space-y-4">
            <Input
              label="Name"
              value={form.name}
              onChange={e => update('name', e.target.value)}
              placeholder="e.g., voip-priority"
            />
            <Input
              label="Interface"
              value={form.interface}
              onChange={e => update('interface', e.target.value)}
              placeholder="e.g., eth0, br-lan"
            />
            <Select
              label="Direction"
              value={form.direction}
              onChange={e => update('direction', e.target.value)}
              options={DIRECTIONS}
            />
            <Input
              label="Bandwidth (Kbps)"
              type="number"
              value={form.bandwidth_kbps}
              onChange={e => update('bandwidth_kbps', e.target.value)}
              placeholder="e.g., 100000 for 100 Mbps"
            />
            <Select
              label="Priority"
              value={form.priority}
              onChange={e => update('priority', e.target.value)}
              options={PRIORITIES}
            />

            <div className="border-t border-navy-800/50 pt-3">
              <p className="text-xs text-navy-400 mb-3 font-medium">Match Criteria (optional)</p>
              <div className="grid grid-cols-2 gap-3">
                <Select
                  label="Protocol"
                  value={form.match_protocol}
                  onChange={e => update('match_protocol', e.target.value)}
                  options={PROTOCOLS}
                />
                <Input
                  label="DSCP (0-63)"
                  type="number"
                  value={form.match_dscp}
                  onChange={e => update('match_dscp', e.target.value)}
                  placeholder="e.g., 46 for EF"
                />
                <Input
                  label="Port Min"
                  type="number"
                  value={form.match_port_min}
                  onChange={e => update('match_port_min', e.target.value)}
                  placeholder="e.g., 5060"
                />
                <Input
                  label="Port Max"
                  type="number"
                  value={form.match_port_max}
                  onChange={e => update('match_port_max', e.target.value)}
                  placeholder="e.g., 5061"
                />
                <div className="col-span-2">
                  <Input
                    label="IP / CIDR"
                    value={form.match_ip}
                    onChange={e => update('match_ip', e.target.value)}
                    placeholder="e.g., 10.0.0.0/24"
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="qos-enabled"
                checked={form.enabled}
                onChange={e => update('enabled', e.target.checked)}
                className="rounded border-navy-600 bg-navy-800 text-blue-500 focus:ring-blue-500/50"
              />
              <label htmlFor="qos-enabled" className="text-sm text-gray-300">Enabled</label>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="secondary" onClick={() => setShowModal(false)}>Cancel</Button>
              <Button onClick={handleSave} disabled={saving}>
                {saving ? 'Saving...' : editingRule ? 'Update' : 'Create'}
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
