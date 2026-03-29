// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { Button, Input, Select, Toggle } from './ui'
import type { CreateShareRequest, ShareProtocol, ShareTemplate, NasUser } from '../types'

interface ShareFormProps {
  users: NasUser[]
  onSubmit: (data: CreateShareRequest) => void
  onCancel: () => void
  loading?: boolean
}

const TEMPLATES: { value: ShareTemplate; label: string; description: string }[] = [
  { value: 'standard', label: 'Standard', description: 'Default read-write share with no guest access' },
  { value: 'public', label: 'Public (Guest Read-Only)', description: 'Guest-accessible, read-only, browseable' },
  { value: 'private', label: 'Private (User Only)', description: 'Restricted to selected users, read-write' },
  { value: 'timemachine', label: 'Time Machine (macOS Backup)', description: 'macOS backup target with VFS Fruit support' },
]

export default function ShareForm({ users, onSubmit, onCancel, loading = false }: ShareFormProps) {
  const [name, setName] = useState('')
  const [path, setPath] = useState('')
  const [protocol, setProtocol] = useState<ShareProtocol>('smb')
  const [template, setTemplate] = useState<ShareTemplate>('standard')
  const [readOnly, setReadOnly] = useState(false)
  const [guestAccess, setGuestAccess] = useState(false)
  const [description, setDescription] = useState('')
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])

  const [errors, setErrors] = useState<Record<string, string>>({})

  const applyTemplate = (tpl: ShareTemplate) => {
    setTemplate(tpl)
    switch (tpl) {
      case 'standard':
        setReadOnly(false)
        setGuestAccess(false)
        break
      case 'public':
        setReadOnly(true)
        setGuestAccess(true)
        break
      case 'private':
        setReadOnly(false)
        setGuestAccess(false)
        break
      case 'timemachine':
        setReadOnly(false)
        setGuestAccess(false)
        break
    }
  }

  const validate = (): boolean => {
    const errs: Record<string, string> = {}
    if (!name.trim()) errs.name = 'Name is required'
    else if (!/^[a-zA-Z0-9_-]+$/.test(name)) errs.name = 'Only letters, numbers, hyphens, underscores'
    if (!path.trim()) errs.path = 'Path is required'
    else if (!path.startsWith('/mnt/')) errs.path = 'Path must start with /mnt/'
    if (template === 'timemachine' && selectedUsers.length === 0) {
      errs.users = 'Time Machine requires at least one user'
    }
    if (template === 'private' && selectedUsers.length === 0) {
      errs.users = 'Private template requires at least one user'
    }
    setErrors(errs)
    return Object.keys(errs).length === 0
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return
    onSubmit({
      name: name.trim(),
      path: path.trim(),
      protocol,
      read_only: readOnly,
      allowed_users: selectedUsers,
      guest_access: guestAccess,
      description: description.trim(),
      template,
    })
  }

  const toggleUser = (username: string) => {
    setSelectedUsers((prev) =>
      prev.includes(username)
        ? prev.filter((u) => u !== username)
        : [...prev, username]
    )
  }

  const selectedTemplateInfo = TEMPLATES.find((t) => t.value === template)

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Template selector */}
      <div>
        <span className="block text-[11px] font-medium text-navy-400 mb-1.5">Template</span>
        <div className="grid grid-cols-2 gap-2">
          {TEMPLATES.map((tpl) => (
            <button
              key={tpl.value}
              type="button"
              onClick={() => applyTemplate(tpl.value)}
              className={`
                text-left p-2.5 rounded-lg border transition-colors text-xs
                ${template === tpl.value
                  ? 'border-emerald-500/60 bg-emerald-500/10 text-emerald-300'
                  : 'border-navy-700/50 bg-navy-800/50 text-gray-400 hover:border-navy-600'}
              `}
            >
              <div className="font-medium text-[12px]">{tpl.label}</div>
            </button>
          ))}
        </div>
        {selectedTemplateInfo && (
          <p className="text-[10px] text-navy-500 mt-1.5">{selectedTemplateInfo.description}</p>
        )}
      </div>

      <Input
        label="Share Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="documents"
        error={errors.name}
        mono
      />

      <Input
        label="Path"
        value={path}
        onChange={(e) => setPath(e.target.value)}
        placeholder="/mnt/crypt-data/documents"
        error={errors.path}
        mono
      />

      <Select
        label="Protocol"
        value={protocol}
        onChange={(e) => setProtocol(e.target.value as ShareProtocol)}
        options={[
          { value: 'smb', label: 'SMB (Windows/Mac)' },
          { value: 'nfs', label: 'NFS (Linux/Unix)' },
          { value: 'rsync', label: 'Rsync' },
        ]}
      />

      <Input
        label="Description"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="Shared documents folder"
      />

      <div className="space-y-3">
        <Toggle
          checked={readOnly}
          onChange={setReadOnly}
          label="Read-only"
        />
        <Toggle
          checked={guestAccess}
          onChange={setGuestAccess}
          label="Allow guest access"
        />
      </div>

      {/* User selection */}
      {!guestAccess && users.length > 0 && (
        <div>
          <p className="text-[11px] font-medium text-navy-400 mb-2">Allowed Users</p>
          {errors.users && (
            <p className="text-[11px] text-red-400 mb-1">{errors.users}</p>
          )}
          <div className="space-y-1 max-h-40 overflow-y-auto">
            {users.map((user) => (
              <label
                key={user.username}
                className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-navy-800/30 cursor-pointer transition-colors"
              >
                <input
                  type="checkbox"
                  checked={selectedUsers.includes(user.username)}
                  onChange={() => toggleUser(user.username)}
                  className="rounded border-navy-700 bg-navy-800 text-emerald-500 focus:ring-emerald-500/50"
                />
                <span className="text-sm text-gray-300">{user.username}</span>
              </label>
            ))}
          </div>
        </div>
      )}

      <div className="flex justify-end gap-3 pt-2">
        <Button variant="secondary" size="sm" type="button" onClick={onCancel} disabled={loading}>
          Cancel
        </Button>
        <Button size="sm" type="submit" loading={loading}>
          Create Share
        </Button>
      </div>
    </form>
  )
}
