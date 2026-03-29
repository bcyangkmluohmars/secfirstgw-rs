// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { Button, Input } from './ui'
import type { CreateUserRequest } from '../types'

interface UserFormProps {
  onSubmit: (data: CreateUserRequest) => void
  onCancel: () => void
  loading?: boolean
}

export default function UserForm({ onSubmit, onCancel, loading = false }: UserFormProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [groups, setGroups] = useState('')

  const [errors, setErrors] = useState<Record<string, string>>({})

  const validate = (): boolean => {
    const errs: Record<string, string> = {}
    if (!username.trim()) errs.username = 'Username is required'
    else if (!/^[a-z_][a-z0-9_-]*$/.test(username)) errs.username = 'Must start with lowercase letter, only a-z, 0-9, -, _'
    if (username.length > 32) errs.username = 'Maximum 32 characters'
    if (!password) errs.password = 'Password is required'
    else if (password.length < 8) errs.password = 'Minimum 8 characters'
    if (password !== confirmPassword) errs.confirmPassword = 'Passwords do not match'
    setErrors(errs)
    return Object.keys(errs).length === 0
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return
    onSubmit({
      username: username.trim(),
      password,
      groups: groups.trim() ? groups.trim().split(',').map((g) => g.trim()).filter(Boolean) : [],
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Input
        label="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="john"
        error={errors.username}
        mono
        autoComplete="off"
      />

      <Input
        label="Password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Minimum 8 characters"
        error={errors.password}
        autoComplete="new-password"
      />

      <Input
        label="Confirm Password"
        type="password"
        value={confirmPassword}
        onChange={(e) => setConfirmPassword(e.target.value)}
        placeholder="Re-enter password"
        error={errors.confirmPassword}
        autoComplete="new-password"
      />

      <Input
        label="Groups (comma-separated)"
        value={groups}
        onChange={(e) => setGroups(e.target.value)}
        placeholder="users, media"
        mono
      />

      <div className="flex justify-end gap-3 pt-2">
        <Button variant="secondary" size="sm" type="button" onClick={onCancel} disabled={loading}>
          Cancel
        </Button>
        <Button size="sm" type="submit" loading={loading}>
          Create User
        </Button>
      </div>
    </form>
  )
}
