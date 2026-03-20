// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback, useRef } from 'react'
import { api, type UserInfo } from '../api'
import { Card, PageHeader, Spinner, Button, Modal, Input, Select, Badge } from '../components/ui'
import { useToast } from '../hooks/useToast'

interface SystemInfo {
  hostname?: string
  platform?: string
  arch?: string
  kernel?: string
  cpu_count?: number
  version?: string
  schema_version?: number
  [key: string]: unknown
}

export default function Settings() {
  const [system, setSystem] = useState<SystemInfo | null>(null)
  const [currentUser, setCurrentUser] = useState<{ id: number; username: string; role: string } | null>(null)
  const [users, setUsers] = useState<UserInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [showChangePassword, setShowChangePassword] = useState<UserInfo | null>(null)
  const [showEditUser, setShowEditUser] = useState<UserInfo | null>(null)
  const [personality, setPersonality] = useState<string>('')
  const [personalities, setPersonalities] = useState<{ name: string; description: string; active: boolean }[]>([])
  const [newUser, setNewUser] = useState({ username: '', password: '', confirmPassword: '', role: 'admin' })
  const [newPassword, setNewPassword] = useState({ password: '', confirmPassword: '' })
  const [editRole, setEditRole] = useState('')
  const [backupLoading, setBackupLoading] = useState(false)
  const [restoreLoading, setRestoreLoading] = useState(false)
  const [showRestoreConfirm, setShowRestoreConfirm] = useState(false)
  const [pendingRestore, setPendingRestore] = useState<unknown>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      const [sysRes, meRes, usersRes, persRes] = await Promise.all([
        api.getSystem(),
        api.getMe(),
        api.getUsers(),
        api.getPersonality(),
      ])
      setSystem(sysRes as SystemInfo)
      setCurrentUser(meRes.user)
      setUsers(usersRes.users ?? [])
      setPersonality(persRes.active)
      setPersonalities(persRes.personalities)
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setLoading(false) }
  }, [toast])

  useEffect(() => { load() }, [load])

  const handleCreateUser = async () => {
    if (!newUser.username.trim()) { toast.error('Username is required'); return }
    if (newUser.password.length < 8) { toast.error('Password must be at least 8 characters'); return }
    if (newUser.password !== newUser.confirmPassword) { toast.error('Passwords do not match'); return }
    try {
      await api.createUser({ username: newUser.username.trim(), password: newUser.password, role: newUser.role })
      toast.success(`User "${newUser.username}" created`)
      setShowCreateUser(false)
      setNewUser({ username: '', password: '', confirmPassword: '', role: 'admin' })
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleChangePassword = async () => {
    if (!showChangePassword) return
    if (newPassword.password.length < 8) { toast.error('Password must be at least 8 characters'); return }
    if (newPassword.password !== newPassword.confirmPassword) { toast.error('Passwords do not match'); return }
    try {
      await api.changePassword(showChangePassword.id, newPassword.password)
      toast.success(`Password updated for "${showChangePassword.username}"`)
      setShowChangePassword(null)
      setNewPassword({ password: '', confirmPassword: '' })
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleUpdateRole = async () => {
    if (!showEditUser) return
    try {
      await api.updateUser(showEditUser.id, { role: editRole })
      toast.success(`Role updated for "${showEditUser.username}"`)
      setShowEditUser(null)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDeleteUser = async (user: UserInfo) => {
    if (user.id === currentUser?.id) { toast.error('Cannot delete your own account'); return }
    try {
      await api.deleteUser(user.id)
      toast.success(`User "${user.username}" deleted`)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleSetPersonality = async (name: string) => {
    try {
      const res = await api.setPersonality(name)
      setPersonality(res.active)
      setPersonalities(prev => prev.map(p => ({ ...p, active: p.name === res.active })))
      toast.success(`Personality: ${res.active}`)
    } catch (e: unknown) { toast.error((e as Error).message) }
  }

  const handleDownloadBackup = async () => {
    setBackupLoading(true)
    try {
      await api.downloadBackup()
      toast.success('Backup downloaded')
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally { setBackupLoading(false) }
  }

  const handleRestoreFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result as string)
        if (!data.format_version) {
          toast.error('Invalid backup file: missing format_version')
          return
        }
        setPendingRestore(data)
        setShowRestoreConfirm(true)
      } catch {
        toast.error('Invalid backup file: not valid JSON')
      }
    }
    reader.readAsText(file)
    // Reset file input so the same file can be selected again
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleConfirmRestore = async () => {
    if (!pendingRestore) return
    setShowRestoreConfirm(false)
    setRestoreLoading(true)
    try {
      const res = await api.restoreBackup(pendingRestore)
      const counts = Object.entries(res.stats ?? {})
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ')
      toast.success(`Configuration restored (${counts})`)
      load()
    } catch (e: unknown) { toast.error((e as Error).message) }
    finally {
      setRestoreLoading(false)
      setPendingRestore(null)
    }
  }

  if (loading) return <Spinner label="Loading settings..." />

  const isAdmin = currentUser?.role === 'admin'

  return (
    <div className="space-y-6 stagger-children">
      <PageHeader title="Settings" />

      <Card title="System Information">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            ['Hostname', system?.hostname ?? '---'],
            ['Platform', system?.platform ?? '---'],
            ['Architecture', system?.arch ?? '---'],
            ['Kernel', system?.kernel ?? '---'],
            ['CPU Cores', system?.cpu_count ?? '---'],
            ['Version', system?.version ?? '---'],
            ['DB Schema', system?.schema_version ?? '---'],
          ].map(([label, value]) => (
            <div key={String(label)} className="flex items-center gap-4">
              <span className="w-32 text-sm text-navy-400 shrink-0">{String(label)}</span>
              <span className="text-sm font-mono text-gray-200">{String(value)}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* Personality */}
      <Card title="Personality">
        <p className="text-xs text-navy-400 mb-4">
          Controls the style of error messages, rate-limit responses, honeypot replies, and IDS alerts.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {personalities.map((p) => (
            <button
              key={p.name}
              onClick={() => handleSetPersonality(p.name)}
              className={`text-left rounded-lg border p-3 transition-all ${
                p.name === personality
                  ? 'border-emerald-500/50 bg-emerald-500/10'
                  : 'border-navy-700/50 bg-navy-900/30 hover:border-navy-600/50 hover:bg-navy-800/30'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-mono font-medium text-gray-200">{p.name}</span>
                {p.name === personality && (
                  <Badge variant="success">active</Badge>
                )}
              </div>
              <span className="text-xs text-navy-400">{p.description}</span>
            </button>
          ))}
        </div>
      </Card>

      {/* Current account */}
      <Card title="Your Account">
        {currentUser ? (
          <div className="space-y-3">
            <div className="flex items-center gap-4">
              <span className="w-32 text-sm text-navy-400">Username</span>
              <span className="text-sm font-mono text-gray-200">{currentUser.username}</span>
            </div>
            <div className="flex items-center gap-4">
              <span className="w-32 text-sm text-navy-400">Role</span>
              <Badge variant={currentUser.role === 'admin' ? 'success' : 'info'}>{currentUser.role.toUpperCase()}</Badge>
            </div>
            <div className="pt-2">
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  setNewPassword({ password: '', confirmPassword: '' })
                  setShowChangePassword(currentUser as UserInfo)
                }}
              >
                Change Password
              </Button>
            </div>
          </div>
        ) : (
          <p className="text-sm text-navy-500">Unable to load account info</p>
        )}
      </Card>

      {/* User management */}
      {isAdmin && (
        <Card
          title="User Management"
          actions={<Button size="sm" onClick={() => {
            setNewUser({ username: '', password: '', confirmPassword: '', role: 'admin' })
            setShowCreateUser(true)
          }}>+ Add User</Button>}
        >
          {users.length === 0 ? (
            <p className="text-sm text-navy-500">No users found</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-navy-800/50">
                    {['Username', 'Role', 'Created', ''].map((h) => (
                      <th key={h} className="text-left px-4 py-2 text-[11px] text-navy-400 uppercase tracking-wider font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id} className="border-b border-navy-800/30 hover:bg-navy-800/20 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-gray-200">{user.username}</span>
                          {user.id === currentUser?.id && (
                            <span className="text-[10px] text-navy-500 border border-navy-700/50 rounded px-1.5 py-0.5">you</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant={user.role === 'admin' ? 'success' : 'info'}>{user.role.toUpperCase()}</Badge>
                      </td>
                      <td className="px-4 py-3 text-xs text-navy-400 font-mono">
                        {user.created_at ? new Date(user.created_at).toLocaleDateString() : '---'}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <Button variant="secondary" size="sm" onClick={() => {
                            setEditRole(user.role)
                            setShowEditUser(user)
                          }}>Edit</Button>
                          <Button variant="secondary" size="sm" onClick={() => {
                            setNewPassword({ password: '', confirmPassword: '' })
                            setShowChangePassword(user)
                          }}>Password</Button>
                          {user.id !== currentUser?.id && (
                            <Button variant="danger" size="sm" onClick={() => handleDeleteUser(user)}>Delete</Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* Create User Modal */}
      <Modal open={showCreateUser} onClose={() => setShowCreateUser(false)} title="Create User">
        <div className="space-y-4">
          <Input
            label="Username"
            mono
            value={newUser.username}
            onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
            placeholder="admin2"
          />
          <Input
            label="Password (min. 8 characters)"
            type="password"
            mono
            value={newUser.password}
            onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
          />
          <Input
            label="Confirm Password"
            type="password"
            mono
            value={newUser.confirmPassword}
            onChange={(e) => setNewUser({ ...newUser, confirmPassword: e.target.value })}
          />
          <Select
            label="Role"
            value={newUser.role}
            onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
            options={[
              { value: 'admin', label: 'Admin — Full access' },
              { value: 'readonly', label: 'Read-only — View only' },
            ]}
          />
          <div className="flex gap-2 pt-2">
            <Button onClick={handleCreateUser}>Create User</Button>
            <Button variant="secondary" onClick={() => setShowCreateUser(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Change Password Modal */}
      <Modal
        open={showChangePassword !== null}
        onClose={() => setShowChangePassword(null)}
        title={`Change Password: ${showChangePassword?.username ?? ''}`}
      >
        <div className="space-y-4">
          <Input
            label="New Password (min. 8 characters)"
            type="password"
            mono
            value={newPassword.password}
            onChange={(e) => setNewPassword({ ...newPassword, password: e.target.value })}
          />
          <Input
            label="Confirm New Password"
            type="password"
            mono
            value={newPassword.confirmPassword}
            onChange={(e) => setNewPassword({ ...newPassword, confirmPassword: e.target.value })}
          />
          {showChangePassword && showChangePassword.id !== currentUser?.id && (
            <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">
              <p className="text-xs text-amber-400">This will log out all active sessions for this user.</p>
            </div>
          )}
          <div className="flex gap-2 pt-2">
            <Button onClick={handleChangePassword}>Change Password</Button>
            <Button variant="secondary" onClick={() => setShowChangePassword(null)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Edit User Modal */}
      <Modal
        open={showEditUser !== null}
        onClose={() => setShowEditUser(null)}
        title={`Edit User: ${showEditUser?.username ?? ''}`}
      >
        <div className="space-y-4">
          <Select
            label="Role"
            value={editRole}
            onChange={(e) => setEditRole(e.target.value)}
            options={[
              { value: 'admin', label: 'Admin — Full access' },
              { value: 'readonly', label: 'Read-only — View only' },
            ]}
          />
          {showEditUser?.id === currentUser?.id && editRole !== 'admin' && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
              <p className="text-xs text-red-400">Warning: Demoting yourself from admin will restrict your access.</p>
            </div>
          )}
          <div className="flex gap-2 pt-2">
            <Button onClick={handleUpdateRole}>Save</Button>
            <Button variant="secondary" onClick={() => setShowEditUser(null)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      <Card title="Backup / Restore">
        <p className="text-sm text-navy-500 mb-4">
          Export or import gateway configuration. Secrets (VPN keys, wireless passwords, WAN credentials) are not included in backups and must be re-entered after restore. Devices must re-adopt.
        </p>
        <div className="flex gap-3">
          <Button onClick={handleDownloadBackup} disabled={backupLoading}>
            {backupLoading ? 'Exporting...' : 'Download Backup'}
          </Button>
          <Button variant="secondary" onClick={() => fileInputRef.current?.click()} disabled={restoreLoading}>
            {restoreLoading ? 'Restoring...' : 'Restore from Backup'}
          </Button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            className="hidden"
            onChange={handleRestoreFile}
          />
        </div>
      </Card>

      <Modal open={showRestoreConfirm} onClose={() => { setShowRestoreConfirm(false); setPendingRestore(null) }} title="Confirm Restore">
        <div className="space-y-4">
          <p className="text-sm text-navy-400">
            This will overwrite the current gateway configuration with the backup file. All existing networks, firewall rules, VPN tunnels, wireless networks, and interface settings will be replaced.
          </p>
          <p className="text-sm text-red-400 font-medium">
            Secrets (VPN private keys, wireless passwords) are not included in backups. You will need to re-enter them. Devices must re-adopt.
          </p>
          <div className="flex gap-2 pt-2">
            <Button variant="danger" onClick={handleConfirmRestore}>Restore Configuration</Button>
            <Button variant="secondary" onClick={() => { setShowRestoreConfirm(false); setPendingRestore(null) }}>Cancel</Button>
          </div>
        </div>
      </Modal>

      <Card title="Firmware">
        <div className="flex items-center gap-4">
          <span className="w-32 text-sm text-navy-400">Version</span>
          <span className="text-sm font-mono text-gray-200">{system?.version ?? '0.1.0'}</span>
        </div>
        <div className="mt-3">
          <a href="/update" className="text-sm text-emerald-400 hover:text-emerald-300 transition-colors">
            Manage firmware updates &rarr;
          </a>
        </div>
      </Card>
    </div>
  )
}
