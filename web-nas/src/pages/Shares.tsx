// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import {
  FolderOpen,
  Plus,
  Trash2,
  Users,
  Lock,
  Unlock,
  RefreshCw,
  Key,
  FolderSync,
} from 'lucide-react'
import {
  PageHeader,
  Tabs,
  Spinner,
  Card,
  Button,
  Badge,
  Modal,
  ConfirmDialog,
  EmptyState,
  Input,
  Toggle,
} from '../components/ui'
import ShareForm from '../components/ShareForm'
import UserForm from '../components/UserForm'
import { api } from '../api'
import type { Share, NasUser, RsyncModule, CreateShareRequest, CreateUserRequest, ChangePasswordRequest, CreateRsyncModuleRequest } from '../types'

type TabKey = 'shares' | 'users' | 'rsync'

export default function Shares() {
  const [activeTab, setActiveTab] = useState<TabKey>('shares')
  const [shares, setShares] = useState<Share[]>([])
  const [users, setUsers] = useState<NasUser[]>([])
  const [rsyncModules, setRsyncModules] = useState<RsyncModule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Modals
  const [showCreateShare, setShowCreateShare] = useState(false)
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [showCreateRsync, setShowCreateRsync] = useState(false)
  const [showChangePassword, setShowChangePassword] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<{ type: 'share' | 'user' | 'rsync'; name: string } | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [confirmNewPassword, setConfirmNewPassword] = useState('')
  const [passwordError, setPasswordError] = useState('')

  // Rsync create form state
  const [rsyncName, setRsyncName] = useState('')
  const [rsyncPath, setRsyncPath] = useState('')
  const [rsyncReadOnly, setRsyncReadOnly] = useState(true)
  const [rsyncComment, setRsyncComment] = useState('')
  const [rsyncErrors, setRsyncErrors] = useState<Record<string, string>>({})

  const [submitting, setSubmitting] = useState(false)

  const fetchData = useCallback(async () => {
    try {
      const [s, u] = await Promise.all([api.getShares(), api.getUsers()])
      setShares(Array.isArray(s) ? s : [])
      setUsers(Array.isArray(u) ? u : [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchRsync = useCallback(async () => {
    try {
      const mods = await api.getRsyncModules()
      setRsyncModules(Array.isArray(mods) ? mods : [])
    } catch {
      // rsync may not be configured
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  useEffect(() => {
    if (activeTab === 'rsync') {
      fetchRsync()
    }
  }, [activeTab, fetchRsync])

  const handleCreateShare = async (data: CreateShareRequest) => {
    setSubmitting(true)
    try {
      await api.createShare(data)
      setShowCreateShare(false)
      await fetchData()
    } catch {
      // Error
    } finally {
      setSubmitting(false)
    }
  }

  const handleCreateUser = async (data: CreateUserRequest) => {
    setSubmitting(true)
    try {
      await api.createUser(data)
      setShowCreateUser(false)
      await fetchData()
    } catch {
      // Error
    } finally {
      setSubmitting(false)
    }
  }

  const validateRsyncForm = (): boolean => {
    const errs: Record<string, string> = {}
    if (!rsyncName.trim()) {
      errs.name = 'Name is required'
    } else if (!/^[a-zA-Z0-9_-]+$/.test(rsyncName)) {
      errs.name = 'Only letters, numbers, hyphens, underscores'
    }
    if (!rsyncPath.trim()) {
      errs.path = 'Path is required'
    } else if (!rsyncPath.startsWith('/mnt/')) {
      errs.path = 'Path must start with /mnt/'
    }
    setRsyncErrors(errs)
    return Object.keys(errs).length === 0
  }

  const handleCreateRsync = async () => {
    if (!validateRsyncForm()) return
    setSubmitting(true)
    try {
      const req: CreateRsyncModuleRequest = {
        name: rsyncName.trim(),
        path: rsyncPath.trim(),
        read_only: rsyncReadOnly,
        comment: rsyncComment.trim(),
      }
      await api.createRsyncModule(req)
      setShowCreateRsync(false)
      setRsyncName('')
      setRsyncPath('')
      setRsyncReadOnly(true)
      setRsyncComment('')
      setRsyncErrors({})
      await fetchRsync()
    } catch {
      // Error
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    setSubmitting(true)
    try {
      if (deleteTarget.type === 'share') {
        await api.deleteShare(deleteTarget.name)
      } else if (deleteTarget.type === 'user') {
        await api.deleteUser(deleteTarget.name)
      } else if (deleteTarget.type === 'rsync') {
        await api.deleteRsyncModule(deleteTarget.name)
      }
      setDeleteTarget(null)
      if (deleteTarget.type === 'rsync') {
        await fetchRsync()
      } else {
        await fetchData()
      }
    } catch {
      // Error
    } finally {
      setSubmitting(false)
    }
  }

  const handleChangePassword = async () => {
    if (!showChangePassword) return
    if (newPassword.length < 8) {
      setPasswordError('Minimum 8 characters')
      return
    }
    if (newPassword !== confirmNewPassword) {
      setPasswordError('Passwords do not match')
      return
    }
    setSubmitting(true)
    try {
      const req: ChangePasswordRequest = {
        username: showChangePassword,
        new_password: newPassword,
      }
      await api.changePassword(req)
      setShowChangePassword(null)
      setNewPassword('')
      setConfirmNewPassword('')
      setPasswordError('')
    } catch {
      // Error
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) return <Spinner label="Loading shares..." />

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <p className="text-sm text-red-400 mb-2">Failed to load data</p>
          <p className="text-xs text-navy-500">{error}</p>
          <Button variant="secondary" size="sm" className="mt-4" onClick={fetchData}>
            Retry
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Shares & Users"
        subtitle={
          <span className="text-xs text-navy-400">
            {shares.length} share{shares.length !== 1 ? 's' : ''} &middot; {users.length} user{users.length !== 1 ? 's' : ''}
          </span>
        }
        actions={
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={activeTab === 'rsync' ? fetchRsync : fetchData}>
              <RefreshCw className="w-3.5 h-3.5 mr-1.5 inline" />
              Refresh
            </Button>
            {activeTab === 'shares' && (
              <Button size="sm" onClick={() => setShowCreateShare(true)}>
                <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                Add Share
              </Button>
            )}
            {activeTab === 'users' && (
              <Button size="sm" onClick={() => setShowCreateUser(true)}>
                <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                Add User
              </Button>
            )}
            {activeTab === 'rsync' && (
              <Button size="sm" onClick={() => setShowCreateRsync(true)}>
                <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                Add Module
              </Button>
            )}
          </div>
        }
      />

      <Tabs
        tabs={[
          { key: 'shares', label: 'Shares', count: shares.length },
          { key: 'users', label: 'Users', count: users.length },
          { key: 'rsync', label: 'Rsync Modules', count: rsyncModules.length },
        ]}
        active={activeTab}
        onChange={(k) => setActiveTab(k as TabKey)}
      />

      {/* Shares tab */}
      {activeTab === 'shares' && (
        <div className="space-y-3">
          {shares.length > 0 ? (
            shares.map((share) => (
              <Card key={share.name} className="!p-0">
                <div className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
                      <FolderOpen className="w-5 h-5 text-sky-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-semibold text-gray-100">{share.name}</h3>
                        <Badge variant={(share.enabled ?? true) ? 'success' : 'neutral'}>
                          {(share.enabled ?? true) ? 'Active' : 'Disabled'}
                        </Badge>
                        {share.protocol && (
                          <Badge variant="info">{(share.protocol ?? 'smb').toUpperCase()}</Badge>
                        )}
                      </div>
                      <p className="text-[11px] text-navy-400 font-mono mt-0.5">{share.path ?? ''}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => setDeleteTarget({ type: 'share', name: share.name })}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
                <div className="px-4 pb-3 flex items-center gap-4 text-[11px] border-t border-navy-800/30 pt-3">
                  <div className="flex items-center gap-1.5">
                    {share.read_only ? (
                      <Lock className="w-3 h-3 text-amber-400" />
                    ) : (
                      <Unlock className="w-3 h-3 text-emerald-400" />
                    )}
                    <span className="text-navy-400">{share.read_only ? 'Read-only' : 'Read-write'}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Users className="w-3 h-3 text-navy-500" />
                    <span className="text-navy-400">
                      {share.guest_access
                        ? 'Guest access'
                        : (share.allowed_users ?? []).length > 0
                          ? (share.allowed_users ?? []).join(', ')
                          : 'No users'}
                    </span>
                  </div>
                  {(share.description || share.comment) && (
                    <span className="text-navy-500">{share.description || share.comment}</span>
                  )}
                </div>
              </Card>
            ))
          ) : (
            <EmptyState
              icon={<FolderOpen className="w-12 h-12" />}
              title="No shares configured"
              description="Create a share to start sharing files on your network."
              action={
                <Button size="sm" onClick={() => setShowCreateShare(true)}>
                  <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                  Create Share
                </Button>
              }
            />
          )}
        </div>
      )}

      {/* Users tab */}
      {activeTab === 'users' && (
        <div className="space-y-3">
          {users.length > 0 ? (
            users.map((user) => (
              <Card key={user.username} className="!p-0">
                <div className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                      <Users className="w-5 h-5 text-emerald-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-semibold text-gray-100">{user.username}</h3>
                        <Badge variant={(user.enabled ?? true) ? 'success' : 'neutral'}>
                          {(user.enabled ?? true) ? 'Active' : 'Disabled'}
                        </Badge>
                        {user.uid != null && (
                          <span className="text-[10px] text-navy-500 font-mono">UID {user.uid}</span>
                        )}
                      </div>
                      <p className="text-[11px] text-navy-400 mt-0.5">
                        Groups: {(user.groups ?? []).length > 0 ? (user.groups ?? []).join(', ') : 'none'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setShowChangePassword(user.username)
                        setNewPassword('')
                        setConfirmNewPassword('')
                        setPasswordError('')
                      }}
                    >
                      <Key className="w-3.5 h-3.5 mr-1 inline" />
                      Password
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => setDeleteTarget({ type: 'user', name: user.username })}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
                {(user.shares ?? []).length > 0 && (
                  <div className="px-4 pb-3 border-t border-navy-800/30 pt-3">
                    <p className="text-[10px] text-navy-500 uppercase tracking-wider mb-1.5">Shares</p>
                    <div className="flex gap-1.5 flex-wrap">
                      {(user.shares ?? []).map((s) => (
                        <Badge key={s} variant="info">{s}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </Card>
            ))
          ) : (
            <EmptyState
              icon={<Users className="w-12 h-12" />}
              title="No users configured"
              description="Create users to control access to your shares."
              action={
                <Button size="sm" onClick={() => setShowCreateUser(true)}>
                  <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                  Add User
                </Button>
              }
            />
          )}
        </div>
      )}

      {/* Rsync tab */}
      {activeTab === 'rsync' && (
        <div className="space-y-3">
          {rsyncModules.length > 0 ? (
            rsyncModules.map((mod) => (
              <Card key={mod.name} className="!p-0">
                <div className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3">
                    <FolderSync className="w-5 h-5 text-amber-400" />
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-semibold text-gray-100">{mod.name}</h3>
                        <Badge variant={mod.read_only ? 'warning' : 'success'}>
                          {mod.read_only ? 'Read-only' : 'Read-write'}
                        </Badge>
                      </div>
                      <p className="text-[11px] text-navy-400 font-mono mt-0.5">{mod.path ?? 'N/A'}</p>
                    </div>
                  </div>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => setDeleteTarget({ type: 'rsync', name: mod.name })}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
                <div className="px-4 pb-3 flex items-center gap-4 text-[11px] border-t border-navy-800/30 pt-3">
                  {mod.comment && (
                    <div>
                      <span className="text-navy-500">Comment: </span>
                      <span className="text-gray-300">{mod.comment}</span>
                    </div>
                  )}
                  {(mod.allowed_hosts ?? []).length > 0 && (
                    <div>
                      <span className="text-navy-500">Allowed hosts: </span>
                      <span className="text-gray-300 font-mono">{(mod.allowed_hosts ?? []).join(', ')}</span>
                    </div>
                  )}
                </div>
              </Card>
            ))
          ) : (
            <EmptyState
              icon={<FolderSync className="w-12 h-12" />}
              title="No rsync modules configured"
              description="Rsync modules allow remote backup synchronization."
              action={
                <Button size="sm" onClick={() => setShowCreateRsync(true)}>
                  <Plus className="w-3.5 h-3.5 mr-1.5 inline" />
                  Create Module
                </Button>
              }
            />
          )}
        </div>
      )}

      {/* Create share modal */}
      <Modal
        open={showCreateShare}
        onClose={() => setShowCreateShare(false)}
        title="Create Share"
      >
        <ShareForm
          users={users}
          onSubmit={handleCreateShare}
          onCancel={() => setShowCreateShare(false)}
          loading={submitting}
        />
      </Modal>

      {/* Create user modal */}
      <Modal
        open={showCreateUser}
        onClose={() => setShowCreateUser(false)}
        title="Create User"
      >
        <UserForm
          onSubmit={handleCreateUser}
          onCancel={() => setShowCreateUser(false)}
          loading={submitting}
        />
      </Modal>

      {/* Create rsync module modal */}
      <Modal
        open={showCreateRsync}
        onClose={() => { setShowCreateRsync(false); setRsyncErrors({}) }}
        title="Create Rsync Module"
      >
        <div className="space-y-4">
          <Input
            label="Module Name"
            value={rsyncName}
            onChange={(e) => setRsyncName(e.target.value)}
            placeholder="backup"
            error={rsyncErrors.name}
            mono
          />
          <Input
            label="Path"
            value={rsyncPath}
            onChange={(e) => setRsyncPath(e.target.value)}
            placeholder="/mnt/crypt-data/backup"
            error={rsyncErrors.path}
            mono
          />
          <Input
            label="Comment"
            value={rsyncComment}
            onChange={(e) => setRsyncComment(e.target.value)}
            placeholder="Backup share"
          />
          <Toggle
            checked={rsyncReadOnly}
            onChange={setRsyncReadOnly}
            label="Read-only"
          />
          <div className="flex justify-end gap-3 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => { setShowCreateRsync(false); setRsyncErrors({}) }}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button size="sm" onClick={handleCreateRsync} loading={submitting}>
              Create Module
            </Button>
          </div>
        </div>
      </Modal>

      {/* Change password modal */}
      <Modal
        open={showChangePassword !== null}
        onClose={() => setShowChangePassword(null)}
        title={`Change Password: ${showChangePassword ?? ''}`}
        size="sm"
      >
        <div className="space-y-4">
          <Input
            label="New Password"
            type="password"
            value={newPassword}
            onChange={(e) => { setNewPassword(e.target.value); setPasswordError('') }}
            placeholder="Minimum 8 characters"
            autoComplete="new-password"
          />
          <Input
            label="Confirm Password"
            type="password"
            value={confirmNewPassword}
            onChange={(e) => { setConfirmNewPassword(e.target.value); setPasswordError('') }}
            placeholder="Re-enter password"
            error={passwordError}
            autoComplete="new-password"
          />
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="secondary" size="sm" onClick={() => setShowChangePassword(null)} disabled={submitting}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleChangePassword} loading={submitting}>
              Change Password
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title={`Delete ${deleteTarget?.type === 'share' ? 'Share' : deleteTarget?.type === 'user' ? 'User' : 'Rsync Module'}`}
        message={`Are you sure you want to delete "${deleteTarget?.name ?? ''}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        loading={submitting}
      />
    </div>
  )
}
