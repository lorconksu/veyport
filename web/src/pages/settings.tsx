import { useState, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, X } from 'lucide-react'
import { useAuth } from '@/hooks/use-auth'
import { apiFetch } from '@/lib/api'
import { getAvatarColor, setAvatarColor as persistAvatarColor, AVATAR_COLORS } from '@/lib/avatar'
import { validatePassword } from '@/lib/password'
import { formatRelative, isFuture, isNoAutoUnlock } from '@/lib/time'
import type { ChangePasswordRequest, User, Role, TOTPDisableRequest, AccountStatus } from '@/types/api'
import { CreateUserModal } from '@/pages/create-user-modal'
import { NotificationsTab } from '@/pages/settings-notifications-tab'
import { PreferencesTab } from '@/pages/settings-preferences-tab'
import { DirectoryTab } from '@/pages/settings-directory-tab'
import { AccountPolicyCard } from '@/pages/account-policy-card'

/** u.status when present; otherwise derives from `locked_until` (007 fallback, still exercised by pre-008 fixtures). */
function effectiveStatus(u: User): AccountStatus {
  if (u.status) return u.status
  if (u.locked_until && isFuture(u.locked_until)) return 'locked'
  return 'active'
}

type ConfirmActionType = 'disable' | 'enable' | 'unlock' | 'exempt' | 'unexempt'

interface ConfirmCopy {
  title: string
  body: string
  confirmLabel: string
  danger?: boolean
}

function confirmCopyFor(type: ConfirmActionType, username: string): ConfirmCopy {
  switch (type) {
    case 'disable':
      return {
        title: 'Disable User',
        body: `Disable ${username}? Their sessions end on their next request and all their API tokens are revoked. You can enable the account again later.`,
        confirmLabel: 'Disable',
        danger: true,
      }
    case 'enable':
      return {
        title: 'Enable User',
        body: `Enable ${username}? Any lock and failure count are cleared.`,
        confirmLabel: 'Enable',
      }
    case 'unlock':
      return {
        title: 'Unlock User',
        body: `Unlock ${username}? The lock and failure count are cleared.`,
        confirmLabel: 'Unlock',
      }
    case 'exempt':
      return {
        title: 'Dormancy Exemption',
        body: `Mark ${username} as never dormant? Use this for the recovery administrator.`,
        confirmLabel: 'Exempt',
      }
    case 'unexempt':
      return {
        title: 'Dormancy Exemption',
        body: `Remove the dormancy exemption from ${username}?`,
        confirmLabel: 'Remove exemption',
      }
  }
}

function firstMutationError(...muts: { isError: boolean; error: unknown }[]): string | null {
  for (const m of muts) {
    if (m.isError) return m.error instanceof Error ? m.error.message : 'Request failed'
  }
  return null
}

function ConfirmActionModal({
  title,
  body,
  confirmLabel,
  danger,
  isPending,
  onCancel,
  onConfirm,
}: {
  title: string
  body: string
  confirmLabel: string
  danger?: boolean
  isPending: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-sm">
        <h3 className="text-sm font-semibold text-text-primary mb-2">{title}</h3>
        <p className="text-text-muted text-xs mb-4">{body}</p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="flex-1 border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isPending}
            className={`flex-1 text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50 ${
              danger ? 'bg-status-error hover:bg-status-error/80' : 'bg-accent hover:bg-accent-hover'
            }`}
          >
            {isPending ? `${confirmLabel}...` : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

function roleBadgeTone(role: Role): string {
  switch (role) {
    case 'admin':
      return 'bg-accent/20 text-accent'
    case 'auditor':
      return 'bg-status-warning/20 text-status-warning'
    default:
      return 'bg-elevated text-text-muted'
  }
}

function roleLabel(role: Role): string {
  switch (role) {
    case 'admin':
      return 'Admin'
    case 'auditor':
      return 'Auditor'
    default:
      return 'Viewer'
  }
}

function ProfileTab() {
  const { user } = useAuth()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordErrors, setPasswordErrors] = useState<string[]>([])
  const [success, setSuccess] = useState('')
  const [avatarColor, setAvatarColor] = useState(() => getAvatarColor(user?.username ?? ''))
  const fileInputRef = useRef<HTMLInputElement>(null)
  const { login } = useAuth()

  const avatarMutation = useMutation({
    mutationFn: (avatar: string) =>
      apiFetch<{ status: string }>('/auth/avatar', {
        method: 'PUT',
        body: JSON.stringify({ avatar }),
      }),
    onSuccess: () => {
      // Refresh user data to get updated avatar
      apiFetch<User>('/auth/me').then(updatedUser => {
        login(updatedUser)
      })
    },
  })

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    if (!file.type.startsWith('image/')) return
    if (file.size > 500 * 1024) {
      alert('Image must be under 500KB. Resize to 128x128 or 256x256 for best results.')
      return
    }

    const reader = new FileReader()
    reader.onload = () => {
      const dataUrl = reader.result as string
      avatarMutation.mutate(dataUrl)
    }
    reader.readAsDataURL(file)
  }

  const handleRemoveAvatar = () => {
    avatarMutation.mutate('')
  }

  const runValidatePassword = (pw: string) => {
    const errors = validatePassword(pw)
    setPasswordErrors(errors)
    return errors.length === 0
  }

  const mutation = useMutation({
    mutationFn: (data: ChangePasswordRequest) =>
      apiFetch<{ status: string }>('/auth/password', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      setSuccess('Password updated successfully.')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setPasswordErrors([])
    },
  })

  const handleSubmit = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    setSuccess('')

    if (!runValidatePassword(newPassword)) return
    if (newPassword !== confirmPassword) {
      mutation.reset()
      return
    }

    mutation.mutate({
      current_password: currentPassword,
      new_password: newPassword,
    })
  }

  return (
    <div className="max-w-lg space-y-6">
      {/* Avatar */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Avatar</h3>
        <div className="bg-surface border border-border rounded p-4">
          <div className="flex items-center gap-4 mb-4">
            {user?.avatar ? (
              <img src={user.avatar} alt="" className="w-14 h-14 rounded-full object-cover shrink-0" />
            ) : (
              <div
                className="w-14 h-14 rounded-full flex items-center justify-center text-xl font-bold text-white shrink-0"
                style={{ backgroundColor: avatarColor }}
              >
                {user?.username?.charAt(0).toUpperCase()}
              </div>
            )}
            <div className="flex-1">
              <div className="text-sm text-text-primary font-medium">{user?.username}</div>
              <div className="text-xs text-text-muted mt-0.5">
                {user?.avatar ? 'Custom image' : 'Using initial with color'}
              </div>
              <div className="flex items-center gap-2 mt-2">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={avatarMutation.isPending}
                  className="flex items-center gap-1.5 bg-elevated border border-border rounded px-3 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
                >
                  <Upload className="w-3 h-3" />
                  {avatarMutation.isPending ? 'Uploading...' : 'Upload image'}
                </button>
                {user?.avatar && (
                  <button
                    type="button"
                    onClick={handleRemoveAvatar}
                    disabled={avatarMutation.isPending}
                    className="flex items-center gap-1 text-xs text-text-muted hover:text-status-error transition-colors"
                  >
                    <X className="w-3 h-3" />
                    Remove
                  </button>
                )}
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                onChange={handleFileUpload}
                className="hidden"
              />
            </div>
          </div>

          {avatarMutation.isError && (
            <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
              {avatarMutation.error instanceof Error ? avatarMutation.error.message : 'Failed to update avatar'}
            </div>
          )}

          <div className="border-t border-border pt-3">
            <div className="text-xs text-text-muted mb-2">
              {user?.avatar ? 'Fallback color (used if image is removed):' : 'Default color:'}
            </div>
            <div className="flex gap-2">
              {AVATAR_COLORS.map(color => (
                <button
                  key={color}
                  type="button"
                  onClick={() => { persistAvatarColor(color); setAvatarColor(color) }}
                  className={`w-6 h-6 rounded-full transition-all ${
                    avatarColor === color ? 'ring-2 ring-offset-2 ring-offset-surface ring-white scale-110' : 'hover:scale-110'
                  }`}
                  style={{ backgroundColor: color }}
                />
              ))}
            </div>
          </div>

          <div className="text-[10px] text-text-faint mt-3">
            For best results, use a square image (128x128 or 256x256 px), PNG or JPG, under 500KB.
          </div>
        </div>
      </div>

      {/* Account Info */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Account Info</h3>
        <div className="bg-surface border border-border rounded p-4 space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-text-muted">Username</span>
            <span className="text-text-primary">{user?.username}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-text-muted">Email</span>
            <span className="text-text-primary">{user?.email}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-text-muted">Role</span>
            <span className="text-text-primary capitalize">{user?.role}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-text-muted">2FA</span>
            <span className="text-status-online">Enabled</span>
          </div>
        </div>
      </div>

      {/* Change Password */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Change Password</h3>
        <form onSubmit={handleSubmit} className="space-y-3">
          {mutation.isError && (
            <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
              {mutation.error instanceof Error ? mutation.error.message : 'Failed to update password'}
            </div>
          )}
          {success && (
            <div className="bg-status-online/10 border border-status-online/20 text-status-online text-xs rounded px-3 py-2">
              {success}
            </div>
          )}

          <input
            type="password"
            placeholder="Current password"
            value={currentPassword}
            onChange={e => setCurrentPassword(e.target.value)}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
            required
          />
          <div>
            <input
              type="password"
              placeholder="New password (min 12 chars)"
              value={newPassword}
              onChange={e => { setNewPassword(e.target.value); runValidatePassword(e.target.value) }}
              className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
              required
            />
            {newPassword && passwordErrors.length > 0 && (
              <div className="mt-2 space-y-1">
                {passwordErrors.map(err => (
                  <div key={err} className="text-status-warning text-[10px]">• {err}</div>
                ))}
              </div>
            )}
          </div>
          <input
            type="password"
            placeholder="Confirm new password"
            value={confirmPassword}
            onChange={e => setConfirmPassword(e.target.value)}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
            required
          />
          {confirmPassword && newPassword !== confirmPassword && (
            <div className="text-status-warning text-[10px]">• Passwords do not match</div>
          )}
          <button
            type="submit"
            disabled={mutation.isPending || passwordErrors.length > 0 || newPassword !== confirmPassword}
            className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-4 py-2 transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? 'Updating...' : 'Update Password'}
          </button>
        </form>
      </div>
    </div>
  )
}

function UsersTab() {
  const { user: currentUser } = useAuth()
  const queryClient = useQueryClient()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [disableTotpUserId, setDisableTotpUserId] = useState<string | null>(null)
  const [adminTotpCode, setAdminTotpCode] = useState('')
  const [deleteUserId, setDeleteUserId] = useState<string | null>(null)
  const [deleteUsername, setDeleteUsername] = useState('')
  const [confirmAction, setConfirmAction] = useState<{ type: ConfirmActionType; user: User } | null>(null)

  const { data: usersData, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => apiFetch<{ users: User[] }>('/users'),
  })
  const users = usersData?.users

  const updateRoleMutation = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: Role }) =>
      apiFetch<{ user: User }>(`/users/${userId}/role`, {
        method: 'PUT',
        body: JSON.stringify({ role }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const deleteUserMutation = useMutation({
    mutationFn: (userId: string) =>
      apiFetch<{ status: string }>(`/users/${userId}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setDeleteUserId(null)
      setDeleteUsername('')
    },
  })

  const disableTotpMutation = useMutation({
    mutationFn: (data: TOTPDisableRequest) =>
      apiFetch<{ status: string }>('/auth/totp/disable', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setDisableTotpUserId(null)
      setAdminTotpCode('')
    },
  })

  const statusMutation = useMutation({
    mutationFn: ({ userId, disabled }: { userId: string; disabled: boolean }) =>
      apiFetch<{ user: User }>(`/users/${userId}/status`, {
        method: 'PUT',
        body: JSON.stringify({ disabled }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setConfirmAction(null)
    },
    onError: () => {
      setConfirmAction(null)
    },
  })

  const unlockMutation = useMutation({
    mutationFn: (userId: string) =>
      apiFetch<{ user: User }>(`/users/${userId}/unlock`, { method: 'POST' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setConfirmAction(null)
    },
    onError: () => {
      setConfirmAction(null)
    },
  })

  const exemptMutation = useMutation({
    mutationFn: ({ userId, exempt }: { userId: string; exempt: boolean }) =>
      apiFetch<{ user: User }>(`/users/${userId}/dormancy-exemption`, {
        method: 'PUT',
        body: JSON.stringify({ exempt }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setConfirmAction(null)
    },
    onError: () => {
      setConfirmAction(null)
    },
  })

  const openConfirm = (type: ConfirmActionType, user: User) => {
    statusMutation.reset()
    unlockMutation.reset()
    exemptMutation.reset()
    setConfirmAction({ type, user })
  }

  const handleConfirmAction = () => {
    if (!confirmAction) return
    const { type, user } = confirmAction
    switch (type) {
      case 'disable':
        statusMutation.mutate({ userId: user.id, disabled: true })
        break
      case 'enable':
        statusMutation.mutate({ userId: user.id, disabled: false })
        break
      case 'unlock':
        unlockMutation.mutate(user.id)
        break
      case 'exempt':
        exemptMutation.mutate({ userId: user.id, exempt: true })
        break
      case 'unexempt':
        exemptMutation.mutate({ userId: user.id, exempt: false })
        break
    }
  }

  const actionBannerError = firstMutationError(updateRoleMutation, statusMutation, unlockMutation, exemptMutation)

  const handleDisableTotp = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!disableTotpUserId) return
    disableTotpMutation.mutate({
      user_id: disableTotpUserId,
      admin_totp_code: adminTotpCode,
    })
  }

  const formatDate = (iso: string) => {
    const date = new Date(iso)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
    if (diffDays === 0) return 'Today'
    if (diffDays === 1) return 'Yesterday'
    if (diffDays < 30) return `${diffDays} days ago`
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  // Exact local date-time for the "Last login" cell's title attribute.
  const formatDateTime = (iso: string) => new Date(iso).toLocaleString()

  const lockedUntilLabel = (lockedUntil: string) => {
    if (isNoAutoUnlock(lockedUntil)) return 'Locked (no auto-unlock)'
    const hh = new Date(lockedUntil).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
    return `Locked until ${hh}`
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-text-primary">User Management</h3>
        <button
          type="button"
          onClick={() => setShowCreateModal(true)}
          className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-4 py-1.5 transition-colors"
        >
          Create User
        </button>
      </div>

      <AccountPolicyCard />

      {actionBannerError && (
        <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
          {actionBannerError}
        </div>
      )}

      <div className="border border-border rounded overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-surface border-b border-border">
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Username</th>
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Email</th>
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Role</th>
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">2FA</th>
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Last login</th>
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Status</th>
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Created</th>
              <th className="text-left px-4 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-text-muted">Loading...</td></tr>
            )}
            {!isLoading && (!users || users.length === 0) && (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-text-muted">No users found.</td></tr>
            )}
            {!isLoading && users && users.length > 0 && users.map(u => {
              const status = effectiveStatus(u)
              const disabledByUsername = u.disabled_by ? users.find(x => x.id === u.disabled_by)?.username : undefined
              const isExemptAdmin = !!u.dormancy_exempt && u.role === 'admin'
              return (
              <tr key={u.id} className={`border-b border-border last:border-b-0 hover:bg-surface/50 ${status === 'disabled' ? 'opacity-60' : ''}`}>
                <td className="px-4 py-2 text-text-primary">{u.username}</td>
                <td className="px-4 py-2 text-text-secondary">{u.email}</td>
                <td className="px-4 py-2">
                  {u.id === currentUser?.id ? (
	                    <span className={`text-xs px-2 py-0.5 rounded ${roleBadgeTone(u.role)}`}>
	                      {/* c8 ignore next */}
	                      {roleLabel(u.role)}
	                    </span>
                  ) : (
                    <select
                      value={u.role}
                      onChange={e => updateRoleMutation.mutate({ userId: u.id, role: e.target.value as Role })}
                      disabled={updateRoleMutation.isPending}
                      className="bg-elevated border border-border rounded px-2 py-0.5 text-xs text-text-primary focus:outline-none focus:border-accent"
                    >
                      <option value="admin">Admin</option>
                      <option value="auditor">Auditor</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  )}
                </td>
                <td className="px-4 py-2">
                  {u.totp_enabled ? (
                    <span className="text-xs text-status-online">Enabled</span>
                  ) : (
                    <span className="text-xs text-status-warning">Not set up</span>
                  )}
                </td>
                <td className="px-4 py-2 text-xs">
                  {u.last_login_at ? (
                    <span className="text-text-secondary" title={formatDateTime(u.last_login_at)}>
                      {formatRelative(u.last_login_at)}
                    </span>
                  ) : (
                    <span className="text-text-muted">Never</span>
                  )}
                </td>
                <td className="px-4 py-2 text-xs">
                  <div className="flex items-center gap-1.5">
                    {status === 'disabled' && (
                      <span
                        className="text-xs px-2 py-0.5 rounded bg-elevated text-text-muted border border-border"
                        title={`Disabled ${u.disabled_at ? formatDate(u.disabled_at) : ''}${disabledByUsername ? ` by ${disabledByUsername}` : ''}`}
                      >
                        Disabled
                      </span>
                    )}
                    {status === 'dormant' && (
                      <span
                        className="text-xs px-2 py-0.5 rounded bg-status-warning/20 text-status-warning"
                        title={`Last activity ${u.last_activity_at ? formatRelative(u.last_activity_at) : 'never'}`}
                      >
                        Dormant
                      </span>
                    )}
                    {status === 'locked' && u.locked_until && (
                      <span className="text-status-warning" title={`${u.failed_login_count ?? 0} failed attempts`}>
                        {lockedUntilLabel(u.locked_until)}
                      </span>
                    )}
                    {status === 'active' && (
                      <span className="text-text-muted">Active</span>
                    )}
                    {isExemptAdmin && (
                      <span className="text-text-faint text-[10px]" title="Exempt from dormancy">
                        Never dormant
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-2 text-text-muted text-xs">{formatDate(u.created_at)}</td>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-3 flex-wrap">
                    {u.id !== currentUser?.id && u.totp_enabled && (
                      <button
                        type="button"
                        onClick={() => setDisableTotpUserId(u.id)}
                        className="text-xs text-status-warning hover:text-status-error transition-colors"
                      >
                        Disable 2FA
                      </button>
                    )}
                    {u.id !== currentUser?.id && status === 'locked' && (
                      <button
                        type="button"
                        onClick={() => openConfirm('unlock', u)}
                        className="text-xs text-text-secondary hover:text-text-primary transition-colors"
                      >
                        Unlock
                      </button>
                    )}
                    {u.id !== currentUser?.id && status !== 'disabled' && (
                      <button
                        type="button"
                        onClick={() => openConfirm('disable', u)}
                        className="text-xs text-status-warning hover:text-status-error transition-colors"
                      >
                        Disable
                      </button>
                    )}
                    {u.id !== currentUser?.id && status === 'disabled' && (
                      <button
                        type="button"
                        onClick={() => openConfirm('enable', u)}
                        className="text-xs text-status-online transition-colors"
                      >
                        Enable
                      </button>
                    )}
                    {u.id !== currentUser?.id && u.role === 'admin' && (
                      <button
                        type="button"
                        onClick={() => openConfirm(isExemptAdmin ? 'unexempt' : 'exempt', u)}
                        className="text-xs text-text-muted hover:text-text-primary transition-colors"
                      >
                        {isExemptAdmin ? 'Remove exemption' : 'Exempt from dormancy'}
                      </button>
                    )}
                    {u.id !== currentUser?.id && (
                      <button
                        type="button"
                        onClick={() => { setDeleteUserId(u.id); setDeleteUsername(u.username) }}
                        className="text-xs text-text-muted hover:text-status-error transition-colors"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <CreateUserModal onClose={() => setShowCreateModal(false)} />
      )}

      {/* Disable TOTP Confirmation Modal */}
      {disableTotpUserId && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-sm">
            <h3 className="text-sm font-semibold text-text-primary mb-2">Disable 2FA</h3>
            <p className="text-text-muted text-xs mb-4">
              Enter your own TOTP code to confirm disabling 2FA for this user.
            </p>

            {disableTotpMutation.isError && (
              <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
                {disableTotpMutation.error instanceof Error ? disableTotpMutation.error.message : 'Failed to disable 2FA'}
              </div>
            )}

            <form onSubmit={handleDisableTotp}>
              <input
                type="text"
                placeholder="Your 6-digit TOTP code"
                value={adminTotpCode}
                onChange={e => setAdminTotpCode(e.target.value)}
                className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent mb-4 font-mono text-center tracking-widest"
                maxLength={6}
                autoFocus
                required
              />
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => { setDisableTotpUserId(null); setAdminTotpCode('') }}
                  className="flex-1 border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={disableTotpMutation.isPending || adminTotpCode.length !== 6}
                  className="flex-1 bg-status-error hover:bg-status-error/80 text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50"
                >
                  {/* c8 ignore next */}
                  {disableTotpMutation.isPending ? 'Disabling...' : 'Disable 2FA'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete User Confirmation Modal */}
      {deleteUserId && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-sm">
            <h3 className="text-sm font-semibold text-text-primary mb-2">Delete User</h3>
            <p className="text-text-muted text-xs mb-4">
              Are you sure you want to delete <span className="text-text-primary font-medium">"{deleteUsername}"</span>? This cannot be undone.
            </p>

            {deleteUserMutation.isError && (
              <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
                {deleteUserMutation.error instanceof Error ? deleteUserMutation.error.message : 'Failed to delete user'}
              </div>
            )}

            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => { setDeleteUserId(null); setDeleteUsername(''); deleteUserMutation.reset() }}
                className="flex-1 border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => deleteUserMutation.mutate(deleteUserId)}
                disabled={deleteUserMutation.isPending}
                className="flex-1 bg-status-error hover:bg-status-error/80 text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50"
              >
                {/* c8 ignore next */}
                {deleteUserMutation.isPending ? 'Deleting...' : 'Delete User'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Disable / Enable / Unlock / Dormancy exemption Confirmation Modal */}
      {confirmAction && (() => {
        const copy = confirmCopyFor(confirmAction.type, confirmAction.user.username)
        return (
          <ConfirmActionModal
            title={copy.title}
            body={copy.body}
            confirmLabel={copy.confirmLabel}
            danger={copy.danger}
            isPending={statusMutation.isPending || unlockMutation.isPending || exemptMutation.isPending}
            onCancel={() => setConfirmAction(null)}
            onConfirm={handleConfirmAction}
          />
        )
      })()}
    </div>
  )
}

export function SettingsPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [searchParams, setSearchParams] = useSearchParams()
  const tabFromUrl = searchParams.get('tab')

  const resolveTab = (): 'profile' | 'users' | 'directory' | 'notifications' | 'alerts' => {
    if (tabFromUrl === 'users' && isAdmin) return 'users'
    if (tabFromUrl === 'directory' && isAdmin) return 'directory'
    if (tabFromUrl === 'notifications' && isAdmin) return 'notifications'
    if (tabFromUrl === 'alerts') return 'alerts'
    return 'profile'
  }

  const activeTab = resolveTab()

  const setActiveTab = (tab: 'profile' | 'users' | 'directory' | 'notifications' | 'alerts') => {
    setSearchParams({ tab }, { replace: true })
  }

  return (
    <div className="p-6">
      <h2 className="text-lg font-semibold text-text-primary mb-4">Settings</h2>

      {/* Tab bar */}
      <div className="flex border-b border-border mb-6">
        <button
          type="button"
          onClick={() => setActiveTab('profile')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'profile'
              ? 'border-accent text-text-primary'
              : 'border-transparent text-text-muted hover:text-text-secondary'
          }`}
        >
          Profile
        </button>
        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab('users')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'users'
                ? 'border-accent text-text-primary'
                : 'border-transparent text-text-muted hover:text-text-secondary'
            }`}
          >
            Users
          </button>
        )}
        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab('directory')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'directory'
                ? 'border-accent text-text-primary'
                : 'border-transparent text-text-muted hover:text-text-secondary'
            }`}
          >
            Directory
          </button>
        )}
        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab('notifications')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'notifications'
                ? 'border-accent text-text-primary'
                : 'border-transparent text-text-muted hover:text-text-secondary'
            }`}
          >
            Notifications
          </button>
        )}
        <button
          type="button"
          onClick={() => setActiveTab('alerts')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'alerts'
              ? 'border-accent text-text-primary'
              : 'border-transparent text-text-muted hover:text-text-secondary'
          }`}
        >
          Alerts
        </button>
      </div>

      {/* Tab content */}
      {activeTab === 'profile' && <ProfileTab />}
      {activeTab === 'users' && isAdmin && <UsersTab />}
      {activeTab === 'directory' && isAdmin && <DirectoryTab />}
      {activeTab === 'notifications' && isAdmin && <NotificationsTab />}
      {activeTab === 'alerts' && <PreferencesTab />}
    </div>
  )
}
