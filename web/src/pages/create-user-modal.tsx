import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Eye, EyeOff } from 'lucide-react'
import { apiFetch } from '@/lib/api'
import type { CreateUserRequest, CreateUserResponse, Role } from '@/types/api'

interface CreateUserModalProps {
  onClose: () => void
}

export function CreateUserModal({ onClose }: Readonly<CreateUserModalProps>) {
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [tempPassword, setTempPassword] = useState('')
  const [copied, setCopied] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const mutation = useMutation({
    mutationFn: (data: CreateUserRequest) =>
      apiFetch<CreateUserResponse>('/users', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: (data) => {
      setTempPassword(data.temporary_password)
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const handleSubmit = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    mutation.mutate({ username, email, role })
  }

  const copyPassword = async () => {
    await navigator.clipboard.writeText(tempPassword)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-md">
        {tempPassword ? (
          // Success state — show temporary password
          <div>
            <h3 className="text-sm font-semibold text-text-primary mb-4">User Created</h3>
            <p className="text-text-muted text-xs mb-3">
              Share this temporary password with the user. It will not be shown again.
            </p>
            <div className="flex items-center gap-2 mb-4">
              <code className="flex-1 bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary font-mono select-all">
                {showPassword ? tempPassword : '••••••••••••••••'}
              </code>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="px-2 py-2 text-text-muted hover:text-text-primary transition-colors"
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
              <button
                type="button"
                onClick={copyPassword}
                className="px-3 py-2 bg-accent hover:bg-accent-hover text-white text-sm rounded transition-colors"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="w-full border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated transition-colors"
            >
              Done
            </button>
          </div>
        ) : (
          // Form state
          <form onSubmit={handleSubmit}>
            <h3 className="text-sm font-semibold text-text-primary mb-4">Create User</h3>

            {mutation.isError && (
              <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
                {mutation.error instanceof Error ? mutation.error.message : 'Failed to create user'}
              </div>
            )}

            <div className="space-y-3">
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                autoFocus
                required
              />
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
                required
              />
              <select
                value={role}
                onChange={e => setRole(e.target.value as Role)}
                className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent"
              >
                <option value="viewer">Viewer</option>
                <option value="auditor">Auditor</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div className="flex gap-2 mt-4">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={mutation.isPending}
                className="flex-1 bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50"
              >
                {mutation.isPending ? 'Creating...' : 'Create User'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
