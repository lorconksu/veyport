import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiFetch } from '@/lib/api'
import { validatePassword } from '@/lib/password'
import type { RegisterRequest, AuthStatusResponse } from '@/types/api'

export function SetupPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [passwordErrors, setPasswordErrors] = useState<string[]>([])

  useEffect(() => {
    apiFetch<AuthStatusResponse>('/auth/status')
      .then(resp => {
        if (resp.initialized) navigate('/login')
      })
      .catch(() => {})
  }, [navigate])

  const runValidatePassword = (pw: string) => {
    const errors = validatePassword(pw)
    setPasswordErrors(errors)
    return errors.length === 0
  }

  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!runValidatePassword(password)) return

    setError('')
    setLoading(true)

    try {
      const resp = await apiFetch<{ setup_token: string }>('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ username, email, password } satisfies RegisterRequest),
      })

      navigate('/setup/totp', { state: { setupToken: resp.setup_token } })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="text-text-muted text-[10px] uppercase tracking-widest mb-4">Create Admin Account</div>

      {error && (
        <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-4">
          {error}
        </div>
      )}

      <div className="space-y-3">
        <input
          type="text" placeholder="username" value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          required
        />
        <input
          type="email" placeholder="email" value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          required
        />
        <div>
          <input
            type="password" placeholder="password (min 12 chars)" value={password}
            onChange={(e) => { setPassword(e.target.value); runValidatePassword(e.target.value) }}
            className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
            required
          />
          {password && passwordErrors.length > 0 && (
            <div className="mt-2 space-y-1">
              {passwordErrors.map(err => (
                <div key={err} className="text-status-warning text-[10px]">• {err}</div>
              ))}
            </div>
          )}
        </div>
        <button
          type="submit" disabled={loading}
          className="w-full bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50"
        >
          {loading ? 'Creating...' : 'Create Account'}
        </button>
      </div>
    </form>
  )
}
