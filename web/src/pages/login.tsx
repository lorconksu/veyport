import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiFetch } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import type { LoginRequest, LoginResponse, AuthResponse, AuthStatusResponse } from '@/types/api'

export function LoginPage() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    apiFetch<AuthStatusResponse>('/auth/status')
      .then(resp => {
        if (!resp.initialized) navigate('/setup', { replace: true })
      })
      .catch(() => {})
  }, [navigate])

  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      // Use raw fetch for login — apiFetch's auto-refresh on 401 would
      // redirect to /login instead of showing the "invalid credentials" error.
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password } satisfies LoginRequest),
        credentials: 'same-origin',
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Login failed' }))
        throw new Error((body as { error?: string }).error || 'Login failed')
      }

      const resp = await res.json() as LoginResponse | AuthResponse

      if ('user' in resp && resp.user) {
        login(resp.user)
        navigate('/')
        return
      }

      if ('requires_totp_setup' in resp && resp.requires_totp_setup && resp.setup_token) {
        navigate('/setup/totp', { state: { setupToken: resp.setup_token, mustChangePassword: resp.must_change_password === true } })
      } else if ('totp_token' in resp && resp.totp_token) {
        navigate('/login/totp', { state: { totpToken: resp.totp_token } })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="text-text-muted text-[10px] uppercase tracking-widest mb-4">Sign In</div>

      {error && (
        <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-4">
          {error}
        </div>
      )}

      <div className="space-y-3">
        <input
          type="text"
          placeholder="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          autoFocus
          required
        />
        <input
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
          required
        />
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
      </div>
    </form>
  )
}
