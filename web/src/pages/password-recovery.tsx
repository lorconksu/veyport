import { useState } from 'react'
import { apiFetchWithToken } from '@/lib/api'
import { validatePassword } from '@/lib/password'
import { useSensitiveTask } from '@/hooks/use-sensitive-task'
import type { PasswordRecoveryResponse } from '@/types/api'

// Recovery authority stays in the MFA page's local state. It is never installed
// as a session, placed in router/history state or retained in a query cache.
export function PasswordRecoveryForm({ recovery, onComplete, onCancel }: Readonly<{
  recovery: PasswordRecoveryResponse
  onComplete: () => void
  onCancel: () => void
}>) {
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const task = useSensitiveTask()
  const policyErrors = validatePassword(password)
  const submit = async (event: React.SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (task.busy || password !== confirmation || policyErrors.length) return
    setError('')
    try {
      await task.run(signal => apiFetchWithToken<{ requires_login: true }>('/auth/password/recovery', recovery.recovery_token, {
        method: 'POST', signal, cache: 'no-store', body: JSON.stringify({ new_password: password }),
      }))
      setPassword(''); setConfirmation(''); onComplete()
    } catch (err) {
      if (!(err instanceof DOMException && err.name === 'AbortError')) setError('Password change could not be completed. Check password policy and history, or cancel and sign in again if this recovery has expired or changed.')
    }
  }
  const cancel = () => { task.cancel(); setPassword(''); setConfirmation(''); onCancel() }
  return <form onSubmit={event => void submit(event)} className="space-y-3">
    <h2 className="text-sm font-semibold text-text-primary">Change temporary password</h2>
    <p className="text-xs text-text-muted">MFA verified. Set a permanent password before accessing Veyport. After completion, sign in again with your new password and existing MFA.</p>
    <p className="text-xs text-text-muted">Recovery expires: <time dateTime={recovery.expires_at}>{new Date(recovery.expires_at).toLocaleString()}</time></p>
    {error && <p role="alert" className="text-xs text-status-error">{error}</p>}
    <label className="block text-xs text-text-secondary">New password<input type="password" autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} required className="block w-full mt-1 bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" /></label>
    <label className="block text-xs text-text-secondary">Confirm new password<input type="password" autoComplete="new-password" value={confirmation} onChange={event => setConfirmation(event.target.value)} required className="block w-full mt-1 bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" /></label>
    {password && policyErrors.map(message => <p key={message} className="text-xs text-status-warning">{message}</p>)}
    {confirmation && confirmation !== password && <p className="text-xs text-status-warning">Passwords do not match.</p>}
    <button type="submit" disabled={task.busy || !password || password !== confirmation || policyErrors.length > 0} className="w-full bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded py-2 disabled:opacity-50">{task.busy ? 'Changing...' : 'Change password and return to sign-in'}</button>
    <button type="button" onClick={cancel} className="w-full border border-border rounded py-2 text-sm text-text-secondary">Cancel and return to sign-in</button>
  </form>
}
