import { safeApplicationReturn } from '@/lib/application-launch'
import { useState, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { apiFetch } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import type { LoginTOTPRequest, AuthResponse, PasswordRecoveryResponse } from '@/types/api'
import { PasswordRecoveryForm } from '@/pages/password-recovery'
import { useTOTPDigits, TOTPDigitInput } from '@/components/totp-digit-input'

export function LoginTOTPPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuth()
  // Security: TOTP token is passed via React Router state (in-memory only, not in URL)
  const totpToken = (location.state as { totpToken?: string })?.totpToken

  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [recovery, setRecovery] = useState<PasswordRecoveryResponse | null>(null)
  const { digits, inputRefs, handleDigitChange, handlePaste, handleKeyDown, reset } = useTOTPDigits(submitCode)

  async function submitCode(code: string) {
    if (!totpToken) return
    setError('')
    setLoading(true)

    try {
      const resp = await apiFetch<AuthResponse | PasswordRecoveryResponse>('/auth/login/totp', {
        method: 'POST',
        body: JSON.stringify({ totp_token: totpToken, code } satisfies LoginTOTPRequest),
      })

      if ('recovery_token' in resp) {
        reset()
        setRecovery(resp)
        return
      }

      login(resp.user)
      navigate(safeApplicationReturn((location.state as { returnTo?: unknown } | null)?.returnTo), { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed')
      reset()
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!totpToken) navigate('/login')
  }, [totpToken, navigate])

  /* c8 ignore next */
  const handleVerifyClick = () => submitCode(digits.join(''))

  if (recovery) {
    const returnToSignIn = () => { setRecovery(null); navigate('/login', { replace: true, state: null }) }
    return <PasswordRecoveryForm recovery={recovery} onComplete={returnToSignIn} onCancel={returnToSignIn} />
  }

  return (
    <div>
      <div className="text-text-muted text-[10px] uppercase tracking-widest mb-2">Two-Factor Authentication</div>
      <p className="text-text-faint text-xs mb-4">Enter the 6-digit code from your authenticator app</p>

      {error && (
        <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-4">
          {error}
        </div>
      )}

      <TOTPDigitInput
        digits={digits}
        inputRefs={inputRefs}
        handleDigitChange={handleDigitChange}
        handlePaste={handlePaste}
        handleKeyDown={handleKeyDown}
        disabled={loading}
      />

      <button
        type="button"
        onClick={handleVerifyClick}
        disabled={loading || digits.includes('')}
        className="w-full bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50"
      >
        {loading ? 'Verifying...' : 'Verify'}
      </button>
    </div>
  )
}
