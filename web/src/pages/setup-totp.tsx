import { useState, useEffect, useRef, useCallback } from 'react'
import QRCode from 'qrcode'
import { useLocation, useNavigate } from 'react-router-dom'
import { Copy, Check } from 'lucide-react'
import { apiFetchWithToken } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import { validatePassword } from '@/lib/password'
import type { TOTPSetupResponse, TOTPEnableRequest, AuthResponse } from '@/types/api'
import { useTOTPDigits, TOTPDigitInput } from '@/components/totp-digit-input'

export function SetupTOTPPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuth()
  // Security: setupToken is passed via React Router state (in-memory only, not in URL)
  const setupState = (location.state as { setupToken?: string; mustChangePassword?: boolean }) ?? {}
  const setupToken = setupState.setupToken
  const mustChangePassword = setupState.mustChangePassword === true

  const [totpData, setTotpData] = useState<TOTPSetupResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordErrors, setPasswordErrors] = useState<string[]>([])
  const hasFetched = useRef(false)
  const qrCanvasRef = useRef<HTMLCanvasElement>(null)

  const renderQR = useCallback((qrUrl: string) => {
    if (!qrCanvasRef.current) return
    QRCode.toCanvas(qrCanvasRef.current, qrUrl, { width: 192, margin: 2 })
  }, [])

  const submitCode = async (code: string) => {
    if (!setupToken) return
    setError('')
    setLoading(true)

    try {
      if (mustChangePassword) {
        const errors = validatePassword(newPassword)
        setPasswordErrors(errors)
        if (errors.length > 0) {
          throw new Error(errors[0] || 'New password does not meet policy')
        }
        if (newPassword !== confirmPassword) {
          throw new Error('New password confirmation does not match')
        }
      }
      const resp = await apiFetchWithToken<AuthResponse>('/auth/totp/enable', setupToken, {
        method: 'POST',
        body: JSON.stringify({ code, new_password: mustChangePassword ? newPassword : undefined } satisfies TOTPEnableRequest),
      })

      login(resp.user)
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed')
      reset()
    } finally {
      setLoading(false)
    }
  }

  const { digits, inputRefs, handleDigitChange, handlePaste, handleKeyDown, reset } = useTOTPDigits(submitCode)

  /* c8 ignore next */
  const handleVerifyClick = () => submitCode(digits.join(''))

  useEffect(() => {
    if (!setupToken) { navigate('/login'); return }
    if (hasFetched.current) return
    hasFetched.current = true

    apiFetchWithToken<TOTPSetupResponse>('/auth/totp/setup', setupToken, { method: 'POST' })
      .then(setTotpData)
      .catch(() => setError('Failed to generate TOTP secret'))
  }, [setupToken, navigate])

  return (
    <div>
      <div className="text-text-muted text-[10px] uppercase tracking-widest mb-2">Set Up Two-Factor Authentication</div>
      <p className="text-text-faint text-xs mb-4">Scan this QR code with your authenticator app, then enter the 6-digit code</p>

      {error && (
        <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-4">
          {error}
        </div>
      )}

      {totpData && (
        <>
          <div className="bg-white rounded-lg p-4 mb-4 flex items-center justify-center">
            <canvas ref={(el) => { qrCanvasRef.current = el; if (el) renderQR(totpData.qr_url) }} />
          </div>

          <div className="bg-elevated border border-border rounded px-3 py-2 mb-4">
            <div className="flex items-center justify-between mb-1">
              <div className="text-text-muted text-[10px] uppercase tracking-widest">Manual Entry Key</div>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(totpData.secret)
                  setCopied(true)
                  setTimeout(() => setCopied(false), 2000)
                }}
                className="flex items-center gap-1 text-text-muted hover:text-text-primary text-[10px] uppercase tracking-wider transition-colors"
              >
                {copied ? <Check className="w-3 h-3 text-status-online" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <code className="text-text-primary text-xs font-mono break-all select-all">{totpData.secret}</code>
          </div>

          <TOTPDigitInput
            digits={digits}
            inputRefs={inputRefs}
            handleDigitChange={handleDigitChange}
            handlePaste={handlePaste}
            handleKeyDown={handleKeyDown}
            disabled={loading}
          />

          {mustChangePassword && (
            <div className="space-y-3 mb-4">
              <div className="text-xs text-text-muted">
                This account was created with a temporary password. Set a permanent password now.
              </div>
              <input
                type="password"
                placeholder="New password"
                value={newPassword}
                onChange={e => {
                  setNewPassword(e.target.value)
                  setPasswordErrors(validatePassword(e.target.value))
                }}
                className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
              />
              <input
                type="password"
                placeholder="Confirm new password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                className="w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:outline-none focus:border-accent"
              />
              {newPassword && passwordErrors.length > 0 && (
                <div className="space-y-1">
                  {passwordErrors.map(err => (
                    <div key={err} className="text-status-warning text-[10px]">• {err}</div>
                  ))}
                </div>
              )}
            </div>
          )}

          <button
            type="button"
            onClick={handleVerifyClick}
            disabled={loading || digits.includes('')}
            className="w-full bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50"
          >
            {loading ? 'Verifying...' : 'Verify & Enable 2FA'}
          </button>
        </>
      )}
    </div>
  )
}
