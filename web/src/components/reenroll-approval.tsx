import { useState } from 'react'
import { AlertTriangle, ShieldCheck, ShieldX } from 'lucide-react'
import { TOTPDigitInput, useTOTPDigits } from './totp-digit-input'
import { useApproveReEnroll, useDenyReEnroll } from '@/hooks/use-reenroll'
import type { ReEnrollRequest } from '@/types/api'

interface AnomalyFlags {
  fingerprint_changed?: boolean
  original_online?: boolean
}

function parseAnomalyFlags(flagsJson: string): AnomalyFlags {
  try {
    return JSON.parse(flagsJson) as AnomalyFlags
  } catch {
    return {}
  }
}

function isCloneRisk(flags: AnomalyFlags): boolean {
  return Boolean(flags.fingerprint_changed || flags.original_online)
}

interface ReEnrollApprovalProps {
  request: ReEnrollRequest
}

export function ReEnrollApproval({ request }: Readonly<ReEnrollApprovalProps>) {
  const [showTOTP, setShowTOTP] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<'approved' | 'denied' | null>(null)

  const approveMutation = useApproveReEnroll()
  const denyMutation = useDenyReEnroll()

  const flags = parseAnomalyFlags(request.anomaly_flags ?? '{}')
  const cloneRisk = isCloneRisk(flags)

  const handleApproveClick = () => {
    setError(null)
    setShowTOTP(true)
  }

  const handleDenyClick = () => {
    setError(null)
    denyMutation.mutate(
      { serverId: request.server_id, requestId: request.id },
      {
        onSuccess: () => setSuccess('denied'),
        onError: (err) => setError(err instanceof Error ? err.message : 'Failed to deny request'),
      },
    )
  }

  const handleTOTPComplete = (code: string) => {
    setError(null)
    approveMutation.mutate(
      { serverId: request.server_id, requestId: request.id, totpCode: code },
      {
        onSuccess: () => setSuccess('approved'),
        onError: (err) => {
          setError(err instanceof Error ? err.message : 'Failed to approve request')
          reset()
        },
      },
    )
  }

  const { digits, inputRefs, handleDigitChange, handlePaste, handleKeyDown, reset } =
    useTOTPDigits(handleTOTPComplete)

  if (success === 'approved') {
    return (
      <div className="flex items-center gap-2 bg-status-online/10 border border-status-online/20 text-status-online text-sm rounded px-4 py-3">
        <ShieldCheck className="w-4 h-4 shrink-0" />
        Re-enrollment approved. The agent will reconnect with its new certificate.
      </div>
    )
  }

  if (success === 'denied') {
    return (
      <div className="flex items-center gap-2 bg-status-error/10 border border-status-error/20 text-status-error text-sm rounded px-4 py-3">
        <ShieldX className="w-4 h-4 shrink-0" />
        Re-enrollment denied.
      </div>
    )
  }

  return (
    <div className="border border-status-warning/30 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 bg-status-warning/10 px-4 py-3 border-b border-status-warning/20">
        <AlertTriangle className="w-4 h-4 text-status-warning shrink-0" />
        <span className="text-sm font-medium text-text-primary">Pending Re-Enrollment Request</span>
      </div>

      <div className="px-4 py-3 space-y-3 bg-surface/50">
        {/* Clone warning */}
        {cloneRisk && (
          <div
            role="alert"
            className="flex items-start gap-2 bg-status-error/10 border border-status-error/30 text-status-error text-sm rounded px-3 py-2"
          >
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">⚠️ Possible clone — verify before approving</p>
              <ul className="mt-1 space-y-0.5 text-xs text-status-error/80">
                {flags.fingerprint_changed && (
                  <li>Node fingerprint has changed since last registration.</li>
                )}
                {flags.original_online && (
                  <li>Original node is still online — a second instance may be impersonating this server.</li>
                )}
              </ul>
            </div>
          </div>
        )}

        {/* Request details */}
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-text-secondary">
          {request.ip_address && (
            <>
              <span className="text-text-muted">Requesting IP</span>
              <span className="font-mono">{request.ip_address}</span>
            </>
          )}
          {request.fingerprint && (
            <>
              <span className="text-text-muted">Fingerprint</span>
              <span className="font-mono truncate">{request.fingerprint}</span>
            </>
          )}
          {request.requested_at && (
            <>
              <span className="text-text-muted">Requested</span>
              <span>{new Date(request.requested_at).toLocaleString()}</span>
            </>
          )}
        </div>

        {/* TOTP step-up */}
        {showTOTP && (
          <div className="border-t border-border pt-3 space-y-2">
            <p className="text-sm text-text-primary font-medium">
              Enter TOTP authenticator code to confirm approval
            </p>
            <TOTPDigitInput
              digits={digits}
              inputRefs={inputRefs}
              handleDigitChange={handleDigitChange}
              handlePaste={handlePaste}
              handleKeyDown={handleKeyDown}
              disabled={approveMutation.isPending}
            />
            <p className="text-xs text-text-muted text-center">
              Enter the 6-digit code from your authenticator app
            </p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
            {error}
          </div>
        )}

        {/* Actions */}
        {!showTOTP && (
          <div className="flex items-center gap-2 pt-1">
            <button
              type="button"
              onClick={handleApproveClick}
              disabled={approveMutation.isPending || denyMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm rounded transition-colors disabled:opacity-50"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Approve
            </button>
            <button
              type="button"
              onClick={handleDenyClick}
              disabled={denyMutation.isPending || approveMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-status-error/15 hover:bg-status-error/25 text-status-error text-sm rounded border border-status-error/30 transition-colors disabled:opacity-50"
            >
              <ShieldX className="w-3.5 h-3.5" />
              {denyMutation.isPending ? 'Denying...' : 'Deny'}
            </button>
          </div>
        )}

        {showTOTP && (
          <div className="flex items-center gap-2 pt-1">
            <button
              type="button"
              onClick={() => { setShowTOTP(false); reset() }}
              disabled={approveMutation.isPending}
              className="px-3 py-1.5 bg-elevated hover:bg-border text-text-secondary text-sm rounded transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
