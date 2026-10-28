import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetchOnce, ApiError } from '@/lib/api'
import { useSensitiveTask } from '@/hooks/use-sensitive-task'
import type { ResetPasswordResponse, User } from '@/types/api'
import { useDialogFocus } from '@/hooks/use-dialog-focus'

const lifecycleActions = { dormant: 'Reactivate', disabled: 'Enable', locked: 'Unlock', active: '' }

export function ResetPasswordModal({ user, onClose }: Readonly<{ user: User; onClose: () => void }>) {
  const queryClient = useQueryClient()
  const task = useSensitiveTask()
  const [result, setResult] = useState<ResetPasswordResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [copyFailed, setCopyFailed] = useState(false)
  const dialogRef = useDialogFocus(result ? 'result' : 'confirmation')
  // The mutation resolves without returning the credential. Only this mounted
  // dialog owns the response; TanStack's settled mutation cache contains no secret.
  const mutation = useMutation({
    retry: false,
    gcTime: 0,
    mutationFn: async () => {
      const response = await task.run(signal => apiFetchOnce<ResetPasswordResponse>(`/users/${user.id}/password-reset`, {
        method: 'POST', cache: 'no-store', signal,
        body: JSON.stringify({ expected_revision: user.credential_revision }),
      }))
      setResult(response)
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['users'] })
      void queryClient.invalidateQueries({ queryKey: ['sessions'] })
      void queryClient.invalidateQueries({ queryKey: ['my-sessions'] })
    },
  })
  const close = () => { task.cancel(); setResult(null); mutation.reset(); onClose() }
  const copy = async () => {
    if (!result) return
    try { await navigator.clipboard.writeText(result.temporary_password); setCopied(true); setCopyFailed(false) }
    catch { setCopyFailed(true) }
  }
  const conflict = mutation.error instanceof ApiError && mutation.error.status === 409
  return <div className="fixed inset-0 flex items-center justify-center z-50 p-4">
    <dialog ref={dialogRef} tabIndex={-1} onCancel={event => { event.preventDefault(); close() }} aria-labelledby="reset-password-title" className="fixed inset-0 m-auto h-fit max-h-[calc(100dvh_-_2rem)] overflow-y-auto backdrop:bg-black/50 bg-surface border border-border rounded-lg p-6 w-[calc(100%_-_2rem)] max-w-md">
      <h3 id="reset-password-title" className="text-sm font-semibold text-text-primary mb-2">{result ? 'Temporary password generated' : 'Reset local password'}</h3>
      <p className="text-xs text-text-secondary mb-4">{user.username} · Local</p>
      {result ? <>
        <p className="text-sm text-text-muted mb-3">Shown once. Share privately with the user. They must change it at sign-in; existing MFA remains required. Closing this dialog permanently hides this password.</p>
        <code className="block break-all bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary select-all">{result.temporary_password}</code>
        <p className="text-xs text-text-muted mt-3">Expires: <time dateTime={result.expires_at}>{new Date(result.expires_at).toLocaleString()}</time></p>
        {result.user.status && result.user.status !== 'active' && <output className="block text-xs text-status-warning mt-3">Account remains {result.user.status}. {lifecycleActions[result.user.status]} it separately before sign-in.</output>}
        {copyFailed && <p role="alert" className="text-xs text-status-error mt-3">Copy failed. Select and copy the password manually.</p>}
        <div className="flex gap-2 mt-5"><button type="button" onClick={() => void copy()} className="flex-1 bg-accent hover:bg-accent-hover text-white rounded py-2 text-sm">{copied ? 'Copied' : 'Copy'}</button><button type="button" onClick={close} className="flex-1 border border-border rounded py-2 text-sm text-text-secondary">Done</button></div>
      </> : <>
        <div className="text-sm text-text-muted space-y-3 mb-4"><p>Generate an expiring temporary password, shown once. The user must replace it at sign-in.</p><p>Existing sessions and API tokens will be revoked. MFA stays enabled. This does not enable, reactivate or unlock the account.</p></div>
        {mutation.isError && <p role="alert" className="text-xs text-status-error mb-4">{conflict ? 'This account changed. Close this dialog, review its refreshed state and explicitly start a new reset.' : 'The reset result could not be confirmed. It may have completed. Close this dialog and check current account state before explicitly starting a new reset. The password cannot be retrieved.'}</p>}
        {mutation.isPending && <p className="text-xs text-status-warning mb-4">A reset is in progress. Closing this dialog cannot undo it. If it completes, the password cannot be retrieved; review the account before explicitly starting another reset.</p>}
        <div className="flex gap-2"><button type="button" onClick={close} className="border border-border rounded px-4 py-2 text-sm text-text-secondary">Cancel</button><button type="button" onClick={() => mutation.mutate()} disabled={mutation.isPending || mutation.isError || user.credential_revision === undefined} className="flex-1 bg-accent hover:bg-accent-hover text-white rounded py-2 text-sm font-semibold disabled:opacity-50">{mutation.isPending ? 'Generating...' : 'Generate temporary password'}</button></div>
      </>}
    </dialog>
  </div>
}
