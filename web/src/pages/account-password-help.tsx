import { UserRound, UsersRound } from 'lucide-react'
import type { User } from '@/types/api'
import { useDialogFocus } from '@/hooks/use-dialog-focus'

const sourceLabels = new Map([['local', 'Local'], ['ldap', 'LDAP']])

export function AccountSourceBadge({ provider }: Readonly<{ provider?: string }>) {
  const label = sourceLabels.get(provider ?? '') ?? 'Unknown'
  const Icon = provider === 'ldap' ? UsersRound : UserRound
  return <span className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs ${provider === 'ldap' ? 'bg-accent/10 text-accent' : 'bg-elevated text-text-secondary'}`}><Icon size={14} aria-hidden="true" />{label}</span>
}

export function DirectoryPasswordHelp({ user, onClose }: Readonly<{ user: User; onClose: () => void }>) {
  const dialogRef = useDialogFocus()
  return <div className="fixed inset-0 flex items-center justify-center z-50 p-4">
    <dialog ref={dialogRef} tabIndex={-1} onCancel={event => { event.preventDefault(); onClose() }} aria-labelledby="directory-password-title" className="fixed inset-0 m-auto h-fit max-h-[calc(100dvh_-_2rem)] overflow-y-auto backdrop:bg-black/50 bg-surface border border-border rounded-lg p-6 w-[calc(100%_-_2rem)] max-w-md">
      <h3 id="directory-password-title" className="text-sm font-semibold text-text-primary mb-2">Directory-managed password</h3>
      <p className="text-xs text-text-secondary mb-4">{user.username} · LDAP</p>
      <div className="space-y-3 text-sm text-text-muted">
        <p>This password is managed in your directory. A directory administrator must reset it there; a Veyport administrator may not have directory permissions.</p>
        <p>Complete any directory-required password change before signing in to Veyport. Your existing Veyport MFA stays enabled.</p>
      </div>
      <button type="button" onClick={onClose} className="mt-5 w-full border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated">Close</button>
    </dialog>
  </div>
}
