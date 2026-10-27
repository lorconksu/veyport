import { UserRound, UsersRound } from 'lucide-react'
import type { User } from '@/types/api'
import { useDialogFocus } from '@/hooks/use-dialog-focus'

export function AccountSourceBadge({ provider }: Readonly<{ provider?: string }>) {
  const label = provider === 'local' ? 'Local' : provider === 'ldap' ? 'LDAP' : 'Unknown'
  const Icon = provider === 'ldap' ? UsersRound : UserRound
  return <span className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs ${provider === 'ldap' ? 'bg-accent/10 text-accent' : 'bg-elevated text-text-secondary'}`}><Icon size={14} aria-hidden="true" />{label}</span>
}

export function DirectoryPasswordHelp({ user, onClose }: Readonly<{ user: User; onClose: () => void }>) {
  const { ref: dialogRef, onKeyDown: dialogKeyDown } = useDialogFocus()
  return <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
    <section ref={dialogRef} tabIndex={-1} onKeyDown={event => dialogKeyDown(event, onClose)} role="dialog" aria-modal="true" aria-labelledby="directory-password-title" className="bg-surface border border-border rounded-lg p-6 w-full max-w-md">
      <h3 id="directory-password-title" className="text-sm font-semibold text-text-primary mb-2">Directory-managed password</h3>
      <p className="text-xs text-text-secondary mb-4">{user.username} · LDAP</p>
      <div className="space-y-3 text-sm text-text-muted">
        <p>This password is managed in your directory. A directory administrator must reset it there; a Veyport administrator may not have directory permissions.</p>
        <p>Complete any directory-required password change before signing in to Veyport. Your existing Veyport MFA stays enabled.</p>
      </div>
      <button type="button" onClick={onClose} className="mt-5 w-full border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated">Close</button>
    </section>
  </div>
}
