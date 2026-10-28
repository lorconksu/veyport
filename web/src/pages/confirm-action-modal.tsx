import { useDialogFocus } from '@/hooks/use-dialog-focus'

/**
 * Generic confirmation dialog shared by Settings' account-lifecycle actions
 * (disable/enable/unlock/dormancy exemption in settings.tsx) and the
 * Sessions modal's per-row and footer actions (sessions-modal.tsx).
 */
export function ConfirmActionModal({
  title,
  body,
  confirmLabel,
  danger,
  isPending,
  onCancel,
  onConfirm,
}: Readonly<{
  title: string
  body: string
  confirmLabel: string
  danger?: boolean
  isPending: boolean
  onCancel: () => void
  onConfirm: () => void
}>) {
  const dialogRef = useDialogFocus()
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50">
      <dialog ref={dialogRef} tabIndex={-1} aria-labelledby="confirm-action-title" onCancel={event => { event.preventDefault(); onCancel() }} className="fixed inset-0 m-auto h-fit max-h-[calc(100dvh_-_2rem)] overflow-y-auto backdrop:bg-black/50 bg-surface border border-border rounded-lg p-6 w-[calc(100%_-_2rem)] max-w-sm">
        <h3 id="confirm-action-title" className="text-sm font-semibold text-text-primary mb-2">{title}</h3>
        <p className="text-text-muted text-xs mb-4">{body}</p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="flex-1 border border-border rounded py-2 text-sm text-text-secondary hover:bg-elevated transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isPending}
            className={`flex-1 text-white text-sm font-semibold rounded py-2 transition-colors disabled:opacity-50 ${
              danger ? 'bg-status-error hover:bg-status-error/80' : 'bg-accent hover:bg-accent-hover'
            }`}
          >
            {isPending ? `${confirmLabel}...` : confirmLabel}
          </button>
        </div>
      </dialog>
    </div>
  )
}
