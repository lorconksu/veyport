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
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-sm">
        <h3 className="text-sm font-semibold text-text-primary mb-2">{title}</h3>
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
      </div>
    </div>
  )
}
