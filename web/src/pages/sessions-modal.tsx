import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { formatRelative } from '@/lib/time'
import type { EndedCountResponse, Session, SessionKind, SessionListResponse } from '@/types/api'
import { ConfirmActionModal } from '@/pages/confirm-action-modal'

const KIND_LABELS: Record<SessionKind, string> = {
  web: 'Web',
  cli: 'CLI',
  ssh: 'SSH shell',
  terminal: 'Web terminal',
}

function isShell(session: Session): boolean {
  return session.kind === 'ssh' || session.kind === 'terminal'
}

function startedAt(session: Session): string | undefined {
  return session.created_at ?? session.started_at
}

function lastSeenAt(session: Session): string | undefined {
  return session.last_seen_at ?? session.last_activity_at
}

function exactTime(iso: string | undefined): string | undefined {
  return iso ? new Date(iso).toLocaleString() : undefined
}

function relativeOrDash(iso: string | undefined): string {
  return iso ? formatRelative(iso) : '—'
}

/**
 * Row table shared by the admin/self Sessions modal (below) and the
 * Profile tab's inline "Your sessions" card (settings.tsx).
 */
export function SessionsTable({
  sessions,
  rowActionLabel,
  onRowAction,
  pendingId,
}: Readonly<{
  sessions: Session[]
  rowActionLabel: (session: Session) => string | null
  onRowAction: (session: Session) => void
  pendingId: string | null
}>) {
  const showServerColumn = sessions.some(isShell)

  return (
    <div className="border border-border rounded overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-surface border-b border-border">
            <th className="text-left px-3 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Kind</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Address</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Started</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Last seen</th>
            {showServerColumn && (
              <th className="text-left px-3 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Server</th>
            )}
            <th className="text-left px-3 py-2 text-text-muted font-medium text-xs uppercase tracking-wider">Actions</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map(s => {
            const label = rowActionLabel(s)
            const started = startedAt(s)
            const lastSeen = lastSeenAt(s)
            return (
              <tr key={s.id} className="border-b border-border last:border-b-0">
                <td className="px-3 py-2 text-text-primary">
                  {KIND_LABELS[s.kind]}
                  {s.current && (
                    <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-accent/20 text-accent">This session</span>
                  )}
                </td>
                <td className="px-3 py-2 text-text-secondary text-xs">{s.ip || '—'}</td>
                <td className="px-3 py-2 text-xs text-text-secondary" title={exactTime(started)}>
                  {relativeOrDash(started)}
                </td>
                <td className="px-3 py-2 text-xs text-text-secondary" title={exactTime(lastSeen)}>
                  {relativeOrDash(lastSeen)}
                </td>
                {showServerColumn && (
                  <td className="px-3 py-2 text-xs text-text-secondary">{s.server ?? '—'}</td>
                )}
                <td className="px-3 py-2">
                  {label && (
                    <button
                      type="button"
                      onClick={() => onRowAction(s)}
                      disabled={pendingId === s.id}
                      className="text-xs text-status-warning hover:text-status-error transition-colors disabled:opacity-50"
                    >
                      {label}
                    </button>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

interface RowConfirm {
  session: Session
  label: string
}

function rowConfirmCopy(mode: 'admin' | 'self', username: string, target: RowConfirm) {
  const shell = isShell(target.session)
  if (shell) {
    return {
      title: 'Terminate shell',
      body: mode === 'admin'
        ? `Terminate this shell for ${username}? The connection closes immediately.`
        : 'Terminate this shell? The connection closes immediately.',
      confirmLabel: 'Terminate',
      danger: true,
    }
  }
  return {
    title: 'Log out session',
    body: mode === 'admin'
      ? `Log out this session for ${username}? It ends immediately.`
      : 'Log out this session? It ends immediately.',
    confirmLabel: 'Log out',
  }
}

function footerConfirmCopy(mode: 'admin' | 'self', username: string) {
  if (mode === 'admin') {
    return {
      title: 'Log out everywhere',
      body: `Log out ${username} everywhere? All web and CLI sessions end now and any open SSH shells are closed.`,
      confirmLabel: 'Log out everywhere',
      danger: true,
    }
  }
  return {
    title: 'Sign out other sessions',
    body: 'Sign out all other sessions? They end now and any open SSH shells are closed.',
    confirmLabel: 'Sign out',
    danger: true,
  }
}

/**
 * Sessions modal (contracts/ui-cli.md "Settings → Users tab" /
 * "Settings → Profile tab"). Two modes:
 *  - admin: Users tab row action "Sessions" for any user (incl. the
 *    viewer's own row) — lists/ends that user's sessions and shells.
 *  - self: the caller's own sessions (also embedded inline, sans the
 *    modal chrome, by the Profile tab's "Your sessions" card).
 */
export function SessionsModal({
  mode,
  userId,
  username,
  onClose,
}: Readonly<{
  mode: 'admin' | 'self'
  userId?: string
  username: string
  onClose: () => void
}>) {
  const queryClient = useQueryClient()
  const [rowConfirm, setRowConfirm] = useState<RowConfirm | null>(null)
  const [confirmAll, setConfirmAll] = useState(false)

  const listPath = mode === 'admin' ? `/users/${userId}/sessions` : '/auth/sessions'
  const queryKey = mode === 'admin' ? ['sessions', userId] : ['my-sessions']

  const { data, isLoading, isError } = useQuery({
    queryKey,
    queryFn: () => apiFetch<SessionListResponse>(listPath),
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey })
    queryClient.invalidateQueries({ queryKey: ['users'] })
  }

  const endOneMutation = useMutation({
    mutationFn: (session: Session) =>
      apiFetch<{ status: string }>(
        mode === 'admin' ? `/users/${userId}/sessions/${session.id}` : `/auth/sessions/${session.id}`,
        { method: 'DELETE' },
      ),
    onSuccess: () => {
      invalidate()
      setRowConfirm(null)
    },
  })

  const endAllMutation = useMutation({
    mutationFn: () =>
      mode === 'admin'
        ? apiFetch<EndedCountResponse>(`/users/${userId}/sessions`, { method: 'DELETE' })
        : apiFetch<EndedCountResponse>('/auth/sessions/sign-out-others', { method: 'POST' }),
    onSuccess: () => {
      invalidate()
      setConfirmAll(false)
    },
  })

  const sessions = data?.sessions ?? []
  const onlyCurrentSession = mode === 'self' && sessions.length <= 1

  const rowActionLabel = (s: Session): string | null => {
    if (mode === 'self' && s.current) return null
    return isShell(s) ? 'Terminate' : 'Log out'
  }

  const handleRowAction = (session: Session) => {
    endOneMutation.reset()
    setRowConfirm({ session, label: rowActionLabel(session) ?? 'Log out' })
  }

  const errorMessage = (() => {
    if (endOneMutation.isError) {
      return endOneMutation.error instanceof Error ? endOneMutation.error.message : 'Failed to end session'
    }
    if (endAllMutation.isError) {
      return endAllMutation.error instanceof Error ? endAllMutation.error.message : 'Failed to end sessions'
    }
    return null
  })()

  const emptyText = mode === 'admin' ? 'No active sessions.' : 'This is your only active session.'
  const showTable = sessions.length > 0 && !onlyCurrentSession
  const showEmpty = sessions.length === 0 || onlyCurrentSession
  const showFooterButton = mode === 'admin' ? sessions.length > 0 : !onlyCurrentSession

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-2xl">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-text-primary">
            {mode === 'admin' ? `Sessions — ${username}` : 'Sessions'}
          </h3>
          <button type="button" onClick={onClose} className="text-text-muted hover:text-text-primary text-sm">
            Close
          </button>
        </div>

        {errorMessage && (
          <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2 mb-3">
            {errorMessage}
          </div>
        )}

        {isLoading && <div className="text-text-muted text-sm py-4 text-center">Loading...</div>}
        {!isLoading && isError && (
          <div className="bg-status-error/10 border border-status-error/20 text-status-error text-xs rounded px-3 py-2">
            Failed to load sessions.
          </div>
        )}
        {!isLoading && !isError && showEmpty && (
          <div className="text-text-muted text-sm py-4 text-center">{emptyText}</div>
        )}
        {!isLoading && !isError && showTable && (
          <SessionsTable
            sessions={sessions}
            rowActionLabel={rowActionLabel}
            onRowAction={handleRowAction}
            pendingId={endOneMutation.isPending ? rowConfirm?.session.id ?? null : null}
          />
        )}

        {!isLoading && !isError && showFooterButton && (
          <div className="mt-4 flex justify-end">
            <button
              type="button"
              onClick={() => { endAllMutation.reset(); setConfirmAll(true) }}
              className="text-xs text-status-error hover:text-status-error/80 font-semibold transition-colors"
            >
              {mode === 'admin' ? 'Log out everywhere' : 'Sign out other sessions'}
            </button>
          </div>
        )}
      </div>

      {rowConfirm && (() => {
        const copy = rowConfirmCopy(mode, username, rowConfirm)
        return (
          <ConfirmActionModal
            title={copy.title}
            body={copy.body}
            confirmLabel={copy.confirmLabel}
            danger={copy.danger}
            isPending={endOneMutation.isPending}
            onCancel={() => setRowConfirm(null)}
            onConfirm={() => endOneMutation.mutate(rowConfirm.session)}
          />
        )
      })()}

      {confirmAll && (() => {
        const copy = footerConfirmCopy(mode, username)
        return (
          <ConfirmActionModal
            title={copy.title}
            body={copy.body}
            confirmLabel={copy.confirmLabel}
            danger={copy.danger}
            isPending={endAllMutation.isPending}
            onCancel={() => setConfirmAll(false)}
            onConfirm={() => endAllMutation.mutate()}
          />
        )
      })()}
    </div>
  )
}
