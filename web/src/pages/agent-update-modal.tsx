import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { ApiError } from '@/lib/api'
import { agentUpdateStatus, canStartAgentUpdate, checkAgentUpdate, sameArtifact, startAgentUpdate, terminalAgentUpdate } from '@/lib/agent-updates-api'
import { hasCapability } from '@/lib/auth'
import { useAuth } from '@/hooks/use-auth'
import { usePageVisible } from '@/hooks/use-agent-updates'
import type { Server } from '@/types/api'
import type { AgentUpdate, AgentUpdateAttempt, AgentUpdateCheck } from '@/types/agent-updates'

const stateLabels: Record<AgentUpdate['state'], string> = {
  requested: 'Update requested', downloading: 'Downloading verified agent', installing: 'Installing and restarting agent',
  bootstrap_required: 'Manual upgrade required', confirmation_pending: 'Awaiting durable agent confirmation',
  rollback_confirmation_pending: 'Awaiting durable rollback confirmation', unknown: 'Update outcome unknown',
  succeeded: 'Agent update verified', failed: 'Agent update failed', rolled_back: 'Agent update rolled back',
  expired: 'Update authorization expired', recovery_acknowledged: 'Manual recovery acknowledged',
}

function sameCheck(a: AgentUpdateCheck, b: AgentUpdateCheck): boolean {
  return canStartAgentUpdate(b) && sameArtifact(a.target, b.target) && a.connection_id === b.connection_id
    && a.current?.version === b.current?.version && a.current?.revision === b.current?.revision && a.current?.sha256 === b.current?.sha256
}

export function AgentUpdateModal({ server, scope, attempt, open, onClose, onAttempt }: Readonly<{
  server: Server
  scope: string
  attempt?: AgentUpdateAttempt
  open: boolean
  onClose: () => void
  onAttempt: (attempt: AgentUpdateAttempt) => void
}>) {
  const { user, refreshUser } = useAuth()
  const client = useQueryClient()
  const visible = usePageVisible()
  const isAdmin = hasCapability(user, 'operations.admin')
  const [monitorStartedAt, setMonitorStartedAt] = useState(Date.now)
  const busy = useRef(false)
  const dispatched = useRef(false)
  const authority = useRef(user)
  const lifecycle = useRef<AbortController | null>(null)
  useEffect(() => { authority.current = user }, [user])
  useEffect(() => {
    const controller = new AbortController()
    lifecycle.current = controller
    return () => { controller.abort(); authority.current = null }
  }, [])
  useEffect(() => {
    if (!visible || !open || !isAdmin) {
      void client.cancelQueries({ queryKey: [scope, 'status', server.id] })
      void client.cancelQueries({ queryKey: [scope, 'confirmation', server.id] })
    }
  }, [visible, open, isAdmin, client, scope, server.id])

  const status = useQuery({
    queryKey: [scope, 'status', server.id, attempt?.uncertain ? 'latest' : attempt?.operation?.id ?? 'latest'],
    enabled: isAdmin && open && visible,
    retry: false,
    staleTime: 0,
    refetchOnMount: 'always',
    queryFn: async ({ signal }) => {
      try {
        return await agentUpdateStatus(server.id, attempt?.uncertain ? undefined : attempt?.operation?.id, signal,
          attempt?.uncertain ? undefined : attempt?.operation?.target)
      } catch (error) {
        if (error instanceof ApiError && error.status === 404 && !attempt?.operation) return null
        throw error
      }
    },
    refetchInterval: query => {
      const op = query.state.data
      return visible && open && op && !terminalAgentUpdate(op) && op.state !== 'unknown'
        && Date.now() - monitorStartedAt < 150_000 ? 2_000 : false
    },
  })

  const check = useQuery({
    queryKey: [scope, 'confirmation', server.id],
    enabled: isAdmin && open && visible && server.status === 'online' && !attempt?.uncertain,
    retry: false,
    staleTime: 0,
    refetchOnMount: 'always',
    queryFn: ({ signal }) => checkAgentUpdate(server.id, signal),
  })

  const recovered = status.data
  useEffect(() => {
    if (!recovered || !isAdmin) return
    if (attempt?.uncertain && (recovered.id === attempt.previousOperationId
      || !attempt.target || !sameArtifact(recovered.target, attempt.target))) return
    if (attempt?.operation !== recovered) onAttempt({ operation: recovered })
  }, [recovered, isAdmin, attempt, onAttempt])

  useEffect(() => {
    if ([status.error, check.error].some(error => error instanceof ApiError && (error.status === 401 || error.status === 403))) {
      void refreshUser()
    }
  }, [status.error, check.error, refreshUser])

  const mutation = useMutation({
    retry: false,
    mutationFn: async (checked: AgentUpdateCheck) => {
      const actorId = user?.id
      const controller = lifecycle.current
      const freshUser = await refreshUser()
      controller?.signal.throwIfAborted()
      if (!freshUser || freshUser.id !== actorId || authority.current?.id !== actorId
        || !hasCapability(freshUser, 'operations.admin') || !hasCapability(authority.current, 'operations.admin')) {
        throw new Error('Administrator access changed. Refresh your session before continuing.')
      }
      const freshCheck = await checkAgentUpdate(server.id, controller?.signal)
      controller?.signal.throwIfAborted()
      if (!sameCheck(checked, freshCheck)) throw new Error('The node or Hub artifact changed. Close and reopen this dialog to review a fresh check.')
      // Guard the final dispatch again after the asynchronous authority checks.
      if (authority.current?.id !== actorId || !hasCapability(authority.current, 'operations.admin')) {
        throw new Error('Administrator access changed. Refresh your session before continuing.')
      }
      dispatched.current = true
      onAttempt({ uncertain: true, previousOperationId: status.data?.id, target: checked.target })
      return startAgentUpdate(server.id, freshCheck)
    },
    onSuccess: op => {
      if (lifecycle.current?.signal.aborted) return
      onAttempt({ operation: op })
      setMonitorStartedAt(Date.now())
      void client.invalidateQueries({ queryKey: [scope, 'status', server.id] })
      void client.invalidateQueries({ queryKey: [scope, 'availability'] })
      void client.invalidateQueries({ queryKey: ['servers'] })
    },
    onError: error => {
      if (lifecycle.current?.signal.aborted) return
      if (dispatched.current) void client.invalidateQueries({ queryKey: [scope, 'status', server.id] })
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) void refreshUser()
    },
    onSettled: () => { busy.current = false },
  })

  if (!open || !isAdmin) return null

  const op = recovered ?? attempt?.operation
  const uncertain = !!attempt?.uncertain
  const statusReady = status.isSuccess && !status.isFetching
  const checkReady = check.isSuccess && !check.isFetching
  const mayStart = statusReady && checkReady && check.data && canStartAgentUpdate(check.data)
    && (!op || terminalAgentUpdate(op)) && !uncertain && mutation.isIdle
  const current = check.data?.current?.version ?? server.agent_version ?? 'Not reported'

  const refresh = () => {
    setMonitorStartedAt(Date.now())
    void status.refetch()
    if (server.status === 'online' && !uncertain) void check.refetch()
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div role="dialog" aria-modal="true" aria-labelledby="agent-update-title" className="bg-surface border border-border rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-4">
          <h3 id="agent-update-title" className="text-sm font-semibold text-text-primary">Agent update: {server.name}</h3>
          <button type="button" aria-label="Close agent update" onClick={onClose} className="text-text-muted hover:text-text-primary"><X className="w-4 h-4" /></button>
        </div>
        <p className="text-xs text-text-muted break-all mb-3">Node: {server.name} ({server.id})</p>
        {(status.isPending || (check.isPending && server.status === 'online' && !uncertain)) && <p className="text-sm text-text-muted mb-3">Checking authoritative update status...</p>}
        {status.error && <p role="alert" className="text-sm text-status-warning mb-3">Status unavailable: {status.error.message}. Inspect this operation before starting another update.</p>}
        {check.error && <p role="alert" className="text-sm text-status-warning mb-3">Update check refused: {check.error.message}</p>}
        {uncertain && <p role="alert" className="text-sm text-status-warning mb-3">The update request outcome is uncertain. It may have started. Refresh status or inspect through the CLI before taking further action.</p>}
        {mutation.error && <p role="alert" className="text-sm text-status-warning mb-3">{mutation.error.message}</p>}
        {op && !uncertain && (
          <div className="border border-border bg-elevated rounded p-3 mb-4 text-sm text-text-secondary" aria-live="polite">
            <p className={op.state === 'succeeded' ? 'text-status-online' : 'text-text-primary'}>{stateLabels[op.state]}</p>
            <p className="text-xs font-mono break-all mt-2">Operation: {op.id}</p>
            <p className="text-xs mt-1">Target: {op.target.version} ({op.target.revision})</p>
            {op.reason && <p className="text-xs mt-2 break-words">{op.reason}</p>}
            {['unknown', 'confirmation_pending', 'rollback_confirmation_pending', 'recovery_acknowledged'].includes(op.state)
              && <p className="text-xs text-status-warning mt-2">The target update has not reached verified success. Inspect this operation before another update.</p>}
          </div>
        )}
        {server.status !== 'online' && <p className="text-sm text-text-muted mb-3">The node is {server.status}. Updates require an enrolled, online agent. Durable operation status can still be inspected.</p>}
        {check.data?.bootstrap_required && <p className="text-sm text-status-warning mb-3">Manual upgrade required. Coordinate idle work and upgrade through direct SSH using the CLI preserving bootstrap workflow.</p>}
        {check.data && !check.data.bootstrap_required && !check.data.supported && <p className="text-sm text-status-warning mb-3">Update unsupported. {check.data.reason}</p>}
        {check.data?.reason && check.data.bootstrap_required && <p className="text-xs text-text-muted mb-3">{check.data.reason}</p>}
        {mayStart && (
          <div className="text-sm text-text-secondary mb-4">
            <p>Current agent: <span className="font-mono">{current}</span></p>
            <p>Target agent: <span className="font-mono">{check.data.target.version} ({check.data.target.revision})</span></p>
            <p className="mt-3">This updates only {server.name}. The agent briefly restarts and disconnects. Terminal, file, upload, and log activity must be idle; the Hub will refuse busy nodes.</p>
          </div>
        )}
        {check.data?.supported && !check.data.update_available && !uncertain && <p className="text-sm text-text-muted mb-3">No newer verified Hub agent artifact is available.</p>}
        {!op && statusReady && !uncertain && <p className="text-xs text-text-muted mb-3">No previous update operation was found.</p>}
        <p className="text-xs text-text-muted mb-4">Status checks run for up to 150 seconds while this dialog is visible. Close and reopen to continue monitoring, or refresh status.</p>
        <p className="text-xs text-text-muted mb-4">CLI inspection: <code className="block font-mono break-all mt-1">vey servers update {JSON.stringify(server.id)} --status{op ? ` --operation ${JSON.stringify(op.id)}` : ''}</code></p>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={onClose} className="border border-border rounded px-3 py-2 text-sm text-text-secondary hover:bg-elevated">{mayStart ? 'Cancel' : 'Close'}</button>
          <button type="button" onClick={refresh} disabled={status.isFetching || check.isFetching || mutation.isPending} className="border border-border rounded px-3 py-2 text-sm text-text-secondary hover:bg-elevated disabled:opacity-50">Refresh status</button>
          {(mayStart || mutation.isPending) && <button type="button" disabled={!mayStart} onClick={() => {
            if (busy.current || !mayStart || !check.data) return
            busy.current = true
            mutation.mutate(check.data)
          }} className="bg-accent hover:bg-accent-hover text-white rounded px-3 py-2 text-sm disabled:opacity-50">{mutation.isPending ? 'Starting update...' : 'Update agent'}</button>}
        </div>
      </div>
    </div>
  )
}
