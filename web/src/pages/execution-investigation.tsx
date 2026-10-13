import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '@/hooks/use-auth'
import { hasCapability } from '@/lib/auth'
import { listExecutions } from '@/lib/executions-api'
import type { ExecutionFilters, ExecutionView, OriginalKind, OriginalRequest } from '@/types/executions'

const PAGE_SIZE = 50

export interface ExecutionInvestigationProps {
  onRequestOriginal?: (execution: ExecutionView, request: OriginalRequest) => void
}

export function ExecutionInvestigation({ onRequestOriginal }: ExecutionInvestigationProps) {
  const { user } = useAuth()
  const [filters, setFilters] = useState<Required<ExecutionFilters>>({ actor_id: '', node_id: '', os_user: '', policy_version: '', state: '', evidence_state: '' })
  const [offset, setOffset] = useState(0)
  const canReadOriginal = hasCapability(user, 'audit.original.read')
  const query = useQuery({
    queryKey: ['executions', user?.id, filters, PAGE_SIZE, offset],
    queryFn: ({ signal }) => listExecutions(filters, PAGE_SIZE, offset, signal),
    enabled: hasCapability(user, 'audit.read'),
    throwOnError: false,
  })
  if (!hasCapability(user, 'audit.read')) return null

  const updateFilter = (key: keyof ExecutionFilters, value: string) => {
    setFilters(current => ({ ...current, [key]: value }))
    setOffset(0)
  }
  const executions = query.data?.executions ?? []
  const total = query.data?.total ?? 0

  return (
    <section className="bg-surface border border-border rounded p-4 space-y-4" aria-labelledby="execution-investigation-title">
      <div>
        <h3 id="execution-investigation-title" className="text-sm font-semibold text-text-primary">Execution investigation</h3>
        <p className="text-xs text-text-muted mt-1">Process outcome and audit evidence are reported separately. Command contents are not included here.</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Filter label="Actor ID" value={filters.actor_id} onChange={value => updateFilter('actor_id', value)} />
        <Filter label="Node ID" value={filters.node_id} onChange={value => updateFilter('node_id', value)} />
        <Filter label="OS user" value={filters.os_user} onChange={value => updateFilter('os_user', value)} />
        <Filter label="Policy version" value={filters.policy_version} onChange={value => updateFilter('policy_version', value)} />
        <Filter label="Process state" value={filters.state} onChange={value => updateFilter('state', value)} />
        <Filter label="Evidence state" value={filters.evidence_state} onChange={value => updateFilter('evidence_state', value)} />
      </div>
      {query.isLoading && <p className="text-sm text-text-muted" role="status">Loading execution records…</p>}
      {query.isError && <p className="text-sm text-status-error" role="alert">Failed to load execution records. {query.error instanceof Error ? query.error.message : ''}</p>}
      {!query.isLoading && !query.isError && executions.length === 0 && <p className="text-sm text-text-muted">No execution records match these filters.</p>}
      {!query.isLoading && !query.isError && executions.length > 0 && (
        <div className="space-y-3">
          {executions.map(execution => (
            <article key={execution.id} className="rounded border border-border p-3 space-y-2">
              <div className="flex flex-wrap justify-between gap-2">
                <h4 className="text-sm font-semibold text-text-primary">{execution.actor_name || execution.actor_id} on {execution.node_name || execution.node_id}</h4>
                <span className="text-xs text-text-muted">{new Date(execution.created_at).toLocaleString()}</span>
              </div>
              <dl className="grid gap-x-4 gap-y-1 sm:grid-cols-2 text-xs">
                <Info label="Execution ID" value={execution.id} mono />
                <Info label="Actor" value={`${execution.actor_name || execution.actor_id} (${execution.actor_id})`} />
                <Info label="OS identity" value={execution.preparation ? `${execution.preparation.identity.username} · UID ${execution.preparation.identity.uid} · GID ${execution.preparation.identity.gid}` : 'Unavailable (identity was not prepared)'} />
                <Info label="Node" value={`${execution.node_name || execution.node_id} (${execution.node_id})`} />
                <Info label="Requested user" value={execution.requested_user || '—'} />
                <Info label="Command SHA-256" value={execution.command_sha256} mono />
                <Info label="Policy" value={`${execution.policy_version} · ${execution.policy_sha256}`} mono />
                <Info label="Process outcome" value={`${execution.state}${execution.exit_code !== undefined ? ` · exit ${execution.exit_code}` : ''}${execution.signal ? ` · signal ${execution.signal}` : ''}`} />
                <Info label="Evidence state and gaps" value={`${execution.evidence_state}${execution.admission_disposition ? ` · admission ${execution.admission_disposition}` : ''}`} />
              </dl>
              {canReadOriginal && execution.originals.length > 0 && <ProtectedOriginalRequests key={`${user?.id}:${execution.id}`} execution={execution} onRequestOriginal={onRequestOriginal} />}
            </article>
          ))}
        </div>
      )}
      {total > 0 && <div className="flex items-center justify-between text-sm text-text-muted"><span>Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span><div className="flex gap-2"><button type="button" onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0 || query.isFetching} className="px-3 py-1 border border-border rounded disabled:opacity-50">Previous</button><button type="button" onClick={() => setOffset(offset + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total || query.isFetching} className="px-3 py-1 border border-border rounded disabled:opacity-50">Next</button></div></div>}
    </section>
  )
}

function ProtectedOriginalRequests({ execution, onRequestOriginal }: { execution: ExecutionView; onRequestOriginal?: ExecutionInvestigationProps['onRequestOriginal'] }) {
  const [pendingKind, setPendingKind] = useState<OriginalKind | null>(null)
  const [purpose, setPurpose] = useState('')
  const close = () => {
    setPendingKind(null)
    setPurpose('')
  }
  return (
    <>
      <div className="flex flex-wrap gap-2 pt-1">{execution.originals.map(kind => <button key={kind} type="button" onClick={() => { setPendingKind(kind); setPurpose('') }} className="text-xs border border-border rounded px-3 py-2">Request {kind} original</button>)}</div>
      {pendingKind && <div role="dialog" aria-modal="true" aria-labelledby={`original-request-title-${execution.id}`} className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
        <div className="w-full max-w-lg rounded border border-border bg-surface p-5 space-y-3">
          <h4 id={`original-request-title-${execution.id}`} className="text-base font-semibold text-text-primary">Request protected original</h4>
          <p className="text-sm text-text-secondary">Execution {execution.id} · {pendingKind}. A purpose is required. Access is separately authorized and the original is delivered through a short-lived one-use request.</p>
          <label className="block text-xs text-text-muted">Purpose
            <textarea value={purpose} onChange={event => setPurpose(event.target.value)} maxLength={1024} rows={3} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
          </label>
          {!onRequestOriginal && <p className="text-xs text-text-muted">Protected access is not configured in this view yet.</p>}
          <div className="flex justify-end gap-2"><button type="button" onClick={close} className="text-sm border border-border rounded px-3 py-2">Cancel</button><button type="button" onClick={() => { if (onRequestOriginal) onRequestOriginal(execution, { purpose: purpose.trim(), records: [pendingKind] }); close() }} disabled={!onRequestOriginal || !purpose.trim() || /\p{Cc}/u.test(purpose)} className="text-sm bg-accent hover:bg-accent-hover text-white rounded px-3 py-2 disabled:opacity-50">Continue to protected review</button></div>
        </div>
      </div>}
    </>
  )
}

function Filter({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  const id = `execution-filter-${label.toLowerCase().replaceAll(' ', '-')}`
  return <label htmlFor={id} className="text-xs text-text-muted">{label}<input id={id} value={value} maxLength={256} onChange={event => onChange(event.target.value)} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" /></label>
}

function Info({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="min-w-0"><dt className="text-text-muted">{label}</dt><dd className={`text-text-secondary break-all ${mono ? 'font-mono' : ''}`}>{value}</dd></div>
}
