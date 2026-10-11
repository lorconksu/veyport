import { useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '@/hooks/use-auth'
import { useSensitiveTask } from '@/hooks/use-sensitive-task'
import { FreshMFADialog } from '@/components/fresh-mfa-dialog'
import { hasCapability } from '@/lib/auth'
import { canDecideChange, securityIdentityKey } from '@/lib/security-authority'
import { approveSecurityChange, applySecurityChange, createSecuritySecret, getSecurityChange, previewSecurityChange, reconcileSecurityChange, requestSecurityChange, securityStepUp } from '@/lib/security-api'
import type { SecurityChange, SecurityPreview } from '@/types/security'
import { SecurityPrincipalRequest } from './security-principal-request'
import { SecuritySettingsTab } from './security-settings-tab'

type Decision = { action: 'request'; preview: SecurityPreview } | { action: 'approve' | 'apply' | 'reconcile'; change: SecurityChange }

export function SecurityWorkspace({ broadAccess, requestId, onRequestId }: { broadAccess: boolean; requestId: string; onRequestId: (id: string) => void }) {
  const { user } = useAuth()
  return <SecurityWorkspaceSession key={securityIdentityKey(user)} broadAccess={broadAccess} requestId={requestId} onRequestId={onRequestId} />
}

function SecurityWorkspaceSession({ broadAccess, requestId, onRequestId }: { broadAccess: boolean; requestId: string; onRequestId: (id: string) => void }) {
  const { user, refreshUser } = useAuth()
  const client = useQueryClient()
  const [decision, setDecision] = useState<Decision | null>(null)
  const [openId, setOpenId] = useState(requestId)
  const [notice, setNotice] = useState('')
  const task = useSensitiveTask()
  const reviewQuery = useQuery({ queryKey: ['security', 'change', user?.id, securityIdentityKey(user), requestId], queryFn: ({ signal }) => getSecurityChange(requestId, signal), enabled: !!user && !!requestId, retry: false })
  const changed = async (change: SecurityChange) => {
    setDecision(null)
    setNotice(`Request ${change.id}: ${change.state}.`)
    onRequestId(change.id)
    await refreshUser()
    await client.invalidateQueries({ queryKey: ['security'] })
  }
  const submit = async (code: string, signal: AbortSignal) => {
    if (!decision) throw new Error('Exact review required')
    const action = decision.action
    if (action === 'reconcile') throw new Error('Reconciliation has separate existing authorization')
    const digest = action === 'request' ? decision.preview.digest : decision.change.digest
    if (action === 'request') {
      const latest = await previewSecurityChange(decision.preview.proposal, signal)
      signal.throwIfAborted()
      if (latest.digest !== digest || JSON.stringify(latest.proposal) !== JSON.stringify(decision.preview.proposal)) throw new Error('Request changed; review it again')
    } else {
      const latest = await getSecurityChange(decision.change.id, signal)
      signal.throwIfAborted()
      if (latest.digest !== digest || latest.revision !== decision.change.revision || !canDecideChange(user, latest, action)) throw new Error('Request or authority changed; review current status')
    }
    const step = await securityStepUp(`security.${action}`, digest, code, action === 'request' ? undefined : decision.change.id, signal)
    signal.throwIfAborted()
    if (!Number.isFinite(Date.parse(step.expires_at)) || Date.parse(step.expires_at) <= Date.now()) throw new Error('Fresh proof expired')
    const proof = step.proof
    const result = action === 'request' ? await requestSecurityChange(decision.preview, proof, signal) : await (action === 'approve' ? approveSecurityChange : applySecurityChange)(decision.change, proof, signal)
    signal.throwIfAborted()
    // Only safe request metadata is retained after the one-use operation.
    setNotice(`Request ${result.id}: ${result.state}.`)
    onRequestId(result.id)
  }
  const reconcile = async () => {
    if (decision?.action !== 'reconcile') return
    try {
      const result = await task.run(async signal => {
        const latest = await getSecurityChange(decision.change.id, signal)
        signal.throwIfAborted()
        if (latest.digest !== decision.change.digest || !canDecideChange(user, latest, 'reconcile')) throw new Error('Current applying request required')
        return reconcileSecurityChange(latest.id, signal)
      })
      await changed(result)
    } catch { setDecision(null); setNotice('Reconciliation could not be confirmed. Check current request status before trying again.') }
  }
  const close = () => { task.cancel(); setDecision(null) }
  return <div className="space-y-4">
    {notice && <p role="status" className="text-sm text-text-secondary">{notice}</p>}
    {broadAccess && <>
      <SecuritySettingsTab onPreview={proposal => task.run(signal => previewSecurityChange(proposal, signal))} onRequest={preview => setDecision({ action: 'request', preview })} onApprove={change => setDecision({ action: 'approve', change })} onApply={change => setDecision({ action: 'apply', change })} onReconcile={change => setDecision({ action: 'reconcile', change })} />
      {hasCapability(user, 'security.request') && <SecurityPrincipalRequest onPreview={(proposal, signal) => previewSecurityChange(proposal, signal)} onRequest={preview => setDecision({ action: 'request', preview })} />}
      {(hasCapability(user, 'security.request') || hasCapability(user, 'security.bootstrap')) && <WriteOnlyCredential />}
    </>}
    <section className="rounded border border-border bg-surface p-4 space-y-3" aria-labelledby="specific-request-title">
      <h3 id="specific-request-title" className="font-semibold text-text-primary">Review a specific request</h3>
      <p className="text-xs text-text-muted">Nominated initial approvers can review their exact request here. This does not grant access to other security settings.</p>
      <form onSubmit={event => { event.preventDefault(); onRequestId(openId.trim()) }} className="flex gap-2"><label className="flex-1 text-sm text-text-secondary">Request ID<input value={openId} maxLength={128} onChange={event => setOpenId(event.target.value)} className="block w-full rounded border border-border bg-elevated px-3 py-2" /></label><button type="submit" disabled={!/^[a-zA-Z0-9_-]{1,128}$/.test(openId.trim())} className="self-end rounded border border-border px-3 py-2 text-sm disabled:opacity-50">Open request</button></form>
      {reviewQuery.isLoading && <p role="status">Loading exact request…</p>}
      {reviewQuery.isError && <p role="alert" className="text-sm text-status-error">This request is unavailable or you do not have authority to review it.</p>}
      {reviewQuery.isSuccess && reviewQuery.data && <SecurityRequestReview change={reviewQuery.data} onDecision={action => setDecision({ action, change: reviewQuery.data })} />}
    </section>
    {decision && decision.action !== 'reconcile' && <FreshMFADialog key={`${decision.action}:${decision.action === 'request' ? decision.preview.digest : decision.change.digest}`} title={decision.action === 'request' ? 'Confirm exact security request' : `Confirm exact ${decision.action}`} onClose={close} onSubmit={submit} onSuccess={() => { setDecision(null); void refreshUser().then(() => client.invalidateQueries({ queryKey: ['security'] })) }}>
      <ExactProposal value={decision.action === 'request' ? decision.preview : decision.change} />
      <p className="text-xs text-text-muted">This code authorizes only security.{decision.action} for the displayed digest and your current interactive session.</p>
    </FreshMFADialog>}
    {decision?.action === 'reconcile' && <div role="dialog" aria-modal="true" aria-label="Reconcile archived transition" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"><div className="rounded border border-border bg-surface p-5 space-y-3 max-w-2xl"><h3 className="font-semibold">Reconcile archived transition</h3><ExactProposal value={decision.change} /><p className="text-sm">Resume only this already authorized transition using its preserved evidence. Current authority and the external anchor will be checked.</p><button type="button" onClick={close} className="rounded border px-3 py-2">Cancel</button><button type="button" disabled={task.busy} onClick={() => void reconcile()} className="rounded border px-3 py-2">Confirm reconciliation</button></div></div>}
  </div>
}

function ExactProposal({ value }: { value: SecurityPreview | SecurityChange }) {
  const proposal = 'proposal' in value ? value.proposal : value
  return <div className="space-y-2 text-sm text-text-secondary"><p>Reason: {proposal.reason}</p><p>Expected policy version: {proposal.expected_version}</p><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(proposal.change, null, 2)}</pre><p className="break-all">Digest: {value.digest}</p></div>
}

function SecurityRequestReview({ change, onDecision }: { change: SecurityChange; onDecision: (action: 'approve' | 'apply' | 'reconcile') => void }) {
  const { user } = useAuth()
  return <article className="rounded border border-border p-3 space-y-2"><h4 className="font-semibold">Request {change.id} · {change.state}</h4><ExactProposal value={change} /><p className="text-xs">Requester {change.requester_id} · person {change.requester_person_id} · revision {change.revision} · expires {new Date(change.expires_at).toLocaleString()}</p><ul aria-label="Request approvals" className="text-xs">{change.approvals?.map(item => <li key={item.person_id}>{item.person_id} · {item.user_id}{item.invalidated_at ? ' · invalidated' : ' · approved'}</li>)}</ul>{(['approve', 'apply', 'reconcile'] as const).filter(action => canDecideChange(user, change, action)).map(action => <button key={action} type="button" onClick={() => onDecision(action)} className="mr-2 rounded border border-border px-3 py-2 text-sm">{action === 'approve' ? 'Approve this exact request' : action === 'apply' ? 'Apply this exact request' : 'Reconcile this transition'}</button>)}</article>
}

function WriteOnlyCredential() {
  const fileInput = useRef<HTMLInputElement>(null)
  const [kind, setKind] = useState<'destination' | 'password'>('destination')
  const [value, setValue] = useState('')
  const [reference, setReference] = useState('')
  const [failed, setFailed] = useState(false)
  const task = useSensitiveTask()
  const upload = async () => {
    const exact = value
    setValue(''); setReference(''); setFailed(false)
    if (fileInput.current) fileInput.current.value = ''
    try {
      const result = await task.run(signal => createSecuritySecret(kind, exact, signal))
      setReference(result.credential_ref)
    } catch { setFailed(true) }
  }
  const selectFile = async (file?: File) => {
    setValue(''); setReference(''); setFailed(false)
    if (fileInput.current) fileInput.current.value = ''
    if (!file) return
    if (!file.size || file.size > 8192) { setFailed(true); return }
    try {
      const exact = await task.run(async signal => { const bytes = await file.arrayBuffer(); signal.throwIfAborted(); return new TextDecoder('utf-8', { fatal: true }).decode(bytes) })
      setValue(exact)
    } catch { setFailed(true) }
  }
  return <section className="rounded border border-border bg-surface p-4 space-y-3"><h3 className="font-semibold text-text-primary">Upload write-only secret</h3><p className="text-xs text-text-muted">This separate write-only upload returns an immutable reference. It does not change policy. {kind === 'destination' ? 'Paste or load the exact configured credential document.' : 'Enter or load the exact recovery password; requests contain only its immutable reference.'}</p><label className="block text-sm text-text-secondary">Secret kind<select value={kind} disabled={task.busy} onChange={event => { setKind(event.target.value as typeof kind); setValue(''); setReference(''); if (fileInput.current) fileInput.current.value = '' }} className="block rounded border bg-elevated px-3 py-2"><option value="destination">Destination credential</option><option value="password">Recovery password</option></select></label><label className="block text-sm text-text-secondary">Write-only secret value<input type="password" autoComplete="off" value={value} disabled={task.busy} onChange={event => setValue(event.target.value)} className="block w-full rounded border border-border bg-elevated px-3 py-2" /></label><label className="block text-sm text-text-secondary">Credential file (UTF-8, at most 8192 bytes)<input ref={fileInput} type="file" disabled={task.busy} onChange={event => void selectFile(event.target.files?.[0])} className="block mt-1" /></label><button type="button" onClick={() => void upload()} disabled={task.busy || !value || new TextEncoder().encode(value).length > 8192} className="rounded border border-border px-3 py-2 text-sm disabled:opacity-50">Upload credential</button>{reference && <p role="status" className="text-sm break-all">Immutable credential reference: {reference}</p>}{failed && <p role="alert" className="text-sm text-status-error">Credential upload could not be confirmed. No secret value is retained in this form.</p>}</section>
}
