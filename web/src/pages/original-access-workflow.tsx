import { useEffect, useRef, useState } from 'react'
import { useAuth } from '@/hooks/use-auth'
import { useSensitiveTask } from '@/hooks/use-sensitive-task'
import { FreshMFADialog } from '@/components/fresh-mfa-dialog'
import { hasCapability } from '@/lib/auth'
import { securityIdentityKey } from '@/lib/security-authority'
import { downloadOriginal, originalAccessStepUp, previewOriginalAccess, requestOriginalAccess } from '@/lib/executions-api'
import type { ExecutionView, OriginalPreview, OriginalRequest } from '@/types/executions'
import { ExecutionInvestigation } from './execution-investigation'

export function OriginalAccessInvestigation() {
  const { user } = useAuth()
  return <OriginalAccessSession key={securityIdentityKey(user)} />
}

function OriginalAccessSession() {
  const { user } = useAuth()
  const [pending, setPending] = useState<{ execution: ExecutionView; request: OriginalRequest } | null>(null)
  const [notice, setNotice] = useState('')
  return <>
    {notice && <p role="status" className="text-sm text-text-secondary">{notice}</p>}
    <ExecutionInvestigation onRequestOriginal={hasCapability(user, 'audit.original.read') ? (execution, request) => { setNotice(''); setPending({ execution, request }) } : undefined} />
    {pending && hasCapability(user, 'audit.original.read') && <OriginalReview key={`${pending.execution.id}:${pending.request.records[0]}:${pending.request.purpose}`} execution={pending.execution} request={pending.request} onClose={() => setPending(null)} onSuccess={() => { setPending(null); setNotice('The hub delivered the original response bytes to this browser. This does not confirm that a file was saved.') }} />}
  </>
}

function OriginalReview({ execution, request, onClose, onSuccess }: { execution: ExecutionView; request: OriginalRequest; onClose: () => void; onSuccess: () => void }) {
  const { refreshUser } = useAuth()
  const [preview, setPreview] = useState<OriginalPreview | null>(null)
  const [failed, setFailed] = useState(false)
  const blobURL = useRef<string | null>(null)
  const task = useSensitiveTask()
  const run = task.run
  useEffect(() => {
    let active = true
    void run(signal => previewOriginalAccess(execution.id, request, signal)).then(value => { if (active) setPreview(value) }).catch(error => { if (active && !(error instanceof DOMException && error.name === 'AbortError')) setFailed(true) })
    return () => { active = false; if (blobURL.current) { URL.revokeObjectURL(blobURL.current); blobURL.current = null } }
  }, [execution.id, request, run])
  const submit = async (code: string, signal: AbortSignal) => {
    if (!preview) throw new Error('Exact descriptor preview required')
    const latest = await previewOriginalAccess(execution.id, request, signal)
    signal.throwIfAborted()
    if (latest.digest !== preview.digest || JSON.stringify(latest.records) !== JSON.stringify(preview.records)) throw new Error('Original selection changed; preview it again')
    const step = await originalAccessStepUp(execution.id, request, preview.digest, code, signal)
    signal.throwIfAborted()
    if (!Number.isFinite(Date.parse(step.expires_at)) || Date.parse(step.expires_at) <= Date.now()) throw new Error('Fresh proof expired')
    const proof = step.proof
    const access = await requestOriginalAccess(execution.id, request, preview.digest, proof, signal)
    signal.throwIfAborted()
    // The handle remains local and is consumed immediately. Never navigate
    // to it or retain it in React/query state, history or storage.
    const response = await downloadOriginal(access, signal)
    signal.throwIfAborted()
    const url = URL.createObjectURL(response.blob)
    blobURL.current = url
    const link = document.createElement('a')
    link.href = url; link.download = response.filename
    document.body.append(link); link.click(); link.remove()
    setTimeout(() => { URL.revokeObjectURL(url); if (blobURL.current === url) blobURL.current = null }, 0)
  }
  if (!preview) return <div role="dialog" aria-modal="true" aria-label="Preview protected original" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"><div className="max-w-lg rounded border border-border bg-surface p-5 space-y-3"><h3 className="font-semibold">Preview protected original</h3>{failed ? <p role="alert" className="text-sm text-status-error">The original is unavailable or access was refused. Start a new review after checking current authority and retention.</p> : <p role="status">Loading exact original descriptors…</p>}<button type="button" onClick={onClose} className="rounded border border-border px-3 py-2">Cancel</button></div></div>
  return <FreshMFADialog title="Confirm protected original access" onClose={onClose} onSubmit={submit} onSuccess={() => { onSuccess(); void refreshUser() }}>
    <p className="text-sm text-text-secondary">Execution {execution.id} · purpose: {request.purpose}</p>
    <ul className="text-xs text-text-secondary space-y-2" aria-label="Exact original descriptors">{preview.records.map(record => <li key={record.version_id}><p>{record.kind} · {record.bytes} bytes</p><p className="break-all">Event: {record.event_id}</p><p className="break-all">SHA-256: {record.sha256}</p><p className="break-all">Version: {record.version_id}</p></li>)}</ul>
    <p className="text-xs break-all text-text-secondary">Digest: {preview.digest}</p>
    <p className="text-xs text-text-muted">Fresh MFA authorizes audit.original.read for this exact purpose, selection and session. The one-use access is consumed immediately; a refused or interrupted read requires a new review.</p>
  </FreshMFADialog>
}
