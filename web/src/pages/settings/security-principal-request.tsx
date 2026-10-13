import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '@/hooks/use-auth'
import { getAuditPolicy, listSecurityPrincipals } from '@/lib/security-api'
import type { SecurityPreview, SecurityProposal, SecurityChangePayload } from '@/types/security'
import type { SecurityRole } from '@/types/api'
import { useSensitiveTask } from '@/hooks/use-sensitive-task'

export function SecurityPrincipalRequest({ onPreview, onRequest }: { onPreview: (proposal: SecurityProposal, signal: AbortSignal) => Promise<SecurityPreview>; onRequest: (preview: SecurityPreview) => void }) {
  const { user } = useAuth()
  const policy = useQuery({ queryKey: ['security', 'policy', user?.id], queryFn: ({ signal }) => getAuditPolicy(signal) })
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const principals = useQuery({ queryKey: ['security', 'principals', user?.id, 50, offset, search], queryFn: ({ signal }) => listSecurityPrincipals(50, offset, search, signal) })
  const [userID, setUserID] = useState('')
  const [operation, setOperation] = useState('grant-role')
  const [role, setRole] = useState<SecurityRole>('original-reader')
  const [personID, setPersonID] = useState('')
  const [verification, setVerification] = useState('')
  const [secretRef, setSecretRef] = useState('')
  const [reason, setReason] = useState('')
  const [preview, setPreview] = useState<SecurityPreview | null>(null)
  const [failed, setFailed] = useState(false)
  const task = useSensitiveTask()
  const clear = () => { task.cancel(); setPreview(null); setFailed(false) }
  const prepare = async () => {
    const response = policy.data
    if (!response || !('policy' in response)) return
    let change: SecurityChangePayload
    if (operation === 'grant-role' || operation === 'revoke-role') change = { kind: 'role', role: { user_id: userID, role, grant: operation === 'grant-role' } }
    else if (operation === 'link-person') change = { kind: 'person', person: { user_id: userID, person_id: personID, verification } }
    else change = { kind: 'recovery', recovery: { user_id: userID, operation: operation as 'reenable' | 'mfa-reset' | 'password-reset', ...(operation === 'password-reset' ? { secret_ref: secretRef } : {}) } }
    setFailed(false); setPreview(null)
    try { setPreview(await task.run(signal => onPreview({ reason: reason.trim(), expected_version: response.policy.version, change }, signal))) } catch (error) { if (!(error instanceof DOMException && error.name === 'AbortError')) setFailed(true) }
  }
  const disabled = !userID || !reason.trim() || (operation === 'link-person' && (!personID.trim() || !verification.trim())) || (operation === 'password-reset' && !secretRef.trim())
  return <section className="rounded border border-border bg-surface p-4 space-y-3"><h3 className="font-semibold text-text-primary">Protected principal request</h3><p className="text-xs text-text-muted">Role, verified-person and recovery changes use the same independent quorum. Password recovery refers to a separate write-only secret upload.</p>
    <label className="block text-sm">Search protected principals<input value={search} maxLength={128} onChange={event => { clear(); setSearch(event.target.value); setOffset(0) }} className="block rounded border bg-elevated px-3 py-2" /></label>
    <label className="block text-sm">Target principal ID<input value={userID} list="safe-security-principals" maxLength={128} onChange={event => { clear(); setUserID(event.target.value) }} className="block w-full rounded border bg-elevated px-3 py-2" /></label><datalist id="safe-security-principals">{principals.data?.principals.map(item => <option key={item.id} value={item.id}>{item.username}</option>)}</datalist>
    <div className="flex gap-2"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))} className="rounded border px-2 py-1 text-xs">Previous protected principals</button><button disabled={!principals.data || offset + principals.data.principals.length >= principals.data.total} onClick={() => setOffset(offset + 50)} className="rounded border px-2 py-1 text-xs">Next protected principals</button></div>
    <label className="block text-sm">Protected operation<select value={operation} onChange={event => { clear(); setOperation(event.target.value) }} className="block rounded border bg-elevated px-3 py-2"><option value="grant-role">Grant security role</option><option value="revoke-role">Revoke security role</option><option value="link-person">Link verified person</option><option value="reenable">Reenable protected principal</option><option value="mfa-reset">Reset protected MFA</option><option value="password-reset">Reset protected password</option></select></label>
    {(operation === 'grant-role' || operation === 'revoke-role') && <label className="block text-sm">Security role<select value={role} onChange={event => { clear(); setRole(event.target.value as SecurityRole) }} className="block rounded border bg-elevated px-3 py-2"><option value="original-reader">Original reader</option><option value="security-officer">Security officer</option><option value="security-approver">Security approver</option></select></label>}
    {operation === 'link-person' && <><label className="block text-sm">New verified person ID<input value={personID} maxLength={128} onChange={event => { clear(); setPersonID(event.target.value) }} className="block rounded border bg-elevated px-3 py-2" /></label><label className="block text-sm">Person verification evidence<textarea value={verification} maxLength={2048} onChange={event => { clear(); setVerification(event.target.value) }} className="block w-full rounded border bg-elevated px-3 py-2" /></label></>}
    {operation === 'password-reset' && <label className="block text-sm">Immutable password secret reference<input value={secretRef} maxLength={256} onChange={event => { clear(); setSecretRef(event.target.value) }} className="block w-full rounded border bg-elevated px-3 py-2" /></label>}
    <label className="block text-sm">Principal change reason<textarea value={reason} maxLength={2048} onChange={event => { clear(); setReason(event.target.value) }} className="block w-full rounded border bg-elevated px-3 py-2" /></label>
    <button type="button" disabled={disabled || task.busy || !policy.isSuccess || principals.isError} onClick={() => void prepare()} className="rounded border px-3 py-2 text-sm disabled:opacity-50">Preview protected principal request</button>
    {(failed || policy.isError || principals.isError) && <p role="alert" className="text-sm text-status-error">The protected request could not be prepared. Check live authority and current policy before starting again.</p>}
    {preview && <div className="space-y-2"><p className="text-sm">Expected policy version: {preview.proposal.expected_version}</p><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(preview.proposal.change, null, 2)}</pre><p className="text-xs break-all">Digest: {preview.digest}</p><button type="button" onClick={() => onRequest(preview)} className="rounded border px-3 py-2 text-sm">Request this protected principal change</button></div>}
  </section>
}
