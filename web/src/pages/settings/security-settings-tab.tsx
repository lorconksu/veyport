import { useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useAuth } from '@/hooks/use-auth'
import { canDecideChange } from '@/lib/security-authority'
import { canBootstrapSecurity, canViewSecurity, hasCapability } from '@/lib/auth'
import { getAuditPolicy, listSecurityChanges, listSecurityPrincipals, previewSecurityChange } from '@/lib/security-api'
import type { AuditPolicy, AuditPolicyResponse, SecurityChange, SecurityNomination, SecurityPreview, SecurityProposal, SecurityPrincipal } from '@/types/security'
import type { SecurityRole } from '@/types/api'

const PAGE_SIZE = 50

export interface SecuritySettingsActions {
  onPreview?: (proposal: SecurityProposal) => Promise<SecurityPreview>
  onRequest?: (preview: SecurityPreview) => void
  onApprove?: (change: SecurityChange) => void
  onApply?: (change: SecurityChange) => void
  onReconcile?: (change: SecurityChange) => void
}

function responseProfile(response: AuditPolicyResponse): string {
  return 'policy' in response ? response.policy.policy.profile : response.profile
}

function readinessLabel(response: AuditPolicyResponse, key: 'governance' | 'archive_and_transport' | 'enrollment_marker'): string {
  if (!('readiness' in response)) return 'Unavailable in this response'
  if (key === 'archive_and_transport' && responseProfile(response) === 'standard') return 'Not applicable while Standard is active'
  if (key !== 'governance' && !response.governance_enrolled) return 'Not applicable before enrollment'
  return response.readiness[key] ? 'Ready' : 'Not ready'
}

function PolicyDraft({
  response,
  user,
  onPreview,
  onRequest,
  principals,
  principalSearch,
  onPrincipalSearchChange,
  principalOffset,
  onPrincipalOffsetChange,
  principalTotal,
}: {
  response: AuditPolicyResponse
  user: NonNullable<ReturnType<typeof useAuth>['user']>
  onPreview?: SecuritySettingsActions['onPreview']
  onRequest?: SecuritySettingsActions['onRequest']
  principals: SecurityPrincipal[]
  principalSearch: string
  onPrincipalSearchChange: (value: string) => void
  principalOffset: number
  onPrincipalOffsetChange: (value: number) => void
  principalTotal: number
}) {
  const current = 'policy' in response ? response.policy.policy : undefined
  const initial: AuditPolicy = current ?? {
    profile: 'standard', actors: [], nodes: [], runtime_seconds: 3600, retention_hours: 720,
    destination: '', credential_ref: '', trust_key_ids: [], qualification_sha256: '',
  }
  const isBootstrap = response.governance_enrolled === false
  const [profile, setProfile] = useState<AuditPolicy['profile']>(isBootstrap ? 'enhanced' : initial.profile)
  const [actors, setActors] = useState(initial.actors.join(', '))
  const [nodes, setNodes] = useState(initial.nodes.join(', '))
  const [runtime, setRuntime] = useState(String(initial.runtime_seconds))
  const [retention, setRetention] = useState(String(initial.retention_hours))
  const [destination, setDestination] = useState(initial.destination)
  const [credentialRef, setCredentialRef] = useState(initial.credential_ref)
  const [trustKeyIDs, setTrustKeyIDs] = useState(initial.trust_key_ids.join(', '))
  const [qualificationHash, setQualificationHash] = useState(initial.qualification_sha256)
  const [reason, setReason] = useState('')
  const [nominees, setNominees] = useState([
    { principalId: user.id, personId: user.person_id ?? '', verification: '', role: 'security-officer' as SecurityRole },
    { principalId: '', personId: '', verification: '', role: 'security-approver' as SecurityRole },
    { principalId: '', personId: '', verification: '', role: 'security-approver' as SecurityRole },
  ])
  const [selectedPrincipalSnapshots, setSelectedPrincipalSnapshots] = useState<Array<SecurityPrincipal | null>>([null, null])
  const draftRevision = useRef(0)
  const [draftVersion, setDraftVersion] = useState(0)
  const [confirmedPreview, setConfirmedPreview] = useState<{ value: SecurityPreview; revision: number } | null>(null)
  const [previewFailure, setPreviewFailure] = useState<{ message: string; revision: number } | null>(null)

  const policy: AuditPolicy = {
    ...initial,
    profile,
    actors: actors.split(',').map(value => value.trim()).filter(Boolean),
    nodes: nodes.split(',').map(value => value.trim()).filter(Boolean),
    runtime_seconds: Number(runtime),
    retention_hours: Number(retention),
    destination,
    credential_ref: credentialRef,
    trust_key_ids: trustKeyIDs.split(',').map(value => value.trim()).filter(Boolean),
    qualification_sha256: qualificationHash,
  }
  const expectedVersion = 'policy' in response ? response.policy.version : response.version
  const nominationList: SecurityNomination[] = nominees
    .filter(nominee => nominee.principalId && nominee.personId.trim() && nominee.verification.trim())
    .map(nominee => ({ user_id: nominee.principalId, person_id: nominee.personId.trim(), verification: nominee.verification.trim(), roles: [nominee.role] }))
  const proposal: SecurityProposal = {
    reason: reason.trim(), expected_version: expectedVersion,
    change: response.governance_enrolled === false ? { kind: 'bootstrap', policy, nominations: nominationList } : { kind: 'policy', policy },
  }
  const previewMutation = useMutation({
    mutationFn: ({ next }: { next: SecurityProposal; revision: number }) => onPreview ? onPreview(next) : previewSecurityChange(next),
    onSuccess: (value, variables) => {
      if (variables.revision === draftRevision.current) setConfirmedPreview({ value, revision: variables.revision })
    },
    onError: (error, variables) => {
      if (variables.revision === draftRevision.current) setPreviewFailure({ message: error instanceof Error ? error.message : 'Preview failed.', revision: variables.revision })
    },
  })
  const invalidatePreview = () => {
    draftRevision.current += 1
    setDraftVersion(draftRevision.current)
    setConfirmedPreview(null)
    setPreviewFailure(null)
    previewMutation.reset()
  }
  const activePreview = confirmedPreview?.revision === draftVersion ? confirmedPreview.value : null
  const activeFailure = previewFailure?.revision === draftVersion ? previewFailure.message : null
  const update = <T,>(setter: (value: T) => void, value: T) => {
    invalidatePreview()
    setter(value)
  }

  return (
    <section className="bg-surface border border-border rounded p-4 space-y-4" aria-labelledby="policy-draft-title">
      <div>
        <h3 id="policy-draft-title" className="text-sm font-semibold text-text-primary">Policy request</h3>
        <p className="text-xs text-text-muted mt-1">Changes are reviewed as proposals. This form never changes enforcement on its own.</p>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs text-text-muted">Profile
          <select value={profile} disabled={isBootstrap} onChange={event => update(setProfile, event.target.value as AuditPolicy['profile'])} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary disabled:opacity-60">
            {!isBootstrap && <option value="standard">Standard</option>}<option value="enhanced">Enhanced</option>
          </select>
        </label>
        <label className="text-xs text-text-muted">Runtime limit (seconds)
          <input type="number" min="1" value={runtime} onChange={event => update(setRuntime, event.target.value)} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Actor IDs (comma separated)
          <input value={actors} onChange={event => update(setActors, event.target.value)} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Node IDs (comma separated)
          <input value={nodes} onChange={event => update(setNodes, event.target.value)} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Retention (hours)
          <input type="number" min="1" value={retention} onChange={event => update(setRetention, event.target.value)} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Archive destination
          <input value={destination} onChange={event => update(setDestination, event.target.value)} maxLength={4096} placeholder="Configured archive destination" className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Immutable credential reference
          <input value={credentialRef} onChange={event => update(setCredentialRef, event.target.value)} maxLength={256} placeholder="Write-only credential reference" className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Trust key IDs (comma separated)
          <input value={trustKeyIDs} onChange={event => update(setTrustKeyIDs, event.target.value)} maxLength={2048} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
        <label className="text-xs text-text-muted">Qualification SHA-256
          <input value={qualificationHash} onChange={event => update(setQualificationHash, event.target.value)} maxLength={64} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
        </label>
      </div>
      {response.governance_enrolled === false && (
        <fieldset className="rounded border border-border p-3 space-y-3">
          <legend className="text-sm font-semibold text-text-primary px-1">Initial officer and approver nominations</legend>
          <p className="text-xs text-text-muted">The requester must be the nominated security officer. Add two other people as approvers. Record verified person IDs and the operator evidence for all three; each person must be distinct and have completed MFA.</p>
          <label className="block text-xs text-text-muted">Search principals<input value={principalSearch} onChange={event => onPrincipalSearchChange(event.target.value)} maxLength={128} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" /></label>
          <p className="text-xs text-text-muted">Showing {principalTotal ? principalOffset + 1 : 0}–{Math.min(principalOffset + principals.length, principalTotal)} of {principalTotal} eligible principals.</p>
          {nominees.map((nominee, index) => {
            const selectedSnapshot = index > 0 ? selectedPrincipalSnapshots[index - 1] : null
            const principalOptions = principals.filter(principal => principal.totp_enabled)
            if (selectedSnapshot && !principalOptions.some(principal => principal.id === selectedSnapshot.id)) principalOptions.unshift(selectedSnapshot)
            return <div key={index} className="grid gap-2 md:grid-cols-4">
            <label className="text-xs text-text-muted">Principal
              {index === 0 ? <input value={`${user.username} · ${user.id}`} readOnly aria-label="Requesting officer" className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" /> : <select value={nominee.principalId} onChange={event => {
                const principalId = event.target.value
                const selected = principals.find(principal => principal.id === principalId) ?? selectedPrincipalSnapshots[index - 1]
                invalidatePreview()
                setNominees(rows => rows.map((row, rowIndex) => rowIndex === index ? { ...row, principalId } : row))
                setSelectedPrincipalSnapshots(rows => rows.map((row, rowIndex) => rowIndex === index - 1 ? (principalId ? selected ?? null : null) : row))
              }} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary">
                <option value="">Select principal</option>{principalOptions.map(principal => <option key={principal.id} value={principal.id}>{principal.username} · {principal.id}</option>)}
              </select>}
              {index === 0 && <span className="block mt-1 text-text-muted">Security officer · requester</span>}
              {index > 0 && <span className="block mt-1 text-text-muted">Security approver</span>}
            </label>
            <label className="text-xs text-text-muted">Verified person ID<input value={nominee.personId} maxLength={128} onChange={event => { invalidatePreview(); setNominees(rows => rows.map((row, rowIndex) => rowIndex === index ? { ...row, personId: event.target.value } : row)) }} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" /></label>
            <label className="text-xs text-text-muted">Operator verification evidence<input value={nominee.verification} maxLength={2048} onChange={event => { invalidatePreview(); setNominees(rows => rows.map((row, rowIndex) => rowIndex === index ? { ...row, verification: event.target.value } : row)) }} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" /></label>
          </div>
          })}
          <div className="flex justify-end gap-2"><button type="button" onClick={() => onPrincipalOffsetChange(Math.max(0, principalOffset - 50))} disabled={principalOffset === 0} className="text-xs border border-border rounded px-3 py-2 disabled:opacity-50">Previous principals</button><button type="button" onClick={() => onPrincipalOffsetChange(principalOffset + 50)} disabled={principalOffset + principals.length >= principalTotal} className="text-xs border border-border rounded px-3 py-2 disabled:opacity-50">Next principals</button></div>
        </fieldset>
      )}
      <label className="block text-xs text-text-muted">Reason
        <textarea value={reason} onChange={event => update(setReason, event.target.value)} maxLength={2048} rows={2} className="mt-1 w-full bg-elevated border border-border rounded px-3 py-2 text-sm text-text-primary" />
      </label>
      {isBootstrap && !user.totp_enabled && <p className="text-sm text-status-error" role="alert">The requesting officer must have completed MFA before governance can be enrolled.</p>}
      <button type="button" onClick={() => { setConfirmedPreview(null); setPreviewFailure(null); previewMutation.mutate({ next: proposal, revision: draftRevision.current }) }} disabled={previewMutation.isPending || !reason.trim() || !Number.isSafeInteger(policy.runtime_seconds) || policy.runtime_seconds < 1 || !Number.isSafeInteger(policy.retention_hours) || policy.retention_hours < 1 || (isBootstrap && (!user.totp_enabled || policy.profile !== 'enhanced' || nominationList.length !== 3 || nominationList[0]?.user_id !== user.id || nominationList[0]?.roles[0] !== 'security-officer' || nominationList.slice(1).some(item => item.roles[0] !== 'security-approver') || new Set(nominationList.map(item => item.person_id)).size !== 3 || new Set(nominationList.map(item => item.user_id)).size !== 3))} className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-3 py-2 disabled:opacity-50">{previewMutation.isPending ? 'Preparing preview…' : 'Preview request'}</button>
      {activeFailure && <p className="text-sm text-status-error" role="alert">Preview failed. {activeFailure}</p>}
      {activePreview && (
        <div className="rounded border border-border bg-elevated/40 p-3 space-y-2" aria-live="polite">
          <h4 className="text-sm font-semibold text-text-primary">Confirm exact request</h4>
          <p className="text-xs text-text-secondary">Reason: {activePreview.proposal.reason}</p>
          <p className="text-xs text-text-secondary">Expected policy version: {activePreview.proposal.expected_version}</p>
          <pre className="text-xs text-text-secondary whitespace-pre-wrap break-all">{JSON.stringify(activePreview.proposal.change, null, 2)}</pre>
          <p className="text-xs text-text-muted break-all">Digest: {activePreview.digest}</p>
          <p className="text-xs text-text-muted">A request requires fresh MFA and two approvals from independent people. Operator administrator status does not grant approval authority.</p>
          <button type="button" onClick={() => onRequest?.(activePreview)} disabled={!onRequest} className="bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded px-3 py-2 disabled:opacity-50">Request this change</button>
        </div>
      )}
    </section>
  )
}

function ApprovalsPanel({ actions }: { actions: SecuritySettingsActions }) {
  const { user } = useAuth()
  const [offset, setOffset] = useState(0)
  const changesQuery = useQuery({
    queryKey: ['security', 'changes', user?.id, PAGE_SIZE, offset],
    queryFn: ({ signal }) => listSecurityChanges(PAGE_SIZE, offset, signal),
    enabled: hasCapability(user, 'security.read') || hasCapability(user, 'security.approve') || hasCapability(user, 'security.apply'),
  })
  const changes = changesQuery.data?.changes ?? []
  const canApprove = hasCapability(user, 'security.approve')
  const canApply = hasCapability(user, 'security.apply')
  const canList = hasCapability(user, 'security.read') || canApprove || canApply

  return (
    <section className="bg-surface border border-border rounded p-4 space-y-3" aria-labelledby="approvals-title">
      <div><h3 id="approvals-title" className="text-sm font-semibold text-text-primary">Approvals</h3><p className="text-xs text-text-muted mt-1">Requests show their exact reason, revision, digest, expiry, and independent-person approvals.</p></div>
      {changesQuery.isLoading && <p className="text-sm text-text-muted" role="status">Loading requests…</p>}
      {changesQuery.isError && <p className="text-sm text-status-error" role="alert">Failed to load security requests. {changesQuery.error instanceof Error ? changesQuery.error.message : ''}</p>}
      {!canList && <p className="text-sm text-text-muted">The broad request list is unavailable to this account.</p>}
      {canList && !changesQuery.isLoading && !changesQuery.isError && changes.length === 0 && <p className="text-sm text-text-muted">No security requests are available.</p>}
      <div className="space-y-3">
        {changes.map(change => (
          <article key={`${change.id}:${change.revision}`} className="rounded border border-border p-3 space-y-2">
            <div className="flex flex-wrap justify-between gap-2"><h4 className="text-sm font-semibold text-text-primary">{change.change.kind} · {change.state}</h4><span className="text-xs text-text-muted">Expires {new Date(change.expires_at).toLocaleString()}</span></div>
            <p className="text-xs text-text-secondary">Reason: {change.reason}</p>
            <p className="text-xs text-text-secondary">Requested by {change.requester_id} · revision {change.revision} · {change.approvals?.length ?? 0} approval(s)</p>
            {change.approvals && change.approvals.length > 0 && <ul className="text-xs text-text-secondary space-y-1" aria-label="Independent-person approvals">{change.approvals.map((approval, index) => <li key={`${approval.person_id}:${index}`}>{approval.person_id} · {approval.user_id} · {new Date(approval.approved_at).toLocaleString()}{approval.invalidated_at ? ' · invalidated' : ''}</li>)}</ul>}
            <p className="text-xs text-text-muted break-all">Digest: {change.digest}</p>
            <pre className="text-xs text-text-secondary whitespace-pre-wrap break-all">{JSON.stringify(change.change, null, 2)}</pre>
            {canDecideChange(user, change, 'approve') && <button type="button" disabled={!actions.onApprove} onClick={() => actions.onApprove?.(change)} className="mr-2 text-xs border border-border rounded px-3 py-2 disabled:opacity-50">Approve request</button>}
            {canDecideChange(user, change, 'apply') && <button type="button" disabled={!actions.onApply} onClick={() => actions.onApply?.(change)} className="mr-2 text-xs border border-border rounded px-3 py-2 disabled:opacity-50">Apply request</button>}
            {canDecideChange(user, change, 'reconcile') && <button type="button" disabled={!actions.onReconcile} onClick={() => actions.onReconcile?.(change)} className="text-xs border border-border rounded px-3 py-2 disabled:opacity-50">Reconcile apply</button>}
          </article>
        ))}
      </div>
      {!changesQuery.isLoading && !changesQuery.isError && (changes.length > 0 || offset > 0) && <div className="flex items-center justify-between text-sm text-text-muted"><span>{changes.length ? `Showing ${offset + 1}–${offset + changes.length} requests` : 'No requests on this page'}</span><div className="flex gap-2"><button type="button" onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0 || changesQuery.isFetching} className="text-xs border border-border rounded px-3 py-2 disabled:opacity-50">Previous requests</button><button type="button" onClick={() => setOffset(offset + PAGE_SIZE)} disabled={changes.length < PAGE_SIZE || changesQuery.isFetching} className="text-xs border border-border rounded px-3 py-2 disabled:opacity-50">Next requests</button></div></div>}
    </section>
  )
}

export function SecuritySettingsTab(actions: SecuritySettingsActions) {
  const { user } = useAuth()
  const canQuery = hasCapability(user, 'security.read') || hasCapability(user, 'security.bootstrap')
  const [principalSearch, setPrincipalSearch] = useState('')
  const [principalOffset, setPrincipalOffset] = useState(0)
  const policyQuery = useQuery({
    queryKey: ['security', 'policy', user?.id],
    queryFn: ({ signal }) => getAuditPolicy(signal),
    enabled: canQuery,
  })
  const policy = policyQuery.data
  const visible = canViewSecurity(user, policy)
  const principalsQuery = useQuery({
    queryKey: ['security', 'principals', user?.id, 50, principalOffset, principalSearch],
    queryFn: ({ signal }) => listSecurityPrincipals(50, principalOffset, principalSearch, signal),
    enabled: visible,
  })

  if (!canQuery) return <div className="text-sm text-text-muted">Security settings are unavailable to this account.</div>
  if (policyQuery.isLoading) return <div className="text-sm text-text-muted" role="status">Loading security readiness…</div>
  if (policyQuery.isError) return <div className="text-sm text-status-error" role="alert">Failed to load security readiness. {policyQuery.error instanceof Error ? policyQuery.error.message : ''}</div>
  if (!visible || !policy) return <div className="text-sm text-text-muted">Security settings are not available for this policy.</div>

  const enrolled = policy.governance_enrolled
  const active = 'policy' in policy ? policy.policy : null
  const pending = 'pending' in policy ? policy.pending : null

  return (
    <div className="space-y-4">
      <section className="bg-surface border border-border rounded p-4 space-y-3">
        <div className="flex flex-wrap justify-between gap-2"><div><h3 className="text-sm font-semibold text-text-primary">Auditing</h3><p className="text-xs text-text-muted mt-1">Current policy and server-reported readiness.</p></div><span className="text-xs rounded bg-elevated px-2 py-1 text-text-secondary">{policy.state}</span></div>
        <div className="grid gap-3 md:grid-cols-3">
          <Readiness label="Independent governance" value={readinessLabel(policy, 'governance')} />
          <Readiness label="Archive and transport" value={readinessLabel(policy, 'archive_and_transport')} />
          <Readiness label="Enrollment marker" value={readinessLabel(policy, 'enrollment_marker')} />
        </div>
        <p className="text-sm text-text-secondary">Active profile: {responseProfile(policy)}{active ? ` · version ${active.version} · ${active.sha256}` : ` · version ${'version' in policy ? policy.version : policy.policy.version}`}</p>
        {pending && <div className="rounded border border-status-warning/30 bg-status-warning/10 p-3 text-xs text-text-secondary">Pending policy version {pending.version} · {pending.policy.profile} · digest {pending.sha256}</div>}
        {!enrolled && <p className="text-xs text-text-muted">Governance is not enrolled. Archive and enrollment-marker readiness do not apply until enrollment.</p>}
        {policyQuery.data && 'credential_set' in policyQuery.data && <p className="text-xs text-text-muted">Destination credential: {policyQuery.data.credential_set ? 'configured' : 'not configured'}</p>}
      </section>
      {principalsQuery.isError && <p className="text-sm text-status-error" role="alert">Unable to load the safe principal list. {principalsQuery.error instanceof Error ? principalsQuery.error.message : ''}</p>}
      {principalsQuery.isLoading && <p className="text-sm text-text-muted" role="status">Loading eligible principals…</p>}
      {principalsQuery.data && <p className="text-xs text-text-muted">Safe principal selector: {principalsQuery.data.principals.length} of {principalsQuery.data.total} principals loaded. Initial nominations require separate operator verification.</p>}
      {(hasCapability(user, 'security.request') || canBootstrapSecurity(user, policy)) && <PolicyDraft key={`${user?.id}:${'policy' in policy ? policy.policy.version : policy.version}:${policy.governance_enrolled}`} response={policy} user={user!} onPreview={actions.onPreview} onRequest={actions.onRequest} principals={principalsQuery.data?.principals ?? []} principalSearch={principalSearch} onPrincipalSearchChange={value => { setPrincipalSearch(value); setPrincipalOffset(0) }} principalOffset={principalOffset} onPrincipalOffsetChange={setPrincipalOffset} principalTotal={principalsQuery.data?.total ?? 0} />}
      <ApprovalsPanel actions={actions} />
    </div>
  )
}

function Readiness({ label, value }: { label: string; value: string }) {
  const ready = value === 'Ready'
  return <div className="rounded border border-border bg-elevated/40 p-3"><div className="text-xs text-text-muted">{label}</div><div className={`text-sm font-semibold mt-1 ${ready ? 'text-status-online' : 'text-text-secondary'}`}>{value}</div></div>
}
