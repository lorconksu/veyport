import { apiFetch, apiFetchOnce, ApiError } from './api'
import type {
  AuditPolicy, AuditPolicyResponse, SecurityAction, SecurityChange, SecurityChangesPage,
  SecurityCredentialReference, SecurityPreview, SecurityPrincipalsPage, SecurityProposal,
  SecurityStepupResponse,
} from '@/types/security'

function changePath(id: string): string {
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id)) throw new Error('Invalid security change ID')
  return `/security/changes/${encodeURIComponent(id)}`
}

function requireDigest(digest: string): void {
  if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error('Exact security proposal digest required')
}

async function securityPost<T>(path: string, body: unknown, secrets: string[] = [], signal?: AbortSignal): Promise<T> {
  try {
    return await apiFetchOnce<T>(path, { method: 'POST', body: JSON.stringify(body), cache: 'no-store', signal })
  } catch (error) {
    throw redactedSecurityError(error, secrets)
  }
}

// Preserve actionable status but deliberately discard an original cause/stack:
// the thrown value can itself contain write-only input or an MFA proof.
function redactedSecurityError(error: unknown, secrets: string[]): Error {
  if (!(error instanceof Error)) return new Error('Security operation failed')
  let message = error.message
  for (const secret of secrets) {
    if (!secret) continue
    message = message.replaceAll(secret, '[redacted]').replaceAll(JSON.stringify(secret).slice(1, -1), '[redacted]')
  }
  return error instanceof ApiError ? new ApiError(message, error.status) : new Error(message)
}

export function getAuditPolicy(signal?: AbortSignal): Promise<AuditPolicyResponse> {
  return apiFetch('/audit-policy', { signal, cache: 'no-store' })
}

export function testAuditPolicy(policy: AuditPolicy, signal?: AbortSignal): Promise<{ ready: boolean }> {
  return securityPost('/audit-policy/test', policy, [], signal)
}

export function createSecuritySecret(kind: 'destination' | 'password', value: string, signal?: AbortSignal): Promise<SecurityCredentialReference> {
  if (!value || new TextEncoder().encode(value).length > 8192) throw new Error('Bounded write-only secret required')
  return securityPost('/security/secrets', { kind, value }, [value], signal)
}

export function previewSecurityChange(proposal: SecurityProposal, signal?: AbortSignal): Promise<SecurityPreview> {
  if (!proposal.reason.trim() || new TextEncoder().encode(proposal.reason).length > 2048 || !Number.isSafeInteger(proposal.expected_version) || proposal.expected_version < 1) {
    throw new Error('Reason and explicit expected policy version required')
  }
  return securityPost('/security/changes/preview', proposal, [], signal)
}

export function requestSecurityChange(preview: SecurityPreview, proof: string, signal?: AbortSignal): Promise<SecurityChange> {
  requireDigest(preview.digest)
  if (!proof) throw new Error('Fresh request MFA proof required')
  // Use the returned typed proposal exactly. The hub recomputes its canonical
  // digest and consumes only a proof bound to this action/session/proposal.
  return securityPost('/security/changes', { ...preview.proposal, step_up_proof: proof }, [proof], signal)
}

export function listSecurityChanges(limit = 50, offset = 0, signal?: AbortSignal): Promise<SecurityChangesPage> {
  const query = pageQuery(limit, offset)
  return apiFetch(`/security/changes?${query}`, { signal, cache: 'no-store' })
}

export function getSecurityChange(id: string, signal?: AbortSignal): Promise<SecurityChange> {
  return apiFetch(changePath(id), { signal, cache: 'no-store' })
}

export function securityStepUp(action: SecurityAction, digest: string, code: string, changeId?: string, signal?: AbortSignal): Promise<SecurityStepupResponse> {
  requireDigest(digest)
  if (!['security.request', 'security.approve', 'security.apply'].includes(action)) throw new Error('Invalid security action')
  if (!/^\d{6}$/.test(code)) throw new Error('Fresh six-digit MFA code required')
  if (action !== 'security.request' && !changeId) throw new Error('Exact change ID required for approval/apply MFA')
  if (changeId) changePath(changeId)
  return securityPost('/security/step-up', { action, digest, code, ...(changeId ? { change_id: changeId } : {}) }, [code], signal)
}

export function approveSecurityChange(change: Pick<SecurityChange, 'id' | 'digest'>, proof: string, signal?: AbortSignal): Promise<SecurityChange> {
  return mutateSecurityChange(change, proof, 'approve', signal)
}

export function applySecurityChange(change: Pick<SecurityChange, 'id' | 'digest'>, proof: string, signal?: AbortSignal): Promise<SecurityChange> {
  return mutateSecurityChange(change, proof, 'apply', signal)
}

function mutateSecurityChange(change: Pick<SecurityChange, 'id' | 'digest'>, proof: string, action: 'approve' | 'apply', signal?: AbortSignal): Promise<SecurityChange> {
  requireDigest(change.digest)
  if (!proof) throw new Error('Fresh action-bound MFA proof required')
  return securityPost(`${changePath(change.id)}/${action}`, { step_up_proof: proof }, [proof], signal)
}

export function reconcileSecurityChange(id: string, signal?: AbortSignal): Promise<SecurityChange> {
  return securityPost(`${changePath(id)}/reconcile`, undefined, [], signal)
}

export function listSecurityPrincipals(limit = 50, offset = 0, search = '', signal?: AbortSignal): Promise<SecurityPrincipalsPage> {
  const query = pageQuery(limit, offset)
  if (new TextEncoder().encode(search).length > 128 || /[\r\n\0]/.test(search)) throw new Error('Bounded principal search required')
  if (search) query.set('search', search)
  return apiFetch(`/security/principals?${query}`, { signal, cache: 'no-store' })
}

function pageQuery(limit: number, offset: number): URLSearchParams {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(offset) || offset < 0 || offset > 1_000_000) {
    throw new Error('Bounded security pagination required')
  }
  return new URLSearchParams({ limit: String(limit), offset: String(offset) })
}
