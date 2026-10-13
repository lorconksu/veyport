import { apiFetch, apiFetchOnce, ApiError } from './api'
import { getCSRFToken } from './auth'
import type {
  ExecutionFilters, ExecutionsPage, ExecutionView, OriginalHandle, OriginalPreview, OriginalRequest,
} from '@/types/executions'
import type { SecurityStepupResponse } from '@/types/security'

function executionPath(id: string): string {
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id)) throw new Error('Invalid execution ID')
  return `/executions/${encodeURIComponent(id)}`
}

export function listExecutions(filters: ExecutionFilters = {}, limit = 50, offset = 0, signal?: AbortSignal): Promise<ExecutionsPage> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(offset) || offset < 0 || offset > 1_000_000) {
    throw new Error('Bounded execution pagination required')
  }
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined && ['actor_id', 'node_id', 'os_user', 'policy_version', 'state', 'evidence_state'].includes(key)) continue
    if (!['actor_id', 'node_id', 'os_user', 'policy_version', 'state', 'evidence_state'].includes(key) || typeof value !== 'string' || new TextEncoder().encode(value).length > 256 || /\p{Cc}/u.test(value)) {
      throw new Error('Bounded execution filters required')
    }
    if (value) query.set(key, value)
  }
  return apiFetch(`/executions?${query}`, { signal, cache: 'no-store' })
}

export function getExecution(id: string, signal?: AbortSignal): Promise<ExecutionView> {
  return apiFetch(executionPath(id), { signal, cache: 'no-store' })
}

function validateRequest(request: OriginalRequest, digest?: string): void {
  if (!request.purpose || request.purpose !== request.purpose.trim() || new TextEncoder().encode(request.purpose).length > 1024 || /\p{Cc}/u.test(request.purpose) || request.records.length !== 1 || !['envelope', 'script'].includes(request.records[0])) {
    throw new Error('Purpose and one selected original required')
  }
  if (digest !== undefined && !/^[a-f0-9]{64}$/.test(digest)) throw new Error('Exact original preview digest required')
}

function safeOriginalError(error: unknown, secrets: string[]): Error {
  let message = error instanceof Error || error instanceof DOMException ? error.message : 'Original access failed'
  for (const secret of secrets) if (secret) message = message.replaceAll(secret, '[redacted]')
  return error instanceof ApiError ? new ApiError(message, error.status) : new Error(message)
}

async function originalPost<T>(path: string, body: unknown, secrets: string[] = [], signal?: AbortSignal): Promise<T> {
  try {
    return await apiFetchOnce<T>(path, { method: 'POST', body: JSON.stringify(body), cache: 'no-store', signal })
  } catch (error) {
    throw safeOriginalError(error, secrets)
  }
}

export function previewOriginalAccess(id: string, request: OriginalRequest, signal?: AbortSignal): Promise<OriginalPreview> {
  validateRequest(request)
  return originalPost(`${executionPath(id)}/original-access/preview`, request, [], signal)
}

export function originalAccessStepUp(id: string, request: OriginalRequest, digest: string, code: string, signal?: AbortSignal): Promise<SecurityStepupResponse> {
  validateRequest(request, digest)
  if (!/^\d{6}$/.test(code)) throw new Error('Fresh six-digit MFA code required')
  return originalPost(`${executionPath(id)}/original-access/step-up`, { ...request, digest, code }, [code], signal)
}

export function requestOriginalAccess(id: string, request: OriginalRequest, digest: string, proof: string, signal?: AbortSignal): Promise<OriginalHandle> {
  validateRequest(request, digest)
  if (!proof) throw new Error('Fresh original-read MFA proof required')
  return originalPost(`${executionPath(id)}/original-access`, { ...request, digest, step_up_proof: proof }, [proof], signal)
}

export async function downloadOriginal(access: OriginalHandle, signal?: AbortSignal): Promise<{ blob: Blob; filename: string }> {
  if (!/^[a-f0-9]{64}$/.test(access.handle) || access.download_url !== `/api/audit-originals/${access.handle}`) throw new Error('Exact one-use original download required')
  try {
    const response = await fetch(access.download_url, {
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
      headers: { Accept: 'application/octet-stream', 'X-CSRF-Token': getCSRFToken() },
    })
    if (!response.ok) {
      const body = await response.json().catch(() => null) as { error?: unknown } | null
      throw new ApiError(typeof body?.error === 'string' ? body.error : `HTTP ${response.status}`, response.status)
    }
    if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/octet-stream') throw new Error('Unexpected original download content type')
    const filename = /filename="([^"\r\n]+)"/.exec(response.headers.get('Content-Disposition') ?? '')?.[1] ?? 'audit-original.bin'
    const blob = await response.blob()
    return { blob, filename: /[/\\]|\p{Cc}/u.test(filename) ? 'audit-original.bin' : filename }
  } catch (error) {
    throw safeOriginalError(error, [access.handle])
  }
}
