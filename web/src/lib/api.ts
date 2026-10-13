import { getCSRFToken } from './auth'

const BASE_URL = '/api'

// Singleton refresh promise to prevent race conditions when multiple
// requests hit 401 simultaneously
let refreshPromise: Promise<boolean> | null = null
const REFRESH_TIMEOUT_MS = 10_000

export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function responseError(response: Response): Promise<ApiError> {
  const body = await response.json().catch(() => ({ error: 'Unknown error' })) as { error?: string }
  return new ApiError(typeof body?.error === 'string' && body.error ? body.error : `HTTP ${response.status}`, response.status)
}

function shouldSetJsonContentType(body: BodyInit | null | undefined): boolean {
  return body != null && !(body instanceof FormData)
}

function buildHeaders(options: RequestInit): Headers {
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')

  if (shouldSetJsonContentType(options.body)) {
    headers.set('Content-Type', 'application/json')
  }

  const csrfToken = getCSRFToken()
  if (csrfToken) {
    headers.set('X-CSRF-Token', csrfToken)
  }

  return headers
}

async function refreshToken(): Promise<boolean> {
  if (refreshPromise) return refreshPromise

  refreshPromise = (async () => {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), REFRESH_TIMEOUT_MS)
    try {
      const csrfToken = getCSRFToken()
      const res = await fetch(`${BASE_URL}/auth/refresh`, {
        method: 'POST',
        credentials: 'same-origin',
        signal: controller.signal,
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
      })
      return res.ok
    } finally {
      clearTimeout(timeout)
      refreshPromise = null
    }
  })()

  return refreshPromise
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  refreshOnUnauthorized = true,
): Promise<T> {
  const headers = buildHeaders(options)

  let res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  })

  // Handle 401 with automatic refresh (singleton to prevent race conditions)
  if (res.status === 401 && refreshOnUnauthorized) {
    const refreshed = await refreshToken()
    // A hidden/unmounted page can cancel its check while another request shares
    // the refresh. Do not retry or redirect on behalf of that cancelled caller.
    options.signal?.throwIfAborted()

    if (refreshed) {
      // Retry with new cookies (set by server)
      const newCsrf = getCSRFToken()
      if (newCsrf) {
        headers.set('X-CSRF-Token', newCsrf)
      }
      res = await fetch(`${BASE_URL}${path}`, {
        ...options,
        headers,
        credentials: 'same-origin',
      })
    } else {
      globalThis.location.href = '/login'
      throw new ApiError('Session expired', 401)
    }
  }

  if (!res.ok) {
    throw await responseError(res)
  }

  if (options.method?.toUpperCase() === 'HEAD' || res.status === 204 || res.headers.get('content-length') === '0') {
    return undefined as T
  }
  return res.json() as Promise<T>
}

// Original-access operations consume one-use authority. A 401 is returned to
// the caller directly; automatic session refresh must not replay their request.
export function apiFetchOnce<T>(path: string, options: RequestInit = {}): Promise<T> {
  return apiFetch(path, options, false)
}

// Re-enrollment API

import type { ReEnrollRequest } from '@/types/api'

export function listPendingReEnroll(): Promise<ReEnrollRequest[]> {
  return apiFetch<ReEnrollRequest[]>('/servers/reenroll/pending')
}

export function approveReEnroll(serverId: string, requestId: string, totpCode: string): Promise<void> {
  return apiFetch<void>(`/servers/${serverId}/reenroll/approve`, {
    method: 'POST',
    body: JSON.stringify({ request_id: requestId, totp_code: totpCode }),
  })
}

export function denyReEnroll(serverId: string, requestId: string): Promise<void> {
  return apiFetch<void>(`/servers/${serverId}/reenroll/deny`, {
    method: 'POST',
    body: JSON.stringify({ request_id: requestId }),
  })
}

// Convenience for requests that use a specific token (setup/totp)
// These tokens are NOT in cookies — they are passed via navigation state
export async function apiFetchWithToken<T>(
  path: string,
  token: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = buildHeaders(options)
  headers.set('Authorization', `Bearer ${token}`)

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  })

  if (!res.ok) {
    throw await responseError(res)
  }

  return res.json() as Promise<T>
}
