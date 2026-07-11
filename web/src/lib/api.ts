import { getCSRFToken } from './auth'

const BASE_URL = '/api'

// Singleton refresh promise to prevent race conditions when multiple
// requests hit 401 simultaneously
let refreshPromise: Promise<boolean> | null = null

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
    try {
      const csrfToken = getCSRFToken()
      const res = await fetch(`${BASE_URL}/auth/refresh`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
      })
      return res.ok
    } finally {
      refreshPromise = null
    }
  })()

  return refreshPromise
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = buildHeaders(options)

  let res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  })

  // Handle 401 with automatic refresh (singleton to prevent race conditions)
  if (res.status === 401) {
    const refreshed = await refreshToken()

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
      throw new Error('Session expired')
    }
  }

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error((error as { error?: string }).error || `HTTP ${res.status}`)
  }

  if (res.status === 204 || res.headers.get('content-length') === '0') {
    return undefined as T
  }
  return res.json() as Promise<T>
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
    const error = await res.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error((error as { error?: string }).error || `HTTP ${res.status}`)
  }

  return res.json() as Promise<T>
}
