import { vi, type MockedFunction } from 'vitest'
import { apiFetch, apiFetchWithToken } from '../api'

const mockFetch = vi.fn() as MockedFunction<typeof fetch>

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch)
  mockFetch.mockReset()
  // Clear cookies
  document.cookie = 'veyport_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
  // Reset window.location.href stub
  Object.defineProperty(window, 'location', {
    value: { href: '' },
    writable: true,
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function makeResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  const headersObj = new Headers({ 'Content-Type': 'application/json', ...headers })
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: headersObj,
    json: () => Promise.resolve(body),
    body: null,
  } as unknown as Response
}

describe('apiFetch', () => {
  it('calls fetch with the correct URL, JSON content-type, and credentials', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ data: 'ok' }))
    const result = await apiFetch<{ data: string }>('/test')
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/test',
      expect.objectContaining({
        headers: expect.any(Headers),
        credentials: 'same-origin',
      }),
    )
    expect(result).toEqual({ data: 'ok' })
  })

  it('does not force JSON content-type for FormData bodies', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    const formData = new FormData()
    formData.append('file', new Blob(['hello']), 'test.txt')

    await apiFetch('/upload', { method: 'POST', body: formData })

    const [, init] = mockFetch.mock.calls[0]
    const headers = init!.headers as Headers
    expect(headers.get('Content-Type')).toBeNull()
    expect(headers.get('Accept')).toBe('application/json')
  })

  it('includes X-CSRF-Token header when CSRF cookie exists', async () => {
    document.cookie = 'veyport_csrf=csrf-token-abc'
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    await apiFetch('/protected')
    const [, init] = mockFetch.mock.calls[0]
    const headers = init!.headers as Headers
    expect(headers.get('X-CSRF-Token')).toBe('csrf-token-abc')
  })

  it('does not include X-CSRF-Token header when no CSRF cookie', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    await apiFetch('/public')
    const [, init] = mockFetch.mock.calls[0]
    const headers = init!.headers as Headers
    expect(headers.get('X-CSRF-Token')).toBeNull()
  })

  it('throws with the error message from JSON body on non-ok response', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ error: 'Forbidden' }, 403))
    await expect(apiFetch('/fail')).rejects.toThrow('Forbidden')
  })

  it('throws HTTP status message when JSON error field is missing', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({}, 500))
    await expect(apiFetch('/fail')).rejects.toThrow('HTTP 500')
  })

  it('throws Unknown error when JSON body cannot be parsed', async () => {
    const badResponse = {
      ok: false,
      status: 503,
      headers: new Headers(),
      json: () => Promise.reject(new Error('bad json')),
      body: null,
    } as unknown as Response
    mockFetch.mockResolvedValueOnce(badResponse)
    await expect(apiFetch('/fail')).rejects.toThrow('Unknown error')
  })

  it('returns undefined for 204 responses', async () => {
    const noContent = {
      ok: true,
      status: 204,
      headers: new Headers(),
      json: vi.fn(),
      body: null,
    } as unknown as Response
    mockFetch.mockResolvedValueOnce(noContent)
    const result = await apiFetch('/delete')
    expect(result).toBeUndefined()
  })

  it('returns undefined when content-length is 0', async () => {
    const emptyResponse = {
      ok: true,
      status: 200,
      headers: new Headers({ 'content-length': '0' }),
      json: vi.fn(),
      body: null,
    } as unknown as Response
    mockFetch.mockResolvedValueOnce(emptyResponse)
    const result = await apiFetch('/empty')
    expect(result).toBeUndefined()
  })

  it('on 401: refreshes via cookie and retries successfully', async () => {
    // First call returns 401
    mockFetch.mockResolvedValueOnce(makeResponse({ error: 'Unauthorized' }, 401))
    // Second call is the refresh request — returns ok (server sets new cookies)
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    // Third call is the retry
    mockFetch.mockResolvedValueOnce(makeResponse({ data: 'success' }))

    const result = await apiFetch<{ data: string }>('/protected')
    expect(result).toEqual({ data: 'success' })

    // Verify refresh was called with credentials
    const [refreshUrl, refreshInit] = mockFetch.mock.calls[1]
    expect(refreshUrl).toBe('/api/auth/refresh')
    expect(refreshInit!.method).toBe('POST')
    expect(refreshInit!.credentials).toBe('same-origin')
  })

  it('on 401: redirects to /login when refresh fails', async () => {
    // First call returns 401
    mockFetch.mockResolvedValueOnce(makeResponse({ error: 'Unauthorized' }, 401))
    // Refresh call fails
    mockFetch.mockResolvedValueOnce(makeResponse({ error: 'Invalid refresh' }, 401))

    await expect(apiFetch('/protected')).rejects.toThrow('Session expired')
    expect(window.location.href).toBe('/login')
  })

  it('passes custom options (method, body) to fetch', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ created: true }, 201))
    await apiFetch('/items', { method: 'POST', body: JSON.stringify({ name: 'test' }) })
    const [, init] = mockFetch.mock.calls[0]
    expect(init!.method).toBe('POST')
    expect(init!.body).toBe(JSON.stringify({ name: 'test' }))
  })

  it('includes CSRF token in refresh request when cookie exists', async () => {
    document.cookie = 'veyport_csrf=my-csrf'
    mockFetch.mockResolvedValueOnce(makeResponse({ error: 'Unauthorized' }, 401))
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    mockFetch.mockResolvedValueOnce(makeResponse({ data: 'ok' }))

    await apiFetch('/protected')

    const [, refreshInit] = mockFetch.mock.calls[1]
    expect((refreshInit!.headers as Record<string, string>)['X-CSRF-Token']).toBe('my-csrf')
  })
})

describe('apiFetchWithToken', () => {
  it('sets Authorization header with the provided token', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    await apiFetchWithToken('/setup', 'setup-token-123')
    const [, init] = mockFetch.mock.calls[0]
    const headers = init!.headers as Headers
    expect(headers.get('Authorization')).toMatch(/^Bearer .+/)
  })

  it('includes credentials same-origin', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    await apiFetchWithToken('/setup', 'tok')
    const [, init] = mockFetch.mock.calls[0]
    expect(init!.credentials).toBe('same-origin')
  })

  it('returns parsed JSON on success', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ secret: 'abc', qr_url: 'otpauth://...' }))
    const result = await apiFetchWithToken<{ secret: string }>('/auth/totp/setup', 'token')
    expect(result.secret).toBe('abc')
  })

  it('throws with error message on non-ok response', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ error: 'Not found' }, 404))
    await expect(apiFetchWithToken('/bad', 'tok')).rejects.toThrow('Not found')
  })

  it('throws HTTP status when JSON error field missing', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({}, 500))
    await expect(apiFetchWithToken('/bad', 'tok')).rejects.toThrow('HTTP 500')
  })

  it('throws Unknown error when JSON cannot be parsed', async () => {
    const badResponse = {
      ok: false,
      status: 400,
      headers: new Headers(),
      json: () => Promise.reject(new Error('parse error')),
      body: null,
    } as unknown as Response
    mockFetch.mockResolvedValueOnce(badResponse)
    await expect(apiFetchWithToken('/bad', 'tok')).rejects.toThrow('Unknown error')
  })

  it('passes additional options (method, body)', async () => {
    mockFetch.mockResolvedValueOnce(makeResponse({ status: 'ok' }))
    await apiFetchWithToken('/auth/totp/enable', 'setup-tok', {
      method: 'POST',
      body: JSON.stringify({ code: '123456' }),
    })
    const [url, init] = mockFetch.mock.calls[0]
    expect(url).toBe('/api/auth/totp/enable')
    expect(init!.method).toBe('POST')
  })

  it('includes CSRF token when cookie exists', async () => {
    document.cookie = 'veyport_csrf=csrf-for-setup'
    mockFetch.mockResolvedValueOnce(makeResponse({ ok: true }))
    await apiFetchWithToken('/setup', 'tok')
    const [, init] = mockFetch.mock.calls[0]
    const headers = init!.headers as Headers
    expect(headers.get('X-CSRF-Token')).toBe('csrf-for-setup')
  })
})
