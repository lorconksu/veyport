import { getCSRFToken, clearTokens } from '../auth'

describe('auth', () => {
  beforeEach(() => {
    // Clear cookies
    document.cookie = 'veyport_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
    vi.restoreAllMocks()
  })

  describe('getCSRFToken', () => {
    it('returns empty string when no CSRF cookie is set', () => {
      expect(getCSRFToken()).toBe('')
    })

    it('returns the CSRF token from cookie', () => {
      document.cookie = 'veyport_csrf=test-csrf-token-123'
      expect(getCSRFToken()).toBe('test-csrf-token-123')
    })

    it('returns the CSRF token when multiple cookies exist', () => {
      document.cookie = 'other_cookie=abc'
      document.cookie = 'veyport_csrf=my-csrf-value'
      document.cookie = 'another=xyz'
      expect(getCSRFToken()).toBe('my-csrf-value')
    })
  })

  describe('clearTokens', () => {
    it('calls the logout endpoint', async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true })
      vi.stubGlobal('fetch', mockFetch)

      await clearTokens()

      expect(mockFetch).toHaveBeenCalledWith('/api/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
      })

      vi.unstubAllGlobals()
    })

    it('does not throw when fetch fails', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'))
      vi.stubGlobal('fetch', mockFetch)

      await expect(clearTokens()).resolves.toBeUndefined()

      vi.unstubAllGlobals()
    })
  })
})
