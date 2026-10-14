import { getCSRFToken, clearTokens, assignedRoles, hasCapability, canBootstrapSecurity, canViewSecurity } from '../auth'
import type { User } from '@/types/api'
import type { AuditPolicyResponse } from '@/types/security'

describe('auth', () => {
  beforeEach(() => {
    // Clear cookies
    document.cookie = '__Host-veyport_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure'
    vi.restoreAllMocks()
  })

  describe('getCSRFToken', () => {
    it('returns empty string when no CSRF cookie is set', () => {
      expect(getCSRFToken()).toBe('')
    })

    it('returns the CSRF token from cookie', () => {
      document.cookie = '__Host-veyport_csrf=test-csrf-token-123; Path=/; Secure'
      expect(getCSRFToken()).toBe('test-csrf-token-123')
    })

    it('returns the CSRF token when multiple cookies exist', () => {
      document.cookie = 'other_cookie=abc'
      document.cookie = '__Host-veyport_csrf=my-csrf-value; Path=/; Secure'
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
        headers: { 'X-CSRF-Token': '' },
        signal: expect.any(AbortSignal),
      })

      vi.unstubAllGlobals()
    })

    it.each([403, 500])('does not claim signout after server%d refuses revocation', async status => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status })))
      await expect(clearTokens()).rejects.toThrow('Could not sign out. Retry.')
      vi.unstubAllGlobals()
    })

    it('reports a retryable error when fetch fails', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'))
      vi.stubGlobal('fetch', mockFetch)

      await expect(clearTokens()).rejects.toThrow('Could not sign out. Retry.')

      vi.unstubAllGlobals()
    })
  })
})

describe('live authority', () => {
  const admin = { id: 'u', username: 'admin', role: 'admin' } as User
  const standard = { state: 'standard', version: 1, profile: 'standard', capabilities: ['security.bootstrap'], governance_enrolled: false } as AuditPolicyResponse

  it('keeps legacy operational permissions without granting security authority', () => {
    expect(hasCapability(admin, 'operations.admin')).toBe(true)
    expect(hasCapability(admin, 'audit.read')).toBe(true)
    expect(hasCapability({ ...admin, role: 'viewer', terminal_access: true }, 'terminal.execute')).toBe(true)
    expect(hasCapability(admin, 'security.read')).toBe(false)
    expect(hasCapability(admin, 'audit.original.read')).toBe(false)
    expect(canViewSecurity(admin, standard)).toBe(false)
    expect(hasCapability(null, 'nodes.read')).toBe(false)
  })

  it('honors explicit empty capabilities and does not infer authority from roles', () => {
    const revoked = { ...admin, capabilities: [], roles: ['admin', 'security-officer'] } as User
    expect(hasCapability(revoked, 'operations.admin')).toBe(false)
    expect(hasCapability(revoked, 'security.request')).toBe(false)
    expect(hasCapability({ ...admin, capabilities: undefined }, 'operations.admin')).toBe(false)
    expect(hasCapability({ ...admin, role: 'viewer', roles: ['original-reader'] }, 'audit.original.read')).toBe(false)
    expect(assignedRoles(revoked)).toEqual(['admin', 'security-officer'])
    expect(assignedRoles(admin)).toEqual(['admin'])
    expect(assignedRoles({ ...admin, roles: [] })).toEqual([])
    expect(assignedRoles({ ...admin, roles: undefined })).toEqual([])
    expect(assignedRoles(null)).toEqual([])
  })

  it('supports independent security and original-reader capabilities', () => {
    const officer = { ...admin, role: 'viewer', capabilities: ['security.read', 'security.request', 'audit.read'] } as User
    expect(canViewSecurity(officer)).toBe(true)
    expect(hasCapability(officer, 'operations.admin')).toBe(false)
    expect(hasCapability(officer, 'audit.read')).toBe(true)
    expect(hasCapability(officer, 'security.apply')).toBe(false)
  })

  it('permits bootstrap only for explicit capability, never-enrolled Standard policy', () => {
    const bootstrap = { ...admin, capabilities: ['security.bootstrap'] } as User
    expect(canBootstrapSecurity(bootstrap, standard)).toBe(true)
    expect(canViewSecurity(bootstrap, standard)).toBe(true)
    expect(canBootstrapSecurity(bootstrap, { ...standard, governance_enrolled: true })).toBe(false)
    expect(canBootstrapSecurity(bootstrap, undefined)).toBe(false)
    const full = { ...standard, policy: { version: 1, sha256: '', policy: { profile: 'standard' } }, pending: null, readiness: {}, credential_set: false } as AuditPolicyResponse
    expect(canBootstrapSecurity(bootstrap, full)).toBe(true)
    expect(canBootstrapSecurity(bootstrap, { ...full, policy: { version: 1, sha256: '', policy: { profile: 'enhanced' } } } as AuditPolicyResponse)).toBe(false)
  })
})
