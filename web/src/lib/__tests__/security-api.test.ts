import { ApiError } from '../api'
import {
  getAuditPolicy, testAuditPolicy, createSecuritySecret, previewSecurityChange,
  requestSecurityChange, listSecurityChanges, getSecurityChange, securityStepUp,
  approveSecurityChange, applySecurityChange, reconcileSecurityChange, listSecurityPrincipals,
} from '../security-api'
import type { AuditPolicy, SecurityPreview, SecurityProposal } from '@/types/security'

const mockFetch = vi.fn<typeof fetch>()
const digest = 'a'.repeat(64)
const policy: AuditPolicy = {
  profile: 'enhanced', actors: [], nodes: [], runtime_seconds: 60, retention_hours: 24,
  destination: 'https://receipt.example', credential_ref: 'secret:immutable-version',
  trust_key_ids: ['lab-key'], qualification_sha256: 'b'.repeat(64),
}
const proposal: SecurityProposal = { reason: 'Reviewed exact coverage', expected_version: 7, change: { kind: 'policy', policy } }
const preview: SecurityPreview = { digest, proposal }

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch)
  mockFetch.mockReset()
  document.cookie = 'veyport_csrf=current-session-csrf'
})

afterEach(() => {
  vi.unstubAllGlobals()
  document.cookie = 'veyport_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
})

describe('security workflow HTTP bindings', () => {
  it('previews and submits exact typed bytes using session cookies, CSRF and fresh digest-bound MFA', async () => {
    mockFetch.mockResolvedValueOnce(response(preview))
      .mockResolvedValueOnce(response({ proof: 'fresh-request-proof', expires_at: 'soon' }))
      .mockResolvedValueOnce(response({ id: 'change-1', state: 'requested' }, 201))
    const exact = await previewSecurityChange(proposal)
    const step = await securityStepUp('security.request', exact.digest, '123456')
    await requestSecurityChange(exact, step.proof)
    expect(mockFetch.mock.calls.map(call => call[0])).toEqual([
      '/api/security/changes/preview', '/api/security/step-up', '/api/security/changes',
    ])
    expect(JSON.parse(String(mockFetch.mock.calls[1][1]?.body))).toEqual({ action: 'security.request', digest, code: '123456' })
    expect(JSON.parse(String(mockFetch.mock.calls[2][1]?.body))).toEqual({ ...proposal, step_up_proof: 'fresh-request-proof' })
    for (const [url, options] of mockFetch.mock.calls) {
      expect(url).not.toContain('123456')
      expect(url).not.toContain('proof')
      expect(options?.credentials).toBe('same-origin')
      expect((options?.headers as Headers).get('X-CSRF-Token')).toBe('current-session-csrf')
      expect((options?.headers as Headers).has('Authorization')).toBe(false)
    }
  })

  it('binds approval/apply step-up to exact change ID and digest and sends only the one-use proof', async () => {
    for (const action of ['approve', 'apply'] as const) {
      mockFetch.mockResolvedValueOnce(response({ proof: `${action}-proof` })).mockResolvedValueOnce(response({ state: action === 'apply' ? 'applied' : 'approved' }))
      const step = await securityStepUp(`security.${action}`, digest, '654321', 'change-2')
      await (action === 'approve' ? approveSecurityChange : applySecurityChange)({ id: 'change-2', digest }, step.proof)
    }
    expect(JSON.parse(String(mockFetch.mock.calls[0][1]?.body))).toEqual({ action: 'security.approve', digest, code: '654321', change_id: 'change-2' })
    expect(mockFetch.mock.calls[1][0]).toBe('/api/security/changes/change-2/approve')
    expect(JSON.parse(String(mockFetch.mock.calls[1][1]?.body))).toEqual({ step_up_proof: 'approve-proof' })
    expect(mockFetch.mock.calls[3][0]).toBe('/api/security/changes/change-2/apply')
  })

  it('keeps status, pagination, selector, destination test and reconcile bound to existing APIs', async () => {
    mockFetch.mockImplementation(async () => response({ ready: true }))
    await getAuditPolicy()
    await listSecurityChanges(10, 20)
    await getSecurityChange('change-3')
    await listSecurityPrincipals(5, 10, 'person & name')
    await testAuditPolicy(policy)
    await reconcileSecurityChange('change-3')
    expect(mockFetch.mock.calls.map(call => call[0])).toEqual([
      '/api/audit-policy', '/api/security/changes?limit=10&offset=20', '/api/security/changes/change-3',
      '/api/security/principals?limit=5&offset=10&search=person+%26+name', '/api/audit-policy/test',
      '/api/security/changes/change-3/reconcile',
    ])
    expect(mockFetch.mock.calls.slice(0, 4).every(call => call[1]?.cache === 'no-store')).toBe(true)
    expect(JSON.parse(String(mockFetch.mock.calls[4][1]?.body))).toEqual(policy)
    expect(mockFetch.mock.calls[5][1]?.body).toBeUndefined()
  })

  it.each([[403, 'self-approval denied'], [409, 'stale version'], [403, 'expired proof']])('preserves HTTP %i refusals without manufacturing retry/approval', async (status, message) => {
    mockFetch.mockResolvedValueOnce(response({ error: message }, status))
    await expect(approveSecurityChange({ id: 'change-4', digest }, 'distinct-MFA-proof')).rejects.toMatchObject({ name: 'ApiError', status, message })
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('redacts exact and escaped secret/code/proof reflections while preserving status', async () => {
    const secret = '{"bearer":"CANARY\ncredential"}'
    mockFetch.mockResolvedValueOnce(response({ error: `bad ${secret} and ${JSON.stringify(secret).slice(1, -1)}` }, 400))
    const error = await createSecuritySecret('destination', secret).catch(error => error)
    expect(error).toBeInstanceOf(ApiError)
    expect(error.status).toBe(400)
    expect(error.message).not.toContain('CANARY')
    mockFetch.mockRejectedValueOnce(new Error('network reflected 123456'))
    await expect(securityStepUp('security.request', digest, '123456')).rejects.toThrow('network reflected [redacted]')
    mockFetch.mockResolvedValueOnce(response({ error: 'expired proof-CANARY' }, 403))
    await expect(requestSecurityChange(preview, 'proof-CANARY')).rejects.toThrow('expired [redacted]')
  })

  it('returns an expired session without refreshing or replaying one-use MFA and decisions', async () => {
    for (const operation of [
      () => securityStepUp('security.apply', digest, '123456', 'change-5'),
      () => requestSecurityChange(preview, 'request-proof'),
      () => approveSecurityChange({ id: 'change-5', digest }, 'approval-proof'),
      () => applySecurityChange({ id: 'change-5', digest }, 'apply-proof'),
    ]) {
      mockFetch.mockResolvedValueOnce(response({ error: 'interactive session expired' }, 401))
      await expect(operation()).rejects.toMatchObject({ status: 401 })
    }
    expect(mockFetch).toHaveBeenCalledTimes(4)
    expect(mockFetch.mock.calls.some(call => call[0] === '/api/auth/refresh')).toBe(false)
  })

  it('returns only a write-only reference while preserving uploaded secret bytes', async () => {
    const value = 'exact\r\ncredential\n'
    mockFetch.mockResolvedValueOnce(response({ credential_ref: 'secret:version', credential_set: true }, 201))
    await expect(createSecuritySecret('destination', value)).resolves.toEqual({ credential_ref: 'secret:version', credential_set: true })
    expect(JSON.parse(String(mockFetch.mock.calls[0][1]?.body))).toEqual({ kind: 'destination', value })
  })

  it('rejects bounded input, malformed identity/digest and incomplete MFA before HTTP', () => {
    expect(() => listSecurityChanges(101)).toThrow('pagination')
    expect(() => listSecurityPrincipals(10, -1)).toThrow('pagination')
    expect(() => listSecurityPrincipals(10, 0, 'x'.repeat(129))).toThrow('search')
    expect(() => listSecurityPrincipals(10, 0, '\n')).toThrow('search')
    expect(() => getSecurityChange('../users')).toThrow('ID')
    expect(() => securityStepUp('security.approve', digest, '123456')).toThrow('change ID')
    expect(() => securityStepUp('security.request', digest, '12345')).toThrow('six-digit')
    expect(() => securityStepUp('security.request', 'bad', '123456')).toThrow('digest')
    expect(() => securityStepUp('unknown' as 'security.request', digest, '123456')).toThrow('action')
    expect(() => approveSecurityChange({ id: 'c', digest }, '')).toThrow('proof')
    expect(() => requestSecurityChange(preview, '')).toThrow('proof')
    expect(() => previewSecurityChange({ ...proposal, reason: '' })).toThrow('Reason')
    expect(() => previewSecurityChange({ ...proposal, expected_version: 0 })).toThrow('version')
    expect(() => createSecuritySecret('password', 'é'.repeat(4097))).toThrow('secret')
    expect(() => createSecuritySecret('password', '')).toThrow('secret')
    expect(mockFetch).not.toHaveBeenCalled()
  })
})
