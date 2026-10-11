import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import { SecuritySettingsTab } from '../security-settings-tab'

const mocks = vi.hoisted(() => ({
  getAuditPolicy: vi.fn(),
  listSecurityChanges: vi.fn(),
  listSecurityPrincipals: vi.fn(),
  previewSecurityChange: vi.fn(),
  user: { id: 'user-1', username: 'reviewer', person_id: 'person-1', role: 'viewer' as const, totp_enabled: true, capabilities: ['security.read', 'security.request', 'security.approve', 'security.apply'] as string[] },
}))

vi.mock('@/lib/security-api', () => mocks)
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: mocks.user }) }))

function renderTab() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(<QueryClientProvider client={client}><SecuritySettingsTab /></QueryClientProvider>)
  return { ...view, client }
}

const policyResponse = {
  state: 'standard' as const,
  capabilities: ['security.read', 'security.request'],
  governance_enrolled: true,
  policy: { version: 3, sha256: 'active-hash', policy: { profile: 'standard' as const, actors: ['actor-a'], nodes: ['node-a'], runtime_seconds: 300, retention_hours: 720, destination: '', credential_ref: '', trust_key_ids: [], qualification_sha256: '' } },
  pending: null,
  credential_set: false,
  readiness: { governance: true, archive_and_transport: false, enrollment_marker: true },
}

describe('SecuritySettingsTab', () => {
  beforeEach(() => {
    mocks.user = { id: 'user-1', username: 'reviewer', person_id: 'person-1', role: 'viewer', totp_enabled: true, capabilities: ['security.read', 'security.request', 'security.approve', 'security.apply'] }
    mocks.getAuditPolicy.mockReset().mockResolvedValue(policyResponse)
    mocks.listSecurityChanges.mockReset().mockResolvedValue({ changes: [], limit: 50, offset: 0 })
    mocks.listSecurityPrincipals.mockReset().mockResolvedValue({ principals: [{ id: 'user-2', username: 'approver-two', person_id: 'person-2', roles: ['viewer'], totp_enabled: true }, { id: 'user-3', username: 'approver-three', person_id: 'person-3', roles: ['viewer'], totp_enabled: true }], total: 2, limit: 50, offset: 0 })
    mocks.previewSecurityChange.mockReset().mockResolvedValue({ digest: 'preview-digest', proposal: { reason: 'Rotate archive policy', expected_version: 3, change: { kind: 'policy', policy: policyResponse.policy.policy } } })
  })

  it('shows server readiness, current policy and empty approvals state', async () => {
    renderTab()
    expect(await screen.findByText('Active profile: standard · version 3 · active-hash')).toBeInTheDocument()
    expect(screen.getByText('Archive and transport')).toBeInTheDocument()
    expect(screen.getByText('Not applicable while Standard is active')).toBeInTheDocument()
    expect(await screen.findByText('No security requests are available.')).toBeInTheDocument()
  })

  it('displays the exact server preview and only enables request after preview', async () => {
    renderTab()
    fireEvent.change(await screen.findByLabelText('Reason'), { target: { value: 'Rotate archive policy' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview request' }))
    expect(await screen.findByText('Digest: preview-digest')).toBeInTheDocument()
    expect(screen.getByText('Expected policy version: 3')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Request this change' })).toBeDisabled()
    expect(mocks.previewSecurityChange).toHaveBeenCalledWith(expect.objectContaining({ expected_version: 3, reason: 'Rotate archive policy' }))
  })

  it('builds a valid three-person Enhanced bootstrap for the actual bootstrap-only requester', async () => {
    mocks.user = { id: 'bootstrap-admin', username: 'initial-admin', person_id: 'person-admin', role: 'admin', totp_enabled: true, capabilities: ['security.bootstrap'] }
    mocks.getAuditPolicy.mockResolvedValue({ ...policyResponse, governance_enrolled: false, state: 'standard', policy: { ...policyResponse.policy, policy: { ...policyResponse.policy.policy, profile: 'standard' } }, readiness: { governance: false, archive_and_transport: false, enrollment_marker: false } })
    renderTab()
    await waitFor(() => expect(screen.getAllByLabelText('Operator verification evidence')).toHaveLength(3))
    const evidenceFields = screen.getAllByLabelText('Operator verification evidence')
    fireEvent.change(evidenceFields[0], { target: { value: 'Identity checked with hardware token' } })
    fireEvent.change(evidenceFields[1], { target: { value: 'In-person identity evidence, case A' } })
    fireEvent.change(evidenceFields[2], { target: { value: 'In-person identity evidence, case B' } })
    const personFields = screen.getAllByLabelText('Verified person ID')
    fireEvent.change(personFields[1], { target: { value: 'person-2' } })
    fireEvent.change(personFields[2], { target: { value: 'person-3' } })
    await waitFor(async () => expect(await screen.findAllByRole('option', { name: 'approver-two · user-2' })).toHaveLength(2))
    const selects = screen.getAllByRole('combobox')
    fireEvent.change(selects[1], { target: { value: 'user-2' } })
    fireEvent.change(selects[2], { target: { value: 'user-3' } })
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Enroll verified security governance' } })
    expect(screen.getByLabelText('Profile')).toHaveValue('enhanced')
    expect(screen.getByLabelText('Profile')).toBeDisabled()
    expect(personFields.map(field => (field as HTMLInputElement).value)).toEqual(['person-admin', 'person-2', 'person-3'])
    expect(evidenceFields.map(field => (field as HTMLInputElement).value)).toEqual(['Identity checked with hardware token', 'In-person identity evidence, case A', 'In-person identity evidence, case B'])
    expect(selects.map(field => (field as HTMLSelectElement).value)).toEqual(['enhanced', 'user-2', 'user-3'])
    expect(screen.getByRole('button', { name: 'Preview request' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Preview request' }))
    await waitFor(() => expect(mocks.previewSecurityChange).toHaveBeenCalled())
    const submitted = mocks.previewSecurityChange.mock.calls[0][0]
    expect(submitted.change.kind).toBe('bootstrap')
    expect(submitted.change.policy.profile).toBe('enhanced')
    expect(submitted.change.nominations).toEqual([
      expect.objectContaining({ user_id: 'bootstrap-admin', person_id: 'person-admin', roles: ['security-officer'], verification: 'Identity checked with hardware token' }),
      expect.objectContaining({ user_id: 'user-2', person_id: 'person-2', roles: ['security-approver'] }),
      expect.objectContaining({ user_id: 'user-3', person_id: 'person-3', roles: ['security-approver'] }),
    ])
    expect(screen.getByText('The broad request list is unavailable to this account.')).toBeInTheDocument()
  })

  it('invalidates an exact preview as soon as a draft field changes', async () => {
    renderTab()
    fireEvent.change(await screen.findByLabelText('Reason'), { target: { value: 'Rotate archive policy' } })
    fireEvent.change(screen.getByLabelText('Archive destination'), { target: { value: 'https://archive.example.invalid/v2' } })
    fireEvent.change(screen.getByLabelText('Immutable credential reference'), { target: { value: 'credential-ref-2' } })
    fireEvent.change(screen.getByLabelText('Trust key IDs (comma separated)'), { target: { value: 'key-a, key-b' } })
    fireEvent.change(screen.getByLabelText('Qualification SHA-256'), { target: { value: 'qualification-hash' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview request' }))
    expect(await screen.findByText('Digest: preview-digest')).toBeInTheDocument()
    expect(mocks.previewSecurityChange.mock.calls[0][0].change.policy).toEqual(expect.objectContaining({
      destination: 'https://archive.example.invalid/v2', credential_ref: 'credential-ref-2',
      trust_key_ids: ['key-a', 'key-b'], qualification_sha256: 'qualification-hash',
    }))
    fireEvent.change(screen.getByLabelText('Runtime limit (seconds)'), { target: { value: '301' } })
    expect(screen.queryByText('Digest: preview-digest')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Request this change' })).not.toBeInTheDocument()
  })

  it('discards a preview that returns after its draft has changed', async () => {
    let resolvePreview: ((value: { digest: string; proposal: typeof mocks.previewSecurityChange.mock.calls[0][0] }) => void) | undefined
    mocks.previewSecurityChange.mockReturnValue(new Promise(resolve => { resolvePreview = resolve }))
    renderTab()
    fireEvent.change(await screen.findByLabelText('Reason'), { target: { value: 'Preview old version' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview request' }))
    fireEvent.change(screen.getByLabelText('Runtime limit (seconds)'), { target: { value: '900' } })
    resolvePreview?.({ digest: 'late-digest', proposal: { reason: 'Preview old version', expected_version: 3, change: { kind: 'policy', policy: policyResponse.policy.policy } } })
    await waitFor(() => expect(screen.queryByText('Digest: late-digest')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Request this change' })).not.toBeInTheDocument()
  })

  it('searches and paginates the bounded principal selector', async () => {
    mocks.user = { id: 'bootstrap-admin', username: 'initial-admin', person_id: 'person-admin', role: 'admin', totp_enabled: true, capabilities: ['security.bootstrap'] }
    mocks.getAuditPolicy.mockResolvedValue({ ...policyResponse, governance_enrolled: false })
    mocks.listSecurityPrincipals.mockImplementation(async (limit: number, offset: number, search: string) => ({
      principals: Array.from({ length: offset === 0 ? 50 : 2 }, (_, index) => ({ id: `person-${offset + index}`, username: `${search || 'principal'}-${offset + index}`, person_id: `person-id-${offset + index}`, roles: ['viewer'], totp_enabled: true })),
      total: 52, limit, offset,
    }))
    renderTab()
    fireEvent.change(await screen.findByLabelText('Search principals'), { target: { value: 'incident-team' } })
    await waitFor(() => expect(mocks.listSecurityPrincipals).toHaveBeenLastCalledWith(50, 0, 'incident-team', expect.any(AbortSignal)))
    fireEvent.click(screen.getByRole('button', { name: 'Next principals' }))
    await waitFor(() => expect(mocks.listSecurityPrincipals).toHaveBeenLastCalledWith(50, 50, 'incident-team', expect.any(AbortSignal)))
    expect(await screen.findByText('Showing 51–52 of 52 eligible principals.')).toBeInTheDocument()
  })

  it('keeps selected safe principals visible when nominees come from different pages', async () => {
    mocks.user = { id: 'bootstrap-admin', username: 'initial-admin', person_id: 'person-admin', role: 'admin', totp_enabled: true, capabilities: ['security.bootstrap'] }
    mocks.getAuditPolicy.mockResolvedValue({ ...policyResponse, governance_enrolled: false })
    mocks.listSecurityPrincipals.mockImplementation(async (limit: number, offset: number) => ({
      principals: Array.from({ length: offset === 0 ? 50 : 2 }, (_, index) => ({ id: `safe-${offset + index}`, username: `safe-person-${offset + index}`, person_id: `person-${offset + index}`, roles: ['viewer'], totp_enabled: true })),
      total: 52, limit, offset,
    }))
    renderTab()
    await screen.findByLabelText('Search principals')
    await waitFor(() => expect(screen.getAllByRole('option', { name: 'safe-person-0 · safe-0' })).toHaveLength(2))
    let nomineeSelects = screen.getAllByRole('combobox')
    fireEvent.change(nomineeSelects[1], { target: { value: 'safe-0' } })
    fireEvent.click(screen.getByRole('button', { name: 'Next principals' }))
    await waitFor(() => expect(mocks.listSecurityPrincipals).toHaveBeenLastCalledWith(50, 50, '', expect.any(AbortSignal)))
    await waitFor(() => expect(screen.getAllByRole('combobox')[2].querySelector('option[value="safe-50"]')).not.toBeNull())
    nomineeSelects = screen.getAllByRole('combobox')
    expect(nomineeSelects[1]).toHaveValue('safe-0')
    fireEvent.change(nomineeSelects[2], { target: { value: 'safe-50' } })
    expect(nomineeSelects[2]).toHaveValue('safe-50')
    expect(nomineeSelects[1].querySelector('option[value="safe-0"]')).not.toBeNull()
  })

  it('resets the policy draft on identity or active policy version changes', async () => {
    const { rerender, client } = renderTab()
    fireEvent.change(await screen.findByLabelText('Reason'), { target: { value: 'Draft for first identity' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview request' }))
    expect(await screen.findByText('Digest: preview-digest')).toBeInTheDocument()

    mocks.user = { ...mocks.user, id: 'user-2', username: 'second-user' }
    rerender(<QueryClientProvider client={client}><SecuritySettingsTab /></QueryClientProvider>)
    expect(await screen.findByLabelText('Reason')).toHaveValue('')
    expect(screen.queryByText('Digest: preview-digest')).not.toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Draft for version three' } })
    const nextPolicy = { ...policyResponse, policy: { ...policyResponse.policy, version: 4, sha256: 'next-hash' } }
    mocks.getAuditPolicy.mockResolvedValue(nextPolicy)
    client.setQueryData(['security', 'policy', 'user-2'], nextPolicy)
    expect(await screen.findByText('Active profile: standard · version 4 · next-hash')).toBeInTheDocument()
    expect(screen.getByLabelText('Reason')).toHaveValue('')
  })

  it('paginates approvals in bounded pages of fifty', async () => {
    const makeChange = (index: number) => ({
      id: `change-${index}`, revision: 1, reason: `Review ${index}`, expected_version: 3, change: { kind: 'policy', policy: policyResponse.policy.policy },
      requester_id: 'requester', requester_person_id: 'requester-person', digest: `digest-${index}`, state: 'requested',
      created_at: '2026-10-11T10:00:00Z', expires_at: '2026-10-12T10:00:00Z', approvals: [],
    })
    mocks.listSecurityChanges.mockImplementation(async (_limit: number, offset: number) => ({ changes: Array.from({ length: offset ? 2 : 50 }, (_, index) => makeChange(offset + index)), limit: 50, offset }))
    renderTab()
    expect(await screen.findByRole('button', { name: 'Next requests' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Next requests' }))
    await waitFor(() => expect(mocks.listSecurityChanges).toHaveBeenLastCalledWith(50, 50, expect.any(AbortSignal)))
    expect(await screen.findByText('Showing 51–52 requests')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Previous requests' })).toBeEnabled()
  })

  it('reports policy loading failures', async () => {
    mocks.getAuditPolicy.mockRejectedValue(new Error('Policy unavailable'))
    renderTab()
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load security readiness. Policy unavailable')
    await waitFor(() => expect(mocks.listSecurityChanges).not.toHaveBeenCalled())
  })
})
