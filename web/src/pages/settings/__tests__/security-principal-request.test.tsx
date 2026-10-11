import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SecurityPrincipalRequest } from '../security-principal-request'
const m = vi.hoisted(() => ({ getAuditPolicy: vi.fn(), listSecurityPrincipals: vi.fn() }))
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: { id: 'officer' } }) }))
vi.mock('@/lib/security-api', () => m)
const preview = vi.fn()
const request = vi.fn()
function setup() {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SecurityPrincipalRequest onPreview={preview} onRequest={request} /></QueryClientProvider>)
}
async function fill() {
  await waitFor(() => expect(m.getAuditPolicy).toHaveBeenCalled())
  fireEvent.change(screen.getByLabelText('Target principal ID'), { target: { value: 'target' } })
  fireEvent.change(screen.getByLabelText('Principal change reason'), { target: { value: 'Verified protected mutation' } })
}
beforeEach(() => { vi.clearAllMocks(); m.getAuditPolicy.mockResolvedValue({ policy: { version: 7 } }); m.listSecurityPrincipals.mockResolvedValue({ principals: [{ id: 'target', username: 'target' }], total: 52 }); preview.mockImplementation(async proposal => ({ proposal, digest: 'a'.repeat(64) })) })
it.each(['grant-role', 'revoke-role', 'link-person', 'reenable', 'mfa-reset', 'password-reset'])('previews typed %s with live expected version and no inline credential', async operation => {
  setup(); await fill()
  fireEvent.change(screen.getByLabelText('Protected operation'), { target: { value: operation } })
  if (operation === 'link-person') {
    fireEvent.change(screen.getByLabelText('New verified person ID'), { target: { value: 'person-target' } })
    fireEvent.change(screen.getByLabelText('Person verification evidence'), { target: { value: 'Verified externally' } })
  }
  if (operation === 'password-reset') fireEvent.change(screen.getByLabelText('Immutable password secret reference'), { target: { value: 'password-ref' } })
  fireEvent.click(screen.getByText('Preview protected principal request'))
  expect(await screen.findByText('Expected policy version: 7')).toBeInTheDocument()
  const proposal = preview.mock.calls[0][0]
  expect(proposal.reason).toBe('Verified protected mutation')
  expect(proposal.expected_version).toBe(7)
  if (operation.includes('role')) expect(proposal.change).toEqual({ kind: 'role', role: { user_id: 'target', role: 'original-reader', grant: operation === 'grant-role' } })
  else if (operation === 'link-person') expect(proposal.change).toEqual({ kind: 'person', person: { user_id: 'target', person_id: 'person-target', verification: 'Verified externally' } })
  else expect(proposal.change).toEqual({ kind: 'recovery', recovery: { user_id: 'target', operation, ...(operation === 'password-reset' ? { secret_ref: 'password-ref' } : {}) } })
  fireEvent.click(screen.getByText('Request this protected principal change'))
  expect(request).toHaveBeenCalledWith({ proposal, digest: 'a'.repeat(64) })
  fireEvent.change(screen.getByLabelText('Target principal ID'), { target: { value: 'another' } })
  expect(screen.queryByText('Request this protected principal change')).not.toBeInTheDocument()
})
it('aborts and discards a late preview when its role or reason changes', async () => {
  let finish!: (value: unknown) => void
  preview.mockReturnValue(new Promise(resolve => { finish = resolve }))
  setup(); await fill(); fireEvent.click(screen.getByText('Preview protected principal request'))
  await waitFor(() => expect(preview).toHaveBeenCalled())
  const signal = preview.mock.calls[0][1] as AbortSignal
  fireEvent.change(screen.getByLabelText('Security role'), { target: { value: 'security-officer' } })
  expect(signal.aborted).toBe(true)
  await act(async () => finish({ proposal: {}, digest: 'PRIVATE-LATE' }))
  expect(screen.queryByText(/PRIVATE-LATE/)).not.toBeInTheDocument()
  expect(screen.getByText('Preview protected principal request')).toBeEnabled()
})
it('reports policy/selector/preview refusal without enabling submission', async () => {
  preview.mockRejectedValue(new Error('refused'))
  setup(); await fill(); fireEvent.click(screen.getByText('Preview protected principal request'))
  expect(await screen.findByRole('alert')).toHaveTextContent('could not be prepared')
  expect(request).not.toHaveBeenCalled()
})
it('searches and paginates the bounded safe selector', async () => {
  setup(); await fill()
  fireEvent.change(screen.getByLabelText('Search protected principals'), { target: { value: 'literal-search' } })
  await waitFor(() => expect(m.listSecurityPrincipals).toHaveBeenLastCalledWith(50, 0, 'literal-search', expect.any(AbortSignal)))
  fireEvent.click(screen.getByText('Next protected principals'))
  await waitFor(() => expect(m.listSecurityPrincipals).toHaveBeenLastCalledWith(50, 50, 'literal-search', expect.any(AbortSignal)))
  fireEvent.click(screen.getByText('Previous protected principals'))
  await waitFor(() => expect(m.listSecurityPrincipals).toHaveBeenLastCalledWith(50, 0, 'literal-search', expect.any(AbortSignal)))
})
