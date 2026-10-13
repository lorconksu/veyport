import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { User } from '@/types/api'
import type { ExecutionView, OriginalPreview, OriginalRequest } from '@/types/executions'
import { OriginalAccessInvestigation } from '../original-access-workflow'
const m = vi.hoisted(() => ({ user: null as User | null, refreshUser: vi.fn(), previewOriginalAccess: vi.fn(), originalAccessStepUp: vi.fn(), requestOriginalAccess: vi.fn(), downloadOriginal: vi.fn() }))
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: m.user, refreshUser: m.refreshUser }) }))
vi.mock('@/lib/executions-api', () => m)
vi.mock('../execution-investigation', () => ({ ExecutionInvestigation: ({ onRequestOriginal }: { onRequestOriginal?: (execution: ExecutionView, request: OriginalRequest) => void }) => <button disabled={!onRequestOriginal} onClick={() => onRequestOriginal?.(execution, request)}>Review script original</button> }))
const execution = { id: 'execution-1' } as ExecutionView
const request: OriginalRequest = { purpose: 'Investigate incident 42', records: ['script'] }
const preview: OriginalPreview = { action: 'audit.original.read', digest: 'a'.repeat(64), records: [{ kind: 'script', event_id: 'admission-event', sha256: 'b'.repeat(64), bytes: 17, version_id: 'immutable-version' }] }
const handle = { handle: 'c'.repeat(64), expires_at: new Date(Date.now() + 60_000).toISOString(), download_url: `/api/audit-originals/${'c'.repeat(64)}` }
function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(<QueryClientProvider client={client}><OriginalAccessInvestigation /></QueryClientProvider>)
  fireEvent.click(screen.getByText('Review script original'))
  return { ...view, client }
}
async function confirm() {
  fireEvent.change(await screen.findByLabelText('Fresh MFA code'), { target: { value: '123456' } })
  fireEvent.click(screen.getByText('Confirm with fresh MFA'))
}
beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear()
  m.user = { id: 'investigator', username: 'investigator', role: 'viewer', roles: ['auditor'], capabilities: ['audit.read', 'audit.original.read'], totp_enabled: true, created_at: '', updated_at: '', avatar: null, email: '' }
  m.refreshUser.mockResolvedValue(m.user)
  m.previewOriginalAccess.mockResolvedValue(preview)
  m.originalAccessStepUp.mockResolvedValue({ proof: 'PRIVATE-ORIGINAL-PROOF', expires_at: new Date(Date.now() + 60_000).toISOString() })
  m.requestOriginalAccess.mockResolvedValue(handle)
  m.downloadOriginal.mockResolvedValue({ blob: new Blob(['PRIVATE-ORIGINAL-BYTES']), filename: 'original-script.bin' })
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:ephemeral-download'), revokeObjectURL: vi.fn() }))
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })
it('previews exact descriptors/purpose before fresh MFA and immediately consumes the local handle', async () => {
  const { client } = setup()
  expect(await screen.findByText('Version: immutable-version')).toBeInTheDocument()
  expect(screen.getByText('Execution execution-1 · purpose: Investigate incident 42')).toBeInTheDocument()
  expect(m.originalAccessStepUp).not.toHaveBeenCalled()
  await confirm()
  expect(await screen.findByText(/does not confirm that a file was saved/)).toBeInTheDocument()
  expect(m.previewOriginalAccess).toHaveBeenCalledTimes(2)
  expect(m.originalAccessStepUp).toHaveBeenCalledWith('execution-1', request, preview.digest, '123456', expect.any(AbortSignal))
  expect(m.requestOriginalAccess).toHaveBeenCalledWith('execution-1', request, preview.digest, 'PRIVATE-ORIGINAL-PROOF', expect.any(AbortSignal))
  expect(m.downloadOriginal).toHaveBeenCalledWith(handle, expect.any(AbortSignal))
  expect(URL.createObjectURL).toHaveBeenCalledTimes(1)
  await waitFor(() => expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:ephemeral-download'))
  expect(document.body.textContent).not.toMatch(/PRIVATE-|api\/audit-originals/)
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(client.getQueryCache().getAll()).toHaveLength(0)
  expect(localStorage.length).toBe(0)
})
it('refuses missing role without making a protected preview', () => {
  m.user = { ...m.user!, capabilities: ['audit.read'] }
  setup()
  expect(screen.getByText('Review script original')).toBeDisabled()
  expect(m.previewOriginalAccess).not.toHaveBeenCalled()
})
it('handles unavailable/expired originals without prompting MFA', async () => {
  m.previewOriginalAccess.mockRejectedValue(new Error('PRIVATE-UPSTREAM-DETAIL'))
  setup()
  expect(await screen.findByRole('alert')).toHaveTextContent('original is unavailable')
  expect(screen.queryByLabelText('Fresh MFA code')).not.toBeInTheDocument()
  expect(screen.queryByText(/PRIVATE-UPSTREAM-DETAIL/)).not.toBeInTheDocument()
  expect(m.originalAccessStepUp).not.toHaveBeenCalled()
})
it('refuses changed descriptors before requesting MFA', async () => {
  m.previewOriginalAccess.mockResolvedValueOnce(preview).mockResolvedValue({ ...preview, records: [{ ...preview.records[0], version_id: 'other-version' }] })
  setup(); await confirm()
  expect(await screen.findByRole('alert')).toHaveTextContent('refused')
  expect(m.originalAccessStepUp).not.toHaveBeenCalled()
  expect(m.downloadOriginal).not.toHaveBeenCalled()
})
it('refuses an expired proof before creating a one-use handle', async () => {
  m.originalAccessStepUp.mockResolvedValue({ proof: 'PRIVATE-PROOF', expires_at: '2000-01-01T00:00:00Z' })
  setup(); await confirm()
  expect(await screen.findByRole('alert')).toHaveTextContent('refused')
  expect(m.requestOriginalAccess).not.toHaveBeenCalled()
})
it.each(['intent', 'download'])('does not replay a refused %s or expose its handle/proof', async stage => {
  if (stage === 'intent') m.requestOriginalAccess.mockRejectedValue(new Error('PRIVATE-ORIGINAL-PROOF'))
  else m.downloadOriginal.mockRejectedValue(new Error(handle.download_url))
  setup(); await confirm()
  expect(await screen.findByRole('alert')).toHaveTextContent('proof will not be reused')
  expect(screen.queryByLabelText('Fresh MFA code')).not.toBeInTheDocument()
  expect(document.body.textContent).not.toMatch(/PRIVATE-|api\/audit-originals/)
  expect(m.requestOriginalAccess).toHaveBeenCalledTimes(1)
  expect(m.downloadOriginal).toHaveBeenCalledTimes(stage === 'intent' ? 0 : 1)
  expect(URL.createObjectURL).not.toHaveBeenCalled()
})
it('cancels a preview and ignores its late result', async () => {
  let finish!: (value: OriginalPreview) => void
  m.previewOriginalAccess.mockReturnValue(new Promise(resolve => { finish = resolve }))
  setup()
  await waitFor(() => expect(m.previewOriginalAccess).toHaveBeenCalled())
  const signal = m.previewOriginalAccess.mock.calls[0][2] as AbortSignal
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(signal.aborted).toBe(true)
  await act(async () => finish(preview))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(m.originalAccessStepUp).not.toHaveBeenCalled()
})
it('clears pending authority on capability loss and never sends a late MFA proof', async () => {
  let finish!: (value: unknown) => void
  m.originalAccessStepUp.mockReturnValue(new Promise(resolve => { finish = resolve }))
  const view = setup(); await confirm()
  await waitFor(() => expect(m.originalAccessStepUp).toHaveBeenCalled())
  const signal = m.originalAccessStepUp.mock.calls[0][4] as AbortSignal
  m.user = { ...m.user!, capabilities: [] }
  view.rerender(<QueryClientProvider client={view.client}><OriginalAccessInvestigation /></QueryClientProvider>)
  expect(signal.aborted).toBe(true)
  await act(async () => finish({ proof: 'LATE-PRIVATE', expires_at: new Date(Date.now() + 60_000).toISOString() }))
  expect(m.requestOriginalAccess).not.toHaveBeenCalled()
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
it('aborts an active one-use download on cancellation without creating any blob URL', async () => {
  let finish!: (value: unknown) => void
  m.downloadOriginal.mockReturnValue(new Promise(resolve => { finish = resolve }))
  setup(); await confirm()
  await waitFor(() => expect(m.downloadOriginal).toHaveBeenCalled())
  const signal = m.downloadOriginal.mock.calls[0][1] as AbortSignal
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(signal.aborted).toBe(true)
  await act(async () => finish({ blob: new Blob(['PRIVATE-BYTES']), filename: 'original.bin' }))
  expect(URL.createObjectURL).not.toHaveBeenCalled()
  expect(m.downloadOriginal).toHaveBeenCalledTimes(1)
})
