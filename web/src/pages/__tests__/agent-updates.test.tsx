import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import { DashboardPage } from '../dashboard'
import { apiFetch, apiFetchOnce, ApiError } from '@/lib/api'
import { useAuth } from '@/hooks/use-auth'
import type { Server, User } from '@/types/api'
import type { AgentUpdate, AgentUpdateCheck } from '@/types/agent-updates'

vi.mock('@/lib/api', async importOriginal => {
  const actual = await importOriginal() as typeof import('@/lib/api')
  return { ...actual, apiFetch: vi.fn(), apiFetchOnce: vi.fn() }
})
vi.mock('@/hooks/use-auth', () => ({ useAuth: vi.fn() }))

const admin: User = { id: 'admin', username: 'admin', role: 'admin', email: 'admin@example.test', avatar: null, totp_enabled: true, created_at: '', updated_at: '' }
const target = { os: 'linux', arch: 'amd64', version: 'v2.0.0', revision: 'target-revision', sha256: 'a'.repeat(64), bytes: 100 }
const checked: AgentUpdateCheck = { supported: true, update_available: true, bootstrap_required: false,
  bootstrap_idle_confirmation_required: false, connection_id: 'connection1', target,
  current: { version: 'v1.0.0', revision: 'previous-revision', sha256: 'b'.repeat(64) } }
const operation: AgentUpdate = { id: 'operation1', node_id: 's1', state: 'requested', target, created_at: 100, updated_at: 100, expires_at: 200 }

function server(id = 's1', status: Server['status'] = 'online'): Server {
  return { id, name: `node-${id}`, hostname: id, ip_address: null, os: 'Linux', arch: 'amd64', agent_version: 'v1.0.0', status,
    last_seen_at: null, registered_at: '', created_at: '', updated_at: '' } as Server
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

let servers: Server[]
let checks: Record<string, AgentUpdateCheck | Error>
let statuses: Record<string, AgentUpdate | Error | undefined>
const refreshUser = vi.fn()

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const view = render(<QueryClientProvider client={client}><BrowserRouter><DashboardPage /></BrowserRouter></QueryClientProvider>)
  return { ...view, client }
}

async function openUpdate(node = 's1', label = 'Update available') {
  fireEvent.click(await screen.findByRole('button', { name: `${label} for node-${node}` }))
  return screen.findByRole('dialog')
}

beforeEach(() => {
  vi.clearAllMocks()
  servers = [server()]
  checks = { s1: checked }
  statuses = {}
  refreshUser.mockResolvedValue(admin)
  vi.mocked(useAuth).mockReturnValue({ user: admin, isLoading: false, isAuthenticated: true, refreshUser, login: vi.fn(), logout: vi.fn() })
  vi.mocked(apiFetch).mockImplementation(async path => {
    if (path.startsWith('/servers?')) {
      const params = new URLSearchParams(path.split('?')[1])
      const offset = Number(params.get('offset') ?? 0)
      const limit = Number(params.get('limit') ?? 25)
      return { servers: servers.slice(offset, offset + limit), total: servers.length }
    }
    const id = path.split('/')[2]
    if (path.includes('/agent-update/status')) {
      const status = statuses[id]
      if (status instanceof Error || status instanceof DOMException) throw status
      if (!status) throw new ApiError('Not found', 404)
      return status
    }
    const check = checks[id] ?? checked
    if (check instanceof Error) throw check
    return check
  })
  vi.mocked(apiFetchOnce).mockImplementation(async () => {
    statuses.s1 = operation
    return { operation }
  })
})

afterEach(() => {
  vi.useRealTimers()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
})

it('shows Hub availability, current, unsupported, legacy and offline states beside versions', async () => {
  servers = [server(), server('current'), server('unsupported'), server('legacy'), server('offline', 'offline'), server('pending', 'pending')]
  checks.current = { ...checked, update_available: false }
  checks.unsupported = { ...checked, supported: false, reason: 'Supervisor unavailable' }
  checks.legacy = { ...checked, supported: false, bootstrap_required: true, bootstrap_idle_confirmation_required: true, current: null,
    target: { ...target, arch: '', sha256: '', bytes: 0 } }
  renderPage()
  for (const [node, label] of [['s1', 'Update available'], ['current', 'Up to date'], ['unsupported', 'Update unsupported'], ['legacy', 'Manual upgrade required'], ['offline', 'Inspect update']]) {
    expect(await screen.findByRole('button', { name: `${label} for node-${node}` })).toBeInTheDocument()
  }
  expect(screen.getByText('Waiting for agent')).toBeInTheDocument()
  expect(vi.mocked(apiFetch).mock.calls.some(([path]) => path.includes('/offline/agent-update') || path.includes('/pending/agent-update'))).toBe(false)
})

it.each(['viewer', 'auditor'] as const)('makes no update requests and exposes no controls to %s', async role => {
  vi.mocked(useAuth).mockReturnValue({ ...useAuth(), user: { ...admin, role } })
  renderPage()
  expect(await screen.findByText('node-s1')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /update.*node-s1/i })).not.toBeInTheDocument()
  expect(vi.mocked(apiFetch).mock.calls.some(([path]) => path.includes('agent-update'))).toBe(false)
})

it('honors explicit empty admin capabilities', async () => {
  vi.mocked(useAuth).mockReturnValue({ ...useAuth(), user: { ...admin, capabilities: [] } })
  renderPage()
  await screen.findByText('node-s1')
  expect(vi.mocked(apiFetch).mock.calls.some(([path]) => path.includes('agent-update'))).toBe(false)
})

it('confirms one named node and target, and cancellation sends no POST', async () => {
  renderPage()
  const dialog = await openUpdate()
  await within(dialog).findByRole('button', { name: 'Update agent' })
  expect(within(dialog).getByText(/Current agent:/)).toHaveTextContent('v1.0.0')
  expect(within(dialog).getByText(/Target agent:/)).toHaveTextContent('v2.0.0 (target-revision)')
  expect(within(dialog).getByText(/briefly restarts/)).toHaveTextContent('only node-s1')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it('dispatches the exact checked target only once even on rapid repeated clicks', async () => {
  const start = deferred<unknown>()
  vi.mocked(apiFetchOnce).mockReturnValue(start.promise)
  renderPage()
  const dialog = await openUpdate()
  const button = await within(dialog).findByRole('button', { name: 'Update agent' })
  fireEvent.click(button)
  fireEvent.click(button)
  await waitFor(() => expect(apiFetchOnce).toHaveBeenCalledTimes(1))
  expect(apiFetchOnce).toHaveBeenCalledWith('/servers/s1/agent-update', expect.objectContaining({ method: 'POST',
    body: JSON.stringify({ expected_version: target.version, expected_revision: target.revision }) }))
  expect(refreshUser).toHaveBeenCalledTimes(1)
  statuses.s1 = operation
  await act(async () => { start.resolve({ operation }) })
  expect(await within(dialog).findByText('Update requested')).toBeInTheDocument()
  expect(within(dialog).queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
})

it.each([
  ['confirmation_pending', 'Awaiting durable agent confirmation'], ['rollback_confirmation_pending', 'Awaiting durable rollback confirmation'],
  ['unknown', 'Update outcome unknown'], ['failed', 'Agent update failed'], ['rolled_back', 'Agent update rolled back'],
  ['expired', 'Update authorization expired'], ['recovery_acknowledged', 'Manual recovery acknowledged'],
  ['downloading', 'Downloading verified agent'], ['installing', 'Installing and restarting agent'],
] as const)('shows honest %s operation state', async (state, label) => {
  statuses.s1 = { ...operation, state }
  checks.s1 = { ...checked, operation: statuses.s1 as AgentUpdate, update_available: false }
  renderPage()
  fireEvent.click(await screen.findByRole('button', { name: /for node-s1$/ }))
  const dialog = await screen.findByRole('dialog')
  expect(await within(dialog).findByText(label)).toBeInTheDocument()
  expect(within(dialog).queryByText('Agent update verified')).not.toBeInTheDocument()
  expect(within(dialog).queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
})

it('shows verified success only after exact version, revision and digest evidence', async () => {
  statuses.s1 = { ...operation, state: 'succeeded', observed_version: target.version, observed_revision: target.revision, observed_sha256: target.sha256 }
  checks.s1 = { ...checked, update_available: false, operation: statuses.s1 as AgentUpdate }
  renderPage()
  await openUpdate('s1', 'Up to date')
  expect(await screen.findByText('Agent update verified')).toBeInTheDocument()
})

function completeUpdate() {
  const completed: AgentUpdate = { ...operation, state: 'succeeded', observed_version: target.version,
    observed_revision: target.revision, observed_sha256: target.sha256 }
  statuses.s1 = completed
  checks.s1 = { ...checked, current: { version: target.version, revision: target.revision, sha256: target.sha256 },
    update_available: false, operation: completed }
  servers = [{ ...server(), agent_version: target.version }]
}

async function advancePolling(ms: number) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms) })
}

it('refreshes the row and confirmation automatically when polling verifies completion', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText('Update requested')
  completeUpdate()
  await advancePolling(2_000)
  await within(dialog).findByText('Agent update verified')
  expect(await screen.findByRole('button', { name: 'Up to date for node-s1' })).toBeInTheDocument()
  const row = screen.getByText('node-s1').closest('tr')!
  expect(within(row).getByText(target.version)).toBeInTheDocument()
  expect(await within(dialog).findByText('No newer verified Hub agent artifact is available.')).toBeInTheDocument()
  expect(within(dialog).queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
  const reads = vi.mocked(apiFetch).mock.calls.length
  await advancePolling(6_000)
  expect(apiFetch).toHaveBeenCalledTimes(reads)
  expect(apiFetchOnce).toHaveBeenCalledTimes(1)
})

it('keeps the reported version and pending outcome until the Hub verifies completion', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText('Update requested')
  statuses.s1 = { ...operation, state: 'confirmation_pending' }
  await advancePolling(2_000)
  expect(await within(dialog).findByText('Awaiting durable agent confirmation')).toBeInTheDocument()
  expect(within(screen.getByText('node-s1').closest('tr')!).getByText('v1.0.0')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Inspect update for node-s1' })).toBeInTheDocument()
  expect(screen.queryByText('Agent update verified')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Up to date for node-s1' })).not.toBeInTheDocument()
  expect(apiFetchOnce).toHaveBeenCalledTimes(1)
})

it('refreshes a completed row through normal fleet polling after closing the dialog', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText('Update requested')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close agent update' }))
  const statusReads = vi.mocked(apiFetch).mock.calls.filter(([path]) => path.includes('/agent-update/status')).length
  completeUpdate()
  await advancePolling(10_000)
  expect(await screen.findByRole('button', { name: 'Up to date for node-s1' })).toBeInTheDocument()
  expect(within(screen.getByText('node-s1').closest('tr')!).getByText(target.version)).toBeInTheDocument()
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(vi.mocked(apiFetch).mock.calls.filter(([path]) => path.includes('/agent-update/status'))).toHaveLength(statusReads)
  expect(apiFetchOnce).toHaveBeenCalledTimes(1)
})

it('reconciles a closed dialog through bounded availability polling even without a version change', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  servers = [{ ...server(), agent_version: target.version }]
  checks.s1 = { ...checked, current: { ...checked.current!, version: target.version } }
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText('Update requested')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close agent update' }))
  completeUpdate()
  await advancePolling(60_000)
  expect(await screen.findByRole('button', { name: 'Up to date for node-s1' })).toBeInTheDocument()
  expect(apiFetchOnce).toHaveBeenCalledTimes(1)
})

it.each(['failed', 'rolled_back', 'expired', 'recovery_acknowledged'] as const)('refreshes eligibility after %s without promoting the target version', async state => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText('Update requested')
  statuses.s1 = { ...operation, state }
  checks.s1 = { ...checked, operation: statuses.s1 }
  await advancePolling(2_000)
  expect(await screen.findByRole('button', { name: 'Update available for node-s1' })).toBeInTheDocument()
  expect(within(screen.getByText('node-s1').closest('tr')!).getByText('v1.0.0')).toBeInTheDocument()
  expect(screen.queryByText('Agent update verified')).not.toBeInTheDocument()
  expect(apiFetchOnce).toHaveBeenCalledTimes(1)
})

it('keeps a closed uncertain request blocking until the dialog reconciles its matching operation', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  vi.mocked(apiFetchOnce).mockRejectedValue(new TypeError('Lost response'))
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText(/request outcome is uncertain/)
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close agent update' }))
  completeUpdate()
  await advancePolling(10_000)
  await waitFor(() => expect(within(screen.getByText('node-s1').closest('tr')!).getByText(target.version)).toBeInTheDocument())
  expect(screen.getByRole('button', { name: 'Inspect update for node-s1' })).toBeInTheDocument()
  const reopened = await openUpdate('s1', 'Inspect update')
  expect(await within(reopened).findByText('Agent update verified')).toBeInTheDocument()
  expect(await screen.findByRole('button', { name: 'Up to date for node-s1' })).toBeInTheDocument()
  expect(apiFetchOnce).toHaveBeenCalledTimes(1)
})

it.each(['different operation', 'different artifact'])('does not replace a retained attempt with terminal availability for a %s', async kind => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText('Update requested')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close agent update' }))
  completeUpdate()
  const completed = checks.s1 as AgentUpdateCheck
  completed.operation = kind === 'different operation' ? { ...completed.operation!, id: 'older-operation' }
    : { ...completed.operation!, target: { ...target, bytes: target.bytes + 1 } }
  await advancePolling(10_000)
  await waitFor(() => expect(within(screen.getByText('node-s1').closest('tr')!).getByText(target.version)).toBeInTheDocument())
  expect(screen.getByRole('button', { name: 'Inspect update for node-s1' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Up to date for node-s1' })).not.toBeInTheDocument()
})

it('refuses a falsely successful status with a different digest', async () => {
  statuses.s1 = { ...operation, state: 'succeeded', observed_version: target.version, observed_revision: target.revision, observed_sha256: 'wrong' }
  renderPage()
  await openUpdate()
  expect(await screen.findByText(/Status unavailable: Update success is unverified/)).toBeInTheDocument()
  expect(screen.queryByText('Agent update verified')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
})

it.each(['legacy', 'unsupported'] as const)('never POSTs or asserts idle for a %s node', async kind => {
  checks.s1 = kind === 'legacy' ? { ...checked, supported: false, bootstrap_required: true, bootstrap_idle_confirmation_required: true }
    : { ...checked, supported: false, reason: 'Supervisor unavailable' }
  renderPage()
  await openUpdate('s1', kind === 'legacy' ? 'Manual upgrade required' : 'Update unsupported')
  expect(await screen.findByText(kind === 'legacy' ? /Coordinate idle work/ : /Supervisor unavailable/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it('recovers latest durable operation while offline after a full dashboard reload', async () => {
  servers = [server('s1', 'offline')]
  statuses.s1 = { ...operation, state: 'unknown' }
  const first = renderPage()
  await openUpdate('s1', 'Inspect update')
  expect(await screen.findByText('Update outcome unknown')).toBeInTheDocument()
  first.unmount()
  renderPage()
  await openUpdate('s1', 'Inspect update')
  expect(await screen.findByText('Operation: operation1')).toBeInTheDocument()
  expect(vi.mocked(apiFetch).mock.calls.some(([path]) => path === '/servers/s1/agent-update/status')).toBe(true)
  expect(screen.queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
})

it('retains exact operation ID after closing and reopening while node becomes offline', async () => {
  const { client } = renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await within(dialog).findByText('Update requested')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close agent update' }))
  servers = [server('s1', 'offline')]
  await act(async () => { await client.invalidateQueries({ queryKey: ['servers'] }) })
  statuses.s1 = { ...operation, state: 'confirmation_pending' }
  await openUpdate('s1', 'Inspect update')
  expect(await screen.findByText('Awaiting durable agent confirmation')).toBeInTheDocument()
  expect(apiFetch).toHaveBeenCalledWith('/servers/s1/agent-update/status?operation_id=operation1', expect.anything())
  expect(screen.queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
})

it.each([new TypeError('Network response lost'), new ApiError('Dispatch failed', 409)])('never retries uncertain POST outcomes: %s', async error => {
  vi.mocked(apiFetchOnce).mockRejectedValue(error)
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  expect(await screen.findByText(/request outcome is uncertain/)).toBeInTheDocument()
  fireEvent.click(await screen.findByRole('button', { name: 'Refresh status' }))
  await waitFor(() => expect(apiFetchOnce).toHaveBeenCalledTimes(1))
  fireEvent.click(screen.getByRole('button', { name: 'Close agent update' }))
  await openUpdate('s1', 'Inspect update')
  expect(await screen.findByText(/request outcome is uncertain/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
})

it('reconciles an operation created by a POST whose response was lost', async () => {
  vi.mocked(apiFetchOnce).mockImplementation(async () => { statuses.s1 = operation; throw new TypeError('Lost response') })
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  expect(await screen.findByText('Update requested')).toBeInTheDocument()
  await waitFor(() => expect(screen.queryByText(/request outcome is uncertain/)).not.toBeInTheDocument())
  expect(apiFetchOnce).toHaveBeenCalledTimes(1)
})

it('keeps uncertainty when latest status is the older successful operation', async () => {
  const older: AgentUpdate = { ...operation, id: 'previous', state: 'succeeded', observed_version: target.version, observed_revision: target.revision, observed_sha256: target.sha256 }
  statuses.s1 = older
  vi.mocked(apiFetchOnce).mockRejectedValue(new TypeError('Lost response'))
  renderPage()
  const dialog = await openUpdate()
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/servers/s1/agent-update/status?operation_id=previous', expect.anything()))
  await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Update agent' })).not.toBeDisabled())
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  expect(await screen.findByText(/request outcome is uncertain/)).toBeInTheDocument()
  expect(screen.queryByText('Agent update verified')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
})

it('requires fresh review after Hub artifact changes between confirmation and dispatch', async () => {
  renderPage()
  const dialog = await openUpdate()
  const confirm = await within(dialog).findByRole('button', { name: 'Update agent' })
  checks.s1 = { ...checked, target: { ...target, version: 'v3.0.0' } }
  fireEvent.click(confirm)
  expect(await screen.findByText(/node or Hub artifact changed/)).toBeInTheDocument()
  expect(apiFetchOnce).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Close agent update' }))
  const freshDialog = await openUpdate()
  expect(await within(freshDialog).findByRole('button', { name: 'Update agent' })).toBeInTheDocument()
  expect(within(freshDialog).getByText(/Target agent:/)).toHaveTextContent('v3.0.0')
})

it('cancels preflight after closing during an authority refresh', async () => {
  const fresh = deferred<User | null>()
  refreshUser.mockReturnValue(fresh.promise)
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await waitFor(() => expect(refreshUser).toHaveBeenCalledTimes(1))
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close agent update' }))
  await act(async () => { fresh.resolve(admin) })
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it('does not dispatch or expose cached operation authority after user switches', async () => {
  const fresh = deferred<User | null>()
  refreshUser.mockReturnValue(fresh.promise)
  const view = renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  await waitFor(() => expect(refreshUser).toHaveBeenCalledTimes(1))
  vi.mocked(useAuth).mockReturnValue({ ...useAuth(), user: { ...admin, id: 'viewer', role: 'viewer' } })
  view.rerender(<QueryClientProvider client={view.client}><BrowserRouter><DashboardPage /></BrowserRouter></QueryClientProvider>)
  await act(async () => { fresh.resolve(admin) })
  expect(apiFetchOnce).not.toHaveBeenCalled()
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(view.client.getQueryCache().findAll().some(query => String(query.queryKey[0]).startsWith('agent-updates:') && query.state.data != null)).toBe(false)
})

it('refuses dispatch when fresh user has lost admin authority', async () => {
  refreshUser.mockResolvedValue({ ...admin, role: 'viewer' })
  renderPage()
  const dialog = await openUpdate()
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Update agent' }))
  expect(await screen.findByText(/Administrator access changed/)).toBeInTheDocument()
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it('makes a governance/permission refusal actionable and stops queued availability checks', async () => {
  servers = Array.from({ length: 25 }, (_, i) => server(`s${i}`))
  for (const node of servers) checks[node.id] = new ApiError('agent update is forbidden', 403)
  renderPage()
  expect(await screen.findByRole('button', { name: 'Check update for node-s24' })).toBeInTheDocument()
  const requests = vi.mocked(apiFetch).mock.calls.filter(([path]) => path.endsWith('/agent-update'))
  expect(requests.length).toBeLessThanOrEqual(3)
  await openUpdate('s0', 'Check update')
  expect(await screen.findByText(/Update check refused: agent update is forbidden/)).toBeInTheDocument()
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it('paginates at the server across the whole fleet and clears current-page bulk selection', async () => {
  servers = Array.from({ length: 130 }, (_, i) => server(`s${i}`))
  renderPage()
  await screen.findByText('Page 1 of 6')
  expect(screen.queryByText('node-s25')).not.toBeInTheDocument()
  fireEvent.click(screen.getAllByRole('checkbox')[0])
  expect(screen.getByText('25 selected')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await screen.findByText('node-s25')
  expect(screen.queryByText('25 selected')).not.toBeInTheDocument()
  expect(apiFetch).toHaveBeenCalledWith('/servers?limit=25&offset=25')
  const ids = vi.mocked(apiFetch).mock.calls.filter(([path]) => path.endsWith('/agent-update')).map(([path]) => path.split('/')[2])
  expect(ids.every(id => Number(id.slice(1)) < 50)).toBe(true)
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it('returns to an existing page when another operator removes the last page', async () => {
  servers = Array.from({ length: 26 }, (_, i) => server(`s${i}`))
  const { client } = renderPage()
  await screen.findByText('Page 1 of 2')
  fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await screen.findByText('node-s25')
  servers = servers.slice(0, 25)
  await act(async () => { await client.invalidateQueries({ queryKey: ['servers'] }) })
  expect(await screen.findByText('node-s0')).toBeInTheDocument()
  expect(screen.queryByText(/No servers found/)).not.toBeInTheDocument()
})

it('bulk unregister controls never dispatch an agent update', async () => {
  renderPage()
  await screen.findByText('node-s1')
  fireEvent.click(screen.getAllByRole('checkbox')[0])
  fireEvent.click(screen.getByRole('button', { name: 'Unregister Selected' }))
  await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/servers/s1/unregister', { method: 'DELETE' }))
  expect(apiFetchOnce).not.toHaveBeenCalled()
})

it('limits availability concurrency to three and cancels queued work when hidden', async () => {
  servers = Array.from({ length: 30 }, (_, i) => server(`s${i}`))
  const pending: Array<{ signal: AbortSignal; resolve: (value: AgentUpdateCheck) => void }> = []
  const fallback = vi.mocked(apiFetch).getMockImplementation()!
  vi.mocked(apiFetch).mockImplementation((path, options) => {
    if (!path.endsWith('/agent-update')) return fallback(path, options)
    const value = deferred<AgentUpdateCheck>()
    pending.push({ signal: options!.signal as AbortSignal, resolve: value.resolve })
    return value.promise
  })
  renderPage()
  await waitFor(() => expect(pending).toHaveLength(3))
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
  fireEvent(document, new Event('visibilitychange'))
  await waitFor(() => expect(pending.every(request => request.signal.aborted)).toBe(true))
  await act(async () => { pending.forEach(request => request.resolve(checked)) })
  expect(pending).toHaveLength(3)
})

it('allows status refresh after a request timeout without issuing another POST', async () => {
  statuses.s1 = new DOMException('Status request timed out', 'TimeoutError')
  renderPage()
  await openUpdate()
  expect(await screen.findByText(/Status unavailable: Status request timed out/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Update agent' })).not.toBeInTheDocument()
  statuses.s1 = { ...operation, state: 'unknown' }
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  expect(await screen.findByText('Update outcome unknown')).toBeInTheDocument()
  expect(apiFetchOnce).not.toHaveBeenCalled()
})
