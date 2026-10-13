import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import { ExecutionInvestigation } from '../execution-investigation'
import type { ExecutionView } from '@/types/executions'

const mocks = vi.hoisted(() => ({ listExecutions: vi.fn(), user: { id: 'user-1', role: 'viewer', capabilities: ['audit.read', 'audit.original.read'] as string[] } }))
vi.mock('@/lib/executions-api', () => ({ listExecutions: mocks.listExecutions }))
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: mocks.user }) }))

const rows: ExecutionView[] = [
  {
    id: 'exec-unprepared', enhanced: true, actor_id: 'actor-1', actor_name: 'Operator', actor_provider: 'local', actor_person_id: 'person-1', actor_subject: 'subject-1',
    node_id: 'node-1', node_name: 'host-one', requested_user: 'deploy', command_sha256: 'command-hash', command_length: 20,
    policy_version: '7', policy_sha256: 'policy-hash', state: 'completed', evidence_state: 'completed', preparation: null, originals: ['envelope'],
    created_at: '2026-10-11T10:00:00Z', updated_at: '2026-10-11T10:00:01Z',
  },
  {
    id: 'exec-root', enhanced: true, actor_id: 'actor-2', actor_name: 'Root task', actor_provider: 'local', actor_person_id: 'person-2', actor_subject: 'subject-2',
    node_id: 'node-2', node_name: 'host-two', requested_user: 'root', command_sha256: 'root-command-hash', command_length: 12,
    policy_version: '7', policy_sha256: 'policy-hash', state: 'interrupted', evidence_state: 'unconfirmed', preparation: {
      preparation_id: 'prep-1', boot_id: 'boot-1', expires_unix_milli: 0,
      limits: { max_frame_bytes: 100, max_buffer_bytes: 100, runtime_seconds: 5, term_grace_seconds: 1, blocked_consumer_seconds: 1 },
      identity: { username: 'root', uid: 0, gid: 0, groups: [0], groups_sha256: 'groups-hash', identity_sha256: 'identity-hash', home: '/root', shell: '/bin/sh', cwd: '/root' },
    }, originals: ['script'], created_at: '2026-10-11T10:01:00Z', updated_at: '2026-10-11T10:01:01Z',
  },
]

function renderInvestigation(onRequestOriginal?: React.ComponentProps<typeof ExecutionInvestigation>['onRequestOriginal']) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}><ExecutionInvestigation onRequestOriginal={onRequestOriginal} /></QueryClientProvider>)
}

describe('ExecutionInvestigation', () => {
  beforeEach(() => {
    mocks.user = { id: 'user-1', role: 'viewer', capabilities: ['audit.read', 'audit.original.read'] }
    mocks.listExecutions.mockReset().mockResolvedValue({ executions: rows, total: rows.length, limit: 50, offset: 0 })
  })

  it('distinguishes missing OS identity from a prepared root identity and separates evidence from outcome', async () => {
    renderInvestigation()
    expect(await screen.findByText('Unavailable (identity was not prepared)')).toBeInTheDocument()
    expect(screen.getByText('root · UID 0 · GID 0')).toBeInTheDocument()
    expect(screen.getByText('interrupted')).toBeInTheDocument()
    expect(screen.getByText('unconfirmed')).toBeInTheDocument()
  })

  it('submits bounded actor and evidence filters and asks for purpose before protected request', async () => {
    const onRequest = vi.fn()
    renderInvestigation(onRequest)
    fireEvent.change(await screen.findByLabelText('Actor ID'), { target: { value: 'actor-1' } })
    fireEvent.change(screen.getByLabelText('Evidence state'), { target: { value: 'unconfirmed' } })
    expect(await screen.findByText('Showing 1–2 of 2')).toBeInTheDocument()
    expect(mocks.listExecutions).toHaveBeenLastCalledWith(expect.objectContaining({ actor_id: 'actor-1', evidence_state: 'unconfirmed' }), 50, 0, expect.any(AbortSignal))
    fireEvent.click(screen.getByRole('button', { name: 'Request envelope original' }))
    fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'Incident review' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue to protected review' }))
    expect(onRequest).toHaveBeenCalledWith(rows[0], { purpose: 'Incident review', records: ['envelope'] })
  })

  it('shows a loading state while records are pending', () => {
    mocks.listExecutions.mockImplementation(() => new Promise(resolve => setTimeout(() => resolve({ executions: [], total: 0, limit: 50, offset: 0 }), 25)))
    renderInvestigation()
    expect(screen.getByRole('status')).toHaveTextContent('Loading execution records')
  })

  it('shows an empty state when no executions match', async () => {
    mocks.listExecutions.mockResolvedValue({ executions: [], total: 0, limit: 50, offset: 0 })
    renderInvestigation()
    expect(await screen.findByText('No execution records match these filters.')).toBeInTheDocument()
  })

  it('clears and hides the purpose dialog when original-read authority is lost', async () => {
    const { rerender } = renderInvestigation()
    fireEvent.click(await screen.findByRole('button', { name: 'Request envelope original' }))
    fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'Confidential incident review' } })
    mocks.user = { id: 'user-1', role: 'viewer', capabilities: ['audit.read'] }
    rerender(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ExecutionInvestigation /></QueryClientProvider>)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    mocks.user = { id: 'user-2', role: 'viewer', capabilities: ['audit.read', 'audit.original.read'] }
    rerender(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ExecutionInvestigation /></QueryClientProvider>)
    fireEvent.click(await screen.findByRole('button', { name: 'Request envelope original' }))
    expect(screen.getByLabelText('Purpose')).toHaveValue('')
  })
})
