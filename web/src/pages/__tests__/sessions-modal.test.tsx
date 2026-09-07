import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SessionsModal } from '../sessions-modal'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

/** Wrap a non-Error value so mockApiRoutes rejects with it verbatim. */
class RejectWith {
  constructor(public value: unknown) {}
}

/**
 * Routes apiFetch calls by path: each path gets its own FIFO queue of
 * responses (mirrors settings.test.tsx's helper of the same name/shape).
 */
function mockApiRoutes(routes: Record<string, unknown[]>) {
  const queues = new Map<string, unknown[]>(Object.entries(routes).map(([path, values]) => [path, [...values]]))
  mockApiFetch.mockImplementation((path: string) => {
    const queue = queues.get(path)
    if (queue && queue.length > 0) {
      const next = queue.shift()
      if (next instanceof RejectWith) return Promise.reject(next.value)
      if (next instanceof Error) return Promise.reject(next)
      return Promise.resolve(next)
    }
    return Promise.resolve({})
  })
}

function renderModal(props: Partial<React.ComponentProps<typeof SessionsModal>> = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const onClose = vi.fn()
  const utils = render(
    <QueryClientProvider client={qc}>
      <SessionsModal mode="admin" userId="u2" username="viewer" onClose={onClose} {...props} />
    </QueryClientProvider>,
  )
  return { ...utils, onClose }
}

/** Scopes to a confirm dialog's own card by its heading. */
function getModal(headingText: string): HTMLElement {
  return screen.getByRole('heading', { name: headingText }).closest('div') as HTMLElement
}

describe('SessionsModal', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
  })

  it('admin mode: shows a loading state while fetching', () => {
    mockApiFetch.mockReturnValue(new Promise(() => {}))
    renderModal()
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('admin mode: fetches GET /users/{id}/sessions and renders rows by kind with address/started/last seen', async () => {
    mockApiRoutes({
      '/users/u2/sessions': [{
        sessions: [
          { id: 's1', kind: 'web', ip: '10.0.0.5', created_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-05T00:00:00Z', current: false },
          { id: 's2', kind: 'cli', ip: '10.0.0.9', created_at: '2026-09-02T00:00:00Z', last_seen_at: '2026-09-05T01:00:00Z', current: false },
        ],
      }],
    })
    renderModal()

    await screen.findByRole('heading', { name: 'Sessions — viewer' })
    expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/sessions')
    expect(await screen.findByText('Web')).toBeInTheDocument()
    expect(screen.getByText('CLI')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.9')).toBeInTheDocument()
  })

  it('admin mode: shows the server column and target for shell rows', async () => {
    mockApiRoutes({
      '/users/u2/sessions': [{
        sessions: [
          { id: 'shell:srv1:sess1', kind: 'ssh', server: 'web-01', started_at: '2026-09-01T00:00:00Z', last_activity_at: '2026-09-05T00:00:00Z', current: false },
        ],
      }],
    })
    renderModal()

    expect(await screen.findByText('SSH shell')).toBeInTheDocument()
    expect(screen.getByText('web-01')).toBeInTheDocument()
    expect(screen.getByText('Server')).toBeInTheDocument()
  })

  it('admin mode: tags the admin\'s own current session "This session"', async () => {
    mockApiRoutes({
      '/users/u2/sessions': [{
        sessions: [{ id: 's1', kind: 'web', ip: '10.0.0.5', created_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-05T00:00:00Z', current: true }],
      }],
    })
    renderModal()
    expect(await screen.findByText('This session')).toBeInTheDocument()
  })

  it('admin mode: shows "No active sessions." when the list is empty', async () => {
    mockApiRoutes({ '/users/u2/sessions': [{ sessions: [] }] })
    renderModal()
    expect(await screen.findByText('No active sessions.')).toBeInTheDocument()
  })

  it('admin mode: shows an error banner when the list fails to load', async () => {
    mockApiRoutes({ '/users/u2/sessions': [new Error('boom')] })
    renderModal()
    await waitFor(() => {
      expect(screen.getByText('Failed to load sessions.')).toBeInTheDocument()
    })
  })

  it('admin mode: Log out on a web/cli row confirms with contract copy and issues DELETE, invalidating the query', async () => {
    mockApiRoutes({
      '/users/u2/sessions': [
        { sessions: [{ id: 's1', kind: 'web', ip: '10.0.0.5', created_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-05T00:00:00Z', current: false }] },
        { sessions: [] },
      ],
      '/users/u2/sessions/s1': [{ status: 'ended' }],
    })
    renderModal()

    fireEvent.click(await screen.findByRole('button', { name: 'Log out' }))
    await screen.findByRole('heading', { name: 'Log out session' })
    expect(screen.getByText('Log out this session for viewer? It ends immediately.')).toBeInTheDocument()

    fireEvent.click(within(getModal('Log out session')).getByRole('button', { name: 'Log out' }))

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/sessions/s1', expect.objectContaining({ method: 'DELETE' }))
    })
    await waitFor(() => {
      expect(screen.getByText('No active sessions.')).toBeInTheDocument()
    })
  })

  it('admin mode: Terminate on a shell row confirms with contract copy and issues DELETE shell:...', async () => {
    mockApiRoutes({
      '/users/u2/sessions': [
        { sessions: [{ id: 'shell:srv1:sess1', kind: 'ssh', server: 'web-01', started_at: '2026-09-01T00:00:00Z', last_activity_at: '2026-09-05T00:00:00Z', current: false }] },
        { sessions: [] },
      ],
      '/users/u2/sessions/shell:srv1:sess1': [{ status: 'ended' }],
    })
    renderModal()

    fireEvent.click(await screen.findByRole('button', { name: 'Terminate' }))
    await screen.findByRole('heading', { name: 'Terminate shell' })
    expect(screen.getByText('Terminate this shell for viewer? The connection closes immediately.')).toBeInTheDocument()

    fireEvent.click(within(getModal('Terminate shell')).getByRole('button', { name: 'Terminate' }))

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/sessions/shell:srv1:sess1', expect.objectContaining({ method: 'DELETE' }))
    })
  })

  it('admin mode: "Log out everywhere" uses the exact contract copy and issues DELETE /users/{id}/sessions', async () => {
    mockApiRoutes({
      '/users/u2/sessions': [
        { sessions: [{ id: 's1', kind: 'cli', ip: '10.0.0.9', created_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-05T00:00:00Z', current: false }] },
        { sessions: [] },
      ],
    })
    renderModal()

    fireEvent.click(await screen.findByRole('button', { name: 'Log out everywhere' }))
    await screen.findByRole('heading', { name: 'Log out everywhere' })
    expect(screen.getByText(
      'Log out viewer everywhere? All web and CLI sessions end now and any open SSH shells are closed.',
    )).toBeInTheDocument()

    fireEvent.click(within(getModal('Log out everywhere')).getByRole('button', { name: 'Log out everywhere' }))

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/sessions', expect.objectContaining({ method: 'DELETE' }))
    })
  })

  it('admin mode: shows a mutation error banner and keeps the row available to retry', async () => {
    mockApiRoutes({
      '/users/u2/sessions': [{ sessions: [{ id: 's1', kind: 'web', ip: '10.0.0.5', current: false }] }],
      '/users/u2/sessions/s1': [new Error('cannot end that session')],
    })
    renderModal()

    fireEvent.click(await screen.findByRole('button', { name: 'Log out' }))
    await screen.findByRole('heading', { name: 'Log out session' })
    fireEvent.click(within(getModal('Log out session')).getByRole('button', { name: 'Log out' }))

    await waitFor(() => {
      expect(screen.getByText('cannot end that session')).toBeInTheDocument()
    })
  })

  it('calls onClose when Close is clicked', async () => {
    mockApiRoutes({ '/users/u2/sessions': [{ sessions: [] }] })
    const { onClose } = renderModal()
    await screen.findByText('No active sessions.')
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalled()
  })

  it('self mode: queries /auth/sessions and marks the caller\'s current session', async () => {
    mockApiRoutes({
      '/auth/sessions': [{
        sessions: [
          { id: 'cur', kind: 'web', ip: '10.0.0.1', current: true },
          { id: 'other', kind: 'cli', ip: '10.0.0.2', current: false },
        ],
      }],
    })
    renderModal({ mode: 'self', userId: undefined, username: 'me' })

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/sessions')
    })
    expect(await screen.findByText('This session')).toBeInTheDocument()
  })

  it('self mode: hides the row action on the current session but shows it on others', async () => {
    mockApiRoutes({
      '/auth/sessions': [{
        sessions: [
          { id: 'cur', kind: 'web', ip: '10.0.0.1', current: true },
          { id: 'other', kind: 'cli', ip: '10.0.0.2', current: false },
        ],
      }],
    })
    renderModal({ mode: 'self', userId: undefined, username: 'me' })

    await screen.findByText('This session')
    const rows = screen.getAllByRole('row').slice(1) // drop the header row
    const currentRow = rows.find(r => within(r).queryByText('This session'))!
    const otherRow = rows.find(r => !within(r).queryByText('This session'))!
    expect(within(currentRow).queryByRole('button', { name: 'Log out' })).not.toBeInTheDocument()
    expect(within(otherRow).getByRole('button', { name: 'Log out' })).toBeInTheDocument()
  })

  it('self mode: "Sign out other sessions" posts to /auth/sessions/sign-out-others', async () => {
    mockApiRoutes({
      '/auth/sessions': [
        {
          sessions: [
            { id: 'cur', kind: 'web', ip: '10.0.0.1', current: true },
            { id: 'other', kind: 'cli', ip: '10.0.0.2', current: false },
          ],
        },
        { sessions: [{ id: 'cur', kind: 'web', ip: '10.0.0.1', current: true }] },
      ],
      '/auth/sessions/sign-out-others': [{ ended: 1, shells_closed: 0 }],
    })
    renderModal({ mode: 'self', userId: undefined, username: 'me' })

    fireEvent.click(await screen.findByRole('button', { name: 'Sign out other sessions' }))
    await screen.findByRole('heading', { name: 'Sign out other sessions' })
    fireEvent.click(within(getModal('Sign out other sessions')).getByRole('button', { name: 'Sign out' }))

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/sessions/sign-out-others', expect.objectContaining({ method: 'POST' }))
    })
  })

  it('self mode: shows "This is your only active session." and hides the footer button when only the current session exists', async () => {
    mockApiRoutes({ '/auth/sessions': [{ sessions: [{ id: 'cur', kind: 'web', ip: '10.0.0.1', current: true }] }] })
    renderModal({ mode: 'self', userId: undefined, username: 'me' })

    expect(await screen.findByText('This is your only active session.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sign out other sessions' })).not.toBeInTheDocument()
  })
})
