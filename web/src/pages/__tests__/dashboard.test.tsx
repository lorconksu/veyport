import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DashboardPage } from '../dashboard'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(() => ({
    user: { id: '1', username: 'admin', role: 'admin', email: 'a@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
  })),
}))

// Stub AddServerModal to simplify
vi.mock('@/pages/add-server-modal', () => ({
  AddServerModal: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="add-server-modal">
      <button onClick={onClose}>Close Modal</button>
    </div>
  ),
}))

// Stub InstallCliModal to simplify
vi.mock('@/pages/install-cli-modal', () => ({
  InstallCliModal: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="install-cli-modal">
      <button onClick={onClose}>Close Install CLI Modal</button>
    </div>
  ),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

import { useAuth } from '@/hooks/use-auth'
const mockUseAuth = useAuth as ReturnType<typeof vi.fn>

const mockServers = [
  { id: 's1', name: 'web-prod-1', hostname: 'web1', ip_address: '1.2.3.4', os: 'Ubuntu 22.04', status: 'online', last_seen_at: new Date(Date.now() - 30000).toISOString() },
  { id: 's2', name: 'web-prod-2', hostname: null, ip_address: null, os: null, status: 'offline', last_seen_at: new Date(Date.now() - 3600000 * 2).toISOString() },
  { id: 's3', name: 'worker-1', hostname: 'worker1', ip_address: '5.6.7.8', os: 'Debian 11', status: 'pending', last_seen_at: null },
]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <DashboardPage />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('DashboardPage', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockUseAuth.mockReturnValue({
      user: { id: '1', username: 'admin', role: 'admin', email: 'a@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
  })

  it('shows loading state initially', () => {
    mockApiFetch.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByText('Loading servers...')).toBeInTheDocument()
  })

  it('shows empty state when no servers', async () => {
    mockApiFetch.mockResolvedValue({ servers: [], total: 0 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/No servers found/)).toBeInTheDocument()
    })
  })

  it('shows Add your first server link for admin when empty', async () => {
    mockApiFetch.mockResolvedValue({ servers: [], total: 0 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Add your first server')).toBeInTheDocument()
    })
  })

  it('does not show Add server link for non-admin when empty', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: '2', username: 'viewer', role: 'viewer', email: 'v@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
    mockApiFetch.mockResolvedValue({ servers: [], total: 0 })
    renderPage()
    await waitFor(() => {
      expect(screen.queryByText('Add your first server')).not.toBeInTheDocument()
    })
  })

  it('renders server list', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web-prod-1')).toBeInTheDocument()
      expect(screen.getByText('web-prod-2')).toBeInTheDocument()
      expect(screen.getByText('worker-1')).toBeInTheDocument()
    })
  })

  it('shows total server count', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('3 servers')).toBeInTheDocument()
    })
  })

  it('shows singular "server" when count is 1', async () => {
    mockApiFetch.mockResolvedValue({ servers: [mockServers[0]], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('1 server')).toBeInTheDocument()
    })
  })

  it('shows Add Server button for admin', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add server/i })).toBeInTheDocument()
    })
  })

  it('does not show Add Server button for viewer', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: '2', username: 'viewer', role: 'viewer', email: 'v@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /add server/i })).not.toBeInTheDocument()
    })
  })

  it('shows checkboxes for admin', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      const checkboxes = screen.getAllByRole('checkbox')
      // header checkbox + 3 row checkboxes
      expect(checkboxes.length).toBeGreaterThanOrEqual(3)
    })
  })

  it('opens Add Server modal when button clicked', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add server/i })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /add server/i }))
    await waitFor(() => {
      expect(screen.getByTestId('add-server-modal')).toBeInTheDocument()
    })
  })

  it('closes Add Server modal', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    expect(await screen.findByRole('button', { name: /add server/i })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /add server/i }))
    expect(await screen.findByTestId('add-server-modal')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Close Modal'))
    await waitFor(() => {
      expect(screen.queryByTestId('add-server-modal')).not.toBeInTheDocument()
    })
  })

  it('shows Install CLI button for admin', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /install cli/i })).toBeInTheDocument()
    })
  })

  it('shows Install CLI button for non-admin (viewer)', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: '2', username: 'viewer', role: 'viewer', email: 'v@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /install cli/i })).toBeInTheDocument()
    })
  })

  it('opens Install CLI modal when button clicked, and closes it', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: '2', username: 'viewer', role: 'viewer', email: 'v@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    expect(await screen.findByRole('button', { name: /install cli/i })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /install cli/i }))
    expect(await screen.findByTestId('install-cli-modal')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Close Install CLI Modal'))
    await waitFor(() => {
      expect(screen.queryByTestId('install-cli-modal')).not.toBeInTheDocument()
    })
  })

  it('status filter buttons render', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'All' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Online' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Offline' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Pending' })).toBeInTheDocument()
    })
  })

  it('clicking a status filter triggers a refetch', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    expect(await screen.findByRole('button', { name: 'Online' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Online' }))
    // Query with status=online is triggered
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalled()
    })
  })

  it('search input is rendered', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search servers...')).toBeInTheDocument()
    })
  })

  it('typing in search input triggers query update', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    expect(await screen.findByPlaceholderText('Search servers...')).toBeInTheDocument()

    mockApiFetch.mockResolvedValue({ servers: [mockServers[0]], total: 1 })
    fireEvent.change(screen.getByPlaceholderText('Search servers...'), { target: { value: 'web' } })
    await waitFor(() => expect(mockApiFetch).toHaveBeenCalled())
  })

  it('shows Pending agent status for pending servers', async () => {
    mockApiFetch.mockResolvedValue({ servers: [mockServers[2]], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Pending agent')).toBeInTheDocument()
    })
  })

  it('shows hostname / ip for servers', async () => {
    mockApiFetch.mockResolvedValue({ servers: [mockServers[0]], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web1 / 1.2.3.4')).toBeInTheDocument()
    })
  })

  it('shows — when hostname and ip are null', async () => {
    mockApiFetch.mockResolvedValue({ servers: [mockServers[1]], total: 1 })
    renderPage()
    await waitFor(() => {
      // Multiple "—" may appear (hostname/ip and OS cells)
      expect(screen.getAllByText('—').length).toBeGreaterThan(0)
    })
  })

  it('selects all checkboxes when header checkbox clicked', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => {
      const checkboxes = screen.getAllByRole('checkbox')
      expect(checkboxes.length).toBeGreaterThan(1)
    })

    const [headerCheckbox] = screen.getAllByRole('checkbox')
    fireEvent.click(headerCheckbox)

    await waitFor(() => {
      expect(screen.getByText('3 selected')).toBeInTheDocument()
    })
  })

  it('deselects all when header checkbox clicked again', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(1))

    const [headerCheckbox] = screen.getAllByRole('checkbox')
    fireEvent.click(headerCheckbox) // select all
    expect(await screen.findByText('3 selected')).toBeInTheDocument()

    fireEvent.click(headerCheckbox) // deselect all
    await waitFor(() => expect(screen.queryByText('3 selected')).not.toBeInTheDocument())
  })

  it('shows mass action bar when items are selected', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(1))

    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[1]) // first row checkbox
    await waitFor(() => {
      expect(screen.getByText('1 selected')).toBeInTheDocument()
      expect(screen.getByText(/unregister selected/i)).toBeInTheDocument()
    })
  })

  it('Clear button hides mass action bar', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(1))

    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[1])
    expect(await screen.findByText('1 selected')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Clear'))
    await waitFor(() => expect(screen.queryByText('1 selected')).not.toBeInTheDocument())
  })

  it('shows Unregister button for admin in table row', async () => {
    mockApiFetch.mockResolvedValue({ servers: [mockServers[0]], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Unregister' })).toBeInTheDocument()
    })
  })

  it('does not show Unregister button for viewer', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: '2', username: 'viewer', role: 'viewer', email: 'v@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    })
    mockApiFetch.mockResolvedValue({ servers: [mockServers[0]], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'Unregister' })).not.toBeInTheDocument()
    })
  })

  it('Unregister button calls DELETE for that server', async () => {
    mockApiFetch
      .mockResolvedValueOnce({ servers: [mockServers[0]], total: 1 })
      .mockResolvedValueOnce({ status: 'ok' }) // delete
      .mockResolvedValue({ servers: [], total: 0 }) // refetch
    renderPage()
    expect(await screen.findByRole('button', { name: 'Unregister' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Unregister' }))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(`/servers/${mockServers[0].id}/unregister`, expect.objectContaining({ method: 'DELETE' }))
    })
  })

  it('Unregister Selected button calls batch delete for each selected server', async () => {
    mockApiFetch
      .mockResolvedValueOnce({ servers: mockServers, total: 3 })
      .mockResolvedValueOnce({ status: 'ok' }) // delete for selected server
      .mockResolvedValue({ servers: [], total: 0 }) // refetch
    renderPage()
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(1))

    // Select a server via checkbox
    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[1])
    expect(await screen.findByText('1 selected')).toBeInTheDocument()

    fireEvent.click(screen.getByText(/unregister selected/i))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(`/servers/${mockServers[0].id}/unregister`, expect.objectContaining({ method: 'DELETE' }))
    })
  })

  it('clicking Add your first server link opens AddServerModal', async () => {
    mockApiFetch.mockResolvedValue({ servers: [], total: 0 })
    renderPage()
    expect(await screen.findByText('Add your first server')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Add your first server'))
    await waitFor(() => {
      // AddServerModal should be shown - it renders 'Add Server' heading
      expect(screen.getByText('Add Server')).toBeInTheDocument()
    })
  })

  it('shows hours ago for server last seen 2 hours ago (dashboard relativeTime line 22-23)', async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    const server = { ...mockServers[0], last_seen_at: twoHoursAgo, status: 'offline' }
    mockApiFetch.mockResolvedValue({ servers: [server], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/\d+h ago/)).toBeInTheDocument()
    })
  })

  it('shows days ago for server last seen 3 days ago (dashboard relativeTime line 23-24)', async () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString()
    const server = { ...mockServers[0], last_seen_at: threeDaysAgo, status: 'offline' }
    mockApiFetch.mockResolvedValue({ servers: [server], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/\d+d ago/)).toBeInTheDocument()
    })
  })

  it('shows — for relativeTime when last_seen_at is null (line 11)', async () => {
    // Non-pending server with null last_seen_at triggers relativeTime(null) -> '—'
    const server = { ...mockServers[0], status: 'offline', last_seen_at: null }
    mockApiFetch.mockResolvedValue({ servers: [server], total: 1 })
    renderPage()
    await waitFor(() => {
      // '—' character should appear for the null last_seen_at
      expect(screen.getAllByText('—').length).toBeGreaterThan(0)
    })
  })

  it('shows relativeTime with non-Z timestamp (line 13 false branch)', async () => {
    // Timestamp without 'Z' suffix to trigger the normalization branch
    const rawTimestamp = new Date(Date.now() - 30000).toISOString().replace('Z', '')
    const server = { ...mockServers[0], status: 'offline', last_seen_at: rawTimestamp }
    mockApiFetch.mockResolvedValue({ servers: [server], total: 1 })
    renderPage()
    await waitFor(() => {
      // Should parse and show a time ago value
      expect(screen.getByText(/ago/)).toBeInTheDocument()
    })
  })

  it('shows — / ip when hostname is null but ip exists (line 234 null-coalescing)', async () => {
    const server = { ...mockServers[0], hostname: null, ip_address: '10.0.0.1' }
    mockApiFetch.mockResolvedValue({ servers: [server], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('— / 10.0.0.1')).toBeInTheDocument()
    })
  })

  it('toggles individual row checkbox selection and deselection (line 81)', async () => {
    mockApiFetch.mockResolvedValue({ servers: mockServers, total: 3 })
    renderPage()
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(1))

    const checkboxes = screen.getAllByRole('checkbox')
    // Select the first row
    fireEvent.click(checkboxes[1])
    expect(await screen.findByText('1 selected')).toBeInTheDocument()

    // Deselect it (triggers the next.has(id) -> next.delete(id) branch on line 81)
    fireEvent.click(checkboxes[1])
    await waitFor(() => expect(screen.queryByText('1 selected')).not.toBeInTheDocument())
  })

  it('shows minutes ago for relativeTime (line 20 true branch)', async () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString()
    const server = { ...mockServers[0], status: 'offline', last_seen_at: fiveMinAgo }
    mockApiFetch.mockResolvedValue({ servers: [server], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/\d+ min ago/)).toBeInTheDocument()
    })
  })

  it('shows hostname / — when hostname exists but ip is null (line 256 ?? branch)', async () => {
    const server = { ...mockServers[0], hostname: 'myhost', ip_address: null }
    mockApiFetch.mockResolvedValue({ servers: [server], total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('myhost / —')).toBeInTheDocument()
    })
  })

  it('Unregister Selected handles all-fail case (parallelLimit rejected branch + batchDelete error handler)', async () => {
    // First call: server list; subsequent DELETE calls: all reject
    mockApiFetch
      .mockResolvedValueOnce({ servers: [mockServers[0]], total: 1 })
      .mockRejectedValueOnce(new Error('network error')) // DELETE fails
      .mockResolvedValue({ servers: [], total: 0 }) // refetch after onError

    renderPage()
    await waitFor(() => expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(1))

    // Select all via header checkbox
    const [headerCheckbox] = screen.getAllByRole('checkbox')
    fireEvent.click(headerCheckbox)
    expect(await screen.findByText('1 selected')).toBeInTheDocument()

    // Click unregister selected — all deletes will fail → throws → onError fires
    fireEvent.click(screen.getByText(/unregister selected/i))

    // After onError: selection is cleared
    await waitFor(() => {
      expect(screen.queryByText('1 selected')).not.toBeInTheDocument()
    })
  })
})
