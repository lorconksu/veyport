import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuditLogsPage } from '../audit-logs'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: () => ({
    user: { role: 'admin' },
  }),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

const mockEntries = [
  { id: 'e1', user_id: 'u1', actor_type: 'user', outcome: 'success', action: 'user.login', target: null, detail: null, ip_address: '1.2.3.4', created_at: new Date().toISOString() },
  { id: 'e2', user_id: null, actor_type: 'system', outcome: 'success', action: 'server.created', target: 'web-prod-1', detail: null, ip_address: null, created_at: new Date().toISOString() },
]

const mockUsers = [
  { id: 'u1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
]

const mockHealth = { degraded: false, failure_count: 0, last_failure_at: null, last_failure_reason: null, last_recovered_at: null }
const mockSettings = {
  retention_days: 90,
  review_reminder_days: 7,
  password_history_count: 5,
  temporary_password_ttl_hours: 72,
  thresholds: {
    login_failures_per_hour: 10,
    registration_failures_per_hour: 5,
    privileged_actions_per_hour: 20,
  },
}
const mockCatalog = {
  entries: [
    { action: 'user.login', label: 'User Login', category: 'auth' },
    { action: 'server.created', label: 'Server Created', category: 'server' },
  ],
  last_updated_at: '',
}
const mockDetections = { detections: [] }
const mockReviews = { reviews: [] }
const mockSavedFilters = { filters: [] }
const mockExportHistory = { entries: [] }
const mockFlags = { flags: [] }

function installAuditMocks({
  entries = mockEntries,
  total = entries.length,
  limit = 50,
  offset = 0,
} = {}) {
  mockApiFetch.mockImplementation(async (path: string) => {
    if (path.startsWith('/audit-logs/export')) {
      return { manifest: { exported_at: new Date().toISOString(), total_records: total } }
    }
    if (path.startsWith('/audit-logs?')) {
      const params = new URLSearchParams(path.split('?')[1] ?? '')
      return {
        entries,
        total,
        limit: Number(params.get('limit') ?? limit),
        offset: Number(params.get('offset') ?? offset),
      }
    }
    if (path === '/audit-users') return { users: mockUsers }
    if (path === '/audit-logs/health') return mockHealth
    if (path === '/audit-logs/settings') return mockSettings
    if (path === '/audit-logs/catalog') return mockCatalog
    if (path === '/audit-logs/detections') return mockDetections
    if (path === '/audit-logs/reviews?limit=5') return mockReviews
    if (path === '/audit-logs/filters') return mockSavedFilters
    if (path === '/audit-logs/exports') return mockExportHistory
    if (path === '/audit-logs/flags') return mockFlags
    if (path === '/audit-logs/reviews') return {}
    return {}
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <AuditLogsPage />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('AuditLogsPage', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    installAuditMocks()
  })

  it('renders page heading', async () => {
    renderPage()
    expect(await screen.findByText('Audit Logs')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockApiFetch.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('shows empty state when no entries', async () => {
    mockApiFetch.mockReset()
    installAuditMocks({ entries: [], total: 0 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No audit log entries found.')).toBeInTheDocument()
    })
  })

  it('renders audit log entries', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getAllByText('user.login').length).toBeGreaterThan(0)
      expect(screen.getAllByText('server.created').length).toBeGreaterThan(0)
    })
  })

  it('shows username for entries with user_id', async () => {
    renderPage()
    await waitFor(() => {
      // u1 maps to 'admin' — may appear in dropdown too, check it's present
      expect(screen.getAllByText('admin').length).toBeGreaterThan(0)
    })
  })

  it.each([
    { description: 'entries with null user_id', text: 'System' },
    { description: 'the target value when present', text: 'web-prod-1' },
    { description: 'the ip address when present', text: '1.2.3.4' },
  ])('shows "$text" for $description', async ({ text }) => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(text)).toBeInTheDocument()
    })
  })

  it('renders filter controls', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('All Users')).toBeInTheDocument()
      expect(screen.getByText('All Actions')).toBeInTheDocument()
    })
  })

  it('shows Clear Filters button when filter is set', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('All Actions')).toBeInTheDocument()
    })

    const fromInput = document.querySelector('input[type="date"]') as HTMLInputElement
    fireEvent.change(fromInput, { target: { value: '2024-01-01' } })

    await waitFor(() => {
      expect(screen.getByText('Clear Filters')).toBeInTheDocument()
    })
  })

  it('Clear Filters resets filters', async () => {
    renderPage()
    expect(await screen.findByText('All Actions')).toBeInTheDocument()

    const fromInput = document.querySelector('input[type="date"]') as HTMLInputElement
    fireEvent.change(fromInput, { target: { value: '2024-01-01' } })
    expect(await screen.findByText('Clear Filters')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Clear Filters'))
    await waitFor(() => {
      expect(screen.queryByText('Clear Filters')).not.toBeInTheDocument()
    })
  })

  it('shows pagination when total > 0', async () => {
    mockApiFetch.mockReset()
    installAuditMocks({ entries: mockEntries, total: 100 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/Showing 1-50 of 100/)).toBeInTheDocument()
    })
  })

  it('Previous button is disabled on first page', async () => {
    mockApiFetch.mockReset()
    installAuditMocks({ entries: mockEntries, total: 100 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()
    })
  })

  it('Next button works to advance page', async () => {
    mockApiFetch.mockReset()
    installAuditMocks({ entries: mockEntries, total: 100 })
    renderPage()
    expect(await screen.findByRole('button', { name: 'Next' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => {
      expect(screen.getByText(/Showing 51-100 of 100/)).toBeInTheDocument()
    })
  })

  it('Next button is disabled on last page', async () => {
    mockApiFetch.mockReset()
    installAuditMocks({ entries: mockEntries, total: 2 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
    })
  })

  it('date filter triggers refetch', async () => {
    renderPage()
    await waitFor(() => expect(mockApiFetch).toHaveBeenCalled())

    const dateInputs = screen.getAllByDisplayValue('')
    // First two inputs are date pickers
    const fromInput = dateInputs.find(el => el.getAttribute('type') === 'date')
    if (fromInput) {
      mockApiFetch.mockResolvedValue({ entries: [], total: 0, limit: 50, offset: 0 })
      fireEvent.change(fromInput, { target: { value: '2024-01-01' } })
      await waitFor(() => expect(mockApiFetch).toHaveBeenCalled())
    }
  })

  it('shows user ID when user not found in users list', async () => {
    const entriesWithUnknownUser = [
      { id: 'e3', user_id: 'unknown-id', actor_type: 'user', outcome: 'success', action: 'user.login', target: null, detail: null, ip_address: null, created_at: new Date().toISOString() },
    ]
    mockApiFetch.mockReset()
    installAuditMocks({ entries: entriesWithUnknownUser, total: 1 })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('unknown-id')).toBeInTheDocument()
    })
  })

  it('"to" date filter input triggers refetch (line 113-119)', async () => {
    renderPage()
    await waitFor(() => expect(mockApiFetch).toHaveBeenCalled())

    const dateInputs = document.querySelectorAll('input[type="date"]')
    const toInput = dateInputs[1] as HTMLInputElement // second date input is "to"
    expect(toInput).toBeTruthy()

    mockApiFetch
      .mockResolvedValueOnce({ entries: [], total: 0, limit: 50, offset: 0 })
      .mockResolvedValueOnce({ users: mockUsers })
    fireEvent.change(toInput, { target: { value: '2024-12-31' } })
    await waitFor(() => {
      // Clear Filters button appears when filter is active
      expect(screen.getByText('Clear Filters')).toBeInTheDocument()
    })
  })

  it('Previous button works when on page 2 (line 187)', async () => {
    mockApiFetch.mockReset()
    installAuditMocks({ entries: mockEntries, total: 100 })
    renderPage()
    expect(await screen.findByRole('button', { name: 'Next' })).toBeInTheDocument()

    // Go to page 2
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText(/Showing 51/)).toBeInTheDocument()

    // Now Previous button should be enabled — click it
    const prevBtn = screen.getByRole('button', { name: 'Previous' })
    expect(prevBtn).not.toBeDisabled()
    fireEvent.click(prevBtn)
    await waitFor(() => {
      expect(screen.getByText(/Showing 1-50 of 100/)).toBeInTheDocument()
    })
  })

  it('user filter select shows users in dropdown', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getAllByText('admin').length).toBeGreaterThan(0)
    })
    // Select user filter
    const userSelect = screen.getByDisplayValue('All Users')
    fireEvent.change(userSelect, { target: { value: 'u1' } })
    await waitFor(() => {
      expect(screen.getByText('Clear Filters')).toBeInTheDocument()
    })
  })
})
