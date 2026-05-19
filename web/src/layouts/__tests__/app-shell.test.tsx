import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AppShell } from '../app-shell'

// Mock hooks and utilities
vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(() => ({
    user: { id: '1', username: 'admin', role: 'admin', email: 'a@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
    logout: vi.fn(),
  })),
}))

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

vi.mock('@/lib/avatar', () => ({
  getAvatarColor: vi.fn(() => '#3b82f6'),
}))

// Mock react-router-dom partially — keep BrowserRouter/NavLink etc but mock Outlet/useNavigate
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    Outlet: () => <div data-testid="outlet">main content</div>,
  }
})

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

import { useAuth } from '@/hooks/use-auth'
const mockUseAuth = useAuth as ReturnType<typeof vi.fn>

function renderWithProviders(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>{ui}</BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('AppShell', () => {
  beforeEach(() => {
    mockApiFetch.mockResolvedValue({ servers: [], total: 0 })
    mockNavigate.mockReset()
    // Reset global fetch mock
    vi.restoreAllMocks()
  })

  it('renders navigation links', async () => {
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByText('Fleet Dashboard')).toBeInTheDocument()
      expect(screen.getByText('Audit Logs')).toBeInTheDocument()
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })
  })

  it('renders the Logo', async () => {
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByAltText('Veyport')).toBeInTheDocument()
    })
  })

  it('renders a larger dashboard header logo', async () => {
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByAltText('Veyport')).toHaveClass('w-40')
    })
  })

  it('renders the username', async () => {
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByText('admin')).toBeInTheDocument()
    })
  })

  it('renders the Outlet (main content area)', async () => {
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByTestId('outlet')).toBeInTheDocument()
    })
  })

  it('clicking logout calls logout and navigates to /login', async () => {
    const logoutFn = vi.fn()
    mockUseAuth.mockReturnValue({
      user: { id: '1', username: 'admin', role: 'admin', email: 'a@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
      logout: logoutFn,
    })

    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByTitle('Sign out')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTitle('Sign out'))
    expect(logoutFn).toHaveBeenCalled()
    expect(mockNavigate).toHaveBeenCalledWith('/login')
  })

  it('shows server status counts', async () => {
    mockApiFetch.mockResolvedValue({
      servers: [
        { id: '1', status: 'online' },
        { id: '2', status: 'online' },
        { id: '3', status: 'offline' },
        { id: '4', status: 'pending' },
      ],
      total: 4,
    })
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByText(/2 Online/)).toBeInTheDocument()
      expect(screen.getByText(/1 Offline/)).toBeInTheDocument()
      expect(screen.getByText(/1 Pending/)).toBeInTheDocument()
    })
  })

  it('toggle collapse button collapses/expands navigation', async () => {
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByText('Fleet Dashboard')).toBeInTheDocument()
    })

    const collapseButton = screen.getByTitle('Collapse menu')
    fireEvent.click(collapseButton)

    // After collapse, labels are hidden but expand button shows
    await waitFor(() => {
      expect(screen.getByTitle('Expand menu')).toBeInTheDocument()
    })
  })

  it('renders avatar image when user has avatar', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: '1', username: 'admin', role: 'admin', email: 'a@b.com', avatar: 'data:image/png;base64,abc', totp_enabled: true, created_at: '', updated_at: '' },
      logout: vi.fn(),
    })
    renderWithProviders(<AppShell />)
    await waitFor(() => {
      const avatarImg = screen.getByAltText('')
      expect(avatarImg).toBeInTheDocument()
    })
  })

  it('renders avatar initial when user has no avatar and no username (covers ?? branch on line 59)', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: '1', username: undefined, role: 'admin', email: 'a@b.com', avatar: null, totp_enabled: true, created_at: '', updated_at: '' },
      logout: vi.fn(),
    })
    renderWithProviders(<AppShell />)
    // Just verify it renders without crashing; getAvatarColor is called with ''
    await waitFor(() => {
      expect(screen.getByTestId('outlet')).toBeInTheDocument()
    })
  })

  it('displays version when fetch resolves with version string', async () => {
    // Mock global fetch so the useEffect resolves with a version
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      json: () => Promise.resolve({ version: '1.2.3', user: null }),
    } as Response)

    renderWithProviders(<AppShell />)
    await waitFor(() => {
      expect(screen.getByText('v1.2.3')).toBeInTheDocument()
    })
  })
})
