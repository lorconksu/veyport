import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { LoginPage } from '../login'

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

const mockLogin = vi.fn()
vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(() => ({
    login: mockLogin,
  })),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

function mockFetchResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('LoginPage', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockNavigate.mockReset()
    mockLogin.mockReset()
    vi.restoreAllMocks()
    // Default: system is initialized (apiFetch used for /auth/status)
    mockApiFetch.mockResolvedValueOnce({ initialized: true })
  })

  it('renders username and password inputs', () => {
    renderPage()
    expect(screen.getByPlaceholderText('username')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('password')).toBeInTheDocument()
  })

  it('renders the Sign In button', () => {
    renderPage()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('redirects to /setup when system not initialized', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockResolvedValueOnce({ initialized: false })
    renderPage()
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/setup', { replace: true })
    })
  })

  it('does not redirect when system is initialized', async () => {
    renderPage()
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/status')
    })
    expect(mockNavigate).not.toHaveBeenCalledWith('/setup', expect.anything())
  })

  it('submits form and navigates to /login/totp when totp_token returned', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      mockFetchResponse({ totp_token: 'totp-tok-123' })
    )
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('password'), { target: { value: 'secret' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login/totp', { state: { totpToken: 'totp-tok-123' } })
    })
  })

  it('navigates to /setup/totp when requires_totp_setup is true', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      mockFetchResponse({ requires_totp_setup: true, setup_token: 'setup-tok' })
    )
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('password'), { target: { value: 'secret' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/setup/totp', {
        state: { setupToken: 'setup-tok', mustChangePassword: false },
      })
    })
  })

  it('shows error message when login fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      mockFetchResponse({ error: 'Invalid credentials' }, 401)
    )
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('password'), { target: { value: 'wrong' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Invalid credentials')).toBeInTheDocument()
    })
  })

  it('shows generic error when fetch throws', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('Network error'))
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('password'), { target: { value: 'x' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument()
    })
  })

  it('shows loading state during submit', async () => {
    let resolvePromise!: (val: Response) => void
    vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(
      new Promise(r => { resolvePromise = r })
    )
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('password'), { target: { value: 'secret' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Signing in...')).toBeInTheDocument()
    })
    resolvePromise(mockFetchResponse({ totp_token: 't' }))
  })

  it('ignores status check errors', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockRejectedValueOnce(new Error('Network error'))
    renderPage()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('username')).toBeInTheDocument()
    })
  })

  it('does nothing when login response has no totp_token or requires_totp_setup', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockFetchResponse({}))
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('password'), { target: { value: 'secret' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith('/api/auth/login', expect.any(Object))
    })
    expect(mockNavigate).not.toHaveBeenCalled()
  })

  it('logs in directly when login returns a user payload', async () => {
    const user = {
      id: 'preview-user',
      username: 'preview',
      email: 'preview@test.local',
      role: 'admin',
      totp_enabled: false,
      avatar: null,
      created_at: '',
      updated_at: '',
    }

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mockFetchResponse({ user }))
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'preview' } })
    fireEvent.change(screen.getByPlaceholderText('password'), { target: { value: 'secret' } })
    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }).closest('form')!)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith(user)
      expect(mockNavigate).toHaveBeenCalledWith('/')
    })
  })
})
