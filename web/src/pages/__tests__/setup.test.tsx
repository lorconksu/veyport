import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SetupPage } from '../setup'

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <SetupPage />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('SetupPage', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockNavigate.mockReset()
    // Default: system not initialized
    mockApiFetch.mockResolvedValueOnce({ initialized: false })
  })

  it('renders form fields', () => {
    renderPage()
    expect(screen.getByPlaceholderText('username')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('email')).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument()
  })

  it('renders Create Account button', () => {
    renderPage()
    expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument()
  })

  it('redirects to /login when already initialized', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockResolvedValueOnce({ initialized: true })
    renderPage()
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login')
    })
  })

  it('shows password validation errors for weak password', async () => {
    renderPage()
    const passwordInput = screen.getByPlaceholderText(/password/i)
    fireEvent.change(passwordInput, { target: { value: 'weak' } })
    await waitFor(() => {
      // The text includes a bullet prefix ("• At least 12 characters") in the DOM
      expect(screen.getByText(/At least 12 characters/)).toBeInTheDocument()
      expect(screen.getByText(/One uppercase letter/)).toBeInTheDocument()
      expect(screen.getByText(/One digit/)).toBeInTheDocument()
      expect(screen.getByText(/One special character/)).toBeInTheDocument()
    })
  })

  it('clears password errors when valid password entered', async () => {
    renderPage()
    const passwordInput = screen.getByPlaceholderText(/password/i)
    fireEvent.change(passwordInput, { target: { value: 'weak' } })
    expect(await screen.findByText(/At least 12 characters/)).toBeInTheDocument()

    fireEvent.change(passwordInput, { target: { value: 'ValidPass1@#$' } })
    await waitFor(() => {
      expect(screen.queryByText(/At least 12 characters/)).not.toBeInTheDocument()
    })
  })

  it('submits form and navigates to /setup/totp', async () => {
    mockApiFetch.mockResolvedValueOnce({ setup_token: 'setup-tok' })
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } })
    fireEvent.change(screen.getByPlaceholderText(/password/i), { target: { value: 'ValidPass1@#$' } })
    fireEvent.submit(screen.getByRole('button', { name: /create account/i }).closest('form')!)

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/setup/totp', { state: { setupToken: 'setup-tok' } })
    })
  })

  it('shows error when submission fails', async () => {
    mockApiFetch.mockRejectedValueOnce(new Error('Username taken'))
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } })
    fireEvent.change(screen.getByPlaceholderText(/password/i), { target: { value: 'ValidPass1@#$' } })
    fireEvent.submit(screen.getByRole('button', { name: /create account/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Username taken')).toBeInTheDocument()
    })
  })

  it('shows generic error for non-Error rejection', async () => {
    mockApiFetch.mockRejectedValueOnce('fail')
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } })
    fireEvent.change(screen.getByPlaceholderText(/password/i), { target: { value: 'ValidPass1@#$' } })
    fireEvent.submit(screen.getByRole('button', { name: /create account/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Registration failed')).toBeInTheDocument()
    })
  })

  it('does not submit with invalid password', async () => {
    renderPage()
    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } })
    fireEvent.change(screen.getByPlaceholderText(/password/i), { target: { value: 'weak' } })
    fireEvent.submit(screen.getByRole('button', { name: /create account/i }).closest('form')!)

    // apiFetch should only have been called for status check
    await waitFor(() => expect(mockApiFetch).toHaveBeenCalledTimes(1))
  })

  it('shows loading state during submit', async () => {
    let resolve!: (val: unknown) => void
    mockApiFetch.mockReturnValueOnce(new Promise(r => { resolve = r }))
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('email'), { target: { value: 'a@b.com' } })
    fireEvent.change(screen.getByPlaceholderText(/password/i), { target: { value: 'ValidPass1@#$' } })
    fireEvent.submit(screen.getByRole('button', { name: /create account/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Creating...')).toBeInTheDocument()
    })
    resolve({ setup_token: 'tok' })
  })
})
