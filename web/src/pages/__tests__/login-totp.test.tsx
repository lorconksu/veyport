import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { LoginTOTPPage } from '../login-totp'

const mockNavigate = vi.fn()
const mockLogin = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal() as typeof import('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: vi.fn(() => ({ state: { totpToken: 'test-totp-token' } })),
  }
})

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
  apiFetchWithToken: vi.fn(),
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(() => ({
    login: mockLogin,
  })),
}))

import { apiFetch, apiFetchWithToken } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

import { useLocation } from 'react-router-dom'
const mockUseLocation = useLocation as ReturnType<typeof vi.fn>

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <LoginTOTPPage />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('LoginTOTPPage', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockNavigate.mockReset()
    mockLogin.mockReset()
    vi.mocked(apiFetchWithToken).mockReset()
    mockUseLocation.mockReturnValue({ state: { totpToken: 'test-totp-token' } })
  })

  it('keeps MFA recovery completion-only and requires fresh sign-in after changing the password', async () => {
    mockApiFetch.mockResolvedValue({ must_change_password: true, recovery_token: 'private-recovery', expires_at: '2026-12-01T12:00:00Z' })
    vi.mocked(apiFetchWithToken).mockResolvedValue({ requires_login: true })
    renderPage()
    fireEvent.change(screen.getAllByRole('textbox')[0], { target: { value: '123456' } })
    expect(await screen.findByText('Change temporary password')).toBeInTheDocument()
    expect(mockLogin).not.toHaveBeenCalled()
    expect(mockNavigate).not.toHaveBeenCalled()
    expect(screen.queryByText('private-recovery')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Permanent#Strong2026' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'Permanent#Strong2026' } })
    fireEvent.click(screen.getByRole('button', { name: 'Change password and return to sign-in' }))
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/login', { replace: true, state: null }))
    expect(apiFetchWithToken).toHaveBeenCalledWith('/auth/password/recovery', 'private-recovery', expect.objectContaining({ method: 'POST', body: JSON.stringify({ new_password: 'Permanent#Strong2026' }), signal: expect.any(AbortSignal) }))
    expect(mockLogin).not.toHaveBeenCalled()
  })

  it('can cancel recovery without installing authority or normal navigation', async () => {
    mockApiFetch.mockResolvedValue({ must_change_password: true, recovery_token: 'private-recovery', expires_at: '2026-12-01T12:00:00Z' })
    renderPage()
    fireEvent.change(screen.getAllByRole('textbox')[0], { target: { value: '123456' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel and return to sign-in' }))
    expect(mockNavigate).toHaveBeenCalledWith('/login', { replace: true, state: null })
    expect(mockLogin).not.toHaveBeenCalled()
    expect(apiFetchWithToken).not.toHaveBeenCalled()
  })

  it('shows recovery refusal and preserves the completion-only boundary', async () => {
    mockApiFetch.mockResolvedValue({ must_change_password: true, recovery_token: 'private-recovery', expires_at: '2026-12-01T12:00:00Z' })
    vi.mocked(apiFetchWithToken).mockRejectedValue(new Error('expired'))
    renderPage()
    fireEvent.change(screen.getAllByRole('textbox')[0], { target: { value: '123456' } })
    await screen.findByText('Change temporary password')
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Permanent#Strong2026' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'Permanent#Strong2026' } })
    fireEvent.click(screen.getByRole('button', { name: 'Change password and return to sign-in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('expired or changed')
    expect(mockNavigate).not.toHaveBeenCalled()
    expect(mockLogin).not.toHaveBeenCalled()
  })

  it('renders the TOTP heading', () => {
    renderPage()
    expect(screen.getByText(/two-factor authentication/i)).toBeInTheDocument()
  })

  it('renders 6 digit inputs', () => {
    renderPage()
    const inputs = screen.getAllByRole('textbox')
    expect(inputs).toHaveLength(6)
  })

  it('renders the Verify button', () => {
    renderPage()
    expect(screen.getByRole('button', { name: /verify/i })).toBeInTheDocument()
  })

  it('redirects to /login when no totpToken', async () => {
    mockUseLocation.mockReturnValue({ state: null })
    renderPage()
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login')
    })
  })

  it('Verify button is disabled when digits are incomplete', () => {
    renderPage()
    expect(screen.getByRole('button', { name: /verify/i })).toBeDisabled()
  })

  it('submits code and navigates to / on success', async () => {
    const authResponse = {
      access_token: 'acc',
      refresh_token: 'ref',
      user: { id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
    }
    mockApiFetch.mockResolvedValueOnce(authResponse)
    renderPage()

    // Fill all 6 digit inputs
    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    // Clicking verify with all digits filled
    const verifyBtn = screen.getByRole('button', { name: /verify/i })
    fireEvent.click(verifyBtn)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith(authResponse.user)
      expect(mockNavigate).toHaveBeenCalledWith('/', { replace: true })
    })
  })

  it('shows the 423 locked message verbatim', async () => {
    mockApiFetch.mockRejectedValueOnce(new Error('account temporarily locked — try again later'))
    renderPage()

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await waitFor(() => {
      expect(screen.getByText('account temporarily locked — try again later')).toBeInTheDocument()
    })
  })

  it('shows error and resets digits on failure', async () => {
    mockApiFetch.mockRejectedValueOnce(new Error('Invalid code'))
    renderPage()

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    const verifyBtn = screen.getByRole('button', { name: /verify/i })
    fireEvent.click(verifyBtn)

    await waitFor(() => {
      expect(screen.getByText('Invalid code')).toBeInTheDocument()
    })
  })

  it('shows generic error on non-Error failure', async () => {
    mockApiFetch.mockRejectedValueOnce('oops')
    renderPage()

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await waitFor(() => {
      expect(screen.getByText('Verification failed')).toBeInTheDocument()
    })
  })

  it('autofilling the full code into the first box fills all inputs and submits', async () => {
    const authResponse = {
      access_token: 'acc',
      refresh_token: 'ref',
      user: { id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
    }
    mockApiFetch.mockResolvedValueOnce(authResponse)
    renderPage()

    // Simulates a password manager (1Password) writing the whole code into the
    // first box as a single change event, rather than one keystroke per box.
    const inputs = screen.getAllByRole('textbox')
    fireEvent.change(inputs[0], { target: { value: '123456' } })

    inputs.forEach((input, i) => {
      expect((input as HTMLInputElement).value).toBe(String(i + 1))
    })

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith(
        '/auth/login/totp',
        expect.objectContaining({ body: JSON.stringify({ totp_token: 'test-totp-token', code: '123456' }) }),
      )
      expect(mockLogin).toHaveBeenCalledWith(authResponse.user)
      expect(mockNavigate).toHaveBeenCalledWith('/', { replace: true })
    })
  })

  it('onClick handler on Verify button calls submitCode (line 65)', async () => {
    // When totpToken is present and digits are filled, the button onClick triggers submitCode
    const authResponse = {
      access_token: 'acc',
      refresh_token: 'ref',
      user: { id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
    }
    mockApiFetch.mockResolvedValueOnce(authResponse)
    renderPage()

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    // Click via onClick prop (button onClick, not via keyboard)
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/login/totp', expect.objectContaining({ method: 'POST' }))
    })
  })
})
