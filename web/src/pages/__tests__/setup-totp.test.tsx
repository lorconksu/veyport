import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SetupTOTPPage } from '../setup-totp'

const mockNavigate = vi.fn()
const mockLogin = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: vi.fn(() => ({ state: { setupToken: 'setup-tok-123' } })),
  }
})

vi.mock('@/lib/api', () => ({
  apiFetchWithToken: vi.fn(),
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(() => ({
    login: mockLogin,
  })),
}))

vi.mock('qrcode', () => ({
  default: { toCanvas: vi.fn() },
}))

// Mock clipboard
Object.assign(navigator, {
  clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
})

import { apiFetchWithToken } from '@/lib/api'
const mockApiFetchWithToken = apiFetchWithToken as ReturnType<typeof vi.fn>

import { useLocation } from 'react-router-dom'
const mockUseLocation = useLocation as ReturnType<typeof vi.fn>

const totpData = { secret: 'ABCDEFGHIJKLMNOP', qr_url: 'otpauth://totp/Veyport?secret=ABCDEFGHIJKLMNOP' }

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <SetupTOTPPage />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('SetupTOTPPage', () => {
  beforeEach(() => {
    mockApiFetchWithToken.mockReset()
    mockNavigate.mockReset()
    mockLogin.mockReset()
    mockUseLocation.mockReturnValue({ state: { setupToken: 'setup-tok-123' } })
  })

  it('renders the setup heading', async () => {
    mockApiFetchWithToken.mockResolvedValueOnce(totpData)
    renderPage()
    expect(screen.getByText(/set up two-factor authentication/i)).toBeInTheDocument()
  })

  it('redirects to /login when no setupToken', async () => {
    mockUseLocation.mockReturnValue({ state: null })
    renderPage()
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login')
    })
  })

  it('renders QR code canvas after fetching TOTP data', async () => {
    const QRCode = await import('qrcode')
    mockApiFetchWithToken.mockResolvedValueOnce(totpData)
    renderPage()
    await waitFor(() => {
      expect(QRCode.default.toCanvas).toHaveBeenCalled()
    })
  })

  it('displays the secret key', async () => {
    mockApiFetchWithToken.mockResolvedValueOnce(totpData)
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('ABCDEFGHIJKLMNOP')).toBeInTheDocument()
    })
  })

  it('renders 6 digit inputs after TOTP data loads', async () => {
    mockApiFetchWithToken.mockResolvedValueOnce(totpData)
    renderPage()
    await waitFor(() => {
      expect(screen.getAllByRole('textbox')).toHaveLength(6)
    })
  })

  it('renders Verify & Enable 2FA button', async () => {
    mockApiFetchWithToken.mockResolvedValueOnce(totpData)
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /verify & enable 2fa/i })).toBeInTheDocument()
    })
  })

  it('shows error when TOTP setup fetch fails', async () => {
    mockApiFetchWithToken.mockRejectedValueOnce(new Error('Failed to setup'))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Failed to generate TOTP secret')).toBeInTheDocument()
    })
  })

  it('copies secret key to clipboard when Copy button clicked', async () => {
    mockApiFetchWithToken.mockResolvedValueOnce(totpData)
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('ABCDEFGHIJKLMNOP')).toBeInTheDocument()
    })

    const copyButton = screen.getByText('Copy')
    fireEvent.click(copyButton)
    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith('ABCDEFGHIJKLMNOP')
    })
  })

  it('submits code and navigates to / on success', async () => {
    const authResponse = {
      access_token: 'acc',
      refresh_token: 'ref',
      user: { id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
    }
    // First call: setup (returns totpData), Second call: enable (returns authResponse)
    mockApiFetchWithToken
      .mockResolvedValueOnce(totpData)
      .mockResolvedValueOnce(authResponse)

    renderPage()

    // Wait for the Verify button to appear (which means totpData loaded)
    const verifyBtn = await screen.findByRole('button', { name: /verify & enable 2fa/i })

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    fireEvent.click(verifyBtn)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith(authResponse.user)
      expect(mockNavigate).toHaveBeenCalledWith('/')
    })
  })

  it('shows error on verification failure', async () => {
    mockApiFetchWithToken
      .mockResolvedValueOnce(totpData)
      .mockRejectedValueOnce(new Error('Invalid TOTP code'))

    renderPage()

    const verifyBtn = await screen.findByRole('button', { name: /verify & enable 2fa/i })

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    fireEvent.click(verifyBtn)

    await waitFor(() => {
      expect(screen.getByText('Invalid TOTP code')).toBeInTheDocument()
    })
  })

  it('shows generic error on non-Error verification failure', async () => {
    mockApiFetchWithToken
      .mockResolvedValueOnce(totpData)
      .mockRejectedValueOnce('fail')

    renderPage()

    const verifyBtn = await screen.findByRole('button', { name: /verify & enable 2fa/i })

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    fireEvent.click(verifyBtn)

    await waitFor(() => {
      expect(screen.getByText('Verification failed')).toBeInTheDocument()
    })
  })

  it('does not call setup twice (hasFetched guard)', async () => {
    mockApiFetchWithToken.mockResolvedValueOnce(totpData)
    renderPage()
    await waitFor(() => {
      expect(mockApiFetchWithToken).toHaveBeenCalledTimes(1)
    })
  })

  it('onClick handler on Verify & Enable 2FA button calls submitCode (line 100)', async () => {
    const authResponse = {
      access_token: 'acc',
      refresh_token: 'ref',
      user: { id: '1', username: 'admin', email: 'a@b.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
    }
    mockApiFetchWithToken
      .mockResolvedValueOnce(totpData)
      .mockResolvedValueOnce(authResponse)

    renderPage()
    const verifyBtn = await screen.findByRole('button', { name: /verify & enable 2fa/i })

    const inputs = screen.getAllByRole('textbox')
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: String(i + 1) } })
    })

    // Direct click on the button (covers the onClick arrow function on line 100)
    fireEvent.click(verifyBtn)
    await waitFor(() => {
      expect(mockApiFetchWithToken).toHaveBeenCalledWith('/auth/totp/enable', 'setup-tok-123', expect.objectContaining({ method: 'POST' }))
    })
  })
})
