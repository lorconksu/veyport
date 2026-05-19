import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { NotificationsTab } from '../settings-notifications-tab'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

const mockSMTPConfig = {
  host: 'smtp.example.com',
  port: 587,
  username: 'user@example.com',
  password: 'secret',
  from: 'Veyport <noreply@example.com>',
  tls: true,
  enabled: true,
}

const mockLogEntries = [
  {
    id: 'n1',
    user_id: 'u1',
    username: 'admin',
    event_type: 'agent.offline',
    subject: 'Agent went offline',
    status: 'sent' as const,
    error: null,
    created_at: new Date().toISOString(),
  },
  {
    id: 'n2',
    user_id: 'u2',
    username: 'viewer',
    event_type: 'user.login',
    subject: 'New login detected',
    status: 'failed' as const,
    error: 'connection refused',
    created_at: new Date().toISOString(),
  },
]

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <NotificationsTab />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('NotificationsTab', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string) => {
      if (url === '/settings/smtp') return Promise.resolve(mockSMTPConfig)
      if (url === '/notifications/log') return Promise.resolve({ entries: mockLogEntries, total: 2 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })
  })

  it('renders SMTP Configuration heading', () => {
    renderTab()
    expect(screen.getByText('SMTP Configuration')).toBeInTheDocument()
  })

  it('renders all SMTP form fields', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('smtp.example.com')).toBeInTheDocument()
    })
    expect(screen.getByPlaceholderText('587')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('user@example.com')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('••••••••')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Veyport <noreply@example.com>')).toBeInTheDocument()
    expect(screen.getByText('Use TLS')).toBeInTheDocument()
    expect(screen.getByText('Enable SMTP')).toBeInTheDocument()
  })

  it('loads SMTP config into form', async () => {
    renderTab()
    await waitFor(() => {
      const hostInput = screen.getByPlaceholderText('smtp.example.com') as HTMLInputElement
      expect(hostInput.value).toBe('smtp.example.com')
    })
  })

  it('renders Save SMTP Settings button', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save SMTP Settings' })).toBeInTheDocument()
    })
  })

  it('calls PUT /settings/smtp on save', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string, opts?: any) => {
      if (url === '/settings/smtp' && !opts?.method) return Promise.resolve(mockSMTPConfig)
      if (url === '/settings/smtp' && opts?.method === 'PUT') return Promise.resolve(mockSMTPConfig)
      if (url === '/notifications/log') return Promise.resolve({ entries: [], total: 0 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })
    renderTab()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save SMTP Settings' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Save SMTP Settings' }))

    await waitFor(() => {
      const calls = mockApiFetch.mock.calls
      const putCall = calls.find(c => c[1]?.method === 'PUT')
      expect(putCall).toBeTruthy()
      expect(putCall![0]).toBe('/settings/smtp')
    })
  })

  it('shows success message after save', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string, opts?: any) => {
      if (url === '/settings/smtp' && !opts?.method) return Promise.resolve(mockSMTPConfig)
      if (url === '/settings/smtp' && opts?.method === 'PUT') return Promise.resolve(mockSMTPConfig)
      if (url === '/notifications/log') return Promise.resolve({ entries: [], total: 0 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })

    renderTab()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save SMTP Settings' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Save SMTP Settings' }))

    await waitFor(() => {
      expect(screen.getByText('SMTP configuration saved.')).toBeInTheDocument()
    })
  })

  it('renders test email section', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByText('Send Test Email')).toBeInTheDocument()
    })
    expect(screen.getByPlaceholderText('recipient@example.com')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send Test' })).toBeInTheDocument()
  })

  it('calls POST /settings/smtp/test on send test', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string, opts?: any) => {
      if (url === '/settings/smtp' && !opts?.method) return Promise.resolve(mockSMTPConfig)
      if (url === '/settings/smtp/test' && opts?.method === 'POST') return Promise.resolve({ status: 'sent' })
      if (url === '/notifications/log') return Promise.resolve({ entries: [], total: 0 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })

    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('recipient@example.com')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText('recipient@example.com'), {
      target: { value: 'test@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Send Test' }))

    await waitFor(() => {
      const calls = mockApiFetch.mock.calls
      const postCall = calls.find(c => c[0] === '/settings/smtp/test')
      expect(postCall).toBeTruthy()
      expect(postCall![1]?.method).toBe('POST')
    })
  })

  it('shows test email success', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string, opts?: any) => {
      if (url === '/settings/smtp' && !opts?.method) return Promise.resolve(mockSMTPConfig)
      if (url === '/settings/smtp/test' && opts?.method === 'POST') return Promise.resolve({ status: 'sent' })
      if (url === '/notifications/log') return Promise.resolve({ entries: [], total: 0 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })

    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('recipient@example.com')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText('recipient@example.com'), {
      target: { value: 'test@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Send Test' }))

    await waitFor(() => {
      expect(screen.getByText('Test email sent successfully.')).toBeInTheDocument()
    })
  })

  it('shows test email error on failure', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string, opts?: any) => {
      if (url === '/settings/smtp' && !opts?.method) return Promise.resolve(mockSMTPConfig)
      if (url === '/settings/smtp/test' && opts?.method === 'POST') return Promise.reject(new Error('Connection refused'))
      if (url === '/notifications/log') return Promise.resolve({ entries: [], total: 0 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })

    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('recipient@example.com')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText('recipient@example.com'), {
      target: { value: 'test@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Send Test' }))

    await waitFor(() => {
      expect(screen.getByText('Connection refused')).toBeInTheDocument()
    })
  })

  it('renders Notification Log heading', () => {
    renderTab()
    expect(screen.getByText('Notification Log')).toBeInTheDocument()
  })

  it('renders notification log table headers', () => {
    renderTab()
    expect(screen.getByText('Date')).toBeInTheDocument()
    expect(screen.getByText('Recipient')).toBeInTheDocument()
    expect(screen.getByText('Event')).toBeInTheDocument()
    expect(screen.getByText('Subject')).toBeInTheDocument()
    expect(screen.getByText('Status')).toBeInTheDocument()
  })

  it('renders log entries', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByText('agent.offline')).toBeInTheDocument()
      expect(screen.getByText('Agent went offline')).toBeInTheDocument()
      expect(screen.getByText('admin')).toBeInTheDocument()
    })
  })

  it('shows Sent in green for sent entries', async () => {
    renderTab()
    await waitFor(() => {
      const sentEl = screen.getByText('Sent')
      expect(sentEl).toHaveClass('text-status-online')
    })
  })

  it('shows Failed in red for failed entries', async () => {
    renderTab()
    await waitFor(() => {
      const failedEl = screen.getByText('Failed')
      expect(failedEl).toHaveClass('text-status-error')
    })
  })

  it('shows empty state when no entries', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string) => {
      if (url === '/settings/smtp') return Promise.resolve(mockSMTPConfig)
      if (url === '/notifications/log') return Promise.resolve({ entries: [], total: 0 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })

    renderTab()
    await waitFor(() => {
      expect(screen.getByText('No notifications sent yet')).toBeInTheDocument()
    })
  })

  it('shows loading state for SMTP form', () => {
    mockApiFetch.mockReturnValue(new Promise(() => {}))
    renderTab()
    const loadingEls = screen.getAllByText('Loading...')
    expect(loadingEls.length).toBeGreaterThan(0)
  })

  it('updates host input when user types', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('smtp.example.com')).toBeInTheDocument()
    })

    const hostInput = screen.getByPlaceholderText('smtp.example.com') as HTMLInputElement
    fireEvent.change(hostInput, { target: { value: 'mail.myserver.com' } })
    expect(hostInput.value).toBe('mail.myserver.com')
  })

  it('updates port input when user types', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('587')).toBeInTheDocument()
    })

    const portInput = screen.getByPlaceholderText('587') as HTMLInputElement
    fireEvent.change(portInput, { target: { value: '465' } })
    expect(portInput.value).toBe('465')
  })

  it('updates username input when user types', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('user@example.com')).toBeInTheDocument()
    })

    const usernameInput = screen.getByPlaceholderText('user@example.com') as HTMLInputElement
    fireEvent.change(usernameInput, { target: { value: 'admin@myserver.com' } })
    expect(usernameInput.value).toBe('admin@myserver.com')
  })

  it('updates password input when user types', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('••••••••')).toBeInTheDocument()
    })

    const passwordInput = screen.getByPlaceholderText('••••••••') as HTMLInputElement
    fireEvent.change(passwordInput, { target: { value: 'newpassword123' } })
    expect(passwordInput.value).toBe('newpassword123')
  })

  it('updates from address input when user types', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Veyport <noreply@example.com>')).toBeInTheDocument()
    })

    const fromInput = screen.getByPlaceholderText('Veyport <noreply@example.com>') as HTMLInputElement
    fireEvent.change(fromInput, { target: { value: 'MyApp <no-reply@myapp.com>' } })
    expect(fromInput.value).toBe('MyApp <no-reply@myapp.com>')
  })

  it('shows save error when SMTP save fails', async () => {
    mockApiFetch.mockReset()
    mockApiFetch.mockImplementation((url: string, opts?: any) => {
      if (url === '/settings/smtp' && !opts?.method) return Promise.resolve(mockSMTPConfig)
      if (url === '/settings/smtp' && opts?.method === 'PUT') return Promise.reject(new Error('SMTP save failed'))
      if (url === '/notifications/log') return Promise.resolve({ entries: [], total: 0 })
      if (url === '/settings/hub') return Promise.resolve({ grpc_external_addr: '' })
      return Promise.resolve({})
    })

    renderTab()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save SMTP Settings' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Save SMTP Settings' }))

    await waitFor(() => {
      expect(screen.getByText('SMTP save failed')).toBeInTheDocument()
    })
  })

  it('Send Test button is disabled when recipient is empty', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send Test' })).toBeInTheDocument()
    })

    const sendButton = screen.getByRole('button', { name: 'Send Test' })
    expect(sendButton).toBeDisabled()
  })

  it('Send Test button is enabled after typing a recipient', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByPlaceholderText('recipient@example.com')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText('recipient@example.com'), {
      target: { value: 'test@example.com' },
    })

    const sendButton = screen.getByRole('button', { name: 'Send Test' })
    expect(sendButton).not.toBeDisabled()
  })

  it('labels have correct htmlFor associations', async () => {
    renderTab()
    await waitFor(() => {
      expect(screen.getByLabelText('Host')).toBeInTheDocument()
      expect(screen.getByLabelText('Port')).toBeInTheDocument()
      expect(screen.getByLabelText('Username')).toBeInTheDocument()
      expect(screen.getByLabelText('Password')).toBeInTheDocument()
      expect(screen.getByLabelText('From Address')).toBeInTheDocument()
    })
  })
})
