import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CreateUserModal } from '../create-user-modal'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

Object.assign(navigator, {
  clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
})

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

const mockUser = { id: 'u2', username: 'newuser', email: 'new@b.com', role: 'viewer', totp_enabled: false, avatar: null, created_at: '', updated_at: '' }
const mockCreateResponse = { user: mockUser, temporary_password: 'TempPass123!@#' }

function renderModal(onClose = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <CreateUserModal onClose={onClose} />
      </BrowserRouter>
    </QueryClientProvider>,
  )
}

describe('CreateUserModal', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
  })

  it('renders form heading', () => {
    renderModal()
    // "Create User" appears as both h3 heading and submit button text
    expect(screen.getAllByText('Create User').length).toBeGreaterThan(0)
  })

  it('renders username, email and role fields', () => {
    renderModal()
    expect(screen.getByPlaceholderText('Username')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Email')).toBeInTheDocument()
    expect(screen.getByRole('combobox')).toBeInTheDocument()
  })

  it('default role is viewer', () => {
    renderModal()
    expect(screen.getByRole('combobox')).toHaveValue('viewer')
  })

  it('can change role to admin', () => {
    renderModal()
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'admin' } })
    expect(screen.getByRole('combobox')).toHaveValue('admin')
  })

  it('Cancel button calls onClose', () => {
    const onClose = vi.fn()
    renderModal(onClose)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalled()
  })

  it('Create User button submits form', async () => {
    mockApiFetch.mockResolvedValueOnce(mockCreateResponse)
    renderModal()

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/users', expect.objectContaining({ method: 'POST' }))
    })
  })

  it('shows temporary password after user creation', async () => {
    mockApiFetch.mockResolvedValueOnce(mockCreateResponse)
    renderModal()

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('User Created')).toBeInTheDocument()
    })
    // Password is masked by default — click reveal toggle
    fireEvent.click(screen.getByTitle('Show password'))
    expect(screen.getByText('TempPass123!@#')).toBeInTheDocument()
  })

  it('Copy button copies temporary password', async () => {
    mockApiFetch.mockResolvedValueOnce(mockCreateResponse)
    renderModal()

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    expect(await screen.findByText('User Created')).toBeInTheDocument()
    // Password is masked by default — click reveal toggle
    fireEvent.click(screen.getByTitle('Show password'))

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith('TempPass123!@#')
    })
  })

  it('shows Copied! state briefly after copying', async () => {
    mockApiFetch.mockResolvedValueOnce(mockCreateResponse)
    renderModal()

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    expect(await screen.findByText('User Created')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('Show password'))

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    expect(await screen.findByText('Copied!')).toBeInTheDocument()
  })

  it('Done button calls onClose', async () => {
    const onClose = vi.fn()
    mockApiFetch.mockResolvedValueOnce(mockCreateResponse)
    renderModal(onClose)

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    expect(await screen.findByText('Done')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Done'))
    expect(onClose).toHaveBeenCalled()
  })

  it('shows error message on failure', async () => {
    mockApiFetch.mockRejectedValueOnce(new Error('Email already in use'))
    renderModal()

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Email already in use')).toBeInTheDocument()
    })
  })

  it('shows generic error for non-Error rejection', async () => {
    mockApiFetch.mockRejectedValueOnce('fail')
    renderModal()

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Failed to create user')).toBeInTheDocument()
    })
  })

  it('shows creating state during submit', async () => {
    let resolve!: (val: unknown) => void
    mockApiFetch.mockReturnValueOnce(new Promise(r => { resolve = r }))
    renderModal()

    fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'newuser' } })
    fireEvent.change(screen.getByPlaceholderText('Email'), { target: { value: 'new@b.com' } })
    fireEvent.submit(screen.getByRole('button', { name: /create user/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Creating...')).toBeInTheDocument()
    })
    resolve(mockCreateResponse)
  })
})
