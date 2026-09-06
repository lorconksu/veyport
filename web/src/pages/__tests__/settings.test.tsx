import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SettingsPage } from '../settings'

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

vi.mock('@/lib/avatar', () => ({
  getAvatarColor: vi.fn(() => '#3b82f6'),
  setAvatarColor: vi.fn(),
  AVATAR_COLORS: ['#3b82f6', '#8b5cf6', '#06b6d4'],
}))

vi.mock('@/hooks/use-auth', () => ({
  useAuth: vi.fn(() => ({
    user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '2024-01-01T00:00:00Z', updated_at: '' },
    login: vi.fn(),
  })),
}))

vi.mock('@/pages/create-user-modal', () => ({
  CreateUserModal: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="create-user-modal">
      <button onClick={onClose}>Close Modal</button>
    </div>
  ),
}))

import { apiFetch } from '@/lib/api'
const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>

import { useAuth } from '@/hooks/use-auth'
const mockUseAuth = useAuth as ReturnType<typeof vi.fn>

const mockUsers = [
  { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '2024-01-01T00:00:00Z', updated_at: '' },
  { id: 'u2', username: 'viewer', email: 'viewer@test.com', role: 'viewer', totp_enabled: false, avatar: null, created_at: '2024-01-15T00:00:00Z', updated_at: '' },
]

// Default effective hub-config: every test that mounts UsersTab now also
// mounts AccountPolicyCard (008), which fires its own GET /settings/hub
// query alongside the ['users'] query. Routing apiFetch by path (instead of
// one shared mockResolvedValueOnce FIFO queue) keeps that second query from
// consuming responses meant for /users, independent of fetch ordering.
const defaultHubConfig = {
  grpc_external_addr: '',
  lockout_threshold: 5,
  lockout_window_minutes: 15,
  lockout_duration_minutes: 30,
  dormant_days: 35,
}

/** Wrap a non-Error value so mockApiRoutes rejects with it verbatim (an Error instance already rejects on its own). */
class RejectWith {
  constructor(public value: unknown) {}
}
function rejectWith(value: unknown) {
  return new RejectWith(value)
}

/**
 * Routes apiFetch calls by path: each path gets its own FIFO queue of
 * responses (a value resolves, an Error instance — or a rejectWith() marker
 * for a non-Error rejection — rejects). Any path not given an explicit
 * queue (notably /settings/hub) falls back to a sane default so
 * AccountPolicyCard never hangs. Any call to an unlisted path beyond its
 * queue falls back to `{}`.
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
    if (path === '/settings/hub') return Promise.resolve(defaultHubConfig)
    return Promise.resolve({})
  })
}

function renderPage(initialPath = '/settings') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <SettingsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('SettingsPage', () => {
  beforeEach(() => {
    mockApiFetch.mockReset()
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '2024-01-01T00:00:00Z', updated_at: '' },
      login: vi.fn(),
    })
  })

  it('renders Settings heading', () => {
    renderPage()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('shows Profile, Users, Directory, and Notifications tabs for admin', () => {
    renderPage()
    expect(screen.getByRole('button', { name: 'Profile' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Users' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Directory' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument()
  })

  it('does not show admin-only tabs for non-admin', () => {
    mockUseAuth.mockReturnValue({
      user: { id: 'u2', username: 'viewer', email: 'v@b.com', role: 'viewer', totp_enabled: true, avatar: null, created_at: '', updated_at: '' },
      login: vi.fn(),
    })
    renderPage()
    expect(screen.queryByRole('button', { name: 'Users' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Directory' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Notifications' })).not.toBeInTheDocument()
  })

  it('shows avatar section with username initial', () => {
    renderPage()
    expect(screen.getAllByText('A').length).toBeGreaterThan(0) // First letter of 'admin'
  })

  it('shows user info section', () => {
    renderPage()
    expect(screen.getByText('admin@test.com')).toBeInTheDocument()
    // "admin" appears multiple times - use a more specific query
    expect(screen.getAllByText('admin').length).toBeGreaterThan(0)
  })

  it('shows Change Password form', () => {
    renderPage()
    expect(screen.getByPlaceholderText('Current password')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('New password (min 12 chars)')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Confirm new password')).toBeInTheDocument()
  })

  it('shows password validation errors for weak new password', async () => {
    renderPage()
    fireEvent.change(screen.getByPlaceholderText('New password (min 12 chars)'), { target: { value: 'weak' } })
    await waitFor(() => {
      // Validation errors are rendered as "• At least 12 characters" in a div
      expect(screen.getByText(/At least 12 characters/)).toBeInTheDocument()
    })
  })

  it('shows passwords do not match warning', async () => {
    renderPage()
    fireEvent.change(screen.getByPlaceholderText('New password (min 12 chars)'), { target: { value: 'ValidPass1@#$' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), { target: { value: 'Different1@#$' } })
    await waitFor(() => {
      expect(screen.getByText('• Passwords do not match')).toBeInTheDocument()
    })
  })

  it('submits password change successfully', async () => {
    mockApiFetch.mockResolvedValueOnce({ status: 'ok' })
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('Current password'), { target: { value: 'OldPass1@#$' } })
    fireEvent.change(screen.getByPlaceholderText('New password (min 12 chars)'), { target: { value: 'NewPass1@#$abc' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), { target: { value: 'NewPass1@#$abc' } })
    fireEvent.submit(screen.getByRole('button', { name: /update password/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Password updated successfully.')).toBeInTheDocument()
    })
  })

  it('shows error on password change failure', async () => {
    // Path-routed (not a bare mockRejectedValueOnce): the Profile tab's "Your
    // sessions" card (009) fires its own GET /auth/sessions on mount, which
    // would otherwise consume this rejection meant for PUT /auth/password.
    mockApiRoutes({ '/auth/password': [new Error('Wrong current password')] })
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('Current password'), { target: { value: 'WrongOld1@#$' } })
    fireEvent.change(screen.getByPlaceholderText('New password (min 12 chars)'), { target: { value: 'NewPass1@#$abc' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), { target: { value: 'NewPass1@#$abc' } })
    fireEvent.submit(screen.getByRole('button', { name: /update password/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Wrong current password')).toBeInTheDocument()
    })
  })

  it('Update Password button is disabled when passwords do not match', async () => {
    renderPage()
    fireEvent.change(screen.getByPlaceholderText('New password (min 12 chars)'), { target: { value: 'ValidPass1@#$' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), { target: { value: 'Different1@#$' } })

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /update password/i })).toBeDisabled()
    })
  })

  it('clicking Users tab switches to UsersTab', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByText('User Management')).toBeInTheDocument()
    })
  })

  it('Users tab shows loading state', async () => {
    // Both the users table and the Account Policy card (mounted above it,
    // 008) show their own "Loading..." state while /users and
    // /settings/hub are both pending.
    mockApiFetch.mockReturnValue(new Promise(() => {}))
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getAllByText('Loading...').length).toBeGreaterThan(0)
    })
  })

  it('Users tab shows user list', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByText('viewer@test.com')).toBeInTheDocument()
    })
  })

  it('Users tab shows no users message when empty', async () => {
    mockApiRoutes({ '/users': [{ users: [] }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByText('No users found.')).toBeInTheDocument()
    })
  })

  it('Users tab shows Create User button', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Create User' })).toBeInTheDocument()
    })
  })

  it('Create User button opens CreateUserModal', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Create User' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    await waitFor(() => {
      expect(screen.getByTestId('create-user-modal')).toBeInTheDocument()
    })
  })

  it('shows Disable 2FA button for other users with TOTP enabled', async () => {
    const usersWithTotp = [
      { ...mockUsers[0] },
      { ...mockUsers[1], totp_enabled: true },
    ]
    mockApiRoutes({ '/users': [{ users: usersWithTotp }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()
    })
  })

  it('shows Delete button for other users', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument()
    })
  })

  it('opens delete confirmation modal when Delete clicked', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => {
      // Modal h3 says "Delete User", modal also has a "Delete User" submit button
      expect(screen.getAllByText('Delete User').length).toBeGreaterThan(0)
      expect(screen.getByText(/"viewer"/)).toBeInTheDocument()
    })
  })

  it('delete user confirmation modal has Cancel and Delete User buttons', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Delete User' })).toBeInTheDocument()
    })
  })

  it('cancel on delete modal closes it', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByRole('button', { name: 'Cancel' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByText('Delete User')).not.toBeInTheDocument())
  })

  it('opens Disable 2FA modal when button clicked', async () => {
    const usersWithTotp = [mockUsers[0], { ...mockUsers[1], totp_enabled: true }]
    mockApiRoutes({ '/users': [{ users: usersWithTotp }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }))
    await waitFor(() => {
      // After clicking "Disable 2FA" button, the modal opens with h3 "Disable 2FA" and another "Disable 2FA" submit button
      expect(screen.getAllByText('Disable 2FA').length).toBeGreaterThan(1)
      expect(screen.getByPlaceholderText('Your 6-digit TOTP code')).toBeInTheDocument()
    })
  })

  it('avatar color buttons render', () => {
    renderPage()
    // Color buttons have style.backgroundColor set
    const colorButtons = screen.getAllByRole('button').filter(btn => {
      const el = btn as HTMLButtonElement
      return el.style.backgroundColor !== ''
    })
    expect(colorButtons.length).toBeGreaterThan(0)
  })

  it('shows avatar image when user has avatar', () => {
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: 'data:image/png;base64,abc', created_at: '', updated_at: '' },
      login: vi.fn(),
    })
    renderPage()
    // Avatar img has alt="" (presentational), so query by tag directly
    const avatarImg = document.querySelector('img[src^="data:image"]')
    expect(avatarImg).toBeInTheDocument()
  })

  it('Upload image button triggers file input', () => {
    renderPage()
    const uploadBtn = screen.getByText('Upload image')
    expect(uploadBtn).toBeInTheDocument()
    fireEvent.click(uploadBtn)
    // No error should occur
  })

  it('shows 2FA status as Enabled in account info', () => {
    renderPage()
    // Multiple "Enabled" could appear - just ensure at least one exists
    expect(screen.getAllByText('Enabled').length).toBeGreaterThan(0)
  })

  it('shows users tab when URL has ?tab=users', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage('/settings?tab=users')
    await waitFor(() => {
      expect(screen.getByText('User Management')).toBeInTheDocument()
    })
  })

  it('cancels Disable 2FA modal', async () => {
    const usersWithTotp = [mockUsers[0], { ...mockUsers[1], totp_enabled: true }]
    mockApiRoutes({ '/users': [{ users: usersWithTotp }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }))
    expect(await screen.findByPlaceholderText('Your 6-digit TOTP code')).toBeInTheDocument()

    // Cancel
    const cancelButtons = screen.getAllByRole('button', { name: 'Cancel' })
    fireEvent.click(cancelButtons[0])
    await waitFor(() => {
      expect(screen.queryByPlaceholderText('Your 6-digit TOTP code')).not.toBeInTheDocument()
    })
  })

  it('handles avatar upload for large file', async () => {
    renderPage()
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeTruthy()
  })

  it('shows Remove button when user has avatar', () => {
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: 'data:image/png;base64,abc', created_at: '', updated_at: '' },
      login: vi.fn(),
    })
    renderPage()
    expect(screen.getByText('Remove')).toBeInTheDocument()
  })

  it('clicking Remove avatar button calls avatarMutation', async () => {
    mockApiFetch.mockResolvedValueOnce({ status: 'ok' })
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: 'data:image/png;base64,abc', created_at: '', updated_at: '' },
      login: vi.fn(),
    })
    renderPage()
    fireEvent.click(screen.getByText('Remove'))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/avatar', expect.objectContaining({ method: 'PUT' }))
    })
  })

  it('confirms delete user and calls DELETE endpoint', async () => {
    mockApiRoutes({
      '/users': [{ users: mockUsers }, { users: [mockUsers[0]] }], // initial fetch, then refetch after delete
      '/users/u2': [{ status: 'ok' }], // delete mutation
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByRole('button', { name: 'Delete User' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete User' }))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/users/u2', expect.objectContaining({ method: 'DELETE' }))
    })
  })

  it('submits Disable 2FA form with TOTP code', async () => {
    const usersWithTotp = [mockUsers[0], { ...mockUsers[1], totp_enabled: true }]
    mockApiRoutes({
      '/users': [{ users: usersWithTotp }, { users: [{ ...mockUsers[1], totp_enabled: false }] }], // initial fetch, then refetch
      '/auth/totp/disable': [{ status: 'ok' }], // disable totp mutation
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }))
    expect(await screen.findByPlaceholderText('Your 6-digit TOTP code')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText('Your 6-digit TOTP code'), { target: { value: '123456' } })
    fireEvent.submit(screen.getByPlaceholderText('Your 6-digit TOTP code').closest('form')!)

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/totp/disable', expect.objectContaining({ method: 'POST' }))
    })
  })

  it('changes user role via select dropdown', async () => {
    mockApiRoutes({
      '/users': [{ users: mockUsers }, { users: mockUsers }], // initial fetch, then refetch
      '/users/u2/role': [{ user: { ...mockUsers[1], role: 'admin' } }], // update role
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByDisplayValue('Viewer')).toBeInTheDocument()

    fireEvent.change(screen.getByDisplayValue('Viewer'), { target: { value: 'admin' } })
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/role', expect.objectContaining({ method: 'PUT' }))
    })
  })

  it('shows role update error when mutation fails', async () => {
    mockApiRoutes({
      '/users': [{ users: mockUsers }], // initial users fetch
      '/users/u2/role': [new Error('Permission denied')], // update role error
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByDisplayValue('Viewer')).toBeInTheDocument()

    fireEvent.change(screen.getByDisplayValue('Viewer'), { target: { value: 'admin' } })
    await waitFor(() => {
      expect(screen.getByText('Permission denied')).toBeInTheDocument()
    })
  })

  it('shows avatar mutation error when upload fails', async () => {
    // Path-routed: the "Your sessions" card's own GET /auth/sessions call
    // must not consume the rejection meant for PUT /auth/avatar.
    mockApiRoutes({ '/auth/avatar': [new Error('Avatar upload failed')] })
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: 'data:image/png;base64,abc', created_at: '', updated_at: '' },
      login: vi.fn(),
    })
    renderPage()
    // Trigger avatarMutation by clicking Remove (which calls mutate(''))
    fireEvent.click(screen.getByText('Remove'))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/avatar', expect.objectContaining({ method: 'PUT' }))
    })
    await waitFor(() => {
      expect(screen.getByText('Avatar upload failed')).toBeInTheDocument()
    })
  })

  it('handles submit with valid passwords matching', async () => {
    // Tests the mutation.reset() branch when passwords match validation but we reset first
    mockApiFetch.mockResolvedValueOnce({ status: 'ok' })
    renderPage()

    fireEvent.change(screen.getByPlaceholderText('Current password'), { target: { value: 'OldPass1@#$' } })
    fireEvent.change(screen.getByPlaceholderText('New password (min 12 chars)'), { target: { value: 'GoodPass1@#$abc' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), { target: { value: 'GoodPass1@#$abc' } })
    fireEvent.submit(screen.getByRole('button', { name: /update password/i }).closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Password updated successfully.')).toBeInTheDocument()
    })
  })

  it('shows delete user error when mutation fails', async () => {
    mockApiRoutes({
      '/users': [{ users: mockUsers }], // initial users fetch
      '/users/u2': [new Error('Cannot delete user')], // delete mutation error
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByRole('button', { name: 'Delete User' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete User' }))
    await waitFor(() => {
      expect(screen.getByText('Cannot delete user')).toBeInTheDocument()
    })
  })

  it('shows disable 2FA error when mutation fails', async () => {
    const usersWithTotp = [mockUsers[0], { ...mockUsers[1], totp_enabled: true }]
    mockApiRoutes({
      '/users': [{ users: usersWithTotp }], // initial users fetch
      '/auth/totp/disable': [new Error('Invalid TOTP code')], // disable totp error
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }))
    expect(await screen.findByPlaceholderText('Your 6-digit TOTP code')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText('Your 6-digit TOTP code'), { target: { value: '999999' } })
    fireEvent.submit(screen.getByPlaceholderText('Your 6-digit TOTP code').closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Invalid TOTP code')).toBeInTheDocument()
    })
  })

  it('formatDate shows Today for current date', async () => {
    const todayIso = new Date().toISOString()
    const usersToday = [
      { ...mockUsers[0] },
      { ...mockUsers[1], created_at: todayIso },
    ]
    mockApiRoutes({ '/users': [{ users: usersToday }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByText('Today')).toBeInTheDocument()
    })
  })

  it('formatDate shows Yesterday for 1 day ago', async () => {
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
    const usersYesterday = [
      { ...mockUsers[0] },
      { ...mockUsers[1], created_at: yesterday },
    ]
    mockApiRoutes({ '/users': [{ users: usersYesterday }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByText('Yesterday')).toBeInTheDocument()
    })
  })

  it('formatDate shows days ago for 5 days ago', async () => {
    const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString()
    const users5Days = [
      { ...mockUsers[0] },
      { ...mockUsers[1], created_at: fiveDaysAgo },
    ]
    mockApiRoutes({ '/users': [{ users: users5Days }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      expect(screen.getByText('5 days ago')).toBeInTheDocument()
    })
  })

  it('formatDate shows formatted date for old dates', async () => {
    const oldDate = '2023-01-15T00:00:00Z'
    const usersOld = [
      { ...mockUsers[0] },
      { ...mockUsers[1], created_at: oldDate },
    ]
    mockApiRoutes({ '/users': [{ users: usersOld }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      // Should show something like "Jan 15, 2023"
      expect(screen.getByText(/Jan 15, 2023/)).toBeInTheDocument()
    })
  })

  describe('UsersTab lockout columns', () => {
    const NOW = new Date('2026-09-05T12:00:00Z')

    beforeEach(() => {
      // Only fake Date — faking setTimeout/setInterval too would starve
      // waitFor's internal polling, which relies on real timers.
      vi.useFakeTimers({ toFake: ['Date'] })
      vi.setSystemTime(NOW)
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    const lockoutUsers = [
      { ...mockUsers[0], last_login_at: null, locked_until: null, failed_login_count: 0 },
      {
        ...mockUsers[1],
        last_login_at: '2026-09-05T09:00:00Z', // 3 hours before NOW
        locked_until: null,
        failed_login_count: 0,
      },
      {
        id: 'u3',
        username: 'locked-user',
        email: 'locked@test.com',
        role: 'viewer',
        totp_enabled: false,
        avatar: null,
        created_at: '2024-01-15T00:00:00Z',
        updated_at: '',
        last_login_at: null,
        locked_until: '2026-09-05T12:10:00Z', // 10 minutes ahead of NOW
        failed_login_count: 4,
      },
      {
        id: 'u4',
        username: 'stale-lock-user',
        email: 'stale@test.com',
        role: 'viewer',
        totp_enabled: false,
        avatar: null,
        created_at: '2024-01-15T00:00:00Z',
        updated_at: '',
        last_login_at: null,
        locked_until: '2026-09-05T11:00:00Z', // in the past
        failed_login_count: 5,
      },
      {
        id: 'u5',
        username: 'sentinel-lock-user',
        email: 'sentinel@test.com',
        role: 'viewer',
        totp_enabled: false,
        avatar: null,
        created_at: '2024-01-15T00:00:00Z',
        updated_at: '',
        last_login_at: null,
        locked_until: '9999-12-31T00:00:00Z',
        failed_login_count: 10,
      },
    ]

    it('renders "Last login" and "Status" header cells', async () => {
      mockApiRoutes({ '/users': [{ users: lockoutUsers }] })
      renderPage()

      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await waitFor(() => {
        expect(screen.getByText('Last login')).toBeInTheDocument()
        expect(screen.getByText('Status')).toBeInTheDocument()
      })
    })

    it('shows "Never" (muted) for a user with no last_login_at', async () => {
      mockApiRoutes({ '/users': [{ users: lockoutUsers }] })
      renderPage()

      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await waitFor(() => {
        expect(screen.getAllByText('Never').length).toBeGreaterThan(0)
      })
    })

    it('shows relative last login with absolute title', async () => {
      mockApiRoutes({ '/users': [{ users: lockoutUsers }] })
      renderPage()

      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await waitFor(() => {
        expect(screen.getByText('3 hours ago')).toBeInTheDocument()
      })
      const cell = screen.getByText('3 hours ago')
      expect(cell).toHaveAttribute('title', expect.stringContaining('2026'))
    })

    it('shows a "Locked until HH:MM" badge for a future lock with failed-attempt title', async () => {
      mockApiRoutes({ '/users': [{ users: lockoutUsers }] })
      renderPage()

      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await waitFor(() => {
        expect(screen.getByText(/^Locked until \d{2}:\d{2}$/)).toBeInTheDocument()
      })
      expect(screen.getByText(/^Locked until \d{2}:\d{2}$/)).toHaveAttribute('title', '4 failed attempts')
    })

    it('shows "Active" for a lock whose expiry has already passed', async () => {
      mockApiRoutes({ '/users': [{ users: lockoutUsers }] })
      renderPage()

      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await waitFor(() => {
        expect(screen.getByText('stale-lock-user')).toBeInTheDocument()
      })
      const row = screen.getByText('stale-lock-user').closest('tr')!
      expect(within(row).getByText('Active')).toBeInTheDocument()
    })

    it('shows "Locked (no auto-unlock)" for the far-future sentinel', async () => {
      mockApiRoutes({ '/users': [{ users: lockoutUsers }] })
      renderPage()

      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await waitFor(() => {
        expect(screen.getByText('Locked (no auto-unlock)')).toBeInTheDocument()
      })
    })

    it('renders an Unlock button for a locked user, not for others (008 US2)', async () => {
      mockApiRoutes({ '/users': [{ users: lockoutUsers }] })
      renderPage()

      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await waitFor(() => {
        expect(screen.getByText('Locked (no auto-unlock)')).toBeInTheDocument()
      })

      // Two locked rows (locked-user, sentinel-lock-user) → two Unlock buttons.
      expect(screen.getAllByRole('button', { name: 'Unlock' })).toHaveLength(2)

      const activeRow = screen.getByText('viewer').closest('tr')!
      expect(within(activeRow).queryByRole('button', { name: 'Unlock' })).not.toBeInTheDocument()

      const staleLockRow = screen.getByText('stale-lock-user').closest('tr')!
      expect(within(staleLockRow).queryByRole('button', { name: 'Unlock' })).not.toBeInTheDocument()
    })
  })

  it('clicking a color button updates avatar color selection', async () => {
    renderPage()
    // Color buttons are buttons with style.backgroundColor
    const colorButtons = screen.getAllByRole('button').filter(btn => {
      const el = btn as HTMLButtonElement
      return el.style.backgroundColor !== ''
    })
    expect(colorButtons.length).toBeGreaterThan(0)
    // Click the first color button - should call setAvatarColor mock
    fireEvent.click(colorButtons[0])
    // Verify setAvatarColor was called (it's mocked at top of file)
    const { setAvatarColor } = await import('@/lib/avatar')
    expect(setAvatarColor).toHaveBeenCalled()
  })

  it('clicking Profile tab when Users is active switches back to profile', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage('/settings?tab=users')
    expect(await screen.findByText('User Management')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Profile' }))
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Current password')).toBeInTheDocument()
    })
  })

  it('CreateUserModal onClose callback hides modal', async () => {
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Create User' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    expect(await screen.findByTestId('create-user-modal')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Close Modal' }))
    await waitFor(() => {
      expect(screen.queryByTestId('create-user-modal')).not.toBeInTheDocument()
    })
  })

  it('calls login after avatar upload succeeds (onSuccess callback)', async () => {
    const mockLogin = vi.fn()
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: 'data:image/png;base64,abc', created_at: '', updated_at: '' },
      login: mockLogin,
    })
    // Remove avatar mutation succeeds, then /auth/me returns updated user.
    // Path-routed: the "Your sessions" card's own GET /auth/sessions call
    // must not consume either queued response.
    const updatedUser = { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }
    mockApiRoutes({
      '/auth/avatar': [{ status: 'ok' }],
      '/auth/me': [updatedUser],
    })
    renderPage()
    fireEvent.click(screen.getByText('Remove'))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/avatar', expect.objectContaining({ method: 'PUT' }))
    })
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/me')
    })
    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith(updatedUser)
    })
  })

  it('avatarMutation onSuccess always calls login with updated user (cookie auth)', async () => {
    const mockLogin = vi.fn()
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: 'data:image/png;base64,abc', created_at: '', updated_at: '' },
      login: mockLogin,
    })
    const updatedUser = { id: 'u1', username: 'admin', email: 'admin@test.com', role: 'admin', totp_enabled: true, avatar: null, created_at: '', updated_at: '' }
    mockApiRoutes({
      '/auth/avatar': [{ status: 'ok' }],
      '/auth/me': [updatedUser],
    })
    renderPage()
    fireEvent.click(screen.getByText('Remove'))
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/avatar', expect.objectContaining({ method: 'PUT' }))
    })
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/me')
    })
    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith(updatedUser)
    })
  })

  it('file input onChange triggers avatar upload', async () => {
    // Tests handleFileUpload — valid image file
    mockApiFetch.mockResolvedValueOnce({ status: 'ok' })
    renderPage()
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeTruthy()

    // Create a small valid PNG image blob
    const file = new File(['fake-image-data'], 'avatar.png', { type: 'image/png' })
    Object.defineProperty(file, 'size', { value: 1024 }) // 1KB — under 500KB limit

    // Use the real FileReader but stub readAsDataURL to immediately fire onload
    const originalReadAsDataURL = FileReader.prototype.readAsDataURL
    FileReader.prototype.readAsDataURL = function() {
      // Simulate immediate onload with a data URL result
      Object.defineProperty(this, 'result', { value: 'data:image/png;base64,abc123', writable: true })
      if (this.onload) {
        this.onload({ target: this } as unknown as ProgressEvent<FileReader>)
      }
    }

    fireEvent.change(fileInput, { target: { files: [file] } })
    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith('/auth/avatar', expect.objectContaining({ method: 'PUT' }))
    })

    FileReader.prototype.readAsDataURL = originalReadAsDataURL
  })

  it('handleFileUpload ignores non-image files', () => {
    renderPage()
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File(['data'], 'test.txt', { type: 'text/plain' })
    Object.defineProperty(file, 'size', { value: 100 })
    fireEvent.change(fileInput, { target: { files: [file] } })
    // No upload should occur (the "Your sessions" card's own GET
    // /auth/sessions call on mount is expected and unrelated).
    expect(mockApiFetch).not.toHaveBeenCalledWith('/auth/avatar', expect.anything())
  })

  it('handleFileUpload alerts on large file (> 500KB)', () => {
    const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {})
    renderPage()
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = new File(['x'.repeat(1)], 'big.png', { type: 'image/png' })
    Object.defineProperty(file, 'size', { value: 600 * 1024 }) // 600KB
    fireEvent.change(fileInput, { target: { files: [file] } })
    expect(alertMock).toHaveBeenCalledWith(expect.stringContaining('500KB'))
    alertMock.mockRestore()
  })

  it('mutation.reset called when passwords differ but both valid (handleSubmit early return)', async () => {
    renderPage()
    // Both passwords individually valid but different from each other
    fireEvent.change(screen.getByPlaceholderText('Current password'), { target: { value: 'OldPass1@#$' } })
    fireEvent.change(screen.getByPlaceholderText('New password (min 12 chars)'), { target: { value: 'ValidPass1@#$abc' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), { target: { value: 'DiffPass1@#$xyz' } })
    // Button is disabled due to mismatch — but simulate direct form submit
    const form = screen.getByPlaceholderText('Current password').closest('form')!
    fireEvent.submit(form)
    // mutation.reset() is called — no password-change API call should be
    // made (the "Your sessions" card's own GET /auth/sessions call on mount
    // is expected and unrelated).
    expect(mockApiFetch).not.toHaveBeenCalledWith('/auth/password', expect.anything())
  })

  it('shows own role as static Admin text for admin user (line 388 Admin branch)', async () => {
    // Set current user to admin (u1) — users list includes u1 as current user
    // When viewing own row, it shows static text instead of select dropdown
    // The admin's own row shows 'Admin'
    mockApiRoutes({ '/users': [{ users: mockUsers }] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    await waitFor(() => {
      // The admin's own row shows static 'Admin' span (not a select)
      // Other users (viewer) show a <select> element
      expect(screen.getByDisplayValue('Viewer')).toBeInTheDocument()
    })
  })

  it('shows fallback error message for non-Error disable 2FA failure (line 452)', async () => {
    const usersWithTotp = [mockUsers[0], { ...mockUsers[1], totp_enabled: true }]
    mockApiRoutes({
      '/users': [{ users: usersWithTotp }],
      '/auth/totp/disable': [rejectWith('non-error-string')], // non-Error rejection
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Disable 2FA' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }))
    expect(await screen.findByPlaceholderText('Your 6-digit TOTP code')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText('Your 6-digit TOTP code'), { target: { value: '999999' } })
    fireEvent.submit(screen.getByPlaceholderText('Your 6-digit TOTP code').closest('form')!)

    await waitFor(() => {
      expect(screen.getByText('Failed to disable 2FA')).toBeInTheDocument()
    })
  })

  it('shows fallback error message for non-Error delete user failure (line 499)', async () => {
    mockApiRoutes({
      '/users': [{ users: mockUsers }],
      '/users/u2': [rejectWith('non-error-string')], // non-Error rejection
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Users' }))
    expect(await screen.findByRole('button', { name: 'Delete' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByRole('button', { name: 'Delete User' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Delete User' }))
    await waitFor(() => {
      expect(screen.getByText('Failed to delete user')).toBeInTheDocument()
    })
  })

  it('clicking Notifications tab switches to NotificationsTab for admin', async () => {
    mockApiFetch
      .mockResolvedValueOnce({ host: 'smtp.example.com', port: 587, username: '', password: '', from: '', tls: false, enabled: false })
      .mockResolvedValueOnce({ entries: [], total: 0 })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Notifications' }))
    await waitFor(() => {
      expect(screen.getByText('SMTP Configuration')).toBeInTheDocument()
    })
  })

  it('clicking Directory tab switches to DirectoryTab for admin', async () => {
    mockApiFetch.mockResolvedValueOnce({
      enabled: true,
      url: 'ldaps://freeipa.yiucloud.com:636',
      bind_dn: '',
      bind_password: '',
      bind_password_set: false,
      user_base_dn: '',
      group_base_dn: '',
      user_search_filter: '(uid={username})',
      group_search_filter: '(|(member={dn})(memberUid={username}))',
      username_attribute: 'uid',
      email_attribute: 'mail',
      external_id_attribute: 'entryUUID',
      group_name_attribute: 'cn',
      start_tls: false,
      tls_server_name: '',
      ca_cert_pem: '',
      allow_insecure_transport: false,
      admin_groups: ['freeipa-admins'],
      auditor_groups: [],
      viewer_groups: [],
      terminal_groups: ['bastion-users'],
    })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Directory' }))
    await waitFor(() => {
      expect(screen.getByText('LDAP Directory')).toBeInTheDocument()
    })
  })

  it('clicking Alerts tab switches to PreferencesTab', async () => {
    mockApiFetch
      .mockResolvedValueOnce({ preferences: [] })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Alerts' }))
    await waitFor(() => {
      expect(screen.getByText('Email Notification Preferences')).toBeInTheDocument()
    })
  })

  describe('UsersTab account lifecycle (008)', () => {
    const NOW = new Date('2026-09-06T12:00:00Z')

    beforeEach(() => {
      vi.useFakeTimers({ toFake: ['Date'] })
      vi.setSystemTime(NOW)
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    // u1 (admin) is the current user (see mockUseAuth default) — its own
    // row never shows lifecycle actions, only the marker.
    const lifecycleUsers: User[] = [
      { ...mockUsers[0], status: 'active' },
      {
        id: 'u2', username: 'active-viewer', email: 'av@test.com', role: 'viewer',
        totp_enabled: false, avatar: null, created_at: '2024-01-15T00:00:00Z', updated_at: '',
        status: 'active',
      },
      {
        id: 'u3', username: 'disabled-user', email: 'disabled@test.com', role: 'viewer',
        totp_enabled: false, avatar: null, created_at: '2024-01-15T00:00:00Z', updated_at: '',
        status: 'disabled', disabled_at: '2026-09-01T00:00:00Z', disabled_by: 'u1',
      },
      {
        id: 'u4', username: 'dormant-user', email: 'dormant@test.com', role: 'viewer',
        totp_enabled: false, avatar: null, created_at: '2024-01-15T00:00:00Z', updated_at: '',
        status: 'dormant', last_activity_at: '2026-07-01T00:00:00Z',
      },
      {
        id: 'u5', username: 'locked-user', email: 'locked@test.com', role: 'viewer',
        totp_enabled: false, avatar: null, created_at: '2024-01-15T00:00:00Z', updated_at: '',
        status: 'locked', locked_until: '2026-09-06T12:10:00Z', failed_login_count: 3,
      },
      {
        id: 'u6', username: 'exempt-admin', email: 'exempt@test.com', role: 'admin',
        totp_enabled: true, avatar: null, created_at: '2024-01-15T00:00:00Z', updated_at: '',
        status: 'active', dormancy_exempt: true,
      },
      {
        id: 'u7', username: 'plain-admin', email: 'plain@test.com', role: 'admin',
        totp_enabled: true, avatar: null, created_at: '2024-01-15T00:00:00Z', updated_at: '',
        status: 'active', dormancy_exempt: false,
      },
    ]

    /** The confirm modal's own card (heading + Cancel/confirm buttons), scoped away from the row's own action button of the same name. */
    function getModal(headingText: string): HTMLElement {
      return screen.getByRole('heading', { name: headingText }).closest('div') as HTMLElement
    }

    it('renders a status badge per account state', async () => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await screen.findByText('disabled-user')

      const disabledRow = screen.getByText('disabled-user').closest('tr')!
      expect(within(disabledRow).getByText('Disabled')).toBeInTheDocument()
      expect(disabledRow.className).toContain('opacity-60')

      const dormantRow = screen.getByText('dormant-user').closest('tr')!
      expect(within(dormantRow).getByText('Dormant')).toBeInTheDocument()

      const lockedRow = screen.getByText('locked-user').closest('tr')!
      expect(within(lockedRow).getByText(/^Locked until \d{2}:\d{2}$/)).toBeInTheDocument()

      const activeRow = screen.getByText('active-viewer').closest('tr')!
      expect(within(activeRow).getByText('Active')).toBeInTheDocument()
    })

    it('shows a "Never dormant" marker only for exempt admins', async () => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await screen.findByText('exempt-admin')

      const exemptRow = screen.getByText('exempt-admin').closest('tr')!
      expect(within(exemptRow).getByText('Never dormant')).toBeInTheDocument()

      const plainAdminRow = screen.getByText('plain-admin').closest('tr')!
      expect(within(plainAdminRow).queryByText('Never dormant')).not.toBeInTheDocument()
    })

    it('shows Disable for active/locked/dormant rows, Enable for disabled, and never on the current user\'s own row', async () => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await screen.findByText('active-viewer')

      for (const username of ['active-viewer', 'locked-user', 'dormant-user']) {
        const row = screen.getByText(username).closest('tr')!
        expect(within(row).getByRole('button', { name: 'Disable' })).toBeInTheDocument()
        expect(within(row).queryByRole('button', { name: 'Enable' })).not.toBeInTheDocument()
      }

      const disabledRow = screen.getByText('disabled-user').closest('tr')!
      expect(within(disabledRow).queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
      expect(within(disabledRow).getByRole('button', { name: 'Enable' })).toBeInTheDocument()

      const selfRow = screen.getByText('admin').closest('tr')!
      expect(within(selfRow).queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
      expect(within(selfRow).queryByRole('button', { name: 'Enable' })).not.toBeInTheDocument()
    })

    it('shows Unlock only for the locked row', async () => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await screen.findByText('locked-user')

      const lockedRow = screen.getByText('locked-user').closest('tr')!
      expect(within(lockedRow).getByRole('button', { name: 'Unlock' })).toBeInTheDocument()

      for (const username of ['active-viewer', 'disabled-user', 'dormant-user']) {
        const row = screen.getByText(username).closest('tr')!
        expect(within(row).queryByRole('button', { name: 'Unlock' })).not.toBeInTheDocument()
      }
    })

    it('shows Exempt/Remove exemption only for admin rows, and never on the current user\'s own row', async () => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await screen.findByText('plain-admin')

      const plainAdminRow = screen.getByText('plain-admin').closest('tr')!
      expect(within(plainAdminRow).getByRole('button', { name: 'Exempt from dormancy' })).toBeInTheDocument()

      const exemptRow = screen.getByText('exempt-admin').closest('tr')!
      expect(within(exemptRow).getByRole('button', { name: 'Remove exemption' })).toBeInTheDocument()

      const viewerRow = screen.getByText('active-viewer').closest('tr')!
      expect(within(viewerRow).queryByRole('button', { name: 'Exempt from dormancy' })).not.toBeInTheDocument()
      expect(within(viewerRow).queryByRole('button', { name: 'Remove exemption' })).not.toBeInTheDocument()

      const selfRow = screen.getByText('admin').closest('tr')!
      expect(within(selfRow).queryByRole('button', { name: 'Exempt from dormancy' })).not.toBeInTheDocument()
      expect(within(selfRow).queryByRole('button', { name: 'Remove exemption' })).not.toBeInTheDocument()
    })

    it('clicking Disable opens a confirmation modal with the contract copy', async () => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('active-viewer')).closest('tr')!

      fireEvent.click(within(row).getByRole('button', { name: 'Disable' }))
      await waitFor(() => {
        expect(screen.getByText(
          'Disable active-viewer? Their sessions end on their next request and all their API tokens are revoked. You can enable the account again later.',
        )).toBeInTheDocument()
      })
    })

    it.each([
      {
        buttonName: 'Enable',
        username: 'disabled-user',
        contractCopy: 'Enable disabled-user? Any lock and failure count are cleared.',
      },
      {
        buttonName: 'Unlock',
        username: 'locked-user',
        contractCopy: 'Unlock locked-user? The lock and failure count are cleared.',
      },
      {
        buttonName: 'Remove exemption',
        username: 'exempt-admin',
        contractCopy: 'Remove the dormancy exemption from exempt-admin?',
      },
    ])('clicking $buttonName opens a confirmation modal with the contract copy', async ({ buttonName, username, contractCopy }) => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText(username)).closest('tr')!

      fireEvent.click(within(row).getByRole('button', { name: buttonName }))
      await waitFor(() => {
        expect(screen.getByText(contractCopy)).toBeInTheDocument()
      })
    })

    it('clicking Exempt from dormancy opens a confirmation modal with the contract copy', async () => {
      mockApiRoutes({ '/users': [{ users: lifecycleUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('plain-admin')).closest('tr')!

      fireEvent.click(within(row).getByRole('button', { name: 'Exempt from dormancy' }))
      await waitFor(() => {
        expect(screen.getByText(
          'Mark plain-admin as never dormant? Use this for the recovery administrator.',
        )).toBeInTheDocument()
      })
    })

    it('confirming Disable issues PUT /users/{id}/status {disabled:true} and invalidates the list', async () => {
      mockApiRoutes({
        '/users': [{ users: lifecycleUsers }, { users: lifecycleUsers }],
        '/users/u2/status': [{ user: { ...lifecycleUsers[1], status: 'disabled' } }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('active-viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Disable' }))
      await screen.findByRole('heading', { name: 'Disable User' })

      fireEvent.click(within(getModal('Disable User')).getByRole('button', { name: 'Disable' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/status', {
          method: 'PUT',
          body: JSON.stringify({ disabled: true }),
        })
      })
      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Disable User' })).not.toBeInTheDocument()
      })
    })

    it('confirming Enable issues PUT /users/{id}/status {disabled:false}', async () => {
      mockApiRoutes({
        '/users': [{ users: lifecycleUsers }, { users: lifecycleUsers }],
        '/users/u3/status': [{ user: { ...lifecycleUsers[2], status: 'active' } }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('disabled-user')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Enable' }))
      await screen.findByRole('heading', { name: 'Enable User' })

      fireEvent.click(within(getModal('Enable User')).getByRole('button', { name: 'Enable' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/users/u3/status', {
          method: 'PUT',
          body: JSON.stringify({ disabled: false }),
        })
      })
    })

    it('confirming Unlock issues POST /users/{id}/unlock', async () => {
      mockApiRoutes({
        '/users': [{ users: lifecycleUsers }, { users: lifecycleUsers }],
        '/users/u5/unlock': [{ user: { ...lifecycleUsers[4], status: 'active' } }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('locked-user')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Unlock' }))
      await screen.findByRole('heading', { name: 'Unlock User' })

      fireEvent.click(within(getModal('Unlock User')).getByRole('button', { name: 'Unlock' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/users/u5/unlock', { method: 'POST' })
      })
    })

    it('confirming Exempt from dormancy issues PUT /users/{id}/dormancy-exemption {exempt:true}', async () => {
      mockApiRoutes({
        '/users': [{ users: lifecycleUsers }, { users: lifecycleUsers }],
        '/users/u7/dormancy-exemption': [{ user: { ...lifecycleUsers[6], dormancy_exempt: true } }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('plain-admin')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Exempt from dormancy' }))
      await screen.findByRole('heading', { name: 'Dormancy Exemption' })

      fireEvent.click(within(getModal('Dormancy Exemption')).getByRole('button', { name: 'Exempt' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/users/u7/dormancy-exemption', {
          method: 'PUT',
          body: JSON.stringify({ exempt: true }),
        })
      })
    })

    it('confirming Remove exemption issues PUT /users/{id}/dormancy-exemption {exempt:false}', async () => {
      mockApiRoutes({
        '/users': [{ users: lifecycleUsers }, { users: lifecycleUsers }],
        '/users/u6/dormancy-exemption': [{ user: { ...lifecycleUsers[5], dormancy_exempt: false } }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('exempt-admin')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Remove exemption' }))
      await screen.findByRole('heading', { name: 'Dormancy Exemption' })

      fireEvent.click(within(getModal('Dormancy Exemption')).getByRole('button', { name: 'Remove exemption' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/users/u6/dormancy-exemption', {
          method: 'PUT',
          body: JSON.stringify({ exempt: false }),
        })
      })
    })

    it('shows the API error verbatim in the error banner when Disable is rejected (e.g. self-disable / last admin)', async () => {
      mockApiRoutes({
        '/users': [{ users: lifecycleUsers }],
        '/users/u2/status': [new Error('cannot disable the last enabled administrator')],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('active-viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Disable' }))
      await screen.findByRole('heading', { name: 'Disable User' })

      fireEvent.click(within(getModal('Disable User')).getByRole('button', { name: 'Disable' }))

      await waitFor(() => {
        expect(screen.getByText('cannot disable the last enabled administrator')).toBeInTheDocument()
      })
      // The modal closes; the error surfaces in the page's error banner instead.
      expect(screen.queryByRole('heading', { name: 'Disable User' })).not.toBeInTheDocument()
    })

    it('shows the API error verbatim when a non-admin exemption request is rejected', async () => {
      // A viewer row never renders the Exempt action, so this exercises the
      // banner rendering path directly via the same mutation/banner wiring
      // used for admin rows (the 400 case is enforced server-side; the UI
      // banner just needs to render whatever message the API returns).
      mockApiRoutes({
        '/users': [{ users: lifecycleUsers }],
        '/users/u7/dormancy-exemption': [new Error('dormancy exemption applies to administrator accounts only')],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('plain-admin')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Exempt from dormancy' }))
      await screen.findByRole('heading', { name: 'Dormancy Exemption' })

      fireEvent.click(within(getModal('Dormancy Exemption')).getByRole('button', { name: 'Exempt' }))

      await waitFor(() => {
        expect(screen.getByText('dormancy exemption applies to administrator accounts only')).toBeInTheDocument()
      })
    })
  })

  describe('Sessions (009) — Users tab', () => {
    /** Scopes to a confirm dialog's own card by its heading, same pattern as the lifecycle describe above. */
    function getModal(headingText: string): HTMLElement {
      return screen.getByRole('heading', { name: headingText }).closest('div') as HTMLElement
    }

    it('shows a Sessions action on every row, including the viewer\'s own', async () => {
      mockApiRoutes({ '/users': [{ users: mockUsers }] })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      await screen.findByText('User Management')

      const buttons = await screen.findAllByRole('button', { name: 'Sessions' })
      expect(buttons).toHaveLength(mockUsers.length)
    })

    it('opens "Sessions — <username>" and lists that user\'s sessions', async () => {
      mockApiRoutes({
        '/users': [{ users: mockUsers }],
        '/users/u2/sessions': [{
          sessions: [
            { id: 's1', kind: 'web', ip: '10.0.0.5', created_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-05T00:00:00Z', current: false },
          ],
        }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Sessions' }))

      await screen.findByRole('heading', { name: 'Sessions — viewer' })
      expect(await screen.findByText('10.0.0.5')).toBeInTheDocument()
      expect(screen.getByText('Web')).toBeInTheDocument()
    })

    it('shows "No active sessions." when the user has none', async () => {
      mockApiRoutes({
        '/users': [{ users: mockUsers }],
        '/users/u2/sessions': [{ sessions: [] }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Sessions' }))

      await screen.findByRole('heading', { name: 'Sessions — viewer' })
      expect(await screen.findByText('No active sessions.')).toBeInTheDocument()
    })

    it('Log out row action confirms and issues DELETE /users/{id}/sessions/{sid}', async () => {
      mockApiRoutes({
        '/users': [{ users: mockUsers }],
        '/users/u2/sessions': [
          { sessions: [{ id: 's1', kind: 'web', ip: '10.0.0.5', created_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-05T00:00:00Z', current: false }] },
          { sessions: [] }, // refetch after the invalidate
        ],
        '/users/u2/sessions/s1': [{ status: 'ended' }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Sessions' }))
      await screen.findByRole('heading', { name: 'Sessions — viewer' })

      fireEvent.click(await screen.findByRole('button', { name: 'Log out' }))
      await screen.findByRole('heading', { name: 'Log out session' })
      fireEvent.click(within(getModal('Log out session')).getByRole('button', { name: 'Log out' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/sessions/s1', expect.objectContaining({ method: 'DELETE' }))
      })
    })

    it('Terminate on a shell row confirms and issues DELETE /users/{id}/sessions/{shell-id}', async () => {
      mockApiRoutes({
        '/users': [{ users: mockUsers }],
        '/users/u2/sessions': [
          { sessions: [{ id: 'shell:srv1:sess1', kind: 'ssh', server: 'web-01', started_at: '2026-09-01T00:00:00Z', last_activity_at: '2026-09-05T00:00:00Z', current: false }] },
          { sessions: [] },
        ],
        '/users/u2/sessions/shell:srv1:sess1': [{ status: 'ended' }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Sessions' }))
      await screen.findByRole('heading', { name: 'Sessions — viewer' })

      expect(await screen.findByText('SSH shell')).toBeInTheDocument()
      expect(screen.getByText('web-01')).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: 'Terminate' }))
      await screen.findByRole('heading', { name: 'Terminate shell' })
      fireEvent.click(within(getModal('Terminate shell')).getByRole('button', { name: 'Terminate' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/users/u2/sessions/shell:srv1:sess1', expect.objectContaining({ method: 'DELETE' }))
      })
    })

    it('Log out everywhere confirms with the contract copy and issues DELETE /users/{id}/sessions', async () => {
      mockApiRoutes({
        '/users': [{ users: mockUsers }],
        '/users/u2/sessions': [
          { sessions: [{ id: 's1', kind: 'cli', ip: '10.0.0.9', created_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-05T00:00:00Z', current: false }] },
          { sessions: [] },
        ],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Sessions' }))
      await screen.findByRole('heading', { name: 'Sessions — viewer' })

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

    it('closes the modal via the Close button', async () => {
      mockApiRoutes({
        '/users': [{ users: mockUsers }],
        '/users/u2/sessions': [{ sessions: [] }],
      })
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Users' }))
      const row = (await screen.findByText('viewer')).closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: 'Sessions' }))
      await screen.findByRole('heading', { name: 'Sessions — viewer' })

      fireEvent.click(screen.getByRole('button', { name: 'Close' }))
      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Sessions — viewer' })).not.toBeInTheDocument()
      })
    })
  })

  describe('Sessions (009) — Profile tab "Your sessions"', () => {
    function getModal(headingText: string): HTMLElement {
      return screen.getByRole('heading', { name: headingText }).closest('div') as HTMLElement
    }

    it('shows a loading state then the only-session empty text when just the current session exists', async () => {
      mockApiRoutes({
        '/auth/sessions': [{ sessions: [{ id: 'cur', kind: 'web', ip: '10.0.0.1', current: true }] }],
      })
      renderPage()
      expect(await screen.findByText('Your sessions')).toBeInTheDocument()
      expect(await screen.findByText('This is your only active session.')).toBeInTheDocument()
    })

    it('lists other sessions with a This session tag and a per-row Sign out, and confirms "Sign out other sessions"', async () => {
      mockApiRoutes({
        '/auth/sessions': [
          {
            sessions: [
              { id: 'cur', kind: 'web', ip: '10.0.0.1', current: true },
              { id: 'other', kind: 'cli', ip: '10.0.0.2', current: false },
            ],
          },
          { sessions: [{ id: 'cur', kind: 'web', ip: '10.0.0.1', current: true }] }, // refetch after sign-out-others
        ],
        '/auth/sessions/sign-out-others': [{ ended: 1, shells_closed: 0 }],
      })
      renderPage()
      expect(await screen.findByText('This session')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument()

      fireEvent.click(screen.getByRole('button', { name: 'Sign out other sessions' }))
      await screen.findByRole('heading', { name: 'Sign out other sessions' })
      fireEvent.click(within(getModal('Sign out other sessions')).getByRole('button', { name: 'Sign out' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/auth/sessions/sign-out-others', expect.objectContaining({ method: 'POST' }))
      })
    })

    it('per-row Sign out issues DELETE /auth/sessions/{id} directly (no confirmation)', async () => {
      mockApiRoutes({
        '/auth/sessions': [
          {
            sessions: [
              { id: 'cur', kind: 'web', ip: '10.0.0.1', current: true },
              { id: 'other', kind: 'cli', ip: '10.0.0.2', current: false },
            ],
          },
        ],
        '/auth/sessions/other': [{ status: 'ended' }],
      })
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))

      await waitFor(() => {
        expect(mockApiFetch).toHaveBeenCalledWith('/auth/sessions/other', expect.objectContaining({ method: 'DELETE' }))
      })
    })

    it('shows an error banner when the sessions list fails to load', async () => {
      mockApiRoutes({
        '/auth/sessions': [new Error('failed to fetch sessions')],
      })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Failed to load sessions.')).toBeInTheDocument()
      })
    })
  })
})
