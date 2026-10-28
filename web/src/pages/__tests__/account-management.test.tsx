import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { SettingsPage } from '../settings'
import { ResetPasswordModal } from '../reset-password-modal'
import type { User } from '@/types/api'
import { ApiError } from '@/lib/api'

const mocks = vi.hoisted(() => ({ api: vi.fn(), once: vi.fn(), actor: { id: 'admin', username: 'admin', role: 'admin' } as Partial<User> | null }))
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ user: mocks.actor }) }))
vi.mock('@/lib/api', async importOriginal => {
  const actual = await importOriginal() as typeof import('@/lib/api')
  return { ...actual, apiFetch: mocks.api, apiFetchOnce: mocks.once }
})

const target: User = { id: 'local', username: 'localuser', email: 'local@example.test', role: 'viewer', auth_provider: 'local', credential_revision: 4, protected: false, status: 'dormant', totp_enabled: true, avatar: null, created_at: '2026-01-01', updated_at: '2026-01-01' }
const secret = 'SYNTHETIC-temporary-37!'
const result = { user: target, temporary_password: secret, expires_at: '2026-12-01T12:00:00Z' }
function setup(children = <SettingsPage />, mutationRetry = 3) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: mutationRetry } } })
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}><MemoryRouter initialEntries={['/settings?tab=users']}>{children}</MemoryRouter></QueryClientProvider>
  return { ...render(children, { wrapper }), client }
}
function row(username = target.username) { return screen.getByText(username, { selector: 'td' }).closest('tr')! }
beforeEach(() => {
  vi.clearAllMocks()
  mocks.actor = { id: 'admin', username: 'admin', role: 'admin' }
  mocks.api.mockImplementation(async (path: string) => path === '/users' ? { users: [target] } : {})
  mocks.once.mockResolvedValue(result)
  Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
})

it('shows Local/LDAP/Unknown, directory ownership help, safe source actions and existing policy controls', async () => {
  mocks.api.mockImplementation(async (path: string) => path === '/users' ? { users: [target, { ...target, id: 'ldap', username: 'directoryuser', auth_provider: 'ldap' }, { ...target, id: 'unknown', username: 'unknownuser', auth_provider: 'future' }, { ...target, id: 'missing', username: 'missinguser', auth_provider: undefined }] } : {})
  setup()
  expect(await screen.findByRole('columnheader', { name: 'Account source' })).toBeInTheDocument()
  await screen.findByText(target.username, { selector: 'td' })
  expect(within(row()).getByText('Local')).toBeInTheDocument()
  expect(within(row('directoryuser')).getByText('LDAP')).toBeInTheDocument()
  for (const username of ['unknownuser', 'missinguser']) {
    expect(within(row(username)).getByText('Unknown')).toBeInTheDocument()
    expect(within(row(username)).queryByRole('button', { name: 'Reset password' })).not.toBeInTheDocument()
  }
  expect(screen.getByText('Account policy')).toBeInTheDocument()
  fireEvent.click(within(row('directoryuser')).getByRole('button', { name: 'Password help' }))
  expect(screen.getByRole('dialog')).toHaveTextContent('A directory administrator must reset it there')
  expect(screen.getByRole('dialog')).toHaveTextContent('directory-required password change')
  fireEvent.click(screen.getByRole('button', { name: 'Close' }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('reactivates directly, waits for server confirmation and explains a remaining lock', async () => {
  let finish!: (value: unknown) => void
  const pending = new Promise(resolve => { finish = resolve })
  mocks.api.mockImplementation((path: string) => path.endsWith('/reactivate') ? pending : Promise.resolve(path === '/users' ? { users: [target] } : {}))
  setup()
  fireEvent.click(await screen.findByRole('button', { name: 'Reactivate', exact: true }))
  expect(screen.getByText(/Any separate lockout remains/)).toBeInTheDocument()
  fireEvent.click(screen.getAllByRole('button', { name: 'Reactivate', exact: true })[1])
  expect(await screen.findByRole('button', { name: 'Reactivate...' })).toBeDisabled()
  expect(within(row()).getByText('Dormant')).toBeInTheDocument()
  await act(async () => finish({ user: { ...target, status: 'locked' }, changed: true }))
  expect(await screen.findByRole('status')).toHaveTextContent('remains locked')
  expect(mocks.api).toHaveBeenCalledWith('/users/local/reactivate', { method: 'POST' })
  expect(mocks.api).not.toHaveBeenCalledWith('/users/local/status', expect.anything())
  await waitFor(() => expect(mocks.api.mock.calls.filter(([path]) => path === '/users').length).toBeGreaterThan(1))
})

it('routes protected recovery to Security and keeps disabled enable separate', async () => {
  mocks.actor = { id: 'admin', username: 'admin', role: 'admin', capabilities: ['operations.admin', 'security.read'] }
  mocks.api.mockImplementation(async (path: string) => path === '/users' ? { users: [{ ...target, protected: true }, { ...target, id: 'disabled', username: 'disableduser', status: 'disabled' }] } : {})
  setup()
  await screen.findByText(target.username, { selector: 'td' })
  expect(within(row()).getByRole('link', { name: 'Security approval required' })).toHaveAttribute('href', '/settings?tab=security')
  expect(within(row()).queryByRole('button', { name: 'Reset password' })).not.toBeInTheDocument()
  expect(within(row()).queryByRole('button', { name: 'Reactivate' })).not.toBeInTheDocument()
  expect(within(row('disableduser')).getByRole('button', { name: 'Enable' })).toBeInTheDocument()
  expect(within(row('disableduser')).queryByRole('button', { name: 'Reactivate' })).not.toBeInTheDocument()
})

it('guides an enrolled operations administrator to a security officer when Security is unavailable', async () => {
  mocks.actor = { id: 'admin', username: 'admin', role: 'admin', capabilities: ['operations.admin', 'security.bootstrap'] }
  mocks.api.mockImplementation(async (path: string) => path === '/users' ? { users: [{ ...target, protected: true }] } : { governance_enrolled: true, profile: 'standard' })
  setup()
  await screen.findByText(target.username, { selector: 'td' })
  expect(within(row()).getByText('Protected account. Contact a security officer for independently approved recovery.')).toBeInTheDocument()
  expect(within(row()).queryByRole('link')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Security', exact: true })).not.toBeInTheDocument()
})

it('keeps the reset secret out of caches, copies only explicitly and discards on close', async () => {
  const { client } = setup()
  fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  expect(await screen.findByText(secret)).toBeInTheDocument()
  expect(screen.getByText(/Expires:/)).toBeInTheDocument()
  expect(screen.getByRole('dialog')).toHaveTextContent('Account remains dormant')
  expect(navigator.clipboard.writeText).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
  await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(secret))
  expect(JSON.stringify(client.getMutationCache().getAll().map(mutation => mutation.state))).not.toContain(secret)
  expect(JSON.stringify(client.getQueryCache().getAll().map(query => query.state))).not.toContain(secret)
  expect(localStorage.length).toBe(0)
  expect(sessionStorage.length).toBe(0)
  expect(mocks.once).toHaveBeenCalledWith('/users/local/password-reset', expect.objectContaining({ body: JSON.stringify({ expected_revision: 4 }), cache: 'no-store', signal: expect.any(AbortSignal) }))
  fireEvent.click(screen.getByRole('button', { name: 'Done' }))
  expect(screen.queryByText(secret)).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Reset password' }))
  expect(screen.queryByText(secret)).not.toBeInTheDocument()
  expect(mocks.once).toHaveBeenCalledTimes(1)
})

it('never automatically retries an uncertain reset and requires a new explicit dialog', async () => {
  mocks.once.mockRejectedValue(new TypeError('network failed'))
  setup(<ResetPasswordModal user={target} onClose={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('It may have completed')
  expect(screen.getByRole('button', { name: 'Generate temporary password' })).toBeDisabled()
  expect(mocks.once).toHaveBeenCalledTimes(1)
})

it('reloads a conflicting account and requires a newly confirmed revision before another reset', async () => {
  mocks.once.mockRejectedValueOnce(new ApiError('stale account revision', 409))
  setup()
  fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }))
  mocks.api.mockImplementation(async (path: string) => path === '/users' ? { users: [{ ...target, credential_revision: 5 }] } : {})
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('This account changed')
  expect(screen.getByRole('button', { name: 'Generate temporary password' })).toBeDisabled()
  expect(mocks.once).toHaveBeenCalledTimes(1)
  await waitFor(() => expect(mocks.api.mock.calls.filter(([path]) => path === '/users').length).toBeGreaterThan(1))
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  fireEvent.click(screen.getByRole('button', { name: 'Reset password' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  expect(await screen.findByText(secret)).toBeInTheDocument()
  expect(mocks.once).toHaveBeenLastCalledWith('/users/local/password-reset', expect.objectContaining({ body: JSON.stringify({ expected_revision: 5 }) }))
})

it.each([
  ['disabled', 'Enable'], ['locked', 'Unlock'], ['active', null], [undefined, null],
] as const)('reports the authoritative lifecycle after a reset of a %s account', async (status, action) => {
  mocks.once.mockResolvedValue({ ...result, user: { ...target, status } })
  setup(<ResetPasswordModal user={target} onClose={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  await screen.findByText(secret)
  if (action) expect(screen.getByRole('status')).toHaveTextContent(`${action} it separately`)
  else expect(screen.queryByRole('status')).not.toBeInTheDocument()
})

it('keeps the one-time result available when explicit clipboard copying fails', async () => {
  vi.mocked(navigator.clipboard.writeText).mockRejectedValue(new Error('clipboard denied'))
  setup(<ResetPasswordModal user={target} onClose={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  await screen.findByText(secret)
  expect(screen.getByRole('button', { name: 'Copy' })).toHaveFocus()
  fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Select and copy the password manually')
  expect(screen.getByText(secret)).toBeInTheDocument()
  expect(mocks.once).toHaveBeenCalledTimes(1)
})

it('native cancellation during a pending reset warns, discards late output and never repeats it', async () => {
  let finish!: (value: unknown) => void
  mocks.once.mockReturnValue(new Promise(resolve => { finish = resolve }))
  setup()
  const trigger = await screen.findByRole('button', { name: 'Reset password' })
  trigger.focus(); fireEvent.click(trigger)
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  expect(await screen.findByText(/Closing this dialog cannot undo it/)).toBeInTheDocument()
  fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }))
  expect(trigger).toHaveFocus()
  expect(mocks.once.mock.calls[0][1].signal.aborted).toBe(true)
  await act(async () => finish(result))
  expect(screen.queryByText(secret)).not.toBeInTheDocument()
  fireEvent.click(trigger)
  expect(screen.getByRole('button', { name: 'Generate temporary password' })).toBeEnabled()
  expect(mocks.once).toHaveBeenCalledTimes(1)
})

it.each(['navigation', 'actor', 'logout'])('clears an already displayed secret on %s', async reason => {
  const { unmount, rerender, client } = setup()
  fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  await screen.findByText(secret)
  if (reason === 'navigation') unmount()
  else { mocks.actor = reason === 'actor' ? { id: 'other', role: 'admin' } : null; rerender(<SettingsPage />) }
  expect(screen.queryByText(secret)).not.toBeInTheDocument()
  expect(JSON.stringify(client.getMutationCache().getAll().map(mutation => mutation.state))).not.toContain(secret)
})

it.each([
  { changed: true, status: 'active', message: 'is reactivated. Current status: active' },
  { changed: true, status: undefined, message: 'is reactivated. Current status: unknown' },
  { changed: false, status: 'active', message: 'needed no reactivation. Current status: active' },
  { changed: false, status: undefined, message: 'needed no reactivation. Current status: unknown' },
])('reports authoritative reactivation/no-change outcomes: $message', async response => {
  mocks.api.mockImplementation(async (path: string) => path.endsWith('/reactivate') ? { user: { ...target, status: response.status }, changed: response.changed } : path === '/users' ? { users: [target] } : {})
  setup()
  fireEvent.click(await screen.findByRole('button', { name: 'Reactivate', exact: true }))
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Reactivate', exact: true }))
  expect(await screen.findByRole('status')).toHaveTextContent(response.message)
})

it('keeps the authoritative dormant state and explains a reactivation refusal', async () => {
  mocks.api.mockImplementation(async (path: string) => {
    if (path.endsWith('/reactivate')) throw new Error('Account changed. Review its current status.')
    return path === '/users' ? { users: [target] } : {}
  })
  setup(<SettingsPage />, 0)
  fireEvent.click(await screen.findByRole('button', { name: 'Reactivate', exact: true }))
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Reactivate', exact: true }))
  expect(await screen.findByText('Account changed. Review its current status.')).toBeInTheDocument()
  expect(within(row()).getByText('Dormant')).toBeInTheDocument()
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('separates user-list failure from an empty list', async () => {
  mocks.api.mockImplementation(async (path: string) => {
    if (path === '/users') throw new Error('offline')
    return {}
  })
  setup()
  expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load users')
  expect(screen.queryByText('No users found.')).not.toBeInTheDocument()
})

it('supports native cancellation of directory help and lifecycle confirmation without mutation', async () => {
  mocks.api.mockImplementation(async (path: string) => path === '/users' ? { users: [{ ...target, auth_provider: 'ldap' }] } : {})
  setup()
  const trigger = await screen.findByRole('button', { name: 'Password help' })
  trigger.focus(); fireEvent.click(trigger)
  expect(screen.getByRole('button', { name: 'Close' })).toHaveFocus()
  fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }))
  expect(trigger).toHaveFocus()
  fireEvent.click(screen.getByRole('button', { name: 'Reactivate', exact: true }))
  fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(mocks.api).not.toHaveBeenCalledWith('/users/local/reactivate', expect.anything())
})

it('opens a modal with initial focus, handles native cancellation and restores focus to its trigger', async () => {
  setup()
  const trigger = await screen.findByRole('button', { name: 'Reset password' })
  trigger.focus()
  fireEvent.click(trigger)
  const cancel = screen.getByRole('button', { name: 'Cancel' })
  expect(cancel).toHaveFocus()
  expect(screen.getByRole('dialog')).toHaveAttribute('open')
  fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(trigger).toHaveFocus()
})

it.each(['close', 'navigation', 'actor', 'logout'])('discards pending/reset authority on %s, including late responses', async reason => {
  let finish!: (value: unknown) => void
  mocks.once.mockReturnValue(new Promise(resolve => { finish = resolve }))
  const { unmount, rerender } = setup()
  fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate temporary password' }))
  await waitFor(() => expect(mocks.once).toHaveBeenCalledTimes(1))
  const signal = mocks.once.mock.calls[0][1].signal as AbortSignal
  if (reason === 'close') fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  else if (reason === 'actor') { mocks.actor = { id: 'other', username: 'other', role: 'admin' }; rerender(<SettingsPage />) }
  else if (reason === 'logout') { mocks.actor = null; rerender(<SettingsPage />) }
  else unmount()
  expect(signal.aborted).toBe(true)
  await act(async () => finish(result))
  expect(screen.queryByText(secret)).not.toBeInTheDocument()
})
