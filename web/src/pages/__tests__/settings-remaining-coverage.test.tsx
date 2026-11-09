import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { AuthProvider } from '@/hooks/use-auth'
import { SettingsPage } from '../settings'
import type { User } from '@/types/api'

const actor: User = { id: 'actor', username: 'operator', email: 'operator@example.test', role: 'admin', totp_enabled: true, avatar: null, created_at: '2026-01-01', updated_at: '' }
const target: User = { ...actor, id: 'target', username: 'target-user', email: 'target@example.test', role: 'viewer' }
const fetchMock = vi.fn<typeof fetch>()
let client: QueryClient
let users: User[]
let mutation: (url: string, options: RequestInit) => Promise<Response>
function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }) }
function deferred() {
  let resolve!: (response: Response) => void
  const promise = new Promise<Response>(yes => { resolve = yes })
  return { promise, resolve }
}
function calls(method: string) { return fetchMock.mock.calls.filter(([, options]) => options?.method === method) }
function row(username: string) { return screen.getByRole('cell', { name: username }).closest('tr')! }
async function renderPage() {
  render(<QueryClientProvider client={client}><AuthProvider><MemoryRouter initialEntries={['/settings?tab=users']}><SettingsPage /></MemoryRouter></AuthProvider></QueryClientProvider>)
  await screen.findByRole('cell', { name: target.username })
}
beforeEach(() => {
  users = [actor, target]
  client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } })
  mutation = async url => { throw new Error(`Unexpected mutation: ${url}`) }
  vi.spyOn(document, 'cookie', 'get').mockReturnValue('__Host-veyport_csrf=settings-csrf')
  vi.stubGlobal('fetch', fetchMock.mockReset().mockImplementation(async (input, options = {}) => {
    const url = String(input)
    if (options.method) return mutation(url, options)
    if (url === '/api/auth/me') return json(actor)
    if (url === '/api/users') return json({ users })
    if (url === '/api/settings/hub') return json({ grpc_external_addr: '', lockout_threshold: 5, lockout_window_minutes: 15, lockout_duration_minutes: 30, dormant_days: 35 })
    throw new Error(`Unexpected request: ${url}`)
  }))
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('renders the signed-in role as a badge and reserves role editing and destructive actions for other users', async () => {
  await renderPage()
  expect(within(row(actor.username)).getByText('Admin')).toBeInTheDocument()
  expect(within(row(actor.username)).queryByRole('combobox')).not.toBeInTheDocument()
  expect(within(row(actor.username)).queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
  expect(within(row(actor.username)).queryByRole('button', { name: 'Disable 2FA' })).not.toBeInTheDocument()
  expect(within(row(target.username)).getByRole('combobox')).toHaveValue('viewer')
  expect(calls('POST')).toHaveLength(0)
  expect(calls('DELETE')).toHaveLength(0)
})

it('confirms 2FA reset with the operator code, blocks repeated pending submission and refreshes on success', async () => {
  const pending = deferred()
  mutation = () => pending.promise
  await renderPage()
  await userEvent.click(within(row(target.username)).getByRole('button', { name: 'Disable 2FA' }))
  const confirm = screen.getAllByRole('button', { name: 'Disable 2FA' }).at(-1)!
  expect(confirm).toBeDisabled()
  await userEvent.type(screen.getByPlaceholderText('Your 6-digit TOTP code'), '12345')
  expect(confirm).toBeDisabled()
  expect(calls('POST')).toHaveLength(0)
  await userEvent.type(screen.getByPlaceholderText('Your 6-digit TOTP code'), '6')
  await userEvent.click(confirm)
  const busy = await screen.findByRole('button', { name: 'Disabling...' })
  expect(busy).toBeDisabled()
  await userEvent.click(busy)
  expect(calls('POST')).toHaveLength(1)
  const [[url, options]] = calls('POST')
  expect(url).toBe('/api/auth/totp/disable')
  expect(JSON.parse(String(options?.body))).toEqual({ user_id: target.id, admin_totp_code: '123456' })
  expect(options?.credentials).toBe('same-origin')
  expect(new Headers(options?.headers).get('X-CSRF-Token')).toBe('settings-csrf')
  users = [actor, { ...target, totp_enabled: false }]
  await act(async () => pending.resolve(json({ status: 'ok' })))
  await waitFor(() => expect(screen.queryByPlaceholderText('Your 6-digit TOTP code')).not.toBeInTheDocument())
  expect(await within(row(target.username)).findByText('Not set up')).toBeInTheDocument()
  expect(within(row(target.username)).queryByRole('button', { name: 'Disable 2FA' })).not.toBeInTheDocument()
})

it('keeps a refused 2FA reset visible and permits an explicit retry without changing cached users', async () => {
  mutation = async () => json({ error: 'Operator code refused' }, 403)
  await renderPage()
  await userEvent.click(within(row(target.username)).getByRole('button', { name: 'Disable 2FA' }))
  await userEvent.type(screen.getByPlaceholderText('Your 6-digit TOTP code'), '123456')
  await userEvent.click(screen.getAllByRole('button', { name: 'Disable 2FA' }).at(-1)!)
  expect(await screen.findByText('Operator code refused')).toBeInTheDocument()
  expect(client.getQueryData(['users'])).toEqual({ users: [actor, target] })
  expect(calls('POST')).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(screen.queryByPlaceholderText('Your 6-digit TOTP code')).not.toBeInTheDocument()
  await userEvent.click(within(row(target.username)).getByRole('button', { name: 'Disable 2FA' }))
  expect(screen.getByPlaceholderText('Your 6-digit TOTP code')).toHaveValue('')
})

it('cancels deletion without a request, then keeps the confirmation busy until the confirmed user is deleted', async () => {
  const pending = deferred()
  mutation = () => pending.promise
  await renderPage()
  await userEvent.click(within(row(target.username)).getByRole('button', { name: 'Delete' }))
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(calls('DELETE')).toHaveLength(0)
  await userEvent.click(within(row(target.username)).getByRole('button', { name: 'Delete' }))
  expect(screen.getByText(/Are you sure you want to delete/)).toHaveTextContent(target.username)
  await userEvent.click(screen.getByRole('button', { name: 'Delete User' }))
  const busy = await screen.findByRole('button', { name: 'Deleting...' })
  expect(busy).toBeDisabled()
  await userEvent.click(busy)
  expect(calls('DELETE')).toHaveLength(1)
  const [[url, options]] = calls('DELETE')
  expect(url).toBe('/api/users/target')
  expect(options?.credentials).toBe('same-origin')
  expect(new Headers(options?.headers).get('X-CSRF-Token')).toBe('settings-csrf')
  users = [actor]
  await act(async () => pending.resolve(json({ status: 'ok' })))
  await waitFor(() => expect(screen.queryByText('Delete User')).not.toBeInTheDocument())
  await waitFor(() => expect(screen.queryByRole('cell', { name: target.username })).not.toBeInTheDocument())
  expect(screen.getByRole('cell', { name: actor.username })).toBeInTheDocument()
})

it('shows a refused deletion without removing the user or automatically retrying', async () => {
  mutation = async () => json({ error: 'Deletion refused' }, 403)
  await renderPage()
  await userEvent.click(within(row(target.username)).getByRole('button', { name: 'Delete' }))
  await userEvent.click(screen.getByRole('button', { name: 'Delete User' }))
  expect(await screen.findByText('Deletion refused')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Delete User' })).toBeEnabled()
  expect(screen.getByRole('cell', { name: target.username })).toBeInTheDocument()
  expect(calls('DELETE')).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(screen.queryByText('Deletion refused')).not.toBeInTheDocument()
})
